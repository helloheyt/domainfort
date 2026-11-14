#![forbid(unsafe_code)]
//! `test-scratch`: a scratch directory inside the workspace, for the tests
//! whose files a `protected-file` reader opens (task T; docs/questions
//! Q-480).
//!
//! The reader walks the path from `/` and accepts a directory only if it is
//! root's or the expected owner's and not writable by group or others
//! (docs/52 R11; Q-468 options 1, 2(b), decision A-102). The system's
//! temporary directory does not pass for an unprivileged test; the workspace
//! checkout does (its ancestors are root's or the test account's). A
//! [`ScratchDir`] is `<workspace>/.test-scratch/<tag>-<pid>-<n>`, mode 0700,
//! removed on drop; `/.test-scratch/` is ignored by git.
//!
//! **One exception, by necessity:** a configuration value that names a path
//! (crates/config `AbsolutePath`, provision's `FilePath`) admits only the
//! octets `A-Z a-z 0-9 . _ - /` (docs/questions/Q-230 item 16), and the tests
//! that provision a domain or write a TLS configuration put scratch paths
//! into such values. When the workspace path holds any other octet (this
//! development host's checkout lies under `…/linux server/…`), the root is
//! `$HOME/.test-scratch` instead — the same properties: the account's own
//! directories, not writable by others. If neither qualifies,
//! [`scratch_root`] fails (Q-480).
//!
//! Only files a protected-file reader opens need it: Unix sockets keep their
//! short paths under the temporary directory (the socket-path length limit).
//!
//! Spec: docs/52 §3.13 (R11), §3.18 (C18: no test seam in a product API);
//! Q-468; Q-480. Std API only.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// Owner-only permissions for the scratch directories, so they pass the
/// directory rule whatever the umask. Spec: Q-468 option 2(b).
const OWNER_ONLY: u32 = 0o700;

/// The directory name under the workspace root. Spec: Q-480.
const SCRATCH_ROOT: &str = ".test-scratch";

static NEXT: AtomicU32 = AtomicU32::new(0);

/// An absolute path made only of the octets a configuration value admits
/// for a path: `A-Z a-z 0-9 . _ - /`.
/// Spec: docs/50 §7.1 ("absolute path"); docs/questions/Q-230 item 16
/// (crates/config `AbsolutePath`; provision `FilePath`).
fn is_configuration_path(path: &Path) -> bool {
    let octets = path.as_os_str().as_bytes();
    octets.first() == Some(&b'/')
        && octets
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

/// `<workspace>/.test-scratch` — the workspace is two levels above this
/// crate's manifest directory (`crates/test-scratch`) — or, when that path
/// cannot appear in a configuration value, `$HOME/.test-scratch` (module
/// documentation).
///
/// # Errors
/// [`io::ErrorKind::NotFound`] if neither yields an absolute path a
/// configuration value admits.
pub fn scratch_root() -> io::Result<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(|workspace| workspace.join(SCRATCH_ROOT));
    if let Some(root) = workspace.filter(|root| is_configuration_path(root)) {
        return Ok(root);
    }
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(SCRATCH_ROOT))
        .filter(|root| is_configuration_path(root))
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}

/// A unique scratch directory under [`scratch_root`], mode 0700, removed
/// (with its content) on drop.
#[derive(Debug)]
pub struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    /// Create `<root>/<tag>-<pid>-<n>` under [`scratch_root`] (the root too,
    /// if absent), both mode 0700. A leftover directory of the same name is
    /// removed first.
    ///
    /// # Errors
    /// Any I/O failure creating or setting the permissions of either.
    pub fn new(tag: &str) -> io::Result<ScratchDir> {
        let root = scratch_root()?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(OWNER_ONLY)
            .create(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(OWNER_ONLY))?;
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!("{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::DirBuilder::new().mode(OWNER_ONLY).create(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(OWNER_ONLY))?;
        Ok(ScratchDir { path })
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `name` inside the directory.
    #[must_use]
    pub fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.path.join(name)
    }

    /// The directory's owner: the account running the test.
    ///
    /// # Errors
    /// The directory could not be inspected.
    pub fn uid(&self) -> io::Result<u32> {
        Ok(std::fs::metadata(&self.path)?.uid())
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
