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
//! # Tier 3 (root)
//!
//! The tier-3 tests (docs/50 §9: "only as root in an isolated environment,
//! `#[ignore]` by default") read root's fixtures with root as the expected
//! owner — so **every** directory from `/` must be root's (Q-480 item 5) —
//! and some start daemons that drop to their own accounts and then walk to
//! their data files and sockets themselves: the walk opens every directory
//! `O_RDONLY`, so those accounts need read and search permission on each
//! one (Q-482 item 6). A [`ScratchDir`] made by [`ScratchDir::new_tier3`] is
//! `<workspace>/.test-scratch-tier3/<tag>-<pid>-<n>`: the root and the
//! directory root's, mode exactly 0755 — never `$HOME` (under `/root`,
//! mode 0700, no other account could walk it) and never the temporary
//! directory (`/tmp` is 1777, refused by the directory rule). Before it
//! makes anything it checks that every directory above the root is a
//! directory (not a link) owned by root, not writable by group or others,
//! readable and searchable by others, and that the process is root, and
//! otherwise refuses with [`HOW_TO_RUN_TIER3`] instead of leaving a test to
//! fail later on a protected-file refusal that does not name the
//! directory. `/.test-scratch-tier3/` is ignored by git (docs/questions
//! Q-680).
//!
//! Spec: docs/52 §3.13 (R11), §3.18 (C18: no test seam in a product API);
//! docs/50 §9 (tier 3); Q-468; Q-480; Q-482 item 6; Q-680. Std API only.

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

/// The directory name of the tier-3 root under the workspace (module
/// documentation, "Tier 3"). Spec: docs/50 §9; Q-680.
const TIER3_ROOT: &str = ".test-scratch-tier3";

/// The mode of the tier-3 root and of each tier-3 scratch directory:
/// written by root alone, read and searched by every account — the daemons'
/// accounts walk these directories after their privilege drop, and the walk
/// opens each one `O_RDONLY` — and not writable by group or others, which
/// the directory rule refuses. Spec: Q-482 item 6; Q-468 option 2(b).
const TIER3_MODE: u32 = 0o755;

/// Write permission for group and for others: what no directory on a
/// protected path may have. Spec: Q-468 option 2(b) (A-102).
const GROUP_OR_OTHER_WRITE: u32 = 0o022;

/// Read and search permission for others: what every directory above a
/// tier-3 scratch directory needs, so that a daemon's account can walk it
/// after its drop. Spec: Q-482 item 6.
const OTHER_READ_SEARCH: u32 = 0o005;

/// The permission bits of a mode, for the refusal text.
const PERMISSION_BITS: u32 = 0o7777;

/// Root's uid: the owner of every directory above a tier-3 scratch
/// directory and of the directory itself. Spec: Q-480 item 5; Q-468 option
/// 2(b) (with root as the file's owner, only root's directories pass).
const ROOT_UID: u32 = 0;

/// How the tier-3 tests must be run; the end of every refusal of
/// [`ScratchDir::new_tier3`] (module documentation, "Tier 3"; Q-680).
pub const HOW_TO_RUN_TIER3: &str = "tier 3 runs as root, on Linux, in an isolated machine, \
     from a checkout copied as root (every file and directory root's) to a path of only \
     `A-Z a-z 0-9 . _ - /` whose every directory from `/` is root's, mode 0755 — e.g. /srv/lds, \
     not under /root (mode 0700): the daemons' accounts walk the path after their privilege drop \
     (crates/test-scratch, ScratchDir::new_tier3; docs/questions/Q-680)";

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
    let workspace = workspace().map(|workspace| workspace.join(SCRATCH_ROOT));
    if let Some(root) = workspace.filter(|root| is_configuration_path(root)) {
        return Ok(root);
    }
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(SCRATCH_ROOT))
        .filter(|root| is_configuration_path(root))
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}

/// The workspace: two levels above this crate's manifest directory
/// (`crates/test-scratch`). Spec: Q-480 item 2.
fn workspace() -> Option<&'static Path> {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2)
}

/// `<workspace>/.test-scratch-tier3` — the workspace only, never `$HOME`
/// (module documentation, "Tier 3").
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] when that path cannot appear in a
/// configuration value (the tier-3 tests put scratch paths into auditd's
/// configuration).
///
/// Spec: docs/50 §9; Q-230 item 16; Q-680.
pub fn tier3_root() -> io::Result<PathBuf> {
    let root = workspace().map(|workspace| workspace.join(TIER3_ROOT));
    match root {
        Some(root) if is_configuration_path(&root) => Ok(root),
        Some(root) => Err(tier3_refusal(
            io::ErrorKind::InvalidInput,
            &format!(
                "{} holds an octet a configuration path does not admit",
                root.display()
            ),
        )),
        None => Err(tier3_refusal(
            io::ErrorKind::InvalidInput,
            "the workspace has no path",
        )),
    }
}

/// A refusal of [`ScratchDir::new_tier3`]: what was found, then
/// [`HOW_TO_RUN_TIER3`].
fn tier3_refusal(kind: io::ErrorKind, found: &str) -> io::Error {
    io::Error::new(
        kind,
        format!("tier-3 scratch refused: {found}; {HOW_TO_RUN_TIER3}"),
    )
}

/// Every directory above `root`, from `/` down: a directory (inspected
/// without following a link), owned by root, not writable by group or
/// others — the directory rule with root as the file's owner, as the
/// production readers apply it — and readable and searchable by others, so
/// that a daemon's account can walk it after its drop.
///
/// # Errors
/// [`io::ErrorKind::PermissionDenied`] naming the first directory that is
/// not, or the error of its inspection.
///
/// Spec: Q-468 options 1, 2(b) (A-102); Q-480 item 5; Q-482 item 6.
fn check_tier3_ancestors(root: &Path) -> io::Result<()> {
    let above: Vec<&Path> = root.ancestors().skip(1).collect();
    for directory in above.into_iter().rev() {
        let facts = std::fs::symlink_metadata(directory)?;
        let mode = facts.mode();
        let accepted = facts.file_type().is_dir()
            && facts.uid() == ROOT_UID
            && mode & GROUP_OR_OTHER_WRITE == 0
            && mode & OTHER_READ_SEARCH == OTHER_READ_SEARCH;
        if !accepted {
            return Err(tier3_refusal(
                io::ErrorKind::PermissionDenied,
                &format!(
                    "{} (owner {}, mode {:o}{}) is not a directory of root's, mode 0755",
                    directory.display(),
                    facts.uid(),
                    mode & PERMISSION_BITS,
                    if facts.file_type().is_symlink() {
                        ", a symbolic link"
                    } else {
                        ""
                    }
                ),
            ));
        }
    }
    Ok(())
}

/// The refusal of a creation that failed for want of permission: only root
/// may create entries in root's 0755 directories.
fn needs_root(path: &Path, error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::PermissionDenied {
        tier3_refusal(
            io::ErrorKind::PermissionDenied,
            &format!("{} cannot be created: not running as root", path.display()),
        )
    } else {
        error
    }
}

/// A unique scratch directory under [`scratch_root`], mode 0700 — or, made
/// by [`ScratchDir::new_tier3`], under [`tier3_root`], root's, mode 0755 —
/// removed (with its content) on drop.
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

    /// For a tier-3 test run as root (module documentation, "Tier 3"):
    /// check every directory above [`tier3_root`] (root's, not writable by
    /// group or others, readable and searchable by others — not a link),
    /// create the root if absent (it must then be a directory of root's,
    /// not a link), create `<root>/<tag>-<pid>-<n>` (a leftover of the same
    /// name removed first) and check that it is root's — the process is
    /// root — then set both to mode exactly 0755.
    ///
    /// # Errors
    /// A refusal ending in [`HOW_TO_RUN_TIER3`]
    /// ([`io::ErrorKind::InvalidInput`] for a workspace path a configuration
    /// value does not admit, [`io::ErrorKind::PermissionDenied`] for a
    /// directory above the root that is not root's 0755, a root that is not
    /// a directory of root's, or a process that is not root), or any other
    /// I/O failure.
    ///
    /// Spec: docs/50 §9 (tier 3: "only as root in an isolated
    /// environment"); Q-468 option 2(b); Q-480 item 5; Q-482 item 6; Q-680.
    pub fn new_tier3(tag: &str) -> io::Result<ScratchDir> {
        let root = tier3_root()?;
        check_tier3_ancestors(&root)?;
        match std::fs::DirBuilder::new().mode(TIER3_MODE).create(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(needs_root(&root, error)),
        }
        let facts = std::fs::symlink_metadata(&root)?;
        if !facts.file_type().is_dir() || facts.uid() != ROOT_UID {
            return Err(tier3_refusal(
                io::ErrorKind::PermissionDenied,
                &format!(
                    "{} (owner {}) is not a directory of root's",
                    root.display(),
                    facts.uid()
                ),
            ));
        }
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!("{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::DirBuilder::new()
            .mode(TIER3_MODE)
            .create(&path)
            .map_err(|error| needs_root(&path, error))?;
        // From here on the directory is removed on drop, whatever fails.
        let scratch = ScratchDir { path };
        let owner = std::fs::symlink_metadata(scratch.path())?.uid();
        if owner != ROOT_UID {
            return Err(tier3_refusal(
                io::ErrorKind::PermissionDenied,
                &format!("not running as root (uid {owner})"),
            ));
        }
        let mode = std::fs::Permissions::from_mode(TIER3_MODE);
        std::fs::set_permissions(&root, mode.clone())?;
        std::fs::set_permissions(scratch.path(), mode)?;
        Ok(scratch)
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

#[cfg(test)]
mod tests {
    use super::*;

    // Source: docs/50 §9 (tier 3: "only as root in an isolated
    // environment"); Q-680 — for an ordinary account `new_tier3` refuses
    // (the workspace path is no configuration path, a directory above the
    // root is not root's 0755, or the process is not root), with a refusal
    // that says how tier 3 must be run. As root (a root-owned checkout may
    // grant it) there is nothing to show.
    #[test]
    fn a_tier3_directory_is_refused_to_an_ordinary_account() {
        let uid = ScratchDir::new("t3probe").unwrap().uid().unwrap();
        if uid == ROOT_UID {
            return;
        }
        let refusal = ScratchDir::new_tier3("t3probe").unwrap_err();
        assert!(refusal.to_string().ends_with(HOW_TO_RUN_TIER3), "{refusal}");
    }

    // Source: Q-468 option 2(b) with root as the file's owner; Q-480 item 5
    // — above an ordinary account's scratch directory (its own, so at least
    // that directory is not root's) the check refuses the first directory
    // that is not root's 0755, names it with its owner and mode, and says
    // how to run tier 3.
    #[test]
    fn a_directory_of_an_ordinary_account_above_is_named() {
        let scratch = ScratchDir::new("t3above").unwrap();
        if scratch.uid().unwrap() == ROOT_UID {
            return;
        }
        let refusal = check_tier3_ancestors(&scratch.join("root")).unwrap_err();
        assert_eq!(refusal.kind(), io::ErrorKind::PermissionDenied);
        let text = refusal.to_string();
        assert!(text.starts_with("tier-3 scratch refused: /"), "{text}");
        assert!(text.contains(" (owner "), "{text}");
        assert!(
            text.contains(") is not a directory of root's, mode 0755; "),
            "{text}"
        );
        assert!(text.ends_with(HOW_TO_RUN_TIER3), "{text}");
    }
}
