//! The installer: the filesystem half of step 1 (the pre-check) and steps
//! 3-9 of docs/51 §4.3, writing exactly what the [`Plan`] holds.
//!
//! # Order (docs/51 §4.3 steps 3-9, §4.4)
//!
//! 1. **Pre-check** ([`precheck`]): the staging directory and every file
//!    target are absent (of any kind — a dangling link counts as present);
//!    each one's parent is an existing directory, not a link, writable by
//!    its owner only, and on the staging directory's filesystem (same
//!    device), so every rename is a same-filesystem rename. Re-run at the
//!    start of [`install`].
//! 2. **Staging** (step 3): a new directory, mode 0700, owner root.
//! 3. **Staged files**, each created exclusively without following links,
//!    its mode set exactly, its owner set through [`Ownership`], written,
//!    `fsync`ed: the integrity key (root:0400, 32 octets — step 4); the
//!    database (an empty 0600 file that redb initialises — "if the file
//!    does not exist, or is an empty file, a new database will be
//!    initialized in it", redb 4.5.0 docs.rs — then **one** `WriteTxn` with
//!    every object, committed and read back, module `store`; owner dird,
//!    0600 — step 5); the policy (root:0644 — step 6); every configuration
//!    file (root:0644 — step 7); the manifest (root:0644 — step 8). Then
//!    the staging directory is `fsync`ed.
//! 4. **Install** (step 9): rename into place, never replacing an existing
//!    path (`RENAME_NOREPLACE`): the configuration files, the policy, the
//!    key, the manifest; `fsync` of each target directory; **then the
//!    database, last**, and `fsync` of its directory.
//! 5. The empty staging directory is removed and its parent `fsync`ed.
//!
//! # A crash — or any error — at each point (docs/51 §4.4)
//!
//! The installer never deletes anything but the empty staging directory at
//! the very end. [`InstallState`] names where it stopped:
//!
//! | stopped | state | dird | a re-run |
//! |---|---|---|---|
//! | in the pre-check, or before the staging directory exists | [`InstallState::NothingWritten`] | — | runs |
//! | after the staging directory exists, before the first rename | [`InstallState::StagingOnly`] — only the staging directory (with what was staged) | no database ⇒ does not start | refuses (staging exists) until the operator removes it |
//! | after a rename, before the database's | [`InstallState::PartlyInstalled`] — some of configuration / policy / key / manifest in place, no database | does not start (fail closed) | refuses (targets exist) until the operator removes them |
//! | after the database's rename | [`InstallState::InstalledStagingLeft`] — the domain is complete; the empty staging directory may remain | starts | refuses (targets exist) |
//!
//! Every domain object is in the one committed transaction (D136): there
//! is never half a domain inside the database.
//!
//! Spec: docs/51 §4.3 steps 1, 3-9, §4.4 (R51-2); docs/50 §6.4, §7.1;
//! Q-270 items 1, 3; A-68; A-86 (O_NOFOLLOW); redb 4.5.0 docs.rs
//! `Database::create`.

use core::fmt;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use dirstore::{IntegrityKey, Store};
use rustix::io::Errno;

use crate::configs::Daemon;
use crate::fs;
use crate::input::{FilePath, Paths};
use crate::ownership::{Ownership, OwnershipError, Staged};
use crate::plan::{Owner, Plan};
use crate::store::{check_domain, write_domain, StoreError};

/// A file the run installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    /// A configuration file.
    Config(Daemon),
    /// The policy file.
    Policy,
    /// The integrity key.
    IntegrityKey,
    /// The manifest.
    Manifest,
    /// The database.
    Store,
}

impl Target {
    /// Its name in messages and in the staging directory.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Target::Config(Daemon::Keyd) => "config-keyd",
            Target::Config(Daemon::Dird) => "config-dird",
            Target::Config(Daemon::Kdc) => "config-kdc",
            Target::Config(Daemon::LdapFront) => "config-ldap-front",
            Target::Config(Daemon::Auditd) => "config-auditd",
            Target::Config(Daemon::Admind) => "config-admind",
            Target::Config(Daemon::Keyadm) => "config-keyadm",
            Target::Policy => "policy",
            Target::IntegrityKey => "integrity-key",
            Target::Manifest => "manifest",
            Target::Store => "database",
        }
    }

    /// Where `paths` installs it.
    #[must_use]
    pub fn path(self, paths: &Paths) -> &FilePath {
        match self {
            Target::Config(Daemon::Keyd) => &paths.keyd_config,
            Target::Config(Daemon::Dird) => &paths.dird_config,
            Target::Config(Daemon::Kdc) => &paths.kdc_config,
            Target::Config(Daemon::LdapFront) => &paths.ldap_front_config,
            Target::Config(Daemon::Auditd) => &paths.auditd_config,
            Target::Config(Daemon::Admind) => &paths.admind_config,
            Target::Config(Daemon::Keyadm) => &paths.keyadm_config,
            Target::Policy => &paths.policy,
            Target::IntegrityKey => &paths.integrity_key,
            Target::Manifest => &paths.manifest,
            Target::Store => &paths.database,
        }
    }

    /// Every target, in installation order: the configuration files, the
    /// policy, the key, the manifest, and the database last.
    /// Spec: docs/51 §4.3 step 9 ("configuration files, policy, key,
    /// manifest — and the database last").
    #[must_use]
    pub fn installation_order() -> Vec<Target> {
        let mut order: Vec<Target> = Daemon::ALL.iter().map(|d| Target::Config(*d)).collect();
        order.extend([
            Target::Policy,
            Target::IntegrityKey,
            Target::Manifest,
            Target::Store,
        ]);
        order
    }
}

/// A point the installer reached (reported to [`Progress`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    /// The staging directory exists.
    StagingCreated,
    /// A file is staged (written, owned, synced).
    Staged(Target),
    /// The staging directory is synced.
    StagingSynced,
    /// A file is renamed into place.
    Installed(Target),
    /// The directories of the installed files (all but the database) are
    /// synced.
    TargetsSynced,
    /// The staging directory is removed.
    StagingRemoved,
}

/// The run was halted by its [`Progress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Halt;

/// Told at every [`Step`]. The binary's implementation reports and never
/// halts; a test halts at a chosen step to leave the state a crash at that
/// point leaves (nothing is undone).
pub trait Progress {
    /// `step` was reached.
    ///
    /// # Errors
    /// [`Halt`] stops the installer at once, with no cleanup.
    fn reached(&mut self, step: Step) -> Result<(), Halt>;
}

/// A [`Progress`] that reports nothing and never halts.
#[derive(Debug, Default, Clone, Copy)]
pub struct Silent;

impl Progress for Silent {
    fn reached(&mut self, _step: Step) -> Result<(), Halt> {
        Ok(())
    }
}

/// Where the installer stopped (module documentation, crash table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallState {
    /// Nothing was written.
    NothingWritten,
    /// Only the staging directory (and what was staged in it) exists.
    StagingOnly,
    /// Some targets are in place; the database is not.
    PartlyInstalled,
    /// Every target is in place; the empty staging directory may remain.
    InstalledStagingLeft,
}

impl fmt::Display for InstallState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            InstallState::NothingWritten => "nothing was written",
            InstallState::StagingOnly => {
                "only the staging directory was written; remove it before a re-run"
            }
            InstallState::PartlyInstalled => {
                "some files were installed but not the database; dird will not start; remove the installed files and the staging directory before a re-run"
            }
            InstallState::InstalledStagingLeft => {
                "every file was installed; the empty staging directory may remain"
            }
        })
    }
}

/// Why the installer stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallCause {
    /// A path that must be absent exists (the flag's name).
    Exists(PathBuf),
    /// A parent directory is missing, is not a directory, or is a link.
    Parent(PathBuf),
    /// A parent directory is writable by its group or by others.
    ParentWritable(PathBuf),
    /// A parent directory is not on the staging directory's filesystem.
    OtherFilesystem(PathBuf),
    /// A filesystem operation failed.
    Io(&'static str, Errno),
    /// Writing a staged file failed.
    Write(std::io::ErrorKind),
    /// A file was not a regular file where one was expected.
    NotRegular(PathBuf),
    /// The owner of a staged file could not be changed.
    Ownership(OwnershipError),
    /// The database could not be written or did not check out.
    Store(StoreError),
    /// The run was halted by its progress observer.
    Halted(Step),
}

impl fmt::Display for InstallCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstallCause::Exists(p) => {
                write!(f, "{} exists (provision never overwrites)", p.display())
            }
            InstallCause::Parent(p) => write!(
                f,
                "{}: parent directory missing or not a directory",
                p.display()
            ),
            InstallCause::ParentWritable(p) => {
                write!(
                    f,
                    "{}: parent directory is writable by group or others",
                    p.display()
                )
            }
            InstallCause::OtherFilesystem(p) => {
                write!(
                    f,
                    "{}: not on the staging directory's filesystem",
                    p.display()
                )
            }
            InstallCause::Io(op, e) => write!(f, "{op} failed: {e}"),
            InstallCause::Write(kind) => write!(f, "write failed: {kind}"),
            InstallCause::NotRegular(p) => write!(f, "{}: not a regular file", p.display()),
            InstallCause::Ownership(e) => write!(f, "{e}"),
            InstallCause::Store(e) => write!(f, "{e}"),
            InstallCause::Halted(step) => write!(f, "halted at {step:?}"),
        }
    }
}

/// An installer error: where it stopped, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallError {
    /// The state left behind.
    pub state: InstallState,
    /// The cause.
    pub cause: InstallCause,
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.cause, self.state)
    }
}

impl std::error::Error for InstallError {}

/// What was installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// Each target and its path, in installation order.
    pub targets: Vec<(Target, FilePath)>,
}

/// `true` if something (anything, a dangling link included) is at `path`.
fn present(path: &Path) -> Result<bool, InstallCause> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(InstallCause::Parent(path.to_path_buf())),
    }
}

/// The parent directory's device, after checking it is an existing
/// directory, not a link, and not writable by group or others.
fn parent_device(parent: &Path) -> Result<u64, InstallCause> {
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| InstallCause::Parent(parent.to_path_buf()))?;
    if !metadata.file_type().is_dir() {
        return Err(InstallCause::Parent(parent.to_path_buf()));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(InstallCause::ParentWritable(parent.to_path_buf()));
    }
    Ok(metadata.dev())
}

/// The filesystem half of step 1 (module documentation, item 1): nothing is
/// written.
///
/// # Errors
/// [`InstallError`] in state [`InstallState::NothingWritten`].
///
/// Spec: docs/51 §4.3 step 1 ("every target path absent (including the
/// staging directory)"), step 3 ("on the same filesystem as the targets"),
/// §4.4 (no `--force`).
pub fn precheck(paths: &Paths) -> Result<(), InstallError> {
    let stop = |cause| InstallError {
        state: InstallState::NothingWritten,
        cause,
    };
    let staging = paths.staging.as_path();
    if present(staging).map_err(stop)? {
        return Err(stop(InstallCause::Exists(staging.to_path_buf())));
    }
    let device = parent_device(paths.staging.parent()).map_err(stop)?;
    for target in Target::installation_order() {
        let path = target.path(paths);
        if present(path.as_path()).map_err(stop)? {
            return Err(stop(InstallCause::Exists(path.as_path().to_path_buf())));
        }
        if parent_device(path.parent()).map_err(stop)? != device {
            return Err(stop(InstallCause::OtherFilesystem(
                path.as_path().to_path_buf(),
            )));
        }
    }
    Ok(())
}

/// The installer's running state.
struct Run<'p, O: Ownership, P: Progress> {
    plan: &'p Plan,
    ownership: &'p mut O,
    progress: &'p mut P,
    state: InstallState,
}

impl<O: Ownership, P: Progress> Run<'_, O, P> {
    /// An error in the current state.
    fn fail(&self, cause: InstallCause) -> InstallError {
        InstallError {
            state: self.state,
            cause,
        }
    }

    /// Report `step`; a halt stops here.
    fn reached(&mut self, step: Step) -> Result<(), InstallError> {
        self.progress
            .reached(step)
            .map_err(|Halt| self.fail(InstallCause::Halted(step)))
    }

    /// A filesystem result in the current state.
    fn io<T>(&self, op: &'static str, result: Result<T, Errno>) -> Result<T, InstallError> {
        result.map_err(|e| self.fail(InstallCause::Io(op, e)))
    }

    /// The staged path of `target`.
    fn staged(&self, target: Target) -> PathBuf {
        self.plan.paths.staging.as_path().join(target.name())
    }

    /// Stage one plain file: create exclusively with `mode`, write `bytes`,
    /// give it `owner`, `fsync`.
    /// Spec: docs/51 §4.3 steps 4, 6-8; module documentation item 3.
    fn stage_file(
        &mut self,
        target: Target,
        staged: Staged,
        mode: rustix::fs::Mode,
        owner: Owner,
        bytes: &[u8],
    ) -> Result<(), InstallError> {
        let path = self.staged(target);
        let mut file = self.io("create", fs::create_new_file(&path, mode))?;
        file.write_all(bytes)
            .map_err(|e| self.fail(InstallCause::Write(e.kind())))?;
        self.ownership
            .change_owner(file.as_fd(), staged, owner)
            .map_err(|e| InstallError {
                state: self.state,
                cause: InstallCause::Ownership(e),
            })?;
        self.io("fsync", fs::sync(&file))?;
        drop(file);
        self.reached(Step::Staged(target))
    }

    /// Stage the database (module documentation item 3).
    /// Spec: docs/51 §4.3 step 5; Q-270 item 3 (dird's account, no group /
    /// other access); module `store`.
    fn stage_store(&mut self) -> Result<(), InstallError> {
        let path = self.staged(Target::Store);
        let empty = self.io("create", fs::create_new_file(&path, fs::mode_0600()))?;
        drop(empty);
        {
            let schema = ad_schema::phase1()
                .map_err(|_| self.fail(InstallCause::Store(StoreError::Store("schema"))))?;
            let key = IntegrityKey::from_bytes(self.plan.integrity_key().bytes());
            let store = Store::open(&path, key, schema.schema().clone())
                .map_err(|_| self.fail(InstallCause::Store(StoreError::Store("open"))))?;
            write_domain(&store, self.plan).map_err(|e| self.fail(InstallCause::Store(e)))?;
            check_domain(&store, self.plan).map_err(|e| self.fail(InstallCause::Store(e)))?;
        }
        let file = self.io("open", fs::open_no_follow(&path))?;
        let metadata = file
            .metadata()
            .map_err(|_| self.fail(InstallCause::NotRegular(path.clone())))?;
        if !metadata.file_type().is_file() {
            return Err(self.fail(InstallCause::NotRegular(path)));
        }
        self.io("fchmod", rustix::fs::fchmod(&file, fs::mode_0600()))?;
        let owner = self.plan.store_owner;
        self.ownership
            .change_owner(file.as_fd(), Staged::Store, owner)
            .map_err(|e| InstallError {
                state: self.state,
                cause: InstallCause::Ownership(e),
            })?;
        self.io("fsync", fs::sync(&file))?;
        drop(file);
        self.reached(Step::Staged(Target::Store))
    }

    /// Rename one staged file into place (never replacing).
    /// Spec: docs/51 §4.3 step 9, §4.4.
    fn install_one(&mut self, target: Target) -> Result<(), InstallError> {
        let from = self.staged(target);
        let to = target.path(&self.plan.paths).as_path().to_path_buf();
        self.io("rename", fs::rename_no_replace(&from, &to))?;
        self.state = if target == Target::Store {
            InstallState::InstalledStagingLeft
        } else {
            InstallState::PartlyInstalled
        };
        self.reached(Step::Installed(target))
    }
}

/// Write the plan (module documentation, items 1-5).
///
/// # Errors
/// [`InstallError`], naming the state left behind.
///
/// Spec: docs/51 §4.3 steps 3-9, §4.4.
pub fn install<O: Ownership, P: Progress>(
    plan: &Plan,
    ownership: &mut O,
    progress: &mut P,
) -> Result<Installed, InstallError> {
    precheck(&plan.paths)?;
    let mut run = Run {
        plan,
        ownership,
        progress,
        state: InstallState::NothingWritten,
    };
    let staging = plan.paths.staging.as_path();

    // Step 3: the staging directory (root, 0700).
    let dir = match fs::create_new_dir(staging, fs::mode_0700()) {
        Ok(dir) => dir,
        Err(e) => {
            // If mkdir itself failed nothing exists; otherwise the
            // directory was created and is left (fail closed: never
            // removed here).
            let state = match present(staging) {
                Ok(false) => InstallState::NothingWritten,
                _ => InstallState::StagingOnly,
            };
            return Err(InstallError {
                state,
                cause: InstallCause::Io("mkdir", e),
            });
        }
    };
    run.state = InstallState::StagingOnly;
    run.ownership
        .change_owner(dir.as_fd(), Staged::StagingDirectory, Owner::ROOT)
        .map_err(|e| InstallError {
            state: InstallState::StagingOnly,
            cause: InstallCause::Ownership(e),
        })?;
    drop(dir);
    run.reached(Step::StagingCreated)?;

    // Step 4: the integrity key (root:0400, 32 octets), written straight
    // from the plan's zeroizing buffer (no copy).
    run.stage_file(
        Target::IntegrityKey,
        Staged::IntegrityKey,
        fs::mode_0400(),
        Owner::ROOT,
        plan.integrity_key().bytes().as_slice(),
    )?;
    // Step 5: the database (dird, 0600).
    run.stage_store()?;
    // Step 6: the policy (root:0644).
    run.stage_file(
        Target::Policy,
        Staged::Policy,
        fs::mode_0644(),
        Owner::ROOT,
        &plan.policy_file,
    )?;
    // Step 7: the configuration files (root:0644).
    for file in &plan.configs {
        run.stage_file(
            Target::Config(file.daemon),
            Staged::Config(file.daemon),
            fs::mode_0644(),
            Owner::ROOT,
            file.text().as_bytes(),
        )?;
    }
    // Step 8: the manifest (root:0644).
    run.stage_file(
        Target::Manifest,
        Staged::Manifest,
        fs::mode_0644(),
        Owner::ROOT,
        plan.manifest.encode().as_bytes(),
    )?;
    run.io("fsync", fs::sync_dir(staging))?;
    run.reached(Step::StagingSynced)?;

    // Step 9: rename into place, the database last.
    let order = Target::installation_order();
    let (before, last) = order.split_at(order.len().saturating_sub(1));
    let mut synced: Vec<&Path> = Vec::new();
    for target in before {
        run.install_one(*target)?;
    }
    for target in before {
        let parent = target.path(&plan.paths).parent();
        if !synced.contains(&parent) {
            run.io("fsync", fs::sync_dir(parent))?;
            synced.push(parent);
        }
    }
    run.reached(Step::TargetsSynced)?;
    for target in last {
        run.install_one(*target)?;
        run.io("fsync", fs::sync_dir(target.path(&plan.paths).parent()))?;
    }

    // The empty staging directory.
    run.io("rmdir", fs::remove_dir(staging))?;
    run.io("fsync", fs::sync_dir(plan.paths.staging.parent()))?;
    run.reached(Step::StagingRemoved)?;

    Ok(Installed {
        targets: order
            .iter()
            .map(|t| (*t, t.path(&plan.paths).clone()))
            .collect(),
    })
}
