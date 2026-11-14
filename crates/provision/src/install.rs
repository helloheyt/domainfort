//! The installer: the filesystem half of step 1 (the pre-check) and steps
//! 3-9 of docs/51 §4.3, writing exactly what the [`Plan`] holds.
//!
//! # Order (docs/51 §4.3 steps 3-9, §4.4)
//!
//! 1. **Pre-check** ([`precheck`]): the staging directory and every file
//!    target are absent (of any kind — a dangling link counts as present);
//!    each one's parent is on the staging directory's filesystem (same
//!    device), so every rename is a same-filesystem rename. Every path is
//!    walked from `/` (crates/protected-file, task R11c): no directory
//!    component may be a link, and every directory must be owned by root
//!    and not be writable by group or others — the database's too (its
//!    file is dird's, its directories root's: dird needs only the file,
//!    docs/50 §6.4). Re-run at the start of [`install`].
//! 2. **Staging** (step 3): a new directory, mode 0700, owner root.
//! 3. **Staged files**, each created exclusively without following links,
//!    its mode set exactly, its owner set through [`Ownership`], written,
//!    `fsync`ed: the integrity key (root:0400, 32 octets — step 4); the
//!    database (an empty 0600 file created for reading and writing, handed
//!    **as that descriptor** to dirstore `Store::open_file` — redb's
//!    `create_with_backend` initialises it, "Open an existing or create a
//!    new database with the given backend", redb 4.5.0 docs.rs — then
//!    **one** `WriteTxn` with every object, committed and read back, module
//!    `store`; owner dird, 0600 — step 5); the policy (root:0644 — step
//!    6); every configuration file (root:0644 — step 7); the manifest
//!    (root:0644 — step 8). Then the staging directory is `fsync`ed.
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
//! # Every operation relative to a walked directory (task R11c)
//!
//! Each creation, rename, removal and `fsync` goes through
//! crates/protected-file (`entry_facts`, `directory_device`,
//! `create_new_directory`, `create_new_file`, `create_new_read_write`,
//! `rename_no_replace`, `remove_empty_directory`, `sync_directory`): the
//! path is walked from `/` under the directory rule and the operation is the
//! `*at` call relative to the walked directory's descriptor — never a lookup
//! of the path from the current directory, so no directory component is
//! followed through a link (docs/52 C13; docs/questions Q-532 item 2,
//! A-109). The database is staged on a descriptor and never reopened by
//! path.
//!
//! Spec: docs/51 §4.3 steps 1, 3-9, §4.4 (R51-2); docs/50 §6.4, §7.1;
//! Q-270 items 1, 3; A-68; A-86 (O_NOFOLLOW); A-109 (Q-532 item 2, task
//! R11c); docs/questions Q-468 option 2(b); redb 4.5.0 docs.rs
//! `Builder::create_with_backend`; std `File::try_clone`.

use core::fmt;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use dirstore::{IntegrityKey, Store};
use protected_file::{EntryError, NewFileMode, OpenError, PathBreak};

use crate::configs::Daemon;
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
    /// A directory on the path is missing, is not a directory, or is a
    /// link — or the path does not end in a file name.
    Parent(PathBuf),
    /// A directory on the path is writable by its group or by others.
    ParentWritable(PathBuf),
    /// A directory on the path is owned by neither root nor the account the
    /// file ends up owned by (task R11c).
    ParentOwner(PathBuf),
    /// A parent directory is not on the staging directory's filesystem.
    OtherFilesystem(PathBuf),
    /// A filesystem operation failed (the system's error kind).
    Io(&'static str, io::ErrorKind),
    /// Writing a staged file failed.
    Write(std::io::ErrorKind),
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
                "{}: a directory on its path is missing, a symbolic link or not a directory",
                p.display()
            ),
            InstallCause::ParentWritable(p) => {
                write!(
                    f,
                    "{}: a directory on its path is writable by group or others",
                    p.display()
                )
            }
            InstallCause::ParentOwner(p) => {
                write!(
                    f,
                    "{}: a directory on its path is owned by neither root nor the file's owner",
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

/// The cause for a directory on `path` that broke crates/protected-file's
/// directory rule.
/// Spec: Q-468 options 1, 2(b) (A-102); docs/51 §4.4.
fn path_cause(path: &Path, broken: PathBreak) -> InstallCause {
    let path = path.to_path_buf();
    match broken {
        PathBreak::NoFileName | PathBreak::NotADirectory => InstallCause::Parent(path),
        PathBreak::DirectoryWrongOwner => InstallCause::ParentOwner(path),
        PathBreak::DirectoryWritableByGroupOrOthers => InstallCause::ParentWritable(path),
    }
}

/// The cause for a failed walk of `path` before anything was written: a
/// directory rule broken, or a directory missing or uninspectable.
fn walk_cause(path: &Path, error: EntryError) -> InstallCause {
    match error {
        EntryError::Path(broken) => path_cause(path, broken),
        EntryError::Io(_) => InstallCause::Parent(path.to_path_buf()),
    }
}

/// `true` if something (anything, a dangling link included) is at `path` —
/// inspected relative to its walked directory, with `owner_uid` as the
/// owner the directory rule admits besides root.
/// Spec: docs/51 §4.3 step 1; crates/protected-file `entry_facts`.
fn present(path: &Path, owner_uid: u32) -> Result<bool, InstallCause> {
    protected_file::entry_facts(path, owner_uid)
        .map(|facts| facts.is_some())
        .map_err(|error| walk_cause(path, error))
}

/// The device of the walked directory `parent` (every directory on its
/// path checked, itself included).
/// Spec: docs/51 §4.3 step 3; crates/protected-file `directory_device`.
fn parent_device(parent: &Path, owner_uid: u32) -> Result<protected_file::Device, InstallCause> {
    protected_file::directory_device(parent, owner_uid).map_err(|error| walk_cause(parent, error))
}

/// The filesystem half of step 1 (module documentation, item 1): nothing is
/// written. `root_uid` is the account root-owned files belong to (0 in
/// production; [`Ownership::root_uid`]): every directory on every path must
/// be root's (or, in a test, that stand-in's) — the directory rule's "root or
/// the file's owner" with root as the owner of everything the installer
/// writes until the last owner change (Q-468 option 2(b)).
///
/// # Errors
/// [`InstallError`] in state [`InstallState::NothingWritten`].
///
/// Spec: docs/51 §4.3 step 1 ("every target path absent (including the
/// staging directory)"), step 3 ("on the same filesystem as the targets"),
/// §4.4 (no `--force`); Q-468 (A-102); Q-532 item 2 (A-109).
pub fn precheck(paths: &Paths, root_uid: u32) -> Result<(), InstallError> {
    let stop = |cause| InstallError {
        state: InstallState::NothingWritten,
        cause,
    };
    let staging = paths.staging.as_path();
    if present(staging, root_uid).map_err(stop)? {
        return Err(stop(InstallCause::Exists(staging.to_path_buf())));
    }
    let device = parent_device(paths.staging.parent(), root_uid).map_err(stop)?;
    for target in Target::installation_order() {
        let path = target.path(paths);
        if present(path.as_path(), root_uid).map_err(stop)? {
            return Err(stop(InstallCause::Exists(path.as_path().to_path_buf())));
        }
        if parent_device(path.parent(), root_uid).map_err(stop)? != device {
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
    /// The account root-owned files belong to ([`Ownership::root_uid`]).
    root_uid: u32,
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

    /// The result of a crates/protected-file operation on `path`, in the
    /// current state: a directory rule broken names the path; a system
    /// failure names the operation.
    fn entry<T>(
        &self,
        op: &'static str,
        path: &Path,
        result: Result<T, EntryError>,
    ) -> Result<T, InstallError> {
        result.map_err(|error| {
            self.fail(match error {
                EntryError::Path(broken) => path_cause(path, broken),
                EntryError::Io(kind) => InstallCause::Io(op, kind),
            })
        })
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
        mode: NewFileMode,
        owner: Owner,
        bytes: &[u8],
    ) -> Result<(), InstallError> {
        let path = self.staged(target);
        let mut file = self.entry(
            "create",
            &path,
            protected_file::create_new_file(&path, self.root_uid, mode),
        )?;
        file.write_all(bytes)
            .map_err(|e| self.fail(InstallCause::Write(e.kind())))?;
        self.ownership
            .change_owner(file.as_fd(), staged, owner)
            .map_err(|e| InstallError {
                state: self.state,
                cause: InstallCause::Ownership(e),
            })?;
        self.sync(&file)?;
        drop(file);
        self.reached(Step::Staged(target))
    }

    /// `fsync` a staged file's descriptor.
    /// Spec: rustix docs.rs `fs::fsync` ("Ensures that file data and
    /// metadata is written to the underlying storage device").
    fn sync(&self, file: &std::fs::File) -> Result<(), InstallError> {
        rustix::fs::fsync(file).map_err(|errno| self.fail(InstallCause::Io("fsync", errno.kind())))
    }

    /// Stage the database (module documentation item 3): one descriptor,
    /// created exclusively (0600, read and write), from which redb builds
    /// the store and on which — after the store is closed — the owner is
    /// changed and the data synced. The file is never reopened by path.
    /// Spec: docs/51 §4.3 step 5; Q-270 item 3 (dird's account, no group /
    /// other access); module `store`; docs/questions Q-532 item 3 (A-109);
    /// dirstore `Store::open_file`; std `File::try_clone` (a second handle
    /// to the same open file).
    fn stage_store(&mut self) -> Result<(), InstallError> {
        let path = self.staged(Target::Store);
        let file = self.entry(
            "create",
            &path,
            protected_file::create_new_read_write(&path, self.root_uid),
        )?;
        let kept = file
            .try_clone()
            .map_err(|e| self.fail(InstallCause::Io("dup", e.kind())))?;
        {
            let schema = ad_schema::phase1()
                .map_err(|_| self.fail(InstallCause::Store(StoreError::Store("schema"))))?;
            let key = IntegrityKey::from_bytes(self.plan.integrity_key().bytes());
            let store = Store::open_file(file, key, schema.schema().clone())
                .map_err(|_| self.fail(InstallCause::Store(StoreError::Store("open"))))?;
            write_domain(&store, self.plan).map_err(|e| self.fail(InstallCause::Store(e)))?;
            check_domain(&store, self.plan).map_err(|e| self.fail(InstallCause::Store(e)))?;
        }
        let owner = self.plan.store_owner;
        self.ownership
            .change_owner(kept.as_fd(), Staged::Store, owner)
            .map_err(|e| InstallError {
                state: self.state,
                cause: InstallCause::Ownership(e),
            })?;
        self.sync(&kept)?;
        drop(kept);
        self.reached(Step::Staged(Target::Store))
    }

    /// Rename one staged file into place (never replacing).
    /// Spec: docs/51 §4.3 step 9, §4.4.
    fn install_one(&mut self, target: Target) -> Result<(), InstallError> {
        let from = self.staged(target);
        let to = target.path(&self.plan.paths).as_path().to_path_buf();
        self.entry(
            "rename",
            &to,
            protected_file::rename_no_replace(&from, self.root_uid, &to, self.root_uid),
        )?;
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
    let root_uid = ownership.root_uid();
    precheck(&plan.paths, root_uid)?;
    let mut run = Run {
        plan,
        ownership,
        progress,
        state: InstallState::NothingWritten,
        root_uid,
    };
    let staging = plan.paths.staging.as_path();

    // Step 3: the staging directory (root, 0700), created relative to its
    // walked parent; its owner given on its own descriptor.
    let created = {
        let ownership = &mut *run.ownership;
        protected_file::create_new_directory(staging, root_uid, |fd| {
            ownership.change_owner(fd, Staged::StagingDirectory, Owner::ROOT)
        })
    };
    if let Err(error) = created {
        // If mkdir itself failed nothing exists; otherwise the directory
        // was created and is left (fail closed: never removed here).
        let state = match present(staging, root_uid) {
            Ok(false) => InstallState::NothingWritten,
            _ => InstallState::StagingOnly,
        };
        return Err(InstallError {
            state,
            cause: match error {
                OpenError::Io(kind) => InstallCause::Io("mkdir", kind),
                OpenError::Path(broken) => path_cause(staging, broken),
                OpenError::Refused(e) => InstallCause::Ownership(e),
            },
        });
    }
    run.state = InstallState::StagingOnly;
    run.reached(Step::StagingCreated)?;

    // Step 4: the integrity key (root:0400, 32 octets), written straight
    // from the plan's zeroizing buffer (no copy).
    run.stage_file(
        Target::IntegrityKey,
        Staged::IntegrityKey,
        NewFileMode::OwnerRead,
        Owner::ROOT,
        plan.integrity_key().bytes().as_slice(),
    )?;
    // Step 5: the database (dird, 0600).
    run.stage_store()?;
    // Step 6: the policy (root:0644).
    run.stage_file(
        Target::Policy,
        Staged::Policy,
        NewFileMode::OwnerWriteEveryoneRead,
        Owner::ROOT,
        &plan.policy_file,
    )?;
    // Step 7: the configuration files (root:0644).
    for file in &plan.configs {
        run.stage_file(
            Target::Config(file.daemon),
            Staged::Config(file.daemon),
            NewFileMode::OwnerWriteEveryoneRead,
            Owner::ROOT,
            file.text().as_bytes(),
        )?;
    }
    // Step 8: the manifest (root:0644).
    run.stage_file(
        Target::Manifest,
        Staged::Manifest,
        NewFileMode::OwnerWriteEveryoneRead,
        Owner::ROOT,
        plan.manifest.encode().as_bytes(),
    )?;
    run.entry(
        "fsync",
        staging,
        protected_file::sync_directory(staging, root_uid),
    )?;
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
            run.entry(
                "fsync",
                parent,
                protected_file::sync_directory(parent, root_uid),
            )?;
            synced.push(parent);
        }
    }
    run.reached(Step::TargetsSynced)?;
    for target in last {
        run.install_one(*target)?;
        let parent = target.path(&plan.paths).parent();
        run.entry(
            "fsync",
            parent,
            protected_file::sync_directory(parent, root_uid),
        )?;
    }

    // The empty staging directory.
    run.entry(
        "rmdir",
        staging,
        protected_file::remove_empty_directory(staging, root_uid),
    )?;
    let staging_parent = plan.paths.staging.parent();
    run.entry(
        "fsync",
        staging_parent,
        protected_file::sync_directory(staging_parent, root_uid),
    )?;
    run.reached(Step::StagingRemoved)?;

    Ok(Installed {
        targets: order
            .iter()
            .map(|t| (*t, t.path(&plan.paths).clone()))
            .collect(),
    })
}
