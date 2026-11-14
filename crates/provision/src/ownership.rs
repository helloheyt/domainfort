//! The privileged step of the installer — giving a staged file its owner —
//! behind a trait, so that the plan and the installer are tested without
//! root while production never has a path that skips the change.
//!
//! - [`RootOwnership`] is the only implementation the binary uses. It
//!   exists only when the process's effective uid is 0 (`new` refuses
//!   otherwise) and changes the owner with `fchown` on the open file
//!   descriptor (never by path — no link is followed).
//! - Tests implement [`Ownership`] to record each requested owner and
//!   check it; they cannot change owners without root. There is no flag,
//!   setting or environment variable that selects a non-changing
//!   implementation in the binary.
//!
//! Spec: docs/51 §4.3 steps 3-9 (the owners and modes), §4.4; Q-270 item 3
//! (the database owned by dird's account); A-68 (the key root:0400); the
//! task's rule "the production implementation requires root and refuses
//! otherwise"; rustix docs.rs `fs::fchown`, `fs::Uid::from_raw`,
//! `fs::Gid::from_raw`, `process::geteuid` (P-2).

use core::fmt;
use std::os::fd::BorrowedFd;

use crate::plan::Owner;

/// What is being given an owner (for the record and the messages).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Staged {
    /// The staging directory.
    StagingDirectory,
    /// The integrity key file.
    IntegrityKey,
    /// The database file.
    Store,
    /// The policy file.
    Policy,
    /// A configuration file.
    Config(crate::configs::Daemon),
    /// The manifest.
    Manifest,
    /// The next policy file of `provision policy`.
    PolicyUpdate,
}

/// The owner could not be changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnershipError;

impl fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the owner of a staged file could not be changed")
    }
}

impl std::error::Error for OwnershipError {}

/// The privileged operations of the installer.
pub trait Ownership {
    /// The uid that owns the files this tool installs as root and the
    /// files it reads as root-owned (`provision policy`): 0 in production.
    fn root_uid(&self) -> u32;

    /// Give the open file or directory `fd` (staged as `what`) the owner
    /// `owner`.
    ///
    /// # Errors
    /// [`OwnershipError`]: the installer stops (fail closed).
    fn change_owner(
        &mut self,
        fd: BorrowedFd<'_>,
        what: Staged,
        owner: Owner,
    ) -> Result<(), OwnershipError>;
}

/// The process is not running as root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotRoot;

impl fmt::Display for NotRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("provision must run as root (effective uid 0)")
    }
}

impl std::error::Error for NotRoot {}

/// The production implementation: `fchown` as root.
/// Spec: docs/51 §4.3 ("root; no daemon runs"), Q-220 option (a) / A-57
/// ("root at provisioning only").
#[derive(Debug)]
pub struct RootOwnership {
    _private: (),
}

impl RootOwnership {
    /// Refuses unless the effective uid is 0.
    ///
    /// # Errors
    /// [`NotRoot`].
    ///
    /// Spec: rustix `process::geteuid` ("Returns the process' effective
    /// user ID"), `Uid::is_root`.
    pub fn new() -> Result<RootOwnership, NotRoot> {
        if rustix::process::geteuid().is_root() {
            Ok(RootOwnership { _private: () })
        } else {
            Err(NotRoot)
        }
    }
}

impl Ownership for RootOwnership {
    fn root_uid(&self) -> u32 {
        0
    }

    /// `fchown(fd, uid, gid)`. Spec: rustix `fs::fchown` ("Sets open file
    /// or directory ownership"), `Uid::from_raw`, `Gid::from_raw` (the
    /// values are never -1: the input refuses the all-ones id).
    fn change_owner(
        &mut self,
        fd: BorrowedFd<'_>,
        _what: Staged,
        owner: Owner,
    ) -> Result<(), OwnershipError> {
        rustix::fs::fchown(
            fd,
            Some(rustix::fs::Uid::from_raw(owner.uid)),
            Some(rustix::fs::Gid::from_raw(owner.gid)),
        )
        .map_err(|_| OwnershipError)
    }
}
