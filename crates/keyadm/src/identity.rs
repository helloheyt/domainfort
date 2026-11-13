//! keyadm refuses to run as root.
//!
//! keyd never maps uid 0 (R50-3: "the host's root does not get a Role for
//! free"), so a run as root would only be refused by keyd — keyadm fails
//! early instead, with a clear message, before reading any file or opening
//! the socket. Both the real and the effective uid are checked (a set-uid
//! start must not turn into a root run either).
//!
//! The uids are read with `daemon_sandbox::read_state`, the project's one
//! reader of the process identity (docs/50 §6.1: "process::getuid/geteuid …
//! to verify", through rustix). On any platform but Linux it returns
//! `Unsupported` and keyadm refuses to run (fail closed) — keyadm is a
//! DC-host tool, and its keyd connection cannot verify keyd's uid off Linux
//! either (crates/ipc-keyd unix.rs).
//!
//! # No hardening plan (docs/questions/Q-347 item 3)
//!
//! keyadm applies none of daemon-sandbox's steps. docs/50 §6.4 lists the
//! daemons; keyadm is a tool started directly under its own non-root
//! account, so there is no identity to drop and no capability to remove
//! (§6.2 is about processes started as root). Not-dumpable / `mlockall` /
//! core 0 protect secrets in memory (§6.4 gives `mlockall` to keyd and
//! admind for keys and passwords); keyadm holds none — its inputs and
//! outputs are GUIDs, bindings and kvnos (docs/47 §2.3; docs/10 I1). And a
//! process that could inspect keyadm runs under keyadm's uid, so it holds
//! Role::Admin in keyd already (docs/50 §3.2: the role comes from the uid) —
//! hardening keyadm would not take anything from it.
//!
//! Spec: docs/50 R50-3, §3.2, §6.1, §6.2, §6.4; docs/51 §4.3 step 11, §6;
//! docs/10 §2, I1; AGENTS.md §6 (fail closed).

use core::fmt;

/// Why keyadm will not run as the current process identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// The real or effective uid is 0.
    Root,
    /// The process identity could not be read (any platform but Linux).
    Unreadable,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IdentityError::Root => {
                "keyadm does not run as root: keyd never maps uid 0 (run it as the keyadm account keyd maps to Admin)"
            }
            IdentityError::Unreadable => {
                "the process identity cannot be read (keyadm runs on Linux only)"
            }
        })
    }
}

impl std::error::Error for IdentityError {}

/// Refuse a real or effective uid of 0.
///
/// # Errors
/// [`IdentityError::Root`].
///
/// Spec: docs/50 R50-3 ("uid 0 is never mapped"), §3.2.
pub const fn refuse_root(real_uid: u32, effective_uid: u32) -> Result<(), IdentityError> {
    if real_uid == 0 || effective_uid == 0 {
        Err(IdentityError::Root)
    } else {
        Ok(())
    }
}

/// Check the current process: not root, and its identity readable.
///
/// # Errors
/// [`IdentityError`].
///
/// Spec: docs/50 R50-3, §6.1; module documentation.
pub fn check_current_process() -> Result<(), IdentityError> {
    let state = daemon_sandbox::read_state().map_err(|_| IdentityError::Unreadable)?;
    refuse_root(state.real_uid, state.effective_uid)
}
