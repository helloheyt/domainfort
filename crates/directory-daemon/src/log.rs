//! The operational log: fixed messages on stderr.
//!
//! Not the audit trail (that is auditd, R50-17). Every message is a fixed
//! text from [`Note`] plus, at most, a numeric identifier (a uid, an OS error
//! number, a count, a policy version) — never request octets, directory
//! values, names, the integrity key or any peer-supplied string (AGENTS.md
//! §6; docs/50 §8.2). No logging crate (docs/50 §8.2). A failed write to
//! stderr is ignored, never a panic.
//!
//! Per-connection notes a local peer can trigger at will (a refused uid, a
//! full quota) are thinned out: written for the 1st, 2nd, 4th, 8th … event of
//! each kind, with the running count (docs/07 §8: "rate limit for the log").
//!
//! Spec: docs/50 §8.2; docs/07 §8; AGENTS.md §6.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// What happened. Each variant has one fixed text.
/// Spec: docs/50 §8.2 ("fixed codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// The dirstore integrity key comes from the development file (Q-213
    /// interim, P-17).
    DevelopmentIntegrityKey,
    /// The policy store is the unsigned development format (Q-219 gap).
    UnsignedDevelopmentPolicy,
    /// The process hardening was applied and verified (R50-14).
    Hardened,
    /// auditd was verified at start (R50-16).
    AuditVerified,
    /// The directory and its domain were verified; the engine runs.
    DirectoryOpen,
    /// dird listens on `dird-kdc.sock`.
    Listening,
    /// A connection's peer uid is not the kdc's; closed without a reply.
    PeerRefused,
    /// A connection's peer credentials could not be read; closed.
    PeerCredentialsUnreadable,
    /// The kdc's connection quota is full; closed.
    QuotaExceeded,
    /// Accepting a connection failed (the listener keeps going).
    AcceptFailed,
    /// Shutdown requested; the queue is being drained.
    Draining,
    /// The engine thread ended before shutdown was requested.
    EngineStopped,
    /// Stopped.
    Stopped,
}

impl Note {
    /// The fixed text.
    const fn text(self) -> &'static str {
        match self {
            Note::DevelopmentIntegrityKey => {
                "WARNING: INSECURE DEVELOPMENT INTEGRITY KEY (docs/50 §7.4, Q-213 interim, owner \
                 item P-17): the dirstore integrity key was read from a development file, not \
                 from a sealed store. Not for deployment."
            }
            // The same text the kdc prints for the same file (A-68).
            Note::UnsignedDevelopmentPolicy => policy_store::UNSIGNED_DEVELOPMENT_WARNING,
            Note::Hardened => "process hardening applied and verified",
            Note::AuditVerified => "audit connection verified",
            Note::DirectoryOpen => "directory opened and domain verified; policy version",
            Note::Listening => "listening",
            Note::PeerRefused => "connection closed: peer uid is not the kdc's",
            Note::PeerCredentialsUnreadable => "connection closed: peer credentials unreadable",
            Note::QuotaExceeded => "connection closed: connection quota exceeded",
            Note::AcceptFailed => "accepting a connection failed",
            Note::Draining => "shutdown requested: draining",
            Note::EngineStopped => "engine thread stopped unexpectedly",
            Note::Stopped => "stopped",
        }
    }
}

/// Write one note, with an optional numeric identifier.
/// Spec: docs/50 §8.2.
pub fn note(note: Note, id: Option<u64>) {
    let mut err = std::io::stderr().lock();
    let _ = match id {
        Some(id) => writeln!(err, "directory-daemon: {} [{id}]", note.text()),
        None => writeln!(err, "directory-daemon: {}", note.text()),
    };
}

/// A count of one frequent per-connection note, logged on powers of two.
/// Spec: docs/07 §8 (rate limit for the log).
pub struct Thinned {
    note: Note,
    count: AtomicU64,
}

impl Thinned {
    /// A counter for `note`.
    #[must_use]
    pub const fn new(note: Note) -> Thinned {
        Thinned {
            note,
            count: AtomicU64::new(0),
        }
    }

    /// Count one event; write the note (with the uid and the running count)
    /// when the count is a power of two.
    pub fn hit(&self, uid: Option<u32>) {
        let count = self.count.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if count.is_power_of_two() {
            let mut err = std::io::stderr().lock();
            let _ = match uid {
                Some(uid) => writeln!(
                    err,
                    "directory-daemon: {} [uid {uid}] [count {count}]",
                    self.note.text()
                ),
                None => writeln!(
                    err,
                    "directory-daemon: {} [count {count}]",
                    self.note.text()
                ),
            };
        }
    }

    /// Events counted so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}
