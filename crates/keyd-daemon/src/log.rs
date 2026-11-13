//! The operational log: fixed messages on stderr.
//!
//! Not the audit trail (that is auditd, R50-17). Every message is a fixed
//! text from [`Note`] plus, at most, a numeric identifier (a uid, an OS error
//! number, a count) — never request octets, keys, tokens, passwords or any
//! peer-supplied string (AGENTS.md §6; docs/50 §8.2: "operational log to
//! stderr in fixed codes + identifiers"; "never logged: raw request bytes …
//! keys, keyd tokens"). No logging crate (docs/50 §8.2). A failed write to
//! stderr is ignored, never a panic.
//!
//! Per-connection notes a local peer can trigger at will (an unmapped uid, a
//! full quota) are thinned out: written for the 1st, 2nd, 4th, 8th … event
//! of each kind, with the running count, so a flood cannot fill the log
//! (docs/07 §8: "rate limit for the log").
//!
//! Spec: docs/50 §8.2; docs/07 §8; AGENTS.md §6.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// What happened. Each variant has one fixed text.
/// Spec: docs/50 §8.2 ("fixed codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// The insecure development key store is in use (R50-18, P-17, D178).
    DevelopmentKeyStore,
    /// The startup hold-down is in force (RFC 4120 3.2.3; A-56, A-62).
    StartupHoldDown,
    /// The process hardening was applied and verified (R50-14).
    Hardened,
    /// The audit connection was verified at start (R50-16).
    AuditVerified,
    /// keyd listens on its socket.
    Listening,
    /// The audit connection was lost; gating operations are refused until
    /// it is back (A-57).
    AuditLost,
    /// The audit connection is back.
    AuditRestored,
    /// A connection's peer uid is not mapped; closed without a reply.
    PeerUnmapped,
    /// A connection's peer credentials could not be read; closed.
    PeerCredentialsUnreadable,
    /// A uid exceeded its connection quota; closed.
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
            Note::DevelopmentKeyStore => {
                "WARNING: INSECURE DEVELOPMENT KEY STORE (docs/50 R50-18, owner item P-17): \
                 every key is held only in this process's memory and is LOST ON RESTART; the \
                 krbtgt key is development-only and not protected by an HSM (D178). \
                 Not for deployment."
            }
            Note::StartupHoldDown => {
                "startup hold-down: Kerberos operations are refused (Unavailable) for two \
                 clock-skew intervals after this start (RFC 4120 3.2.3; A-62)"
            }
            Note::Hardened => "process hardening applied and verified",
            Note::AuditVerified => "audit connection verified",
            Note::Listening => "listening",
            Note::AuditLost => {
                "audit connection lost: gating operations are refused (Busy) until it is back"
            }
            Note::AuditRestored => "audit connection restored",
            Note::PeerUnmapped => "connection closed: peer uid not mapped",
            Note::PeerCredentialsUnreadable => "connection closed: peer credentials unreadable",
            Note::QuotaExceeded => "connection closed: per-uid connection quota exceeded",
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
        Some(id) => writeln!(err, "keyd-daemon: {} [{id}]", note.text()),
        None => writeln!(err, "keyd-daemon: {}", note.text()),
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
                    "keyd-daemon: {} [uid {uid}] [count {count}]",
                    self.note.text()
                ),
                None => writeln!(err, "keyd-daemon: {} [count {count}]", self.note.text()),
            };
        }
    }
}
