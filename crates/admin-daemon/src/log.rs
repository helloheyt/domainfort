//! The operational log: fixed messages on stderr.
//!
//! Not the audit trail (that is auditd, R50-17). Every message is a fixed
//! text from [`Note`] plus, at most, a numeric identifier (a uid, an OS error
//! number, a count) — never request octets, AP-REQs, a password or anything
//! derived from one, a name or any peer-supplied string (docs/CLEAN-ROOM.md;
//! docs/50 §8.2). No logging crate (docs/50 §8.2). A failed write to stderr
//! is ignored, never a panic.
//!
//! Per-connection notes a local peer can trigger at will (a refused
//! connection, a rate-limited request, a malformed frame) are thinned out:
//! written for the 1st, 2nd, 4th, 8th … event of each kind, with the running
//! count (docs/07 §8: "rate limit for the log").
//!
//! Spec: docs/50 §8.2; docs/07 §8; docs/CLEAN-ROOM.md

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// What happened. Each variant has one fixed text.
/// Spec: docs/50 §8.2 ("fixed codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// The process hardening was applied and verified (R50-14).
    Hardened,
    /// auditd was verified at start (R50-16).
    AuditVerified,
    /// admind listens on `admin.sock`.
    Listening,
    /// A connection's peer credentials could not be read; closed.
    PeerCredentialsUnreadable,
    /// A peer's connection quota (or the global bound) is full; refused.
    ConnectionLimit,
    /// A peer's request rate is over its window's limit; answered `Busy`.
    RateLimited,
    /// A frame did not decode (or broke the frame bound); closed.
    MalformedFrame,
    /// A started frame did not complete within the frame timeout; closed.
    FrameTimeout,
    /// The worker's queue is full; the request is answered `Busy`.
    WorkerBusy,
    /// A `SetPassword` was refused `Busy`: auditd could not take its event.
    AuditUnavailable,
    /// An admind event could not be committed after its operation (the
    /// operation's answer is still the true one).
    EventUnrecorded,
    /// The worker did not answer a request it had taken.
    WorkerLost,
    /// Accepting a connection failed (the listener keeps going).
    AcceptFailed,
    /// The audit connection was lost; `SetPassword` is refused until it is
    /// back (A-57).
    AuditLost,
    /// The audit connection is back.
    AuditRestored,
    /// Shutdown requested; requests are being drained.
    Draining,
    /// The stop ended the audit task with events auditd had not
    /// acknowledged (logged with their count).
    AuditUnacknowledged,
    /// The worker thread ended before shutdown was requested.
    WorkerStopped,
    /// Stopped.
    Stopped,
}

impl Note {
    /// The fixed text.
    const fn text(self) -> &'static str {
        match self {
            Note::Hardened => "process hardening applied and verified",
            Note::AuditVerified => "audit connection verified",
            Note::Listening => "listening on the admin socket",
            Note::PeerCredentialsUnreadable => "connection closed: peer credentials unreadable",
            Note::ConnectionLimit => "connection refused: connection quota reached",
            Note::RateLimited => "request refused (busy): peer request rate over its limit",
            Note::MalformedFrame => "connection closed: frame did not decode",
            Note::FrameTimeout => "connection closed: frame did not complete in time",
            Note::WorkerBusy => "request refused (busy): worker queue full",
            Note::AuditUnavailable => {
                "password request refused (busy): auditd cannot take its event"
            }
            Note::EventUnrecorded => "audit event not recorded after its operation",
            Note::WorkerLost => "worker gave no answer to a request it took",
            Note::AcceptFailed => "accepting a connection failed",
            Note::AuditLost => "audit connection lost: password requests refused until it is back",
            Note::AuditRestored => "audit connection restored",
            Note::Draining => "shutdown requested: draining",
            Note::AuditUnacknowledged => {
                "stopping with audit events auditd did not acknowledge within the grace; count"
            }
            Note::WorkerStopped => "worker thread stopped unexpectedly",
            Note::Stopped => "stopped",
        }
    }
}

/// Write one note, with an optional numeric identifier.
/// Spec: docs/50 §8.2.
pub fn note(note: Note, id: Option<u64>) {
    let mut err = std::io::stderr().lock();
    let _ = match id {
        Some(id) => writeln!(err, "admin-daemon: {} [{id}]", note.text()),
        None => writeln!(err, "admin-daemon: {}", note.text()),
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
                    "admin-daemon: {} [uid {uid}] [count {count}]",
                    self.note.text()
                ),
                None => writeln!(err, "admin-daemon: {} [count {count}]", self.note.text()),
            };
        }
    }

    /// Events counted so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}
