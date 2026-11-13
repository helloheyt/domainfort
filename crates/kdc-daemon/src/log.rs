//! The operational log: fixed messages on stderr.
//!
//! Not the audit trail (that is auditd, R50-17). Every message is a fixed
//! text from [`Note`] plus, at most, a numeric identifier (a count, a policy
//! version, an OS error number) — never request octets, names, tickets,
//! addresses or any peer-supplied string (AGENTS.md §6; docs/50 §8.2:
//! "operational log to stderr in fixed codes + identifiers"; "never logged:
//! raw request bytes"). No logging crate (docs/50 §8.2). A failed write to
//! stderr is ignored, never a panic.
//!
//! Notes a network peer can trigger at will (a rate limit, a full queue, a
//! connection limit) are thinned out: written for the 1st, 2nd, 4th, 8th …
//! event of each kind, with the running count, so a flood cannot fill the
//! log (docs/07 §8: "rate limit for the log").
//!
//! Spec: docs/50 §8.2; docs/07 §8; AGENTS.md §6.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// What happened. Each variant has one fixed text.
/// Spec: docs/50 §8.2 ("fixed codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// The policy store is the unsigned development format (A-68).
    UnsignedDevelopmentPolicy,
    /// The listeners were bound (as root, before the drop); nothing is read
    /// or answered on them until the dependencies are verified.
    ListenersBound,
    /// The process hardening was applied and verified (R50-14).
    Hardened,
    /// auditd was verified at start (R50-16).
    AuditVerified,
    /// keyd and dird were verified, the policy versions agree; the engine
    /// runs. The identifier is the policy version.
    DependenciesVerified,
    /// The listeners serve.
    Listening,
    /// The audit connection was lost; requests are not served (29 / silence)
    /// until it is back (A-57).
    AuditLost,
    /// The audit connection is back.
    AuditRestored,
    /// dird's view carries another policy version than the kdc's: the
    /// request was answered as unavailable (R50-2; no reload, Q-275 item 7).
    PolicyVersionMismatch,
    /// A UDP datagram was dropped by the per-source or global limit.
    UdpLimited,
    /// A request was dropped (UDP) or its connection closed (TCP): the
    /// engine queue of its exchange was full.
    QueueFull,
    /// A TCP connection was closed at once: its source holds the most
    /// connections allowed, or the global bound is reached.
    TcpLimited,
    /// Receiving on a UDP socket failed (the loop keeps going).
    ReceiveFailed,
    /// Accepting a TCP connection failed (the listener keeps going).
    AcceptFailed,
    /// Shutdown requested; the queues are being drained.
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
            Note::UnsignedDevelopmentPolicy => policy_store::UNSIGNED_DEVELOPMENT_WARNING,
            Note::ListenersBound => {
                "listeners bound; nothing is served until auditd, keyd and dird are verified"
            }
            Note::Hardened => "process hardening applied and verified",
            Note::AuditVerified => "audit connection verified",
            Note::DependenciesVerified => {
                "keyd and dird verified, policy versions agree; policy version"
            }
            Note::Listening => "listening",
            Note::AuditLost => {
                "audit connection lost: requests are answered as unavailable until it is back"
            }
            Note::AuditRestored => "audit connection restored",
            Note::PolicyVersionMismatch => {
                "request not served: dird's policy version differs from the kdc's (restart both \
                 with the same policy file)"
            }
            Note::UdpLimited => "UDP datagram dropped: per-source or global limit",
            Note::QueueFull => "request dropped: engine queue full",
            Note::TcpLimited => "TCP connection closed: connection limit reached",
            Note::ReceiveFailed => "receiving a UDP datagram failed",
            Note::AcceptFailed => "accepting a TCP connection failed",
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
        Some(id) => writeln!(err, "kdc-daemon: {} [{id}]", note.text()),
        None => writeln!(err, "kdc-daemon: {}", note.text()),
    };
}

/// A count of one frequent note, logged on powers of two.
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

    /// Count one event; write the note with the running count when the
    /// count is a power of two.
    pub fn hit(&self) {
        let count = self.count.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if count.is_power_of_two() {
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "kdc-daemon: {} [count {count}]", self.note.text());
        }
    }

    /// Events counted so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}
