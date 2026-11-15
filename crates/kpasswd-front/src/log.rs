//! The operational log and the front's counted events: fixed messages on
//! stderr, and the counters behind them.
//!
//! docs/53 §9: "kpasswd-front: connection closed (source outside
//! `internal_networks`, malformed framing, version) — with the A-57 noise
//! rule (a count, not a record per datagram)". So the front **counts** what
//! happens at its own layer (connections refused at a limit or for their
//! source, framing failures, other versions, timeouts, dird not serving) —
//! the change itself is audited by dird and keyd (docs/53 §9: dird's
//! `ChangePassword` event, keyd's records). The counts are kept per running
//! daemon ([`Counters`], read through `DaemonControl::counts`), so two
//! daemons in one process (the tests) never mix them.
//!
//! Every message is a fixed text from [`Note`] plus, at most, a count —
//! never request octets, names, addresses, or any peer-supplied string
//! (AGENTS.md §6; docs/53 §9: "never: the password, the KRB-PRIV / AP-REQ
//! octets"; docs/50 §8.2). No logging crate. A failed write to stderr is
//! ignored, never a panic. Notes a network peer can trigger at will are
//! thinned out: written for the 1st, 2nd, 4th, 8th … event of each kind,
//! with the running count, so a flood cannot fill the log (docs/07 §8).
//!
//! Spec: docs/53 §9; A-57 (noise rule); docs/50 §8.2; docs/07 §8;
//! AGENTS.md §6.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// What happened. Each variant has one fixed text.
/// Spec: docs/50 §8.2 ("fixed codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// The configuration was read and checked.
    ConfigurationRead,
    /// The listeners were bound (as root, before the drop); nothing is read
    /// or answered on them until auditd and dird are verified.
    ListenersBound,
    /// The process hardening was applied and verified (R50-14).
    Hardened,
    /// auditd answered the start-up check (R50-16).
    AuditVerified,
    /// dird answered the start-up check on the kpasswd channel (R50-16).
    DirdVerified,
    /// The listeners serve.
    Listening,
    /// A connection was closed at once: the global or per-source connection
    /// bound is reached.
    ConnectionLimited,
    /// A connection was closed at once: its source address is outside every
    /// internal network (docs/53 §3.3; docs/52 R14).
    SourceNotInternal,
    /// A request did not frame (or its messages were not an AP-REQ and a
    /// KRB-PRIV): answered MALFORMED.
    Malformed,
    /// A request carried another protocol version: answered BAD_VERSION.
    BadVersion,
    /// A connection was closed by a timeout (the first frame, or the write
    /// of the reply), or closed by the client before its request was whole.
    TimedOut,
    /// dird did not serve a request: answered HARDERROR.
    DirdNotServing,
    /// Every connection to dird was in use: answered HARDERROR.
    DirdBusy,
    /// Accepting a TCP connection failed (the listener keeps going).
    AcceptFailed,
    /// Stopped.
    Stopped,
}

impl Note {
    /// The fixed text.
    const fn text(self) -> &'static str {
        match self {
            Note::ConfigurationRead => "configuration read",
            Note::ListenersBound => {
                "listeners bound; nothing is served until auditd and dird are verified"
            }
            Note::Hardened => "process hardening applied and verified",
            Note::AuditVerified => "audit connection verified",
            Note::DirdVerified => "dird kpasswd channel verified",
            Note::Listening => "listening",
            Note::ConnectionLimited => "connection closed: connection limit reached",
            Note::SourceNotInternal => {
                "connection closed: source address outside the internal networks"
            }
            Note::Malformed => "request malformed: answered MALFORMED",
            Note::BadVersion => "request of another protocol version: answered BAD_VERSION",
            Note::TimedOut => "connection closed: timeout or incomplete request",
            Note::DirdNotServing => "dird did not serve a request: answered HARDERROR",
            Note::DirdBusy => "every dird connection in use: answered HARDERROR",
            Note::AcceptFailed => "accepting a TCP connection failed",
            Note::Stopped => "stopped",
        }
    }
}

/// Write one note, with an optional count.
/// Spec: docs/50 §8.2.
pub fn note(note: Note, id: Option<u64>) {
    let mut err = std::io::stderr().lock();
    let _ = match id {
        Some(id) => writeln!(err, "kpasswd-front: {} [{id}]", note.text()),
        None => writeln!(err, "kpasswd-front: {}", note.text()),
    };
}

/// A count of one frequent note, logged on powers of two.
/// Spec: docs/07 §8 (rate limit for the log); A-57 (noise is counted).
#[derive(Debug)]
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
            let _ = writeln!(err, "kpasswd-front: {} [count {count}]", self.note.text());
        }
    }

    /// Events counted so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

/// The counters of one running front.
/// Spec: docs/53 §9; A-57.
#[derive(Debug)]
pub struct Counters {
    pub(crate) connection_limited: Thinned,
    pub(crate) source_not_internal: Thinned,
    pub(crate) malformed: Thinned,
    pub(crate) bad_version: Thinned,
    pub(crate) timed_out: Thinned,
    pub(crate) dird_not_serving: Thinned,
    pub(crate) dird_busy: Thinned,
    pub(crate) accept_failed: Thinned,
}

impl Default for Counters {
    fn default() -> Counters {
        Counters {
            connection_limited: Thinned::new(Note::ConnectionLimited),
            source_not_internal: Thinned::new(Note::SourceNotInternal),
            malformed: Thinned::new(Note::Malformed),
            bad_version: Thinned::new(Note::BadVersion),
            timed_out: Thinned::new(Note::TimedOut),
            dird_not_serving: Thinned::new(Note::DirdNotServing),
            dird_busy: Thinned::new(Note::DirdBusy),
            accept_failed: Thinned::new(Note::AcceptFailed),
        }
    }
}

impl Counters {
    /// The counters now.
    #[must_use]
    pub fn snapshot(&self) -> Counts {
        Counts {
            connection_limited: self.connection_limited.count(),
            source_not_internal: self.source_not_internal.count(),
            malformed: self.malformed.count(),
            bad_version: self.bad_version.count(),
            timed_out: self.timed_out.count(),
            dird_not_serving: self.dird_not_serving.count(),
            dird_busy: self.dird_busy.count(),
            accept_failed: self.accept_failed.count(),
        }
    }
}

/// A snapshot of one front's counters (for the operator and the tests).
/// Spec: docs/53 §9 (counts, never content); docs/50 §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    /// Connections closed at a connection bound.
    pub connection_limited: u64,
    /// Connections closed because their source is not internal.
    pub source_not_internal: u64,
    /// Requests answered MALFORMED.
    pub malformed: u64,
    /// Requests answered BAD_VERSION.
    pub bad_version: u64,
    /// Connections closed by a timeout or before their request was whole.
    pub timed_out: u64,
    /// Requests answered HARDERROR because dird did not serve them.
    pub dird_not_serving: u64,
    /// Requests answered HARDERROR because every dird connection was in use.
    pub dird_busy: u64,
    /// Failed accepts.
    pub accept_failed: u64,
}
