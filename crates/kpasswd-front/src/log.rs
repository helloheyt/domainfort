//! The operational log and the front's counted events: fixed messages on
//! stderr, and the counters behind them.
//!
//! docs/53 §9: "kpasswd-front: connection closed (source outside
//! `internal_networks`, malformed framing, version) — with the A-57 noise
//! rule (a count, not a record per datagram)". So the front **counts** what
//! happens at its own layer (connections refused at a limit or for their
//! source, framing failures, other versions, timeouts, dird busy or not
//! serving) — the change itself is audited by dird and keyd (docs/53 §9:
//! dird's `ChangePassword` event, keyd's records). The counts are kept per
//! running daemon ([`Counters`], read through `DaemonControl::counts`), so
//! two daemons in one process (the tests) never mix them.
//!
//! # Noise and failures (docs/questions/Q-961 item 7, A-160; Q-988)
//!
//! The counted cases split by the reading Q-961 item 3 gave dnsd's counters
//! (A-160): a **peer-driven** occurrence at the daemon's own layer is
//! **noise** — counted on the operational log *and* into the audit window,
//! which auditd records as `WindowSummary` counts (`suppressed_noise`;
//! crate::audit); the daemon's own operational failures and its
//! dependencies' (dird) failures are not noise and stay on the operational
//! log only:
//!
//! | counted case | [`Noise`] / [`Failure`] | dnsd's counterpart (Q-961 item 3) |
//! |---|---|---|
//! | source outside `internal_networks` | `Noise::SourceNotInternal` ("dropped") | `SOURCE_NOT_INTERNAL` |
//! | global / per-source connection bound | `Noise::ConnectionLimited` ("limited") | `TCP_LIMITED` |
//! | request not whole in time, client closed first, reply not taken in time | `Noise::TimedOut` (a connection closed at the front's layer, docs/53 §9) | — (dnsd closes silently, uncounted) |
//! | framing failure, not an AP-REQ + KRB-PRIV | `Noise::Malformed` ("malformed framing") | `SILENCED` |
//! | another protocol version | `Noise::BadVersion` ("version") | — |
//! | every dird channel slot in use | `Noise::DirdBusy` ("refused" for the front's own full capacity) | `FORWARD_QUEUE_FULL` |
//! | dird not serving (down, refusal, deadline, unknown outcome) | `Failure::DirdNotServing` | `FORWARD_UNAVAILABLE` (not counted) |
//! | a failed `accept` | `Failure::AcceptFailed` | `ACCEPT_FAILED` (not counted) |
//!
//! **One chokepoint, by construction:** a noise counter moves only through
//! `Counters::noise`, which takes the audit gate and counts into it in the
//! same call — the operational log and the audit window cannot drift (the
//! fields are private to this module; there is no other way to hit them).
//!
//! Every message is a fixed text from [`Note`] plus, at most, a count —
//! never request octets, names, addresses, or any peer-supplied string
//! (docs/CLEAN-ROOM.md; docs/53 §9: "never: the password, the KRB-PRIV / AP-REQ
//! octets"; docs/50 §8.2). No logging crate. A failed write to stderr is
//! ignored, never a panic. Notes a network peer can trigger at will are
//! thinned out: written for the 1st, 2nd, 4th, 8th … event of each kind,
//! with the running count, so a flood cannot fill the log (docs/07 §8).
//!
//! Spec: docs/53 §9; A-57 (noise rule); docs/50 §8.1, §8.2; docs/07 §8;
//! docs/CLEAN-ROOM.md, §6.1; docs/questions/Q-961 items 3, 7 (A-160).

use crate::audit::AuditGate;
use ipc_audit_client::{Undelivered, Unflushed};
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
    /// The audit link verified auditd again after a loss.
    AuditRestored,
    /// The audit link lost auditd; noise counts are kept and sent once it
    /// is verified again (requests are not gated on auditd).
    AuditLost,
    /// Audit events (summaries) still unacknowledged when the front
    /// stopped.
    AuditUnacknowledged,
    /// At the stop, noise counted for a `WindowSummary` that never left
    /// the audit window (auditd unreachable, or the pace held it past the
    /// grace): lost with the process; the identifier is the count
    /// (docs/questions/Q-990 item 4, A-166; Q-995).
    AuditSuppressedNoiseUndelivered,
    /// At the stop, refused gating reservations counted for a summary that
    /// never left the audit window; the identifier is the count (Q-995).
    AuditRefusedGatingUndelivered,
    /// At the stop, lost outcome records counted for a summary that never
    /// left the audit window; the identifier is the count (A-88; Q-995).
    AuditUnrecordedOutcomesUndelivered,
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
            Note::AuditRestored => "audit connection verified again",
            Note::AuditLost => "audit connection lost; noise counts kept",
            Note::AuditUnacknowledged => "audit events unacknowledged at stop",
            Note::AuditSuppressedNoiseUndelivered => {
                "audit count not delivered at stop: suppressed noise"
            }
            Note::AuditRefusedGatingUndelivered => {
                "audit count not delivered at stop: refused gating reservations"
            }
            Note::AuditUnrecordedOutcomesUndelivered => {
                "audit count not delivered at stop: unrecorded outcomes"
            }
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

/// The stop's audit report (`ipc_audit_client::Unflushed::undelivered`): one
/// note per kind auditd did not receive, with its count — the events it did
/// not acknowledge and the counts never sent as a summary alike
/// (docs/questions/Q-990 item 4, A-166; Q-995). Counts only, never event
/// content. The `match` names every kind (no wildcard), so a kind added to
/// the report reaches this log or fails to compile.
/// Spec: docs/50 §8.2; docs/questions/Q-313 (A-82), Q-995.
pub fn audit_undelivered(unflushed: Unflushed) {
    for part in unflushed.undelivered() {
        let kind = match part {
            Undelivered::Events(_) => Note::AuditUnacknowledged,
            Undelivered::SuppressedNoise(_) => Note::AuditSuppressedNoiseUndelivered,
            Undelivered::RefusedGating(_) => Note::AuditRefusedGatingUndelivered,
            Undelivered::UnrecordedOutcomes(_) => Note::AuditUnrecordedOutcomesUndelivered,
        };
        note(kind, Some(part.count()));
    }
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

/// A peer-driven noise occurrence at the front's layer (module
/// documentation, "Noise and failures") — counted on the operational log
/// and into the audit window.
/// Spec: docs/53 §9; A-57; docs/questions/Q-961 item 3 (A-160), Q-988.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Noise {
    /// A connection closed before a byte: its source is outside every
    /// internal network (docs/53 §3.3).
    SourceNotInternal,
    /// A connection closed before a byte: a connection bound was reached
    /// (docs/53 §5.1).
    ConnectionLimited,
    /// A connection closed without a reply: the request was not whole in
    /// time or the client closed first — or the reply was not taken in time.
    TimedOut,
    /// A request answered MALFORMED.
    Malformed,
    /// A request answered BAD_VERSION.
    BadVersion,
    /// A request answered HARDERROR because every dird channel slot of the
    /// front was in use (docs/53 §5.6 step 1).
    DirdBusy,
}

impl Noise {
    /// Every noise case.
    pub const ALL: [Noise; 6] = [
        Noise::SourceNotInternal,
        Noise::ConnectionLimited,
        Noise::TimedOut,
        Noise::Malformed,
        Noise::BadVersion,
        Noise::DirdBusy,
    ];
}

/// The front's own operational failure or a dependency's — not noise
/// (module documentation): the operational log only.
/// Spec: docs/50 §8.2; docs/questions/Q-961 item 3 (A-160), Q-988.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// dird did not serve a request (answered HARDERROR).
    DirdNotServing,
    /// Accepting a TCP connection failed.
    AcceptFailed,
}

/// The counters of one running front. The fields are private: a noise
/// counter moves only through `Counters::noise` (module documentation).
/// Spec: docs/53 §9; A-57.
#[derive(Debug)]
pub struct Counters {
    connection_limited: Thinned,
    source_not_internal: Thinned,
    malformed: Thinned,
    bad_version: Thinned,
    timed_out: Thinned,
    dird_not_serving: Thinned,
    dird_busy: Thinned,
    accept_failed: Thinned,
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
    /// The thinned counter of `noise`.
    fn of_noise(&self, noise: Noise) -> &Thinned {
        match noise {
            Noise::SourceNotInternal => &self.source_not_internal,
            Noise::ConnectionLimited => &self.connection_limited,
            Noise::TimedOut => &self.timed_out,
            Noise::Malformed => &self.malformed,
            Noise::BadVersion => &self.bad_version,
            Noise::DirdBusy => &self.dird_busy,
        }
    }

    /// Count one noise occurrence — **the one place** a noise counter
    /// moves: the operational log's thinned counter and the front's audit
    /// window (sent as the next `WindowSummary`, crate::audit) in one call,
    /// so the two cannot drift.
    /// Spec: docs/53 §9; A-57; docs/questions/Q-961 items 2, 3, 7 (A-160),
    /// Q-988; docs/CLEAN-ROOM.md ("a single chokepoint").
    pub(crate) fn noise(&self, noise: Noise, audit: &AuditGate) {
        self.of_noise(noise).hit();
        audit.count_noise();
    }

    /// Count one operational failure (the operational log only).
    /// Spec: docs/50 §8.2; docs/questions/Q-961 item 3 (A-160).
    pub(crate) fn failure(&self, failure: Failure) {
        match failure {
            Failure::DirdNotServing => self.dird_not_serving.hit(),
            Failure::AcceptFailed => self.accept_failed.hit(),
        }
    }

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

impl Counts {
    /// The count of one noise case.
    #[must_use]
    pub fn of(&self, noise: Noise) -> u64 {
        match noise {
            Noise::SourceNotInternal => self.source_not_internal,
            Noise::ConnectionLimited => self.connection_limited,
            Noise::TimedOut => self.timed_out,
            Noise::Malformed => self.malformed,
            Noise::BadVersion => self.bad_version,
            Noise::DirdBusy => self.dird_busy,
        }
    }

    /// Every noise occurrence counted — what the front's `WindowSummary`
    /// counts (`suppressed_noise`) add up to (module documentation).
    /// Spec: docs/53 §9; A-57; docs/questions/Q-988.
    #[must_use]
    pub fn noise(&self) -> u64 {
        Noise::ALL
            .iter()
            .fold(0u64, |sum, noise| sum.saturating_add(self.of(*noise)))
    }
}
