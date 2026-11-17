//! The operational log: fixed messages on stderr, and the counters behind
//! them. The peer-driven noise counters are also counted into dnsd's audit
//! window and reach the audit log as `WindowSummary` events (crate::audit;
//! docs/54 §9; task DN12) — counted at one place, crate::daemon
//! `Shared::noise`.
//!
//! Not the audit trail. Every message is a fixed text from [`Note`] plus, at
//! most, a numeric identifier (a count, a SERIAL, an OS error number) —
//! never request octets, names, addresses, TSIGs or any peer-supplied
//! string (docs/CLEAN-ROOM.md; docs/50 §8.2: "operational log to stderr in fixed
//! codes + identifiers"; docs/54 §9: "never in a log: message octets, GSS
//! tokens, MICs … raw key_name"). No record per query (docs/54 §9, R54-11:
//! "no record per query"). No logging crate (docs/50 §8.2). A failed write
//! to stderr is ignored, never a panic.
//!
//! Notes a network peer can trigger at will (a dropped source, a rate limit,
//! a connection limit, a refused or malformed request) are thinned out:
//! written for the 1st, 2nd, 4th, 8th … event of each kind, with the running
//! count, so a flood cannot fill the log (docs/07 §8: "rate limit for the
//! log") — they are docs/54 §9's counters ("dropped / limited / malformed /
//! refused").
//!
//! Spec: docs/50 §8.2; docs/07 §8; docs/54 §9; docs/CLEAN-ROOM.md

use ipc_audit_client::{Undelivered, Unflushed};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// What happened. Each variant has one fixed text.
/// Spec: docs/50 §8.2 ("fixed codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// The listeners were bound (as root, before the drop); nothing is read
    /// or answered on them until auditd, dird and the zone image are there.
    ListenersBound,
    /// The process hardening was applied and verified (R50-14).
    Hardened,
    /// auditd answered the start-up check (R50-16).
    AuditVerified,
    /// The audit link was verified again after a loss (uid and source).
    AuditRestored,
    /// The audit link was lost; noise counts are kept until it is back.
    AuditLost,
    /// At the stop, summaries auditd did not acknowledge in time; the
    /// identifier is their number.
    AuditUnacknowledged,
    /// dird was verified and the first zone image fetched; the identifier is
    /// its SERIAL (docs/54 §4.8).
    ZoneImageFetched,
    /// The listeners serve.
    Listening,
    /// A newer zone image replaced the one served; the identifier is its
    /// SERIAL (docs/54 §4.4).
    ZoneImageReplaced,
    /// A periodic SERIAL check with dird failed; the image ages toward the
    /// staleness bound (docs/54 §4.4).
    ZoneRefreshFailed,
    /// A query was answered SERVFAIL: no zone image confirmed within the
    /// staleness bound (docs/54 §4.4, fail closed).
    ZoneUnavailable,
    /// A datagram or connection from a source outside `internal_networks`
    /// was dropped without a byte (A-114).
    SourceNotInternal,
    /// A UDP datagram was dropped by the per-source or global limit.
    UdpLimited,
    /// A TCP message went over the per-source or global limit: its
    /// connection was closed.
    TcpQueryLimited,
    /// A TCP connection was closed at once: connection limit reached.
    TcpLimited,
    /// A request got no reply (dns-zone's silence: oversize, malformed,
    /// a response, or unencodable).
    Silenced,
    /// A signed UPDATE was answered SERVFAIL without reaching dird: the
    /// per-source or global forwarding limit.
    ForwardLimited,
    /// A signed UPDATE was answered SERVFAIL: the forwarding queue was full.
    ForwardQueueFull,
    /// A signed UPDATE was answered SERVFAIL: dird did not serve it.
    ForwardUnavailable,
    /// dird's reply named a new SERIAL but the new image could not be
    /// fetched before the reply was relayed (docs/54 §4.4 (a)); the
    /// periodic check will.
    ForwardRefreshFailed,
    /// A forward verdict for a UDP request (not produced by dns-zone today;
    /// silence — docs/questions/Q-952).
    ForwardOnUdp,
    /// Receiving on a UDP socket failed (the loop keeps going).
    ReceiveFailed,
    /// Accepting a TCP connection failed (the listener keeps going).
    AcceptFailed,
    /// Shutdown requested.
    Draining,
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
            Note::ListenersBound => {
                "listeners bound; nothing is served until auditd, dird and the zone image are there"
            }
            Note::Hardened => "process hardening applied and verified",
            Note::AuditVerified => "audit connection verified",
            Note::AuditRestored => "audit connection restored and verified",
            Note::AuditLost => "audit connection lost; noise counts kept until it is back",
            Note::AuditUnacknowledged => "audit summaries not acknowledged at stop",
            Note::ZoneImageFetched => "dird verified, zone image fetched; SERIAL",
            Note::Listening => "listening",
            Note::ZoneImageReplaced => "zone image replaced; SERIAL",
            Note::ZoneRefreshFailed => "zone SERIAL check with dird failed",
            Note::ZoneUnavailable => {
                "query answered SERVFAIL: no zone image confirmed within the staleness bound"
            }
            Note::SourceNotInternal => "request dropped: source outside the internal networks",
            Note::UdpLimited => "UDP datagram dropped: per-source or global limit",
            Note::TcpQueryLimited => "TCP connection closed: per-source or global message limit",
            Note::TcpLimited => "TCP connection closed: connection limit reached",
            Note::Silenced => "request not answered (oversize, malformed or a response)",
            Note::ForwardLimited => "UPDATE answered SERVFAIL: forwarding limit",
            Note::ForwardQueueFull => "UPDATE answered SERVFAIL: forwarding queue full",
            Note::ForwardUnavailable => "UPDATE answered SERVFAIL: dird did not serve it",
            Note::ForwardRefreshFailed => {
                "UPDATE reply relayed before the new zone image could be fetched"
            }
            Note::ForwardOnUdp => "forward verdict on UDP not wired: silence",
            Note::ReceiveFailed => "receiving a UDP datagram failed",
            Note::AcceptFailed => "accepting a TCP connection failed",
            Note::Draining => "shutdown requested: draining",
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

/// Write one note, with an optional numeric identifier.
/// Spec: docs/50 §8.2.
pub fn note(note: Note, id: Option<u64>) {
    let mut err = std::io::stderr().lock();
    let _ = match id {
        Some(id) => writeln!(err, "dns-daemon: {} [{id}]", note.text()),
        None => writeln!(err, "dns-daemon: {}", note.text()),
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
/// Spec: docs/07 §8 (rate limit for the log); docs/54 §9 (counters).
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
            let _ = writeln!(err, "dns-daemon: {} [count {count}]", self.note.text());
        }
    }

    /// Events counted so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

/// The counters a network peer can drive (docs/54 §9). Process-wide, as
/// the operational log is.
pub static SOURCE_NOT_INTERNAL: Thinned = Thinned::new(Note::SourceNotInternal);
/// UDP datagrams over the limit.
pub static UDP_LIMITED: Thinned = Thinned::new(Note::UdpLimited);
/// TCP messages over the limit.
pub static TCP_QUERY_LIMITED: Thinned = Thinned::new(Note::TcpQueryLimited);
/// TCP connections over a connection limit.
pub static TCP_LIMITED: Thinned = Thinned::new(Note::TcpLimited);
/// Requests dns-zone answers with silence.
pub static SILENCED: Thinned = Thinned::new(Note::Silenced);
/// Queries answered SERVFAIL for want of a current image.
pub static ZONE_UNAVAILABLE: Thinned = Thinned::new(Note::ZoneUnavailable);
/// Failed periodic SERIAL checks.
pub static ZONE_REFRESH_FAILED: Thinned = Thinned::new(Note::ZoneRefreshFailed);
/// Forwards over the forwarding limit.
pub static FORWARD_LIMITED: Thinned = Thinned::new(Note::ForwardLimited);
/// Forwards refused by a full queue.
pub static FORWARD_QUEUE_FULL: Thinned = Thinned::new(Note::ForwardQueueFull);
/// Forwards dird did not serve.
pub static FORWARD_UNAVAILABLE: Thinned = Thinned::new(Note::ForwardUnavailable);
/// Replies relayed before the new image arrived.
pub static FORWARD_REFRESH_FAILED: Thinned = Thinned::new(Note::ForwardRefreshFailed);
/// Forward verdicts on UDP (none today).
pub static FORWARD_ON_UDP: Thinned = Thinned::new(Note::ForwardOnUdp);
/// Failed UDP receives.
pub static RECEIVE_FAILED: Thinned = Thinned::new(Note::ReceiveFailed);
/// Failed TCP accepts.
pub static ACCEPT_FAILED: Thinned = Thinned::new(Note::AcceptFailed);
