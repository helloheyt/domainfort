//! The operational log: fixed messages on stderr, and the counters behind
//! them.
//!
//! Not the audit trail: the LDAP operations are audited by dird, the PEP
//! (docs/50 §4.2: "the LDAP event (`Outcome.audit`) is written by dird, not
//! by the front (R49-14)"; §8.1 lists no front event shape), so the front
//! only **counts** what happens at its own layer (connections refused at a
//! limit, TLS handshakes that failed, parameters refused after a handshake,
//! streams that were not LDAP, sessions closed because dird did not serve,
//! timeouts) — docs/questions/Q-285 item 9.
//!
//! Every message is a fixed text from [`Note`] plus, at most, a count — never
//! request octets, names, addresses, TLS secrets or any peer-supplied string
//! (AGENTS.md §6; docs/50 §8.2: "operational log to stderr in fixed codes +
//! identifiers"; "never logged: raw request bytes … keys"). No logging crate
//! (docs/50 §8.2; rustls `logging` is off). A failed write to stderr is
//! ignored, never a panic.
//!
//! Notes a network peer can trigger at will are thinned out: written for the
//! 1st, 2nd, 4th, 8th … event of each kind, with the running count, so a
//! flood cannot fill the log (docs/07 §8: "rate limit for the log").
//!
//! Spec: docs/50 §8.2; docs/07 §8; AGENTS.md §6.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// What happened. Each variant has one fixed text.
/// Spec: docs/50 §8.2 ("fixed codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// The DC certificate and key were loaded and checked (R50-12); the key
    /// octets read from the file were wiped.
    CredentialLoaded,
    /// The listeners were bound (as root, before the drop); nothing is read
    /// or answered on them until auditd and dird are verified.
    ListenersBound,
    /// The process hardening was applied and verified (R50-14).
    Hardened,
    /// auditd answered the start-up check (R50-16).
    AuditVerified,
    /// dird answered the start-up check on the LDAP channel (R50-16).
    DirdVerified,
    /// The listeners serve.
    Listening,
    /// A connection was closed at once: the global, per-source or
    /// unauthenticated connection bound is reached.
    ConnectionLimited,
    /// A connection was closed at once: its source address is outside every
    /// internal network (phase 1 has no external LDAP connection — docs/52
    /// R14; A-102 on docs/questions/Q-469 (b)).
    SourceNotInternal,
    /// A TLS handshake failed or did not finish in time.
    HandshakeFailed,
    /// A TLS handshake finished with parameters outside docs/50 R50-11.
    TlsParametersRefused,
    /// A client stream was not LDAP, or a message was over its bound.
    NotLdap,
    /// A StartTLS response left cleartext octets buffered (R49-15).
    CleartextAfterStartTls,
    /// A session was closed because dird did not serve it.
    DirdNotServing,
    /// A connection was closed by a timeout (InitRecvTimeout,
    /// MaxConnIdleTime, the handshake bound or a write bound).
    TimedOut,
    /// Accepting a TCP connection failed (the listener keeps going).
    AcceptFailed,
    /// Stopped.
    Stopped,
}

impl Note {
    /// The fixed text.
    const fn text(self) -> &'static str {
        match self {
            Note::CredentialLoaded => "DC certificate and key loaded and checked; key octets wiped",
            Note::ListenersBound => {
                "listeners bound; nothing is served until auditd and dird are verified"
            }
            Note::Hardened => "process hardening applied and verified",
            Note::AuditVerified => "audit connection verified",
            Note::DirdVerified => "dird LDAP channel verified",
            Note::Listening => "listening",
            Note::ConnectionLimited => "connection closed: connection limit reached",
            Note::SourceNotInternal => {
                "connection closed: source address outside the internal networks"
            }
            Note::HandshakeFailed => "connection closed: TLS handshake failed or timed out",
            Note::TlsParametersRefused => {
                "connection closed: negotiated TLS parameters outside the configured profile"
            }
            Note::NotLdap => "connection closed: not an LDAP stream, or a message over its bound",
            Note::CleartextAfterStartTls => {
                "connection closed: cleartext octets buffered after the StartTLS request"
            }
            Note::DirdNotServing => "connection closed: dird did not serve the session",
            Note::TimedOut => "connection closed: timeout",
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
        Some(id) => writeln!(err, "ldap-front: {} [{id}]", note.text()),
        None => writeln!(err, "ldap-front: {}", note.text()),
    };
}

/// A count of one frequent note, logged on powers of two.
/// Spec: docs/07 §8 (rate limit for the log).
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
            let _ = writeln!(err, "ldap-front: {} [count {count}]", self.note.text());
        }
    }

    /// Events counted so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

/// The front's counters (process-wide).
pub(crate) static CONNECTION_LIMITED: Thinned = Thinned::new(Note::ConnectionLimited);
pub(crate) static SOURCE_NOT_INTERNAL: Thinned = Thinned::new(Note::SourceNotInternal);
pub(crate) static HANDSHAKE_FAILED: Thinned = Thinned::new(Note::HandshakeFailed);
pub(crate) static TLS_PARAMETERS_REFUSED: Thinned = Thinned::new(Note::TlsParametersRefused);
pub(crate) static NOT_LDAP: Thinned = Thinned::new(Note::NotLdap);
pub(crate) static CLEARTEXT_AFTER_START_TLS: Thinned = Thinned::new(Note::CleartextAfterStartTls);
pub(crate) static DIRD_NOT_SERVING: Thinned = Thinned::new(Note::DirdNotServing);
pub(crate) static TIMED_OUT: Thinned = Thinned::new(Note::TimedOut);
pub(crate) static ACCEPT_FAILED: Thinned = Thinned::new(Note::AcceptFailed);

/// A snapshot of the front's counters (for the operator and the tests).
/// Spec: docs/50 §8.2 (counts, never content).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    /// Connections closed at a connection bound.
    pub connection_limited: u64,
    /// Connections closed because their source is not internal (docs/52
    /// R14).
    pub source_not_internal: u64,
    /// TLS handshakes that failed or timed out.
    pub handshake_failed: u64,
    /// Handshakes whose parameters were refused.
    pub tls_parameters_refused: u64,
    /// Streams that were not LDAP or messages over their bound.
    pub not_ldap: u64,
    /// StartTLS requests with cleartext octets behind them.
    pub cleartext_after_start_tls: u64,
    /// Sessions closed because dird did not serve.
    pub dird_not_serving: u64,
    /// Connections closed by a timeout.
    pub timed_out: u64,
}

/// The counters now.
#[must_use]
pub fn counts() -> Counts {
    Counts {
        connection_limited: CONNECTION_LIMITED.count(),
        source_not_internal: SOURCE_NOT_INTERNAL.count(),
        handshake_failed: HANDSHAKE_FAILED.count(),
        tls_parameters_refused: TLS_PARAMETERS_REFUSED.count(),
        not_ldap: NOT_LDAP.count(),
        cleartext_after_start_tls: CLEARTEXT_AFTER_START_TLS.count(),
        dird_not_serving: DIRD_NOT_SERVING.count(),
        timed_out: TIMED_OUT.count(),
    }
}
