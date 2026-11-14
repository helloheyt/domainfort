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
    /// dird listens on `dird-ldap.sock` (task P10).
    LdapListening,
    /// A `dird-ldap.sock` connection's peer uid is not ldap-front's; closed
    /// without a reply (docs/50 §3.2).
    LdapPeerRefused,
    /// The bound on concurrent LDAP sessions is reached; the connection is
    /// refused `Busy` and closed.
    LdapSessionLimit,
    /// The LDAP engine queue is full; the request is refused `Busy` and the
    /// connection closed (docs/50 R50-7).
    LdapBusy,
    /// The audit connection was lost; LDAP operations are refused until it
    /// is back (A-57).
    AuditLost,
    /// The audit connection is back.
    AuditRestored,
    /// Shutdown requested; the queue is being drained.
    Draining,
    /// The engine thread ended before shutdown was requested.
    EngineStopped,
    /// The stop ended the audit task with LDAP events auditd had not
    /// acknowledged (logged with their count; docs/questions/Q-313).
    AuditUnacknowledged,
    /// dird listens on `dird-admin.sock` (task A8).
    AdminListening,
    /// The admin service did not start (logged with the reason's code,
    /// `admin_service::NotStarted::code`); dird's other services run.
    AdminNotStarted,
    /// A `dird-admin.sock` connection's peer uid is not admind's; closed
    /// without a reply (docs/51 §7.1).
    AdminPeerRefused,
    /// admind's connection bound is reached; the connection is refused
    /// `Busy` and closed (docs/51 §7.5).
    AdminConnectionLimit,
    /// The admin queue is full; the request is refused `Busy` (docs/51
    /// §7.5).
    AdminBusy,
    /// An admin operation was refused `Unavailable`: auditd could not take
    /// its events (A-85).
    AdminAuditUnavailable,
    /// An admin operation's outcome event could not be committed after the
    /// operation (its decision event documents it).
    AdminOutcomeUnrecorded,
    /// A committed `BeginPasswordSet` was answered `Unavailable`: keyd did
    /// not register its `SetSecret` decision (task A15a; A-102;
    /// docs/questions/Q-453 item 1). The id is the failure's class: 1 keyd
    /// refused it, 2 not performed, 3 outcome unknown.
    AdminGrantNotRegistered,
    /// An `Approve` completed a key request's quorum but its decision was
    /// not registered in keyd (or its decision event was not acknowledged —
    /// class 2): the approval was withdrawn and the answer is `Unavailable`
    /// (A-102, docs/52 §4.3). The id is the failure's class as above.
    AdminDecisionNotRegistered,
    /// A `Delete` of a user or computer committed but keyd did not register
    /// its `DestroyKeySet` decision (A-102, docs/52 §4.3): the account is
    /// deleted and its key sets are unreachable (docs/51 §9); they wait for
    /// a re-registration (docs/questions/Q-470). The id is the failure's
    /// class as above, 4 when the tombstone could not be read.
    AdminDestroyNotRegistered,
    /// The re-registration of lost destroy decisions (A-105) registered
    /// decisions keyd did not hold for tombstoned users or computers. The id
    /// is how many.
    AdminDestroyReregistered,
    /// A re-registration run stopped early; it runs again at the next
    /// interval (A-105). The id is the class: 1 keyd's listing failed, 2 a
    /// registration was not performed or its outcome is unknown, 3 keyd
    /// refused one as unavailable (its table full), 4 the tombstones could
    /// not be read.
    AdminDestroyReconcileStopped,
    /// A dual-controlled tier-map change was written as `policy.next` (task
    /// A16, docs/51 §5.10): root must activate it (`provision policy
    /// --activate-next`) and restart dird and the kdc. The id is its policy
    /// version.
    AdminPolicyNextWritten,
    /// A decided tier-map change could not be written as `policy.next`
    /// (task A16): answered unavailable, nothing pending. The id is the
    /// class: 1 the file system refused a step, 2 the directory could not be
    /// made durable.
    AdminPolicyNextNotWritten,
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
            Note::LdapListening => "listening on the LDAP channel",
            Note::LdapPeerRefused => "LDAP channel connection closed: peer uid is not ldap-front's",
            Note::LdapSessionLimit => "LDAP channel connection refused: session bound reached",
            Note::LdapBusy => "LDAP request refused: engine queue full",
            Note::AuditLost => "audit connection lost: LDAP operations refused until it is back",
            Note::AuditRestored => "audit connection restored",
            Note::Draining => "shutdown requested: draining",
            Note::EngineStopped => "engine thread stopped unexpectedly",
            Note::AuditUnacknowledged => {
                "stopping with audit events auditd did not acknowledge within the grace; count"
            }
            Note::AdminListening => "listening on the admin channel",
            Note::AdminNotStarted => {
                "admin service not started (the other services run); reason code"
            }
            Note::AdminPeerRefused => "admin channel connection closed: peer uid is not admind's",
            Note::AdminConnectionLimit => {
                "admin channel connection refused: connection bound reached"
            }
            Note::AdminBusy => "admin request refused: admin queue full",
            Note::AdminAuditUnavailable => "admin operation refused: auditd cannot take its events",
            Note::AdminOutcomeUnrecorded => {
                "admin operation outcome event not recorded (its decision event was)"
            }
            Note::AdminGrantNotRegistered => {
                "password set begun but keyd did not register its set_secret decision: answered \
                 unavailable (no password set); failure class"
            }
            Note::AdminDecisionNotRegistered => {
                "approval completed a key request but keyd did not register its decision: \
                 approval withdrawn, answered unavailable; failure class"
            }
            Note::AdminDestroyNotRegistered => {
                "account deleted but keyd did not register its destroy decision (key sets \
                 unreachable, awaiting re-registration); failure class"
            }
            Note::AdminDestroyReregistered => {
                "destroy decisions keyd had lost registered again for deleted accounts; count"
            }
            Note::AdminDestroyReconcileStopped => {
                "re-registration of destroy decisions stopped early (runs again later); class"
            }
            Note::AdminPolicyNextWritten => {
                "approved tier-map change written as policy.next: root must activate it and \
                 restart dird and the kdc; policy version"
            }
            Note::AdminPolicyNextNotWritten => {
                "approved tier-map change not written as policy.next: answered unavailable; class"
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
