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

use ipc_audit_client::{Undelivered, Unflushed};
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
    /// (A-102, docs/52 §4.3) — for class 3 (outcome unknown) the decision is
    /// revoked in keyd and the request dropped instead, or, keyd not
    /// reached, the request stays approved (task F3, docs/questions/Q-977).
    /// The id is the failure's class as above.
    AdminDecisionNotRegistered,
    /// keyd did not revoke a key-operation decision (task F3,
    /// docs/questions/Q-976, Q-977): the request stays approved. The id is
    /// the class: 1 keyd refused (the decision's execution already changed
    /// key state) at a `Withdraw` / `Reject`, 2 keyd not reached at a
    /// `Withdraw` / `Reject`, 3 keyd not reached after a registration whose
    /// outcome is unknown.
    AdminDecisionNotRevoked,
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
    /// dird listens on `dird-kpasswd.sock` (task K7, docs/53 §5.6).
    KpasswdListening,
    /// The kpasswd service did not start (logged with the reason's code,
    /// `kpasswd_service::KpasswdNotStarted::code`); dird's other services
    /// run.
    KpasswdNotStarted,
    /// A `dird-kpasswd.sock` connection's peer uid is not kpasswd-front's;
    /// closed without a reply (docs/53 §5.6 step 1; docs/50 R50-3).
    KpasswdPeerRefused,
    /// The front's connection bound is reached; the connection is refused
    /// `Busy` and closed (docs/53 §5.6 step 1).
    KpasswdConnectionLimit,
    /// The kpasswd queue is full; the request is refused `Busy` and the
    /// connection closed — the front answers HARDERROR (docs/53 §5.6 step
    /// 1, §5.7).
    KpasswdBusy,
    /// A change request was answered HARDERROR before keyd was asked:
    /// auditd could not take its events (A-85, docs/53 §5.6).
    KpasswdAuditUnavailable,
    /// A change's outcome event could not be committed after its write (its
    /// decision event documents it).
    KpasswdOutcomeUnrecorded,
    /// A committed `ChangePassword` was answered HARDERROR: keyd did not
    /// register its decision (docs/53 §5.6 step 5). The id is the failure's
    /// class: 1 keyd refused it, 2 not performed, 3 outcome unknown.
    KpasswdDecisionNotRegistered,
    /// keyd's completion of a decided change was not answered: whether the
    /// new password was installed is in keyd's audit records (docs/53 §5.6
    /// step 6 — the safe state of docs/47 §9.2); answered HARDERROR.
    KpasswdCompletionUnknown,
    /// dird listens on `dird-dns.sock` (task DN10a, docs/54 §4.6); the id is
    /// the zone's SERIAL at start.
    DnsListening,
    /// The DNS service did not start (logged with the reason's code,
    /// `dns_service::DnsNotStarted::code`); dird's other services run.
    DnsNotStarted,
    /// A `dird-dns.sock` connection's peer uid is not dnsd's; closed
    /// without a reply (docs/54 §4.6; docs/50 R50-3).
    DnsPeerRefused,
    /// dnsd's connection bound is reached; the connection is refused `Busy`
    /// and closed (docs/54 §4.6).
    DnsConnectionLimit,
    /// The DNS queue is full; the request is refused `Busy` and the
    /// connection closed — dnsd answers SERVFAIL (docs/54 §4.6).
    DnsBusy,
    /// A forwarded UPDATE / TKEY was refused `Unavailable` without being
    /// read: the DNS PEP is not built (tasks DN8, DN9; docs/questions/
    /// Q-1000 item 4).
    DnsForwardRefused,
    /// A zone image could not be projected (logged with the code of
    /// `dns_service::DnsNotStarted::code`, thinned — dnsd chooses how often
    /// it fetches); the fetch was refused `Unavailable` (fail closed — dnsd
    /// keeps its image until its staleness bound).
    DnsZoneUnavailable,
    /// The clock changed the zone's content under its SERIAL (an address
    /// aged out, an account expired) and the serial cannot be advanced yet
    /// (docs/questions/Q-993 item 3, Q-1002): the fetch was refused
    /// `Unavailable`.
    DnsSerialAdvanceNeeded,
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
            Note::AdminDecisionNotRevoked => {
                "keyd did not revoke a key request's decision: request kept approved; class"
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
            Note::KpasswdListening => "listening on the kpasswd channel",
            Note::KpasswdNotStarted => {
                "kpasswd service not started (the other services run); reason code"
            }
            Note::KpasswdPeerRefused => {
                "kpasswd channel connection closed: peer uid is not kpasswd-front's"
            }
            Note::KpasswdConnectionLimit => {
                "kpasswd channel connection refused: connection bound reached"
            }
            Note::KpasswdBusy => "kpasswd request refused: kpasswd queue full",
            Note::KpasswdAuditUnavailable => {
                "kpasswd request answered hard error: auditd cannot take its events"
            }
            Note::KpasswdOutcomeUnrecorded => {
                "password change outcome event not recorded (its decision event was)"
            }
            Note::KpasswdDecisionNotRegistered => {
                "password change committed but keyd did not register its decision: answered hard \
                 error (no password installed); failure class"
            }
            Note::KpasswdCompletionUnknown => {
                "password change completion not answered by keyd (keyd's records tell whether it \
                 was installed): answered hard error"
            }
            Note::DnsListening => "listening on the DNS channel; zone serial",
            Note::DnsNotStarted => "DNS service not started (the other services run); reason code",
            Note::DnsPeerRefused => "DNS channel connection closed: peer uid is not dnsd's",
            Note::DnsConnectionLimit => "DNS channel connection refused: connection bound reached",
            Note::DnsBusy => "DNS request refused: DNS queue full",
            Note::DnsForwardRefused => {
                "forwarded DNS message refused unread: the DNS update service is not built"
            }
            Note::DnsZoneUnavailable => "zone image not projected: fetch refused; reason code",
            Note::DnsSerialAdvanceNeeded => {
                "zone content changed with the clock under its serial and the serial cannot be \
                 advanced: fetch refused"
            }
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
        Some(id) => writeln!(err, "directory-daemon: {} [{id}]", note.text()),
        None => writeln!(err, "directory-daemon: {}", note.text()),
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
