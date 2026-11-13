//! `keyadm ceremony`: create the krbtgt key set and the two service key sets
//! the provisioning manifest names (docs/51 §4.3 step 11).
//!
//! # The steps
//!
//! 1. **Contact** — one `ping` (every mapped role may call it, docs/50
//!    §3.4). The ipc-keyd client checks the peer uid of the new connection
//!    against the configured keyd uid **before it sends anything** (R50-3;
//!    A-63) — a process that took over the socket path receives nothing.
//!    `ping` creates nothing, so a failure here means no key set was
//!    touched.
//! 2. **`create_key` ×3, in order** — `(GUID_krbtgt, Krbtgt)` with
//!    NT-SRV-INST [krbtgt, REALM]; `(GUID_ldap, Service)` with NT-SRV-HST
//!    [ldap, fqdn]; `(GUID_admin, Service)` with NT-SRV-HST [admind, fqdn]
//!    (docs/51 §4.3 step 11; docs/47 §1.4, §9.1; docs/10 §5ב, §7; A-19,
//!    A-73). keyd draws the keys and chooses the kvno (A-35); keyadm only
//!    asks.
//!
//! # Stop at the first failure, never retry
//!
//! keyd's `create_key` refuses a handle that already has a key set
//! (crates/keyd admin.rs, `KeyExists`), but reports that — like every other
//! refusal before its work (wrong role, binding refused, store refusing a
//! critical key) — as the one uniform `Denied` (docs/10 §9; the reason goes
//! only to keyd's audit record). keyadm therefore cannot tell "already
//! created" from "refused", and does not guess: it stops at the first step
//! that did not succeed, and never repeats a request whose fate it does not
//! know (a repeat could only be refused — `create_key` never overwrites —
//! but a blind repeat would hide the earlier outcome). A partial ceremony is
//! recovered in development mode by restarting keyd, which loses every key
//! (P-17), and running the whole ceremony again (A-77; docs/51 §4.5).
//!
//! # What each outcome means
//!
//! The ipc-keyd client says what it knows of a request keyd did not answer
//! (`KeydClient::call_with_fate`, `ipc_keyd::RequestFate`: not sent / not
//! performed / outcome unknown — docs/questions/Q-367, A-88); keyadm
//! reports exactly that.
//!
//! | outcome | created? |
//! |---|---|
//! | keyd answered `Ok(kvno)` | yes, with that kvno |
//! | keyd answered `Err(Denied / Unavailable / RateLimited)` | no — keyd refuses before it stores anything |
//! | not sent: peer uid not keyd's, connect failed, peer credentials unreadable, the deadline passed before sending, unencodable | no — nothing left this process |
//! | not performed: `Refused::Busy` / `Unavailable` / `Malformed` / `VersionMismatch` | no — keyd-daemon refuses a key-state change only before keyd runs it (A-88: `Busy` while auditd is away, `Unavailable` when the intent was not acknowledged in time — keyd's audit then holds the intent and a `NotPerformed` outcome) |
//! | outcome unknown: the request was sent and the connection failed, the deadline passed, or the reply could not be read | **maybe** — keyd's audit log holds the intent and the outcome; check it before anything else |
//!
//! Spec: docs/51 §4.3 steps 10-11, §4.5, §6; docs/10 §2, §7, §9, §10;
//! docs/50 R50-3, §3.4, §3.6, §3.7; A-19; A-35; A-63; A-73; A-77;
//! docs/questions/Q-365, Q-367 (A-88).

use ipc::Refused;
use ipc_keyd::{
    Answer, Call, CallFailure, Connector, KeydClient, RequestFate, TransportError, Unserved,
};
use keyd_types::{Error as KeydError, Kvno};
use provision_manifest::{KeySet, Manifest};

/// The ceremony's key sets, in the order they are created.
/// Spec: docs/51 §4.3 step 11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// `(GUID_krbtgt, Krbtgt)`, NT-SRV-INST [krbtgt, REALM]. Spec: docs/47
    /// §1.4; RFC 4120 §7.3.
    Krbtgt,
    /// `(GUID_ldap, Service)`, NT-SRV-HST [ldap, fqdn]. Spec: docs/10 §5ב;
    /// RFC 4120 §6.2.1.
    LdapService,
    /// `(GUID_admin, Service)`, NT-SRV-HST [admind, fqdn]. Spec: A-73;
    /// RFC 4120 §6.2.1.
    AdminService,
}

impl Step {
    /// Every step, in order. Spec: docs/51 §4.3 step 11.
    pub const ALL: [Step; 3] = [Step::Krbtgt, Step::LdapService, Step::AdminService];

    /// A fixed label for the report.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Step::Krbtgt => "krbtgt",
            Step::LdapService => "ldap service",
            Step::AdminService => "admin service",
        }
    }

    /// The step's key set (handle and binding) as the manifest fixes it.
    /// Spec: docs/51 §4.3 steps 8, 11.
    #[must_use]
    pub fn key_set(self, manifest: &Manifest) -> &KeySet {
        match self {
            Step::Krbtgt => manifest.krbtgt(),
            Step::LdapService => manifest.ldap_service(),
            Step::AdminService => manifest.admin_service(),
        }
    }
}

/// Why a request never left this process.
/// Spec: docs/50 R50-3, §3.7; crates/ipc-keyd client (`Unserved`,
/// `RequestFate::NotSent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotSent {
    /// The socket's peer uid is not the configured keyd uid (R50-3). (Also
    /// a failed `DescribeConfig` check of a client that requires one —
    /// keyadm's never does.)
    PeerMismatch,
    /// The socket could not be connected.
    Connect,
    /// The socket's peer credentials could not be read (on any platform but
    /// Linux they never can — the ipc-keyd connector fails closed).
    PeerCredentials,
    /// The connection failed before the request was written — in keyadm,
    /// the deadline passed while the connection was being opened.
    Transport(TransportError),
    /// The request could not be encoded.
    Unencodable,
}

/// Why keyadm does not know what keyd did with a request it sent.
/// Spec: docs/50 §3.6, §3.7; crates/ipc-keyd client
/// (`RequestFate::OutcomeUnknown`); docs/questions/Q-367 (A-88).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unknown {
    /// The connection failed after the request was handed to it.
    Transport(TransportError),
    /// The reply did not decode.
    MalformedReply,
    /// The reply decoded but did not answer this operation.
    UnexpectedReply,
}

/// How one call to keyd ended, as far as keyadm can know.
/// Spec: module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome<T> {
    /// keyd ran the operation and answered.
    Answered(Result<T, KeydError>),
    /// Nothing reached keyd.
    NotSent(NotSent),
    /// keyd's transport refused the request: keyd did not perform it (A-88).
    NotPerformed(Refused),
    /// The request was sent and may or may not have been performed.
    Unknown(Unknown),
}

impl<T> Outcome<T> {
    /// `true` for `Answered(Ok(_))`.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self, Outcome::Answered(Ok(_)))
    }

    /// `true` if the call may have changed keyd's state without keyadm
    /// knowing (only [`Outcome::Unknown`]).
    #[must_use]
    pub const fn outcome_unknown(&self) -> bool {
        matches!(self, Outcome::Unknown(_))
    }
}

/// Classify the result of one `KeydClient::call_with_fate`; `pick` takes
/// keyd's answer out of the [`Answer`] variant of the operation called.
///
/// The client's fate decides the class (it alone knows whether the request
/// was written); the `Unserved` reason only chooses the text. A combination
/// the client never produces — a refusal reported as not sent other than by
/// the `DescribeConfig` check, or anything but a `Refused` reported as not
/// performed — falls to the class that claims least: not sent ⇒ the peer
/// check, not performed ⇒ outcome unknown.
///
/// Spec: module documentation; crates/ipc-keyd client (`CallFailure`,
/// `RequestFate`); docs/questions/Q-367 (A-88).
pub fn classify<T>(
    result: Result<Answer, CallFailure>,
    pick: impl FnOnce(Answer) -> Option<Result<T, KeydError>>,
) -> Outcome<T> {
    let failure = match result {
        Ok(answer) => {
            return match pick(answer) {
                Some(answered) => Outcome::Answered(answered),
                None => Outcome::Unknown(Unknown::UnexpectedReply),
            }
        }
        Err(failure) => failure,
    };
    match (failure.fate, failure.unserved) {
        (RequestFate::NotSent, Unserved::Unencodable) => Outcome::NotSent(NotSent::Unencodable),
        (RequestFate::NotSent, Unserved::Transport(TransportError::Connect)) => {
            Outcome::NotSent(NotSent::Connect)
        }
        (RequestFate::NotSent, Unserved::Transport(TransportError::PeerCredentials)) => {
            Outcome::NotSent(NotSent::PeerCredentials)
        }
        (RequestFate::NotSent, Unserved::Transport(other)) => {
            Outcome::NotSent(NotSent::Transport(other))
        }
        (
            RequestFate::NotSent,
            Unserved::PeerMismatch
            | Unserved::Refused(_)
            | Unserved::MalformedReply(_)
            | Unserved::UnexpectedReply(_),
        ) => Outcome::NotSent(NotSent::PeerMismatch),
        (RequestFate::NotPerformed, Unserved::Refused(refused)) => Outcome::NotPerformed(refused),
        (RequestFate::NotPerformed | RequestFate::OutcomeUnknown, Unserved::Transport(error)) => {
            Outcome::Unknown(Unknown::Transport(error))
        }
        (RequestFate::NotPerformed | RequestFate::OutcomeUnknown, Unserved::MalformedReply(_)) => {
            Outcome::Unknown(Unknown::MalformedReply)
        }
        (
            RequestFate::NotPerformed | RequestFate::OutcomeUnknown,
            Unserved::UnexpectedReply(_)
            | Unserved::Refused(_)
            | Unserved::PeerMismatch
            | Unserved::Unencodable,
        ) => Outcome::Unknown(Unknown::UnexpectedReply),
    }
}

/// One `create_key` step and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    /// Which key set.
    pub step: Step,
    /// How the call ended (`Ok(kvno)` when created).
    pub outcome: Outcome<Kvno>,
}

/// What the ceremony did: the contact, then the steps attempted (in order;
/// it stops after the first that did not succeed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyReport {
    /// The `ping` that opened (and verified) the connection.
    pub contact: Outcome<()>,
    /// The `create_key` steps attempted.
    pub steps: Vec<StepReport>,
}

impl CeremonyReport {
    /// `true` if all three key sets were created.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.contact.succeeded()
            && self.steps.len() == Step::ALL.len()
            && self.steps.iter().all(|step| step.outcome.succeeded())
    }

    /// The steps whose key set was created, with the kvno keyd chose.
    #[must_use]
    pub fn created(&self) -> Vec<(Step, Kvno)> {
        self.steps
            .iter()
            .filter_map(|report| match report.outcome {
                Outcome::Answered(Ok(kvno)) => Some((report.step, kvno)),
                _ => None,
            })
            .collect()
    }

    /// The steps never attempted (after the one that stopped the ceremony).
    #[must_use]
    pub fn not_attempted(&self) -> Vec<Step> {
        Step::ALL
            .iter()
            .copied()
            .filter(|step| !self.steps.iter().any(|report| report.step == *step))
            .collect()
    }
}

/// Run the ceremony for `manifest` through `client` (see the module
/// documentation): contact, then `create_key` for each [`Step`] in order,
/// stopping at the first that does not succeed. Never retries.
///
/// Spec: docs/51 §4.3 step 11; docs/10 §7; docs/50 R50-3; A-19; A-35; A-77;
/// docs/questions/Q-367 (A-88: each call's fate from the client).
pub fn run<C: Connector>(client: &mut KeydClient<C>, manifest: &Manifest) -> CeremonyReport {
    let contact = classify(client.call_with_fate(&Call::Ping), |answer| match answer {
        Answer::Ping(result) => Some(result),
        _ => None,
    });
    let mut steps = Vec::with_capacity(Step::ALL.len());
    if !contact.succeeded() {
        return CeremonyReport { contact, steps };
    }
    for step in Step::ALL {
        let key_set = step.key_set(manifest);
        let call = Call::CreateKey {
            handle: key_set.handle,
            binding: key_set.binding.clone(),
        };
        let outcome = classify(client.call_with_fate(&call), |answer| match answer {
            Answer::CreateKey(result) => Some(result),
            _ => None,
        });
        let stop = !outcome.succeeded();
        steps.push(StepReport { step, outcome });
        if stop {
            break;
        }
    }
    CeremonyReport { contact, steps }
}
