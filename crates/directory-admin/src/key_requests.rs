//! Dual-controlled key operations (docs/51 §5.6, §6; R51-11, R51-14; task
//! A10; A-102): the pending requests dird holds **in memory**, and the two
//! steps that act on them — `RequestKeyOperation` and `Approve`. The
//! `Approve` that completes the quorum yields the **decision** dird
//! registers in keyd ([`KeyDecision`]; docs/52 R1, §4.3).
//!
//! # The flow (docs/51 §6, as decided)
//!
//! 1. A requester opens a request for one key operation —
//!    `rotate_krbtgt`, `rotate_key` of a service object's randomized key
//!    set, or `retire_kvno` — with a fresh AP-REQ that dird
//!    verified through keyd (A-73). dird builds the Subject from the
//!    directory and asks the PDP for `PolicyAdmin` on the policy scope
//!    `keys` ([`KEY_POLICY_SCOPE`]; docs/51 §5.2 row 11 — docs/questions/
//!    Q-420).
//! 2. Approvers approve it, each with a fresh, verified AP-REQ: distinct
//!    from the requester and from every earlier approver, `decide` = Allow
//!    for the same Action and Resource, and naming **the exact operation**
//!    the request holds — the approval is bound to the request's operation
//!    digest (docs/24 §6 principle "sign the exact operation, not a general
//!    approve", as docs/51 §5.6 cites it). The quorum is `admin_quorum`
//!    (P-22: the requester plus one approver).
//! 3. **(A-102)** The `Approve` that completes the quorum yields a
//!    [`KeyDecision`]: the decision id (the request's id), the decided
//!    operation with its key set, the requester's and the approvers'
//!    objectGUIDs, and the request's remaining lifetime. dird has the
//!    step's `Decision` event acknowledged by auditd, then registers the
//!    decision in keyd (Role::Ldap, `register_decision`), then records an
//!    `Outcome` event of the registration ([`KeyStep::registration_event`]);
//!    if any of it fails the approval is withdrawn
//!    ([`KeyRequests::withdraw`]) so the approver may approve again.
//! 4. keyadm runs `rotate_krbtgt(id)` / `rotate_key(id)` / `retire_kvno(id)`
//!    in keyd as Role::Admin: keyd runs the parameters **dird registered**
//!    and builds the dual-control token itself from the registered
//!    approvers. keyadm takes nothing from dird or admind — the former
//!    `FetchApproved` / `Complete` / `ListPendingDestruction` channel is
//!    retired (docs/52 §4.6, §4.8; docs/questions/Q-460: N2 is impossible
//!    by construction).
//!
//! # The pending table
//!
//! A request = {id, the operation, the key set it acts on, the operation
//! digest, the requester, the approvals, the expiry, fetched?}. The key set
//! of a service object is the target's [`ServiceKeyHandle`] — its purpose
//! derived from the service's name, `Service` for the LDAP service and
//! `AdminService` for the admin service (docs/52 R2b; docs/questions/Q-493
//! item 1): an operation names an object, never a purpose. In dird's
//! memory only, bounded in number ([`MAX_PENDING_KEY_REQUESTS`]) and in
//! time (the configured lifetime, at most [`MAX_KEY_REQUEST_LIFETIME`];
//! expired requests are dropped before every step). A dird restart drops
//! every request (fail closed). The id is a `u64` from a counter seeded by
//! the caller (A-85 / Q-340 item 9).
//!
//! The digest is SHA-256 (the approved RustCrypto `sha2`, called through its
//! documented `Digest` API — no primitive implemented here, AGENTS.md §6)
//! over a domain-separated, fixed-layout encoding of the request: a label,
//! the id, the operation's code, the key set's principal id and purpose,
//! the kvno a `retire_kvno` names, the requester's objectGUID and the
//! expiry ([`operation_digest`]). It is shown back on every step.
//!
//! # Audit (A-85; Q-340 items 1, 9)
//!
//! Every step has a `DirAdmin` `Decision` event — `key_request` (the id),
//! `key_operation` (the keyd operation), `target` (the key set's account),
//! `requester` / `approvers` (objectSids). The `Approve` that completes the
//! quorum has, after its `Decision`, an `Outcome` event saying how the
//! registration of its decision in keyd ended (`Committed`, or the codes
//! `KeyOperationRefused` / `KeyOperationNotPerformed` /
//! `KeyOperationOutcomeUnknown` of docs/questions/Q-421, reused for the
//! registration — A-102). keyd's own records (intent + outcome, the
//! decision id) say what keyd executed (docs/52 §4.5).
//!
//! Spec: docs/51 §5.2 row 11, §5.6, §6, §7.3, §9; docs/24 §6; docs/10 §7;
//! docs/33 §5; A-73; A-85; A-89; P-22; FIPS 180-4 (SHA-256, as provided by
//! the approved `sha2`); docs/questions/Q-420..Q-422; docs/52 §4.2, §4.3
//! (A-102); docs/questions/Q-460.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use directory_pip::DirectoryView;
use dtyp::{Guid, Sid};
use ipc_audit::{
    AdminFailure, AdminRefusal, DirAdminEvent, DirAdminOperation, DirAdminStage, EventBody,
    IntentRecord, KeydOperation, OutcomeResult,
};
use keyd_types::{
    DecidedOperation, DecisionId, KeyHandle, KeyPurpose, Kvno, OperationDigest, PrincipalId,
    ServiceKeyHandle, MAX_KEY_DECISION_SECS,
};
use krb_proto::KerberosTime;
use pdp::{Action, Effect, Obligation, PolicyScope, PolicySnapshot, Resource};
use sha2::{Digest, Sha256};

use crate::admin::{subject_of, DirectoryAdmin, VerificationFailure};
use crate::audit::{pdp_reason, sid_value, EventBase, Refusal, Stop};
use crate::checks::{self, local_ipc_security, malformed, Cx};
use crate::config::ConfigError;
use crate::random::RandomSource;
use crate::record;
use crate::subject::{AdminSubject, SubjectError, VerifiedTicket};

/// The policy scope of the key operations: `PolicyAdmin` on `Policy {scope:
/// "keys"}`. The policy language already matches every scope (`scope:
/// None`, the rule `provision domain` writes for the Tier-0 group) or this
/// one exactly, so no language change is needed.
/// Spec: docs/51 §5.2 row 11 (`PolicyAdmin(scope "keys")`); docs/06 §9;
/// crates/pdp policy.rs (`ResourceMatch::Policy`); docs/questions/Q-420.
pub const KEY_POLICY_SCOPE: &str = "keys";

/// Most pending key-operation requests dird holds at once (approved ones
/// included, until they expire). Project choice: key operations are
/// rare and human-paced. Spec: docs/51 §5.6 ("bounded in number");
/// AGENTS.md §6.
pub const MAX_PENDING_KEY_REQUESTS: usize = 16;

/// The default lifetime of a pending request: 15 minutes — long enough for
/// an approver to obtain a ticket and approve, short enough that an
/// approval is about a decision taken now. Project choice (⚠ the owner may
/// prefer another). Spec: docs/51 §5.6 ("bounded in time", "TTL").
pub const KEY_REQUEST_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// The longest lifetime accepted: one hour (the ceiling of
/// `admin_ticket_age_max`, docs/questions/Q-385 item 4). Spec: docs/51
/// §5.6; AGENTS.md §6.
pub const MAX_KEY_REQUEST_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// Octets of an operation digest (SHA-256). Spec: FIPS 180-4 §6.2 (a 256-bit
/// message digest), as provided by the approved `sha2`.
pub const DIGEST_LEN: usize = 32;

/// The digest's domain-separation label: no other digest of this project
/// starts with it. Project choice.
const DIGEST_LABEL: &[u8] = b"dird key-operation request, layout 1";

/// Which key set a `retire_kvno` names. Spec: docs/51 §6; docs/10 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRef {
    /// The krbtgt key set (the provisioning manifest's).
    Krbtgt,
    /// The key set of a service object (its purpose: the target's
    /// [`ServiceKeyHandle`], [`KeyTargets::handle_of`]).
    Service(Guid),
}

/// The key operation of a pending request. Spec: docs/51 §6 (the
/// `rotate-key`, `rotate-krbtgt`, `retire-kvno` rows: "approved request
/// (dual)"); docs/10 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyOperation {
    /// `rotate_krbtgt(DualControlToken)`.
    RotateKrbtgt,
    /// `rotate_key` of a service object's randomized key set (created by
    /// `create_key` in the ceremony — docs/10 §5ב; not a computer's
    /// password-derived one) — `Service` or `AdminService`, as the
    /// service's name derives it ([`KeyTargets::handle_of`]).
    RotateKey {
        /// The service object's objectGUID.
        service: Guid,
    },
    /// `retire_kvno` after a rotation (docs/33 §5: recovery = a double
    /// rotation, then `retire_kvno`).
    RetireKvno {
        /// The key set.
        key: KeyRef,
        /// The key version to retire.
        kvno: u32,
    },
}

impl KeyOperation {
    /// The keyd operation it asks for (the audit code).
    /// Spec: crate ipc-audit `KeydOperation`.
    #[must_use]
    pub fn keyd_operation(&self) -> KeydOperation {
        match self {
            KeyOperation::RotateKrbtgt => KeydOperation::RotateKrbtgt,
            KeyOperation::RotateKey { .. } => KeydOperation::RotateKey,
            KeyOperation::RetireKvno { .. } => KeydOperation::RetireKvno,
        }
    }

    /// The service object it names, if any. (An operation names an object,
    /// never a purpose: the purpose of a service object's key set is
    /// derived from its name — [`KeyTargets::handle_of`]; docs/52 R2b.)
    fn service(&self) -> Option<Guid> {
        match self {
            KeyOperation::RotateKey { service }
            | KeyOperation::RetireKvno {
                key: KeyRef::Service(service),
                ..
            } => Some(*service),
            KeyOperation::RotateKrbtgt
            | KeyOperation::RetireKvno {
                key: KeyRef::Krbtgt,
                ..
            } => None,
        }
    }

    /// Whether keyd answers it with a kvno (the rotations do; `retire_kvno`
    /// answers `()`). Spec: docs/10 §7.
    #[must_use]
    pub fn answers_kvno(&self) -> bool {
        !matches!(self, KeyOperation::RetireKvno { .. })
    }

    /// The code of the operation in the digest (the admin channel's codes).
    fn code(&self) -> u8 {
        match self {
            KeyOperation::RotateKrbtgt => 1,
            KeyOperation::RotateKey { .. } => 2,
            KeyOperation::RetireKvno { .. } => 3,
        }
    }
}

/// One key-plane request dird serves (docs/51 §7.3, the key-operation
/// rows).
/// Spec: docs/51 §6, §7.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAdminOperation {
    /// `RequestKeyOperation {operation}` (an AP-REQ).
    RequestKeyOperation {
        /// The operation asked for.
        operation: KeyOperation,
    },
    /// `Approve {id, operation}` (an AP-REQ).
    Approve {
        /// The request.
        id: u64,
        /// The exact operation approved.
        operation: KeyOperation,
    },
}

impl KeyAdminOperation {
    /// The audit code. Spec: crate ipc-audit `DirAdminOperation`.
    #[must_use]
    pub fn code(&self) -> DirAdminOperation {
        match self {
            KeyAdminOperation::RequestKeyOperation { .. } => DirAdminOperation::RequestKeyOperation,
            KeyAdminOperation::Approve { .. } => DirAdminOperation::Approve,
        }
    }

    /// Whether the request carries an administrator's AP-REQ (the
    /// requester's or the approver's): both steps do (keyadm's requests,
    /// which carried none, are retired — A-102).
    /// Spec: docs/51 §6; docs/questions/Q-422, Q-460.
    #[must_use]
    pub fn takes_ticket(&self) -> bool {
        true
    }

    /// The `DirAdmin` events it may record: two for `Approve` (its decision
    /// and, when it completes the quorum, the outcome of the decision's
    /// registration in keyd — the second slot is released otherwise), one
    /// for `RequestKeyOperation`.
    /// Spec: module documentation; Q-340 item 1; docs/52 §4.3 (A-102).
    #[must_use]
    pub fn audit_events(&self) -> usize {
        match self {
            KeyAdminOperation::Approve { .. } => 2,
            KeyAdminOperation::RequestKeyOperation { .. } => 1,
        }
    }
}

/// The key sets a request may name: the krbtgt account's objectGUID and the
/// service objects' key sets (the provisioning manifest's — the only
/// randomized service key sets of phase 1, docs/51 §4.3 step 11).
///
/// A service object's key set is a [`ServiceKeyHandle`], which only the
/// derivation from the service's name builds (`Service` for `ldap/<fqdn>`,
/// `AdminService` for `admind/<fqdn>`): the table cannot hold — and a key
/// operation cannot name — a purpose that contradicts the name (docs/52
/// R2b; docs/questions/Q-493 item 1).
/// Spec: docs/51 §4.3 steps 8, 11, §6; docs/questions/Q-386 item 1; docs/47
/// §1.3; docs/52 §5 item 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTargets {
    /// The krbtgt account's objectGUID.
    pub krbtgt: Guid,
    /// The service objects' key sets, each named by its derived handle.
    pub services: BTreeSet<ServiceKeyHandle>,
}

impl KeyTargets {
    /// The key set `operation` acts on: the krbtgt account's `Krbtgt` key
    /// set, or the named service object's key set as its
    /// [`ServiceKeyHandle`] derives it; `None` when the operation names a
    /// service object that is not one of the targets.
    /// Spec: docs/51 §6; docs/10 §1, §7; docs/52 R2b.
    #[must_use]
    pub fn handle_of(&self, operation: &KeyOperation) -> Option<KeyHandle> {
        match operation.service() {
            None => Some(KeyHandle::new(
                PrincipalId::from_bytes(self.krbtgt.to_packet()),
                KeyPurpose::Krbtgt,
            )),
            Some(service) => {
                let principal = PrincipalId::from_bytes(service.to_packet());
                self.services
                    .iter()
                    .find(|target| target.principal() == principal)
                    .map(ServiceKeyHandle::handle)
            }
        }
    }
}

/// A principal of a pending request: its objectGUID (keyd's token) and its
/// objectSid (the audit event).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Party {
    guid: Guid,
    sid: Sid,
}

/// One pending request (module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    operation: KeyOperation,
    /// The key set it acts on ([`KeyTargets::handle_of`]).
    handle: KeyHandle,
    digest: [u8; DIGEST_LEN],
    requester: Party,
    approvals: Vec<Party>,
    expires: u64,
}

/// The pending key-operation requests (module documentation).
/// Spec: docs/51 §5.6.
#[derive(Debug, Clone)]
pub struct KeyRequests {
    pending: BTreeMap<u64, Pending>,
    next_id: u64,
    lifetime: u64,
    targets: KeyTargets,
}

impl KeyRequests {
    /// An empty table. `lifetime` must be 1 s ..=
    /// [`MAX_KEY_REQUEST_LIFETIME`]; ids start after `first_id` (the caller
    /// seeds it, e.g. from its start time, so ids of two runs do not
    /// overlap — Q-388 item 4's rule for operation numbers).
    ///
    /// # Errors
    /// [`ConfigError::KeyRequestLifetime`].
    ///
    /// Spec: docs/51 §5.6.
    pub fn new(
        targets: KeyTargets,
        lifetime: Duration,
        first_id: u64,
    ) -> Result<KeyRequests, ConfigError> {
        if lifetime.as_secs() == 0 || lifetime > MAX_KEY_REQUEST_LIFETIME {
            return Err(ConfigError::KeyRequestLifetime);
        }
        Ok(KeyRequests {
            pending: BTreeMap::new(),
            next_id: first_id,
            lifetime: lifetime.as_secs(),
            targets,
        })
    }

    /// The requests held (expired ones included until the next step drops
    /// them).
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no request is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Drop every request whose expiry is at or before `now`.
    fn purge(&mut self, now: u64) {
        self.pending.retain(|_, pending| pending.expires > now);
    }

    /// Withdraw the approval that completed `decision`'s quorum, after the
    /// decision could not be recorded or registered in keyd (module
    /// documentation, step 3): the request's last approval is removed when
    /// it is that decision's last approver, so the approver may approve
    /// again. `true` if one was removed. keyd accepts the same decision
    /// again unchanged (an identical re-registration — keyd decision.rs), so
    /// a second `Approve` after "outcome unknown" is harmless.
    /// Spec: docs/52 §4.3 ("failure to register ⇒ dird answers
    /// `Unavailable`"); A-85 / docs/questions/Q-453 item 1 (fail closed).
    pub fn withdraw(&mut self, decision: &KeyDecision) -> bool {
        let Some(pending) = self.pending.get_mut(&decision.id.get()) else {
            return false;
        };
        let last = pending
            .approvals
            .last()
            .map(|p| PrincipalId::from_bytes(p.guid.to_packet()));
        if last.is_some() && last == decision.approvers.last().copied() {
            pending.approvals.pop();
            true
        } else {
            false
        }
    }
}

/// The operation digest of a request (module documentation): SHA-256 over
/// `label ‖ id:u64 ‖ code:u8 ‖ principal:[16] ‖ purpose:u8 ‖ kvno:u32 ‖
/// requester:[16] ‖ expires:u64` (integers big-endian; the kvno 0 when the
/// operation names none). `key` is the key set the operation acts on
/// ([`KeyTargets::handle_of`]): its principal and its purpose. Public so
/// that a client can show or check it.
/// Spec: docs/51 §5.6 ("the operation digest"); docs/24 §6 (principle);
/// FIPS 180-4 via the approved `sha2` (`Digest::digest`, docs.rs sha2
/// 0.11.1 as crates/audit-log cites it); docs/questions/Q-420; docs/52 R2b.
#[must_use]
pub fn operation_digest(
    id: u64,
    operation: &KeyOperation,
    key: KeyHandle,
    requester: Guid,
    expires: u64,
) -> [u8; DIGEST_LEN] {
    let kvno = match operation {
        KeyOperation::RetireKvno { kvno, .. } => *kvno,
        KeyOperation::RotateKrbtgt | KeyOperation::RotateKey { .. } => 0,
    };
    let purpose: u8 = match key.purpose {
        KeyPurpose::PrincipalLongterm => 0,
        KeyPurpose::Krbtgt => 1,
        KeyPurpose::Service => 2,
        // The admin service's key set (R2, R2b): a code of its own so that
        // no two purposes share one.
        KeyPurpose::AdminService => 3,
        // The change-password service's key set (task K3, docs/53 §5.2): a
        // code of its own too (keyd refuses to rotate it — docs/53 §4.5).
        KeyPurpose::ChangePasswordService => 4,
    };
    let mut octets = Vec::with_capacity(DIGEST_LABEL.len() + 8 + 1 + 16 + 1 + 4 + 16 + 8);
    octets.extend_from_slice(DIGEST_LABEL);
    octets.extend_from_slice(&id.to_be_bytes());
    octets.push(operation.code());
    octets.extend_from_slice(key.principal.as_bytes());
    octets.push(purpose);
    octets.extend_from_slice(&kvno.to_be_bytes());
    octets.extend_from_slice(&requester.to_packet());
    octets.extend_from_slice(&expires.to_be_bytes());
    <[u8; DIGEST_LEN]>::from(Sha256::digest(&octets))
}

/// A pending request as shown back to the requester and the approvers.
/// Spec: docs/51 §5.6, §7.3 (`id / state`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestView {
    /// The id.
    pub id: u64,
    /// The operation digest.
    pub digest: [u8; DIGEST_LEN],
    /// The operation.
    pub operation: KeyOperation,
    /// Approvals recorded so far.
    pub approvals: usize,
    /// The quorum (requester included).
    pub quorum: usize,
}

/// The decision an `Approve` completing the quorum yields: what dird
/// registers in keyd (`register_decision`, Role::Ldap) so that keyadm can
/// run it there by its id (A-102, docs/52 §4.2, §4.3).
/// Spec: docs/52 §4.2 (`register_decision(id, op, approvers, lifetime)`),
/// §4.3 (the key-operation rows); docs/51 §5.6 (`DualControlToken
/// { approver_1: the requester, approver_2: the approver }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDecision {
    /// The decision id: the request's id (unique across dird's runs,
    /// docs/questions/Q-421 item 3) — the id the operator gives keyadm.
    pub id: DecisionId,
    /// The decided operation, with the key set it acts on.
    pub operation: DecidedOperation,
    /// The requester's objectGUID, then the approvers' in approval order.
    pub approvers: Vec<PrincipalId>,
    /// The request's remaining lifetime, in seconds (1 to keyd's
    /// `MAX_KEY_DECISION_SECS`): the decision lives no longer than the
    /// request it came from (docs/questions/Q-460 parameters).
    pub lifetime_secs: u32,
}

/// How the registration of a [`KeyDecision`] in keyd ended (its `Outcome`
/// event, [`KeyStep::registration_event`]).
/// Spec: docs/52 §4.3, §4.5; docs/10 §9, §10; A-88, A-90 (the fates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistrationOutcome {
    /// keyd registered it.
    Registered,
    /// keyd answered with a refusal.
    Refused,
    /// Not performed: never sent, keyd's transport refused it, or the
    /// step's `Decision` event was not acknowledged in time (nothing was
    /// asked of keyd).
    NotPerformed,
    /// Sent; no usable answer came back (keyd may hold it — its records
    /// say).
    OutcomeUnknown,
}

/// The reply of a key-plane step.
/// Spec: docs/51 §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyReply {
    /// `RequestKeyOperation` / `Approve`.
    Request(KeyRequestView),
}

/// A key-plane step that succeeded: its reply, its `Decision` event, and —
/// for an `Approve` that completed the quorum — the decision to register in
/// keyd and what its registration's `Outcome` event is built from.
/// Spec: module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStep {
    reply: KeyReply,
    events: Vec<DirAdminEvent>,
    decision: Option<KeyDecision>,
    base: EventBase,
    now: KerberosTime,
}

impl KeyStep {
    /// The reply.
    #[must_use]
    pub fn reply(&self) -> &KeyReply {
        &self.reply
    }

    /// The events to commit, in order, before the reply (the `Decision`).
    #[must_use]
    pub fn events(&self) -> &[DirAdminEvent] {
        &self.events
    }

    /// The decision to register in keyd: `Some` only for an `Approve` that
    /// completed the quorum.
    /// Spec: docs/52 §4.3 (A-102).
    #[must_use]
    pub fn decision(&self) -> Option<&KeyDecision> {
        self.decision.as_ref()
    }

    /// The `Outcome` event of the decision's registration (module
    /// documentation, step 3): `Committed` when keyd registered it, else the
    /// codes of docs/questions/Q-421 item 7, reused for the registration.
    /// Spec: docs/52 §4.3, §4.5; docs/51 §5.7 item 2 (decision ⇒ change ⇒
    /// outcome); A-85.
    #[must_use]
    pub fn registration_event(&self, outcome: RegistrationOutcome) -> DirAdminEvent {
        let stage = match outcome {
            RegistrationOutcome::Registered => {
                DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
            }
            RegistrationOutcome::Refused => {
                DirAdminStage::Outcome(OutcomeResult::Refused(AdminRefusal::KeyOperationRefused))
            }
            RegistrationOutcome::NotPerformed => DirAdminStage::Outcome(OutcomeResult::Failed(
                AdminFailure::KeyOperationNotPerformed,
            )),
            RegistrationOutcome::OutcomeUnknown => DirAdminStage::Outcome(OutcomeResult::Failed(
                AdminFailure::KeyOperationOutcomeUnknown,
            )),
        };
        self.base.staged(&self.now, stage)
    }
}

impl KeyStep {
    /// The `Approve` that completed its request's quorum, as a
    /// [`QuorumStep`] — its `Decision` event and the decision to register —
    /// or the step back (no decision, or no event to record it with).
    /// Spec: docs/52 §4.3 (A-102), §3.11 R6 (a).
    ///
    /// # Errors
    /// The step back (boxed: it is large) when it is not such an `Approve`.
    pub fn into_quorum(self) -> Result<QuorumStep, Box<KeyStep>> {
        match (self.events.first().cloned(), self.decision.clone()) {
            (Some(event), Some(decision)) => Ok(QuorumStep {
                event,
                decision,
                step: self,
            }),
            _ => Err(Box::new(self)),
        }
    }
}

/// The `Approve` that completed its request's quorum (A-102, docs/52 §4.3):
/// its `Decision` event — its [`IntentRecord`], which auditd must
/// acknowledge before dird registers the decision in keyd (A-85: no
/// loosening of keyd without the PDP's decision durably recorded) — and the
/// [`KeyDecision`]. dird's registration takes it only as an
/// `ipc_audit::AckedIntent<QuorumStep>` (docs/52 §3.11 R6 (a)). Not `Clone`.
/// Spec: docs/52 §4.3, §3.11 R6 (a); docs/51 §5.6, §5.7 item 2; A-85.
#[derive(Debug, PartialEq, Eq)]
pub struct QuorumStep {
    event: DirAdminEvent,
    decision: KeyDecision,
    step: KeyStep,
}

impl QuorumStep {
    /// The decision to register in keyd.
    #[must_use]
    pub fn decision(&self) -> &KeyDecision {
        &self.decision
    }

    /// The reply.
    #[must_use]
    pub fn reply(&self) -> &KeyReply {
        self.step.reply()
    }

    /// The `Outcome` event of the registration ([`KeyStep::registration_event`]).
    #[must_use]
    pub fn registration_event(&self, outcome: RegistrationOutcome) -> DirAdminEvent {
        self.step.registration_event(outcome)
    }
}

impl IntentRecord for QuorumStep {
    /// The `Approve`'s `Decision` event.
    /// Spec: docs/51 §5.7 item 2; docs/52 §4.3.
    fn intent_event(&self) -> EventBody {
        EventBody::DirAdmin(Box::new(self.event.clone()))
    }
}

/// The principal of a deleted user or computer: a tombstone of the `user`
/// class (users and computers — the objects with key sets, docs/47 §9.1)
/// read from dird's store. Made only by
/// [`DirectoryAdmin::destruction_target`] and
/// [`DirectoryAdmin::destruction_targets`]; the only input from which dird
/// registers a `DestroyKeySet` decision, so a destroy decision can name only
/// an account whose `Delete` committed — after its decision event was
/// acknowledged (A-85) — and never a live account ("harmless by
/// construction: tombstones only", docs/52 §4.3). Not `Clone`.
/// Spec: docs/52 §4.3, §3.11 R6; docs/51 §6, §9; A-18; docs/questions/Q-470
/// (A-105: re-registration).
#[derive(Debug, PartialEq, Eq)]
pub struct TombstonedPrincipal {
    guid: Guid,
}

impl TombstonedPrincipal {
    /// The deleted object's GUID (its tombstone's key).
    #[must_use]
    pub fn guid(&self) -> Guid {
        self.guid
    }

    /// The principal id of its key sets: the objectGUID's packet form
    /// (docs/51 §5.5: keyd's handle of an account is its objectGUID).
    #[must_use]
    pub fn principal(&self) -> PrincipalId {
        PrincipalId::from_bytes(self.guid.to_packet())
    }
}

/// One page of [`DirectoryAdmin::destruction_targets`]: the tombstoned
/// users and computers found, ascending by GUID, and where to resume.
/// Spec: dirstore `TombstonePage`; docs/32 §8 (bounded paging).
#[derive(Debug, PartialEq, Eq)]
pub struct DestructionTargets {
    /// The tombstones of the `user` class on this page.
    pub targets: Vec<TombstonedPrincipal>,
    /// `Some(g)`: records after `g` remain — pass it as `after`; `None`: the
    /// listing is complete.
    pub next: Option<Guid>,
}

/// The per-request inputs of a step.
#[derive(Clone, Copy)]
struct StepInputs<'t, 'v, 'a, 'p> {
    ticket: Option<&'t VerifiedTicket>,
    /// The step's operation digest (R2, docs/52 §5 item 4).
    digest: &'p OperationDigest,
    approvals_supplied: usize,
    view: &'v DirectoryView<'a>,
    policy: &'p PolicySnapshot,
    now: &'p KerberosTime,
}

/// The inputs of one `Approve`.
#[derive(Clone, Copy)]
struct Approval<'r> {
    id: u64,
    operation: &'r KeyOperation,
    ticket: &'r VerifiedTicket,
    approvals_supplied: usize,
}

/// The obligations of an Allow other than the audit record this crate
/// plans (the caller honours them, docs/11 §2).
fn caller_obligations(decision: &pdp::Decision) -> Vec<Obligation> {
    decision
        .obligations
        .iter()
        .filter(|o| !matches!(o, Obligation::Audit))
        .cloned()
        .collect()
}

/// The event base of a key-plane step: the operation code, the id and the
/// keyd operation the request itself names.
fn key_base(operation_id: u64, request: &KeyAdminOperation) -> EventBase {
    let mut base = EventBase::bare(operation_id, request.code());
    match request {
        KeyAdminOperation::RequestKeyOperation { operation } => {
            base.key_operation = Some(operation.keyd_operation());
        }
        KeyAdminOperation::Approve { id, operation } => {
            base.key_request = Some(*id);
            base.key_operation = Some(operation.keyd_operation());
        }
    }
    base
}

/// The objectGUID of the account a key set belongs to (the audit target).
/// Spec: docs/47 §2.3 (R47-3: `PrincipalId = objectGUID`).
fn account_of(handle: &KeyHandle) -> Guid {
    Guid::from_packet(handle.principal.as_bytes())
}

/// Record a pending request's parties and target in `base`.
fn describe(base: &mut EventBase, pending: &Pending) {
    base.key_operation = Some(pending.operation.keyd_operation());
    base.target = Some(account_of(&pending.handle));
    base.requester = sid_value(&pending.requester.sid);
    base.approvers = pending
        .approvals
        .iter()
        .filter_map(|p| sid_value(&p.sid))
        .collect();
}

/// The shown-back state of a pending request.
fn view_of(id: u64, pending: &Pending, quorum: usize) -> KeyRequestView {
    KeyRequestView {
        id,
        digest: pending.digest,
        operation: pending.operation,
        approvals: pending.approvals.len(),
        quorum,
    }
}

impl<R: RandomSource> DirectoryAdmin<R> {
    /// The refusal of a key-plane request whose AP-REQ keyd did not verify
    /// (or could not be asked): its `Decision` event and the uniform
    /// `Denied` / `Unavailable`. The ticket of an `Approve` is the
    /// approver's (`ApproverUnauthenticated`).
    /// Spec: docs/51 §7.4 step 1; A-26; A-56.
    #[must_use]
    pub fn refuse_unverified_key(
        &self,
        operation_id: u64,
        request: &KeyAdminOperation,
        failure: VerificationFailure,
        now: &KerberosTime,
    ) -> Refusal {
        let base = key_base(operation_id, request);
        let stop = match (failure, request) {
            (VerificationFailure::KeydUnavailable, _) => {
                Stop::Failed(AdminFailure::KeydUnavailable)
            }
            (_, KeyAdminOperation::Approve { .. }) | (VerificationFailure::Approver, _) => {
                Stop::Refused(AdminRefusal::ApproverUnauthenticated)
            }
            (VerificationFailure::Requester, _) => Stop::Refused(AdminRefusal::Unauthenticated),
        };
        base.decision_refusal(now, stop)
    }

    /// The refusal of a key-plane request that failed before any check ran
    /// (the view could not be taken, …): its `Decision(Failed(failure))`.
    /// Spec: docs/51 §7.4; A-91 (`ViewUnavailable`).
    #[must_use]
    pub fn refuse_failed_key(
        &self,
        operation_id: u64,
        request: &KeyAdminOperation,
        failure: AdminFailure,
        now: &KerberosTime,
    ) -> Refusal {
        key_base(operation_id, request).decision_refusal(now, Stop::Failed(failure))
    }

    /// Serve one key-plane step (module documentation) against `table` and
    /// ONE view of the policy version `policy` belongs to. `ticket` is the
    /// verified AP-REQ of a step that takes one
    /// ([`KeyAdminOperation::takes_ticket`]; `None` otherwise),
    /// `approvals_supplied` the number of further AP-REQs the request
    /// carried (each such step takes exactly one: more are refused).
    /// `honour` is asked whether the caller can
    /// honour the obligations of an Allow (other than the audit record
    /// planned here — `RateLimit`, `Constrain`) **before** the table
    /// changes; `false` ⇒ refused `ObligationRefused` (docs/11 §2: "the PEP
    /// must honour obligations"; Q-388 item 2).
    ///
    /// `operation_digest` is the digest dird computed from the request it
    /// decoded (crate ipc-dird-admin `operation_digest`): the step reports
    /// `channel_bound` to the PDP only if keyd verified `ticket` bound to it
    /// (R2) — an approver's AP-REQ authorizes exactly this `Approve`.
    ///
    /// `Err` carries the `Decision` event of the refusal and the
    /// client-visible status.
    ///
    /// Spec: docs/51 §5.6, §6, §7.3, §7.4; docs/11 §2, §8; docs/52 §5 item 4;
    /// A-89; P-22.
    #[allow(clippy::too_many_arguments)]
    pub fn key_step(
        &self,
        table: &mut KeyRequests,
        operation_id: u64,
        request: &KeyAdminOperation,
        operation_digest: &OperationDigest,
        ticket: Option<&VerifiedTicket>,
        approvals_supplied: usize,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        now: &KerberosTime,
        honour: &mut dyn FnMut(&[Obligation]) -> bool,
    ) -> Result<KeyStep, Refusal> {
        let mut base = key_base(operation_id, request);
        let inputs = StepInputs {
            ticket,
            digest: operation_digest,
            approvals_supplied,
            view,
            policy,
            now,
        };
        match self.key_checked(table, request, &inputs, honour, &mut base) {
            Ok((reply, decision)) => Ok(KeyStep {
                reply,
                events: vec![base.proceed(now)],
                decision,
                base,
                now: *now,
            }),
            Err(stop) => Err(base.decision_refusal(now, stop)),
        }
    }

    /// The checks of one step; `Ok` carries the reply and, for an `Approve`
    /// that completed the quorum, the decision to register (A-102).
    fn key_checked(
        &self,
        table: &mut KeyRequests,
        request: &KeyAdminOperation,
        inputs: &StepInputs<'_, '_, '_, '_>,
        honour: &mut dyn FnMut(&[Obligation]) -> bool,
        base: &mut EventBase,
    ) -> Result<(KeyReply, Option<KeyDecision>), Stop> {
        let StepInputs {
            ticket,
            digest,
            approvals_supplied,
            view,
            policy,
            now,
        } = *inputs;
        // The view must be of this PEP's domain (fail closed on a
        // misassembled caller), as `prepare` checks.
        if view.context().realm() != self.config.realm()
            || view.context().naming_context() != self.config.naming_context()
        {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        }
        // R2 (docs/52 §5 item 4): bound only if keyd verified the step's
        // one ticket bound to this very step.
        let cx = Cx::new(
            &self.config,
            &self.ids,
            view,
            policy,
            now,
            local_ipc_security(ticket.is_some_and(|t| t.bound_to(digest))),
        )?;
        table.purge(cx.instant.0);
        match request {
            KeyAdminOperation::RequestKeyOperation { operation } => {
                let ticket = ticket.ok_or(Stop::Refused(AdminRefusal::Unauthenticated))?;
                self.request_key(
                    &cx,
                    table,
                    operation,
                    ticket,
                    approvals_supplied,
                    honour,
                    base,
                )
                .map(|reply| (reply, None))
            }
            KeyAdminOperation::Approve { id, operation } => {
                let ticket = ticket.ok_or(Stop::Refused(AdminRefusal::ApproverUnauthenticated))?;
                let approval = Approval {
                    id: *id,
                    operation,
                    ticket,
                    approvals_supplied,
                };
                self.approve_key(&cx, table, &approval, honour, base)
            }
        }
    }

    /// The `PolicyAdmin` decision on the `keys` scope for `subject`.
    /// Spec: docs/51 §5.2 row 11, §5.6 (the same Action and Resource for
    /// the requester and every approver); docs/questions/Q-420.
    fn key_decision(cx: &Cx<'_, '_, '_>, subject: &AdminSubject) -> pdp::Decision {
        cx.decide(
            subject.subject(),
            Action::PolicyAdmin,
            Resource::Policy {
                scope: PolicyScope(String::from(KEY_POLICY_SCOPE)),
            },
        )
    }

    /// The key set `operation` names must be one the request may act on:
    /// the krbtgt account (its objectSid ends in RID 502) or a service
    /// object (the manifest's, a live computer object); a kvno to retire is
    /// never 0. Returns the key set's handle — for a service object the
    /// target's [`ServiceKeyHandle`], its purpose derived from its name
    /// ([`KeyTargets::handle_of`]; docs/52 R2b).
    /// Spec: docs/51 §4.3 steps 5, 8, 11, §6; [MS-SAMR] 2.2.1.14 (RID 502);
    /// docs/10 §5ב, §7; docs/questions/Q-420, Q-493 item 1.
    fn key_target(
        &self,
        cx: &Cx<'_, '_, '_>,
        targets: &KeyTargets,
        operation: &KeyOperation,
    ) -> Result<KeyHandle, Stop> {
        if let KeyOperation::RetireKvno { kvno: 0, .. } = operation {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        match operation.service() {
            None => {
                // The manifest's krbtgt account must be the directory's: a
                // mismatch is a misassembled DC, never the requester's fault.
                let krbtgt = cx
                    .resolve(targets.krbtgt)
                    .map_err(|_| Stop::Failed(AdminFailure::IntegrityFailure))?;
                let sid = record::sid(&krbtgt.obj, self.ids.object_sid)
                    .map_err(malformed)?
                    .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?;
                if sid.sub_authority().last() != Some(&DOMAIN_USER_RID_KRBTGT) {
                    return Err(Stop::Failed(AdminFailure::IntegrityFailure));
                }
                targets
                    .handle_of(operation)
                    .ok_or(Stop::Failed(AdminFailure::InternalFailure))
            }
            Some(service) => {
                let handle = targets
                    .handle_of(operation)
                    .ok_or(Stop::Refused(AdminRefusal::ValueInvalid))?;
                let object = cx.resolve(service)?;
                if object.class != self.ids.computer.id {
                    return Err(Stop::Refused(AdminRefusal::ValueInvalid));
                }
                Ok(handle)
            }
        }
    }

    /// `RequestKeyOperation` (module documentation, step 1).
    /// Spec: docs/51 §5.5 (R51-10), §5.6, §6; A-89 (the Subject); P-22;
    /// docs/11 §2 (obligations).
    #[allow(clippy::too_many_arguments)]
    fn request_key(
        &self,
        cx: &Cx<'_, '_, '_>,
        table: &mut KeyRequests,
        operation: &KeyOperation,
        ticket: &VerifiedTicket,
        approvals_supplied: usize,
        honour: &mut dyn FnMut(&[Obligation]) -> bool,
        base: &mut EventBase,
    ) -> Result<KeyReply, Stop> {
        let requester = subject_of(cx, ticket).map_err(|e| match e {
            SubjectError::NotUsable => Stop::Refused(AdminRefusal::Unauthenticated),
            SubjectError::Unavailable => Stop::Failed(AdminFailure::StoreFailure),
        })?;
        base.requester = sid_value(requester.sid());
        if requester.ticket_age() > self.config.ticket_age_max() {
            return Err(Stop::Refused(AdminRefusal::TicketAge));
        }
        // One step, one AP-REQ: approvals come with `Approve`.
        if approvals_supplied != 0 {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        let decision = Self::key_decision(cx, &requester);
        base.pdp = Some(pdp_reason(decision.reason));
        if decision.effect != Effect::Allow {
            return Err(Stop::Refused(AdminRefusal::PolicyDenied));
        }
        if !honour(&caller_obligations(&decision)) {
            return Err(Stop::Refused(AdminRefusal::ObligationRefused));
        }
        let handle = self.key_target(cx, &table.targets, operation)?;
        base.target = Some(account_of(&handle));
        if table.pending.len() >= MAX_PENDING_KEY_REQUESTS {
            return Err(Stop::Refused(AdminRefusal::PendingLimit));
        }
        let id = table
            .next_id
            .checked_add(1)
            .ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
        let expires = cx
            .instant
            .0
            .checked_add(table.lifetime)
            .ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
        let pending = Pending {
            operation: *operation,
            handle,
            digest: operation_digest(id, operation, handle, requester.guid(), expires),
            requester: Party {
                guid: requester.guid(),
                sid: *requester.sid(),
            },
            approvals: Vec::new(),
            expires,
        };
        table.next_id = id;
        base.key_request = Some(id);
        let view = view_of(id, &pending, self.config.quorum());
        table.pending.insert(id, pending);
        Ok(KeyReply::Request(view))
    }

    /// `Approve` (module documentation, steps 2-3): the approval is
    /// recorded; when it completes the quorum, the decision to register in
    /// keyd is returned with the reply.
    /// Spec: docs/51 §5.6 (distinct, `decide` = Allow for the same Action
    /// and Resource), §6; docs/24 §6 (the exact operation); P-22;
    /// docs/questions/Q-357 items 3-4; docs/52 §4.3 (A-102).
    fn approve_key(
        &self,
        cx: &Cx<'_, '_, '_>,
        table: &mut KeyRequests,
        approval: &Approval<'_>,
        honour: &mut dyn FnMut(&[Obligation]) -> bool,
        base: &mut EventBase,
    ) -> Result<(KeyReply, Option<KeyDecision>), Stop> {
        let Approval {
            id,
            operation,
            ticket,
            approvals_supplied,
        } = *approval;
        let approver = subject_of(cx, ticket).map_err(|e| match e {
            SubjectError::NotUsable => Stop::Refused(AdminRefusal::ApproverUnauthenticated),
            SubjectError::Unavailable => Stop::Failed(AdminFailure::StoreFailure),
        })?;
        let approver_sid = sid_value(approver.sid());
        if let Some(sid) = &approver_sid {
            base.approvers.push(sid.clone());
        }
        if approver.ticket_age() > self.config.ticket_age_max() {
            return Err(Stop::Refused(AdminRefusal::ApproverUnauthenticated));
        }
        if approvals_supplied != 0 {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        // The PDP before anything about the pending requests is looked at:
        // an account not allowed `PolicyAdmin` learns nothing of them (no
        // existence oracle, the rule of A-55).
        let decision = Self::key_decision(cx, &approver);
        base.pdp = Some(pdp_reason(decision.reason));
        if decision.effect != Effect::Allow {
            return Err(Stop::Refused(AdminRefusal::ApproverDenied));
        }
        // The key set the presented operation acts on; a service object
        // that is no target matches no pending request (below).
        let handle = table.targets.handle_of(operation);
        let quorum = self.config.quorum();
        let pending = table
            .pending
            .get_mut(&id)
            .ok_or(Stop::Refused(AdminRefusal::PendingUnknown))?;
        describe(base, pending);
        if let Some(sid) = approver_sid {
            base.approvers.push(sid);
        }
        // The approval is bound to the request's operation digest: the
        // operation the approver names, under this request's id, requester
        // and expiry, must give the same digest.
        let presented = handle.map(|key| {
            operation_digest(id, operation, key, pending.requester.guid, pending.expires)
        });
        if presented != Some(pending.digest) {
            return Err(Stop::Refused(AdminRefusal::OperationMismatch));
        }
        if approver.guid() == pending.requester.guid
            || *approver.sid() == pending.requester.sid
            || pending
                .approvals
                .iter()
                .any(|p| p.guid == approver.guid() || p.sid == *approver.sid())
        {
            return Err(Stop::Refused(AdminRefusal::ApproverNotDistinct));
        }
        if pending.approvals.len() + 1 >= quorum {
            return Err(Stop::Refused(AdminRefusal::Conflict));
        }
        if !honour(&caller_obligations(&decision)) {
            return Err(Stop::Refused(AdminRefusal::ObligationRefused));
        }
        pending.approvals.push(Party {
            guid: approver.guid(),
            sid: *approver.sid(),
        });
        let completed = (pending.approvals.len() + 1 >= quorum)
            .then(|| key_decision(id, pending, cx.instant.0));
        Ok((KeyReply::Request(view_of(id, pending, quorum)), completed))
    }

    /// The principal id of the key sets a committed `Delete` leaves to
    /// destroy: `target`'s tombstone, when its classes include `user` (users
    /// and computers — the objects with key sets, docs/47 §9.1). dird
    /// registers a `DestroyKeySet` decision for it after the commit (A-102,
    /// docs/52 §4.3 row "destroy_key_set" option (a)). `None` for any other
    /// object or when there is no tombstone.
    ///
    /// # Errors
    /// [`AdminFailure::StoreFailure`]-class failure of the snapshot read.
    ///
    /// Spec: docs/51 §6, §9 ("the tombstones of the user / computer classes
    /// (a tombstone keeps GUID + classes, A-18)"); docs/52 §4.3; dirstore
    /// `Snapshot::get_tombstone`.
    pub fn destruction_target(
        &self,
        view: &DirectoryView<'_>,
        target: Guid,
    ) -> Result<Option<TombstonedPrincipal>, AdminFailure> {
        let tombstone = checks::tombstone(view, target).map_err(|_| AdminFailure::StoreFailure)?;
        Ok(tombstone
            .filter(|t| t.classes.contains(&self.ids.user.id))
            .map(|t| TombstonedPrincipal { guid: t.guid }))
    }

    /// One page of the tombstoned users and computers (classes include
    /// `user`), strictly after `after`, ascending by GUID — at most `limit`
    /// tombstones of any class examined per page, as dirstore bounds its own
    /// listing — for dird's re-registration of destroy decisions keyd lost
    /// (A-105, docs/questions/Q-470 item 4).
    ///
    /// # Errors
    /// [`AdminFailure::StoreFailure`]-class failure of the snapshot read.
    ///
    /// Spec: docs/51 §6, §9; docs/52 §4.3 ("`RegisterPendingDestructions` —
    /// dird registers for every tombstone of a user/computer, page by
    /// page"); dirstore `Snapshot::tombstones`; A-18.
    pub fn destruction_targets(
        &self,
        view: &DirectoryView<'_>,
        after: Option<Guid>,
        limit: usize,
    ) -> Result<DestructionTargets, AdminFailure> {
        let page =
            checks::tombstones(view, after, limit).map_err(|_| AdminFailure::StoreFailure)?;
        Ok(DestructionTargets {
            targets: page
                .tombstones
                .into_iter()
                .filter(|t| t.classes.contains(&self.ids.user.id))
                .map(|t| TombstonedPrincipal { guid: t.guid })
                .collect(),
            next: page.next,
        })
    }
}

/// The decision of the request `id`, whose approvals just reached the
/// quorum (module documentation, step 3): the decided operation on the
/// request's key set, the requester then the approvers, and the request's
/// remaining lifetime at `now` (1 to keyd's ceiling).
/// Spec: docs/52 §4.2, §4.3; docs/51 §5.6; docs/questions/Q-460.
fn key_decision(id: u64, pending: &Pending, now: u64) -> KeyDecision {
    let handle = pending.handle;
    let operation = match pending.operation {
        KeyOperation::RotateKrbtgt => DecidedOperation::RotateKrbtgt { krbtgt: handle },
        KeyOperation::RotateKey { .. } => DecidedOperation::RotateKey { handle },
        KeyOperation::RetireKvno { kvno, .. } => DecidedOperation::RetireKvno {
            handle,
            kvno: Kvno::new(kvno),
        },
    };
    let approvers = core::iter::once(&pending.requester)
        .chain(pending.approvals.iter())
        .map(|party| PrincipalId::from_bytes(party.guid.to_packet()))
        .collect();
    let remaining = pending.expires.saturating_sub(now);
    let lifetime_secs =
        u32::try_from(remaining.clamp(1, u64::from(MAX_KEY_DECISION_SECS))).unwrap_or(1);
    KeyDecision {
        id: DecisionId::new(id),
        operation,
        approvers,
        lifetime_secs,
    }
}

/// DOMAIN_USER_RID_KRBTGT. Spec: [MS-SAMR] 2.2.1.14 (0x000001F6).
const DOMAIN_USER_RID_KRBTGT: u32 = 0x0000_01F6;
