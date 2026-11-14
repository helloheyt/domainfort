//! Dual-controlled key operations (docs/51 §5.6, §6; R51-11, R51-14; task
//! A10): the pending requests dird holds **in memory**, and the steps that
//! act on them — `RequestKeyOperation`, `Approve`, `FetchApproved`,
//! `Complete` — plus `ListPendingDestruction` for keyadm's `destroy-sweep`.
//!
//! # The flow (docs/51 §6, as decided)
//!
//! 1. A requester opens a request for one key operation —
//!    `rotate_krbtgt`, `rotate_key` of a service object's randomized
//!    `Service` key set, or `retire_kvno` — with a fresh AP-REQ that dird
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
//! 3. keyadm fetches the approved request (`FetchApproved`, through admind,
//!    which forwards it only from `keyadm_uid`): it gets the operation, the
//!    key set's handle and the requester's and approvers' objectGUIDs — what
//!    keyd's `DualControlToken` names. A request is fetched **once**: one
//!    approval, one execution.
//! 4. keyadm calls keyd as Role::Admin, then reports `Complete {id,
//!    outcome}`; dird records it and drops the request.
//!
//! keyd still trusts keyadm for the token's truthfulness (the residual of
//! crates/keyd-types model.rs), but the token now comes from approvals dird
//! verified cryptographically (docs/51 §6).
//!
//! # The pending table
//!
//! A request = {id, the operation, the key set it acts on, the operation
//! digest, the requester, the approvals, the expiry, fetched?}. In dird's
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
//! `requester` / `approvers` (objectSids). `Complete` has, after its
//! `Decision`, an `Outcome` event saying what keyd did as keyadm reports it
//! (`Committed` with the reported kvno, or the appended codes
//! `KeyOperationRefused` / `KeyOperationNotPerformed` /
//! `KeyOperationOutcomeUnknown` — docs/questions/Q-421).
//!
//! Spec: docs/51 §5.2 row 11, §5.6, §6, §7.3, §9; docs/24 §6; docs/10 §7;
//! docs/33 §5; A-73; A-85; A-89; P-22; FIPS 180-4 (SHA-256, as provided by
//! the approved `sha2`); docs/questions/Q-420..Q-422.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use directory_pip::{AccountKind, DirectoryView};
use dtyp::{Guid, Sid};
use ipc_audit::{
    AdminFailure, AdminRefusal, DirAdminEvent, DirAdminOperation, DirAdminStage, KeydOperation,
    OutcomeResult,
};
use keyd_types::{KeyHandle, KeyPurpose, PrincipalId};
use krb_proto::KerberosTime;
use pdp::{Action, Effect, Obligation, PolicyScope, PolicySnapshot, Resource};
use sha2::{Digest, Sha256};

use crate::admin::{subject_of, DirectoryAdmin, VerificationFailure};
use crate::audit::{pdp_reason, sid_value, EventBase, Refusal, Stop};
use crate::checks::{malformed, store_failure, Cx};
use crate::config::ConfigError;
use crate::random::RandomSource;
use crate::record;
use crate::subject::{AdminSubject, SubjectError, VerifiedTicket};
use crate::time;

/// The policy scope of the key operations: `PolicyAdmin` on `Policy {scope:
/// "keys"}`. The policy language already matches every scope (`scope:
/// None`, the rule `provision domain` writes for the Tier-0 group) or this
/// one exactly, so no language change is needed.
/// Spec: docs/51 §5.2 row 11 (`PolicyAdmin(scope "keys")`); docs/06 §9;
/// crates/pdp policy.rs (`ResourceMatch::Policy`); docs/questions/Q-420.
pub const KEY_POLICY_SCOPE: &str = "keys";

/// Most pending key-operation requests dird holds at once (fetched ones
/// awaiting their `Complete` included). Project choice: key operations are
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

/// Most entries of one `ListPendingDestruction` page: the admin channel's
/// bound (crates/ipc-dird-admin `MAX_DESTRUCTION_ENTRIES`, pinned in dird).
/// Spec: docs/51 §6, §7.5.
pub const MAX_DESTRUCTION_PAGE: usize = 256;

/// The digest's domain-separation label: no other digest of this project
/// starts with it. Project choice.
const DIGEST_LABEL: &[u8] = b"dird key-operation request, layout 1";

/// Which key set a `retire_kvno` names. Spec: docs/51 §6; docs/10 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRef {
    /// The krbtgt key set (the provisioning manifest's).
    Krbtgt,
    /// The `Service` key set of a service object.
    Service(Guid),
}

/// The key operation of a pending request. Spec: docs/51 §6 (the
/// `rotate-key`, `rotate-krbtgt`, `retire-kvno` rows: "approved request
/// (dual)"); docs/10 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyOperation {
    /// `rotate_krbtgt(DualControlToken)`.
    RotateKrbtgt,
    /// `rotate_key` of a service object's randomized `Service` key set
    /// (created by `create_key` in the ceremony — docs/10 §5ב; not a
    /// computer's password-derived one).
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

    /// The purpose of the key set it acts on. Spec: docs/10 §1, §7.
    #[must_use]
    pub fn purpose(&self) -> KeyPurpose {
        match self {
            KeyOperation::RotateKrbtgt
            | KeyOperation::RetireKvno {
                key: KeyRef::Krbtgt,
                ..
            } => KeyPurpose::Krbtgt,
            KeyOperation::RotateKey { .. }
            | KeyOperation::RetireKvno {
                key: KeyRef::Service(_),
                ..
            } => KeyPurpose::Service,
        }
    }

    /// The service object it names, if any.
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

/// How keyadm's call to keyd ended, as `Complete` reports it.
/// Spec: docs/51 §6 (`Complete {id, outcome, kvno}`); docs/10 §9; A-88,
/// A-90.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyOperationOutcome {
    /// keyd performed it; the new kvno of a rotation.
    Performed {
        /// The kvno keyd answered (a rotation), `None` for `retire_kvno`.
        kvno: Option<u32>,
    },
    /// keyd answered with a refusal.
    Refused,
    /// Not performed (never sent, or refused by keyd's transport).
    NotPerformed,
    /// Sent; no usable answer came back.
    OutcomeUnknown,
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
    /// `FetchApproved {id}` (keyadm; no AP-REQ).
    FetchApproved {
        /// The request.
        id: u64,
    },
    /// `Complete {id, outcome}` (keyadm; no AP-REQ).
    Complete {
        /// The request.
        id: u64,
        /// How keyd's call ended.
        outcome: KeyOperationOutcome,
    },
    /// `ListPendingDestruction {cursor}` (keyadm; no AP-REQ).
    ListPendingDestruction {
        /// Resume strictly after this objectGUID.
        cursor: Option<Guid>,
    },
}

impl KeyAdminOperation {
    /// The audit code. Spec: crate ipc-audit `DirAdminOperation`.
    #[must_use]
    pub fn code(&self) -> DirAdminOperation {
        match self {
            KeyAdminOperation::RequestKeyOperation { .. } => DirAdminOperation::RequestKeyOperation,
            KeyAdminOperation::Approve { .. } => DirAdminOperation::Approve,
            KeyAdminOperation::FetchApproved { .. } => DirAdminOperation::FetchApproved,
            KeyAdminOperation::Complete { .. } => DirAdminOperation::Complete,
            KeyAdminOperation::ListPendingDestruction { .. } => {
                DirAdminOperation::ListPendingDestruction
            }
        }
    }

    /// Whether the request carries an administrator's AP-REQ (the
    /// requester's or the approver's); keyadm's requests carry none.
    /// Spec: docs/51 §6; docs/questions/Q-422.
    #[must_use]
    pub fn takes_ticket(&self) -> bool {
        matches!(
            self,
            KeyAdminOperation::RequestKeyOperation { .. } | KeyAdminOperation::Approve { .. }
        )
    }

    /// The `DirAdmin` events it records: two for `Complete` (its decision
    /// and keyd's outcome as reported), one for every other step.
    /// Spec: module documentation; Q-340 item 1.
    #[must_use]
    pub fn audit_events(&self) -> usize {
        match self {
            KeyAdminOperation::Complete { .. } => 2,
            _ => 1,
        }
    }
}

/// The key sets a request may name: the krbtgt account's objectGUID and the
/// service objects' (the provisioning manifest's — the only randomized
/// `Service` key sets of phase 1, docs/51 §4.3 step 11).
/// Spec: docs/51 §4.3 steps 8, 11, §6; docs/questions/Q-386 item 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTargets {
    /// The krbtgt account's objectGUID.
    pub krbtgt: Guid,
    /// The service objects' objectGUIDs.
    pub services: BTreeSet<Guid>,
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
    principal: Guid,
    digest: [u8; DIGEST_LEN],
    requester: Party,
    approvals: Vec<Party>,
    expires: u64,
    fetched: bool,
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

    /// The principal id of the key set `operation` acts on.
    fn principal_of(&self, operation: &KeyOperation) -> Guid {
        operation.service().unwrap_or(self.targets.krbtgt)
    }
}

/// The operation digest of a request (module documentation): SHA-256 over
/// `label ‖ id:u64 ‖ code:u8 ‖ principal:[16] ‖ purpose:u8 ‖ kvno:u32 ‖
/// requester:[16] ‖ expires:u64` (integers big-endian; the kvno 0 when the
/// operation names none). Public so that a client can show or check it.
/// Spec: docs/51 §5.6 ("the operation digest"); docs/24 §6 (principle);
/// FIPS 180-4 via the approved `sha2` (`Digest::digest`, docs.rs sha2
/// 0.11.1 as crates/audit-log cites it); docs/questions/Q-420.
#[must_use]
pub fn operation_digest(
    id: u64,
    operation: &KeyOperation,
    principal: Guid,
    requester: Guid,
    expires: u64,
) -> [u8; DIGEST_LEN] {
    let kvno = match operation {
        KeyOperation::RetireKvno { kvno, .. } => *kvno,
        KeyOperation::RotateKrbtgt | KeyOperation::RotateKey { .. } => 0,
    };
    let purpose: u8 = match operation.purpose() {
        KeyPurpose::PrincipalLongterm => 0,
        KeyPurpose::Krbtgt => 1,
        KeyPurpose::Service => 2,
    };
    let mut octets = Vec::with_capacity(DIGEST_LABEL.len() + 8 + 1 + 16 + 1 + 4 + 16 + 8);
    octets.extend_from_slice(DIGEST_LABEL);
    octets.extend_from_slice(&id.to_be_bytes());
    octets.push(operation.code());
    octets.extend_from_slice(&principal.to_packet());
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

/// The answer to `FetchApproved`: what keyadm needs to call keyd.
/// Spec: docs/51 §6 ("dird returns {operation, GUIDs of the requester and
/// approver}"); crates/keyd-types model.rs (`DualControlToken`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedKeyOperation {
    /// The id.
    pub id: u64,
    /// The operation digest.
    pub digest: [u8; DIGEST_LEN],
    /// The operation.
    pub operation: KeyOperation,
    /// The key set it acts on.
    pub handle: KeyHandle,
    /// The requester's objectGUID.
    pub requester: Guid,
    /// The approvers' objectGUIDs, in approval order.
    pub approvers: Vec<Guid>,
}

/// One tombstone of a user or computer object.
/// Spec: docs/51 §6, §9; A-18.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestructionEntry {
    /// The objectGUID (= the principal id of its key sets).
    pub guid: Guid,
    /// User or computer.
    pub kind: AccountKind,
}

/// One page of `ListPendingDestruction`.
/// Spec: docs/51 §6, §9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestructionPage {
    /// The tombstones of this page (ascending by GUID packet).
    pub entries: Vec<DestructionEntry>,
    /// Where the next page starts; `None` when complete.
    pub next: Option<Guid>,
}

/// The reply of a key-plane step.
/// Spec: docs/51 §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyReply {
    /// `RequestKeyOperation` / `Approve`.
    Request(KeyRequestView),
    /// `FetchApproved`.
    Approved(ApprovedKeyOperation),
    /// `Complete`.
    Done,
    /// `ListPendingDestruction`.
    Page(DestructionPage),
}

/// A key-plane step that succeeded: its reply and its events (the
/// `Decision`, and for `Complete` the `Outcome` after it).
/// Spec: module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStep {
    reply: KeyReply,
    events: Vec<DirAdminEvent>,
}

impl KeyStep {
    /// The reply.
    #[must_use]
    pub fn reply(&self) -> &KeyReply {
        &self.reply
    }

    /// The events to commit, in order, before the reply.
    #[must_use]
    pub fn events(&self) -> &[DirAdminEvent] {
        &self.events
    }
}

/// The per-request inputs of a step.
#[derive(Clone, Copy)]
struct StepInputs<'t, 'v, 'a, 'p> {
    ticket: Option<&'t VerifiedTicket>,
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
        KeyAdminOperation::FetchApproved { id } | KeyAdminOperation::Complete { id, .. } => {
            base.key_request = Some(*id);
        }
        KeyAdminOperation::ListPendingDestruction { .. } => {}
    }
    base
}

/// Record a pending request's parties and target in `base`.
fn describe(base: &mut EventBase, pending: &Pending) {
    base.key_operation = Some(pending.operation.keyd_operation());
    base.target = Some(pending.principal);
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
    /// `Err` carries the `Decision` event of the refusal and the
    /// client-visible status.
    ///
    /// Spec: docs/51 §5.6, §6, §7.3, §7.4; docs/11 §2, §8; A-89; P-22.
    #[allow(clippy::too_many_arguments)]
    pub fn key_step(
        &self,
        table: &mut KeyRequests,
        operation_id: u64,
        request: &KeyAdminOperation,
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
            approvals_supplied,
            view,
            policy,
            now,
        };
        match self.key_checked(table, request, &inputs, honour, &mut base) {
            Ok((reply, outcome)) => {
                let mut events = vec![base.proceed(now)];
                if let Some(stage) = outcome {
                    events.push(base.staged(now, stage));
                }
                Ok(KeyStep { reply, events })
            }
            Err(stop) => Err(base.decision_refusal(now, stop)),
        }
    }

    /// The checks of one step; `Ok` carries the reply and, for `Complete`,
    /// the stage of its `Outcome` event.
    fn key_checked(
        &self,
        table: &mut KeyRequests,
        request: &KeyAdminOperation,
        inputs: &StepInputs<'_, '_, '_, '_>,
        honour: &mut dyn FnMut(&[Obligation]) -> bool,
        base: &mut EventBase,
    ) -> Result<(KeyReply, Option<DirAdminStage>), Stop> {
        let StepInputs {
            ticket,
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
        let instant = time::instant(now).ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
        let cx = Cx {
            config: &self.config,
            ids: &self.ids,
            view,
            policy,
            now: *now,
            instant,
        };
        table.purge(instant.0);
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
                    .map(|reply| (reply, None))
            }
            KeyAdminOperation::FetchApproved { id } => self
                .fetch_key(table, *id, instant.0, base)
                .map(|r| (r, None)),
            KeyAdminOperation::Complete { id, outcome } => self
                .complete_key(table, *id, *outcome, base)
                .map(|stage| (KeyReply::Done, Some(stage))),
            KeyAdminOperation::ListPendingDestruction { cursor } => {
                self.list_destruction(&cx, *cursor).map(|r| (r, None))
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
    /// never 0. Returns the key set's principal id.
    /// Spec: docs/51 §4.3 steps 5, 8, 11, §6; [MS-SAMR] 2.2.1.14 (RID 502);
    /// docs/10 §5ב, §7; docs/questions/Q-420.
    fn key_target(
        &self,
        cx: &Cx<'_, '_, '_>,
        targets: &KeyTargets,
        operation: &KeyOperation,
    ) -> Result<Guid, Stop> {
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
                Ok(targets.krbtgt)
            }
            Some(service) => {
                if !targets.services.contains(&service) {
                    return Err(Stop::Refused(AdminRefusal::ValueInvalid));
                }
                let object = cx.resolve(service)?;
                if object.class != self.ids.computer.id {
                    return Err(Stop::Refused(AdminRefusal::ValueInvalid));
                }
                Ok(service)
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
        let principal = self.key_target(cx, &table.targets, operation)?;
        base.target = Some(principal);
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
            principal,
            digest: operation_digest(id, operation, principal, requester.guid(), expires),
            requester: Party {
                guid: requester.guid(),
                sid: *requester.sid(),
            },
            approvals: Vec::new(),
            expires,
            fetched: false,
        };
        table.next_id = id;
        base.key_request = Some(id);
        let view = view_of(id, &pending, self.config.quorum());
        table.pending.insert(id, pending);
        Ok(KeyReply::Request(view))
    }

    /// `Approve` (module documentation, step 2).
    /// Spec: docs/51 §5.6 (distinct, `decide` = Allow for the same Action
    /// and Resource), §6; docs/24 §6 (the exact operation); P-22;
    /// docs/questions/Q-357 items 3-4.
    fn approve_key(
        &self,
        cx: &Cx<'_, '_, '_>,
        table: &mut KeyRequests,
        approval: &Approval<'_>,
        honour: &mut dyn FnMut(&[Obligation]) -> bool,
        base: &mut EventBase,
    ) -> Result<KeyReply, Stop> {
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
        let principal = table.principal_of(operation);
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
        let presented = operation_digest(
            id,
            operation,
            principal,
            pending.requester.guid,
            pending.expires,
        );
        if presented != pending.digest {
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
        if pending.fetched || pending.approvals.len() + 1 >= quorum {
            return Err(Stop::Refused(AdminRefusal::Conflict));
        }
        if !honour(&caller_obligations(&decision)) {
            return Err(Stop::Refused(AdminRefusal::ObligationRefused));
        }
        pending.approvals.push(Party {
            guid: approver.guid(),
            sid: *approver.sid(),
        });
        Ok(KeyReply::Request(view_of(id, pending, quorum)))
    }

    /// `FetchApproved` (module documentation, step 3): once, and only for a
    /// request whose approvals reach the quorum. A fetched request awaits
    /// its `Complete` for one more lifetime.
    /// Spec: docs/51 §6.
    fn fetch_key(
        &self,
        table: &mut KeyRequests,
        id: u64,
        now: u64,
        base: &mut EventBase,
    ) -> Result<KeyReply, Stop> {
        let lifetime = table.lifetime;
        let quorum = self.config.quorum();
        let pending = table
            .pending
            .get_mut(&id)
            .ok_or(Stop::Refused(AdminRefusal::PendingUnknown))?;
        describe(base, pending);
        if pending.approvals.len() + 1 < quorum {
            return Err(Stop::Refused(AdminRefusal::NotApproved));
        }
        if pending.fetched {
            return Err(Stop::Refused(AdminRefusal::Conflict));
        }
        pending.fetched = true;
        pending.expires = now
            .checked_add(lifetime)
            .ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
        Ok(KeyReply::Approved(ApprovedKeyOperation {
            id,
            digest: pending.digest,
            operation: pending.operation,
            handle: KeyHandle::new(
                PrincipalId::from_bytes(pending.principal.to_packet()),
                pending.operation.purpose(),
            ),
            requester: pending.requester.guid,
            approvers: pending.approvals.iter().map(|p| p.guid).collect(),
        }))
    }

    /// `Complete` (module documentation, step 4): only for a fetched
    /// request; the report must fit the operation (a rotation reports its
    /// new kvno, `retire_kvno` none). The request is dropped; the stage of
    /// the `Outcome` event says what keyd did, as keyadm reports it.
    /// Spec: docs/51 §6, §9 (the "krbtgt rotation" row: "keyd rotated, the
    /// completion was not reported" is the detection signal); A-88; A-90;
    /// docs/questions/Q-421.
    fn complete_key(
        &self,
        table: &mut KeyRequests,
        id: u64,
        outcome: KeyOperationOutcome,
        base: &mut EventBase,
    ) -> Result<DirAdminStage, Stop> {
        let pending = table
            .pending
            .get(&id)
            .ok_or(Stop::Refused(AdminRefusal::PendingUnknown))?;
        describe(base, pending);
        if !pending.fetched {
            return Err(Stop::Refused(AdminRefusal::NotApproved));
        }
        let stage = match outcome {
            KeyOperationOutcome::Performed { kvno } => {
                if kvno.is_some() != pending.operation.answers_kvno() {
                    return Err(Stop::Refused(AdminRefusal::ValueInvalid));
                }
                base.reported_kvnos = kvno.into_iter().collect();
                DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
            }
            KeyOperationOutcome::Refused => {
                DirAdminStage::Outcome(OutcomeResult::Refused(AdminRefusal::KeyOperationRefused))
            }
            KeyOperationOutcome::NotPerformed => DirAdminStage::Outcome(OutcomeResult::Failed(
                AdminFailure::KeyOperationNotPerformed,
            )),
            KeyOperationOutcome::OutcomeUnknown => DirAdminStage::Outcome(OutcomeResult::Failed(
                AdminFailure::KeyOperationOutcomeUnknown,
            )),
        };
        table.pending.remove(&id);
        Ok(stage)
    }

    /// `ListPendingDestruction`: one page of the tombstones whose classes
    /// include `user` (users and computers — the objects with key sets,
    /// docs/47 §9.1), ascending by GUID packet.
    /// Spec: docs/51 §6 ("the tombstones of the user / computer classes
    /// (a tombstone keeps GUID + classes, A-18)"), §9; dirstore
    /// `Snapshot::tombstones`.
    fn list_destruction(
        &self,
        cx: &Cx<'_, '_, '_>,
        cursor: Option<Guid>,
    ) -> Result<KeyReply, Stop> {
        let page = cx
            .view
            .snapshot()
            .tombstones(cursor, MAX_DESTRUCTION_PAGE)
            .map_err(|e| store_failure(&e))?;
        let entries = page
            .tombstones
            .iter()
            .filter(|t| t.classes.contains(&self.ids.user.id))
            .map(|t| DestructionEntry {
                guid: t.guid,
                kind: if t.classes.contains(&self.ids.computer.id) {
                    AccountKind::Computer
                } else {
                    AccountKind::User
                },
            })
            .collect();
        Ok(KeyReply::Page(DestructionPage {
            entries,
            next: page.next,
        }))
    }
}

/// DOMAIN_USER_RID_KRBTGT. Spec: [MS-SAMR] 2.2.1.14 (0x000001F6).
const DOMAIN_USER_RID_KRBTGT: u32 = 0x0000_01F6;
