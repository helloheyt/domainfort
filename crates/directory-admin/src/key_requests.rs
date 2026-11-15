//! Dual-controlled key operations (docs/51 §5.6, §6; R51-11, R51-14; task
//! A10; A-102): what a key operation is, which key set it may act on, the
//! **decision** dird registers in keyd when a key operation's pending
//! request reaches its quorum ([`KeyDecision`]; docs/52 R1, §4.3), and the
//! tombstones a committed `Delete` leaves to destroy.
//!
//! # One mechanism (task D2-c; docs/questions/Q-882, A-148)
//!
//! A key operation is proposed, approved, rejected, withdrawn, listed and
//! shown like every other dual-controlled operation — through the pending
//! requests of crate::requests. The key-only `RequestKeyOperation` /
//! `Approve {id, operation}` steps and their own table (task A10) are
//! retired: two mechanisms for one control could diverge (docs/52 C14).
//! What stays here is what is specific to key operations:
//!
//! 1. the requester and every approver must be allowed `PolicyAdmin` on the
//!    policy scope `keys` ([`KEY_POLICY_SCOPE`]; docs/51 §5.2 row 11 —
//!    docs/questions/Q-420);
//! 2. the key set an operation acts on ([`KeyTargets::handle_of`]): the
//!    krbtgt account's, or a service object's [`ServiceKeyHandle`] — an
//!    operation names an object, never a purpose (docs/52 R2b);
//! 3. **(A-102)** the `Approve` that completes the quorum yields a
//!    [`KeyDecision`]: the decision id (the request's id), the decided
//!    operation with its key set, the requester's and the approvers'
//!    objectGUIDs, and the request's remaining lifetime. dird has the
//!    step's `Decision` event acknowledged by auditd, registers the decision
//!    in keyd (Role::Ldap, `register_decision`), and records an `Outcome`
//!    event of the registration (`QuorumStep::registration_event`); if any
//!    of it fails the approval is reverted (crate::requests
//!    `PendingRequests::revert_approval`) so the approver may approve again
//!    — except when the registration's outcome is unknown (keyd may hold
//!    the decision): then dird first revokes it in keyd and drops the
//!    request, or, keyd not reached, keeps it approved (task F3,
//!    docs/questions/Q-977: a decision keyd may hold is never left without
//!    an approved request in dird);
//! 4. keyadm runs `rotate_krbtgt(id)` / `rotate_key(id)` / `retire_kvno(id)`
//!    in keyd as Role::Admin: keyd runs the parameters **dird registered**
//!    and builds the dual-control token itself from the registered
//!    approvers (docs/52 §4.6, §4.8; docs/questions/Q-460);
//! 5. **(task F3)** a `Withdraw` / `Reject` of an approved key request takes
//!    effect only once keyd revoked its decision (`revoke_decision`,
//!    Role::Ldap — crate::requests `RevocationStep`; docs/questions/Q-937
//!    item 6, Q-977).
//!
//! The change-password service's key set (`kadmin/changepw`,
//! `ChangePasswordService`) is a target like the other service key sets
//! when dird's caller includes it in [`KeyTargets`] (owner decision A-126
//! on docs/questions/Q-660 item 11: rotatable through a decision; Q-978).
//!
//! Spec: docs/51 §5.2 row 11, §5.6, §6, §7.3, §9; docs/24 §6; docs/10 §7;
//! docs/33 §5; A-73; A-85; A-89; P-22; docs/questions/Q-420..Q-422,
//! Q-460, Q-882; docs/52 §4.2, §4.3 (A-102).

use dtyp::Guid;
use ipc_audit::{AdminFailure, AdminRefusal, KeydOperation};
use keyd_types::{
    DecidedOperation, DecisionId, KeyHandle, KeyPurpose, Kvno, PrincipalId, ServiceKeyHandle,
    MAX_KEY_DECISION_SECS,
};
use pdp::{Action, PolicyScope, Resource};
use std::collections::BTreeSet;

use crate::admin::DirectoryAdmin;
use crate::audit::Stop;
use crate::checks::{self, malformed, Cx, KeyTargetRecord};
use crate::random::RandomSource;
use crate::record;

/// The policy scope of the key operations: `PolicyAdmin` on `Policy {scope:
/// "keys"}`. The policy language already matches every scope (`scope:
/// None`, the rule `provision domain` writes for the Tier-0 group) or this
/// one exactly, so no language change is needed.
/// Spec: docs/51 §5.2 row 11 (`PolicyAdmin(scope "keys")`); docs/06 §9;
/// crates/pdp policy.rs (`ResourceMatch::Policy`); docs/questions/Q-420.
pub const KEY_POLICY_SCOPE: &str = "keys";

/// Which key set a `retire_kvno` names. Spec: docs/51 §6; docs/10 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRef {
    /// The krbtgt key set (the provisioning manifest's).
    Krbtgt,
    /// The key set of a service object (its purpose: the target's
    /// [`ServiceKeyHandle`], [`KeyTargets::handle_of`]).
    Service(Guid),
}

/// A dual-controlled key operation. Spec: docs/51 §6 (the `rotate-key`,
/// `rotate-krbtgt`, `retire-kvno` rows: "approved request (dual)"); docs/10
/// §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyOperation {
    /// `rotate_krbtgt(DualControlToken)`.
    RotateKrbtgt,
    /// `rotate_key` of a service object's randomized key set (created by
    /// `create_key` in the ceremony — docs/10 §5b; not a computer's
    /// password-derived one) — `Service`, `AdminService` or (task F3,
    /// A-126) `ChangePasswordService`, as the service's name derives it
    /// ([`KeyTargets::handle_of`]).
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
}

/// The key sets a request may name: the krbtgt account's objectGUID and the
/// service objects' key sets (the provisioning manifest's — the only
/// randomized service key sets of phase 1, docs/51 §4.3 step 11).
///
/// A service object's key set is a [`ServiceKeyHandle`], which only the
/// derivation from the service's name builds (`Service` for `ldap/<fqdn>`,
/// `AdminService` for `admind/<fqdn>`, `ChangePasswordService` for
/// `kadmin/changepw` — task F3, A-126): the table cannot hold — and a key
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

/// The decision an `Approve` completing a key request's quorum yields: what
/// dird registers in keyd (`register_decision`, Role::Ldap) so that keyadm
/// can run it there by its id (A-102, docs/52 §4.2, §4.3).
/// Spec: docs/52 §4.2 (`register_decision(id, op, approvers, lifetime)`),
/// §4.3 (the key-operation rows); docs/51 §5.6 (`DualControlToken
/// { approver_1: the requester, approver_2: the approver }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDecision {
    /// The decision id: the request's id (64 bits from dird's CSPRNG,
    /// docs/questions/Q-882 item 3) — the id the operator gives keyadm.
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

impl KeyDecision {
    /// The decision of the request `id` for `operation` on `handle`, decided
    /// by `parties` (the requester then the approvers), whose request
    /// expires at `expires` (seconds since 1970) — its remaining lifetime at
    /// `now`, 1 to keyd's ceiling.
    /// Spec: docs/52 §4.2, §4.3; docs/51 §5.6; docs/questions/Q-460.
    pub(crate) fn of_request(
        id: u64,
        operation: &KeyOperation,
        handle: KeyHandle,
        parties: impl Iterator<Item = Guid>,
        expires: u64,
        now: u64,
    ) -> KeyDecision {
        let operation = match operation {
            KeyOperation::RotateKrbtgt => DecidedOperation::RotateKrbtgt { krbtgt: handle },
            KeyOperation::RotateKey { .. } => DecidedOperation::RotateKey { handle },
            KeyOperation::RetireKvno { kvno, .. } => DecidedOperation::RetireKvno {
                handle,
                kvno: Kvno::new(*kvno),
            },
        };
        let approvers = parties
            .map(|guid| PrincipalId::from_bytes(guid.to_packet()))
            .collect();
        let remaining = expires.saturating_sub(now);
        let lifetime_secs =
            u32::try_from(remaining.clamp(1, u64::from(MAX_KEY_DECISION_SECS))).unwrap_or(1);
        KeyDecision {
            id: DecisionId::new(id),
            operation,
            approvers,
            lifetime_secs,
        }
    }
}

/// How the registration of a [`KeyDecision`] in keyd ended (its `Outcome`
/// event, `QuorumStep::registration_event`).
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

/// The Action and Resource of every key operation: `PolicyAdmin` on the
/// policy scope `keys` — the requester's and every approver's (docs/51
/// §5.6: "the same Action and Resource").
/// Spec: docs/51 §5.2 row 11, §5.6; docs/questions/Q-420.
pub(crate) fn key_request() -> (Action, Resource) {
    (
        Action::PolicyAdmin,
        Resource::Policy {
            scope: PolicyScope(String::from(KEY_POLICY_SCOPE)),
        },
    )
}

impl<R: RandomSource> DirectoryAdmin<R> {
    /// The key set `operation` names must be one the request may act on:
    /// the krbtgt account (its objectSid ends in RID 502) or a service
    /// object (the manifest's, a live computer object); a kvno to retire is
    /// never 0. Returns the key set's handle — for a service object the
    /// target's [`ServiceKeyHandle`], its purpose derived from its name
    /// ([`KeyTargets::handle_of`]; docs/52 R2b) — and the target's record.
    /// Spec: docs/51 §4.3 steps 5, 8, 11, §6; [MS-SAMR] 2.2.1.14 (RID 502);
    /// docs/10 §5b, §7; docs/questions/Q-420, Q-493 item 1.
    pub(crate) fn key_target(
        &self,
        cx: &Cx<'_, '_, '_>,
        targets: &KeyTargets,
        operation: &KeyOperation,
    ) -> Result<(KeyHandle, KeyTargetRecord), Stop> {
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
                let handle = targets
                    .handle_of(operation)
                    .ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
                Ok((handle, krbtgt))
            }
            Some(service) => {
                let handle = targets
                    .handle_of(operation)
                    .ok_or(Stop::Refused(AdminRefusal::ValueInvalid))?;
                let object = cx.resolve(service)?;
                if object.class != self.ids.computer.id {
                    return Err(Stop::Refused(AdminRefusal::ValueInvalid));
                }
                Ok((handle, object))
            }
        }
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
        view: &directory_pip::DirectoryView<'_>,
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
        view: &directory_pip::DirectoryView<'_>,
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

/// DOMAIN_USER_RID_KRBTGT. Spec: [MS-SAMR] 2.2.1.14 (0x000001F6).
const DOMAIN_USER_RID_KRBTGT: u32 = 0x0000_01F6;
