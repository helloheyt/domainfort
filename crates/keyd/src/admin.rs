//! Admin operations: the key lifecycle (create, rotate, rotate krbtgt under
//! dual control, retire an old kvno, destroy a deleted account's key set).
//! Role `Admin` (tier-0) only.
//!
//! None of these returns key material — only the resulting kvno. "There is
//! no read-key operation — in any role."
//!
//! **A-102 (docs/52 R1, R3):** `create_key` exists only in the provisioning
//! ceremony (before `seal_ceremony`). `rotate_key`, `rotate_krbtgt`,
//! `retire_kvno` and `destroy_key_set` take **a decision id**, never a
//! handle, kvno or approval: keyd runs the parameters dird registered
//! (crate decision.rs), and builds `rotate_krbtgt`'s dual-control token
//! itself from the decision's approvers ([`DualControlToken`] is private to
//! this crate — a fabricated token is unrepresentable).
//!
//! **Task PN8:** `install_attestation_key` — the attestation key of dird's
//! name resolutions, installed once, in the ceremony only, by Role::Admin
//! only; keyd only verifies with it (crate name_resolution; docs/59 §7.4).
//! **Task PN9:** it is the operation `Operation::InstallAttestationKey` —
//! its role and ceremony checks are the capability table's (`Keyd::admit`),
//! and it emits its one audit record (I8).
//!
//! Spec: docs/10 §7; docs/09 א.7 (D32 current + previous); docs/33 §5
//! (double krbtgt rotation after compromise, D20), §6.1 (D178);
//! docs/questions/Q-115 (A-35, `destroy_key_set`); docs/52 §4.2, §4.4;
//! docs/questions/Q-460, Q-462 item 1 (A-102).

use crate::audit::{AuditKeyRef, AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::decision::Recorded;
use crate::entropy::EntropySource;
use crate::error::{Deny, Error, Internal};
use crate::keyd::{new_random_keys, store_deny, AuditFields, Keyd};
use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalBinding, PrincipalId};
use crate::store::{KeyStore, KvnoKeys, StoredKeySet};
use crate::template::check_new_binding;
use keyd_types::{DecidedOperation, DecisionId};
use krb_proto::KerberosTime;
use name_attestation::AttestationKey;

/// The dual-control approval `rotate_krbtgt` requires: two approver
/// identities, **built only inside keyd** from the approvers of a decision
/// dird registered (A-102, docs/52 §4.2: "`DualControlToken` leaves the
/// public API and the wire") — dird verified each approver's AP-REQ and
/// PDP decision (docs/51 §5.6). keyd still checks that the two are
/// distinct (registration already did).
///
/// Spec: docs/10 §7 ("rotate_krbtgt באישור כפול"); docs/43 D175; docs/52
/// §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DualControlToken {
    approver_1: PrincipalId,
    approver_2: PrincipalId,
}

impl DualControlToken {
    /// The token of a decision's approvers: the first two (the requester and
    /// the first approver), or `None` with fewer than two.
    /// Spec: docs/51 §5.6 (`DualControlToken { approver_1: the requester,
    /// approver_2: the approver }`).
    fn of(approvers: &[PrincipalId]) -> Option<DualControlToken> {
        match approvers {
            [approver_1, approver_2, ..] => Some(DualControlToken {
                approver_1: *approver_1,
                approver_2: *approver_2,
            }),
            _ => None,
        }
    }

    /// `true` if the two approvers are distinct.
    /// Spec: docs/10 §7; docs/43 D175.
    fn has_distinct_approvers(&self) -> bool {
        self.approver_1 != self.approver_2
    }
}

/// The recorded result of a rotation (docs/52 §3.10 (a)).
fn rotation_recorded(kvno: &Kvno) -> Recorded {
    Recorded::Kvno(*kvno)
}

/// A rotation's recorded result, returned again.
fn rotation_replayed(recorded: Recorded) -> Result<Kvno, Error> {
    match recorded {
        Recorded::Kvno(kvno) => Ok(kvno),
        Recorded::Refused(error) => Err(error),
        // Cannot happen: a rotation records a kvno (fail closed).
        Recorded::Done => Err(Error::Denied),
    }
}

/// The recorded result of `retire_kvno` / `destroy_key_set`.
fn unit_recorded(_: &()) -> Recorded {
    Recorded::Done
}

/// A unit operation's recorded result, returned again.
fn unit_replayed(recorded: Recorded) -> Result<(), Error> {
    match recorded {
        Recorded::Done => Ok(()),
        Recorded::Refused(error) => Err(error),
        // Cannot happen: a unit operation records `Done` (fail closed).
        Recorded::Kvno(_) => Err(Error::Denied),
    }
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `create_key`: fresh random keys (one per configured enctype) for a
    /// handle that has no key set yet. Returns the initial kvno.
    ///
    /// `binding` is the principal name the new key set is bound to, for
    /// good: Admin (tier-0) is the authority for it, and there is no rename
    /// in phase 1 (a renamed principal is a new key set). It must be in this
    /// realm; a Krbtgt key must be bound to a two-part "krbtgt" name and no
    /// other key may be (RFC 4120 6.2, 7.3).
    ///
    /// Refused if a key set already exists (use rotation — this keeps
    /// `create_key` from bypassing `rotate_krbtgt`'s dual control, and keeps
    /// the binding immutable), and refused for krbtgt when the store does not
    /// accept critical keys (D178).
    ///
    /// **Provisioning only** (A-102, docs/52 R3): after `seal_ceremony` it is
    /// refused at the authorization step (`CeremonySealed`).
    ///
    /// Spec: docs/10 §7 (`create_key`, "draws a key (gMSA, krbtgt init)");
    /// docs/33 §6.1 (D178); RFC 3961 §3 (random-to-key); RFC 4120 6.2, 7.3;
    /// docs/questions/Q-040 (A-19).
    pub fn create_key(
        &mut self,
        caller: &CallerId,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
        now: &KerberosTime,
    ) -> Result<Kvno, Error> {
        let mut fields = AuditFields::for_handle(handle);
        let result = self.create_key_inner(caller, handle, binding, now, &mut fields);
        self.emit(caller, Operation::CreateKey, now, &fields, &result);
        result.map_err(Error::from)
    }

    fn create_key_inner(
        &mut self,
        caller: &CallerId,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<Kvno> {
        self.admit(
            caller,
            Operation::CreateKey,
            &[(HandleSlot::Primary, handle)],
            now,
        )?;
        if !self.store.accepts(handle.purpose) {
            return Err(Deny::denied(AuditReason::StoreRefusedCritical));
        }
        if self.store.get(handle).is_some() {
            return Err(Deny::denied(AuditReason::KeyExists));
        }
        // The creation proof of A-19 — the only way to a new key set (R7).
        let new_binding = check_new_binding(&self.config.realm, handle, binding)?;
        let keys = new_random_keys(&mut self.entropy, &self.enctypes)?;
        let kvno = Kvno::INITIAL;
        fields.kvno = Some(kvno);
        let (handle, set) = StoredKeySet::create(new_binding, KvnoKeys::random(kvno, keys));
        self.store.insert(handle, set).map_err(store_deny)?;
        Ok(kvno)
    }

    /// `rotate_key`: run the `RotateKey` decision `id` dird registered —
    /// new random keys under the next kvno for the decided key set; the
    /// current version becomes previous (still usable to decrypt tickets
    /// until `retire_kvno`), the old previous is dropped and zeroized.
    /// Returns the new kvno; a second presentation of `id` returns the same
    /// result without rotating again (crate decision.rs).
    ///
    /// Not for krbtgt — that is `rotate_krbtgt`, under dual control.
    ///
    /// Spec: docs/10 §7 (`rotate_key`: "new; the current goes down to
    /// previous"), §1; docs/09 D32; docs/52 §4.2 (A-102).
    pub fn rotate_key(
        &mut self,
        caller: &CallerId,
        id: DecisionId,
        now: &KerberosTime,
    ) -> Result<Kvno, Error> {
        self.execute_decision(
            caller,
            Operation::RotateKey,
            id,
            now,
            |keyd, operation, _, fields| match operation {
                DecidedOperation::RotateKey { handle } => keyd.rotate_inner(handle, fields),
                _ => Err(Deny::denied(AuditReason::DecisionMismatch)),
            },
            rotation_recorded,
            rotation_replayed,
        )
    }

    /// `rotate_krbtgt`: run the `RotateKrbtgt` decision `id` — rotate the
    /// krbtgt key set (as `rotate_key`) under dual control. The
    /// dual-control token is built **here** from the decision's approvers
    /// (dird verified each one's AP-REQ and PDP decision); keyd checks that
    /// the two are distinct.
    ///
    /// Recovery after a suspected compromise is a double rotation followed
    /// by `retire_kvno` (docs/33 §5, D20), each its own decision.
    ///
    /// Spec: docs/10 §7 (`rotate_krbtgt`, "dual approval"); docs/43 D175;
    /// docs/33 §5, §6.1; docs/51 §5.6; docs/52 §4.2 (A-102).
    pub fn rotate_krbtgt(
        &mut self,
        caller: &CallerId,
        id: DecisionId,
        now: &KerberosTime,
    ) -> Result<Kvno, Error> {
        self.execute_decision(
            caller,
            Operation::RotateKrbtgt,
            id,
            now,
            |keyd, operation, approvers, fields| {
                let DecidedOperation::RotateKrbtgt { krbtgt } = operation else {
                    return Err(Deny::denied(AuditReason::DecisionMismatch));
                };
                match DualControlToken::of(approvers) {
                    Some(token) if token.has_distinct_approvers() => {
                        keyd.rotate_inner(krbtgt, fields)
                    }
                    _ => Err(Deny::denied(AuditReason::DualControlRejected)),
                }
            },
            rotation_recorded,
            rotation_replayed,
        )
    }

    /// Shared rotation body (after authorization).
    /// Spec: docs/10 §7, §1; RFC 4120 5.2.9 (kvno is UInt32).
    fn rotate_inner(&mut self, handle: &KeyHandle, fields: &mut AuditFields) -> Internal<Kvno> {
        if !self.store.accepts(handle.purpose) {
            return Err(Deny::denied(AuditReason::StoreRefusedCritical));
        }
        let current = self
            .store
            .get(handle)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?
            .current_kvno();
        let next = current
            .next()
            .ok_or(Deny::denied(AuditReason::KvnoExhausted))?;
        let keys = new_random_keys(&mut self.entropy, &self.enctypes)?;
        let set = self
            .store
            .get_mut(handle)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
        // Keys keyd drew itself, the binding unchanged: no name involved
        // (crate::store, R7).
        set.rotate_random(next, keys);
        fields.kvno = Some(next);
        Ok(next)
    }

    /// `retire_kvno`: run the `RetireKvno` decision `id` — remove the
    /// decided retained previous key version from the decided key set's
    /// decryption set. The current version can never be retired.
    ///
    /// Spec: docs/10 §7 (`retire_kvno`: "removes an old kvno from the decrypt
    /// set"); docs/33 §5 (D20); docs/52 §4.2 (A-102).
    pub fn retire_kvno(
        &mut self,
        caller: &CallerId,
        id: DecisionId,
        now: &KerberosTime,
    ) -> Result<(), Error> {
        self.execute_decision(
            caller,
            Operation::RetireKvno,
            id,
            now,
            |keyd, operation, _, _| {
                let DecidedOperation::RetireKvno { handle, kvno } = operation else {
                    return Err(Deny::denied(AuditReason::DecisionMismatch));
                };
                let set = keyd
                    .store
                    .get_mut(handle)
                    .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
                if set.current_kvno() == *kvno || !set.retire_previous(*kvno) {
                    return Err(Deny::denied(AuditReason::KvnoNotRetirable));
                }
                Ok(())
            },
            unit_recorded,
            unit_replayed,
        )
    }

    /// `destroy_key_set`: run the `DestroyKeySet` decision `id` dird
    /// registered after it committed the account's deletion — remove every
    /// key set of the decided principal, its `PrincipalLongterm` and its
    /// `Service` key set (whichever exist), current and previous versions,
    /// and zeroize them. `Ok` means: no key set of the principal exists
    /// afterwards (also when none existed). Afterwards the handles are
    /// unknown to every operation; a later `set_secret` on one (on a new
    /// decision) creates a NEW key set (from `Kvno::INITIAL`, with a binding
    /// that must pass the creation rules again).
    ///
    /// A krbtgt key set is never destroyed, only rotated: a destroy decision
    /// names a principal, and only its `PrincipalLongterm` and `Service`
    /// handles are touched (the store refuses krbtgt too).
    ///
    /// A live AuthnProof issued for a destroyed PrincipalLongterm key set is
    /// discarded with it: it attests a key that no longer exists, and must
    /// not redeem against a key set later recreated on the same handle. A
    /// live service context opened under a destroyed Service key set
    /// (`open_and_verify_service_ticket`) is discarded likewise, its session
    /// key zeroized. A live set-secret decision for either handle is dropped
    /// too.
    ///
    /// The audit record carries the destroyed current kvno of each key set
    /// (not secret).
    ///
    /// Spec: docs/questions/Q-115 (A-35: "an Admin `destroy_key_set`
    /// (zeroize + audit) called on account deletion; never for krbtgt");
    /// docs/10 §7 (Admin operations), §8 / §12 I4 (tokens), §10, §12 I8;
    /// docs/51 §6, §9; docs/52 §4.2, §4.3 (A-102).
    pub fn destroy_key_set(
        &mut self,
        caller: &CallerId,
        id: DecisionId,
        now: &KerberosTime,
    ) -> Result<(), Error> {
        self.execute_decision(
            caller,
            Operation::DestroyKeySet,
            id,
            now,
            |keyd, operation, _, fields| {
                let DecidedOperation::DestroyKeySet { principal } = operation else {
                    return Err(Deny::denied(AuditReason::DecisionMismatch));
                };
                let account = KeyHandle::new(*principal, KeyPurpose::PrincipalLongterm);
                let service = KeyHandle::new(*principal, KeyPurpose::Service);
                fields.kvno = keyd.destroy_one(&account)?;
                let service_kvno = keyd.destroy_one(&service)?;
                fields.secondary = Some(AuditKeyRef {
                    principal: *principal,
                    purpose: KeyPurpose::Service,
                    kvno: service_kvno,
                });
                Ok(())
            },
            unit_recorded,
            unit_replayed,
        )
    }

    /// `install_attestation_key`: put the attestation key dird's name
    /// resolutions are verified with into keyd's slot (task PN8; docs/59
    /// §7.4) — the key `provision` drew and wrote to dird's key file, handed
    /// to keyd by keyadm's ceremony (task PN9; PN12 writes the file). keyd
    /// never exports it, and never tags with it: it only verifies
    /// (`Keyd::verify_name_resolution`).
    ///
    /// Refused — the uniform `Denied`, nothing changed, the refused key
    /// wiped on drop — in this order:
    /// 1. the authorization step ([`Keyd::admit`] with
    ///    `Operation::InstallAttestationKey`): a caller other than
    ///    Role::Admin (`RoleNotPermitted` — the capability table's Admin row
    ///    alone holds it); outside the provisioning ceremony
    ///    (`CeremonySealed` — `authz::provisioning_only`: after
    ///    `seal_ceremony`, or on a keyd that started operational, A-102,
    ///    docs/52 R3) — a key is never installed into a running service;
    /// 2. a key already installed (`AttestationKeyInstalled`): once per
    ///    start, never replaced — so whoever reaches keyd after the ceremony
    ///    cannot swap in a key whose resolutions keyd would then believe.
    ///
    /// Exactly one audit record, success or refusal (I8): the operation, the
    /// caller, the outcome and the reason — no key octet (the record has no
    /// field that could hold one). It is a key-state change
    /// (`authz::changes_key_state`): a daemon has its intent acknowledged by
    /// auditd before it calls this (A-86; docs/questions/Q-1033 item 3).
    ///
    /// Spec: docs/59 §7.4, §7.5; docs/questions/Q-1011 items 2, 8 (A-173:
    /// "drawn by `provision` … delivered to keyd in ceremony mode only, never
    /// exported"), Q-1033 (A-177); docs/52 §4.4, §7 R3 (A-102); docs/10 §10,
    /// §12 I8; D28 / D29; AGENTS.md §6.1.
    pub fn install_attestation_key(
        &mut self,
        caller: &CallerId,
        key: AttestationKey,
        now: &KerberosTime,
    ) -> Result<(), Error> {
        let fields = AuditFields::default();
        let result = self.install_attestation_key_inner(caller, key, now);
        self.emit(
            caller,
            Operation::InstallAttestationKey,
            now,
            &fields,
            &result,
        );
        result.map_err(Error::from)
    }

    /// The checks and the install of [`Keyd::install_attestation_key`], with
    /// the audit-only reason of a refusal (no record of its own).
    /// Spec: docs/questions/Q-1011 item 2; docs/52 §4.4; docs/10 §2 (I2).
    pub(crate) fn install_attestation_key_inner(
        &mut self,
        caller: &CallerId,
        key: AttestationKey,
        now: &KerberosTime,
    ) -> Internal<()> {
        // Role (I2) and the ceremony state (R3), from the compile-time
        // tables — the same step every operation runs first.
        self.admit(caller, Operation::InstallAttestationKey, &[], now)?;
        if self.attestation_key.is_some() {
            return Err(Deny::denied(AuditReason::AttestationKeyInstalled));
        }
        self.attestation_key = Some(key);
        Ok(())
    }

    /// Whether this start's ceremony installed the attestation key. Not
    /// secret (the key itself is never readable).
    /// Spec: docs/59 §7.4; docs/questions/Q-1011 item 2.
    #[must_use]
    pub fn has_attestation_key(&self) -> bool {
        self.attestation_key.is_some()
    }

    /// Destroy the key set of `handle` if it exists, with everything bound
    /// to it (proofs, service contexts, a set-secret decision); its
    /// destroyed current kvno, or `None` when there was none.
    /// Spec: docs/10 §7, §8; docs/questions/Q-115 (A-35), Q-450 item 8.
    fn destroy_one(&mut self, handle: &KeyHandle) -> Internal<Option<Kvno>> {
        // A live set-secret decision for the destroyed key set goes with it:
        // the handle is unknown afterwards (docs/questions/Q-450 item 8).
        self.decisions.discard_secret(handle);
        let Some(current) = self.store.get(handle).map(StoredKeySet::current_kvno) else {
            return Ok(None);
        };
        self.store.destroy(handle).map_err(store_deny)?;
        match handle.purpose {
            KeyPurpose::PrincipalLongterm => {
                let principal = handle.principal;
                self.proofs
                    .discard_where(|entry| entry.principal() == principal);
            }
            // A live service context opened under a destroyed Service (or
            // AdminService) key set goes with it (its session key zeroized):
            // the key set it was verified under no longer exists (docs/49
            // §3.3, A-46). (A destroy decision never names an AdminService
            // or ChangePasswordService key set — crate authz
            // `purpose_permitted`; a change-password request context names
            // the user key set it may install, not the service key set, and
            // the install itself requires the user key set to exist.)
            KeyPurpose::Service | KeyPurpose::AdminService | KeyPurpose::ChangePasswordService => {
                let service = *handle;
                self.service_contexts
                    .discard_where(|entry| entry.service() == service);
            }
            KeyPurpose::Krbtgt => {}
        }
        Ok(Some(current))
    }
}
