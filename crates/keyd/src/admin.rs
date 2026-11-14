//! Admin operations: the key lifecycle (create, rotate, rotate krbtgt under
//! dual control, retire an old kvno, destroy a deleted account's key set).
//! Role `Admin` (tier-0) only.
//!
//! None of these returns key material — only the resulting kvno. "There is
//! no read-key operation — in any role."
//!
//! Spec: docs/10 §7; docs/09 א.7 (D32 current + previous); docs/33 §5
//! (double krbtgt rotation after compromise, D20), §6.1 (D178);
//! docs/questions/Q-115 (A-35, `destroy_key_set`).

use crate::audit::{AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::entropy::EntropySource;
use crate::error::{Deny, Error, Internal};
use crate::keyd::{new_random_keys, store_deny, AuditFields, Keyd};
use crate::model::{DualControlToken, KeyHandle, KeyPurpose, Kvno, PrincipalBinding};
use crate::store::{KeyStore, KvnoKeys, StoredKeySet};
use crate::template::check_new_binding;
use krb_proto::KerberosTime;

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
        check_new_binding(&self.config.realm, handle.purpose, binding)?;
        let keys = new_random_keys(&mut self.entropy, &self.enctypes)?;
        let kvno = Kvno::INITIAL;
        fields.kvno = Some(kvno);
        let set = StoredKeySet::new(binding.clone(), KvnoKeys::new(kvno, keys, None, None));
        self.store.insert(*handle, set).map_err(store_deny)?;
        Ok(kvno)
    }

    /// `rotate_key`: new random keys under the next kvno; the current
    /// version becomes previous (still usable to decrypt tickets until
    /// `retire_kvno`), the old previous is dropped and zeroized.
    ///
    /// Not for krbtgt — that is `rotate_krbtgt`, under dual control.
    ///
    /// Spec: docs/10 §7 (`rotate_key`: "new; the current goes down to
    /// previous"), §1; docs/09 D32.
    pub fn rotate_key(
        &mut self,
        caller: &CallerId,
        handle: &KeyHandle,
        now: &KerberosTime,
    ) -> Result<Kvno, Error> {
        let mut fields = AuditFields::for_handle(handle);
        let result = self
            .admit(
                caller,
                Operation::RotateKey,
                &[(HandleSlot::Primary, handle)],
                now,
            )
            .and_then(|()| self.rotate_inner(handle, &mut fields));
        self.emit(caller, Operation::RotateKey, now, &fields, &result);
        result.map_err(Error::from)
    }

    /// `rotate_krbtgt`: rotate the krbtgt key set (as `rotate_key`) under
    /// dual control. The token must name two DISTINCT approvers; keyd checks
    /// distinctness only — the authenticity of the approvals is verified by
    /// the admin plane (docs/43 D175), a documented residual.
    ///
    /// Recovery after a suspected compromise is a double rotation followed
    /// by `retire_kvno` (docs/33 §5, D20).
    ///
    /// Spec: docs/10 §7 (`rotate_krbtgt`, "dual approval"); docs/43 D175;
    /// docs/33 §5, §6.1.
    pub fn rotate_krbtgt(
        &mut self,
        caller: &CallerId,
        krbtgt: &KeyHandle,
        approval: &DualControlToken,
        now: &KerberosTime,
    ) -> Result<Kvno, Error> {
        let mut fields = AuditFields::for_handle(krbtgt);
        fields.approvers = Some([approval.approver_1, approval.approver_2]);
        let result = self
            .admit(
                caller,
                Operation::RotateKrbtgt,
                &[(HandleSlot::Primary, krbtgt)],
                now,
            )
            .and_then(|()| {
                if approval.has_distinct_approvers() {
                    Ok(())
                } else {
                    Err(Deny::denied(AuditReason::DualControlRejected))
                }
            })
            .and_then(|()| self.rotate_inner(krbtgt, &mut fields));
        self.emit(caller, Operation::RotateKrbtgt, now, &fields, &result);
        result.map_err(Error::from)
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
        set.rotate(KvnoKeys::new(next, keys, None, None));
        fields.kvno = Some(next);
        Ok(next)
    }

    /// `retire_kvno`: remove the retained previous key version from the
    /// decryption set. The current version can never be retired.
    ///
    /// Spec: docs/10 §7 (`retire_kvno`: "removes an old kvno from the decrypt
    /// set"); docs/33 §5 (D20).
    pub fn retire_kvno(
        &mut self,
        caller: &CallerId,
        handle: &KeyHandle,
        kvno: Kvno,
        now: &KerberosTime,
    ) -> Result<(), Error> {
        let mut fields = AuditFields::for_handle(handle);
        fields.kvno = Some(kvno);
        let result = self
            .admit(
                caller,
                Operation::RetireKvno,
                &[(HandleSlot::Primary, handle)],
                now,
            )
            .and_then(|()| {
                let set = self
                    .store
                    .get_mut(handle)
                    .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
                if set.current_kvno() == kvno || !set.retire_previous(kvno) {
                    return Err(Deny::denied(AuditReason::KvnoNotRetirable));
                }
                Ok(())
            });
        self.emit(caller, Operation::RetireKvno, now, &fields, &result);
        result.map_err(Error::from)
    }

    /// `destroy_key_set`: remove the whole key set of `handle` — current
    /// and previous versions — and zeroize it, when the account is deleted.
    /// Afterwards the handle is unknown to every operation; a later
    /// `set_secret` on it creates a NEW key set (from `Kvno::INITIAL`, with
    /// a binding that must pass the creation rules again).
    ///
    /// Purposes: PrincipalLongterm or Service only — a krbtgt key set is
    /// never destroyed, only rotated (purpose table, and the store refuses
    /// it too). An unknown handle is the uniform `Denied`.
    ///
    /// A live AuthnProof issued for a destroyed PrincipalLongterm key set is
    /// discarded with it: it attests a key that no longer exists, and must
    /// not redeem against a key set later recreated on the same handle. A
    /// live service context opened under a destroyed Service key set
    /// (`open_and_verify_service_ticket`) is discarded likewise, its session
    /// key zeroized. A live `set_secret` grant for the handle (task A15a) is
    /// dropped too.
    ///
    /// The audit record carries the destroyed current kvno (not secret).
    ///
    /// Spec: docs/questions/Q-115 (A-35: "an Admin `destroy_key_set`
    /// (zeroize + audit) called on account deletion; never for krbtgt");
    /// docs/10 §7 (Admin operations), §8 / §12 I4 (tokens), §10, §12 I8.
    pub fn destroy_key_set(
        &mut self,
        caller: &CallerId,
        handle: &KeyHandle,
        now: &KerberosTime,
    ) -> Result<(), Error> {
        let mut fields = AuditFields::for_handle(handle);
        let result = self.destroy_key_set_inner(caller, handle, now, &mut fields);
        self.emit(caller, Operation::DestroyKeySet, now, &fields, &result);
        result.map_err(Error::from)
    }

    fn destroy_key_set_inner(
        &mut self,
        caller: &CallerId,
        handle: &KeyHandle,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<()> {
        self.admit(
            caller,
            Operation::DestroyKeySet,
            &[(HandleSlot::Primary, handle)],
            now,
        )?;
        let current = self
            .store
            .get(handle)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?
            .current_kvno();
        fields.kvno = Some(current);
        self.store.destroy(handle).map_err(store_deny)?;
        // A live set_secret grant for the destroyed key set goes with it: the
        // handle is unknown afterwards (docs/questions/Q-450 item 8).
        self.grants.discard(handle);
        match handle.purpose {
            KeyPurpose::PrincipalLongterm => {
                let principal = handle.principal;
                self.proofs
                    .discard_where(|entry| entry.principal() == principal);
            }
            // A live service context opened under a destroyed Service key set
            // goes with it (its session key zeroized): the key set it was
            // verified under no longer exists (docs/49 §3.3, A-46).
            KeyPurpose::Service => {
                let service = *handle;
                self.service_contexts
                    .discard_where(|entry| entry.service() == service);
            }
            KeyPurpose::Krbtgt => {}
        }
        Ok(())
    }
}
