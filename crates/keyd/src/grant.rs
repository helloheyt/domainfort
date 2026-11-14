//! The set_secret grant (task A15a): `grant_set_secret` (Role::Ldap — dird
//! after its PDP; Role::Admin — keyadm's ceremony) and the grant table that
//! Role::Directory's `set_secret` must find a matching, unexpired entry in,
//! and consumes.
//!
//! # The table
//!
//! In memory, bounded ([`MAX_SET_SECRET_GRANTS`] key targets), at most **one
//! grant per handle** — a newer grant for a handle replaces the older one
//! (a fresh PDP decision supersedes it; the count per handle stays one).
//! Expired entries are swept on every registration and every redemption.
//! Lost at every start, like the token tables (docs/10 §11) — which only
//! makes keyd stricter, so nothing is held after a start.
//!
//! # Matching (`set_secret` from Role::Directory)
//!
//! 1. **At the authorization step** ([`Keyd::admit`]): a live grant must
//!    name the handle; otherwise the uniform `Denied`, reason `NoGrant` —
//!    one record, no intent, nothing changed (A-88: an authorization
//!    refusal). `Keyd::admits` gives the daemon the same answer.
//! 2. **First thing after it**: the grant is taken out of the table
//!    ([`GrantTable::redeem`]) — consumed by this presentation whatever the
//!    rest of `set_secret` decides (one attempt per grant). Its binding must
//!    equal the call's binding exactly (realm, name-type and every name
//!    component; no equivalence rule is needed: dird returns the binding and
//!    admind passes it on unchanged) — otherwise `Denied`, reason
//!    `GrantMismatch`, and the grant is gone (treated as misused, as a token
//!    presented by the wrong caller is, crate tokens.rs). An initial-secret
//!    grant (Role::Admin) also requires that the key set still does not
//!    exist.
//!
//! Spec: docs/51 §4.3 steps 11-12, §5.2 row 5, §5.8 option (b), §7.3, §9;
//! docs/47 §9.1, §9.2; docs/10 §2, §6, §8, §10, §11; docs/questions/Q-291
//! (A-74), Q-365 (A-88), Q-450, Q-451.

use crate::audit::{AuditKeyRef, AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation, Role};
use crate::entropy::EntropySource;
use crate::error::{Deny, Error, Internal};
use crate::keyd::{AuditFields, Keyd};
use crate::model::{KeyHandle, PrincipalBinding};
use crate::store::KeyStore;
use crate::time::kerberos_time_seconds;
use keyd_types::grant::max_grant_lifetime_secs;
use keyd_types::{AccountKind, SetSecretTarget, MAX_GRANT_TARGETS};
use krb_proto::KerberosTime;
use std::collections::HashMap;

/// One granted key target.
/// Spec: docs/51 §5.8 option (b): `(handle, binding, expiry)`.
#[derive(Debug, Clone)]
struct GrantEntry {
    binding: PrincipalBinding,
    /// The last second (on the [`kerberos_time_seconds`] scale) at which the
    /// grant is live.
    expires_at: i64,
    /// Registered by Role::Admin: only an initial secret (docs/questions/Q-451).
    initial_only: bool,
}

/// What a redeemed grant still requires of the `set_secret` that consumed it.
/// Spec: docs/questions/Q-451 item 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Redeemed {
    /// The key set must not exist (an initial secret).
    pub(crate) initial_only: bool,
}

/// The grant table (module documentation).
/// Spec: docs/questions/Q-450 items 1, 4; AGENTS.md §6 (bounded, fail closed).
#[derive(Debug)]
pub(crate) struct GrantTable {
    entries: HashMap<KeyHandle, GrantEntry>,
    capacity: usize,
}

impl GrantTable {
    pub(crate) fn new(capacity: usize) -> GrantTable {
        GrantTable {
            entries: HashMap::new(),
            capacity,
        }
    }

    /// Remove every expired entry. Spec: docs/questions/Q-450 item 4.
    fn sweep(&mut self, now: i64) {
        self.entries.retain(|_, e| now <= e.expires_at);
    }

    /// Whether a live grant names `handle` at `now`. Reads only.
    /// Spec: docs/questions/Q-450 item 1.
    pub(crate) fn is_live(&self, handle: &KeyHandle, now: i64) -> bool {
        self.entries
            .get(handle)
            .is_some_and(|e| now <= e.expires_at)
    }

    /// Register one grant for every target, both or none: refused (the
    /// table unchanged, beyond the sweep) when the targets would not fit
    /// beside the live grants of other handles; a live grant of the same
    /// handle is replaced.
    /// Spec: docs/questions/Q-450 items 2, 4.
    fn register(
        &mut self,
        targets: &[SetSecretTarget],
        expires_at: i64,
        initial_only: bool,
        now: i64,
    ) -> Internal<()> {
        self.sweep(now);
        let added = targets
            .iter()
            .filter(|t| !self.entries.contains_key(&t.handle))
            .count();
        if self.entries.len().saturating_add(added) > self.capacity {
            return Err(Deny::unavailable(AuditReason::GrantTableFull));
        }
        for target in targets {
            self.entries.insert(
                target.handle,
                GrantEntry {
                    binding: target.binding.clone(),
                    expires_at,
                    initial_only,
                },
            );
        }
        Ok(())
    }

    /// Consume the grant of `handle` for a `set_secret` naming `binding`:
    /// the entry is removed on ANY presentation (module documentation,
    /// "Matching"). No live grant ⇒ `NoGrant`; another binding ⇒
    /// `GrantMismatch`.
    /// Spec: docs/51 §5.8 option (b) ("refused unless a matching unexpired
    /// grant exists, and consumes it"); docs/questions/Q-450 item 7.
    pub(crate) fn redeem(
        &mut self,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
        now: i64,
    ) -> Internal<Redeemed> {
        let entry = self.entries.remove(handle);
        self.sweep(now);
        let entry = entry.ok_or(Deny::denied(AuditReason::NoGrant))?;
        if now > entry.expires_at {
            return Err(Deny::denied(AuditReason::NoGrant));
        }
        if entry.binding != *binding {
            return Err(Deny::denied(AuditReason::GrantMismatch));
        }
        Ok(Redeemed {
            initial_only: entry.initial_only,
        })
    }

    /// Drop the grant of `handle`, if any (its key set was destroyed).
    /// Spec: docs/10 §7 (`destroy_key_set`: the handle is unknown
    /// afterwards); docs/questions/Q-450 item 8.
    pub(crate) fn discard(&mut self, handle: &KeyHandle) {
        self.entries.remove(handle);
    }

    /// Entries held (live or not yet swept).
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// The handle slots of `targets` for the authorization step: the first
/// target in the `Primary` slot, the second in the `Secondary` slot; a third
/// is not looked at here (the shape check refuses it).
/// Spec: docs/10 §2 (I3); keyd-types authz `purpose_permitted`.
fn slots(targets: &[SetSecretTarget]) -> Vec<(HandleSlot, &KeyHandle)> {
    targets
        .iter()
        .zip([HandleSlot::Primary, HandleSlot::Secondary])
        .map(|(target, slot)| (slot, &target.handle))
        .collect()
}

/// The shape of the targets for `kind`: one target for a user; one or two
/// for a computer, the second of the same principal (the purposes — first
/// `PrincipalLongterm`, second `Service` — are the authorization step's).
/// Spec: docs/47 §9.1; docs/51 §5.2 row 5, §7.3; docs/questions/Q-450
/// item 2.
fn shape_fits(kind: AccountKind, targets: &[SetSecretTarget]) -> bool {
    match (kind, targets) {
        (AccountKind::User, [_]) | (AccountKind::Computer, [_]) => true,
        (AccountKind::Computer, [first, second]) => {
            first.handle.principal == second.handle.principal
        }
        _ => false,
    }
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `grant_set_secret`: register a one-time grant, live for
    /// `lifetime_secs` from `now` (keyd's own clock), that lets
    /// Role::Directory run `set_secret` once on each of `targets` with
    /// exactly its binding (module documentation).
    ///
    /// In order — every refusal is the uniform `Denied` unless noted, with
    /// its reason in the one audit record:
    /// 1. the authorization step ([`Keyd::admit`]): the role (Ldap or Admin,
    ///    I2) and the purposes (first target `PrincipalLongterm`, second
    ///    `Service`, I3);
    /// 2. the shape of the targets for `kind` (`GrantInvalid`);
    /// 3. the caller's rules: a lifetime of 1 to its ceiling
    ///    (`max_grant_lifetime_secs`: Ldap 30 s, Admin 900 s); Role::Admin
    ///    only for a user and only for a key set that does not exist yet
    ///    (`GrantInvalid`, `KeyExists` — docs/questions/Q-451);
    /// 4. the table (`GrantTableFull` ⇒ `Unavailable`).
    ///
    /// The bindings are not judged here: the `set_secret` that redeems a
    /// grant judges its binding exactly as before (the existing key set's,
    /// or the creation rules of a new one — A-19), so a grant can only ever
    /// narrow what `set_secret` accepts (docs/questions/Q-450 item 7).
    ///
    /// No key is read or written; nothing secret is taken or returned. The
    /// audit record names the first target (principal, purpose) and the
    /// second as its secondary key; it carries no binding and no lifetime.
    ///
    /// Spec: docs/51 §5.8 option (b); docs/10 §2, §6, §9, §10; docs/50
    /// R50-5 (keyd's own clock); docs/questions/Q-291 (A-74), Q-450, Q-451.
    pub fn grant_set_secret(
        &mut self,
        caller: &CallerId,
        kind: AccountKind,
        targets: &[SetSecretTarget],
        lifetime_secs: u32,
        now: &KerberosTime,
    ) -> Result<(), Error> {
        let mut fields = AuditFields::default();
        if let Some(first) = targets.first() {
            fields = AuditFields::for_handle(&first.handle);
        }
        if let Some(second) = targets.get(1) {
            fields.secondary = Some(AuditKeyRef {
                principal: second.handle.principal,
                purpose: second.handle.purpose,
                kvno: None,
            });
        }
        let result = self.grant_set_secret_inner(caller, kind, targets, lifetime_secs, now);
        self.emit(caller, Operation::GrantSetSecret, now, &fields, &result);
        result.map_err(Error::from)
    }

    fn grant_set_secret_inner(
        &mut self,
        caller: &CallerId,
        kind: AccountKind,
        targets: &[SetSecretTarget],
        lifetime_secs: u32,
        now: &KerberosTime,
    ) -> Internal<()> {
        self.admit(caller, Operation::GrantSetSecret, &slots(targets), now)?;
        if targets.len() > MAX_GRANT_TARGETS || !shape_fits(kind, targets) {
            return Err(Deny::denied(AuditReason::GrantInvalid));
        }
        // The role passed the capability table, so it has a ceiling; any
        // other role would be refused here too (fail closed).
        let ceiling = max_grant_lifetime_secs(caller.role)
            .ok_or(Deny::denied(AuditReason::RoleNotPermitted))?;
        if lifetime_secs == 0 || lifetime_secs > ceiling {
            return Err(Deny::denied(AuditReason::GrantInvalid));
        }
        let initial_only = caller.role == Role::Admin;
        if initial_only && kind != AccountKind::User {
            return Err(Deny::denied(AuditReason::GrantInvalid));
        }
        // An initial secret only: no key set yet (the binding itself is
        // judged by the `set_secret` that redeems the grant, as before —
        // A-19; docs/questions/Q-450 item 7).
        if initial_only
            && targets
                .iter()
                .any(|target| self.store.get(&target.handle).is_some())
        {
            return Err(Deny::denied(AuditReason::KeyExists));
        }
        let now_s = kerberos_time_seconds(now);
        let expires_at = now_s
            .checked_add(i64::from(lifetime_secs))
            .ok_or(Deny::denied(AuditReason::GrantInvalid))?;
        self.grants
            .register(targets, expires_at, initial_only, now_s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{KeyPurpose, PrincipalId};
    use krb_proto::{KerberosString, PrincipalName, Realm};

    fn target(byte: u8, purpose: KeyPurpose, name: &str) -> SetSecretTarget {
        SetSecretTarget {
            handle: KeyHandle::new(PrincipalId::from_bytes([byte; 16]), purpose),
            binding: PrincipalBinding::new(
                Realm::new("EXAMPLE.ORG").unwrap(),
                PrincipalName {
                    name_type: 1,
                    name_string: vec![KerberosString::new(name).unwrap()],
                },
            ),
        }
    }

    /// Q-450 item 4: bounded; a grant that does not fit is refused whole,
    /// a replacement takes no new room, expired entries make room.
    #[test]
    fn the_table_is_bounded_and_registers_both_or_none() {
        let mut t = GrantTable::new(2);
        let a = target(1, KeyPurpose::PrincipalLongterm, "a");
        let b1 = target(2, KeyPurpose::PrincipalLongterm, "b$");
        let b2 = target(2, KeyPurpose::Service, "b");
        assert!(t.register(std::slice::from_ref(&a), 10, false, 0).is_ok());
        // Two more targets do not fit beside a: refused, nothing added.
        let refused = t.register(&[b1.clone(), b2.clone()], 20, false, 5);
        assert_eq!(
            refused.map_err(|d| d.reason),
            Err(AuditReason::GrantTableFull)
        );
        assert_eq!(t.len(), 1);
        // A replacement of a's grant takes no room.
        assert!(t.register(std::slice::from_ref(&a), 30, false, 5).is_ok());
        assert_eq!(t.len(), 1);
        // After a expires, the computer's two targets fit.
        assert!(t.register(&[b1, b2], 40, false, 31).is_ok());
        assert_eq!(t.len(), 2);
        assert!(!t.is_live(&a.handle, 31));
    }

    /// Q-450 items 1, 7: one presentation consumes the grant; another
    /// binding consumes it too and is refused; an expired grant is no grant.
    #[test]
    fn redeeming_consumes_on_every_presentation() {
        let mut t = GrantTable::new(4);
        let a = target(1, KeyPurpose::PrincipalLongterm, "a");
        assert!(t.register(std::slice::from_ref(&a), 10, false, 0).is_ok());
        assert!(t.is_live(&a.handle, 10));
        assert_eq!(
            t.redeem(&a.handle, &a.binding, 10),
            Ok(Redeemed {
                initial_only: false
            })
        );
        assert_eq!(
            t.redeem(&a.handle, &a.binding, 10).map_err(|d| d.reason),
            Err(AuditReason::NoGrant)
        );

        let other = target(1, KeyPurpose::PrincipalLongterm, "other").binding;
        assert!(t.register(std::slice::from_ref(&a), 10, true, 0).is_ok());
        assert_eq!(
            t.redeem(&a.handle, &other, 1).map_err(|d| d.reason),
            Err(AuditReason::GrantMismatch)
        );
        assert!(!t.is_live(&a.handle, 1));

        assert!(t.register(std::slice::from_ref(&a), 10, false, 0).is_ok());
        assert!(!t.is_live(&a.handle, 11));
        assert_eq!(
            t.redeem(&a.handle, &a.binding, 11).map_err(|d| d.reason),
            Err(AuditReason::NoGrant)
        );
        assert_eq!(t.len(), 0);
    }

    /// docs/47 §9.1; Q-450 item 2: the shapes keyd accepts.
    #[test]
    fn the_shape_follows_the_account_kind() {
        let pl = target(1, KeyPurpose::PrincipalLongterm, "ws$");
        let svc = target(1, KeyPurpose::Service, "host");
        let other_svc = target(2, KeyPurpose::Service, "host");
        assert!(shape_fits(AccountKind::User, std::slice::from_ref(&pl)));
        assert!(!shape_fits(AccountKind::User, &[pl.clone(), svc.clone()]));
        assert!(!shape_fits(AccountKind::User, &[]));
        assert!(shape_fits(AccountKind::Computer, std::slice::from_ref(&pl)));
        assert!(shape_fits(
            AccountKind::Computer,
            &[pl.clone(), svc.clone()]
        ));
        assert!(!shape_fits(AccountKind::Computer, &[pl.clone(), other_svc]));
        assert!(!shape_fits(
            AccountKind::Computer,
            &[pl.clone(), svc.clone(), pl]
        ));
        assert!(!shape_fits(AccountKind::Computer, &[]));
    }
}
