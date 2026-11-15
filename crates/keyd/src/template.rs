//! Ticket-template validation shared by the AS and TGS issuance operations.
//!
//! keyd never seals what the caller asks blindly: it builds the ticket
//! itself and accepts from the caller only template values that pass these
//! structural checks (anti-oracle, docs/09 A.3 (3); docs/10 §4 step 2).
//! Failures are `BadTemplate` — the rules are public policy, nothing secret.
//! The principal-name binding checks are authorization failures and are
//! `Denied`: the creation rule here ([`check_new_binding`], whose proof is
//! the only way to create a key set), and the use rule — a name must be the
//! one the key set is bound to — in `StoredKeySet::bound_to` (crate::store,
//! R7).
//!
//! Spec: RFC 4120 2.1-2.6, 3.1.3, 3.3.3, 5.3, 5.4.1, 6.2, 7.3; docs/10 §4,
//! §5; docs/questions/Q-040 (A-19).

use crate::audit::AuditReason;
use crate::config::TicketPolicy;
use crate::error::{Deny, Internal};
use crate::model::{KeyHandle, KeyPurpose, PrincipalBinding};
use crate::time::{kerberos_time_seconds, within_skew};
use keyd_types::{
    is_admin_service_name, is_change_password_service_name,
    CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS,
};
use krb_proto::constants::KRB_NT_SRV_INST;
use krb_proto::limits::MAX_NAME_COMPONENTS;
use krb_proto::{KerberosFlags, KerberosString, KerberosTime, PrincipalName, Realm, TicketFlags};

/// The first name component of every TGS principal. Spec: RFC 4120 7.3.
const KRBTGT: &str = "krbtgt";

/// The principal name of this realm's ticket-granting service:
/// NT-SRV-INST ("krbtgt", realm). Spec: RFC 4120 7.3.
pub(crate) fn tgs_name(realm: &Realm) -> PrincipalName {
    let first = KerberosString::new(KRBTGT);
    PrincipalName {
        name_type: KRB_NT_SRV_INST,
        name_string: match first {
            Ok(first) => vec![first, realm.clone()],
            // "krbtgt" is valid KerberosString content; an empty name can
            // never equal a ticket's sname, so this branch fails closed.
            Err(_) => Vec::new(),
        },
    }
}

/// `true` if `name` is a TGS name of any realm (first component
/// "krbtgt"). Spec: RFC 4120 7.3.
pub(crate) fn is_tgs_name(name: &PrincipalName) -> bool {
    name.name_string
        .first()
        .is_some_and(|c| c.as_str() == KRBTGT)
}

/// The creation proof of a key set: a binding that passed the creation rule
/// ([`check_new_binding`]) for one handle. Built only there (its fields are
/// private to this module); consumed by `StoredKeySet::create`, the only
/// constructor of a stored key set — so a key set bound to a name the rule
/// refuses cannot be made (docs/52 §3.5, R7: the class C5 on the creation
/// side). Not `Clone`: one proof, one key set.
///
/// Spec: docs/questions/Q-040 (A-19); docs/52 §3.5 (R7).
#[derive(Debug)]
pub(crate) struct NewBinding {
    handle: KeyHandle,
    binding: PrincipalBinding,
}

impl NewBinding {
    /// The handle the rule was checked for, and the binding.
    pub(crate) fn into_parts(self) -> (KeyHandle, PrincipalBinding) {
        (self.handle, self.binding)
    }
}

/// Validate the name binding supplied when the key set of `handle` is
/// created, and return its creation proof ([`NewBinding`]):
/// - the realm is this keyd's realm (phase 1 is single-realm);
/// - the name has 1..=MAX_NAME_COMPONENTS components (krb-proto's bound);
/// - a Krbtgt key is bound to a two-part TGS name ("krbtgt", X), and no other
///   key may be bound to a name starting with "krbtgt" (reserved for the
///   TGS);
/// - an AdminService key is bound to the admin service's two-part name
///   (`admind`, host — `keyd_types::is_admin_service_name`), and no other
///   key may be bound to such a name (R2: the same shape of reservation, for
///   this project's own service);
/// - a ChangePasswordService key is bound to exactly `kadmin/changepw`
///   (`keyd_types::is_change_password_service_name`, RFC 3244 §2), and no
///   other key may be bound to that name (task K3; docs/53 §5.2).
///
/// Failure is `Denied` (reason `InvalidNameBinding`).
///
/// Spec: RFC 4120 6.2 ("Names of any type with an initial component of
/// 'krbtgt' are reserved for the Kerberos ticket-granting service"), 7.3
/// ("a two-part name ... with the first part 'krbtgt'"); docs/questions/
/// Q-040 (A-19); A-73 (the admin service's name); docs/52 §5 item 3 (R2);
/// docs/questions/Q-491.
pub(crate) fn check_new_binding(
    realm: &Realm,
    handle: &KeyHandle,
    binding: &PrincipalBinding,
) -> Internal<NewBinding> {
    let purpose = handle.purpose;
    let bad = Err(Deny::denied(AuditReason::InvalidNameBinding));
    let components = binding.name.name_string.len();
    if binding.realm.as_bytes() != realm.as_bytes()
        || components == 0
        || components > MAX_NAME_COMPONENTS
    {
        return bad;
    }
    let reserved = is_tgs_name(&binding.name);
    // R2: the admin service's name is bound only to the admin service's key
    // set, and that key set to nothing else — so a ticket for `admind/<host>`
    // is never sealed or opened under a plain Service key (the binding check
    // of every issuance and verification, A-19), and the KDC's purpose rule
    // (`KeyPurpose::of_service_name`) is enforced here too.
    let admin = is_admin_service_name(&binding.name);
    // Task K3 (docs/53 §5.2, R53-6): the same reservation for the
    // change-password service's name — so a kpasswd ticket is never sealed
    // or opened under any other key set, and no other key set under its
    // name.
    let change_password = is_change_password_service_name(&binding.name);
    let acceptable = match purpose {
        KeyPurpose::Krbtgt => reserved && components == 2,
        KeyPurpose::AdminService => admin,
        KeyPurpose::ChangePasswordService => change_password,
        KeyPurpose::PrincipalLongterm | KeyPurpose::Service => {
            !reserved && !admin && !change_password
        }
    };
    if acceptable {
        Ok(NewBinding {
            handle: *handle,
            binding: binding.clone(),
        })
    } else {
        bad
    }
}

// The check that an EXISTING key set is bound to a name — A-19 at every use
// of a key — is no longer a function here: it is `StoredKeySet::bound_to`,
// the only way to a stored key (crate::store, docs/52 §3.5, R7).

/// The bits set in both masks.
fn intersect(a: TicketFlags, b: TicketFlags) -> TicketFlags {
    TicketFlags(KerberosFlags::from_bits(a.0.bits() & b.0.bits()))
}

/// Flags of an AS ticket: the requested flags must lie in the allowed mask;
/// keyd then sets INITIAL and PRE-AUTHENT itself — facts it verified (the
/// ticket is issued by the AS exchange after PA-ENC-TIMESTAMP succeeded).
///
/// Spec: RFC 4120 2.1 (INITIAL, PRE-AUTHENT), 3.1.3 ("the flags field of the
/// new ticket will have the following options set if they have been
/// requested and if the policy of the local realm allows"), 5.3.
pub(crate) fn as_ticket_flags(
    policy: &TicketPolicy,
    requested: TicketFlags,
) -> Internal<TicketFlags> {
    if !policy.allowed_flags.contains(requested) {
        return Err(Deny::bad_template(AuditReason::TemplateFlags));
    }
    Ok(requested
        .union(TicketFlags::INITIAL)
        .union(TicketFlags::PRE_AUTHENT))
}

/// Flags of a TGS ticket.
///
/// - requested flags lie in the allowed mask;
/// - INITIAL is never set on a ticket issued from a TGT (RFC 4120 2.1);
/// - PRE-AUTHENT / HW-AUTHENT are carried forward from the TGT and may not
///   be claimed if the TGT lacks them (RFC 4120 2.1);
/// - FORWARDABLE / PROXIABLE only if the TGT has the same flag (RFC 4120
///   5.4.1 kdc-options FORWARDABLE, PROXIABLE).
///
/// Spec: RFC 4120 2.1, 2.5, 2.6, 3.3.3, 5.3, 5.4.1.
pub(crate) fn tgs_ticket_flags(
    policy: &TicketPolicy,
    requested: TicketFlags,
    tgt_flags: TicketFlags,
) -> Internal<TicketFlags> {
    let bad = Err(Deny::bad_template(AuditReason::TemplateFlags));
    if !policy.allowed_flags.contains(requested) || requested.contains(TicketFlags::INITIAL) {
        return bad;
    }
    let carried = TicketFlags::PRE_AUTHENT.union(TicketFlags::HW_AUTHENT);
    if !tgt_flags.contains(intersect(requested, carried)) {
        return bad;
    }
    for derived in [TicketFlags::FORWARDABLE, TicketFlags::PROXIABLE] {
        if requested.contains(derived) && !tgt_flags.contains(derived) {
            return bad;
        }
    }
    Ok(requested.union(intersect(tgt_flags, carried)))
}

/// The time fields of a template.
pub(crate) struct TemplateTimes<'a> {
    pub(crate) starttime: Option<&'a KerberosTime>,
    pub(crate) endtime: &'a KerberosTime,
    pub(crate) renew_till: Option<&'a KerberosTime>,
    pub(crate) renewable: bool,
}

/// Check template times against policy.
///
/// - starttime, when present, is within the clock skew of now: no
///   postdating (RFC 4120 3.1.3, 3.3.3 — POSTDATED has no code path);
/// - the effective start is starttime, else authtime (RFC 4120 5.3
///   starttime: "authtime field SHOULD be used in its place");
/// - endtime is in the future and the lifetime is within [min, max]
///   (RFC 4120 3.1.3 KDC_ERR_NEVER_VALID, §8.2);
/// - renew-till is present exactly when RENEWABLE is set (RFC 4120 5.3), is
///   not before endtime, and the renewable life is within policy (RFC 4120
///   3.1.3, §8.2).
///
/// Spec: RFC 4120 3.1.3, 3.3.3, 5.3, §8.2.
pub(crate) fn check_times(
    policy: &TicketPolicy,
    skew_secs: u32,
    now: i64,
    authtime: &KerberosTime,
    t: &TemplateTimes<'_>,
) -> Internal<()> {
    let bad = Err(Deny::bad_template(AuditReason::TemplateTimes));
    let start = match t.starttime {
        Some(st) => {
            let st = kerberos_time_seconds(st);
            if !within_skew(st, now, skew_secs) {
                return bad;
            }
            st
        }
        None => kerberos_time_seconds(authtime),
    };
    let end = kerberos_time_seconds(t.endtime);
    if end <= now || end <= start {
        return bad;
    }
    let lifetime = end - start;
    if lifetime < i64::from(policy.min_lifetime_secs)
        || lifetime > i64::from(policy.max_lifetime_secs)
    {
        return bad;
    }
    match (t.renewable, t.renew_till) {
        (false, None) => Ok(()),
        (true, Some(renew_till)) => {
            let renew_till = kerberos_time_seconds(renew_till);
            if renew_till < end
                || renew_till - start > i64::from(policy.max_renewable_lifetime_secs)
            {
                return bad;
            }
            Ok(())
        }
        _ => bad,
    }
}

/// The ticket profile of the change-password service (`kadmin/changepw`),
/// enforced by keyd whatever the KDC asks — the flags of the ticket, or
/// `BadTemplate`:
///
/// - no flag requested at all (`TemplateFlags`): never FORWARDABLE,
///   PROXIABLE, RENEWABLE, MAY-POSTDATE or POSTDATED — the realm's policy
///   may allow them for TGTs, the service's profile does not (RFC 4120
///   3.1.3: flags only "if the policy of the local realm allows");
/// - no starttime (`TemplateTimes`): the ticket starts at authtime (RFC 4120
///   5.3) — never postdated;
/// - no renew-till (`TemplateTimes`);
/// - the realm's time rules ([`check_times`]: endtime in the future, the
///   lifetime within the realm's minimum and maximum);
/// - endtime − authtime ≤ [`CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS`]
///   (`TemplateTimes`): "the maximum allowable lifetime associated with the
///   server principal" (RFC 4120 3.1.3).
///
/// The flags are then INITIAL and PRE-AUTHENT — the facts keyd verified
/// ([`as_ticket_flags`] of the empty request): the ticket is issued by the AS
/// after pre-authentication (RFC 4120 2.1: a password-changing service "can
/// insist that this flag be set"; RFC 3244 §2).
///
/// Spec: docs/53 R53-6, §5.2 ("lifetime ≤ 300 s, no renewable, forwardable,
/// proxiable, postdated"; "keyd sets INITIAL and PRE-AUTHENT itself");
/// docs/questions/Q-915 item 4 (A-151); RFC 4120 2.1, 3.1.3, 5.3; RFC 3244
/// §2.
pub(crate) fn change_password_ticket(
    policy: &TicketPolicy,
    skew_secs: u32,
    now: i64,
    authtime: &KerberosTime,
    t: &TemplateTimes<'_>,
    requested: TicketFlags,
) -> Internal<TicketFlags> {
    if requested != TicketFlags::empty() || t.renewable {
        return Err(Deny::bad_template(AuditReason::TemplateFlags));
    }
    if t.starttime.is_some() || t.renew_till.is_some() {
        return Err(Deny::bad_template(AuditReason::TemplateTimes));
    }
    check_times(policy, skew_secs, now, authtime, t)?;
    let lifetime = kerberos_time_seconds(t.endtime) - kerberos_time_seconds(authtime);
    if lifetime > i64::from(CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS) {
        return Err(Deny::bad_template(AuditReason::TemplateTimes));
    }
    as_ticket_flags(policy, TicketFlags::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kt(s: &str) -> KerberosTime {
        // YYYYMMDDHHMMSSZ
        let d = |i: usize| s.as_bytes()[i] - b'0';
        let y =
            u16::from(d(0)) * 1000 + u16::from(d(1)) * 100 + u16::from(d(2)) * 10 + u16::from(d(3));
        KerberosTime::new(
            y,
            d(4) * 10 + d(5),
            d(6) * 10 + d(7),
            d(8) * 10 + d(9),
            d(10) * 10 + d(11),
            d(12) * 10 + d(13),
        )
        .unwrap()
    }

    fn policy() -> TicketPolicy {
        TicketPolicy::default()
    }

    /// RFC 4120 2.1: INITIAL and PRE-AUTHENT are set on AS tickets.
    #[test]
    fn as_flags_add_initial_and_pre_authent() {
        let f = as_ticket_flags(&policy(), TicketFlags::RENEWABLE).unwrap();
        assert!(f.contains(TicketFlags::INITIAL));
        assert!(f.contains(TicketFlags::PRE_AUTHENT));
        assert!(f.contains(TicketFlags::RENEWABLE));
        assert!(as_ticket_flags(&policy(), TicketFlags::FORWARDABLE).is_err());
    }

    /// RFC 4120 2.1: TGS tickets never carry INITIAL; PRE-AUTHENT is carried.
    #[test]
    fn tgs_flags_carry_forward() {
        let tgt = TicketFlags::INITIAL.union(TicketFlags::PRE_AUTHENT);
        let f = tgs_ticket_flags(&policy(), TicketFlags::empty(), tgt).unwrap();
        assert!(f.contains(TicketFlags::PRE_AUTHENT));
        assert!(!f.contains(TicketFlags::INITIAL));
        assert!(tgs_ticket_flags(&policy(), TicketFlags::INITIAL, tgt).is_err());
        // PRE-AUTHENT cannot be claimed if the TGT lacks it.
        assert!(
            tgs_ticket_flags(&policy(), TicketFlags::PRE_AUTHENT, TicketFlags::empty()).is_err()
        );
    }

    /// RFC 4120 5.4.1: FORWARDABLE only from a forwardable TGT.
    #[test]
    fn tgs_forwardable_requires_forwardable_tgt() {
        let mut p = policy();
        p.allowed_flags.insert(TicketFlags::FORWARDABLE);
        assert!(tgs_ticket_flags(&p, TicketFlags::FORWARDABLE, TicketFlags::empty()).is_err());
        assert!(tgs_ticket_flags(&p, TicketFlags::FORWARDABLE, TicketFlags::FORWARDABLE).is_ok());
    }

    #[test]
    fn times_within_policy() {
        let now = kerberos_time_seconds(&kt("20261113100000Z"));
        let auth = kt("20261113100000Z");
        let ok_end = kt("20261113200000Z");
        let t = TemplateTimes {
            starttime: None,
            endtime: &ok_end,
            renew_till: None,
            renewable: false,
        };
        assert!(check_times(&policy(), 300, now, &auth, &t).is_ok());
        // Longer than one day (RFC 4120 §8.2 default max).
        let long_end = kt("20261114100001Z");
        let t = TemplateTimes {
            endtime: &long_end,
            ..t
        };
        assert!(check_times(&policy(), 300, now, &auth, &t).is_err());
        // Shorter than 5 minutes.
        let short_end = kt("20261113100200Z");
        let t = TemplateTimes {
            endtime: &short_end,
            ..t
        };
        assert!(check_times(&policy(), 300, now, &auth, &t).is_err());
        // Postdated start (beyond skew) is refused.
        let future = kt("20261113110000Z");
        let t = TemplateTimes {
            starttime: Some(&future),
            endtime: &ok_end,
            renew_till: None,
            renewable: false,
        };
        assert!(check_times(&policy(), 300, now, &auth, &t).is_err());
        // renew-till requires RENEWABLE and vice versa (RFC 4120 5.3).
        let renew = kt("20261115100000Z");
        let t = TemplateTimes {
            starttime: None,
            endtime: &ok_end,
            renew_till: Some(&renew),
            renewable: false,
        };
        assert!(check_times(&policy(), 300, now, &auth, &t).is_err());
        let t = TemplateTimes {
            renewable: true,
            ..t
        };
        assert!(check_times(&policy(), 300, now, &auth, &t).is_ok());
        let t = TemplateTimes {
            renew_till: None,
            ..t
        };
        assert!(check_times(&policy(), 300, now, &auth, &t).is_err());
    }

    /// docs/53 §5.2 / Q-915 item 4 (the change-password ticket profile);
    /// RFC 4120 2.1 (INITIAL, PRE-AUTHENT), 3.1.3 (the server principal's
    /// maximum lifetime; flags only if policy allows), 5.3 (starttime absent
    /// ⇒ authtime): with a realm policy that allows forwardable, proxiable
    /// and renewable tickets and a one-minute minimum, the profile still
    /// gives exactly INITIAL | PRE-AUTHENT for a request of no flag ending
    /// within 300 s of authtime, and refuses any flag, a starttime, a
    /// renew-till and an endtime beyond authtime + 300 s.
    #[test]
    fn the_change_password_profile() {
        let mut generous = policy();
        generous.allowed_flags = generous
            .allowed_flags
            .union(TicketFlags::FORWARDABLE)
            .union(TicketFlags::PROXIABLE);
        generous.min_lifetime_secs = 60;
        let auth = kt("20261113100000Z");
        let now = kerberos_time_seconds(&auth);
        let end_300 = kt("20261113100500Z");
        let end_301 = kt("20261113100501Z");
        let end_120 = kt("20261113100200Z");
        let times = |endtime| TemplateTimes {
            starttime: None,
            endtime,
            renew_till: None,
            renewable: false,
        };
        for end in [&end_300, &end_120] {
            let flags = change_password_ticket(
                &generous,
                300,
                now,
                &auth,
                &times(end),
                TicketFlags::empty(),
            )
            .unwrap();
            assert_eq!(flags, TicketFlags::INITIAL.union(TicketFlags::PRE_AUTHENT));
        }
        let refused = |t: &TemplateTimes<'_>, flags: TicketFlags| {
            change_password_ticket(&generous, 300, now, &auth, t, flags).is_err()
        };
        assert!(refused(&times(&end_301), TicketFlags::empty()));
        for flag in [
            TicketFlags::FORWARDABLE,
            TicketFlags::PROXIABLE,
            TicketFlags::RENEWABLE,
            TicketFlags::INITIAL,
        ] {
            assert!(refused(&times(&end_300), flag), "{flag:?}");
        }
        let start = kt("20261113100000Z");
        assert!(refused(
            &TemplateTimes {
                starttime: Some(&start),
                ..times(&end_300)
            },
            TicketFlags::empty()
        ));
        let renew = kt("20261113100500Z");
        assert!(refused(
            &TemplateTimes {
                renew_till: Some(&renew),
                ..times(&end_300)
            },
            TicketFlags::empty()
        ));
        assert!(refused(
            &TemplateTimes {
                renewable: true,
                ..times(&end_300)
            },
            TicketFlags::empty()
        ));
        // The realm minimum still applies: 2 minutes under a 5-minute minimum.
        assert!(change_password_ticket(
            &policy(),
            300,
            now,
            &auth,
            &times(&end_120),
            TicketFlags::empty()
        )
        .is_err());
    }

    #[test]
    fn tgs_name_shape() {
        let realm = Realm::new("EXAMPLE.ORG").unwrap();
        let n = tgs_name(&realm);
        assert_eq!(n.name_type, KRB_NT_SRV_INST);
        assert_eq!(n.name_string.len(), 2);
        assert!(is_tgs_name(&n));
    }
}
