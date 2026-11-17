//! The reserved names, judged on the folded form (class C49, docs/59 §3
//! M3; decided A-173 on docs/questions/Q-1009 items 1-2).
//!
//! Before this crate, the reservation of the TGS's name, the admin
//! service's name and the change-password service's name compared octets
//! (`KRBTGT/…`, `ADMIND/…`, `KADMIN/changepw` were "not reserved") while the
//! namespace compares folded names — so "the same name" for one component
//! was another name for the next. Here each reservation is one predicate on
//! a [`PrincipalKey`], which is folded by construction, so every spelling of
//! a reserved name is reserved.
//!
//! The NAMES stay defined where they are: `keyd_types::ADMIN_SERVICE_CLASS`
//! (A-73) and `krb_proto::CHANGE_PASSWORD_SERVICE_NAME` (RFC 3244 §2); this
//! module defines only the EQUIVALENCE to them (docs/59 §4.2). Which object
//! may carry a reserved name — the provisioning claim that owns it, A-163's
//! `claim_of_reserved_purpose` — stays in crates/directory-admin; this module
//! names no key-set purpose (crates/keyd-types
//! tests/one_service_purpose_derivation.rs).
//!
//! The change-password reservation is the exact two-component name only:
//! Q-1009 item 7 (whether every `kadmin/…` name is reserved) is not decided,
//! and no allowed source defines another `kadmin/` service.
//!
//! Spec: RFC 4120 §6.2 ("Names of any type with an initial component of
//! 'krbtgt' are reserved for the Kerberos ticket-granting service"), §7.3;
//! RFC 3244 §2 ("the service principal kadmin/changepw@REALM"); A-73; A-163;
//! docs/59 §4.2 (the reserved-name predicates), §3 M3; Q-1009 items 1-2, 7.

use crate::key::{folded_eq, PrincipalKey};
use keyd_types::ADMIN_SERVICE_CLASS;
use krb_proto::CHANGE_PASSWORD_SERVICE_NAME;

/// The initial component of the ticket-granting service's name.
/// Spec: RFC 4120 §6.2, §7.3 ("a two-part name of type NT-SRV-INST, with
/// the first part "krbtgt"").
pub(crate) const TGS_NAME: &str = "krbtgt";

/// A reserved name a key spells, in any case.
/// Spec: docs/59 §4.2; Q-1009 items 1-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReservedName {
    /// A name whose initial component is "krbtgt" (any number of
    /// components). Spec: RFC 4120 §6.2, §7.3.
    TicketGrantingService,
    /// A two-component name whose first component is the admin service's
    /// class (`admind/<host>`). Spec: A-73; crates/keyd-types
    /// `is_admin_service_name` (the same shape, octet for octet there).
    AdminService,
    /// The change-password service's name, `kadmin/changepw`.
    /// Spec: RFC 3244 §2; crates/krb-proto `is_change_password_service_name`
    /// (the same name, octet for octet there).
    ChangePasswordService,
}

/// The reserved name `key` spells, if any (module documentation).
/// Spec: RFC 4120 §6.2, §7.3; RFC 3244 §2; A-73; Q-1009 items 1-2.
#[must_use]
pub fn reserved_name_of(key: &PrincipalKey) -> Option<ReservedName> {
    if is_tgs_name(key.first_component()) {
        return Some(ReservedName::TicketGrantingService);
    }
    let mut components = key.components();
    let (Some(first), Some(second), None) =
        (components.next(), components.next(), components.next())
    else {
        return None;
    };
    if folded_eq(first, ADMIN_SERVICE_CLASS) {
        return Some(ReservedName::AdminService);
    }
    let [service, instance] = CHANGE_PASSWORD_SERVICE_NAME;
    if folded_eq(first, service) && folded_eq(second, instance) {
        return Some(ReservedName::ChangePasswordService);
    }
    None
}

/// `true` if the (already folded) component is the TGS's reserved initial
/// component. Spec: RFC 4120 §6.2.
pub(crate) fn is_tgs_name(folded_component: &str) -> bool {
    folded_eq(folded_component, TGS_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(parts: &[&str]) -> PrincipalKey {
        PrincipalKey::of_components(parts).unwrap()
    }

    /// Q-1009 items 1-2 (the case variants the octet compare let through:
    /// `KRBTGT/…`, `ADMIND/…`, `KADMIN/changepw`); RFC 4120 §6.2; RFC 3244 §2;
    /// A-73; item 7 undecided ⇒ `kadmin/<host>` is not reserved.
    #[test]
    fn reserved_names_in_any_case() {
        use ReservedName::*;
        assert_eq!(
            reserved_name_of(&key(&["krbtgt"])),
            Some(TicketGrantingService)
        );
        assert_eq!(
            reserved_name_of(&key(&["KRBTGT", "ws01.example.test"])),
            Some(TicketGrantingService)
        );
        assert_eq!(
            reserved_name_of(&key(&["KrbTgt", "a", "b"])),
            Some(TicketGrantingService)
        );
        assert_eq!(
            reserved_name_of(&key(&["ADMIND", "ws01.example.test"])),
            Some(AdminService)
        );
        assert_eq!(
            reserved_name_of(&key(&["admind", "dc01.example.test"])),
            Some(AdminService)
        );
        assert_eq!(
            reserved_name_of(&key(&["KADMIN", "changepw"])),
            Some(ChangePasswordService)
        );
        assert_eq!(
            reserved_name_of(&key(&["kadmin", "CHANGEPW"])),
            Some(ChangePasswordService)
        );
        assert_eq!(
            reserved_name_of(&key(&["kadmin", "ws01.example.test"])),
            None
        );
        assert_eq!(reserved_name_of(&key(&["kadmin", "changepw", "x"])), None);
        assert_eq!(reserved_name_of(&key(&["admind", "a", "b"])), None);
        assert_eq!(reserved_name_of(&key(&["admind"])), None);
        assert_eq!(reserved_name_of(&key(&["krbtgt$"])), None);
        assert_eq!(reserved_name_of(&key(&["host", "krbtgt"])), None);
        assert_eq!(reserved_name_of(&key(&["ldap", "dc01.example.test"])), None);
    }
}
