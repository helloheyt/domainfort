//! Principal-name rules of the phase-1 KDC: exact equivalence, the TGS name,
//! the change-password service's name, and the service-name string handed to
//! the PDP.
//!
//! Phase 1 does exact matching only (main-session decision 4): realm octets
//! and every name-string component, octet for octet, with the same number of
//! components; the name-type is not significant. No case folding, aliases,
//! enterprise names, referrals or canonicalisation. Names are ASCII
//! (krb-proto enforces the IA5 KerberosString repertoire; P-6).
//!
//! Spec: RFC 4120 6.1 ("realm names are case sensitive"), 6.2 ("It is not
//! significant when checking for equivalence. Principal names that differ only
//! in the name-type identify the same principal"; "Names of any type with an
//! initial component of 'krbtgt' are reserved for the Kerberos
//! ticket-granting service"), 7.3 (name of the TGS); RFC 3244 §2 (the
//! change-password service principal `kadmin/changepw@REALM`); [MS-KILE]
//! 3.3.5.1.2 (that name is never canonicalised); main-session decision 4;
//! A-139 (one name space, one canonicalisation function).

use keyd_types::is_change_password_service_name;
use krb_proto::constants::KRB_NT_SRV_INST;
use krb_proto::{KerberosString, PrincipalName, Realm};

/// The first name component of every TGS principal. Spec: RFC 4120 7.3.
const KRBTGT: &str = "krbtgt";

/// Separator of the service-name string given to the PDP.
const SPN_SEPARATOR: char = '/';

/// `true` if the two name-strings are equivalent: same number of components,
/// each equal octet for octet. The name-type is ignored.
/// Spec: RFC 4120 6.2; main-session decision 4.
pub(crate) fn same_name(a: &PrincipalName, b: &PrincipalName) -> bool {
    a.name_string.len() == b.name_string.len()
        && a.name_string
            .iter()
            .zip(b.name_string.iter())
            .all(|(x, y)| x.as_bytes() == y.as_bytes())
}

/// `true` if the two realms are equal octet for octet (case-sensitive).
/// Spec: RFC 4120 6.1.
pub(crate) fn same_realm(a: &Realm, b: &Realm) -> bool {
    a.as_bytes() == b.as_bytes()
}

/// The principal name of the TGS of `realm`: NT-SRV-INST ("krbtgt", realm).
/// `None` only if "krbtgt" were not a valid KerberosString (it is).
/// Spec: RFC 4120 7.3.
pub(crate) fn tgs_name(realm: &Realm) -> Option<PrincipalName> {
    let first = KerberosString::new(KRBTGT).ok()?;
    Some(PrincipalName {
        name_type: KRB_NT_SRV_INST,
        name_string: vec![first, realm.clone()],
    })
}

/// What a requested server name is, from the point of view of a single-realm
/// phase-1 KDC.
/// Spec: RFC 4120 6.2, 7.3; main-session decision 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerNameKind {
    /// ("krbtgt", this realm): this realm's TGS.
    LocalTgs,
    /// ("krbtgt", X) for any other X, or any other name beginning with
    /// "krbtgt": a TGS of another realm (cross-realm) or a malformed TGS
    /// name.
    ForeignTgs,
    /// `kadmin/changepw`: the change-password service (RFC 3244 §2: "The
    /// AP-REQ message must be for the service principal
    /// kadmin/changepw@REALM"). Recognised by
    /// `keyd_types::is_change_password_service_name` — the one rule keyd
    /// binds that service's key set with and `KeyPurpose::of_service_name`
    /// derives its purpose with — so the KDC has no second matching path for
    /// the name (A-139). Exactly the two components, octet for octet; the
    /// name-type is not significant (RFC 4120 6.2); never canonicalised
    /// ([MS-KILE] 3.3.5.1.2). A ticket for it comes only from an armored AS
    /// (docs/53 §5.2; A-117, A-142).
    ChangePassword,
    /// Any other name: an ordinary service.
    Service,
}

/// Classify `name` against this realm's TGS name and the change-password
/// service's name.
/// Spec: RFC 4120 6.2 ("Names ... with an initial component of 'krbtgt' are
/// reserved"), 7.3; RFC 3244 §2; docs/53 §5.2 (task K5); A-139.
pub(crate) fn classify_server(name: &PrincipalName, realm: &Realm) -> ServerNameKind {
    let mut parts = name.name_string.iter();
    match parts.next() {
        Some(first) if first.as_bytes() == KRBTGT.as_bytes() => {
            match (parts.next(), parts.next()) {
                (Some(instance), None) if same_realm(instance, realm) => ServerNameKind::LocalTgs,
                _ => ServerNameKind::ForeignTgs,
            }
        }
        _ if is_change_password_service_name(name) => ServerNameKind::ChangePassword,
        _ => ServerNameKind::Service,
    }
}

/// The service-name string the PDP matches exactly
/// (`KerbResKind::Service(Spn)`, docs/11 §1): the name-string components
/// joined with "/".
///
/// `None` (the caller fails closed) if a component itself contains "/": the
/// joined string would then also name a different component list, and two
/// distinct principals must never reach the PDP as one resource. There is no
/// escaping scheme. Phase-1 project rule (docs/11 §1 "target SPN"; RFC 4120
/// 6.2 "no two names can be the same").
pub(crate) fn service_spn(name: &PrincipalName) -> Option<String> {
    let mut out = String::new();
    for (i, part) in name.name_string.iter().enumerate() {
        if part.as_str().contains(SPN_SEPARATOR) {
            return None;
        }
        if i > 0 {
            out.push(SPN_SEPARATOR);
        }
        out.push_str(part.as_str());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(name_type: i32, parts: &[&str]) -> PrincipalName {
        PrincipalName {
            name_type,
            name_string: parts
                .iter()
                .map(|p| KerberosString::new(p).unwrap())
                .collect(),
        }
    }

    fn realm(r: &str) -> Realm {
        Realm::new(r).unwrap()
    }

    /// RFC 4120 6.2: the name-type is not significant; components must match
    /// exactly in number and value (no case folding — 6.1 / decision 4).
    #[test]
    fn equivalence_ignores_name_type_only() {
        assert!(same_name(&name(1, &["alice"]), &name(0, &["alice"])));
        assert!(!same_name(&name(1, &["alice"]), &name(1, &["Alice"])));
        assert!(!same_name(&name(1, &["a", "b"]), &name(1, &["a/b"])));
        assert!(!same_name(&name(1, &["a"]), &name(1, &["a", ""])));
        assert!(same_realm(&realm("EXAMPLE.ORG"), &realm("EXAMPLE.ORG")));
        assert!(!same_realm(&realm("EXAMPLE.ORG"), &realm("example.org")));
    }

    /// RFC 4120 7.3: ("krbtgt", REALM) is the local TGS; other "krbtgt"
    /// names are not.
    #[test]
    fn server_classification() {
        let r = realm("EXAMPLE.ORG");
        assert_eq!(
            classify_server(&name(2, &["krbtgt", "EXAMPLE.ORG"]), &r),
            ServerNameKind::LocalTgs
        );
        // Name-type is not significant (6.2).
        assert_eq!(
            classify_server(&name(1, &["krbtgt", "EXAMPLE.ORG"]), &r),
            ServerNameKind::LocalTgs
        );
        assert_eq!(
            classify_server(&name(2, &["krbtgt", "OTHER.ORG"]), &r),
            ServerNameKind::ForeignTgs
        );
        assert_eq!(
            classify_server(&name(2, &["krbtgt", "example.org"]), &r),
            ServerNameKind::ForeignTgs
        );
        assert_eq!(
            classify_server(&name(2, &["krbtgt"]), &r),
            ServerNameKind::ForeignTgs
        );
        assert_eq!(
            classify_server(&name(2, &["krbtgt", "EXAMPLE.ORG", "x"]), &r),
            ServerNameKind::ForeignTgs
        );
        assert_eq!(
            classify_server(&name(3, &["host", "a.example.org"]), &r),
            ServerNameKind::Service
        );
        let tgs = tgs_name(&r).unwrap();
        assert_eq!(tgs.name_type, KRB_NT_SRV_INST);
        assert_eq!(classify_server(&tgs, &r), ServerNameKind::LocalTgs);
    }

    /// RFC 3244 §2 (the service principal `kadmin/changepw@REALM`); RFC 4120
    /// 6.2 (the name-type is not significant; components compare exactly);
    /// [MS-KILE] 3.3.5.1.2 (no canonicalisation of that name); task K5:
    /// exactly the two components `kadmin`, `changepw`, under any name-type,
    /// are the change-password service — no case variant, no third
    /// component, no single joined component.
    #[test]
    fn change_password_service_classification() {
        let r = realm("EXAMPLE.ORG");
        for name_type in [1, 2, 3] {
            assert_eq!(
                classify_server(&name(name_type, &["kadmin", "changepw"]), &r),
                ServerNameKind::ChangePassword
            );
        }
        for parts in [
            &["KADMIN", "changepw"][..],
            &["kadmin", "CHANGEPW"],
            &["kadmin", "changepw", "EXAMPLE.ORG"],
            &["kadmin/changepw"],
            &["kadmin"],
            &["changepw", "kadmin"],
            &["kadmin", "changepw "],
        ] {
            assert_eq!(
                classify_server(&name(2, parts), &r),
                ServerNameKind::Service,
                "{parts:?}"
            );
        }
    }

    /// Project rule: an ambiguous rendering is refused (fail closed).
    #[test]
    fn spn_string_is_unambiguous() {
        assert_eq!(
            service_spn(&name(3, &["host", "a.example.org"])).as_deref(),
            Some("host/a.example.org")
        );
        assert_eq!(service_spn(&name(3, &["host/a.example.org"])), None);
        assert_eq!(service_spn(&name(1, &["svc"])).as_deref(), Some("svc"));
    }
}
