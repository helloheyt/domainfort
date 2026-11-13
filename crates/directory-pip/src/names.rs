//! Kerberos name → directory search key (docs/47 §1.3, R47-1).
//!
//! Phase 1 matches exactly: one search key per role, no aliasing, no case
//! folding, no fallback. The AS client is a sAMAccountName (one component);
//! the TGS server is a servicePrincipalName (two or more components joined
//! with "/"). No UPN, no "$" retry, no enterprise name, no
//! canonicalisation; every other shape is "no such principal".
//!
//! Spec: docs/47 §1.3 (R47-1), §1.4 (R47-2); RFC 4120 §6.1, §6.2 ("not
//! significant when checking for equivalence"; names beginning "krbtgt" are
//! reserved for the TGS), §7.3; [MS-KILE] 3.1.5.11 (SPN = serviceclass "/"
//! hostname ...); [MS-SAMR] 2.2.1.14 (DOMAIN_USER_RID_KRBTGT); [MS-DTYP]
//! 2.4.2.4 (KRBTGT = S-1-5-21-<domain>-502); A-27 (Q-070 decision 4); P-6.

use dtyp::Sid;
use krb_proto::PrincipalName;

/// The first component of every TGS name, reserved. Spec: RFC 4120 §6.2,
/// §7.3.
pub(crate) const KRBTGT: &str = "krbtgt";

/// The separator of the SPN string. Spec: [MS-KILE] 3.1.5.11; docs/47 §1.3.
pub(crate) const SPN_SEPARATOR: char = '/';

/// DOMAIN_USER_RID_KRBTGT, "User for Key Distribution Center Service".
/// Spec: [MS-SAMR] 2.2.1.14 (0x000001F6); [MS-DTYP] 2.4.2.4
/// (S-1-5-21-<domain>-502).
pub(crate) const DOMAIN_USER_RID_KRBTGT: u32 = 0x0000_01F6;

/// `true` if `s` is non-empty printable ASCII. Spec: P-6.
fn printable_ascii(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// The sAMAccountName to look up for an AS client name: the single
/// component of `name`, if it has exactly one, is printable ASCII and is
/// not "krbtgt". Otherwise `None` ("no such principal"). The name-type is
/// ignored: a component shaped `x@y` is looked up literally.
///
/// Spec: docs/47 §1.3 AS steps 2 (R47-1); RFC 4120 §6.2; P-6.
pub(crate) fn client_search_key(name: &PrincipalName) -> Option<&str> {
    match name.name_string.as_slice() {
        [only] => {
            let s = only.as_str();
            (printable_ascii(s) && s != KRBTGT).then_some(s)
        }
        _ => None,
    }
}

/// The servicePrincipalName to look up for a TGS server name: the
/// components joined with "/", if there are at least two, none contains
/// "/" (Q-070 item 12: the joined form must name one component list only),
/// every one is printable ASCII and the first is not "krbtgt". Otherwise
/// `None`.
///
/// Spec: docs/47 §1.3 TGS step 2 (R47-1); [MS-KILE] 3.1.5.11; RFC 4120
/// §6.2; Q-070 item 12; P-6.
pub(crate) fn service_search_key(name: &PrincipalName) -> Option<String> {
    let parts = name.name_string.as_slice();
    if parts.len() < 2 {
        return None;
    }
    let mut spn = String::new();
    for (i, part) in parts.iter().enumerate() {
        let s = part.as_str();
        if !printable_ascii(s) || s.contains(SPN_SEPARATOR) || (i == 0 && s == KRBTGT) {
            return None;
        }
        if i > 0 {
            spn.push(SPN_SEPARATOR);
        }
        spn.push_str(s);
    }
    Some(spn)
}

/// `true` if `sid` is the krbtgt account's: its RID (last sub-authority) is
/// DOMAIN_USER_RID_KRBTGT. Read strictly — any SID ending in 502, whatever
/// its domain prefix (Q-136 item 4) — so the krbtgt account is never handed
/// out as a client or a service.
/// Spec: docs/47 §1.3 step 6, §1.4 (R47-2); [MS-SAMR] 2.2.1.14; [MS-DTYP]
/// 2.4.2.4 ("RID: Indicates a unique object ID within the domain").
pub(crate) fn is_krbtgt_sid(sid: &Sid) -> bool {
    sid.sub_authority().last() == Some(&DOMAIN_USER_RID_KRBTGT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb_proto::KerberosString;

    fn name(parts: &[&str]) -> PrincipalName {
        PrincipalName {
            name_type: 1,
            name_string: parts
                .iter()
                .map(|p| KerberosString::new(p).unwrap())
                .collect(),
        }
    }

    /// docs/47 §1.3 AS step 2; RFC 4120 §6.2.
    #[test]
    fn client_keys() {
        assert_eq!(client_search_key(&name(&["alice"])), Some("alice"));
        assert_eq!(
            client_search_key(&name(&["alice@example.test"])),
            Some("alice@example.test")
        );
        assert_eq!(client_search_key(&name(&["krbtgt"])), None);
        assert_eq!(client_search_key(&name(&["a", "b"])), None);
        assert_eq!(client_search_key(&name(&[])), None);
        assert_eq!(client_search_key(&name(&[""])), None);
    }

    /// docs/47 §1.3 TGS step 2; Q-070 item 12.
    #[test]
    fn service_keys() {
        assert_eq!(
            service_search_key(&name(&["host", "ws01.example.test"])).as_deref(),
            Some("host/ws01.example.test")
        );
        assert_eq!(
            service_search_key(&name(&["ldap", "dc01.example.test", "example.test"])).as_deref(),
            Some("ldap/dc01.example.test/example.test")
        );
        assert_eq!(service_search_key(&name(&["ws01$"])), None);
        assert_eq!(service_search_key(&name(&["host/ws01.example.test"])), None);
        assert_eq!(service_search_key(&name(&["host", "a/b"])), None);
        assert_eq!(service_search_key(&name(&["krbtgt", "EXAMPLE.TEST"])), None);
        assert_eq!(service_search_key(&name(&["host", ""])), None);
    }

    /// [MS-SAMR] 2.2.1.14: DOMAIN_USER_RID_KRBTGT = 0x1F6 = 502; [MS-DTYP]
    /// 2.4.2.4 example layout S-1-5-21-1-2-3-<RID>.
    #[test]
    fn krbtgt_rid() {
        let nt = dtyp::SECURITY_NT_AUTHORITY;
        assert_eq!(DOMAIN_USER_RID_KRBTGT, 502);
        assert!(is_krbtgt_sid(&Sid::new(nt, &[21, 1, 2, 3, 502]).unwrap()));
        assert!(!is_krbtgt_sid(&Sid::new(nt, &[21, 1, 2, 3, 500]).unwrap()));
        assert!(!is_krbtgt_sid(&Sid::new(nt, &[]).unwrap()));
    }
}
