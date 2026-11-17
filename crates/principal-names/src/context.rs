//! The realm's names in the namespace: its alias set.
//!
//! # Phase 1: exactly one alias
//!
//! The alias set is the realm's DNS name — the DNS name of the domain NC
//! (A-53), whose upper case is the realm (docs/47 §3.3 item 3; R47-4).
//! Whether the domain's flat (NetBIOS) name and further userPrincipalName
//! suffixes may join it is the owner's decision P-84 (docs/questions/Q-1012,
//! A-173: "Until then: neither alias is built"). So a [`NameContext`] holds
//! exactly one alias, by construction: a second alias cannot be represented
//! until that decision changes this type (task PN15).
//!
//! # Compared folded
//!
//! A realm in a request and a userPrincipalName's suffix are compared with
//! the alias after the namespace fold ([MS-KILE] 3.1.5.7: "Name
//! comparisons, whether for users or domains, MUST NOT be case sensitive").
//! This deviates from RFC 4120 §6.1 ("Kerberos realm names are case
//! sensitive"), as docs/59 §4.2 records; the phase-1 acceptance keeps the
//! realm octet for octet on top of this (docs/59 §6.3, task PN4).
//!
//! # The alias's form
//!
//! RFC 4120 §6.1: "Domain style realm names MUST look like domain names:
//! they consist of components separated by periods (.) and they contain
//! neither colons (:) nor slashes (/)." The alias must also hold no "@" —
//! the separator of a userPrincipalName's suffix (docs/59 §4.2) — and must
//! not be "krbtgt", the TGS's reserved name (RFC 4120 §6.2), since it
//! becomes a key of the krbtgt account (docs/59 §4.4 N5).
//!
//! Spec: docs/59 §4.2 (`NameContext`), §4.4 N5, §4.5; docs/questions/Q-1007
//! item 9, Q-1012 (P-84); A-53; [MS-KILE] 3.1.5.7; RFC 4120 §6.1, §6.2, §7.3.

use crate::error::NameRefused;
use crate::key::{folded_eq, PrincipalKey};
use crate::reserved::TGS_NAME;

/// The label separator of a domain-style realm name. Spec: RFC 4120 §6.1.
const LABEL_SEPARATOR: char = '.';

/// Octets a domain-style realm name contains none of (RFC 4120 §6.1: ":"
/// and "/"), plus "@", the userPrincipalName suffix separator (docs/59
/// §4.2).
const REALM_FORBIDDEN: [char; 3] = [':', '/', '@'];

/// The realm's alias set (module documentation).
/// Spec: docs/59 §4.2; Q-1012 (P-84).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameContext {
    /// The realm's DNS name, folded: the one alias of phase 1.
    realm_dns_name: PrincipalKey,
}

impl NameContext {
    /// The context of the realm whose DNS name is `realm_dns_name` (the
    /// domain NC's DNS name, A-53), checked by the rules of the module
    /// documentation; [`NameRefused::RealmName`] or
    /// [`NameRefused::Reserved`] otherwise.
    /// Spec: RFC 4120 §6.1, §6.2; A-53; docs/59 §4.2, §4.4 N5.
    pub fn new(realm_dns_name: &str) -> Result<NameContext, NameRefused> {
        let labels_ok = realm_dns_name
            .split(LABEL_SEPARATOR)
            .all(|label| !label.is_empty());
        if !labels_ok || realm_dns_name.contains(REALM_FORBIDDEN) {
            return Err(NameRefused::RealmName);
        }
        let realm_dns_name =
            PrincipalKey::of_components(&[realm_dns_name]).map_err(|_| NameRefused::RealmName)?;
        if folded_eq(realm_dns_name.as_str(), TGS_NAME) {
            return Err(NameRefused::Reserved);
        }
        Ok(NameContext { realm_dns_name })
    }

    /// `true` if `name` is a realm alias, compared after the fold.
    /// Spec: [MS-KILE] 3.1.5.7; docs/59 §4.2.
    #[must_use]
    pub fn is_realm_alias(&self, name: &str) -> bool {
        folded_eq(self.realm_dns_name.as_str(), name)
    }

    /// `true` if `key` is a realm alias's key. Spec: docs/59 §4.4 N5.
    pub(crate) fn is_alias_key(&self, key: &PrincipalKey) -> bool {
        *key == self.realm_dns_name
    }

    /// The realm aliases' keys (exactly one in phase 1: the realm's DNS
    /// name). Spec: docs/59 §4.2, §4.3 (`RealmAlias` keys of the krbtgt
    /// account); Q-1012.
    pub fn realm_aliases(&self) -> impl Iterator<Item = &PrincipalKey> {
        core::iter::once(&self.realm_dns_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4120 §6.1 (domain style, examples "ATHENA.MIT.EDU"); [MS-KILE]
    /// 3.1.5.7 (not case sensitive); Q-1012 (one alias).
    #[test]
    fn the_alias_is_the_realm_dns_name_compared_folded() {
        let ctx = NameContext::new("athena.mit.edu").unwrap();
        assert!(ctx.is_realm_alias("ATHENA.MIT.EDU"));
        assert!(ctx.is_realm_alias("athena.mit.edu"));
        assert!(!ctx.is_realm_alias("MIT.EDU"));
        assert!(!ctx.is_realm_alias("ATHENA"));
        assert_eq!(
            ctx.realm_aliases()
                .map(PrincipalKey::as_str)
                .collect::<Vec<_>>(),
            ["athena.mit.edu"]
        );
        assert_eq!(
            NameContext::new("ATHENA.MIT.EDU").unwrap(),
            NameContext::new("athena.mit.edu").unwrap()
        );
    }

    /// RFC 4120 §6.1 (no ":" or "/", components separated by periods);
    /// docs/59 §4.2 (no "@"); RFC 4120 §6.2 (krbtgt reserved).
    #[test]
    fn malformed_realm_names_are_refused() {
        for bad in [
            "",
            ".",
            "a..b",
            ".a",
            "a.",
            "a:b",
            "a/b",
            "a@b",
            "caf\u{e9}",
            "a\tb",
        ] {
            assert_eq!(
                NameContext::new(bad),
                Err(NameRefused::RealmName),
                "{bad:?}"
            );
        }
        assert_eq!(NameContext::new("KRBTGT"), Err(NameRefused::Reserved));
        assert_eq!(
            NameContext::new(&"a".repeat(2049)),
            Err(NameRefused::RealmName)
        );
    }
}
