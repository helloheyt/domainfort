//! The rootDSE (docs/49 §5.2, R49-10).
//!
//! # The request
//!
//! A SearchRequest with the empty baseObject and scope baseObject. "When
//! performing a search against the rootDSE, the server will ignore the
//! contents of the search filter" ([MS-ADTS] 3.1.1.3.1.3.6; docs/49 §5.2),
//! so the filter is not evaluated; derefAliases is ignored (no aliases,
//! R49-17); sizeLimit and timeLimit cannot bind a single computed entry.
//! The empty base with another scope is refused by the dispatcher
//! (unwillingToPerform, docs/49 §5.2) — RFC 4512 §5.1: "The root DSE SHALL
//! NOT be included if the client performs a subtree search starting from the
//! root".
//!
//! # Authorization
//!
//! One PDP decision: `Action::DirRead` on `Resource::RootDse` (L2, A-48). An
//! anonymous requester is admitted only by an anonymous-allowlist entry for
//! the rootDSE and the request's source network (docs/15 §6; A-51:
//! internal networks only); an authenticated one needs the read floor
//! (`{encrypted}`). A denial is a SearchResultDone with the code of
//! [`crate::subject::denial_code`] and no entry. On Allow, the obligations
//! are honoured (docs/11 §2): `Audit` is this request's audit event;
//! `RateLimit` goes to the caller's [`crate::RateLimiter`] (refused → busy
//! (51), Q-190 item 4); `Constrain(MaxPageSize(n))` admits the one entry iff
//! `n ≥ 1` (otherwise adminLimitExceeded (11), docs/49 §6.1 item 7).
//!
//! # The attributes (the phase-1 minimum of docs/49 §5.2)
//!
//! | Attribute | Value | Operational? | Source |
//! |---|---|---|---|
//! | namingContexts | the domain NC DN | N | [MS-ADTS] 3.1.1.3.2.13 |
//! | defaultNamingContext | the same DN | N | 3.1.1.3.2.3 |
//! | rootDomainNamingContext | the same DN (one domain) | N | 3.1.1.3.2.16 |
//! | dNSHostName | the DC's DNS name | N | 3.1.1.3.2.4 |
//! | supportedLDAPVersion | `3` only | N | 3.1.1.3.2.23 (AD returns {2,3}; no LDAPv2 here) |
//! | supportedExtension | the StartTLS OID | Y | 3.1.1.3.2.33, 3.1.1.3.4.2 |
//!
//! Absent, because there is nothing to list: supportedSASLMechanisms (no
//! mechanism until task L7 — RFC 4512 §5.1.7: "If the server does not
//! support any SASL mechanisms, this attribute will not be present") and
//! supportedControl (no control, R49-8 — RFC 4512 §5.1.3: "If the server
//! does not support any request controls, this attribute will be absent").
//! Everything else of [MS-ADTS] 3.1.1.3.2 is outside phase 1 (docs/49 §5.2).
//!
//! The "Operational?" column is [MS-ADTS] 3.1.1.3.2's ("whether the server
//! returns the attribute only when it is explicitly requested"). Selection
//! follows RFC 4511 §4.5.1.8: an empty list or `*` asks for every
//! non-operational attribute; a listed name asks for that attribute; `1.1`
//! alone asks for none; each attribute is returned at most once; an
//! unrecognised description is ignored. RFC 4512 §5.1 instead calls every
//! root DSE attribute operational; following [MS-ADTS] discloses nothing
//! more (any requester can name each attribute) — recorded as
//! docs/questions/Q-190 item 5. Names are matched case-insensitively
//! (RFC 4512 §2.5); a description with options or a numeric OID matches
//! nothing ([MS-ADTS] 3.1.1.3.1.3.6: rootDSE attributes "MUST be specified
//! by their LDAP display name"; RFC 4512 §2.5: an unrecognised option makes
//! the description unrecognised). `typesOnly` returns the descriptions with
//! no values (RFC 4511 §4.5.1.6). The entry's objectName is the empty DN
//! (RFC 4512 §5.1: "named with the DN with zero RDNs").
//!
//! The values carry no secret and no directory data beyond configuration;
//! the rootDSE has no Secret attribute (docs/49 §6.5).
//!
//! Value representations: Object(DS-DN) as the DN string (the naming
//! context's RFC 4514 encoding — one source of truth with the directory,
//! A-53, crate::config), String(Unicode) as UTF-8, Integer as its decimal
//! string, String(Object-Identifier) as the numeric OID ([MS-ADTS]
//! 3.1.1.2.2.2 → RFC 4517 §3.3.16 for Integer).
//!
//! Spec: [MS-ADTS] v20261026 3.1.1.2.2.2, 3.1.1.3, 3.1.1.3.1.3.6, 3.1.1.3.2
//! (table; .3, .4, .13, .16, .21, .23, .24, .33), 3.1.1.3.4.2; RFC 4511
//! §4.5.1.6, §4.5.1.8, §4.5.2; RFC 4512 §2.5, §5.1; RFC 4513 §5.2.1.5
//! (supportedSASLMechanisms readable by anonymous clients); RFC 4517
//! §3.3.16; docs/49 §5.2 (R49-10), §6.5; docs/11 §2, §8.

use parse_ldap::{PartialAttribute, SearchResultEntry, START_TLS_OID};

use crate::config::RootDseValues;

/// The LDAP version advertised, as an Integer value (decimal digits).
/// Spec: [MS-ADTS] 3.1.1.3.2.23; RFC 4517 §3.3.16; R49-17 (no LDAPv2).
const SUPPORTED_LDAP_VERSION: &str = "3";

/// The `*` selector: "all user attributes". Spec: RFC 4511 §4.5.1.8.
const ALL_USER_ATTRIBUTES: &str = "*";

/// One phase-1 rootDSE attribute (module documentation table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attribute {
    NamingContexts,
    DefaultNamingContext,
    RootDomainNamingContext,
    DnsHostName,
    SupportedLdapVersion,
    SupportedExtension,
}

impl Attribute {
    /// Every attribute, in the order they are returned.
    const ALL: [Attribute; 6] = [
        Attribute::NamingContexts,
        Attribute::DefaultNamingContext,
        Attribute::RootDomainNamingContext,
        Attribute::DnsHostName,
        Attribute::SupportedLdapVersion,
        Attribute::SupportedExtension,
    ];

    /// The LDAP display name. Spec: [MS-ADTS] 3.1.1.3.2 (section titles).
    const fn name(self) -> &'static str {
        match self {
            Attribute::NamingContexts => "namingContexts",
            Attribute::DefaultNamingContext => "defaultNamingContext",
            Attribute::RootDomainNamingContext => "rootDomainNamingContext",
            Attribute::DnsHostName => "dNSHostName",
            Attribute::SupportedLdapVersion => "supportedLDAPVersion",
            Attribute::SupportedExtension => "supportedExtension",
        }
    }

    /// Returned only when requested by name. Spec: [MS-ADTS] 3.1.1.3.2 (the
    /// "Operational?" column).
    const fn operational(self) -> bool {
        matches!(self, Attribute::SupportedExtension)
    }

    /// The values. Spec: module documentation table.
    fn values(self, config: &RootDseValues) -> Vec<Vec<u8>> {
        let value = match self {
            Attribute::NamingContexts
            | Attribute::DefaultNamingContext
            | Attribute::RootDomainNamingContext => config.naming_context.as_str(),
            Attribute::DnsHostName => config.dns_host_name.as_str(),
            Attribute::SupportedLdapVersion => SUPPORTED_LDAP_VERSION,
            Attribute::SupportedExtension => START_TLS_OID,
        };
        vec![value.as_bytes().to_vec()]
    }

    /// Whether the selection asks for this attribute (module documentation).
    /// Spec: RFC 4511 §4.5.1.8; RFC 4512 §2.5; [MS-ADTS] 3.1.1.3.1.3.6.
    fn selected(self, selection: &[String]) -> bool {
        let all_user = selection.is_empty() || selection.iter().any(|s| s == ALL_USER_ATTRIBUTES);
        let by_name = selection
            .iter()
            .any(|s| s.eq_ignore_ascii_case(self.name()));
        (all_user && !self.operational()) || by_name
    }
}

/// The rootDSE entry for `selection`. The `1.1` selector ("no attributes",
/// RFC 4511 §4.5.1.8) needs no special case: it is neither the empty list,
/// nor `*`, nor an attribute name, so alone it selects nothing and beside
/// other selectors it is ignored. Spec: module documentation.
pub(crate) fn entry(
    config: &RootDseValues,
    selection: &[String],
    types_only: bool,
) -> SearchResultEntry {
    let attributes = Attribute::ALL
        .iter()
        .filter(|a| a.selected(selection))
        .map(|a| PartialAttribute {
            r#type: a.name().to_owned(),
            vals: if types_only {
                Vec::new()
            } else {
                a.values(config)
            },
        })
        .collect();
    SearchResultEntry {
        // "named with the DN with zero RDNs". Spec: RFC 4512 §5.1.
        object_name: String::new(),
        attributes,
    }
}
