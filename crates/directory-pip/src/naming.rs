//! The DN of the domain naming context's root: configuration (A-53).
//!
//! # The decision: configured explicitly, cross-checked with the realm
//!
//! [MS-ADTS] 3.1.1.1.4: "The DN of a child object is the RDN of the child,
//! followed by "," and the DN of the parent", while "The DN of the root has
//! an assigned value" — the root's DN is not computed from the root object's
//! own RDN. 3.1.1.1.5 gives the form of that assigned value for a domain NC,
//! "dc=n1,dc=n2, ... dc=nk", which "corresponds to the DNS name n1.n2. ...
//! .nk". In this project the NC root is ONE dirstore object with no parent
//! and a single `dc` value (Q-195, residual found in L5), so its assigned DN
//! is configuration of the directory: a [`NamingContext`] built from the
//! labels n1 … nk.
//!
//! It is configured explicitly, not derived from the realm: the realm is the
//! DNS name "converted to uppercase" (docs/47 §3.3 item 3), so the case of
//! the labels is gone from it, and the DN — which `dn_of` emits and the PDP
//! compares exactly (R49-11) — needs one spelling. The realm is still
//! checked against it: [`crate::DirectoryContext::new`] refuses a naming
//! context whose DNS name (3.1.1.1.5), upper-cased, is not the realm octet
//! for octet (fail closed on a misconfiguration).
//!
//! # The one source of truth
//!
//! The same value is the suffix `dn_of` appends for every object of the NC
//! (the root maps to exactly this DN), the suffix DN resolution strips before
//! walking the name index, and — through the LDAP engine's configuration —
//! the rootDSE's namingContexts / defaultNamingContext /
//! rootDomainNamingContext (docs/49 §5.2); the engine refuses to search a
//! view whose naming context differs from its own.
//!
//! # Label rules
//!
//! Each label is non-empty printable ASCII (P-6, Q-080: phase-1 names are
//! ASCII), holds no "." (the label separator of the corresponding DNS name,
//! 3.1.1.1.5), and `dc=<label>` is under 255 characters ([MS-ADTS]
//! 3.1.1.5.1.2, read as `att=val` — Q-090 / A-30). The DNS label syntax of
//! [RFC1034] that 3.1.1.1.5 cites is not checked (RFC 1034 is not pinned):
//! docs/questions/Q-200 item 1.
//!
//! Spec: [MS-ADTS] v20261026 3.1.1.1.4, 3.1.1.1.5, 3.1.1.3.1.2.2,
//! 3.1.1.5.1.2; docs/47 §3.3 item 3; docs/49 §5.2, §7; A-53 (Q-195); Q-080;
//! Q-090.

use crate::error::ViewError;
use pdp::Dn;

/// The lDAPDisplayName of the RDN attribute of every component of a domain
/// NC's DN. Spec: [MS-ADTS] 3.1.1.1.5 ("dc=n1,dc=n2, ... dc=nk"),
/// 3.1.1.3.1.2.2 ("The rDNAttID for the domainDNS class is dc").
pub const NC_RDN_ATTRIBUTE: &str = "dc";

/// Most labels in the naming context's DN (project choice): every object's
/// DN, NC suffix included, is bounded by [`crate::MAX_DN_DEPTH`], so the
/// suffix may use only part of that depth. Spec: docs/CLEAN-ROOM.md (bounds);
/// docs/49 §2.4.
pub const MAX_NC_LABELS: usize = 16;

/// The separator of the labels of the DNS name a domain NC's DN corresponds
/// to. Spec: [MS-ADTS] 3.1.1.1.5 ("n1.n2. ... .nk").
const LABEL_SEPARATOR: char = '.';

/// "The RDN size MUST be less than 255 characters" — `att=val` counted
/// whole (Q-090 / A-30). Spec: [MS-ADTS] 3.1.1.5.1.2.
const RDN_SIZE_LIMIT: usize = 255;

/// The DN of the domain NC's root (module documentation).
/// Spec: [MS-ADTS] 3.1.1.1.4, 3.1.1.1.5; A-53.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamingContext {
    /// n1 … nk, leaf first, exactly as configured.
    labels: Vec<String>,
    /// `dc=n1`, …, `dc=nk`: the directory's canonical DN components (the
    /// form of `DirectoryView::dn_of`), leaf first.
    dn: Dn,
}

impl NamingContext {
    /// The naming context `dc=n1,…,dc=nk` for the labels n1 … nk (leaf
    /// first), checked by the label rules of the module documentation.
    /// Spec: [MS-ADTS] 3.1.1.1.5, 3.1.1.5.1.2; Q-080; Q-090.
    pub fn new<S: AsRef<str>>(labels: &[S]) -> Result<NamingContext, ViewError> {
        if labels.is_empty() || labels.len() > MAX_NC_LABELS {
            return Err(ViewError::NamingContext);
        }
        let mut kept = Vec::with_capacity(labels.len());
        let mut rdns = Vec::with_capacity(labels.len());
        for label in labels {
            let label = label.as_ref();
            let printable = label.bytes().all(|b| (0x20..=0x7E).contains(&b));
            // "dc" + "=" + label < 255 characters (ASCII: octets = characters).
            let fits = NC_RDN_ATTRIBUTE.len() + 1 + label.len() < RDN_SIZE_LIMIT;
            if label.is_empty() || !printable || label.contains(LABEL_SEPARATOR) || !fits {
                return Err(ViewError::NamingContext);
            }
            kept.push(label.to_owned());
            rdns.push(format!("{NC_RDN_ATTRIBUTE}={label}"));
        }
        Ok(NamingContext {
            labels: kept,
            dn: Dn::new(rdns),
        })
    }

    /// n1 … nk, leaf first.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// The DN in the directory's canonical form (`dc=n1`, …, leaf first) —
    /// the suffix of every DN of the NC, and the DN of the NC root.
    /// Spec: [MS-ADTS] 3.1.1.1.4; A-53.
    #[must_use]
    pub fn dn(&self) -> &Dn {
        &self.dn
    }

    /// The DNS name the DN corresponds to, `n1.n2. … .nk`.
    /// Spec: [MS-ADTS] 3.1.1.1.5.
    #[must_use]
    pub fn dns_name(&self) -> String {
        self.labels.join(".")
    }

    /// The label of the NC root object itself (n1): the value of its `dc`
    /// RDN attribute ([MS-ADTS] 3.1.1.1.4 example: `(dc "microsoft")` for
    /// "dc=microsoft,dc=com").
    pub(crate) fn root_label(&self) -> Option<&str> {
        self.labels.first().map(String::as_str)
    }

    /// `true` if `realm` is this NC's DNS name in upper case, octet for
    /// octet. Spec: docs/47 §3.3 item 3 (the realm is the DNS name
    /// "converted to uppercase"); [MS-ADTS] 3.1.1.1.5.
    pub(crate) fn names_realm(&self, realm: &[u8]) -> bool {
        self.dns_name().to_ascii_uppercase().as_bytes() == realm
    }
}
