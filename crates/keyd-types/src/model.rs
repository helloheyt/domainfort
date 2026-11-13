//! The object model: principals, key version numbers, key purposes and key
//! handles.
//!
//! A [`KeyHandle`] names a stored key set — never the key material itself.
//! Spec: docs/10 §1 (object model); docs/09 א.5 ("references to keys are
//! handles, not keys").

use core::fmt;
use krb_proto::{PrincipalName, Realm};

/// Stable identity of a principal: a 16-octet identifier assigned by the
/// directory (docs/10 §1 `type PrincipalId = Guid`).
///
/// Not secret. `Debug` prints it as hex.
/// Spec: docs/10 §1.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PrincipalId([u8; 16]);

impl PrincipalId {
    /// Wrap a 16-octet identifier. Spec: docs/10 §1.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        PrincipalId(bytes)
    }

    /// The identifier octets.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrincipalId(")?;
        for octet in &self.0 {
            write!(f, "{octet:02x}")?;
        }
        f.write_str(")")
    }
}

/// Key version number (`kvno`, RFC 4120 5.2.9 `UInt32`).
///
/// Spec: RFC 4120 5.2.9 (kvno "contains the version number of the key under
/// which data is encrypted"); docs/10 §1 (`type Kvno = u32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Kvno(u32);

impl Kvno {
    /// The first key version keyd assigns to a newly created key set — by
    /// `create_key`, or by `set_secret` when it creates the set (also after
    /// `destroy_key_set`).
    /// Spec: docs/10 §6, §7 (create_key returns the new kvno);
    /// docs/questions/Q-115 (A-35: keyd chooses the kvno). The value is this
    /// project's choice; RFC 4120 does not fix an initial kvno.
    pub const INITIAL: Kvno = Kvno(1);

    /// Wrap a kvno value. Spec: RFC 4120 5.2.9.
    pub const fn new(value: u32) -> Self {
        Kvno(value)
    }

    /// The kvno value.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The next kvno, or `None` when the UInt32 range is exhausted (fail
    /// closed: keyd never wraps a kvno back to an old value).
    /// Spec: RFC 4120 5.2.9 (UInt32); docs/10 §1 (rotation keeps current +
    /// previous).
    pub const fn next(self) -> Option<Kvno> {
        match self.0.checked_add(1) {
            Some(v) => Some(Kvno(v)),
            None => None,
        }
    }
}

/// What a stored key is for. Key separation by purpose is enforced: a key
/// tagged for one purpose is usable only by the operations of that purpose
/// (invariant I3).
///
/// Phase 1 implements exactly these three purposes. The other purposes of
/// docs/10 §1 (GKDI root, backup key, DC identity) are out of scope and have
/// no variant.
///
/// Spec: docs/10 §1 (KeyPurpose), §2, §12 I3; docs/09 א.3 (2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum KeyPurpose {
    /// A user or computer long-term key. Spec: docs/10 §1.
    PrincipalLongterm = 0,
    /// The ticket-granting service key (krbtgt). Spec: docs/10 §1; RFC 4120
    /// 7.3 (name of the TGS).
    Krbtgt = 1,
    /// A service long-term key (key a service ticket is sealed under).
    /// Spec: docs/10 §1; RFC 4120 5.3 ("the server's secret key").
    Service = 2,
}

/// A reference to a stored key set — never the key material.
///
/// Spec: docs/10 §1 (`struct KeyHandle { principal, purpose }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyHandle {
    /// The principal the key set belongs to.
    pub principal: PrincipalId,
    /// The purpose the key set is tagged with.
    pub purpose: KeyPurpose,
}

impl KeyHandle {
    /// Build a handle. Spec: docs/10 §1.
    pub const fn new(principal: PrincipalId, purpose: KeyPurpose) -> Self {
        KeyHandle { principal, purpose }
    }
}

/// The Kerberos principal name a key set is bound to: realm plus
/// PrincipalName. Fixed when the key set is created (by `create_key`, or by
/// `set_secret` when it creates the set) and never changed afterwards —
/// phase 1 has no rename; a renamed principal is a new key set.
///
/// keyd refuses to put a name in a ticket, or to seal a ticket for a name,
/// that is not the name the key is bound to. Phase 1 has no PAC, so the
/// cname IS the identity; without this binding a compromised KDC holding one
/// user's password could mint a TGT for any cname, or seal a ticket for
/// service S under service X's key (docs/questions/Q-040, decided A-19).
///
/// Not secret.
///
/// Spec: docs/10 §1, §4, §5; docs/25 §3.2 (keyd is a PEP); RFC 4120 6.1,
/// 6.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalBinding {
    /// The principal's realm.
    pub realm: Realm,
    /// The principal's name.
    pub name: PrincipalName,
}

impl PrincipalBinding {
    /// Build a binding. Spec: RFC 4120 5.2.2 (Realm, PrincipalName).
    pub fn new(realm: Realm, name: PrincipalName) -> Self {
        PrincipalBinding { realm, name }
    }

    /// `true` if (`realm`, `name`) identifies the bound principal.
    ///
    /// The realm octets and every name-string component are compared
    /// exactly, octet for octet, and the number of components must agree.
    /// The name-type is NOT compared: RFC 4120 6.2 — "The name-type SHOULD be
    /// treated only as a hint ... It is not significant when checking for
    /// equivalence. Principal names that differ only in the name-type
    /// identify the same principal." keyd does no case folding (RFC 4120 6.1:
    /// realm names "are case sensitive"), no aliasing and no enterprise-name
    /// handling; canonicalization is the KDC's job before it calls keyd. (The
    /// 6.2 rule that a principal *authenticated* with name-type UNKNOWN
    /// matches only UNKNOWN names concerns matching an authenticated name
    /// against others, e.g. in access-control lists — not the equivalence of
    /// two names checked here.)
    ///
    /// Names are not secret, so an ordinary comparison is used.
    ///
    /// Spec: RFC 4120 6.1, 6.2.
    pub fn matches(&self, realm: &Realm, name: &PrincipalName) -> bool {
        self.realm.as_bytes() == realm.as_bytes()
            && self.name.name_string.len() == name.name_string.len()
            && self
                .name
                .name_string
                .iter()
                .zip(name.name_string.iter())
                .all(|(a, b)| a.as_bytes() == b.as_bytes())
    }
}

/// The dual-control approval that `rotate_krbtgt` requires: two approver
/// identities.
///
/// keyd verifies only that the two approvers are DISTINCT. Whether each
/// approval is authentic (signed, fresh, from an authorized tier-0 approver)
/// is the admin plane's job (docs/43 D175, docs/07 D21) — a documented
/// residual: keyd trusts the Admin caller to have verified the approvals.
///
/// Spec: docs/10 §7 ("rotate_krbtgt באישור כפול"); docs/43 D175.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualControlToken {
    /// First approver.
    pub approver_1: PrincipalId,
    /// Second approver; must differ from the first.
    pub approver_2: PrincipalId,
}

impl DualControlToken {
    /// `true` if the two approvers are distinct (the only check keyd makes).
    /// Spec: docs/10 §7; docs/43 D175.
    pub fn has_distinct_approvers(&self) -> bool {
        self.approver_1 != self.approver_2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb_proto::KerberosString;

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

    /// RFC 4120 6.2: name-type is not significant for equivalence; realm
    /// (case-sensitive, 6.1) and every component must agree exactly.
    #[test]
    fn binding_equivalence_follows_rfc4120_6_2() {
        let b = PrincipalBinding::new(
            realm("EXAMPLE.ORG"),
            name(3, &["host", "files.example.org"]),
        );
        assert!(b.matches(
            &realm("EXAMPLE.ORG"),
            &name(3, &["host", "files.example.org"])
        ));
        // Name-type only: same principal.
        assert!(b.matches(
            &realm("EXAMPLE.ORG"),
            &name(0, &["host", "files.example.org"])
        ));
        assert!(b.matches(
            &realm("EXAMPLE.ORG"),
            &name(1, &["host", "files.example.org"])
        ));
        // Realm case differs: not equivalent (6.1).
        assert!(!b.matches(
            &realm("example.org"),
            &name(3, &["host", "files.example.org"])
        ));
        // Component case, value or count differs.
        assert!(!b.matches(
            &realm("EXAMPLE.ORG"),
            &name(3, &["HOST", "files.example.org"])
        ));
        assert!(!b.matches(
            &realm("EXAMPLE.ORG"),
            &name(3, &["host", "other.example.org"])
        ));
        assert!(!b.matches(&realm("EXAMPLE.ORG"), &name(3, &["host"])));
        assert!(!b.matches(
            &realm("EXAMPLE.ORG"),
            &name(3, &["host", "files.example.org", "x"])
        ));
        // Joining components differently is a different name.
        assert!(!b.matches(&realm("EXAMPLE.ORG"), &name(3, &["host/files.example.org"])));
    }
}
