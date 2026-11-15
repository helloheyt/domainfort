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
/// Phase 1 implements exactly these five purposes. The other purposes of
/// docs/10 §1 (GKDI root, backup key, DC identity) are out of scope and have
/// no variant.
///
/// Spec: docs/10 §1 (KeyPurpose), §2, §12 I3; docs/09 א.3 (2); docs/52 §3.2,
/// §5 item 3 (R2, the admin service's own purpose; A-102); docs/53 §4.5,
/// §5.2 (the change-password service's own purpose; A-117).
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
    /// The admin service's key set (`admind/<dc-fqdn>`, A-73): the key the
    /// admin channel's tickets are sealed under. A purpose of its own so
    /// that a ticket under it is opened **only** bound to the exact
    /// operation it accompanies (the Authenticator's `cksum`, RFC 4120
    /// 5.5.1, key usage 10 — `AppBinding::OperationDigest`) and never
    /// unbound, and so that no `set_secret` can overwrite it (the A-50
    /// follow-up for the admin service). Bound only to the admin service's
    /// name ([`is_admin_service_name`]).
    /// Spec: docs/52 §3.2 (C2), §5 items 2-3, §7 R2; docs/questions/Q-463
    /// (A-102); A-50; A-73; RFC 4120 5.3.
    AdminService = 3,
    /// The change-password service's key set (`kadmin/changepw`, RFC 3244
    /// §2: "The AP-REQ message must be for the service principal
    /// kadmin/changepw@REALM"): the key the kpasswd tickets are sealed
    /// under. A purpose of its own so that a ticket under it is opened
    /// **only** by `open_change_password_request` — whose AP-REQ must carry
    /// a subkey and a sequence number and whose KRB-PRIV is decrypted under
    /// that subkey in the same call — and by no other verification, and so
    /// that no `set_secret`, grant, destruction or rotation can replace it
    /// (its key is keyd-drawn only). Bound only to the change-password
    /// service's name ([`is_change_password_service_name`]).
    /// Spec: RFC 3244 §2; docs/53 R53-6, §4.5, §5.2, §5.3; docs/questions/
    /// Q-601 item 4 (A-117).
    ChangePasswordService = 4,
}

/// The service class — the first name component — of the admin service's
/// principal `admind/<dc-fqdn>`. A project choice: no specification names
/// this project's own admin service.
/// Spec: PENDING-OWNER A-73 / docs/questions/Q-290 item 4 ("SPN
/// `admind/<fqdn>`"); docs/51 §5.3 item 4.
pub const ADMIN_SERVICE_CLASS: &str = "admind";

/// `true` if `name` is the admin service's: exactly two components, the
/// first [`ADMIN_SERVICE_CLASS`] (octet for octet; the name-type is a hint
/// only, RFC 4120 6.2). The same shape of rule as the reserved TGS name
/// ("a two-part name ... with the first part 'krbtgt'", RFC 4120 7.3):
/// keyd binds an [`KeyPurpose::AdminService`] key set to such a name only,
/// and no other key set to one.
/// Spec: RFC 4120 6.2, 7.3; A-73; docs/52 §5 item 3 (R2).
#[must_use]
pub fn is_admin_service_name(name: &PrincipalName) -> bool {
    name.name_string.len() == 2
        && name
            .name_string
            .first()
            .is_some_and(|c| c.as_bytes() == ADMIN_SERVICE_CLASS.as_bytes())
}

/// The change-password service's name (`kadmin/changepw`, RFC 3244 §2) and
/// its rule — exactly those two components, octet for octet, the name-type a
/// hint only (RFC 4120 6.2). The same shape of rule as
/// [`is_admin_service_name`]: keyd binds a
/// [`KeyPurpose::ChangePasswordService`] key set to this name only, and no
/// other key set to it. Defined once, in krb-proto (moved there from this
/// module — docs/questions/Q-955 item 5, A-158; Q-987), and re-exported here
/// under the path keyd, the kdc and provisioning name.
/// Spec: RFC 3244 §2; RFC 4120 6.2; docs/53 R53-6, §5.2.
pub use krb_proto::{is_change_password_service_name, CHANGE_PASSWORD_SERVICE_NAME};

impl KeyPurpose {
    /// The purpose of the key set a service ticket for `name` is sealed
    /// under: [`KeyPurpose::AdminService`] for the admin service's name
    /// ([`is_admin_service_name`]), [`KeyPurpose::ChangePasswordService`]
    /// for the change-password service's name
    /// ([`is_change_password_service_name`]), [`KeyPurpose::Service`] for
    /// every other service. The KDC's account source names the handle with
    /// it, and keyd refuses any other pairing at the binding check (A-19), so
    /// a ticket for either of those services is never sealed under a plain
    /// service key. The **only** derivation of a service object's purpose
    /// (docs/52 R2b; crate tests `one_service_purpose_derivation`).
    /// Spec: docs/47 §1.3 (`AccountSource::service`: the key set
    /// `(objectGUID, Service)`), §9.1; docs/52 §5 item 3 (R2, R2b); A-73;
    /// docs/53 R53-6, §5.2 (A-117).
    #[must_use]
    pub fn of_service_name(name: &PrincipalName) -> KeyPurpose {
        if is_admin_service_name(name) {
            KeyPurpose::AdminService
        } else if is_change_password_service_name(name) {
            KeyPurpose::ChangePasswordService
        } else {
            KeyPurpose::Service
        }
    }
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

/// The handle of a service object's key set: `(objectGUID, purpose)`, the
/// purpose derived from the service's name by
/// [`KeyPurpose::of_service_name`] — the one derivation — and by nothing
/// else. There is no other constructor, so a component that holds one names
/// exactly the key set the KDC seals that service's tickets under, and
/// cannot name a purpose that contradicts the name: the admin service
/// (`admind/<host>`) is always [`KeyPurpose::AdminService`], the
/// change-password service (`kadmin/changepw`, docs/53 §5.2) always
/// [`KeyPurpose::ChangePasswordService`], every other service
/// [`KeyPurpose::Service`].
///
/// Class closed (docs/52 R2b, AGENTS.md §6.1): one fact — the purpose of a
/// service object's key set — chosen in several places (the KDC's account
/// source from the name, but the admin plane's key operations, the
/// password-set targets and the provisioning manifest each by a literal), so
/// that a divergence failed open or closed by luck (docs/questions/Q-493
/// item 1: the admin service key could not be rotated).
///
/// Spec: docs/47 §1.3 (TGS step 5: the key set of the service), §9.1 (the
/// "computer (service)" row); docs/52 §3.2, §5 item 3; docs/questions/Q-491
/// item 1, Q-493 item 1; A-73.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceKeyHandle {
    handle: KeyHandle,
}

impl ServiceKeyHandle {
    /// The key set of the service object `principal` whose principal name
    /// is `name` (its servicePrincipalName split on "/", or the manifest's
    /// binding of it): the purpose is [`KeyPurpose::of_service_name`]`(name)`.
    /// Spec: docs/47 §1.3, §9.1; docs/52 §5 item 3; docs/questions/Q-491
    /// item 1.
    #[must_use]
    pub fn of_service(principal: PrincipalId, name: &PrincipalName) -> ServiceKeyHandle {
        ServiceKeyHandle {
            handle: KeyHandle::new(principal, KeyPurpose::of_service_name(name)),
        }
    }

    /// The handle. Spec: docs/10 §1.
    #[must_use]
    pub const fn handle(&self) -> KeyHandle {
        self.handle
    }

    /// The service object's principal id (its objectGUID). Spec: docs/47
    /// §2.3.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.handle.principal
    }

    /// The derived purpose: `Service`, `AdminService` or
    /// `ChangePasswordService`. Spec: docs/52 §5 item 3; docs/53 §5.2.
    #[must_use]
    pub const fn purpose(&self) -> KeyPurpose {
        self.handle.purpose
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

    /// docs/52 R2b; docs/questions/Q-491 item 1 (the rule as decided):
    /// `admind/<host>` — exactly two components, the first "admind" octet
    /// for octet, whatever the name-type (RFC 4120 6.2: a hint only) — is
    /// the admin service's key set; every other service name is a plain
    /// `Service` key set. `ServiceKeyHandle` carries the principal given and
    /// exactly the purpose `KeyPurpose::of_service_name` derives.
    #[test]
    fn a_service_key_handle_takes_its_purpose_from_the_name() {
        let p = PrincipalId::from_bytes([7; 16]);
        let admin = ServiceKeyHandle::of_service(p, &name(3, &["admind", "dc01.example.org"]));
        assert_eq!(admin.purpose(), KeyPurpose::AdminService);
        assert_eq!(admin.principal(), p);
        assert_eq!(admin.handle(), KeyHandle::new(p, KeyPurpose::AdminService));
        // The name-type does not change it.
        for name_type in [0, 1, 2] {
            assert_eq!(
                ServiceKeyHandle::of_service(p, &name(name_type, &["admind", "dc01.example.org"]))
                    .purpose(),
                KeyPurpose::AdminService
            );
        }
        // Every other name: the LDAP service, another class, a case
        // variant, one or three components.
        for parts in [
            &["ldap", "dc01.example.org"][..],
            &["host", "dc01.example.org"][..],
            &["ADMIND", "dc01.example.org"][..],
            &["admind"][..],
            &["admind", "dc01.example.org", "x"][..],
            &["dc01.example.org", "admind"][..],
        ] {
            let service = ServiceKeyHandle::of_service(p, &name(3, parts));
            assert_eq!(service.purpose(), KeyPurpose::Service, "{parts:?}");
            assert_eq!(
                service.purpose(),
                KeyPurpose::of_service_name(&name(3, parts))
            );
        }
    }

    /// RFC 3244 §2 ("the service principal kadmin/changepw@REALM"); docs/53
    /// §5.2 (R53-6): exactly `kadmin` / `changepw`, octet for octet, whatever
    /// the name-type (RFC 4120 6.2), derives the change-password service's
    /// key set; a case variant, a reordering, one or three components, or the
    /// admin service's class do not.
    #[test]
    fn the_change_password_service_name_derives_its_own_purpose() {
        let p = PrincipalId::from_bytes([9; 16]);
        for name_type in [0, 1, 2, 3] {
            let handle = ServiceKeyHandle::of_service(p, &name(name_type, &["kadmin", "changepw"]));
            assert_eq!(handle.purpose(), KeyPurpose::ChangePasswordService);
            assert_eq!(
                handle.handle(),
                KeyHandle::new(p, KeyPurpose::ChangePasswordService)
            );
            assert!(is_change_password_service_name(&name(
                name_type,
                &["kadmin", "changepw"]
            )));
        }
        for parts in [
            &["KADMIN", "changepw"][..],
            &["kadmin", "CHANGEPW"][..],
            &["changepw", "kadmin"][..],
            &["kadmin"][..],
            &["kadmin", "changepw", "x"][..],
            &["kadmin/changepw"][..],
            &["kadmin", "admin"][..],
        ] {
            assert!(
                !is_change_password_service_name(&name(1, parts)),
                "{parts:?}"
            );
            assert_ne!(
                KeyPurpose::of_service_name(&name(1, parts)),
                KeyPurpose::ChangePasswordService,
                "{parts:?}"
            );
        }
        // The admin service's rule and this one never overlap.
        assert_eq!(
            KeyPurpose::of_service_name(&name(3, &["admind", "changepw"])),
            KeyPurpose::AdminService
        );
    }
}
