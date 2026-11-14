//! The manifest: its closed key table, the parser, the builder and the
//! canonical encoder, and the key sets it fixes.

use crate::error::{Error, ErrorKind};
use crate::format::{is_printable, Document};
use crate::limits::{MAX_FIRST_ADMINS, MIN_FIRST_ADMINS};
use crate::value::{
    self, binding, binding_text, first_admin_items, guid_text, names_realm, object_entry,
    salt_items, COMPONENT_SEPARATOR, ENTRY_SEPARATOR, LIST_SEPARATOR, MANIFEST_VERSION,
};
use dtyp::{Guid, Sid};
use keyd_types::{KeyHandle, KeyPurpose, PrincipalBinding, PrincipalId};
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST, KRB_NT_SRV_INST};
use krb_proto::{KerberosString, Realm};

/// The keys of the manifest — its closed key table. Every key is required.
/// Spec: docs/51 §4.3 step 8 (what the manifest holds); docs/50 R50-15 (a
/// closed key table).
pub mod keys {
    /// The format version. Project choice (exact version, D57).
    pub const MANIFEST_VERSION: &str = "manifest_version";
    /// The realm. Spec: docs/51 §4.3 step 8 ("realm").
    pub const REALM: &str = "realm";
    /// The domain SID. Spec: docs/51 §4.3 step 8 ("the domain SID").
    pub const DOMAIN_SID: &str = "domain_sid";
    /// The DN of the NC. Spec: docs/51 §4.3 step 8 ("the DN of the NC").
    pub const NAMING_CONTEXT: &str = "naming_context";
    /// The DC's host name, the host component of the service bindings.
    /// Spec: docs/51 §4.3 (input: "the DC's short name and FQDN"), steps 5,
    /// 11.
    pub const DC_FQDN: &str = "dc_fqdn";
    /// The krbtgt object: GUID and binding. Spec: docs/51 §4.3 steps 8, 11.
    pub const KRBTGT: &str = "krbtgt";
    /// The LDAP service object: GUID and binding. Spec: docs/51 §4.3 steps
    /// 5, 8, 11; docs/10 §5ב.
    pub const LDAP_SERVICE: &str = "ldap_service";
    /// The admin service object: GUID and binding. Spec: docs/51 §4.3 steps
    /// 5, 8, 11; A-73.
    pub const ADMIN_SERVICE: &str = "admin_service";
    /// The first administrators: GUID, sAMAccountName and binding of each.
    /// Spec: docs/51 §4.3 steps 5, 8, 12.
    pub const FIRST_ADMINS: &str = "first_admins";
    /// Each first administrator's string-to-key salt, in `first_admins`
    /// order — computed by `provision domain` with the directory's own salt
    /// function (`directory_pip::account_salt`, docs/47 §3.3 R47-4), so that
    /// keyadm's ceremony grant binds exactly the salt `provision
    /// first-admin-secret` presents (A-102, docs/52 §2 row 37, N4) without
    /// keyadm linking the directory code. Required like every other key
    /// (A-105, the Q-473 follow-up): a manifest without it does not parse.
    /// Spec: docs/51 §4.3 steps 8, 11, 12, §7.3; docs/52 §4.2;
    /// docs/questions/Q-473 item 2.
    pub const FIRST_ADMIN_SALTS: &str = "first_admin_salts";
}

/// The first component of the krbtgt binding.
/// Spec: RFC 4120 §7.3 ("a two-part name of type NT-SRV-INST, with the first
/// part "krbtgt" and the second part the name of the realm").
pub const KRBTGT_SERVICE: &str = "krbtgt";

/// The service class of the LDAP service object's binding.
/// Spec: docs/10 §5ב ("a dedicated service object with the single SPN
/// `ldap/<dc-fqdn>`"); docs/51 §4.3 step 5.
pub const LDAP_SERVICE_CLASS: &str = "ldap";

/// The service class of the admin service object's binding.
/// Spec: PENDING-OWNER A-73 / docs/questions/Q-290 item 4 ("SPN
/// `admind/<fqdn>`", a project choice); docs/51 §4.3 step 5.
pub const ADMIN_SERVICE_CLASS: &str = "admind";

/// A comment the encoder writes as the first line. Printable ASCII only
/// (docs/50 §7.1).
const HEADER: &str = "# provisioning manifest (docs/51 4.3 step 8): identifiers only, no secret";

/// A key set the provisioning steps create or fill: its handle and the
/// principal name it is bound to for good (A-19). Not secret.
///
/// `handle.principal` is the object's objectGUID in the [MS-DTYP] 2.3.4.2
/// packet form — the form the directory stores and the KDC's AccountSource
/// hands keyd (docs/47 §2.3: `PrincipalId = objectGUID`).
///
/// Spec: docs/10 §1 (`KeyHandle`, `PrincipalBinding`), §7 (`create_key`);
/// docs/47 §1.4, §2.3, §9.1; PENDING-OWNER A-19.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    /// The key set's handle: (objectGUID, purpose).
    pub handle: KeyHandle,
    /// The immutable binding given at creation.
    pub binding: PrincipalBinding,
}

impl KeySet {
    /// The binding as the manifest writes it (`<NAME-TYPE>:<c1>[/<c2>]`).
    /// Spec: RFC 4120 §6.2.
    #[must_use]
    pub fn binding_text(&self) -> String {
        binding_text(&self.binding)
    }

    /// The object's GUID as the manifest writes it.
    /// Spec: [MS-DTYP] 2.5.1.1; [MS-DRSR] 5.16.3.16.
    #[must_use]
    pub fn guid_text(&self) -> String {
        guid_text(&Guid::from_packet(self.handle.principal.as_bytes()))
    }
}

/// One first administrator: the sAMAccountName and the key set
/// `provision first-admin-secret` fills with `set_secret`.
/// Spec: docs/51 §4.3 steps 5, 12; docs/47 §9.1 (user: `(GUID,
/// PrincipalLongterm)`, binding `(REALM, NT-PRINCIPAL [sAMAccountName])`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstAdmin {
    sam_account_name: KerberosString,
    key_set: KeySet,
    salt: String,
}

impl FirstAdmin {
    /// The sAMAccountName — also the single component of the binding
    /// (docs/47 §1.3, R47-1: the client name is the sAMAccountName).
    #[must_use]
    pub fn sam_account_name(&self) -> &str {
        self.sam_account_name.as_str()
    }

    /// The `(GUID, PrincipalLongterm)` key set and its NT-PRINCIPAL binding.
    #[must_use]
    pub fn key_set(&self) -> &KeySet {
        &self.key_set
    }

    /// The string-to-key salt `provision domain` wrote for this
    /// administrator (`first_admin_salts` — every manifest carries it,
    /// A-105). keyadm's ceremony grant binds it (A-102, N4);
    /// `first-admin-secret` refuses a manifest whose salt is not the
    /// directory's.
    /// Spec: docs/51 §4.3 steps 11, 12; docs/52 §4.2 (N4); Q-473.
    #[must_use]
    pub fn salt(&self) -> &str {
        &self.salt
    }
}

/// The values a provisioning run writes into a manifest
/// ([`Manifest::new`]). Plain data; every rule is checked by `new`.
/// Spec: docs/51 §4.3 steps 2, 8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFields {
    /// The realm (upper case).
    pub realm: String,
    /// The domain SID `S-1-5-21-<n>-<n>-<n>`.
    pub domain_sid: Sid,
    /// The naming context's labels n1 … nk, leaf first.
    pub naming_context: Vec<String>,
    /// The DC's host name (lower case).
    pub dc_fqdn: String,
    /// The krbtgt object's GUID.
    pub krbtgt: Guid,
    /// The LDAP service object's GUID.
    pub ldap_service: Guid,
    /// The admin service object's GUID.
    pub admin_service: Guid,
    /// Each first administrator's GUID and sAMAccountName.
    pub first_admins: Vec<(Guid, String)>,
    /// Each first administrator's string-to-key salt, in `first_admins`
    /// order (the directory's `account_salt`, R47-4; A-102, N4; required —
    /// A-105, Q-473).
    pub first_admin_salts: Vec<String>,
}

/// The provisioning manifest (docs/51 §4.3 step 8): the realm, the domain
/// SID, the NC's DN, the DC's host name, and the GUID and immutable binding
/// of the krbtgt object, the LDAP and admin service objects and each first
/// administrator. Identifiers only — no key, password or token (docs/47
/// §2.3: GUIDs and SIDs are not secrets).
///
/// Invariants (checked by [`Manifest::parse`]; [`Manifest::new`] goes
/// through the parser): the realm is the naming context's DNS name in upper
/// case; every GUID is non-NULL and used once; every binding is exactly the
/// one its object's rule fixes; 2 ..= 8 first administrators with distinct
/// sAMAccountNames (ASCII case folded).
///
/// Spec: docs/51 §4.3 steps 1, 2, 5, 8, 11, 12; docs/47 §1.4, §2.3, §9.1;
/// RFC 4120 §6.2, §6.2.1, §7.3; A-19; A-73; docs/questions/Q-295 (P-22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    realm: Realm,
    domain_sid: Sid,
    naming_context: Vec<String>,
    dc_fqdn: KerberosString,
    krbtgt: KeySet,
    ldap_service: KeySet,
    admin_service: KeySet,
    first_admins: Vec<FirstAdmin>,
}

/// The GUIDs seen so far, for the "used once" rule.
/// Spec: docs/51 §4.3 step 2 ("objectGUID per object — 16 random bytes, not
/// NULL, distinct from each other").
#[derive(Default)]
struct SeenGuids(Vec<[u8; dtyp::GUID_PACKET_LEN]>);

impl SeenGuids {
    fn admit(&mut self, guid: &Guid) -> Result<PrincipalId, ErrorKind> {
        let packet = guid.to_packet();
        if self.0.contains(&packet) {
            return Err(ErrorKind::DuplicateGuid);
        }
        self.0.push(packet);
        Ok(PrincipalId::from_bytes(packet))
    }
}

impl Manifest {
    /// The closed key table, in the order the encoder writes it.
    /// Spec: docs/51 §4.3 step 8; docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        keys::MANIFEST_VERSION,
        keys::REALM,
        keys::DOMAIN_SID,
        keys::NAMING_CONTEXT,
        keys::DC_FQDN,
        keys::KRBTGT,
        keys::LDAP_SERVICE,
        keys::ADMIN_SERVICE,
        keys::FIRST_ADMINS,
        keys::FIRST_ADMIN_SALTS,
    ];

    /// Parse and validate a manifest.
    ///
    /// # Errors
    /// Any rule of the format or of the manifest ([`ErrorKind`]); the error
    /// names a line and a key, never input text.
    ///
    /// Spec: docs/50 R50-15, §7.1; docs/51 §4.3 step 8; the value and
    /// binding rules cited on each item.
    pub fn parse(input: &[u8]) -> Result<Manifest, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        doc.required(keys::MANIFEST_VERSION, value::version)?;
        let (realm, _) = doc.required(keys::REALM, value::realm)?;
        let (domain_sid, _) = doc.required(keys::DOMAIN_SID, value::domain_sid)?;
        let (naming_context, nc_line) =
            doc.required(keys::NAMING_CONTEXT, value::naming_context)?;
        // docs/47 §3.3 item 3; A-55: the realm is the NC's DNS name in upper
        // case — the check dird makes at start.
        if !names_realm(&naming_context, &realm) {
            return Err(Error::at(
                nc_line,
                keys::NAMING_CONTEXT,
                ErrorKind::RealmMismatch,
            ));
        }
        let (dc_fqdn, _) = doc.required(keys::DC_FQDN, value::host_name)?;
        let mut seen = SeenGuids::default();

        // RFC 4120 §7.3; docs/47 §1.4 (R47-2); docs/51 §4.3 step 11:
        // (GUID_krbtgt, Krbtgt), NT-SRV-INST [krbtgt, REALM].
        let krbtgt = Self::object(
            &doc,
            keys::KRBTGT,
            &mut seen,
            KeyPurpose::Krbtgt,
            binding(&realm, KRB_NT_SRV_INST, &[KRBTGT_SERVICE, realm.as_str()]),
        )?;
        // RFC 4120 §6.2.1; docs/10 §5ב; docs/47 §9.1; docs/51 §4.3 step 11:
        // (GUID_ldap, Service), NT-SRV-HST [ldap, fqdn].
        let ldap_service = Self::object(
            &doc,
            keys::LDAP_SERVICE,
            &mut seen,
            KeyPurpose::Service,
            binding(
                &realm,
                KRB_NT_SRV_HST,
                &[LDAP_SERVICE_CLASS, dc_fqdn.as_str()],
            ),
        )?;
        // RFC 4120 §6.2.1; A-73; docs/51 §4.3 step 11: (GUID_admin,
        // AdminService) — the admin service's own purpose (R2, docs/52 §5
        // item 3; A-102), so keyd opens its tickets only bound to an
        // operation — [admind, fqdn], NT-SRV-HST, a service on a host
        // (docs/questions/Q-345 item 4).
        let admin_service = Self::object(
            &doc,
            keys::ADMIN_SERVICE,
            &mut seen,
            KeyPurpose::AdminService,
            binding(
                &realm,
                KRB_NT_SRV_HST,
                &[ADMIN_SERVICE_CLASS, dc_fqdn.as_str()],
            ),
        )?;
        let admins = Self::parse_first_admins(&doc, &mut seen, &realm)?;
        // A-102 (N4), A-105 (Q-473: required): one KerberosString per first
        // administrator, in order.
        let (salts, line) = doc.required(keys::FIRST_ADMIN_SALTS, salt_items)?;
        if salts.len() != admins.len() {
            return Err(Error::at(
                line,
                keys::FIRST_ADMIN_SALTS,
                ErrorKind::InvalidSalt,
            ));
        }
        let first_admins = admins
            .into_iter()
            .zip(salts)
            .map(|((sam_account_name, key_set), salt)| FirstAdmin {
                sam_account_name,
                key_set,
                salt: salt.to_owned(),
            })
            .collect();
        Ok(Manifest {
            realm,
            domain_sid,
            naming_context,
            dc_fqdn,
            krbtgt,
            ldap_service,
            admin_service,
            first_admins,
        })
    }

    /// One service-or-krbtgt object entry: `<guid>:<binding>`, where the
    /// binding must be exactly `expected` (written by [`binding_text`]).
    /// Spec: docs/51 §4.3 steps 8, 11; A-19.
    fn object(
        doc: &Document<'_>,
        key: &'static str,
        seen: &mut SeenGuids,
        purpose: KeyPurpose,
        expected: Result<PrincipalBinding, ErrorKind>,
    ) -> Result<KeySet, Error> {
        let ((guid, written), line) = doc.required(key, object_entry)?;
        let at = |kind| Error::at(line, key, kind);
        let expected = expected.map_err(at)?;
        if written != binding_text(&expected) {
            return Err(at(ErrorKind::BindingMismatch));
        }
        let principal = seen.admit(&guid).map_err(at)?;
        Ok(KeySet {
            handle: KeyHandle::new(principal, purpose),
            binding: expected,
        })
    }

    /// The `first_admins` list: entries `<guid>:NT-PRINCIPAL:<sAMAccountName>`
    /// — each administrator's name and key set (its salt is the matching
    /// item of `first_admin_salts`).
    /// Spec: docs/51 §4.3 steps 5, 8, 12; docs/47 §1.1 (uniqueness folds
    /// A-Z), §1.3, §9.1; docs/questions/Q-295 (P-22).
    fn parse_first_admins(
        doc: &Document<'_>,
        seen: &mut SeenGuids,
        realm: &Realm,
    ) -> Result<Vec<(KerberosString, KeySet)>, Error> {
        let (items, line) = doc.required(keys::FIRST_ADMINS, first_admin_items)?;
        let at = |kind| Error::at(line, keys::FIRST_ADMINS, kind);
        let prefix = match value::name_type_label(KRB_NT_PRINCIPAL) {
            Some(label) => format!("{label}{ENTRY_SEPARATOR}"),
            None => return Err(at(ErrorKind::BindingMismatch)),
        };
        let mut admins: Vec<(KerberosString, KeySet)> = Vec::with_capacity(items.len());
        for item in items {
            let (guid, written) = object_entry(item).map_err(at)?;
            let name = written
                .strip_prefix(prefix.as_str())
                .ok_or(at(ErrorKind::BindingMismatch))?;
            let sam = value::account_name(name).map_err(at)?;
            let repeated = admins
                .iter()
                .any(|(name, _)| name.as_str().eq_ignore_ascii_case(sam.as_str()));
            if repeated {
                return Err(at(ErrorKind::DuplicateAccountName));
            }
            let principal = seen.admit(&guid).map_err(at)?;
            let bound = binding(realm, KRB_NT_PRINCIPAL, &[sam.as_str()]).map_err(at)?;
            admins.push((
                sam,
                KeySet {
                    handle: KeyHandle::new(principal, KeyPurpose::PrincipalLongterm),
                    binding: bound,
                },
            ));
        }
        Ok(admins)
    }

    /// Build a manifest from the values of a provisioning run.
    ///
    /// The values are written in the canonical form and parsed back, so
    /// `new` accepts exactly what [`Manifest::parse`] accepts and its result
    /// always encodes to text the parser accepts. Every text field must be
    /// printable ASCII first, so no field can spill into another line.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidCharacter`] for a non-printable text field;
    /// [`ErrorKind::TooFewFirstAdmins`] / [`ErrorKind::TooManyFirstAdmins`];
    /// otherwise any error of [`Manifest::parse`] (its line numbers refer to
    /// the canonical text).
    ///
    /// Spec: docs/51 §4.3 step 8; docs/50 §7.1.
    pub fn new(fields: &ManifestFields) -> Result<Manifest, Error> {
        let printable = |text: &str| text.bytes().all(is_printable);
        let checks: [(&'static str, bool); 5] = [
            (keys::REALM, printable(&fields.realm)),
            (
                keys::NAMING_CONTEXT,
                fields.naming_context.iter().all(|label| printable(label)),
            ),
            (keys::DC_FQDN, printable(&fields.dc_fqdn)),
            (
                keys::FIRST_ADMINS,
                fields.first_admins.iter().all(|(_, sam)| printable(sam)),
            ),
            (
                keys::FIRST_ADMIN_SALTS,
                fields.first_admin_salts.iter().all(|salt| printable(salt)),
            ),
        ];
        if let Some(&(key, _)) = checks.iter().find(|(_, ok)| !ok) {
            return Err(Error::field(key, ErrorKind::InvalidCharacter));
        }
        let count = fields.first_admins.len();
        if count < MIN_FIRST_ADMINS {
            return Err(Error::field(
                keys::FIRST_ADMINS,
                ErrorKind::TooFewFirstAdmins,
            ));
        }
        if count > MAX_FIRST_ADMINS {
            return Err(Error::field(
                keys::FIRST_ADMINS,
                ErrorKind::TooManyFirstAdmins,
            ));
        }
        let entry = |guid: &Guid, name_type: i32, components: &[&str]| {
            let label = value::name_type_label(name_type).unwrap_or_default();
            format!(
                "{}{ENTRY_SEPARATOR}{label}{ENTRY_SEPARATOR}{}",
                guid_text(guid),
                components.join(COMPONENT_SEPARATOR)
            )
        };
        let admins: Vec<String> = fields
            .first_admins
            .iter()
            .map(|(guid, sam)| entry(guid, KRB_NT_PRINCIPAL, &[sam.as_str()]))
            .collect();
        if fields.first_admin_salts.len() != count {
            return Err(Error::field(
                keys::FIRST_ADMIN_SALTS,
                ErrorKind::InvalidSalt,
            ));
        }
        let lines: [(&str, String); 10] = [
            (keys::MANIFEST_VERSION, MANIFEST_VERSION.to_owned()),
            (keys::REALM, fields.realm.clone()),
            (keys::DOMAIN_SID, fields.domain_sid.to_sid_string()),
            (
                keys::NAMING_CONTEXT,
                value::naming_context_text(&fields.naming_context),
            ),
            (keys::DC_FQDN, fields.dc_fqdn.clone()),
            (
                keys::KRBTGT,
                entry(
                    &fields.krbtgt,
                    KRB_NT_SRV_INST,
                    &[KRBTGT_SERVICE, fields.realm.as_str()],
                ),
            ),
            (
                keys::LDAP_SERVICE,
                entry(
                    &fields.ldap_service,
                    KRB_NT_SRV_HST,
                    &[LDAP_SERVICE_CLASS, fields.dc_fqdn.as_str()],
                ),
            ),
            (
                keys::ADMIN_SERVICE,
                entry(
                    &fields.admin_service,
                    KRB_NT_SRV_HST,
                    &[ADMIN_SERVICE_CLASS, fields.dc_fqdn.as_str()],
                ),
            ),
            (keys::FIRST_ADMINS, admins.join(LIST_SEPARATOR)),
            (
                keys::FIRST_ADMIN_SALTS,
                fields.first_admin_salts.join(LIST_SEPARATOR),
            ),
        ];
        Manifest::parse(render(&lines).as_bytes())
    }

    /// This manifest with `salts` in place of its first administrators'
    /// salts (one per first administrator, in order). The result is encoded
    /// and parsed back, so it holds exactly what [`Manifest::parse`]
    /// accepts.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidSalt`] when the count differs from the first
    /// administrators' or a salt is not a KerberosString;
    /// [`ErrorKind::InvalidCharacter`] for a non-printable salt; otherwise any
    /// error of [`Manifest::parse`].
    ///
    /// Spec: docs/51 §4.3 step 8; docs/52 §4.2 (N4); docs/50 §7.1.
    pub fn with_first_admin_salts(&self, salts: &[String]) -> Result<Manifest, Error> {
        if salts.len() != self.first_admins.len() {
            return Err(Error::field(
                keys::FIRST_ADMIN_SALTS,
                ErrorKind::InvalidSalt,
            ));
        }
        if !salts.iter().all(|salt| salt.bytes().all(is_printable)) {
            return Err(Error::field(
                keys::FIRST_ADMIN_SALTS,
                ErrorKind::InvalidCharacter,
            ));
        }
        let mut salted = self.clone();
        for (admin, salt) in salted.first_admins.iter_mut().zip(salts) {
            admin.salt = salt.clone();
        }
        Manifest::parse(salted.encode().as_bytes())
    }

    /// The canonical text: a header comment, then every key once, in
    /// [`Manifest::KEYS`] order, one `key = value` line each, LF-terminated.
    /// `Manifest::parse(m.encode().as_bytes()) == Ok(m)` for every manifest.
    /// Spec: docs/50 R50-15, §7.1; docs/51 §4.3 step 8.
    #[must_use]
    pub fn encode(&self) -> String {
        let admins: Vec<String> = self
            .first_admins
            .iter()
            .map(|admin| object_text(admin.key_set()))
            .collect();
        let salts: Vec<&str> = self.first_admins.iter().map(FirstAdmin::salt).collect();
        let lines: [(&str, String); 10] = [
            (keys::MANIFEST_VERSION, MANIFEST_VERSION.to_owned()),
            (keys::REALM, self.realm.as_str().to_owned()),
            (keys::DOMAIN_SID, self.domain_sid.to_sid_string()),
            (
                keys::NAMING_CONTEXT,
                value::naming_context_text(&self.naming_context),
            ),
            (keys::DC_FQDN, self.dc_fqdn.as_str().to_owned()),
            (keys::KRBTGT, object_text(&self.krbtgt)),
            (keys::LDAP_SERVICE, object_text(&self.ldap_service)),
            (keys::ADMIN_SERVICE, object_text(&self.admin_service)),
            (keys::FIRST_ADMINS, admins.join(LIST_SEPARATOR)),
            (keys::FIRST_ADMIN_SALTS, salts.join(LIST_SEPARATOR)),
        ];
        render(&lines)
    }

    /// The realm. Spec: docs/51 §4.3 step 8.
    #[must_use]
    pub fn realm(&self) -> &Realm {
        &self.realm
    }

    /// The domain SID. Spec: docs/51 §4.3 step 8; [MS-DTYP] 2.4.2.4.
    #[must_use]
    pub fn domain_sid(&self) -> &Sid {
        &self.domain_sid
    }

    /// The naming context's labels n1 … nk, leaf first. Spec: A-53.
    #[must_use]
    pub fn naming_context_labels(&self) -> &[String] {
        &self.naming_context
    }

    /// The DC's host name. Spec: docs/51 §4.3 (input).
    #[must_use]
    pub fn dc_fqdn(&self) -> &str {
        self.dc_fqdn.as_str()
    }

    /// The krbtgt key set: `(GUID_krbtgt, Krbtgt)`, NT-SRV-INST
    /// [krbtgt, REALM]. Spec: docs/47 §1.4; docs/51 §4.3 step 11; RFC 4120
    /// §7.3.
    #[must_use]
    pub fn krbtgt(&self) -> &KeySet {
        &self.krbtgt
    }

    /// The LDAP service key set: `(GUID_ldap, Service)`, NT-SRV-HST
    /// [ldap, fqdn]. Spec: docs/10 §5ב; docs/51 §4.3 step 11; RFC 4120
    /// §6.2.1.
    #[must_use]
    pub fn ldap_service(&self) -> &KeySet {
        &self.ldap_service
    }

    /// The admin service key set: `(GUID_admin, Service)`, NT-SRV-HST
    /// [admind, fqdn]. Spec: A-73; docs/51 §4.3 step 11; RFC 4120 §6.2.1.
    #[must_use]
    pub fn admin_service(&self) -> &KeySet {
        &self.admin_service
    }

    /// The first administrators, in manifest order. Spec: docs/51 §4.3
    /// steps 5, 12.
    #[must_use]
    pub fn first_admins(&self) -> &[FirstAdmin] {
        &self.first_admins
    }
}

/// An object entry as written: `<guid>:<binding>`.
fn object_text(key_set: &KeySet) -> String {
    format!(
        "{}{ENTRY_SEPARATOR}{}",
        key_set.guid_text(),
        key_set.binding_text()
    )
}

/// The header comment, then one `key = value` line per pair.
fn render(lines: &[(&str, String)]) -> String {
    let mut out = String::new();
    out.push_str(HEADER);
    out.push('\n');
    for (key, value) in lines {
        out.push_str(key);
        out.push_str(crate::limits::SEPARATOR);
        out.push_str(value);
        out.push('\n');
    }
    out
}
