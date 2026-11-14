//! The input of `provision domain` (no secret of any kind) and its pure
//! checks — step 1 of docs/51 §4.3 for everything that does not touch the
//! filesystem (the filesystem half is `install::precheck`).
//!
//! Spec: docs/51 §4.3 ("input (without any secret)"; step 1), §4.4, §4.6,
//! §11; docs/50 §2.4, §3.1, R50-3, §7.1; decisions A-55, A-60, A-72, A-79,
//! P-22 (Q-295); docs/questions/Q-345 items 6-8.

use core::fmt;
use std::path::Path;

use directory_admin::{
    computer_name_ok, computer_sam, dns_host_name_ok, group_sam_ok, rdn_value_ok, spn_ok,
    user_sam_ok,
};
use directory_pip::NamingContext;
use krb_proto::Realm;
use provision_manifest::limits::{MAX_FIRST_ADMINS, MIN_FIRST_ADMINS};
use provision_manifest::{ADMIN_SERVICE_CLASS, LDAP_SERVICE_CLASS};

/// The krbtgt account's fixed name: no other object may take it.
/// Spec: [MS-SAMR] v20260427 3.1.1.6 item 14 ("sAMAccountName MUST be the
/// value "krbtgt" … if the RID of the objectSid attribute is
/// DOMAIN_USER_RID_KRBTGT"); RFC 4120 §7.3 (as cited in docs/47 §1.4).
pub const KRBTGT_NAME: &str = "krbtgt";

/// The all-ones account id, never a valid uid or gid.
/// Spec: docs/questions/Q-230 item 6 (as enforced by crates/config
/// `account_id`).
const ALL_ONES_ID: u32 = u32::MAX;

/// A path the tool writes or names: absolute, one or more components of
/// `A-Z a-z 0-9 . _ -`, none empty, `.` or `..`, no trailing `/`.
///
/// The same rule as crates/config's `AbsolutePath` (docs/50 §7.1; Q-230
/// item 16), applied here to the paths no configuration file carries (the
/// configuration files themselves, the manifest, the staging directory);
/// every path that a configuration carries is re-checked by its parser
/// before anything is written. A second copy of the rule —
/// docs/questions/Q-375 item 6.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilePath(String);

impl FilePath {
    /// Parse a path. Spec: docs/50 §7.1; Q-230 item 16.
    ///
    /// # Errors
    /// [`InputErrorKind::Path`].
    pub fn parse(text: &str) -> Result<FilePath, InputErrorKind> {
        let relative = text.strip_prefix('/').ok_or(InputErrorKind::Path)?;
        let valid = relative.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        });
        if valid {
            Ok(FilePath(text.to_owned()))
        } else {
            Err(InputErrorKind::Path)
        }
    }

    /// The path as text (printable ASCII, checked by [`FilePath::parse`]).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// The parent directory (`/` for a top-level name).
    #[must_use]
    pub fn parent(&self) -> &Path {
        self.as_path().parent().unwrap_or_else(|| Path::new("/"))
    }
}

impl fmt::Debug for FilePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An account a daemon drops to: numeric uid and gid (docs/50 §7.1: no
/// name-service lookup).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    /// The uid.
    pub uid: u32,
    /// The gid.
    pub gid: u32,
}

/// The accounts of the processes (docs/51 §4.3: "numeric uids/gids for the
/// seven accounts").
/// Spec: docs/50 §2.4 (one account per process), R50-3 (uid 0 never
/// mapped); docs/51 §4.3 step 1, §4.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accounts {
    /// keyd.
    pub keyd: Account,
    /// dird (owns the database file, docs/50 §6.4).
    pub dird: Account,
    /// kdc.
    pub kdc: Account,
    /// ldap-front.
    pub ldap_front: Account,
    /// auditd.
    pub auditd: Account,
    /// admind.
    pub admind: Account,
    /// keyadm (a tool started directly as its account, no gid needed —
    /// docs/questions/Q-347 item 2).
    pub keyadm_uid: u32,
    /// The group admitted to `admin.sock`'s directory (docs/51 §4.6).
    pub admin_socket_group: u32,
}

/// Every path the run writes or names. Each file target must be absent;
/// the staging directory must be absent; their parents must exist.
/// Spec: docs/51 §4.3 ("paths (database, integrity key, policy, audit log,
/// socket directories, the operator's TLS certificate and key)"), steps 3,
/// 9; §4.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The staging directory (created, then removed at the end).
    pub staging: FilePath,
    /// dird's database (`database_path`).
    pub database: FilePath,
    /// The development integrity key (`integrity_key_path`).
    pub integrity_key: FilePath,
    /// The policy file (`policy_store_path`, dird and kdc).
    pub policy: FilePath,
    /// The manifest.
    pub manifest: FilePath,
    /// auditd's log (named in its configuration; not created here).
    pub audit_log: FilePath,
    /// keyd's configuration file.
    pub keyd_config: FilePath,
    /// dird's configuration file.
    pub dird_config: FilePath,
    /// kdc's configuration file.
    pub kdc_config: FilePath,
    /// ldap-front's configuration file.
    pub ldap_front_config: FilePath,
    /// auditd's configuration file.
    pub auditd_config: FilePath,
    /// admind's configuration file.
    pub admind_config: FilePath,
    /// keyadm's configuration file.
    pub keyadm_config: FilePath,
    /// `keyd.sock`.
    pub keyd_socket: FilePath,
    /// `dird-kdc.sock`.
    pub dird_kdc_socket: FilePath,
    /// `dird-ldap.sock`.
    pub dird_ldap_socket: FilePath,
    /// `dird-admin.sock`.
    pub dird_admin_socket: FilePath,
    /// `audit.sock`.
    pub audit_socket: FilePath,
    /// `admin.sock`.
    pub admin_socket: FilePath,
    /// The operator's DC certificate (named in ldap-front's file only).
    pub tls_certificate: FilePath,
    /// The operator's DC private key (named in ldap-front's file only).
    pub tls_private_key: FilePath,
}

/// The network settings of the configuration files, in the spelling
/// crates/config parses (every value is parsed back before anything is
/// written). Spec: docs/50 §4.1, §4.2, §7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    /// kdc's `listen` addresses (at least one).
    pub kdc_listen: Vec<String>,
    /// ldap-front's `ldap_listen` addresses.
    pub ldap_listen: Vec<String>,
    /// ldap-front's `ldaps_listen` addresses.
    pub ldaps_listen: Vec<String>,
    /// `internal_networks` (dird and kdc).
    pub internal_networks: Vec<String>,
}

/// The names chosen at provisioning — never hard-coded (docs/47 §6.3).
/// Spec: docs/51 §4.3 ("names chosen at provisioning … Tier-0 OU, Tier-0
/// group, bootstrap group, workstations OU (optional), the
/// sAMAccountNames of the first administrators"); A-79 (the name rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    /// The Tier-0 OU's `ou`.
    pub tier0_ou: String,
    /// The workstations OU's `ou`, if any.
    pub workstations_ou: Option<String>,
    /// The Tier-0 group's sAMAccountName (and cn).
    pub tier0_group: String,
    /// The bootstrap group's sAMAccountName (and cn).
    pub bootstrap_group: String,
    /// The DC's short name: its computer object's cn; sAMAccountName =
    /// name ‖ "$".
    pub dc_name: String,
    /// The LDAP service object's cn; sAMAccountName = name ‖ "$".
    pub ldap_service_name: String,
    /// The admin service object's cn; sAMAccountName = name ‖ "$".
    pub admin_service_name: String,
    /// The first administrators' sAMAccountNames (2 ..= 8).
    pub first_admins: Vec<String>,
}

/// The whole input of `provision domain`.
/// Spec: docs/51 §4.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainInput {
    /// The realm: the domain's DNS name in upper case.
    pub realm: String,
    /// The naming context's labels n1 … nk, leaf first.
    pub naming_context: Vec<String>,
    /// The DC's host name (lower case).
    pub dc_fqdn: String,
    /// The accounts.
    pub accounts: Accounts,
    /// The paths.
    pub paths: Paths,
    /// The network settings.
    pub network: Network,
    /// The names.
    pub names: Names,
}

/// What is wrong with the input. Fixed text: no value is echoed (A-60 rule
/// for configuration errors; nothing here is secret, but the rule keeps
/// every message reviewable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputErrorKind {
    /// Not a path of the accepted form.
    Path,
    /// The realm is not a valid Kerberos realm.
    Realm,
    /// The naming context's labels are refused.
    NamingContext,
    /// The realm is not the naming context's DNS name in upper case.
    RealmMismatch,
    /// The DC host name is refused (lower-case labels only).
    HostName,
    /// A uid or gid is 0 or all-ones.
    ReservedId,
    /// Two processes share a uid.
    DuplicateUid,
    /// A name breaks its [MS-SAMR] / docs/46 rule (A-79).
    Name,
    /// A name is "krbtgt" (any case) where it is not the krbtgt account.
    ReservedName,
    /// Two sAMAccountNames are equal (ASCII case folded).
    DuplicateAccountName,
    /// Two children of one parent have the same RDN (ASCII case folded).
    DuplicateRdn,
    /// Fewer than two first administrators: there is no single-administrator
    /// mode (P-22 item 3).
    TooFewFirstAdmins,
    /// More first administrators than the manifest holds.
    TooManyFirstAdmins,
    /// Two settings name the same path.
    DuplicatePath,
    /// Two servers' sockets share a directory (docs/50 §3.1: each socket in
    /// its own directory).
    SharedSocketDirectory,
    /// A network list item is empty or holds a separator.
    NetworkItem,
    /// No kdc listener, or neither LDAP nor LDAPS listener.
    MissingListener,
}

/// An input error: the field (the command-line flag's name) and the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InputError {
    /// The field.
    pub field: &'static str,
    /// The rule broken.
    pub kind: InputErrorKind,
}

impl InputError {
    pub(crate) const fn new(field: &'static str, kind: InputErrorKind) -> InputError {
        InputError { field, kind }
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rule = match self.kind {
            InputErrorKind::Path => "not an absolute path of A-Z a-z 0-9 . _ - components",
            InputErrorKind::Realm => "not a valid realm",
            InputErrorKind::NamingContext => "naming context refused",
            InputErrorKind::RealmMismatch => {
                "realm is not the naming context's DNS name in upper case"
            }
            InputErrorKind::HostName => "host name refused (lower-case DNS labels)",
            InputErrorKind::ReservedId => "uid or gid 0 or all-ones",
            InputErrorKind::DuplicateUid => "uid used by two processes",
            InputErrorKind::Name => "name breaks its rule",
            InputErrorKind::ReservedName => "name reserved for the krbtgt account",
            InputErrorKind::DuplicateAccountName => "sAMAccountName used twice",
            InputErrorKind::DuplicateRdn => "two objects with one name under one parent",
            InputErrorKind::TooFewFirstAdmins => "at least two first administrators are required",
            InputErrorKind::TooManyFirstAdmins => "too many first administrators",
            InputErrorKind::DuplicatePath => "path used twice",
            InputErrorKind::SharedSocketDirectory => "two sockets share a directory",
            InputErrorKind::NetworkItem => "network item empty or holds a separator",
            InputErrorKind::MissingListener => "listener missing",
        };
        write!(f, "{}: {rule}", self.field)
    }
}

impl std::error::Error for InputError {}

/// The facts the plan needs once the input passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Checked {
    pub(crate) realm: Realm,
    pub(crate) naming_context: NamingContext,
}

/// A uid or gid that is neither 0 nor all-ones.
/// Spec: docs/50 R50-3 ("uid 0 is never mapped"); Q-230 item 6.
const fn valid_id(id: u32) -> bool {
    id != 0 && id != ALL_ONES_ID
}

/// `true` if `items` holds two equal values after ASCII case folding.
fn has_folded_duplicate(items: &[&str]) -> bool {
    items.iter().enumerate().any(|(i, a)| {
        items
            .get(i + 1..)
            .unwrap_or_default()
            .iter()
            .any(|b| a.eq_ignore_ascii_case(b))
    })
}

impl DomainInput {
    /// Every check of step 1 that needs no filesystem access (docs/51 §4.3
    /// step 1): uids distinct and not 0 (R50-3, A-60); realm = the DNS name
    /// in upper case and the NC labels accepted by `NamingContext::new`
    /// (docs/47 §3.3 item 3; A-55); every name by the rules of §11 (A-79,
    /// through directory-admin's own checks); at least two first
    /// administrators (P-22); paths well formed and distinct; each socket
    /// in its own directory (docs/50 §3.1).
    ///
    /// # Errors
    /// The first [`InputError`] found.
    ///
    /// Spec: docs/51 §4.3 step 1, §11; docs/50 §2.4, §3.1, R50-3; A-55;
    /// A-60; A-79; P-22.
    pub(crate) fn check(&self) -> Result<Checked, InputError> {
        let naming_context = NamingContext::new(&self.naming_context)
            .map_err(|_| InputError::new("naming-context", InputErrorKind::NamingContext))?;
        let realm =
            Realm::new(&self.realm).map_err(|_| InputError::new("realm", InputErrorKind::Realm))?;
        // docs/47 §3.3 item 3: the realm is the DNS name "converted to
        // uppercase"; directory-pip and dird refuse anything else (A-53).
        if naming_context.dns_name().to_ascii_uppercase().as_bytes() != realm.as_bytes() {
            return Err(InputError::new("realm", InputErrorKind::RealmMismatch));
        }
        // RFC 4120 §6.2.1 ("MUST be lowercase"), through directory-admin's
        // dNSHostName rule (the host of every service SPN, Q-355 item 3).
        if !dns_host_name_ok(&self.dc_fqdn) {
            return Err(InputError::new("dc-fqdn", InputErrorKind::HostName));
        }
        self.check_accounts()?;
        self.check_names()?;
        self.check_paths()?;
        self.check_network()?;
        Ok(Checked {
            realm,
            naming_context,
        })
    }

    /// uids: never 0 or all-ones, one per process (keyadm included); gids:
    /// never 0 or all-ones.
    /// Spec: docs/50 §2.4, R50-3, §7.1; A-57 (two uids for administration);
    /// A-60.
    fn check_accounts(&self) -> Result<(), InputError> {
        let a = &self.accounts;
        let accounts = [
            ("keyd-account", a.keyd),
            ("dird-account", a.dird),
            ("kdc-account", a.kdc),
            ("ldap-front-account", a.ldap_front),
            ("auditd-account", a.auditd),
            ("admind-account", a.admind),
        ];
        let mut uids: Vec<(&'static str, u32)> = Vec::with_capacity(accounts.len() + 1);
        for (field, account) in accounts {
            if !valid_id(account.uid) || !valid_id(account.gid) {
                return Err(InputError::new(field, InputErrorKind::ReservedId));
            }
            uids.push((field, account.uid));
        }
        if !valid_id(a.keyadm_uid) {
            return Err(InputError::new("keyadm-uid", InputErrorKind::ReservedId));
        }
        uids.push(("keyadm-uid", a.keyadm_uid));
        if !valid_id(a.admin_socket_group) {
            return Err(InputError::new(
                "admin-socket-group",
                InputErrorKind::ReservedId,
            ));
        }
        for (i, (field, uid)) in uids.iter().enumerate() {
            if uids
                .get(i + 1..)
                .unwrap_or_default()
                .iter()
                .any(|(_, other)| other == uid)
            {
                return Err(InputError::new(field, InputErrorKind::DuplicateUid));
            }
        }
        Ok(())
    }

    /// The names (docs/51 §11, A-79 — directory-admin's checks; the
    /// manifest's first-administrator rule, Q-345 item 6: no space), the
    /// first-administrator count (P-22), the reserved name "krbtgt", one
    /// sAMAccountName per object and one RDN per parent.
    /// Spec: [MS-SAMR] 3.1.1.6 items 8-14, 3.1.1.8.4 item 2 (unique
    /// sAMAccountName); docs/46 §5.4, §8.3 item 3 (one RDN per parent),
    /// §8.5; docs/51 §11; A-79; P-22; Q-345 items 6-7.
    fn check_names(&self) -> Result<(), InputError> {
        let n = &self.names;
        let name = |field, ok: bool| {
            if ok {
                Ok(())
            } else {
                Err(InputError::new(field, InputErrorKind::Name))
            }
        };
        name("tier0-ou", rdn_value_ok(&n.tier0_ou))?;
        if let Some(ws) = &n.workstations_ou {
            name("workstations-ou", rdn_value_ok(ws))?;
        }
        name("tier0-group", group_sam_ok(&n.tier0_group))?;
        name("bootstrap-group", group_sam_ok(&n.bootstrap_group))?;
        name("dc-name", computer_name_ok(&n.dc_name))?;
        name("ldap-service-name", computer_name_ok(&n.ldap_service_name))?;
        name(
            "admin-service-name",
            computer_name_ok(&n.admin_service_name),
        )?;
        // The two service SPNs (docs/51 §4.3 step 5; A-73) pass the
        // runtime's own SPN rule: `service "/" host`, host = the object's
        // dNSHostName (the DC's FQDN), lower case, service not "krbtgt"
        // (directory-admin `spn_ok`; Q-355 item 3).
        for class in [LDAP_SERVICE_CLASS, ADMIN_SERVICE_CLASS] {
            let spn = format!("{class}/{}", self.dc_fqdn);
            if !spn_ok(&spn, &self.dc_fqdn) {
                return Err(InputError::new("dc-fqdn", InputErrorKind::HostName));
            }
        }
        if n.first_admins.len() < MIN_FIRST_ADMINS {
            return Err(InputError::new(
                "first-admin",
                InputErrorKind::TooFewFirstAdmins,
            ));
        }
        if n.first_admins.len() > MAX_FIRST_ADMINS {
            return Err(InputError::new(
                "first-admin",
                InputErrorKind::TooManyFirstAdmins,
            ));
        }
        for admin in &n.first_admins {
            // Q-345 item 6 (decided A-86): no space in a first
            // administrator's name — stricter than [MS-SAMR] item 8.
            name(
                "first-admin",
                user_sam_ok(admin) && !admin.bytes().any(|b| b == b' '),
            )?;
        }
        let reserved = [
            ("tier0-group", n.tier0_group.as_str()),
            ("bootstrap-group", n.bootstrap_group.as_str()),
        ]
        .into_iter()
        .chain(n.first_admins.iter().map(|a| ("first-admin", a.as_str())));
        for (field, value) in reserved {
            if value.eq_ignore_ascii_case(KRBTGT_NAME) {
                return Err(InputError::new(field, InputErrorKind::ReservedName));
            }
        }
        // One sAMAccountName per object (the unique index, docs/46 §8.5,
        // folds A–Z — Q-080).
        let computers = [
            computer_sam(&n.dc_name),
            computer_sam(&n.ldap_service_name),
            computer_sam(&n.admin_service_name),
        ];
        let mut sams: Vec<&str> = vec![KRBTGT_NAME, &n.tier0_group, &n.bootstrap_group];
        sams.extend(computers.iter().map(String::as_str));
        sams.extend(n.first_admins.iter().map(String::as_str));
        if has_folded_duplicate(&sams) {
            return Err(InputError::new(
                "first-admin",
                InputErrorKind::DuplicateAccountName,
            ));
        }
        // One RDN per parent (docs/46 §8.3 item 3; dirstore `NameExists`).
        let mut under_root: Vec<&str> = vec![&n.tier0_ou];
        let mut under_tier0: Vec<&str> = vec![
            KRBTGT_NAME,
            &n.dc_name,
            &n.ldap_service_name,
            &n.admin_service_name,
            &n.tier0_group,
        ];
        under_tier0.extend(n.first_admins.iter().map(String::as_str));
        match &n.workstations_ou {
            Some(ws) => under_root.push(ws),
            None => under_root.push(&n.bootstrap_group),
        }
        if has_folded_duplicate(&under_root) || has_folded_duplicate(&under_tier0) {
            return Err(InputError::new("tier0-ou", InputErrorKind::DuplicateRdn));
        }
        Ok(())
    }

    /// Every file target, the staging directory and every named path are
    /// distinct; each socket lies in its own directory.
    /// Spec: docs/51 §4.3 steps 3, 9; docs/50 §3.1 ("each socket in its own
    /// directory, owned by the server's uid"); Q-230 item 16.
    fn check_paths(&self) -> Result<(), InputError> {
        let p = &self.paths;
        let named: [(&'static str, &FilePath); 21] = [
            ("staging-dir", &p.staging),
            ("database-path", &p.database),
            ("integrity-key-path", &p.integrity_key),
            ("policy-path", &p.policy),
            ("manifest-path", &p.manifest),
            ("audit-log-path", &p.audit_log),
            ("keyd-config", &p.keyd_config),
            ("dird-config", &p.dird_config),
            ("kdc-config", &p.kdc_config),
            ("ldap-front-config", &p.ldap_front_config),
            ("auditd-config", &p.auditd_config),
            ("admind-config", &p.admind_config),
            ("keyadm-config", &p.keyadm_config),
            ("keyd-socket", &p.keyd_socket),
            ("dird-kdc-socket", &p.dird_kdc_socket),
            ("dird-ldap-socket", &p.dird_ldap_socket),
            ("dird-admin-socket", &p.dird_admin_socket),
            ("audit-socket", &p.audit_socket),
            ("admin-socket", &p.admin_socket),
            ("tls-certificate-path", &p.tls_certificate),
            ("tls-private-key-path", &p.tls_private_key),
        ];
        for (i, (field, path)) in named.iter().enumerate() {
            let rest = named.get(i + 1..).unwrap_or_default();
            if rest.iter().any(|(_, other)| other == path) {
                return Err(InputError::new(field, InputErrorKind::DuplicatePath));
            }
            // Nothing may live inside the staging directory, which is
            // removed at the end.
            if i > 0 && path.as_path().starts_with(p.staging.as_path()) {
                return Err(InputError::new(field, InputErrorKind::DuplicatePath));
            }
        }
        let sockets = [
            ("keyd-socket", &p.keyd_socket),
            ("dird-kdc-socket", &p.dird_kdc_socket),
            ("dird-ldap-socket", &p.dird_ldap_socket),
            ("dird-admin-socket", &p.dird_admin_socket),
            ("audit-socket", &p.audit_socket),
            ("admin-socket", &p.admin_socket),
        ];
        for (i, (field, socket)) in sockets.iter().enumerate() {
            let rest = sockets.get(i + 1..).unwrap_or_default();
            if rest
                .iter()
                .any(|(_, other)| other.parent() == socket.parent())
            {
                return Err(InputError::new(
                    field,
                    InputErrorKind::SharedSocketDirectory,
                ));
            }
        }
        Ok(())
    }

    /// Network items are non-empty and hold no list separator (they are
    /// written as `", "`-separated lists, crates/config); kdc needs a
    /// listener, ldap-front at least one of LDAP / LDAPS (crates/config
    /// re-checks every address).
    /// Spec: docs/50 §4.1, §4.2, §7.1.
    fn check_network(&self) -> Result<(), InputError> {
        let n = &self.network;
        let lists: [(&'static str, &Vec<String>); 4] = [
            ("kdc-listen", &n.kdc_listen),
            ("ldap-listen", &n.ldap_listen),
            ("ldaps-listen", &n.ldaps_listen),
            ("internal-network", &n.internal_networks),
        ];
        for (field, items) in lists {
            if items
                .iter()
                .any(|item| item.is_empty() || item.bytes().any(|b| b == b',' || b == b' '))
            {
                return Err(InputError::new(field, InputErrorKind::NetworkItem));
            }
        }
        if n.kdc_listen.is_empty() {
            return Err(InputError::new(
                "kdc-listen",
                InputErrorKind::MissingListener,
            ));
        }
        if n.ldap_listen.is_empty() && n.ldaps_listen.is_empty() {
            return Err(InputError::new(
                "ldaps-listen",
                InputErrorKind::MissingListener,
            ));
        }
        Ok(())
    }
}
