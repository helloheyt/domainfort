//! The command line of the `provision` binary.
//!
//! ```text
//! provision domain --realm <REALM> --naming-context dc=<l1>,…,dc=<lk> \
//!     --dc-fqdn <host> --dc-name <name> \
//!     --ldap-service-name <name> --admin-service-name <name> \
//!     --change-password-service-name <name> \
//!     --tier0-ou <ou> [--workstations-ou <ou>] \
//!     --tier0-group <name> --bootstrap-group <name> \
//!     --first-admin <sam> --first-admin <sam> [--first-admin <sam> …] \
//!     --keyd-account <uid>:<gid> --dird-account <uid>:<gid> \
//!     --kdc-account <uid>:<gid> --ldap-front-account <uid>:<gid> \
//!     --auditd-account <uid>:<gid> --admind-account <uid>:<gid> \
//!     --kpasswd-front-account <uid>:<gid> --dnsd-account <uid>:<gid> \
//!     --keyadm-uid <uid> --admin-socket-group <gid> \
//!     --staging-dir <path> --database-path <path> --integrity-key-path <path> \
//!     --policy-path <path> --manifest-path <path> --audit-log-path <path> \
//!     --keyd-config <path> --dird-config <path> --kdc-config <path> \
//!     --ldap-front-config <path> --auditd-config <path> \
//!     --admind-config <path> --keyadm-config <path> \
//!     --kpasswd-front-config <path> --dnsd-config <path> \
//!     --keyd-socket <path> --dird-kdc-socket <path> --dird-ldap-socket <path> \
//!     --dird-admin-socket <path> --dird-kpasswd-socket <path> \
//!     --dird-dns-socket <path> --audit-socket <path> --admin-socket <path> \
//!     --tls-certificate-path <path> --tls-private-key-path <path> \
//!     --policy-next-path <path> \
//!     --kdc-listen <addr:port> [--kdc-listen …] \
//!     [--ldap-listen <addr:port> …] [--ldaps-listen <addr:port> …] \
//!     --kpasswd-listen <addr:port> [--kpasswd-listen …] \
//!     --dnsd-listen <addr:port> [--dnsd-listen …] \
//!     --internal-network <addr/prefix> [--internal-network …]
//!
//! provision policy --policy-path <path> <change> [<change> …]
//!   <change> := --add-principal <SID> <Tier0|Tier1|Tier2>
//!             | --remove-principal <SID>
//!             | --add-subtree <Tier0|Tier1|Tier2> <att=value> [<att=value> …]
//!             | --remove-subtree <att=value> [<att=value> …]
//!
//! provision policy --activate-next --dird-config <path>
//!
//! provision first-admin-secret --manifest-path <path> --admind-config <path> \
//!     [--password-file <sAMAccountName>=<path> …]
//! ```
//!
//! Every value is explicit: there is no default path, name, account or
//! address, no environment variable and no input file. **No secret is ever
//! an argument** (docs/21 D95 as cited in docs/51 §3: "secrets never in
//! argv/env") — `domain` and `policy` take none, and `first-admin-secret`
//! takes the first administrators' passwords only from a terminal (echo
//! off, entered twice) or from a password **file** named by its path
//! (docs/51 §4.4; module crate::first_admin). Every flag of `domain` and
//! `first-admin-secret` but the repeatable ones appears at most once; an
//! unknown flag, a missing value or a value that starts with `--` is a
//! usage error. A subtree's DN is given as its RDN components, leaf first,
//! one argument each (an RDN value may hold a comma; an `att=value`
//! component never starts with `-`). A `--password-file` value is the
//! sAMAccountName, `=`, and the file's absolute path; the name is matched
//! against the manifest when the command runs (one file for every first
//! administrator, or none).
//!
//! `policy --activate-next` (task A16, docs/51 §5.10) takes dird's
//! configuration file and nothing else: the installed policy
//! (`policy_store_path`), dird's `policy.next` (`policy_next_path`) and
//! dird's account (`run_as_uid`, the file's expected owner) all come from
//! that one file — the file dird itself reads — so root's activation and
//! dird cannot disagree on a path or an owner (module crate::update).
//!
//! Task K9 adds the change-password service object's name (docs/53 §5.2),
//! the two network fronts' accounts, files and listeners (kpasswd-front —
//! docs/53 §3.3; dnsd — docs/54 §4.3, §4.7) and the two dird sockets they
//! name (`dird-kpasswd.sock`, docs/53 §4.3; `dird-dns.sock`, docs/54 §4.6).
//!
//! Spec: docs/51 §4.3 (the input; step 12), §4.4 (the password source),
//! §5.10 (`provision policy`), §3 (D95); docs/50 §7.1 (numeric ids, no
//! NSS); docs/53 §3.3, §4.3, §5.2, §10 (K9); docs/54 §4.3, §4.6, §4.7;
//! A-80; P-22; docs/questions/Q-411, Q-973.

use core::fmt;
use std::collections::BTreeMap;
use std::ffi::OsString;

use dtyp::Sid;
use pdp::{Dn, Tier};

use crate::first_admin::{FirstAdminSecret, PasswordFileArg};
use crate::input::{
    Account, Accounts, DomainInput, FilePath, InputError, InputErrorKind, Names, Network, Paths,
};
use crate::policy::TierChange;

/// The most arguments accepted. Project choice (bounded parsing,
/// docs/CLEAN-ROOM.md): the largest `domain` command has under 100.
pub const MAX_ARGUMENTS: usize = 512;

/// The longest argument accepted, in octets (the configuration format's
/// line bound, docs/50 §7.1).
pub const MAX_ARGUMENT_OCTETS: usize = 1024;

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `provision domain …`.
    Domain(Box<DomainInput>),
    /// `provision policy …`.
    Policy {
        /// The policy file.
        path: FilePath,
        /// The edits, in order.
        changes: Vec<TierChange>,
    },
    /// `provision policy --activate-next --dird-config <path>` (task A16).
    ActivatePolicyNext {
        /// dird's configuration file.
        dird_config: FilePath,
    },
    /// `provision first-admin-secret …`.
    FirstAdminSecret(FirstAdminSecret),
}

/// A command-line error. Fixed text; a flag name at most.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliError {
    /// The command line does not have the documented shape.
    Usage(&'static str),
    /// A value broke its rule.
    Input(InputError),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Usage(what) => write!(f, "usage: {what}"),
            CliError::Input(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CliError {}

/// How often a `domain` flag may appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arity {
    /// Exactly once.
    One,
    /// At most once.
    Optional,
    /// Any number of times.
    Repeated,
}

/// The closed flag table of `domain`.
const DOMAIN_FLAGS: &[(&str, Arity)] = &[
    ("--realm", Arity::One),
    ("--naming-context", Arity::One),
    ("--dc-fqdn", Arity::One),
    ("--dc-name", Arity::One),
    ("--ldap-service-name", Arity::One),
    ("--admin-service-name", Arity::One),
    ("--change-password-service-name", Arity::One),
    ("--tier0-ou", Arity::One),
    ("--workstations-ou", Arity::Optional),
    ("--tier0-group", Arity::One),
    ("--bootstrap-group", Arity::One),
    ("--first-admin", Arity::Repeated),
    ("--keyd-account", Arity::One),
    ("--dird-account", Arity::One),
    ("--kdc-account", Arity::One),
    ("--ldap-front-account", Arity::One),
    ("--auditd-account", Arity::One),
    ("--admind-account", Arity::One),
    ("--kpasswd-front-account", Arity::One),
    ("--dnsd-account", Arity::One),
    ("--keyadm-uid", Arity::One),
    ("--admin-socket-group", Arity::One),
    ("--staging-dir", Arity::One),
    ("--database-path", Arity::One),
    ("--integrity-key-path", Arity::One),
    ("--policy-path", Arity::One),
    ("--manifest-path", Arity::One),
    ("--audit-log-path", Arity::One),
    ("--keyd-config", Arity::One),
    ("--dird-config", Arity::One),
    ("--kdc-config", Arity::One),
    ("--ldap-front-config", Arity::One),
    ("--auditd-config", Arity::One),
    ("--admind-config", Arity::One),
    ("--keyadm-config", Arity::One),
    ("--kpasswd-front-config", Arity::One),
    ("--dnsd-config", Arity::One),
    ("--keyd-socket", Arity::One),
    ("--dird-kdc-socket", Arity::One),
    ("--dird-ldap-socket", Arity::One),
    ("--dird-admin-socket", Arity::One),
    ("--dird-kpasswd-socket", Arity::One),
    ("--dird-dns-socket", Arity::One),
    ("--audit-socket", Arity::One),
    ("--admin-socket", Arity::One),
    ("--tls-certificate-path", Arity::One),
    ("--tls-private-key-path", Arity::One),
    ("--policy-next-path", Arity::One),
    ("--kdc-listen", Arity::Repeated),
    ("--ldap-listen", Arity::Repeated),
    ("--ldaps-listen", Arity::Repeated),
    ("--kpasswd-listen", Arity::Repeated),
    ("--dnsd-listen", Arity::Repeated),
    ("--internal-network", Arity::Repeated),
];

/// The arguments as checked text: valid UTF-8, printable ASCII only
/// (0x20..=0x7E), bounded in count and length.
/// Spec: docs/50 §7.1 (printable ASCII); docs/CLEAN-ROOM.md (bounded).
fn texts<I: IntoIterator<Item = OsString>>(args: I) -> Result<Vec<String>, CliError> {
    let mut out = Vec::new();
    for arg in args {
        if out.len() == MAX_ARGUMENTS {
            return Err(CliError::Usage("too many arguments"));
        }
        let text = arg
            .into_string()
            .map_err(|_| CliError::Usage("arguments must be printable ASCII"))?;
        if text.len() > MAX_ARGUMENT_OCTETS || !text.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
            return Err(CliError::Usage("arguments must be printable ASCII"));
        }
        out.push(text);
    }
    Ok(out)
}

/// Parse the arguments after the program name.
///
/// # Errors
/// [`CliError`].
///
/// Spec: module documentation.
pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Command, CliError> {
    let args = texts(args)?;
    match args.split_first() {
        Some((command, rest)) if command == "domain" => {
            parse_domain(rest).map(|input| Command::Domain(Box::new(input)))
        }
        Some((command, rest)) if command == "policy" => parse_policy(rest),
        Some((command, rest)) if command == "first-admin-secret" => {
            parse_first_admin_secret(rest).map(Command::FirstAdminSecret)
        }
        _ => Err(CliError::Usage(
            "provision domain … | provision policy … | provision first-admin-secret …",
        )),
    }
}

/// A canonical unsigned decimal (no sign, no leading zero), as crates/config
/// reads ids (docs/50 §7.1).
fn decimal(text: &str) -> Option<u32> {
    let canonical = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if canonical {
        text.parse().ok()
    } else {
        None
    }
}

/// The `domain` flags and their values.
struct Flags(BTreeMap<&'static str, Vec<String>>);

impl Flags {
    fn one(&self, flag: &'static str) -> Result<&str, CliError> {
        self.0
            .get(flag)
            .and_then(|v| v.first())
            .map(String::as_str)
            .ok_or(CliError::Usage("a required flag is missing"))
    }

    fn optional(&self, flag: &'static str) -> Option<String> {
        self.0.get(flag).and_then(|v| v.first()).cloned()
    }

    fn all(&self, flag: &'static str) -> Vec<String> {
        self.0.get(flag).cloned().unwrap_or_default()
    }

    fn path(&self, flag: &'static str) -> Result<FilePath, CliError> {
        let field = flag.trim_start_matches('-');
        FilePath::parse(self.one(flag)?).map_err(|kind| CliError::Input(InputError { field, kind }))
    }

    fn account(&self, flag: &'static str) -> Result<Account, CliError> {
        let field = flag.trim_start_matches('-');
        let bad = CliError::Input(InputError {
            field,
            kind: InputErrorKind::ReservedId,
        });
        let (uid, gid) = self.one(flag)?.split_once(':').ok_or(bad)?;
        Ok(Account {
            uid: decimal(uid).ok_or(bad)?,
            gid: decimal(gid).ok_or(bad)?,
        })
    }

    fn id(&self, flag: &'static str) -> Result<u32, CliError> {
        let field = flag.trim_start_matches('-');
        decimal(self.one(flag)?).ok_or(CliError::Input(InputError {
            field,
            kind: InputErrorKind::ReservedId,
        }))
    }
}

/// `provision domain …`.
fn parse_domain(args: &[String]) -> Result<DomainInput, CliError> {
    let mut flags: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let &(name, arity) = DOMAIN_FLAGS
            .iter()
            .find(|(name, _)| name == flag)
            .ok_or(CliError::Usage("unknown flag"))?;
        let value = rest
            .next()
            .filter(|v| !v.starts_with("--"))
            .ok_or(CliError::Usage("a flag has no value"))?;
        let values = flags.entry(name).or_default();
        if arity != Arity::Repeated && !values.is_empty() {
            return Err(CliError::Usage("a flag appears twice"));
        }
        values.push(value.clone());
    }
    for (name, arity) in DOMAIN_FLAGS {
        if *arity == Arity::One && !flags.contains_key(name) {
            return Err(CliError::Usage("a required flag is missing"));
        }
    }
    let f = Flags(flags);
    let naming_context = f
        .one("--naming-context")?
        .split(',')
        .map(|component| {
            component
                .strip_prefix("dc=")
                .map(str::to_owned)
                .ok_or(CliError::Input(InputError {
                    field: "naming-context",
                    kind: InputErrorKind::NamingContext,
                }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DomainInput {
        realm: f.one("--realm")?.to_owned(),
        naming_context,
        dc_fqdn: f.one("--dc-fqdn")?.to_owned(),
        accounts: Accounts {
            keyd: f.account("--keyd-account")?,
            dird: f.account("--dird-account")?,
            kdc: f.account("--kdc-account")?,
            ldap_front: f.account("--ldap-front-account")?,
            auditd: f.account("--auditd-account")?,
            admind: f.account("--admind-account")?,
            kpasswd_front: f.account("--kpasswd-front-account")?,
            dnsd: f.account("--dnsd-account")?,
            keyadm_uid: f.id("--keyadm-uid")?,
            admin_socket_group: f.id("--admin-socket-group")?,
        },
        paths: Paths {
            staging: f.path("--staging-dir")?,
            database: f.path("--database-path")?,
            integrity_key: f.path("--integrity-key-path")?,
            policy: f.path("--policy-path")?,
            manifest: f.path("--manifest-path")?,
            audit_log: f.path("--audit-log-path")?,
            keyd_config: f.path("--keyd-config")?,
            dird_config: f.path("--dird-config")?,
            kdc_config: f.path("--kdc-config")?,
            ldap_front_config: f.path("--ldap-front-config")?,
            auditd_config: f.path("--auditd-config")?,
            admind_config: f.path("--admind-config")?,
            keyadm_config: f.path("--keyadm-config")?,
            kpasswd_front_config: f.path("--kpasswd-front-config")?,
            dnsd_config: f.path("--dnsd-config")?,
            keyd_socket: f.path("--keyd-socket")?,
            dird_kdc_socket: f.path("--dird-kdc-socket")?,
            dird_ldap_socket: f.path("--dird-ldap-socket")?,
            dird_admin_socket: f.path("--dird-admin-socket")?,
            dird_kpasswd_socket: f.path("--dird-kpasswd-socket")?,
            dird_dns_socket: f.path("--dird-dns-socket")?,
            audit_socket: f.path("--audit-socket")?,
            admin_socket: f.path("--admin-socket")?,
            tls_certificate: f.path("--tls-certificate-path")?,
            tls_private_key: f.path("--tls-private-key-path")?,
            policy_next: f.path("--policy-next-path")?,
        },
        network: Network {
            kdc_listen: f.all("--kdc-listen"),
            ldap_listen: f.all("--ldap-listen"),
            ldaps_listen: f.all("--ldaps-listen"),
            internal_networks: f.all("--internal-network"),
            kpasswd_listen: f.all("--kpasswd-listen"),
            dnsd_listen: f.all("--dnsd-listen"),
        },
        names: Names {
            tier0_ou: f.one("--tier0-ou")?.to_owned(),
            workstations_ou: f.optional("--workstations-ou"),
            tier0_group: f.one("--tier0-group")?.to_owned(),
            bootstrap_group: f.one("--bootstrap-group")?.to_owned(),
            dc_name: f.one("--dc-name")?.to_owned(),
            ldap_service_name: f.one("--ldap-service-name")?.to_owned(),
            admin_service_name: f.one("--admin-service-name")?.to_owned(),
            change_password_service_name: f.one("--change-password-service-name")?.to_owned(),
            first_admins: f.all("--first-admin"),
        },
    })
}

/// A tier name. Spec: crates/pdp `Tier` (Untiered is never a map row,
/// policy-store).
fn tier(text: &str) -> Result<Tier, CliError> {
    match text {
        "Tier0" => Ok(Tier::Tier0),
        "Tier1" => Ok(Tier::Tier1),
        "Tier2" => Ok(Tier::Tier2),
        _ => Err(CliError::Usage("a tier is Tier0, Tier1 or Tier2")),
    }
}

/// A SID in its string form. Spec: [MS-DTYP] 2.4.2.1 (through dtyp).
fn sid(text: &str) -> Result<Sid, CliError> {
    Sid::parse_sid_string(text).map_err(|_| CliError::Usage("a SID is S-1-…"))
}

/// The RDN components following a subtree flag, up to the next flag.
fn components<'a>(
    rest: &mut core::iter::Peekable<core::slice::Iter<'a, String>>,
) -> Result<Dn, CliError> {
    let mut rdns = Vec::new();
    while let Some(next) = rest.peek() {
        if next.starts_with("--") {
            break;
        }
        rdns.push((*next).clone());
        rest.next();
    }
    if rdns.is_empty() {
        return Err(CliError::Usage("a subtree needs its RDN components"));
    }
    Ok(Dn::new(rdns))
}

/// The value after a flag (never a flag itself).
fn value<'a>(
    rest: &mut core::iter::Peekable<core::slice::Iter<'a, String>>,
) -> Result<&'a String, CliError> {
    rest.next()
        .filter(|v| !v.starts_with("--"))
        .ok_or(CliError::Usage("a flag has no value"))
}

/// `provision policy --activate-next --dird-config <path>` (task A16): the
/// two flags, in either order, each once, and nothing else.
/// Spec: docs/51 §5.10; module documentation.
fn parse_activate(args: &[String]) -> Result<Command, CliError> {
    let usage = CliError::Usage("provision policy --activate-next --dird-config <path>");
    let config = match args {
        [a, b, c] if a == "--activate-next" && b == "--dird-config" => c,
        [a, b, c] if a == "--dird-config" && c == "--activate-next" => b,
        _ => return Err(usage),
    };
    if config.starts_with("--") {
        return Err(usage);
    }
    let dird_config = FilePath::parse(config).map_err(|kind| {
        CliError::Input(InputError {
            field: "dird-config",
            kind,
        })
    })?;
    Ok(Command::ActivatePolicyNext { dird_config })
}

/// `provision policy …`.
fn parse_policy(args: &[String]) -> Result<Command, CliError> {
    if args.iter().any(|a| a == "--activate-next") {
        return parse_activate(args);
    }
    let mut rest = args.iter().peekable();
    let mut path = None;
    let mut changes = Vec::new();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--policy-path" => {
                if path.is_some() {
                    return Err(CliError::Usage("a flag appears twice"));
                }
                path = Some(FilePath::parse(value(&mut rest)?).map_err(|kind| {
                    CliError::Input(InputError {
                        field: "policy-path",
                        kind,
                    })
                })?);
            }
            "--add-principal" => {
                let s = sid(value(&mut rest)?)?;
                let t = tier(value(&mut rest)?)?;
                changes.push(TierChange::AddPrincipal(s, t));
            }
            "--remove-principal" => {
                changes.push(TierChange::RemovePrincipal(sid(value(&mut rest)?)?));
            }
            "--add-subtree" => {
                let t = tier(value(&mut rest)?)?;
                changes.push(TierChange::AddSubtree(components(&mut rest)?, t));
            }
            "--remove-subtree" => changes.push(TierChange::RemoveSubtree(components(&mut rest)?)),
            _ => return Err(CliError::Usage("unknown flag")),
        }
    }
    let path = path.ok_or(CliError::Usage("--policy-path is required"))?;
    if changes.is_empty() {
        return Err(CliError::Usage("at least one change is required"));
    }
    Ok(Command::Policy { path, changes })
}

/// `--password-file <sAMAccountName>=<path>`: split at the first `=`; the
/// name is not empty (it is matched against the manifest when the command
/// runs), the path is a [`FilePath`].
/// Spec: docs/51 §4.4 (source (b)); module documentation.
fn password_file_arg(text: &str) -> Result<PasswordFileArg, CliError> {
    let (sam, path) = text
        .split_once('=')
        .filter(|(sam, _)| !sam.is_empty())
        .ok_or(CliError::Usage(
            "--password-file takes <sAMAccountName>=<path>",
        ))?;
    let path = FilePath::parse(path).map_err(|kind| {
        CliError::Input(InputError {
            field: "password-file",
            kind,
        })
    })?;
    Ok(PasswordFileArg {
        sam: sam.to_owned(),
        path,
    })
}

/// `provision first-admin-secret …`.
/// Spec: docs/51 §4.3 step 12, §4.4; module documentation.
fn parse_first_admin_secret(args: &[String]) -> Result<FirstAdminSecret, CliError> {
    let mut rest = args.iter().peekable();
    let mut manifest = None;
    let mut admind_config = None;
    let mut password_files = Vec::new();
    while let Some(flag) = rest.next() {
        let (slot, field) = match flag.as_str() {
            "--manifest-path" => (&mut manifest, "manifest-path"),
            "--admind-config" => (&mut admind_config, "admind-config"),
            "--password-file" => {
                password_files.push(password_file_arg(value(&mut rest)?)?);
                continue;
            }
            _ => return Err(CliError::Usage("unknown flag")),
        };
        if slot.is_some() {
            return Err(CliError::Usage("a flag appears twice"));
        }
        *slot = Some(
            FilePath::parse(value(&mut rest)?)
                .map_err(|kind| CliError::Input(InputError { field, kind }))?,
        );
    }
    Ok(FirstAdminSecret {
        manifest: manifest.ok_or(CliError::Usage("--manifest-path is required"))?,
        admind_config: admind_config.ok_or(CliError::Usage("--admind-config is required"))?,
        password_files,
    })
}
