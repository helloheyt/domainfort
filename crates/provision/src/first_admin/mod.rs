//! `provision first-admin-secret`: set the first administrators' passwords
//! through keyd, as Role::Directory (docs/51 §4.3 step 12, §4.4, §4.5; §12
//! task A6; R51-1, R51-5, R51-6; decision A-77).
//!
//! # When and by whom
//!
//! Root runs it after `keyadm ceremony` (step 11), with auditd and keyd up;
//! **dird is not required** — it is not contacted at all. docs/47 §9.2's
//! order holds because `provision domain` already wrote the first
//! administrators' `pwdLastSet` (step 5). In development mode keyd keeps
//! keys in memory only (P-17), so steps 11-12 are repeated after every
//! keyd restart (A-77).
//!
//! **The ceremony's grants** (task A15a; docs/51 §5.8 option (b);
//! docs/questions/Q-451): keyd refuses Role::Directory's `set_secret`
//! unless a live, one-time grant names the key set — and dird, which
//! registers the grants of every later password set, does not run yet. So
//! `keyadm ceremony` (Role::Admin) grants each first administrator's
//! **initial** secret, live 15 minutes (`MAX_INITIAL_SECRET_GRANT_SECS`);
//! this command consumes them. Without the ceremony's grant — never run,
//! expired, already consumed, or a key set that exists already — keyd
//! answers its uniform `Denied`, and the report says why that may be. This
//! command itself needs no change: it never names a grant; keyd matches the
//! handle and binding the manifest gives both tools. Against a keyd that
//! still holds the key sets a second run is therefore refused: later
//! password changes go through admind and dird's PDP.
//!
//! # The run ([`run`])
//!
//! 1. **Read**, as root, admind's configuration file and the manifest —
//!    both root-owned, not writable by others, opened without following a
//!    link (module [`root_files`]). From admind's file: the account to drop
//!    to (`run_as_uid` / `run_as_gid`), keyd's socket, uid and deadline,
//!    and `min_password_length` (A-79).
//! 2. **Salts**: `directory_pip::account_salt(realm, User, sAMAccountName)`
//!    for each first administrator — the **same** function the
//!    AccountSource uses for PA-ETYPE-INFO2 (R47-4; docs/47 §3.3).
//! 3. **Sources**: with `--password-file <sAMAccountName>=<path>` — one for
//!    **every** first administrator, none other, none twice — each file is
//!    inspected, opened and checked as the running uid (module
//!    [`password_file`]); without any, standard input must be a terminal
//!    (module [`entry`]). Never argv, never the environment (D95).
//! 4. **Drop** to admind's account (module [`privilege`]: daemon-sandbox,
//!    admind's profile — not dumpable, memory locked, core 0). Nothing of a
//!    password exists before this step.
//! 5. **Passwords**: each file's single line, or each entered twice at the
//!    terminal without echo; each pre-checked by the rule set keyd enforces
//!    (module [`line`], crate admin-password-policy `check_password`, with
//!    admind's `min_password_length`, the sAMAccountName and the realm —
//!    docs/56 §7 P-24; docs/questions/Q-605 item 3, Q-910). **Every**
//!    password is entered and checked before keyd is contacted: a refusal
//!    sends nothing.
//! 6. **keyd**: a `ping` (the client checks keyd's peer uid before anything
//!    is sent, R50-3), then for each first administrator, in the manifest's
//!    order, `set_secret((GUID, PrincipalLongterm), NT-PRINCIPAL
//!    [sAMAccountName], password, account_salt(User))` through
//!    `call_with_fate` (A-90), stopping at the first that does not succeed;
//!    never a retry (module [`keyd`]).
//! 7. **Report** (module [`report`]): handles, bindings, kvnos — never a
//!    password; "outcome unknown" says to check before retrying.
//!
//! # Security
//!
//! The password lives only in zeroizing buffers (the file buffer, the
//! terminal line, [`line::EnteredPassword`], ipc-keyd's `Password` and its
//! encoded frame) and is never printed, logged, put in an error or a
//! `Debug` output. The process is not dumpable and memory-locked while it
//! holds passwords (daemon-sandbox). This crate still links no krb-crypto
//! and no keyd (D182; crates/keyd-types tests/no_crypto_dependency.rs):
//! ipc-keyd's client side and daemon-sandbox are crypto-free.
//!
//! # Residuals (documented, not hidden)
//!
//! - A signal from outside the terminal during a hidden entry ends the
//!   process without restoring the terminal's echo (no signal handler
//!   without `unsafe` or a dependency) — docs/questions/Q-412.
//! - The termios flags' meaning and "a descriptor opened as root stays
//!   readable after the drop" are operating-system semantics not in an
//!   allowed source (P-18): if the latter did not hold, the read fails
//!   closed (nothing sent) — docs/questions/Q-411, Q-412.
//! - Linux only (daemon-sandbox; ipc-keyd's peer credentials); never run on
//!   Linux yet (P-27).
//!
//! # Provenance
//!
//! Written only from, opened in this session: docs/CLEAN-ROOM.md, docs/CLEAN-ROOM.md,
//! specs/SOURCES; docs/51 (whole), docs/47 §3, §9, docs/10 §2, §6, §7, §9,
//! §10, docs/50 §0.3, §6, docs/21 D95; docs/questions PENDING-OWNER (A-15,
//! A-35, A-61, A-73, A-77, A-79, A-86, A-88, A-90, A-92, A-94, P-2, P-12,
//! P-17, P-18, P-24, P-27), Q-296, Q-345, Q-378, Q-400 … Q-409; [MS-SAMR]
//! v20260427 §3.1.1.7.2 (pinned, SHA-256 `083fe00a…8a4e` verified against
//! tools/spec-pin/manifest.json); the public API of this workspace's crates
//! (provision, provision-manifest, config, ipc, ipc-keyd, keyd-types,
//! directory-pip, daemon-sandbox, admin-password-policy; keyadm and
//! admin-daemon as the pattern); the docs.rs API pages of rustix 1.1.6
//! (`termios` and its items, `io::read`, `buffer::Buffer`; P-2) and the std
//! API documentation. No other implementation, password prompt, terminal
//! utility or provisioning tool — its prompts, messages, flags or code —
//! was consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/51 §4.3 steps 5, 11, 12, §4.4, §4.5, §5.8, §12 (A6); docs/47
//! §3.3, §9.1, §9.2; docs/10 §2, §6, §9, §10; docs/50 R50-3, R50-14, §6.4;
//! docs/21 D95; A-35; A-73; A-77; A-79; A-88; A-90; A-94;
//! docs/questions/Q-410 … Q-414.

pub mod entry;
pub mod keyd;
pub mod line;
pub mod password_file;
pub mod privilege;
pub mod report;
pub mod root_files;
pub mod terminal;

use core::fmt;
use std::io::Write;

use directory_pip::{account_salt, AccountKind, SaltError};
use ipc_keyd::{Answer, Call, Password};
use provision_manifest::FirstAdmin;

use crate::input::FilePath;
use entry::{enter_twice, EntryError, Terminal};
use keyd::{classify, KeydAccess, Outcome};
use line::{check_password, EnteredPassword};
use password_file::{open_password_file, FileRefusal, OpenedPasswordFile};
use privilege::{DropError, PrivilegeDrop};
use report::{exit_code, render, AdminKeySet, SecretReport, StepReport, EXIT_NOTHING_SENT};
use root_files::{read_admind_settings, read_manifest, RootFileError};

/// One `--password-file <sAMAccountName>=<path>`.
/// Spec: docs/51 §4.4 (source (b)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordFileArg {
    /// The first administrator's sAMAccountName, as the manifest spells it.
    pub sam: String,
    /// The password file.
    pub path: FilePath,
}

/// The parsed command line of `provision first-admin-secret`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstAdminSecret {
    /// The provisioning manifest (`--manifest-path`).
    pub manifest: FilePath,
    /// admind's configuration file (`--admind-config`).
    pub admind_config: FilePath,
    /// The password files; empty ⇒ the terminal.
    pub password_files: Vec<PasswordFileArg>,
}

/// What the command runs with: the privileged step, the terminal, keyd,
/// and the owners the files must have (0 in production — the binary
/// verified root; the test account in tests).
pub struct Environment<'a, P: ?Sized, T: ?Sized, K: ?Sized> {
    /// The privilege drop.
    pub privilege: &'a mut P,
    /// The terminal (used only without password files).
    pub terminal: &'a mut T,
    /// keyd.
    pub keyd: &'a mut K,
    /// The owner the manifest and admind's configuration must have.
    pub root_uid: u32,
    /// The running uid — the owner a password file must have.
    pub running_uid: u32,
}

/// Why the command stopped before any `set_secret` was sent. Fixed texts,
/// at most a sAMAccountName from the manifest; never a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// admind's configuration file.
    AdmindConfig(RootFileError),
    /// The manifest.
    Manifest(RootFileError),
    /// A first administrator's salt could not be formed.
    Salt {
        /// The administrator.
        sam: String,
        /// Why.
        error: SaltError,
    },
    /// The manifest names no salt, or another salt, for a first
    /// administrator than the directory's salt function gives — keyadm's
    /// ceremony grant binds the manifest's salt (A-102, N4), so keyd would
    /// refuse the `set_secret`.
    SaltMismatch {
        /// The administrator.
        sam: String,
    },
    /// A `--password-file` names no first administrator of the manifest.
    UnknownPasswordFile {
        /// The name given.
        sam: String,
    },
    /// Two `--password-file` name the same administrator.
    DuplicatePasswordFile {
        /// The name given twice.
        sam: String,
    },
    /// Password files were given, but not for this administrator.
    MissingPasswordFile {
        /// The administrator.
        sam: String,
    },
    /// A password file was refused.
    PasswordFile {
        /// The administrator.
        sam: String,
        /// Why.
        refusal: FileRefusal,
    },
    /// No password file was given and standard input is not a terminal.
    NoTerminal,
    /// The privilege drop failed.
    Privilege(DropError),
    /// A terminal entry failed.
    Entry {
        /// The administrator.
        sam: String,
        /// Why.
        error: EntryError,
    },
    /// A password broke the password rules (which one is not said).
    PasswordRules {
        /// The administrator.
        sam: String,
        /// admind's `min_password_length`.
        min_chars: u32,
    },
    /// keyd's client could not be configured.
    KeydClient,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::AdmindConfig(e) => write!(f, "admind's configuration file {e}"),
            Refusal::Manifest(e) => write!(f, "the manifest {e}"),
            Refusal::Salt { sam, error } => {
                write!(f, "the salt of first administrator {sam} cannot be formed: {error}")
            }
            Refusal::SaltMismatch { sam } => write!(
                f,
                "the manifest's salt of first administrator {sam} is missing or not the \
                 directory's (re-run provision domain)"
            ),
            Refusal::UnknownPasswordFile { sam } => write!(
                f,
                "--password-file names {sam}, which is not a first administrator of the manifest"
            ),
            Refusal::DuplicatePasswordFile { sam } => {
                write!(f, "--password-file names {sam} twice")
            }
            Refusal::MissingPasswordFile { sam } => write!(
                f,
                "no --password-file for first administrator {sam} (give one for every first administrator, or none to enter them at the terminal)"
            ),
            Refusal::PasswordFile { sam, refusal } => {
                write!(f, "first administrator {sam}: {refusal}")
            }
            Refusal::NoTerminal => f.write_str(
                "no --password-file was given and standard input is not a terminal",
            ),
            Refusal::Privilege(e) => write!(f, "{e}"),
            Refusal::Entry { sam, error } => {
                write!(f, "first administrator {sam}: {error}")
            }
            Refusal::PasswordRules { sam, min_chars } => write!(
                f,
                "the password for first administrator {sam} does not meet the password rules (at least {min_chars} characters, at most 256 UTF-16 code units and 1024 octets; an ASCII upper-case letter, lower-case letter, digit and special character; no three ascending, descending or repeated characters in a row; not containing the account name, the realm's name or a weak word)"
            ),
            Refusal::KeydClient => f.write_str("keyd's client cannot be configured"),
        }
    }
}

impl std::error::Error for Refusal {}

/// Where one administrator's password comes from.
enum Source {
    /// A password file, opened and checked as root.
    File(OpenedPasswordFile),
    /// The terminal.
    Terminal,
}

/// Step 3 of the run (module documentation): every first administrator's
/// source.
fn sources<T: Terminal + ?Sized>(
    request: &FirstAdminSecret,
    admins: &[FirstAdmin],
    terminal: &T,
    running_uid: u32,
) -> Result<Vec<Source>, Refusal> {
    if request.password_files.is_empty() {
        if !terminal.is_terminal() {
            return Err(Refusal::NoTerminal);
        }
        return Ok(admins.iter().map(|_| Source::Terminal).collect());
    }
    for (i, arg) in request.password_files.iter().enumerate() {
        if !admins.iter().any(|a| a.sam_account_name() == arg.sam) {
            return Err(Refusal::UnknownPasswordFile {
                sam: arg.sam.clone(),
            });
        }
        if request.password_files[..i].iter().any(|o| o.sam == arg.sam) {
            return Err(Refusal::DuplicatePasswordFile {
                sam: arg.sam.clone(),
            });
        }
    }
    let mut out = Vec::with_capacity(admins.len());
    for admin in admins {
        let sam = admin.sam_account_name();
        let arg = request
            .password_files
            .iter()
            .find(|a| a.sam == sam)
            .ok_or_else(|| Refusal::MissingPasswordFile {
                sam: sam.to_owned(),
            })?;
        let opened = open_password_file(arg.path.as_path(), running_uid).map_err(|refusal| {
            Refusal::PasswordFile {
                sam: sam.to_owned(),
                refusal,
            }
        })?;
        out.push(Source::File(opened));
    }
    Ok(out)
}

/// Run `provision first-admin-secret` (module documentation, steps 1-6).
///
/// # Errors
/// [`Refusal`] — and then no `set_secret` was sent. Once keyd is reached
/// the result is the [`SecretReport`], whatever keyd answered.
///
/// Spec: module documentation.
pub fn run<P, T, K>(
    request: &FirstAdminSecret,
    env: &mut Environment<'_, P, T, K>,
) -> Result<SecretReport, Refusal>
where
    P: PrivilegeDrop + ?Sized,
    T: Terminal + ?Sized,
    K: KeydAccess + ?Sized,
{
    // 1. The root-owned inputs.
    let settings = read_admind_settings(request.admind_config.as_path(), env.root_uid)
        .map_err(Refusal::AdmindConfig)?;
    let manifest =
        read_manifest(request.manifest.as_path(), env.root_uid).map_err(Refusal::Manifest)?;
    let admins = manifest.first_admins();

    // 2. The salts — the AccountSource's function (R47-4).
    let mut salts = Vec::with_capacity(admins.len());
    for admin in admins {
        let sam = admin.sam_account_name();
        let salt = account_salt(manifest.realm(), AccountKind::User, sam).map_err(|error| {
            Refusal::Salt {
                sam: sam.to_owned(),
                error,
            }
        })?;
        // A-102 (N4): keyadm's ceremony grant bound the manifest's salt (every
        // manifest names one — A-105, Q-473); a manifest that names another
        // would only be refused by keyd later — refuse here, before anything
        // is entered.
        if admin.salt() != salt.as_str() {
            return Err(Refusal::SaltMismatch {
                sam: sam.to_owned(),
            });
        }
        salts.push(salt.as_str().to_owned());
    }

    // 3. The sources (files opened and checked as root).
    let sources = sources(request, admins, &*env.terminal, env.running_uid)?;

    // 4. The drop: admind's account, not dumpable, memory locked.
    let account = settings.run_as();
    env.privilege
        .drop_to(account.uid(), account.gid())
        .map_err(Refusal::Privilege)?;

    // 5. Every password, entered and checked before keyd is contacted.
    let mut passwords: Vec<EnteredPassword> = Vec::with_capacity(admins.len());
    for (admin, source) in admins.iter().zip(sources) {
        let sam = admin.sam_account_name();
        let password = match source {
            Source::File(file) => file.read().map_err(|refusal| Refusal::PasswordFile {
                sam: sam.to_owned(),
                refusal,
            })?,
            Source::Terminal => {
                enter_twice(&mut *env.terminal, sam).map_err(|error| Refusal::Entry {
                    sam: sam.to_owned(),
                    error,
                })?
            }
        };
        // keyd's own rule set (docs/questions/Q-605 item 3, Q-910): the
        // account's name and the realm, as keyd will pass them.
        check_password(
            password.expose(),
            settings.min_password_length(),
            sam,
            manifest.realm().as_str(),
        )
        .map_err(|_| Refusal::PasswordRules {
            sam: sam.to_owned(),
            min_chars: settings.min_password_length(),
        })?;
        passwords.push(password);
    }

    // 6. keyd: contact, then set_secret per administrator.
    let mut client = env
        .keyd
        .client(&settings)
        .map_err(|_| Refusal::KeydClient)?;
    // Task R9: the client's probe of the new connection already checked
    // the caller role (Directory); the answer's role is that one.
    let contact = classify(client.call_with_fate(&Call::Ping), |answer| match answer {
        Answer::Ping(result) => Some(result.map(|_caller_role| ())),
        _ => None,
    });
    let mut report = SecretReport {
        realm: manifest.realm().as_str().to_owned(),
        admins: admins
            .iter()
            .map(|a| AdminKeySet {
                sam: a.sam_account_name().to_owned(),
                guid: a.key_set().guid_text(),
                binding: a.key_set().binding_text(),
            })
            .collect(),
        contact,
        steps: Vec::with_capacity(admins.len()),
    };
    if !report.contact.succeeded() {
        return Ok(report);
    }
    for (index, ((admin, salt), password)) in admins.iter().zip(salts).zip(passwords).enumerate() {
        let key_set = admin.key_set();
        let call = Call::SetSecret {
            handle: key_set.handle,
            binding: key_set.binding.clone(),
            password: Password::new(password.into_inner()),
            salt,
        };
        let outcome: Outcome<_> = classify(client.call_with_fate(&call), |answer| match answer {
            Answer::SetSecret(result) => Some(result),
            _ => None,
        });
        drop(call);
        let stop = !outcome.succeeded();
        report.steps.push(StepReport {
            admin: index,
            outcome,
        });
        if stop {
            break;
        }
    }
    Ok(report)
}

/// [`run`], printed: the report to `out` (exit status from
/// [`report::exit_code`]), or the refusal to `err` (exit status
/// [`report::EXIT_NOTHING_SENT`]). Every line starts with `provision: `.
///
/// Spec: docs/51 §4.4 ("no secret in the output"); docs/50 §8.2.
pub fn execute<P, T, K>(
    request: &FirstAdminSecret,
    env: &mut Environment<'_, P, T, K>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8
where
    P: PrivilegeDrop + ?Sized,
    T: Terminal + ?Sized,
    K: KeydAccess + ?Sized,
{
    match run(request, env) {
        Ok(report) => {
            for line in render(&report) {
                let _ = writeln!(out, "provision: {line}");
            }
            exit_code(&report)
        }
        Err(refusal) => {
            let _ = writeln!(
                err,
                "provision: first-admin-secret: {refusal}; no password was sent"
            );
            EXIT_NOTHING_SENT
        }
    }
}
