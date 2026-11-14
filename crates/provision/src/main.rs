#![forbid(unsafe_code)]
//! The `provision` binary (crate documentation; usage in module `cli`).
//!
//! Every message is fixed text, at most followed by an error's own fixed
//! description, a path the operator gave, or identifiers that are not
//! secret (realm, domain SID, the manifest's GUIDs — docs/47 §2.3). The
//! integrity key is never printed. Exit status: 0 — done; 1 — refused,
//! nothing was written; 2 — stopped after writing (the message names what
//! was left, module `install`).
//!
//! Spec: docs/51 §4.3 step 9 ("print a summary (without any secret)"),
//! §4.4, §5.10; docs/50 §8.2; A-69; A-80.

use std::io::Write;
use std::process::ExitCode;

use directory_admin::OsRandom;
use provision::cli::{self, Command};
use provision::install::InstallState;
use provision::update::{update_policy, RESTART_NOTICE};
use provision::{provision_domain, Progress, RootOwnership, Step};

/// Refused: nothing was written.
const EXIT_REFUSED: u8 = 1;
/// Stopped after writing.
const EXIT_PARTIAL: u8 = 2;

/// Print a fixed message to standard error.
fn complain(what: &str, error: &dyn std::fmt::Display) {
    let _ = writeln!(std::io::stderr().lock(), "provision: {what}: {error}");
}

/// A panic prints a fixed message and its location only, never a payload
/// (as the daemons, docs/50 §8.2).
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let mut err = std::io::stderr().lock();
        let _ = match info.location() {
            Some(location) => writeln!(
                err,
                "provision: internal error at {}:{}",
                location.file(),
                location.line()
            ),
            None => writeln!(err, "provision: internal error"),
        };
    }));
}

/// The binary's progress: one line per installed file; never halts.
struct Report;

impl Progress for Report {
    fn reached(&mut self, step: Step) -> Result<(), provision::install::Halt> {
        if let Step::Installed(target) = step {
            let _ = writeln!(
                std::io::stdout().lock(),
                "provision: installed {}",
                target.name()
            );
        }
        Ok(())
    }
}

/// `provision domain`.
fn domain(input: &provision::DomainInput) -> ExitCode {
    let mut ownership = match RootOwnership::new() {
        Ok(o) => o,
        Err(e) => {
            complain("identity", &e);
            return ExitCode::from(EXIT_REFUSED);
        }
    };
    let Some(now) = provision::time::system_now() else {
        complain("clock", &"the system clock cannot be read");
        return ExitCode::from(EXIT_REFUSED);
    };
    let mut rng = OsRandom::new();
    match provision_domain(input, now, &mut rng, &mut ownership, &mut Report) {
        Ok((plan, installed)) => {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "provision: domain {} provisioned", plan.realm.as_str());
            let _ = writeln!(
                out,
                "provision: domain SID {}",
                plan.domain_sid.to_sid_string()
            );
            for (target, path) in &installed.targets {
                let _ = writeln!(out, "provision: {} = {}", target.name(), path.as_str());
            }
            let _ = writeln!(
                out,
                "provision: next: start auditd and keyd, run keyadm ceremony with the manifest, set the first administrators' passwords (docs/51 4.3 part B), then start dird, kdc, ldap-front, admind"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            complain("domain", &e);
            ExitCode::from(match e.state() {
                InstallState::NothingWritten => EXIT_REFUSED,
                _ => EXIT_PARTIAL,
            })
        }
    }
}

/// `provision policy`.
fn policy(path: &provision::FilePath, changes: &[provision::policy::TierChange]) -> ExitCode {
    let mut ownership = match RootOwnership::new() {
        Ok(o) => o,
        Err(e) => {
            complain("identity", &e);
            return ExitCode::from(EXIT_REFUSED);
        }
    };
    match update_policy(path, changes, &mut ownership) {
        Ok(version) => {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "provision: policy_version is now {}", version.0);
            let _ = writeln!(out, "provision: {RESTART_NOTICE}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            complain("policy", &e);
            ExitCode::from(EXIT_REFUSED)
        }
    }
}

fn main() -> ExitCode {
    install_panic_hook();
    match cli::parse(std::env::args_os().skip(1)) {
        Ok(Command::Domain(input)) => domain(&input),
        Ok(Command::Policy { path, changes }) => policy(&path, &changes),
        Err(e) => {
            complain("arguments", &e);
            ExitCode::from(EXIT_REFUSED)
        }
    }
}
