#![forbid(unsafe_code)]
//! The keyadm binary: `keyadm <configuration file> ceremony <manifest file>`.
//!
//! Every message is a fixed text, at most followed by an error's own fixed
//! description (configuration and manifest errors never echo input, A-60)
//! or by identifiers the manifest parser validated. Exit status: 0 — the
//! ceremony completed; 1 — nothing was attempted on keyd's key store; 2 —
//! the ceremony stopped after an attempt (crates/keyadm report.rs).
//!
//! Spec: docs/51 §4.3 step 11, §6; docs/50 §8.2; A-60.

use ipc_keyd::{KeydClient, UnixConnector};
use keyadm::cli::{self, Command, USAGE};
use keyadm::report::{self, EXIT_NOTHING_ATTEMPTED};
use keyadm::{ceremony, identity, settings};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

/// Write a fixed failure message to standard error; nothing was attempted
/// on keyd's key store.
/// Spec: docs/50 §8.2.
fn fail(what: &str, error: &dyn std::fmt::Display) -> ExitCode {
    let _ = writeln!(std::io::stderr().lock(), "keyadm: {what}: {error}");
    ExitCode::from(EXIT_NOTHING_ATTEMPTED)
}

/// A panic prints a fixed message and its location only, never a payload
/// (as the daemons, docs/50 §8.2).
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let mut err = std::io::stderr().lock();
        let _ = match info.location() {
            Some(location) => writeln!(
                err,
                "keyadm: internal error at {}:{}",
                location.file(),
                location.line()
            ),
            None => writeln!(err, "keyadm: internal error"),
        };
    }));
}

/// `ceremony`: refuse root, read the configuration and the manifest,
/// connect to keyd (peer uid checked before anything is sent), run, report.
/// Spec: docs/51 §4.3 step 11; docs/50 R50-3.
fn ceremony(config_path: &Path, manifest_path: &Path) -> ExitCode {
    if let Err(error) = identity::check_current_process() {
        return fail("identity", &error);
    }
    let settings = match settings::read_settings(config_path) {
        Ok(settings) => settings,
        Err(error) => return fail("configuration", &error),
    };
    let manifest = match provision_manifest::read_manifest(manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => return fail("manifest", &error),
    };
    let connector = UnixConnector::new(settings.keyd().socket().as_path().to_path_buf());
    let mut client =
        match KeydClient::new(connector, settings.keyd().uid(), settings.keyd_deadline()) {
            Ok(client) => client,
            Err(_) => return fail("configuration", &"keyd_uid cannot be 0"),
        };
    let outcome = ceremony::run(&mut client, &manifest);
    let mut out = std::io::stdout().lock();
    for line in report::render(&outcome, &manifest) {
        let _ = writeln!(out, "keyadm: {line}");
    }
    ExitCode::from(report::exit_code(&outcome))
}

fn main() -> ExitCode {
    install_panic_hook();
    match cli::parse(std::env::args_os().skip(1)) {
        Ok(Command::Ceremony { config, manifest }) => ceremony(&config, &manifest),
        Err(_) => fail("usage", &USAGE),
    }
}
