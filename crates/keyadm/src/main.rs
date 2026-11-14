#![forbid(unsafe_code)]
//! The keyadm binary: `keyadm <configuration file> ceremony <manifest file>`,
//! `… rotate-krbtgt | rotate-key | retire-kvno <decision id>`, `…
//! destroy-sweep` (crates/keyadm cli.rs). keyadm talks to keyd only (A-102,
//! docs/52 §4.6).
//!
//! Every message is a fixed text, at most followed by an error's own fixed
//! description (configuration and manifest errors never echo input, A-60)
//! or by identifiers (GUIDs, kvnos, digests). Exit status: 0 — the command
//! completed; 1 — nothing was attempted on keyd's key store; 2 — the
//! command stopped after an attempt: check keyd's audit log (crates/keyadm
//! report.rs).
//!
//! Spec: docs/51 §4.3 step 11, §6; docs/50 §8.2; A-60; docs/52 §4.6 (A-102).

use ipc_keyd::{ClientConfigError, ExpectedPeer, KeydClient, Role, UnixConnector};
use keyadm::cli::{self, Approved, Command, USAGE};
use keyadm::report::{self, EXIT_NOTHING_ATTEMPTED};
use keyadm::{ceremony, execute, identity, settings, sweep};
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
    let mut client = match admin_peer(settings.keyd().uid()) {
        Ok(peer) => KeydClient::new(connector, peer, settings.keyd_deadline()),
        Err(_) => return fail("configuration", &"keyd_uid cannot be 0"),
    };
    // Every manifest names each first administrator's salt (A-105,
    // docs/questions/Q-473): nothing to refuse before contacting keyd.
    let outcome = ceremony::run(&mut client, &manifest);
    print(report::render(&outcome, &manifest));
    ExitCode::from(report::exit_code(&outcome))
}

/// Refuse root, read the configuration, build keyd's client (its uid
/// checked before anything is sent). keyadm talks to keyd only (A-102).
/// Spec: docs/51 §6; docs/50 R50-3; docs/52 §4.6.
fn keyd_client(config_path: &Path) -> Result<KeydClient<UnixConnector>, ExitCode> {
    if let Err(error) = identity::check_current_process() {
        return Err(fail("identity", &error));
    }
    let settings = match settings::read_settings(config_path) {
        Ok(settings) => settings,
        Err(error) => return Err(fail("configuration", &error)),
    };
    let peer = admin_peer(settings.keyd().uid())
        .map_err(|_| fail("configuration", &"keyd_uid cannot be 0"))?;
    Ok(KeydClient::new(
        UnixConnector::new(settings.keyd().socket().as_path().to_path_buf()),
        peer,
        settings.keyd_deadline(),
    ))
}

/// The keyd keyadm expects: `keyd_uid`, giving keyadm the Admin role —
/// checked on every connection before anything else is sent (task R9).
/// Spec: docs/10 §2 (Role `Admin`); docs/50 R50-3; docs/52 §3.12;
/// docs/questions/Q-466 item 1 (A-102).
fn admin_peer(keyd_uid: u32) -> Result<ExpectedPeer, ClientConfigError> {
    ExpectedPeer::new(keyd_uid, Role::Admin)
}

/// Print `lines` to standard output.
fn print(lines: Vec<String>) {
    let mut out = std::io::stdout().lock();
    for line in lines {
        let _ = writeln!(out, "keyadm: {line}");
    }
}

/// `rotate-krbtgt` / `rotate-key` / `retire-kvno <decision id>`.
/// Spec: docs/51 §6; docs/52 §4.2.
fn execute_decision(config_path: &Path, command: Approved, id: u64) -> ExitCode {
    let mut keyd = match keyd_client(config_path) {
        Ok(client) => client,
        Err(code) => return code,
    };
    let outcome = execute::run(&mut keyd, command, id);
    print(report::render_execution(&outcome));
    ExitCode::from(report::execution_exit_code(&outcome))
}

/// `destroy-sweep`. Spec: docs/51 §6, §9; docs/52 §4.3.
fn destroy_sweep(config_path: &Path) -> ExitCode {
    let mut keyd = match keyd_client(config_path) {
        Ok(client) => client,
        Err(code) => return code,
    };
    let outcome = sweep::run(&mut keyd);
    print(report::render_sweep(&outcome));
    ExitCode::from(report::sweep_exit_code(&outcome))
}

fn main() -> ExitCode {
    install_panic_hook();
    match cli::parse(std::env::args_os().skip(1)) {
        Ok(Command::Ceremony { config, manifest }) => ceremony(&config, &manifest),
        Ok(Command::Execute {
            config,
            command,
            id,
        }) => execute_decision(&config, command, id),
        Ok(Command::DestroySweep { config }) => destroy_sweep(&config),
        Err(_) => fail("usage", &USAGE),
    }
}
