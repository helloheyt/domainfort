#![forbid(unsafe_code)]
//! The keyadm binary: `keyadm <configuration file> ceremony <manifest file>`,
//! `… rotate-krbtgt | rotate-key | retire-kvno <request id>`, `…
//! destroy-sweep` (crates/keyadm cli.rs).
//!
//! Every message is a fixed text, at most followed by an error's own fixed
//! description (configuration and manifest errors never echo input, A-60)
//! or by identifiers (GUIDs, kvnos, digests). Exit status: 0 — the command
//! completed; 1 — nothing was attempted on keyd's key store; 2 — the
//! command stopped after an attempt: check keyd's audit log (crates/keyadm
//! report.rs).
//!
//! Spec: docs/51 §4.3 step 11, §6; docs/50 §8.2; A-60.

use ipc_admin::AdmindClient;
use ipc_keyd::{KeydClient, UnixConnector};
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

/// The clients of the approved-request commands and the sweep: keyd (its
/// uid checked before anything is sent) and admind (likewise — both
/// `admin_socket` and `admind_uid` must be configured).
/// Spec: docs/51 §6; docs/50 R50-3.
type Clients = (
    KeydClient<UnixConnector>,
    AdmindClient<ipc_dird_admin::UnixConnector>,
);

/// Refuse root, read the configuration, build both clients.
/// Spec: docs/51 §6; docs/50 R50-3.
fn clients(config_path: &Path) -> Result<Clients, ExitCode> {
    if let Err(error) = identity::check_current_process() {
        return Err(fail("identity", &error));
    }
    let settings = match settings::read_settings(config_path) {
        Ok(settings) => settings,
        Err(error) => return Err(fail("configuration", &error)),
    };
    let Some(admind) = settings.admind() else {
        return Err(fail(
            "configuration",
            &"admin_socket and admind_uid are required for this command",
        ));
    };
    let keyd = KeydClient::new(
        UnixConnector::new(settings.keyd().socket().as_path().to_path_buf()),
        settings.keyd().uid(),
        settings.keyd_deadline(),
    )
    .map_err(|_| fail("configuration", &"keyd_uid cannot be 0"))?;
    let admind = AdmindClient::new(
        ipc_dird_admin::UnixConnector::new(admind.socket().as_path().to_path_buf()),
        admind.uid(),
        ipc_admin::DEFAULT_DEADLINE,
    )
    .map_err(|_| fail("configuration", &"admind_uid cannot be 0"))?;
    Ok((keyd, admind))
}

/// Print `lines` to standard output.
fn print(lines: Vec<String>) {
    let mut out = std::io::stdout().lock();
    for line in lines {
        let _ = writeln!(out, "keyadm: {line}");
    }
}

/// `rotate-krbtgt` / `rotate-key` / `retire-kvno <request id>`.
/// Spec: docs/51 §6.
fn execute_approved(config_path: &Path, command: Approved, id: u64) -> ExitCode {
    let (mut keyd, mut admind) = match clients(config_path) {
        Ok(clients) => clients,
        Err(code) => return code,
    };
    let outcome = execute::run(&mut admind, &mut keyd, command, id);
    print(report::render_execution(&outcome));
    ExitCode::from(report::execution_exit_code(&outcome))
}

/// `destroy-sweep`. Spec: docs/51 §6, §9.
fn destroy_sweep(config_path: &Path) -> ExitCode {
    let (mut keyd, mut admind) = match clients(config_path) {
        Ok(clients) => clients,
        Err(code) => return code,
    };
    let outcome = sweep::run(&mut admind, &mut keyd);
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
        }) => execute_approved(&config, command, id),
        Ok(Command::DestroySweep { config }) => destroy_sweep(&config),
        Err(_) => fail("usage", &USAGE),
    }
}
