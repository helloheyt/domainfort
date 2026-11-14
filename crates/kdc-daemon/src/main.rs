#![forbid(unsafe_code)]
//! The kdc daemon binary: `kdc-daemon <configuration file>`.
//!
//! The start-up order (docs/50 R50-14, §6.2, §7.5; crates/daemon-sandbox):
//!
//! 1. claim the single-thread proof — the first statement of `main`;
//! 2. read the configuration path from argv and parse it;
//! 3. as root: read the policy file (the same file dird loads) and bind the
//!    UDP and TCP listeners — served only once the dependencies are verified
//!    (crate::startup);
//! 4. apply the hardening plan while the process has exactly one thread —
//!    rustix's identity calls act on the calling thread only;
//! 5. only then build the tokio runtime, and serve.
//!
//! Every start-up failure exits with a failure code (fail closed, §7.5); the
//! service manager restarts with backoff. Messages are fixed texts on stderr
//! (docs/50 §8.2).
//!
//! Spec: docs/50 R50-14, R50-16, §6.2, §7.5, §8.2; docs/questions/Q-235
//! (A-61); A-68.

use daemon_sandbox::{apply, SingleThreadProof};
use kdc_daemon::log::{note, Note};
use kdc_daemon::startup::{bind_listeners, hardening_plan, read_policy, read_settings};
use kdc_daemon::{serve, DaemonControl, DaemonParams};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

/// The owner the configuration and policy files must have.
const ROOT_UID: u32 = 0;

/// Write a fixed start-up failure message and return the failure code.
/// Spec: docs/50 §7.5, §8.2.
fn fail(what: &str, error: &dyn std::fmt::Display) -> ExitCode {
    let _ = writeln!(
        std::io::stderr().lock(),
        "kdc-daemon: start-up failed: {what}: {error}"
    );
    ExitCode::FAILURE
}

/// A panic prints a fixed message and its location only (docs/50 §8.2;
/// core dumps are off, R50-14).
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let mut err = std::io::stderr().lock();
        let _ = match info.location() {
            Some(location) => writeln!(
                err,
                "kdc-daemon: internal error at {}:{}",
                location.file(),
                location.line()
            ),
            None => writeln!(err, "kdc-daemon: internal error"),
        };
    }));
}

fn main() -> ExitCode {
    // 1. The single-thread proof (R50-14): first statement of main.
    let proof = match SingleThreadProof::claim() {
        Ok(proof) => proof,
        Err(error) => return fail("thread guard", &error),
    };
    install_panic_hook();

    // 2. The configuration path from argv (exactly one argument).
    let mut args = std::env::args_os().skip(1);
    let (Some(path), None) = (args.next(), args.next()) else {
        return fail("usage", &"kdc-daemon <configuration file>");
    };
    let settings = match read_settings(Path::new(&path), ROOT_UID) {
        Ok(settings) => settings,
        Err(error) => return fail("configuration", &error),
    };
    let params = DaemonParams::from_settings(&settings);

    // 3. As root, before the drop: the policy file and the listeners.
    let policy = match read_policy(settings.policy_store_path().as_path(), ROOT_UID) {
        Ok(policy) => policy,
        Err(error) => return fail("policy store", &error),
    };
    note(Note::UnsignedDevelopmentPolicy, None);
    let listeners = match bind_listeners(&settings) {
        Ok(listeners) => listeners,
        Err(error) => return fail("listeners", &error),
    };
    note(Note::ListenersBound, None);

    // 4. Hardening, before any thread exists (R50-14).
    let plan = match hardening_plan(&settings) {
        Ok(plan) => plan,
        Err(error) => return fail("hardening plan", &error),
    };
    if let Err(error) = apply(&plan, proof) {
        return fail("hardening", &error);
    }
    note(Note::Hardened, None);

    // 5. Only now: the runtime (one current-thread runtime; the engine
    //    thread is spawned inside `serve`).
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return fail("runtime", &error),
    };
    let keyd = ipc_keyd::UnixConnector::new(settings.keyd().socket().as_path().to_path_buf());
    let dird = ipc_directory::UnixConnector::new(settings.dird().socket().as_path().to_path_buf());
    let control = DaemonControl::new();
    let result = runtime.block_on(serve(params, policy, listeners, keyd, dird, control));
    drop(runtime);
    match result {
        Ok(stopped) => {
            let engine_failed = stopped.engine_failed();
            if stopped.join().is_err() || engine_failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => fail("serve", &error),
    }
}
