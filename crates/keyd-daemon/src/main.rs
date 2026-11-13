#![forbid(unsafe_code)]
//! The keyd daemon binary: `keyd-daemon <configuration file>`.
//!
//! The start-up order (docs/50 R50-14, §6.2, §7.5; crates/daemon-sandbox):
//!
//! 1. claim the single-thread proof — the first statement of `main`, before
//!    anything could start a thread;
//! 2. read the configuration path from argv and parse it;
//! 3. the privileged set-up that needs root: the socket directory;
//! 4. apply the hardening plan (identity drop, no_new_privs, capabilities,
//!    core 0, not dumpable, umask, mlockall) while the process has exactly
//!    one thread — rustix's identity calls act on the calling thread only;
//! 5. only then build the tokio runtime, and serve.
//!
//! Every start-up failure exits with a failure code (fail closed, §7.5); the
//! service manager restarts with backoff. Messages are fixed texts on stderr
//! (docs/50 §8.2).
//!
//! Spec: docs/50 R50-14, R50-16, R50-18, §6.2, §7.5, §8.2; docs/questions/
//! Q-235 (A-61).

use daemon_sandbox::{apply, SingleThreadProof};
use keyd_daemon::log::{note, Note};
use keyd_daemon::startup::{
    development_keyd, hardening_plan, prepare_socket_directory, read_settings, realm,
};
use keyd_daemon::{serve, DaemonControl, DaemonParams, SystemClock};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

/// Write a fixed start-up failure message and return the failure code.
/// Spec: docs/50 §7.5, §8.2.
fn fail(what: &str, error: &dyn std::fmt::Display) -> ExitCode {
    let _ = writeln!(
        std::io::stderr().lock(),
        "keyd-daemon: start-up failed: {what}: {error}"
    );
    ExitCode::FAILURE
}

/// A panic prints a fixed message and its location only — never a payload,
/// which could carry data (docs/50 §8.2: "panic: a hook that prints a fixed
/// message + location only"; core dumps are off, R50-14).
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let mut err = std::io::stderr().lock();
        let _ = match info.location() {
            Some(location) => writeln!(
                err,
                "keyd-daemon: internal error at {}:{}",
                location.file(),
                location.line()
            ),
            None => writeln!(err, "keyd-daemon: internal error"),
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
        return fail("usage", &"keyd-daemon <configuration file>");
    };
    let settings = match read_settings(Path::new(&path)) {
        Ok(settings) => settings,
        Err(error) => return fail("configuration", &error),
    };
    let realm = match realm(&settings) {
        Ok(realm) => realm,
        Err(error) => return fail("configuration", &error),
    };
    let params = match DaemonParams::from_settings(&settings) {
        Ok(params) => params,
        Err(error) => return fail("configuration", &error),
    };

    // 3. Privileged set-up (root): the socket directory (docs/50 §3.1).
    if let Err(error) = prepare_socket_directory(&settings) {
        return fail("socket directory", &error);
    }

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
    let control = DaemonControl::new();
    let result = runtime.block_on(serve(params, SystemClock, development_keyd(realm), control));
    // Dropping the runtime ends the connection tasks and with them the last
    // engine-queue senders; the engine thread then ends.
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
