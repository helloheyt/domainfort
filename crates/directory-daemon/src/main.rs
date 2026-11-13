#![forbid(unsafe_code)]
//! The dird binary: `directory-daemon <configuration file>` — the
//! directory-view service only (task P8).
//!
//! The start-up order (docs/50 R50-14, §6.2, §7.5; crates/daemon-sandbox):
//!
//! 1. claim the single-thread proof — the first statement of `main`;
//! 2. read the configuration path from argv and parse it;
//! 3. as root: read the development integrity key and the development
//!    policy (both root-owned files, read before the drop), and prepare the
//!    socket directory;
//! 4. apply the hardening plan while the process has exactly one thread;
//! 5. only then build the tokio runtime, and serve (auditd first, then the
//!    directory, then the socket).
//!
//! Every start-up failure exits with a failure code (fail closed, §7.5).
//! Messages are fixed texts on stderr (docs/50 §8.2); the key never appears.
//!
//! Spec: docs/50 R50-2, R50-14, R50-16, §6.2, §7.2, §7.4, §7.5, §8.2;
//! docs/questions/Q-213, Q-219 (A-57), Q-235 (A-61), Q-270.

use daemon_sandbox::{apply, SingleThreadProof};
use directory_daemon::log::{note, Note};
use directory_daemon::startup::{
    hardening_plan, params, prepare_socket_directory, read_integrity_key, read_policy,
    read_settings,
};
use directory_daemon::{serve, DaemonControl, StoreSource};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

/// The owner every root-only input file must have: root (uid 0).
/// Spec: docs/50 §7.1 ("file root:0644"), §7.4; Q-270 item 1.
const ROOT_UID: u32 = 0;

/// Write a fixed start-up failure message and return the failure code.
/// Spec: docs/50 §7.5, §8.2.
fn fail(what: &str, error: &dyn std::fmt::Display) -> ExitCode {
    let _ = writeln!(
        std::io::stderr().lock(),
        "directory-daemon: start-up failed: {what}: {error}"
    );
    ExitCode::FAILURE
}

/// A panic prints a fixed message and its location only — never a payload
/// (docs/50 §8.2; core dumps are off, R50-14).
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let mut err = std::io::stderr().lock();
        let _ = match info.location() {
            Some(location) => writeln!(
                err,
                "directory-daemon: internal error at {}:{}",
                location.file(),
                location.line()
            ),
            None => writeln!(err, "directory-daemon: internal error"),
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
        return fail("usage", &"directory-daemon <configuration file>");
    };
    let settings = match read_settings(Path::new(&path)) {
        Ok(settings) => settings,
        Err(error) => return fail("configuration", &error),
    };
    let params = match params(&settings) {
        Ok(params) => params,
        Err(error) => return fail("configuration", &error),
    };

    // 3. As root, before the drop: the development key and policy, the
    //    socket directory (docs/50 §7.4, §7.2, §3.1).
    let key = match read_integrity_key(settings.integrity_key_path().as_path(), ROOT_UID) {
        Ok(key) => key,
        Err(error) => return fail("integrity key", &error),
    };
    note(Note::DevelopmentIntegrityKey, None);
    let policy = match read_policy(settings.policy_store_path().as_path(), ROOT_UID) {
        Ok(policy) => policy,
        Err(error) => return fail("policy store", &error),
    };
    note(Note::UnsignedDevelopmentPolicy, None);
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
    let source = StoreSource::File {
        path: settings.database_path().as_path().to_path_buf(),
        key,
        owner_uid: settings.run_as().uid(),
    };
    let control = DaemonControl::new();
    let result = runtime.block_on(serve(params, source, policy, control));
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
