#![forbid(unsafe_code)]
//! The ldap-front binary: `ldap-front <configuration file>`.
//!
//! The start-up order (docs/50 R50-14, R50-16, §6.2, §7.5; crates/
//! daemon-sandbox):
//!
//! 1. claim the single-thread proof — the first statement of `main`;
//! 2. read the configuration path from argv and parse it;
//! 3. as root: read the DC certificate and the key (0400, root-owned),
//!    check them (RFC 5280 structure, signature and key algorithms, the key
//!    match, validity at the start-up time) and build the TLS
//!    configuration — the key octets are wiped
//!    once it is built — and bind the listeners (served only once auditd
//!    and dird are verified);
//! 4. apply the hardening plan while the process has exactly one thread —
//!    rustix's identity calls act on the calling thread only;
//! 5. only then build the tokio runtime, and serve (auditd verified, dird
//!    verified, the listeners served).
//!
//! Every start-up failure exits with a failure code (fail closed, §7.5); the
//! service manager restarts with backoff. Messages are fixed texts on stderr
//! (docs/50 §8.2).
//!
//! Spec: docs/50 R50-12, R50-14, R50-16, §6.2, §7.5, §8.2; docs/questions/
//! Q-235 (A-61).

use daemon_sandbox::{apply, SingleThreadProof};
use ldap_front::log::{note, Note};
use ldap_front::startup::{
    bind_listeners, hardening_plan, load_tls_config, read_settings, start_time,
};
use ldap_front::{serve, DaemonControl, FrontParams};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

/// The owner the configuration, certificate and key files must have.
const ROOT_UID: u32 = 0;

/// Write a fixed start-up failure message and return the failure code.
/// Spec: docs/50 §7.5, §8.2.
fn fail(what: &str, error: &dyn std::fmt::Display) -> ExitCode {
    let _ = writeln!(
        std::io::stderr().lock(),
        "ldap-front: start-up failed: {what}: {error}"
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
                "ldap-front: internal error at {}:{}",
                location.file(),
                location.line()
            ),
            None => writeln!(err, "ldap-front: internal error"),
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
        return fail("usage", &"ldap-front <configuration file>");
    };
    let settings = match read_settings(Path::new(&path), ROOT_UID) {
        Ok(settings) => settings,
        Err(error) => return fail("configuration", &error),
    };
    let params = FrontParams::from_settings(&settings);

    // 3. As root, before the drop: the certificate and key, checked at the
    //    start-up time (the key octets are wiped inside `load_tls_config`),
    //    then the listeners.
    let now = match start_time() {
        Ok(now) => now,
        Err(error) => return fail("clock", &error),
    };
    let tls = match load_tls_config(&settings, ROOT_UID, now) {
        Ok(tls) => tls,
        Err(error) => return fail("TLS credential", &error),
    };
    note(Note::CredentialLoaded, None);
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

    // 5. Only now: the runtime (one current-thread runtime).
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return fail("runtime", &error),
    };
    let control = DaemonControl::new();
    let result = runtime.block_on(serve(params, tls, listeners, control));
    drop(runtime);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail("serve", &error),
    }
}
