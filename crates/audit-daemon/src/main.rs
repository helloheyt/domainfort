#![forbid(unsafe_code)]
//! The auditd binary: the start-up sequence of `audit_daemon::startup`, in
//! order, failing closed at every step (docs/50 §7.5: "every daemon exits
//! with an error code on any start-up failure").
//!
//! Spec: docs/50 R50-14, R50-16, R50-17, §6.2, §7.5, §8.2; task P6b.

use audit_daemon::listener::{self, ListenerConfig};
use audit_daemon::recovery;
use audit_daemon::signing::SigningMode;
use audit_daemon::startup::{self, EXIT_CHAIN_BREAK, EXIT_STARTUP, EXIT_WRITER};
use audit_daemon::writer;
use audit_log::SegmentLimit;
use daemon_sandbox::SingleThreadProof;
use std::process::ExitCode;
use std::sync::Arc;

fn main() -> ExitCode {
    // Step 1 — the first statement: the process has exactly one thread
    // (docs/50 R50-14; A-61).
    let Ok(proof) = SingleThreadProof::claim() else {
        eprintln!("audit-daemon: thread guard refused");
        return ExitCode::from(EXIT_STARTUP);
    };
    // Step 2 — fixed panic output (docs/50 §8.2).
    startup::install_panic_hook();
    run(proof)
}

/// Steps 3-9 (crate::startup documents each).
fn run(proof: SingleThreadProof) -> ExitCode {
    // Step 3 — configuration (docs/50 R50-15, §7.1).
    let settings = match startup::config_path(std::env::args_os())
        .and_then(|path| startup::read_settings(&path))
    {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("audit-daemon: {error}");
            return ExitCode::from(EXIT_STARTUP);
        }
    };

    // Step 4 — hardening, before any thread (docs/50 R50-14, §6.2, §6.4).
    let plan = match startup::hardening_plan(&settings) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("audit-daemon: hardening plan refused: {error}");
            return ExitCode::from(EXIT_STARTUP);
        }
    };
    if let Err(error) = daemon_sandbox::apply(&plan, proof) {
        eprintln!("audit-daemon: process hardening failed: {error}");
        return ExitCode::from(EXIT_STARTUP);
    }

    // Step 5 — verify the log, recover a torn tail, refuse a break
    // (docs/50 §7.5; docs/37 §2; Q-250 item 8).
    let opened = match recovery::open_log(
        settings.audit_log_path().as_path(),
        SegmentLimit::DEFAULT,
        settings.run_as().uid(),
    ) {
        Ok(opened) => opened,
        Err(error) if error.is_chain_break() => {
            eprintln!("audit-daemon: refusing to start: {error}");
            return ExitCode::from(EXIT_CHAIN_BREAK);
        }
        Err(error) => {
            eprintln!("audit-daemon: start-up failed: {error}");
            return ExitCode::from(EXIT_STARTUP);
        }
    };

    // Step 6 — what start-up found, and the signing mode (P-20).
    eprintln!("{}", startup::start_notice(opened.start));
    eprintln!("{}", SigningMode::Unsigned.startup_notice());

    // Step 7 — the runtime, with an explicit worker count (docs/50 §6.2).
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(startup::WORKER_THREADS)
        .thread_name("audit-daemon-io")
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("audit-daemon: runtime start failed: {}", error.kind());
            return ExitCode::from(EXIT_STARTUP);
        }
    };

    // Step 8 — bind only now that the log verified (docs/50 R50-16).
    let bound = {
        let _context = runtime.enter();
        listener::bind(settings.audit_socket().as_path())
    };
    let socket = match bound {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("audit-daemon: {error}");
            return ExitCode::from(EXIT_STARTUP);
        }
    };

    // Step 9 — serve; the main thread becomes the single writer.
    let (submitter, inbox) = writer::queue(writer::QUEUE_CAPACITY);
    let _serving = runtime.spawn(listener::serve(
        socket,
        Arc::new(settings.uid_sources().clone()),
        submitter,
        ListenerConfig::from_settings(&settings),
    ));
    eprintln!("audit-daemon: listening");
    let result = writer::run(opened.sink, inbox);
    runtime.shutdown_background();
    match result {
        Ok(()) => eprintln!("audit-daemon: stopping: the listener ended"),
        Err(failure) => eprintln!("audit-daemon: stopping: {failure}"),
    }
    ExitCode::from(EXIT_WRITER)
}
