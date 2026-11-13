//! Tier 3 (docs/50 R50-19, §9: "hardening — privilege drop, rlimits,
//! no_new_privs — only as root in an isolated environment, `#[ignore]` by
//! default"): keyd's own hardening plan (`keyd_daemon::startup::
//! hardening_plan`) applied the way `main` applies it.
//!
//! Hardening changes the process it runs in, so every scenario runs in a
//! fresh **child process** of this binary (`std::env::current_exe()` with the
//! scenario in an environment variable), whose `main` is the first and only
//! thread when it claims its `SingleThreadProof` — as in the daemon
//! (R50-14), and as crates/daemon-sandbox's own process tests do. The
//! parent is never hardened.
//!
//! * `unprivileged_apply_fails_closed` — default: as a non-root user (or on
//!   a non-Linux host) applying keyd's plan must fail, never half-succeed
//!   silently (docs/50 §7.5: the daemon then exits).
//! * `root_keyd_plan_applies_then_runtime_and_threads_start` — the
//!   `#[ignore]` equivalent (a `harness = false` binary has no attribute):
//!   skipped unless `--ignored` / `--include-ignored`; needs root on Linux
//!   in an isolated environment. It applies keyd's plan (identity drop,
//!   mlockall under the MEMLOCK limit, …), which `apply` reads back and
//!   checks, then builds the tokio runtime and starts a thread — the order
//!   of `main` — showing the MEMLOCK limit leaves room for both.
//!
//! Sources: docs/50 R50-14, R50-19, §6.1, §6.2, §6.4, §9; docs/questions/
//! Q-235 (A-61). Test identities (uid/gid 61001) are project choices.

use config::KeydSettings;
use daemon_sandbox::{apply, SandboxError, SingleThreadProof};
use keyd_daemon::startup::hardening_plan;
use std::env;
use std::os::unix::fs::MetadataExt;
use std::process::{Command, ExitCode};

/// Names the scenario a child process runs.
const SCENARIO_ENV: &str = "KEYD_DAEMON_TIER3_SCENARIO";

/// Why the root scenario is skipped by default (docs/50 R50-19 tier 3).
const ROOT_ONLY: &str = "requires root on Linux in an isolated environment: it drops the \
process identity and locks memory (docs/50 R50-19 tier 3); run with -- --ignored";

/// A keyd configuration (docs/50 §7.1) whose account is 61001.
const KEYD: &str = "\
run_as_uid = 61001
run_as_gid = 61001
realm = EXAMPLE.TEST
keyd_socket = /run/keyd/keyd.sock
uid_roles = 61003:Kdc
key_store = insecure-development
audit_socket = /run/auditd/audit.sock
auditd_uid = 61005
";

type Outcome = Result<(), String>;

struct Scenario {
    name: &'static str,
    ignore: Option<&'static str>,
    run: fn() -> Outcome,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "unprivileged_apply_fails_closed",
        ignore: None,
        run: unprivileged_apply_fails_closed,
    },
    Scenario {
        name: "root_keyd_plan_applies_then_runtime_and_threads_start",
        ignore: Some(ROOT_ONLY),
        run: root_keyd_plan_applies_then_runtime_and_threads_start,
    },
];

fn main() -> ExitCode {
    match env::var(SCENARIO_ENV) {
        Ok(name) => run_child(&name),
        Err(_) => run_parent(),
    }
}

/// In the child: one scenario on the main (only) thread.
fn run_child(name: &str) -> ExitCode {
    let Some(scenario) = SCENARIOS.iter().find(|s| s.name == name) else {
        eprintln!("unknown scenario {name}");
        return ExitCode::FAILURE;
    };
    match (scenario.run)() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{name}: {message}");
            ExitCode::FAILURE
        }
    }
}

/// In the parent: select scenarios by the libtest-like flags cargo passes
/// (`--ignored`, `--include-ignored`, `--list`, name filters) and run each
/// in a child.
fn run_parent() -> ExitCode {
    let mut ignored_only = false;
    let mut include_ignored = false;
    let mut list = false;
    let mut filters = Vec::new();
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--ignored" => ignored_only = true,
            "--include-ignored" => include_ignored = true,
            "--list" => list = true,
            other if other.starts_with("--") => {}
            other => filters.push(other.to_owned()),
        }
    }
    let selected: Vec<&Scenario> = SCENARIOS
        .iter()
        .filter(|s| filters.is_empty() || filters.iter().any(|f| s.name.contains(f.as_str())))
        .collect();
    if list {
        for scenario in &selected {
            println!("{}: test", scenario.name);
        }
        return ExitCode::SUCCESS;
    }
    let Ok(exe) = env::current_exe() else {
        eprintln!("cannot locate the test binary");
        return ExitCode::FAILURE;
    };
    let mut failed = 0usize;
    for scenario in selected {
        let run = match scenario.ignore {
            Some(_) => ignored_only || include_ignored,
            None => !ignored_only,
        };
        if !run {
            println!(
                "test {} ... ignored, {}",
                scenario.name,
                scenario.ignore.unwrap_or("")
            );
            continue;
        }
        let status = Command::new(&exe).env(SCENARIO_ENV, scenario.name).status();
        if matches!(status, Ok(s) if s.success()) {
            println!("test {} ... ok", scenario.name);
        } else {
            println!("test {} ... FAILED", scenario.name);
            failed += 1;
        }
    }
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The current uid: the owner of the current executable's directory entry is
/// not reliable, so read it from a file this process creates.
fn current_uid() -> Result<u32, String> {
    let dir = env::temp_dir().join(format!("kdd-t3-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let uid = std::fs::metadata(&dir).map_err(|e| e.to_string())?.uid();
    let _ = std::fs::remove_dir(&dir);
    Ok(uid)
}

/// docs/50 §7.5 (exit on any start-up failure), R50-14: without root (or off
/// Linux) keyd's plan cannot be applied — `apply` reports the failing step
/// (`Os` on Linux, `Unsupported` elsewhere); it never reports success.
fn unprivileged_apply_fails_closed() -> Outcome {
    let proof = SingleThreadProof::claim().map_err(|e| e.to_string())?;
    if current_uid()? == 0 {
        println!("skipped: running as root");
        return Ok(());
    }
    let settings = KeydSettings::parse(KEYD.as_bytes()).map_err(|e| e.to_string())?;
    let plan = hardening_plan(&settings).map_err(|e| e.to_string())?;
    match apply(&plan, proof) {
        Ok(_) => Err(String::from("applied without privilege")),
        Err(SandboxError::Os { .. } | SandboxError::Unsupported { .. }) => Ok(()),
        Err(other) => Err(format!("unexpected failure: {other}")),
    }
}

/// docs/50 R50-14, §6.2, §6.4 (keyd), Q-235 item 7 (MEMLOCK for keyd): as
/// root on Linux, keyd's plan applies and verifies; afterwards the tokio
/// runtime builds and a thread starts (the order of `main`), under the
/// MEMLOCK limit with all memory locked.
fn root_keyd_plan_applies_then_runtime_and_threads_start() -> Outcome {
    let proof = SingleThreadProof::claim().map_err(|e| e.to_string())?;
    let settings = KeydSettings::parse(KEYD.as_bytes()).map_err(|e| e.to_string())?;
    let plan = hardening_plan(&settings).map_err(|e| e.to_string())?;
    let report = apply(&plan, proof).map_err(|e| e.to_string())?;
    if report.applied != plan.steps() {
        return Err(String::from("not every step was applied"));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {});
    std::thread::spawn(|| ())
        .join()
        .map_err(|_| String::from("thread failed"))?;
    Ok(())
}
