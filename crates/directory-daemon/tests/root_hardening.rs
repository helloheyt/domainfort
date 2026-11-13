//! Tier 3 (docs/50 R50-19, §9: "hardening — privilege drop, rlimits,
//! no_new_privs — only as root in an isolated environment, `#[ignore]` by
//! default"): dird's own hardening plan (`directory_daemon::startup::
//! hardening_plan`) applied the way `main` applies it.
//!
//! Hardening changes the process it runs in, so every scenario runs in a
//! fresh **child process** of this binary (`std::env::current_exe()` with the
//! scenario in an environment variable), whose `main` is the first and only
//! thread when it claims its `SingleThreadProof` — as in the daemon
//! (R50-14), and as crates/keyd-daemon's and crates/daemon-sandbox's process
//! tests do. The parent is never hardened.
//!
//! * `unprivileged_apply_fails_closed` — default: as a non-root user (or on
//!   a non-Linux host) applying dird's plan must fail, never half-succeed
//!   silently (docs/50 §7.5: the daemon then exits).
//! * `root_dird_plan_applies_then_key_is_unreadable` — the `#[ignore]`
//!   equivalent (a `harness = false` binary has no attribute): skipped
//!   unless `--ignored` / `--include-ignored`; needs root on Linux in an
//!   isolated environment. As root it reads a root-owned 0400 integrity-key
//!   file (as `main` does before the drop), applies dird's plan (identity
//!   drop, no_new_privs, no capabilities, core 0, not dumpable, umask),
//!   which `apply` reads back and checks; afterwards the same key file can
//!   no longer be opened (the drop took effect), and the tokio runtime and a
//!   thread start — the order of `main`.
//!
//! Sources: docs/50 R50-14, R50-19, §6.1, §6.2, §6.4, §7.4, §9;
//! docs/questions/Q-235 (A-61), Q-270 item 1. Test identities (uid/gid
//! 61002) are project choices.

use config::DirdSettings;
use daemon_sandbox::{apply, SandboxError, SingleThreadProof};
use directory_daemon::startup::{hardening_plan, read_integrity_key};
use std::env;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Command, ExitCode};

/// Names the scenario a child process runs.
const SCENARIO_ENV: &str = "DIRD_TIER3_SCENARIO";

/// Why the root scenario is skipped by default (docs/50 R50-19 tier 3).
const ROOT_ONLY: &str = "requires root on Linux in an isolated environment: it drops the \
process identity (docs/50 R50-19 tier 3); run with -- --ignored";

/// A dird configuration (docs/50 §7.1) whose account is 61002.
const DIRD: &str = "\
run_as_uid = 61002
run_as_gid = 61002
realm = EXAMPLE.ORG
naming_context = dc=example,dc=org
dns_host_name = dc1.example.org
database_path = /var/lib/dird/directory.redb
integrity_key_source = insecure-development-file
integrity_key_path = /etc/dird/integrity.key
policy_store_path = /etc/domain/policy.store
policy_store_format = unsigned-development
dird_kdc_socket = /run/dird/kdc/dird-kdc.sock
kdc_uid = 61003
dird_ldap_socket = /run/dird/ldap/dird-ldap.sock
ldap_front_uid = 61004
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
        name: "root_dird_plan_applies_then_key_is_unreadable",
        ignore: Some(ROOT_ONLY),
        run: root_dird_plan_applies_then_key_is_unreadable,
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
/// and run each in a child.
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

/// The current uid: the owner of a directory this process creates.
fn current_uid() -> Result<u32, String> {
    let dir = env::temp_dir().join(format!("dird-t3-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let uid = std::fs::metadata(&dir).map_err(|e| e.to_string())?.uid();
    let _ = std::fs::remove_dir(&dir);
    Ok(uid)
}

/// docs/50 §7.5, R50-14: without root (or off Linux) dird's plan cannot be
/// applied — `apply` reports the failing step; it never reports success.
fn unprivileged_apply_fails_closed() -> Outcome {
    let proof = SingleThreadProof::claim().map_err(|e| e.to_string())?;
    if current_uid()? == 0 {
        println!("skipped: running as root");
        return Ok(());
    }
    let settings = DirdSettings::parse(DIRD.as_bytes()).map_err(|e| e.to_string())?;
    let plan = hardening_plan(&settings).map_err(|e| e.to_string())?;
    match apply(&plan, proof) {
        Ok(_) => Err(String::from("applied without privilege")),
        Err(SandboxError::Os { .. } | SandboxError::Unsupported { .. }) => Ok(()),
        Err(other) => Err(format!("unexpected failure: {other}")),
    }
}

/// docs/50 R50-14, §6.2, §6.4 (dird), §7.4; Q-270 item 1: as root on Linux,
/// the root-owned 0400 key file is read before the drop; dird's plan
/// applies and verifies; afterwards the key file is unreadable to the
/// process; the runtime builds and a thread starts.
fn root_dird_plan_applies_then_key_is_unreadable() -> Outcome {
    let proof = SingleThreadProof::claim().map_err(|e| e.to_string())?;
    let key_dir = env::temp_dir().join(format!("dird-t3-key-{}", std::process::id()));
    std::fs::create_dir_all(&key_dir).map_err(|e| e.to_string())?;
    let key_path = key_dir.join("integrity.key");
    std::fs::write(&key_path, [0x5D; 32]).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o400))
        .map_err(|e| e.to_string())?;
    let _key = read_integrity_key(&key_path, 0).map_err(|e| e.to_string())?;
    let settings = DirdSettings::parse(DIRD.as_bytes()).map_err(|e| e.to_string())?;
    let plan = hardening_plan(&settings).map_err(|e| e.to_string())?;
    let report = apply(&plan, proof).map_err(|e| e.to_string())?;
    if report.applied != plan.steps() {
        return Err(String::from("not every step was applied"));
    }
    if std::fs::File::open(&key_path).is_ok() {
        return Err(String::from(
            "the key file is still readable after the drop",
        ));
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
