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
//! # How to run the root scenario (docs/questions/Q-680)
//!
//! As root, on Linux, in an isolated machine (never a host), from a
//! checkout **copied as root** — every file and directory root's (`cp -r`
//! as root, not `cp -a` / `rsync -a` of an account's tree, which keep its
//! owner) — to a path of only `A-Z a-z 0-9 . _ - /` whose every directory
//! from `/` is root's, mode 0755, e.g. `/srv/lds` (not under `/root`, mode
//! 0700 — the other tier-3 tests' daemons must walk the path after their
//! drop; one layout serves them all); built and run there as root:
//! `cargo test -p directory-daemon --test root_hardening -- --ignored`.
//! `HOME` does not matter.
//!
//! # Fixtures, as production has them
//!
//! The **parent** (root, never hardened) makes the scenario's tier-3
//! scratch directory (crates/test-scratch `ScratchDir::new_tier3`: root's,
//! mode 0755, every directory above it root's 0755 — or a refusal naming
//! the directory at fault) and removes it once the child exits: the child,
//! after its drop, can no longer remove root's files. In it the child
//! writes `integrity.key`: root's (written by the root child), mode exactly
//! 0400, 32 octets — the rule of `read_integrity_key` (docs/50 §7.4; Q-270
//! item 1), read with root as the expected owner, so every directory on the
//! path must be root's (Q-468 option 2(b), Q-480 item 5).
//!
//! Sources: docs/50 R50-14, R50-19, §6.1, §6.2, §6.4, §7.4, §9;
//! docs/questions/Q-235 (A-61), Q-270 item 1, Q-480, Q-680. Test identities
//! (uid/gid 61002) are project choices.

use config::DirdSettings;
use daemon_sandbox::{apply, SandboxError, SingleThreadProof};
use directory_daemon::startup::{hardening_plan, read_integrity_key};
use std::env;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// Names the scenario a child process runs.
const SCENARIO_ENV: &str = "DIRD_TIER3_SCENARIO";

/// Names the tier-3 scratch directory the parent made for the child's
/// scenario (module documentation).
const SCRATCH_ENV: &str = "DIRD_TIER3_SCRATCH";

/// The integrity key file's mode. Spec: docs/50 §7.4; Q-270 item 1 ("root,
/// mode exactly 0400").
const KEY_FILE_MODE: u32 = 0o400;

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
    /// The tag of the tier-3 scratch directory the parent makes for the
    /// scenario, if it needs one (module documentation).
    scratch: Option<&'static str>,
    run: fn() -> Outcome,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "unprivileged_apply_fails_closed",
        ignore: None,
        scratch: None,
        run: unprivileged_apply_fails_closed,
    },
    Scenario {
        name: "root_dird_plan_applies_then_key_is_unreadable",
        ignore: Some(ROOT_ONLY),
        scratch: Some("dird3"),
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
        let scratch = match scenario
            .scratch
            .map(test_scratch::ScratchDir::new_tier3)
            .transpose()
        {
            Ok(scratch) => scratch,
            Err(error) => {
                println!("test {} ... FAILED: {error}", scenario.name);
                failed += 1;
                continue;
            }
        };
        let mut command = Command::new(&exe);
        command.env(SCENARIO_ENV, scenario.name);
        if let Some(scratch) = &scratch {
            command.env(SCRATCH_ENV, scratch.path());
        }
        let status = command.status();
        // Removed by root, now that the child has exited.
        drop(scratch);
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

/// The current uid: the owner of a directory this process creates (in the
/// workspace's scratch root, crates/test-scratch — not the temporary
/// directory).
fn current_uid() -> Result<u32, String> {
    let dir = test_scratch::ScratchDir::new("dird-t3-uid").map_err(|e| e.to_string())?;
    dir.uid().map_err(|e| e.to_string())
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
    // The parent's tier-3 scratch directory (module documentation): root's,
    // 0755, every directory above it root's — the protected-file walk from
    // `/` accepts each one for root's expectation (Q-468 option 2(b)).
    let key_dir = env::var_os(SCRATCH_ENV)
        .map(PathBuf::from)
        .ok_or("no tier-3 scratch directory: the parent makes it")?;
    let key_path = key_dir.join("integrity.key");
    // Written by this root process: root's; then mode exactly 0400.
    std::fs::write(&key_path, [0x5D; 32]).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(KEY_FILE_MODE))
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
