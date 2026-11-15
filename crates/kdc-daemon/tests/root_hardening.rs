//! Tier 3 (docs/50 R50-19, §9: "hardening — privilege drop, rlimits,
//! no_new_privs — only as root in an isolated environment, `#[ignore]` by
//! default"): the kdc's own hardening plan (`kdc_daemon::startup::
//! hardening_plan`) applied the way `main` applies it — after the listeners
//! were bound as root.
//!
//! Every scenario runs in a fresh **child process** of this binary, whose
//! `main` is the first and only thread when it claims its
//! `SingleThreadProof` (R50-14), as the other daemons' tier-3 tests do. The
//! parent is never hardened. No scenario binds a privileged port: the
//! listeners are loopback sockets on ports the system picks.
//!
//! * `unprivileged_apply_fails_closed` — default: as a non-root user (or off
//!   Linux) applying the kdc's plan fails, never half-succeeds silently
//!   (docs/50 §7.5: the daemon then exits).
//! * `root_kdc_plan_applies_after_bind` — skipped unless `--ignored` /
//!   `--include-ignored`; needs root on Linux in an isolated environment. As
//!   root it binds a UDP socket and a TCP listener (as `main` does before
//!   the drop), applies the plan (identity drop, no_new_privs, no
//!   capabilities, core 0, not dumpable, umask), which `apply` reads back
//!   and checks; afterwards a root-only directory can no longer be written
//!   (the drop took effect), the bound sockets are still open, and the
//!   tokio runtime starts and takes them (`from_std`) — the order of `main`.
//!
//! Sources: docs/50 R50-14, R50-19, §6.1, §6.2, §6.4, §9; docs/questions/
//! Q-235 (A-61), Q-275 item 3. Test identities (uid/gid 61003) are project
//! choices.

use config::KdcSettings;
use daemon_sandbox::{apply, SandboxError, SingleThreadProof};
use kdc_daemon::startup::hardening_plan;
use std::env;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Command, ExitCode};

const SCENARIO_ENV: &str = "KDC_TIER3_SCENARIO";

const ROOT_ONLY: &str = "requires root on Linux in an isolated environment: it drops the \
process identity (docs/50 R50-19 tier 3); run with -- --ignored";

/// A kdc configuration (docs/50 §7.1) whose account is 61003; the listen
/// address is only parsed here (nothing binds it).
const KDC: &str = "\
run_as_uid = 61003
run_as_gid = 61003
listen = 10.0.0.5:88
internal_networks = 10.0.0.0/8
keyd_socket = /run/keyd/keyd.sock
keyd_uid = 61001
dird_kdc_socket = /run/dird/kdc/dird-kdc.sock
dird_uid = 61002
policy_store_path = /etc/domain/policy.store
policy_store_format = unsigned-development
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
        name: "root_kdc_plan_applies_after_bind",
        ignore: Some(ROOT_ONLY),
        run: root_kdc_plan_applies_after_bind,
    },
];

fn main() -> ExitCode {
    match env::var(SCENARIO_ENV) {
        Ok(name) => run_child(&name),
        Err(_) => run_parent(),
    }
}

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

fn current_uid() -> Result<u32, String> {
    let dir = env::temp_dir().join(format!("kdcd-t3-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let uid = std::fs::metadata(&dir).map_err(|e| e.to_string())?.uid();
    let _ = std::fs::remove_dir(&dir);
    Ok(uid)
}

/// docs/50 §7.5, R50-14: without root (or off Linux) the kdc's plan cannot
/// be applied — `apply` reports the failing step, never success.
fn unprivileged_apply_fails_closed() -> Outcome {
    let proof = SingleThreadProof::claim().map_err(|e| e.to_string())?;
    if current_uid()? == 0 {
        println!("skipped: running as root");
        return Ok(());
    }
    let settings = KdcSettings::parse(KDC.as_bytes()).map_err(|e| e.to_string())?;
    let plan = hardening_plan(&settings).map_err(|e| e.to_string())?;
    match apply(&plan, proof) {
        Ok(_) => Err(String::from("applied without privilege")),
        Err(SandboxError::Os { .. } | SandboxError::Unsupported { .. }) => Ok(()),
        Err(other) => Err(format!("unexpected failure: {other}")),
    }
}

/// docs/50 R50-14, §6.2 ("bind ⇒ … drop … ⇒ only then the runtime; the
/// listeners handed to tokio with `from_std`"), §6.4 (kdc: "capabilities
/// only until the bind"): as root on Linux, sockets bound before the drop
/// stay usable after it; the drop took effect; the runtime takes them.
fn root_kdc_plan_applies_after_bind() -> Outcome {
    let proof = SingleThreadProof::claim().map_err(|e| e.to_string())?;
    let root_dir = env::temp_dir().join(format!("kdcd-t3-root-{}", std::process::id()));
    std::fs::create_dir_all(&root_dir).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&root_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let settings = KdcSettings::parse(KDC.as_bytes()).map_err(|e| e.to_string())?;
    let plan = hardening_plan(&settings).map_err(|e| e.to_string())?;
    let report = apply(&plan, proof).map_err(|e| e.to_string())?;
    if report.applied != plan.steps() {
        return Err(String::from("not every step was applied"));
    }
    if std::fs::write(root_dir.join("probe"), b"x").is_ok() {
        return Err(String::from(
            "a root-only directory is writable after the drop",
        ));
    }
    udp.local_addr().map_err(|e| e.to_string())?;
    tcp.local_addr().map_err(|e| e.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        udp.set_nonblocking(true).map_err(|e| e.to_string())?;
        tcp.set_nonblocking(true).map_err(|e| e.to_string())?;
        tokio::net::UdpSocket::from_std(udp).map_err(|e| e.to_string())?;
        tokio::net::TcpListener::from_std(tcp).map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    })?;
    std::thread::spawn(|| ())
        .join()
        .map_err(|_| String::from("thread failed"))?;
    Ok(())
}
