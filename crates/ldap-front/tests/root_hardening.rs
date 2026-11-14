//! Tier 3 (docs/50 R50-19, §9: "hardening — privilege drop, rlimits,
//! no_new_privs — only as root in an isolated environment, `#[ignore]` by
//! default"): ldap-front's own hardening plan (`ldap_front::startup::
//! hardening_plan`) applied the way `main` applies it — after the TLS key
//! was read and the listeners were bound as root.
//!
//! Every scenario runs in a fresh **child process** of this binary, whose
//! `main` is the first and only thread when it claims its
//! `SingleThreadProof` (R50-14), as the other daemons' tier-3 tests do. The
//! parent is never hardened. No scenario binds a privileged port: the
//! listener is a loopback socket on a port the system picks.
//!
//! * `unprivileged_apply_fails_closed` — default: as a non-root user (or off
//!   Linux) applying the plan fails, never half-succeeds silently (docs/50
//!   §7.5: the daemon then exits).
//! * `root_front_plan_applies_after_key_and_bind` — skipped unless
//!   `--ignored` / `--include-ignored`; needs root on Linux in an isolated
//!   environment. As root it writes a root-owned 0400 key file and reads it
//!   through the daemon's own reader (as `main` does before the drop), binds
//!   a TCP listener, applies the plan (identity drop, no_new_privs, no
//!   capabilities, core 0, not dumpable, umask), which `apply` reads back
//!   and checks; afterwards the key file can no longer be read (the drop
//!   took effect — R50-12: the key is read before it), the bound socket is
//!   still open, and the tokio runtime starts and takes it (`from_std`).
//!
//! Sources: docs/50 R50-12, R50-14, R50-19, §6.1, §6.2, §6.4, §9;
//! docs/questions/Q-235 (A-61). Test identities (uid/gid 61004) are project
//! choices; the key octets are arbitrary test data (the reader does not
//! parse them).

use config::LdapFrontSettings;
use daemon_sandbox::{apply, SandboxError, SingleThreadProof};
use ldap_front::startup::{hardening_plan, read_private_key};
use std::env;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Command, ExitCode};

const SCENARIO_ENV: &str = "LDAP_FRONT_TIER3_SCENARIO";

const ROOT_ONLY: &str = "requires root on Linux in an isolated environment: it drops the \
process identity (docs/50 R50-19 tier 3); run with -- --ignored";

/// An ldap-front configuration (docs/50 §7.1) whose account is 61004; the
/// paths and addresses are only parsed here.
const FRONT: &str = "\
run_as_uid = 61004
run_as_gid = 61004
ldap_listen = 10.0.0.5:389
ldaps_listen = 10.0.0.5:636
tls_certificate_path = /etc/ldap-front/dc-cert.der
tls_private_key_path = /etc/ldap-front/dc-key.der
dird_ldap_socket = /run/dird/ldap/dird-ldap.sock
dird_uid = 61002
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
        name: "root_front_plan_applies_after_key_and_bind",
        ignore: Some(ROOT_ONLY),
        run: root_front_plan_applies_after_key_and_bind,
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
    let dir = env::temp_dir().join(format!("lfront-t3-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let uid = std::fs::metadata(&dir).map_err(|e| e.to_string())?.uid();
    let _ = std::fs::remove_dir(&dir);
    Ok(uid)
}

/// docs/50 §7.5, R50-14: without root (or off Linux) the front's plan
/// cannot be applied — `apply` reports the failing step, never success.
fn unprivileged_apply_fails_closed() -> Outcome {
    let proof = SingleThreadProof::claim().map_err(|e| e.to_string())?;
    if current_uid()? == 0 {
        println!("skipped: running as root");
        return Ok(());
    }
    let settings = LdapFrontSettings::parse(FRONT.as_bytes()).map_err(|e| e.to_string())?;
    let plan = hardening_plan(&settings).map_err(|e| e.to_string())?;
    match apply(&plan, proof) {
        Ok(_) => Err(String::from("applied without privilege")),
        Err(SandboxError::Os { .. } | SandboxError::Unsupported { .. }) => Ok(()),
        Err(other) => Err(format!("unexpected failure: {other}")),
    }
}

/// docs/50 R50-12 ("the key is read as root before the privilege drop, the
/// file 0400"), R50-14, §6.2, §6.4 (ldap-front: "the TLS key is read as
/// root, then the privileges drop"): as root on Linux, the key is read and
/// the socket bound before the drop; afterwards the key file is unreadable,
/// the socket still usable, and the runtime takes it.
fn root_front_plan_applies_after_key_and_bind() -> Outcome {
    let proof = SingleThreadProof::claim().map_err(|e| e.to_string())?;
    // Inside the workspace (crates/test-scratch, Q-480): the protected-file
    // walk from `/` must accept every directory for root's expectation — so
    // the checkout must be root's (P-27).
    let root_dir = test_scratch::ScratchDir::new("lfront-t3-root").map_err(|e| e.to_string())?;
    std::fs::set_permissions(root_dir.path(), std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let key_path = root_dir.join("dc-key.der");
    std::fs::write(&key_path, [0x5Au8; 64]).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o400))
        .map_err(|e| e.to_string())?;
    let key = read_private_key(&key_path, 0).map_err(|e| e.to_string())?;
    if key.len() != 64 {
        return Err(String::from("the key was not read before the drop"));
    }
    drop(key);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let settings = LdapFrontSettings::parse(FRONT.as_bytes()).map_err(|e| e.to_string())?;
    let plan = hardening_plan(&settings).map_err(|e| e.to_string())?;
    let report = apply(&plan, proof).map_err(|e| e.to_string())?;
    if report.applied != plan.steps() {
        return Err(String::from("not every step was applied"));
    }
    if std::fs::read(&key_path).is_ok() {
        return Err(String::from("the key file is readable after the drop"));
    }
    tcp.local_addr().map_err(|e| e.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        tcp.set_nonblocking(true).map_err(|e| e.to_string())?;
        tokio::net::TcpListener::from_std(tcp).map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    })?;
    std::thread::spawn(|| ())
        .join()
        .map_err(|_| String::from("thread failed"))?;
    Ok(())
}
