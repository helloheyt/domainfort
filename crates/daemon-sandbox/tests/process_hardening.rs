//! Process-level tests of `daemon-sandbox` (docs/50 R50-14, R50-19, §9).
//!
//! Hardening changes the process it runs in, so every scenario runs in a
//! fresh **child process**: this binary re-invokes itself
//! (`std::process::Command` on `std::env::current_exe()`) with the scenario
//! name in an environment variable. The binary has its own `main` (Cargo
//! `harness = false`), so in the child `main` is the first and only thread
//! when the scenario claims its `SingleThreadProof` — the exact situation of a
//! daemon (R50-14). The test harness process itself is never hardened.
//!
//! Two tiers (docs/50 §9):
//! * **CI scenarios** — run by default, unprivileged: building and applying
//!   the safe-unprivileged subset (umask, lowered rlimits, dumpable off,
//!   no_new_privs), reading the state back, the single-thread guard, and the
//!   `Unsupported` path on non-Linux targets.
//! * **Root scenarios** (tier 3: identity drop, chroot, mlockall) — the
//!   equivalent of `#[ignore]`: a `harness = false` binary has no attribute,
//!   so this runner skips them by default and prints the reason; they run
//!   with `cargo test -p daemon-sandbox -- --ignored` (or
//!   `--include-ignored`) and require root on Linux in an isolated
//!   environment.
//!
//! Sources: docs/50 R50-14, R50-19, §6.1, §6.4, §9; the rustix 1.1.6 API docs
//! cited per scenario. Test values (ids, limits, paths) are project choices.

use std::env;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use daemon_sandbox::{
    apply, read_state, verify, HardeningPlan, ProcessIdentity, SandboxError, SingleThreadProof,
    Step, ThreadGuardError, DAEMON_FILE_MODE_MASK,
};

/// Names the scenario a child process runs.
const SCENARIO_ENV: &str = "DAEMON_SANDBOX_TEST_SCENARIO";

/// Optional numeric uid / gid for the root scenarios (default: project test
/// values below).
const TEST_UID_ENV: &str = "DAEMON_SANDBOX_TEST_UID";
const TEST_GID_ENV: &str = "DAEMON_SANDBOX_TEST_GID";
const DEFAULT_TEST_UID: u32 = 61_000;
const DEFAULT_TEST_GID: u32 = 61_000;

/// Why the root scenarios are skipped by default (docs/50 R50-19 tier 3).
const ROOT_ONLY: &str = "requires root on Linux in an isolated environment: it drops the \
process identity (docs/50 R50-19 tier 3); run with -- --ignored";

type Outcome = Result<(), String>;

struct Scenario {
    name: &'static str,
    /// `Some(reason)`: skipped unless `--ignored` / `--include-ignored`.
    ignore: Option<&'static str>,
    run: fn() -> Outcome,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "unprivileged_subset_applies_and_verifies",
        ignore: None,
        run: unprivileged_subset_applies_and_verifies,
    },
    Scenario {
        name: "read_state_without_hardening",
        ignore: None,
        run: read_state_without_hardening,
    },
    Scenario {
        name: "proof_is_claimed_once",
        ignore: None,
        run: proof_is_claimed_once,
    },
    Scenario {
        name: "second_thread_cannot_claim",
        ignore: None,
        run: second_thread_cannot_claim,
    },
    Scenario {
        name: "claim_by_another_thread_blocks_main",
        ignore: None,
        run: claim_by_another_thread_blocks_main,
    },
    Scenario {
        name: "unsupported_target_fails_closed",
        ignore: None,
        run: unsupported_target_fails_closed,
    },
    Scenario {
        name: "unprivileged_drop_stops_at_first_failure",
        ignore: None,
        run: unprivileged_drop_stops_at_first_failure,
    },
    Scenario {
        name: "root_daemon_baseline_drop",
        ignore: Some(ROOT_ONLY),
        run: root_daemon_baseline_drop,
    },
    Scenario {
        name: "root_change_root",
        ignore: Some(ROOT_ONLY),
        run: root_change_root,
    },
    Scenario {
        name: "root_lock_all_memory",
        ignore: Some(ROOT_ONLY),
        run: root_lock_all_memory,
    },
];

fn main() -> ExitCode {
    match env::var(SCENARIO_ENV) {
        Ok(name) => run_child(&name),
        Err(_) => run_parent(),
    }
}

// ---------------------------------------------------------------------------
// Runner

/// In the child: run one scenario on the main (only) thread.
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

/// In the parent: select scenarios like the libtest flags cargo passes
/// (`--ignored`, `--include-ignored`, `--exact`, `--list`, name filters) and
/// run each selected one in a child process.
fn run_parent() -> ExitCode {
    let mut ignored_only = false;
    let mut include_ignored = false;
    let mut exact = false;
    let mut list = false;
    let mut filters = Vec::new();
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--ignored" => ignored_only = true,
            "--include-ignored" => include_ignored = true,
            "--exact" => exact = true,
            "--list" => list = true,
            other if other.starts_with('-') => {} // other libtest flags: no effect here
            other => filters.push(other.to_owned()),
        }
    }
    // `--ignored` runs only the ignored scenarios (the others are filtered
    // out, as libtest does).
    let selected: Vec<&Scenario> = SCENARIOS
        .iter()
        .filter(|s| !ignored_only || s.ignore.is_some())
        .filter(|s| {
            filters.is_empty()
                || filters.iter().any(|f| {
                    if exact {
                        s.name == f
                    } else {
                        s.name.contains(f.as_str())
                    }
                })
        })
        .collect();
    if list {
        for s in &selected {
            println!("{}: test", s.name);
        }
        return ExitCode::SUCCESS;
    }
    let exe = match env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!("cannot locate the test binary: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("\nrunning {} tests", selected.len());
    let (mut passed, mut failed, mut ignored) = (0, 0, 0);
    for s in selected {
        if let Some(reason) = s.ignore {
            if !(ignored_only || include_ignored) {
                ignored += 1;
                println!("test {} ... ignored, {reason}", s.name);
                continue;
            }
        }
        match Command::new(&exe).env(SCENARIO_ENV, s.name).output() {
            Ok(out) if out.status.success() => {
                passed += 1;
                println!("test {} ... ok", s.name);
            }
            Ok(out) => {
                failed += 1;
                println!("test {} ... FAILED", s.name);
                eprintln!("{}", String::from_utf8_lossy(&out.stderr));
            }
            Err(e) => {
                failed += 1;
                println!("test {} ... FAILED (spawn: {e})", s.name);
            }
        }
    }
    let verdict = if failed == 0 { "ok" } else { "FAILED" };
    println!("\ntest result: {verdict}. {passed} passed; {failed} failed; {ignored} ignored\n");
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn ensure(condition: bool, message: &str) -> Outcome {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn claim() -> Result<SingleThreadProof, String> {
    SingleThreadProof::claim().map_err(|e| format!("claim: {e}"))
}

// ---------------------------------------------------------------------------
// CI scenarios (unprivileged)

/// The safe-unprivileged subset: umask 077, core limit 0, a lowered nofile
/// limit, dumpable off, no_new_privs — applied in the child, then verified.
/// Source: docs/50 R50-14, §6.1, §6.4 (the values); rustix 1.1.6
/// process::umask / setrlimit / set_dumpable_behavior,
/// thread::set_no_new_privs (the calls); task P3 (the unprivileged subset).
fn unprivileged_subset_applies_and_verifies() -> Outcome {
    let proof = claim()?;
    let open_files = lowered_open_files_limit();
    let plan = HardeningPlan::builder()
        .file_mode_mask(DAEMON_FILE_MODE_MASK)
        .disable_core_dumps()
        .open_files_limit(open_files)
        .not_dumpable()
        .no_new_privs()
        .build()
        .map_err(|e| format!("plan: {e}"))?;
    let expected_steps = vec![
        Step::SetFileModeMask,
        Step::SetResourceLimits,
        Step::DisableDumpable,
        Step::SetNoNewPrivs,
        Step::VerifyState,
    ];
    ensure(plan.steps() == expected_steps, "plan step order")?;

    let result = apply(&plan, proof);
    if !cfg!(target_os = "linux") {
        return ensure(
            result
                == Err(SandboxError::Unsupported {
                    step: Step::SetFileModeMask,
                }),
            "non-Linux apply must fail closed at the first step",
        );
    }
    let report = result.map_err(|e| format!("apply: {e}"))?;
    ensure(report.applied == expected_steps, "applied steps")?;
    ensure(
        report.previous_file_mode_mask.is_some(),
        "previous mask reported",
    )?;
    ensure(report.state.no_new_privs, "no_new_privs read back")?;
    ensure(
        report.state.dumpable == daemon_sandbox::DumpableState::NotDumpable,
        "dumpable read back",
    )?;
    ensure(
        report.state.core_limit == daemon_sandbox::LimitState::fixed(0),
        "core limit read back",
    )?;
    ensure(
        report.state.open_files_limit == daemon_sandbox::LimitState::fixed(open_files),
        "nofile read back",
    )?;
    // The start-up assertion a daemon makes after apply.
    let again = verify(&plan).map_err(|e| format!("verify: {e}"))?;
    ensure(again == report.state, "verify matches the report")?;
    file_mode_mask_in_effect()
}

/// A nofile limit no higher than the current hard limit (lowering only),
/// and well above what this small child process holds open.
#[cfg(target_os = "linux")]
fn lowered_open_files_limit() -> u64 {
    const CEILING: u64 = 512; // project test value
    match read_state() {
        Ok(state) => state
            .open_files_limit
            .hard
            .map_or(CEILING, |h| h.min(CEILING)),
        Err(_) => CEILING,
    }
}

#[cfg(not(target_os = "linux"))]
fn lowered_open_files_limit() -> u64 {
    512 // never applied off Linux
}

/// A file created after the mask 077 has no group or other permission bit.
/// Source: docs/50 §6.1 ("umask 077"), docs/21 zone 3 as cited there (tight
/// permissions).
#[cfg(target_os = "linux")]
fn file_mode_mask_in_effect() -> Outcome {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = env::temp_dir().join(format!("daemon-sandbox-umask-{}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .open(&path)
        .map_err(|e| format!("create: {e}"))?;
    let mode = file
        .metadata()
        .map_err(|e| format!("metadata: {e}"))?
        .permissions()
        .mode();
    drop(file);
    let _ = std::fs::remove_file(&path);
    ensure(mode & DAEMON_FILE_MODE_MASK == 0, "mask 077 in effect")
}

#[cfg(not(target_os = "linux"))]
fn file_mode_mask_in_effect() -> Outcome {
    Ok(())
}

/// Reading the state needs no hardening and no proof (a daemon can assert it
/// at any time). Source: docs/50 §6.1 (verification); rustix 1.1.6 process
/// and thread getters.
fn read_state_without_hardening() -> Outcome {
    let result = read_state();
    if !cfg!(target_os = "linux") {
        return ensure(
            result
                == Err(SandboxError::Unsupported {
                    step: Step::VerifyState,
                }),
            "non-Linux read-back must fail closed",
        );
    }
    result.map(|_| ()).map_err(|e| format!("read_state: {e}"))
}

/// At most one proof per process. Source: docs/50 R50-14 (one drop, before
/// any thread); crate design (SingleThreadProof).
fn proof_is_claimed_once() -> Outcome {
    let _proof = claim()?;
    ensure(
        SingleThreadProof::claim().map(|_| ()) == Err(ThreadGuardError::AlreadyClaimed),
        "second claim must be refused",
    )
}

/// After main claimed, a second thread cannot obtain a proof, so it can never
/// call `apply`. Source: docs/50 R50-14.
fn second_thread_cannot_claim() -> Outcome {
    let _proof = claim()?;
    let refused = std::thread::spawn(|| {
        SingleThreadProof::claim().map(|_| ()) == Err(ThreadGuardError::AlreadyClaimed)
    })
    .join()
    .map_err(|_| "thread panicked".to_owned())?;
    ensure(refused, "a second thread must not obtain a proof")
}

/// If another thread already exists and claimed first, `main` gets no proof
/// and cannot harden — the daemon must exit. Source: docs/50 R50-14.
fn claim_by_another_thread_blocks_main() -> Outcome {
    let claimed_elsewhere = std::thread::spawn(|| SingleThreadProof::claim().is_ok())
        .join()
        .map_err(|_| "thread panicked".to_owned())?;
    ensure(claimed_elsewhere, "the other thread claims")?;
    ensure(
        SingleThreadProof::claim().map(|_| ()) == Err(ThreadGuardError::AlreadyClaimed),
        "main must be refused once another thread claimed",
    )
}

/// On a non-Linux target the full baseline fails closed at its first step and
/// the read-back is refused. On Linux this path is covered by the unit tests
/// of the crate's unsupported backend. Source: task P3; docs/50 R50-14.
fn unsupported_target_fails_closed() -> Outcome {
    if cfg!(target_os = "linux") {
        return Ok(());
    }
    let proof = claim()?;
    let identity = test_identity()?;
    let plan = HardeningPlan::daemon_baseline(identity)
        .open_files_limit(64)
        .locked_memory_limit(1 << 20)
        .lock_all_memory()
        .change_root("/var/empty")
        .build()
        .map_err(|e| format!("plan: {e}"))?;
    ensure(
        apply(&plan, proof)
            == Err(SandboxError::Unsupported {
                step: Step::SetFileModeMask,
            }),
        "apply must be refused",
    )?;
    ensure(
        verify(&plan)
            == Err(SandboxError::Unsupported {
                step: Step::VerifyState,
            }),
        "verify must be refused",
    )
}

/// Without privilege, the full baseline must stop with an OS error at its
/// first privileged step — the bounding-set removal, which rustix documents
/// as working "only if the thread has the SetPermittedCapabilities
/// capability" — and must not have reached the identity steps. (Skipped when
/// the CI runner is itself root: the drop would then succeed.)
/// Source: docs/50 R50-14, §7.5 (fail closed, exit); rustix 1.1.6
/// thread::remove_capability_from_bounding_set.
fn unprivileged_drop_stops_at_first_failure() -> Outcome {
    if !cfg!(target_os = "linux") {
        return Ok(()); // covered by unsupported_target_fails_closed
    }
    let before = read_state().map_err(|e| format!("read_state: {e}"))?;
    if before.effective_uid == 0 {
        return Ok(());
    }
    let proof = claim()?;
    let identity = test_identity()?;
    let plan = HardeningPlan::daemon_baseline(identity)
        .build()
        .map_err(|e| format!("plan: {e}"))?;
    match apply(&plan, proof) {
        Err(SandboxError::Os {
            step: Step::DropBoundingCapabilities,
            call: "remove_capability_from_bounding_set",
            ..
        }) => {}
        other => {
            return Err(format!(
                "expected a refusal of the bounding set, got {other:?}"
            ))
        }
    }
    let after = read_state().map_err(|e| format!("read_state: {e}"))?;
    ensure(
        after.real_uid == before.real_uid && after.real_gid == before.real_gid,
        "no identity step may run after the failure",
    )?;
    // The steps before the failure were applied (docs: "every earlier step
    // was applied").
    ensure(
        after.dumpable == daemon_sandbox::DumpableState::NotDumpable
            && after.core_limit == daemon_sandbox::LimitState::fixed(0),
        "the steps before the failure were applied",
    )
}

// ---------------------------------------------------------------------------
// Root scenarios (docs/50 R50-19 tier 3) — skipped unless --ignored

fn test_identity() -> Result<ProcessIdentity, String> {
    let read = |name: &str, default: u32| -> Result<u32, String> {
        match env::var(name) {
            Ok(v) => v.parse().map_err(|_| format!("{name} is not a number")),
            Err(_) => Ok(default),
        }
    };
    ProcessIdentity::new(
        read(TEST_UID_ENV, DEFAULT_TEST_UID)?,
        read(TEST_GID_ENV, DEFAULT_TEST_GID)?,
    )
    .map_err(|e| format!("identity: {e}"))
}

fn require_root_on_linux() -> Outcome {
    if !cfg!(target_os = "linux") {
        return Err("root scenarios require Linux".to_owned());
    }
    let state = read_state().map_err(|e| format!("read_state: {e}"))?;
    ensure(state.effective_uid == 0, "root scenarios must run as root")
}

/// Check what every root scenario's report must show: the identity, no
/// groups, no capabilities, no_new_privs, not dumpable.
/// Source: docs/50 §6.4 baseline.
fn check_dropped(report: &daemon_sandbox::HardeningReport, identity: ProcessIdentity) -> Outcome {
    let s = &report.state;
    ensure(
        s.real_uid == identity.uid() && s.effective_uid == identity.uid(),
        "uid",
    )?;
    ensure(
        s.real_gid == identity.gid() && s.effective_gid == identity.gid(),
        "gid",
    )?;
    ensure(s.supplementary_groups.is_empty(), "groups")?;
    ensure(
        s.capabilities == daemon_sandbox::CapabilityState::NONE,
        "capabilities",
    )?;
    ensure(s.no_new_privs, "no_new_privs")?;
    ensure(
        s.dumpable == daemon_sandbox::DumpableState::NotDumpable,
        "dumpable",
    )
}

/// The docs/50 §6.4 baseline from root: identity drop with groups cleared,
/// no_new_privs, capabilities dropped, core 0, not dumpable, umask 077, plus
/// a nofile limit. Source: docs/50 R50-14, §6.2, §6.4; rustix 1.1.6
/// thread::set_thread_groups / set_thread_res_gid / set_thread_res_uid /
/// set_capabilities / remove_capability_from_bounding_set.
fn root_daemon_baseline_drop() -> Outcome {
    let proof = claim()?;
    require_root_on_linux()?;
    let identity = test_identity()?;
    let plan = HardeningPlan::daemon_baseline(identity)
        .open_files_limit(lowered_open_files_limit())
        .build()
        .map_err(|e| format!("plan: {e}"))?;
    let report = apply(&plan, proof).map_err(|e| format!("apply: {e}"))?;
    ensure(report.applied == plan.steps(), "applied steps")?;
    check_dropped(&report, identity)?;
    verify(&plan)
        .map(|_| ())
        .map_err(|e| format!("verify: {e}"))
}

/// chroot into a fresh directory, then chdir to its root, then the baseline
/// drop. Source: docs/50 §6.1, §6.4 (keyd/auditd chroot); rustix 1.1.6
/// process::chroot / chdir.
fn root_change_root() -> Outcome {
    let proof = claim()?;
    require_root_on_linux()?;
    let identity = test_identity()?;
    let jail: PathBuf = env::temp_dir().join(format!("daemon-sandbox-jail-{}", std::process::id()));
    std::fs::create_dir(&jail).map_err(|e| format!("create jail: {e}"))?;
    std::fs::write(jail.join("marker"), b"inside").map_err(|e| format!("marker: {e}"))?;
    let plan = HardeningPlan::daemon_baseline(identity)
        .change_root(&jail)
        .build()
        .map_err(|e| format!("plan: {e}"))?;
    let report = apply(&plan, proof).map_err(|e| format!("apply: {e}"))?;
    ensure(report.applied == plan.steps(), "applied steps")?;
    check_dropped(&report, identity)?;
    let cwd = env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    ensure(
        cwd == std::path::Path::new("/"),
        "working directory is the new root",
    )?;
    ensure(
        std::path::Path::new("/marker").exists(),
        "the jail's content is at /",
    )?;
    ensure(!jail.exists(), "the outside path is not visible")
    // The jail directory is left behind (the process cannot reach it any
    // more); it lives under the system temporary directory.
}

/// keyd's addition: a locked-memory limit set before the drop, then
/// mlockall, then the baseline. Source: docs/50 §6.1, §6.4; rustix 1.1.6
/// mm::mlockall, process::Resource::Memlock.
fn root_lock_all_memory() -> Outcome {
    const LOCKED_MEMORY: u64 = 64 << 20; // project test value (64 MiB)
    let proof = claim()?;
    require_root_on_linux()?;
    let identity = test_identity()?;
    let plan = HardeningPlan::daemon_baseline(identity)
        .locked_memory_limit(LOCKED_MEMORY)
        .lock_all_memory()
        .build()
        .map_err(|e| format!("plan: {e}"))?;
    let report = apply(&plan, proof).map_err(|e| format!("apply: {e}"))?;
    ensure(report.applied == plan.steps(), "applied steps")?;
    check_dropped(&report, identity)?;
    ensure(
        report.state.locked_memory_limit == daemon_sandbox::LimitState::fixed(LOCKED_MEMORY),
        "memlock read back",
    )
}
