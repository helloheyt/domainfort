//! Tier 3 (docs/50 §9: "hardening — privilege drop, rlimits, no_new_privs —
//! only as root in an isolated environment, `#[ignore]` by default"): the
//! real binary, started as root, must drop to its configured account
//! **before** it opens the log or binds the socket (docs/50 R50-14, §6.2,
//! §6.4; crate::startup step 5), so every file it creates belongs to that
//! account; and a root connection — uid 0, never mapped (R50-3) — is closed
//! without a reply.
//!
//! # How to run (docs/questions/Q-680)
//!
//! As root, on Linux, in an isolated machine (never a host), from a
//! checkout **copied as root** — every file and directory root's (`cp -r`
//! as root, not `cp -a` / `rsync -a` of an account's tree, which keep its
//! owner) — to a path of only `A-Z a-z 0-9 . _ - /` whose every directory
//! from `/` is root's, mode 0755, e.g. `/srv/lds`; built and run there as
//! root: `cargo test -p audit-daemon --test tier3_root -- --ignored`. **Not
//! under `/root`** (mode 0700): after its drop the daemon walks to its log
//! and socket directories as `RUN_AS`, and the walk opens every directory
//! `O_RDONLY` (docs/questions/Q-482 item 6). `HOME` does not matter: the
//! fixtures live under `<checkout>/.test-scratch-tier3/`
//! (crates/test-scratch `ScratchDir::new_tier3`), which refuses, naming the
//! directory at fault, on any other layout. Off Linux or not as root the
//! test reports why it skipped.
//!
//! # Fixtures, as production has them
//!
//! | path (under the tier-3 scratch directory) | owner | mode | rule |
//! |---|---|---|---|
//! | every directory above it, and itself | root | 0755 | the walk from `/` for root (configuration) and for `RUN_AS` (log, socket) — Q-468 option 2(b), Q-482 item 6 |
//! | `auditd.conf` | root | 0644 | docs/50 §7.1 ("root:0644"); crate::startup step 3 |
//! | `log/` | `RUN_AS`:`RUN_AS` | 0750 | auditd's data directory: root's or auditd's, not writable by group or others (crate::segments) |
//! | `log/audit.log.<n>` | `RUN_AS` (made by the daemon) | 0600 | `data_file_rule` (A-109) |
//! | `run/` | `RUN_AS`:`RUN_AS` | 0750 | the socket directory, present: auditd's, no group write, nothing for others (docs/50 §3.1; `prepare_socket_directory`, A-113) |
//! | `run/audit.sock` | `RUN_AS` (bound by the daemon) | 0660 | docs/50 §3.1 |

mod common;

use common::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The account the daemon drops to in this test (numeric, need not exist —
/// docs/50 §7.1 "numeric ids, no NSS lookup").
const RUN_AS: u32 = 4321;

/// The configuration file's mode. Spec: docs/50 §7.1 ("root:0644 (not
/// secret)").
const CONFIGURATION_MODE: u32 = 0o644;

/// The mode of auditd's log and socket directories here: rwx for auditd,
/// r-x for its group, nothing for others — what the socket directory may
/// have at most (docs/50 §3.1: "mode 0750") and the log directory's walk
/// accepts (no write for group or others).
const DAEMON_DIRECTORY_MODE: u32 = 0o750;

/// Create `path` as a directory of `RUN_AS` (uid and gid) with
/// [`DAEMON_DIRECTORY_MODE`], set exactly whatever the umask.
fn daemon_directory(path: &Path) {
    std::fs::create_dir(path).unwrap();
    std::os::unix::fs::chown(path, Some(RUN_AS), Some(RUN_AS)).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(DAEMON_DIRECTORY_MODE)).unwrap();
}

#[test]
#[ignore = "root only (docs/50 §9 tier 3): run as root on Linux with --ignored"]
fn daemon_drops_privileges_before_creating_files_and_binding() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipped: process hardening is Linux only (crates/daemon-sandbox)");
        return;
    }
    if own_uid() != 0 {
        eprintln!("skipped: the privilege drop needs root");
        return;
    }
    // Root's, 0755, every directory above root's 0755 — or a refusal that
    // says how to run tier 3 (module documentation).
    let dir = test_scratch::ScratchDir::new_tier3("adt3").unwrap_or_else(|e| panic!("{e}"));
    let log_dir = dir.join("log");
    let run_dir = dir.join("run");
    daemon_directory(&log_dir);
    daemon_directory(&run_dir);
    let socket = run_dir.join("audit.sock");
    let base = log_dir.join("audit.log");
    let config_path = dir.join("auditd.conf");
    // Written by this root process: root's.
    std::fs::write(
        &config_path,
        format!(
            "run_as_uid = {RUN_AS}\nrun_as_gid = {RUN_AS}\naudit_socket = {}\n\
             audit_log_path = {}\nuid_sources = {}:kdc\n",
            socket.display(),
            base.display(),
            RUN_AS + 1
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        &config_path,
        std::fs::Permissions::from_mode(CONFIGURATION_MODE),
    )
    .unwrap();
    assert_eq!(std::fs::metadata(&config_path).unwrap().uid(), 0);

    let mut child = Command::new(env!("CARGO_BIN_EXE_audit-daemon"))
        .arg(&config_path)
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the daemon");
    let started = Instant::now();
    while !socket.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            panic!(
                "daemon exited early ({status}): {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(started.elapsed() < Duration::from_secs(10), "no socket");
        std::thread::sleep(Duration::from_millis(50));
    }

    let socket_meta = std::fs::symlink_metadata(&socket).unwrap();
    assert_eq!(socket_meta.uid(), RUN_AS, "socket bound after the drop");
    assert_eq!(socket_meta.mode() & 0o777, 0o660);
    let segment = audit_daemon::segments::segment_path(&base, 1);
    let segment_meta = std::fs::metadata(&segment).unwrap();
    assert_eq!(segment_meta.uid(), RUN_AS, "log created after the drop");
    assert_eq!(segment_meta.mode() & 0o777, 0o600);

    // Root is never mapped: closed with no reply.
    let mut client = connect(&socket);
    let frame = ipc_audit::encode_request(&ipc_audit::AuditRequest::Ping).unwrap();
    let _ = std::io::Write::write_all(&mut client, frame.as_bytes());
    assert_eq!(receive(&mut client), Got::Closed);

    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit-daemon: audit log created"),
        "{stderr}"
    );
    assert!(stderr.contains("UNSIGNED mode"), "{stderr}");
}
