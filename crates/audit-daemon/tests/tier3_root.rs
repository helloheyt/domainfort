//! Tier 3 (docs/50 §9: "hardening — privilege drop, rlimits, no_new_privs —
//! only as root in an isolated environment, `#[ignore]` by default"): the
//! real binary, started as root, must drop to its configured account
//! **before** it opens the log or binds the socket (docs/50 R50-14, §6.2,
//! §6.4; crate::startup step 5), so every file it creates belongs to that
//! account; and a root connection — uid 0, never mapped (R50-3) — is closed
//! without a reply.
//!
//! Run as root on Linux with `cargo test -p audit-daemon --test tier3_root
//! -- --ignored`. Anywhere else the test reports why it skipped.

mod common;

use common::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The account the daemon drops to in this test (numeric, need not exist —
/// docs/50 §7.1 "numeric ids, no NSS lookup").
const RUN_AS: u32 = 4321;

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
    let dir = TempDir::new();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let log_dir = dir.path().join("log");
    let run_dir = dir.path().join("run");
    for sub in [&log_dir, &run_dir] {
        std::fs::create_dir(sub).unwrap();
        std::os::unix::fs::chown(sub, Some(RUN_AS), Some(RUN_AS)).unwrap();
        std::fs::set_permissions(sub, std::fs::Permissions::from_mode(0o750)).unwrap();
    }
    let socket = run_dir.join("audit.sock");
    let base = log_dir.join("audit.log");
    let config_path = dir.path().join("auditd.conf");
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
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o644)).unwrap();

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
