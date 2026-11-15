//! The start-up steps before the runtime: reading the protected
//! configuration file, the parameters it gives, binding (TCP only), and the
//! hardening plan.
//!
//! Sources: docs/50 R50-14 (hardening before any thread), R50-15 (one file,
//! closed keys), §6.1, §6.2 (bind as root, then drop), §6.4 (the baseline),
//! §7.1 (root:0644, bounded); docs/53 R53-3 (TCP 464 only — no UDP), §3.3,
//! §5.1; docs/52 §3.18 (C18: the product parameters come from the file
//! only); docs/questions/Q-468 (A-102: the protected-file walk). The sample
//! file is written by hand for these tests (obviously fake uids, paths and
//! the TEST-NET-1 / loopback addresses).

#![cfg(unix)]

use core::time::Duration;
use kpasswd_front::startup::{
    bind_listeners, hardening_plan, read_settings, StartupError, OPEN_FILES_HEADROOM,
};
use kpasswd_front::FrontParams;
use std::os::unix::fs::PermissionsExt;
use test_scratch::ScratchDir;

/// A kpasswd-front file (docs/50 §7.1): the listener is a loopback address
/// on a port the test does not bind (nothing binds it here except
/// `bind_listeners`, which the test gives its own file).
const SAMPLE: &str = "\
# kpasswd-front (docs/53 K8)
run_as_uid = 61464
run_as_gid = 61464
listen = 127.0.0.1:1464
internal_networks = 127.0.0.0/8, 192.0.2.0/24
realm = EXAMPLE.TEST
dird_kpasswd_socket = /run/dird/kpasswd/dird-kpasswd.sock
dird_uid = 61002
audit_socket = /run/auditd/audit.sock
auditd_uid = 61005
max_tcp_connections = 512
max_tcp_connections_per_source = 8
tcp_first_frame_timeout = 7s
tcp_frame_timeout = 9s
dird_deadline = 20s
";

fn write_config(dir: &ScratchDir, text: &str, mode: u32) -> std::path::PathBuf {
    let path = dir.join("kpasswd-front.conf");
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

/// docs/50 R50-15, §7.1; docs/52 §3.18: the protected file is read and its
/// values become the daemon's parameters, one for one.
#[test]
fn the_file_gives_the_parameters() {
    let dir = ScratchDir::new("kpasswd-front-settings").unwrap();
    let owner = dir.uid().unwrap();
    let path = write_config(&dir, SAMPLE, 0o644);
    let settings = read_settings(&path, owner).unwrap();
    let params = FrontParams::from_settings(&settings);
    assert_eq!(params.realm, "EXAMPLE.TEST");
    assert_eq!(params.dird.uid, 61002);
    assert_eq!(
        params.dird.socket.to_str(),
        Some("/run/dird/kpasswd/dird-kpasswd.sock")
    );
    assert_eq!(params.audit.uid, 61005);
    assert_eq!(params.limits.max_connections, 512);
    assert_eq!(params.limits.max_per_source, 8);
    assert_eq!(params.timeouts.first_frame, Duration::from_secs(7));
    assert_eq!(params.timeouts.reply_write, Duration::from_secs(9));
    assert_eq!(params.timeouts.dird_deadline, Duration::from_secs(20));
    assert_eq!(params.internal_networks.len(), 2);
}

/// docs/50 §7.1 ("root:0644" — not writable by group or others); Q-468: a
/// group-writable file, a file of another owner and a missing file are
/// refused; a refused configuration never echoes its value (A-60).
#[test]
fn the_file_must_be_protected_and_valid() {
    let dir = ScratchDir::new("kpasswd-front-protect").unwrap();
    let owner = dir.uid().unwrap();
    let path = write_config(&dir, SAMPLE, 0o664);
    assert_eq!(
        read_settings(&path, owner),
        Err(StartupError::ConfigPermissions)
    );
    let path = write_config(&dir, SAMPLE, 0o644);
    assert_eq!(
        read_settings(&path, owner + 1),
        Err(StartupError::ConfigPermissions)
    );
    assert_eq!(
        read_settings(&dir.join("absent.conf"), owner),
        Err(StartupError::ConfigUnreadable)
    );
    let secret_looking = SAMPLE.replace("realm = EXAMPLE.TEST", "realm = hunter2$SECRET");
    let path = write_config(&dir, &secret_looking, 0o644);
    match read_settings(&path, owner) {
        Err(StartupError::Config(text)) => assert!(!text.contains("hunter2"), "{text}"),
        other => panic!("{other:?}"),
    }
}

/// docs/53 R53-3 (TCP only — A-117: no UDP code path); docs/50 §6.2: the
/// listeners are TCP listeners on the configured addresses, and nothing
/// else is bound.
#[test]
fn only_tcp_listeners_are_bound() {
    let dir = ScratchDir::new("kpasswd-front-bind").unwrap();
    let owner = dir.uid().unwrap();
    // A port the system picks, then freed, so the file names a free port.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let text = SAMPLE.replace("127.0.0.1:1464", &format!("127.0.0.1:{port}"));
    let path = write_config(&dir, &text, 0o644);
    let settings = read_settings(&path, owner).unwrap();
    let listeners = bind_listeners(&settings).unwrap();
    assert_eq!(listeners.tcp.len(), 1);
    assert_eq!(listeners.tcp[0].local_addr().unwrap().port(), port);
    // The UDP port of the same number is still free: no UDP socket exists.
    assert!(std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok());
}

/// docs/50 R50-14, §6.1, §6.4 (the baseline: identity drop, no_new_privs,
/// no capabilities, core 0, not dumpable; nofile from the connection
/// quota); docs/53 §3.3: the plan drops to the configured account and
/// holds no memory lock (the front holds no secret).
#[test]
fn the_hardening_plan_is_the_baseline() {
    let dir = ScratchDir::new("kpasswd-front-plan").unwrap();
    let owner = dir.uid().unwrap();
    let path = write_config(&dir, SAMPLE, 0o644);
    let settings = read_settings(&path, owner).unwrap();
    let plan = hardening_plan(&settings).unwrap();
    let identity = plan.identity().unwrap();
    assert_eq!((identity.uid(), identity.gid()), (61464, 61464));
    assert!(plan.sets_no_new_privs());
    assert!(plan.drops_capabilities());
    assert!(plan.disables_core_dumps());
    assert!(plan.makes_not_dumpable());
    assert!(!plan.locks_all_memory());
    let expected = 512 + ipc_kpasswd::MAX_FRONT_CONNECTIONS as u64 + 1 + OPEN_FILES_HEADROOM;
    assert_eq!(plan.open_files_limit(), Some(expected));
    assert_eq!(plan.working_directory().and_then(|p| p.to_str()), Some("/"));
}
