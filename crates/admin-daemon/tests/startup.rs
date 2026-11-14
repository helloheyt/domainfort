//! admind's start-up (docs/50 R50-14, R50-15, R50-16, §6.4, §7.1, §7.5):
//! no auditd ⇒ no start; a configuration file not owned by root is
//! refused; the hardening plan is the baseline plus admind's row
//! (`mlockall`); the socket directory's rule; the parameters from the file.
//!
//! Every test names its source. Configuration texts are hand-written in the
//! docs/50 §7.1 format (as crates/config's own samples); no vector comes
//! from any other implementation.

mod support;

use admin_daemon::startup::{
    hardening_plan, params, prepare_socket_directory, read_settings, read_settings_owned_by,
    StartupError, LOCKED_MEMORY_LIMIT, OPEN_FILES_HEADROOM, SOCKET_DIRECTORY_MODE,
};
use admin_daemon::{
    serve, AuditEndpoint, AuditLinkError, DaemonControl, DaemonError, DaemonParams, Limits,
    WORKER_QUEUE_CAPACITY,
};
use config::AdmindSettings;
use core::time::Duration;
use daemon_sandbox::Step;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use support::{my_uid, FakeAuditd, TempDir};
// The files the tests read through crates/protected-file live in a scratch
// directory the walk from `/` accepts (crates/test-scratch, Q-480); sockets
// stay in `TempDir`.
use test_scratch::ScratchDir;

/// admind, every key present (docs/50 §2.4, §3.2, §3.6, §7.1; A-79).
const ADMIND: &str = "\
run_as_uid = 806
run_as_gid = 806
admin_socket = /run/admind/admin.sock
admin_socket_group = 810
min_password_length = 14
dird_admin_socket = /run/dird/admin/dird-admin.sock
dird_uid = 802
keyd_socket = /run/keyd/keyd.sock
keyd_uid = 801
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
frame_timeout = 4s
keyd_deadline = 1s
";

fn settings(text: &str) -> AdmindSettings {
    AdmindSettings::parse(text.as_bytes()).unwrap()
}

/// The parameters of an admind in `dir` whose auditd is at `audit` as
/// `auditd_uid` (dird and keyd are never contacted at start).
fn test_params(dir: &TempDir, audit: &Path, auditd_uid: u32) -> DaemonParams {
    let uid = my_uid(dir);
    DaemonParams {
        admin_socket: dir.join("am.sock"),
        audit: AuditEndpoint {
            socket: audit.to_path_buf(),
            uid: auditd_uid,
        },
        frame_timeout: Duration::from_secs(1),
        min_password_length: 12,
        // The production clients: never contacted at start (and they hold
        // no runtime of their own, unlike the tests' non-Linux connectors,
        // so the parameters may be dropped inside the runtime).
        dird: admin_daemon::links::unix_dird(&dir.join("absent-dird.sock"), uid).unwrap(),
        keyd: admin_daemon::links::unix_keyd(
            &dir.join("absent-keyd.sock"),
            uid,
            Duration::from_secs(1),
        )
        .unwrap(),
        // docs/52 C18 (task R15): the product parameters — the limits, the
        // worker queue and the audit window are the product `serve`'s own
        // constants, not fields.
    }
}

fn run(params: DaemonParams) -> Result<(), DaemonError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let control = DaemonControl::new();
    control.stop();
    runtime.block_on(serve(params, control)).map(|stopped| {
        let _ = stopped.join();
    })
}

/// docs/50 R50-16 ("auditd → keyd → dird → … → admind; a daemon binds
/// nothing until its dependencies were verified"); docs/51 §5.7 (every
/// `SetPassword` is gating on auditd): no auditd ⇒ admind does not start,
/// and `admin.sock` is never bound. An auditd running under another uid is
/// refused too (R50-3: the client checks the server's uid).
#[test]
fn without_auditd_admind_does_not_start() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    let params = test_params(&dir, &dir.join("no-auditd.sock"), uid);
    assert_eq!(
        run(params),
        Err(DaemonError::Audit(AuditLinkError::Connect))
    );
    assert!(!dir.join("am.sock").exists());

    let auditd =
        FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Admind);
    let params = test_params(&dir, &dir.join("a.sock"), uid + 1);
    assert_eq!(
        run(params),
        Err(DaemonError::Audit(AuditLinkError::PeerMismatch))
    );
    assert!(!dir.join("am.sock").exists());

    // With auditd under the configured uid it starts (and stops at once).
    let params = test_params(&dir, &dir.join("a.sock"), uid);
    assert_eq!(run(params), Ok(()));
    assert!(
        !dir.join("am.sock").exists(),
        "the socket is removed at stop"
    );
    drop(auditd);
}

/// Attack — task R9b (docs/questions/Q-512, Q-560; docs/50 §3.2: "the source
/// is set from the uid"): the real auditd (crates/audit-daemon's listener and
/// writer) whose map gives admind's uid another source is refused at its
/// first `Pong`: admind does not start, `admin.sock` is never bound, and
/// auditd records nothing from admind's uid; the one auditd that records
/// admind as admind is served (a positive control).
#[test]
fn an_auditd_recording_admind_under_another_source_is_refused() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    for (name, expected) in [
        (
            "keyd",
            Err(DaemonError::Audit(AuditLinkError::SourceMismatch)),
        ),
        (
            "dird",
            Err(DaemonError::Audit(AuditLinkError::SourceMismatch)),
        ),
        (
            "kdc",
            Err(DaemonError::Audit(AuditLinkError::SourceMismatch)),
        ),
        (
            "ldap-front",
            Err(DaemonError::Audit(AuditLinkError::SourceMismatch)),
        ),
        ("admind", Ok(())),
    ] {
        let logs = support::auditd::TempDir::new();
        let settings = support::auditd::settings_for(&logs, uid, name, 5);
        let auditd = support::auditd::Server::start(
            &settings,
            audit_daemon::listener::ListenerConfig::from_settings(&settings),
            8,
            true,
        );
        let params = test_params(&dir, &logs.socket(), uid);
        assert_eq!(run(params), expected, "{name}");
        assert!(!dir.join("am.sock").exists(), "{name}");
        assert_eq!(auditd.stop(), Some(Ok(())), "{name}");
        let (records, _) =
            support::auditd::read_segment(&logs.base(), 1, audit_log::Anchor::Genesis);
        let from_admind = records.iter().filter(|r| r.source_uid == uid).count();
        assert_eq!(from_admind, 0, "{name}: nothing recorded from admind");
    }
}

/// docs/50 §3.1 ("the daemon manages this explicitly"): a file that is not
/// a socket in the way of `admin_socket` is never removed — admind does not
/// start.
#[test]
fn a_file_in_the_way_of_the_socket_is_not_removed() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    let _auditd =
        FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Admind);
    std::fs::write(dir.join("am.sock"), b"not a socket").unwrap();
    let params = test_params(&dir, &dir.join("a.sock"), uid);
    assert_eq!(run(params), Err(DaemonError::SocketPathOccupied));
    assert_eq!(std::fs::read(dir.join("am.sock")).unwrap(), b"not a socket");
}

/// docs/50 §7.1 ("file root:0644"): a configuration file owned by another
/// account than root is refused before it is parsed — as is a missing one.
#[test]
fn a_configuration_not_owned_by_root_is_refused() {
    let dir = ScratchDir::new("admind-startup").unwrap();
    let uid = dir.uid().unwrap();
    if uid == 0 {
        return; // the file would be root's
    }
    let path = dir.join("admind.conf");
    std::fs::write(&path, ADMIND).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().uid(), uid);
    assert_eq!(read_settings(&path), Err(StartupError::ConfigPermissions));
    // A missing file is unreadable (asked with the test account standing in
    // for root: with root's expectation the walk refuses the test account's
    // own scratch directory first — task T, Q-468).
    assert_eq!(
        read_settings_owned_by(&dir.join("absent.conf"), uid),
        Err(StartupError::ConfigUnreadable)
    );
}

/// Task F7 (A-86 follow-up, "O_NOFOLLOW in every reader"): with the test
/// account standing in for root, the configuration is read through its own
/// path, and a symbolic link to the same file is refused as
/// `ConfigPermissions` (not a regular file) — never followed.
#[test]
fn a_symbolic_link_to_a_valid_configuration_is_refused() {
    let dir = ScratchDir::new("admind-startup").unwrap();
    let uid = dir.uid().unwrap();
    let path = dir.join("admind.conf");
    std::fs::write(&path, ADMIND).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        read_settings_owned_by(&path, uid).unwrap(),
        AdmindSettings::parse(ADMIND.as_bytes()).unwrap()
    );
    let link = dir.join("link.conf");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(
        read_settings_owned_by(&link, uid),
        Err(StartupError::ConfigPermissions)
    );
    assert_eq!(read_settings(&link), Err(StartupError::ConfigPermissions));
}

/// Task T (docs/52 R11; Q-468 options 1, 2(b), A-102): every directory on
/// the configuration's path is checked — a symbolic link in a directory
/// component, or a directory writable by group or others, is refused as
/// `ConfigPermissions`; the file through real, unwritable directories is
/// read.
#[test]
fn a_link_or_a_writable_directory_on_the_path_is_refused() {
    let dir = ScratchDir::new("admind-startup").unwrap();
    let uid = dir.uid().unwrap();
    let real = dir.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = real.join("admind.conf");
    std::fs::write(&path, ADMIND).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_settings_owned_by(&path, uid).is_ok());
    std::os::unix::fs::symlink(&real, dir.join("via")).unwrap();
    assert_eq!(
        read_settings_owned_by(&dir.join("via/admind.conf"), uid),
        Err(StartupError::ConfigPermissions)
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o720)).unwrap();
    assert_eq!(
        read_settings_owned_by(&path, uid),
        Err(StartupError::ConfigPermissions)
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(read_settings_owned_by(&path, uid).is_ok());
}

/// docs/50 R50-14, §6.1, §6.4 (admind: `mlockall` — passwords in transit);
/// docs/51 §7.6; docs/questions/Q-235 (A-61): the plan drops to
/// `run_as_uid` / `run_as_gid`, sets no_new_privs, drops every capability,
/// disables core dumps, makes the process not dumpable, sets umask 077,
/// locks all memory with its MEMLOCK limit, bounds open files by the
/// connection bound, and has no chroot.
#[test]
fn the_hardening_plan_is_the_baseline_plus_admind_row() {
    let plan = hardening_plan(&settings(ADMIND)).unwrap();
    let identity = plan.identity().unwrap();
    assert_eq!((identity.uid(), identity.gid()), (806, 806));
    assert!(plan.sets_no_new_privs());
    assert!(plan.drops_capabilities());
    assert!(plan.disables_core_dumps());
    assert!(plan.makes_not_dumpable());
    assert_eq!(plan.file_mode_mask(), Some(0o077));
    assert!(plan.locks_all_memory());
    assert_eq!(plan.locked_memory_limit(), Some(LOCKED_MEMORY_LIMIT));
    assert_eq!(
        plan.open_files_limit(),
        Some(admin_daemon::rate::MAX_CONNECTIONS as u64 + OPEN_FILES_HEADROOM)
    );
    assert_eq!(plan.change_root(), None);
    assert_eq!(plan.working_directory(), Some(Path::new("/")));
    let steps = plan.steps();
    for step in [
        Step::LockAllMemory,
        Step::SetUserId,
        Step::SetNoNewPrivs,
        Step::ClearCapabilitySets,
        Step::ConfirmIdentityIrreversible,
        Step::VerifyState,
    ] {
        assert!(steps.contains(&step), "{step:?}");
    }
}

/// docs/50 §7.1, §3.6; A-79: the parameters are the file's values
/// (`min_password_length` included) with the daemon's constants for the
/// rest.
#[test]
fn the_parameters_come_from_the_file() {
    // docs/52 C18 (task R15): the product parameters carry only the file's
    // values; the constants the product `serve` adds are read back through
    // the test seam's conversion (the one `serve` uses).
    let params = admin_daemon::test_seams::DaemonParams::from(params(&settings(ADMIND)).unwrap());
    assert_eq!(
        params.admin_socket,
        std::path::PathBuf::from("/run/admind/admin.sock")
    );
    assert_eq!(params.audit.uid, 805);
    assert_eq!(params.min_password_length, 14);
    assert_eq!(params.frame_timeout, Duration::from_secs(4));
    assert_eq!(params.limits, Limits::DEFAULT);
    assert_eq!(params.queue_capacity, WORKER_QUEUE_CAPACITY);
}

/// docs/50 §3.1 (the socket's own directory: mode 0750, owned by the
/// server's uid, group = the channel's clients); docs/51 §4.6
/// (`admin_socket_group`): an existing directory with another owner or
/// group, group write or access for others is refused.
#[test]
fn the_socket_directory_rule() {
    // Inside the workspace (crates/test-scratch, Q-480): since task R11c the
    // preparation walks the directory's parent from `/`.
    let dir = ScratchDir::new("adm-sock").unwrap();
    let uid = dir.uid().unwrap();
    if uid == 0 {
        return;
    }
    let socket_dir = dir.join("adm");
    std::fs::create_dir(&socket_dir).unwrap();
    std::fs::set_permissions(
        &socket_dir,
        std::fs::Permissions::from_mode(SOCKET_DIRECTORY_MODE),
    )
    .unwrap();
    let gid = std::fs::metadata(&socket_dir).unwrap().gid();
    let text = |owner: u32, group: u32| {
        ADMIND
            .replace("run_as_uid = 806", &format!("run_as_uid = {owner}"))
            .replace(
                "admin_socket = /run/admind/admin.sock",
                &format!("admin_socket = {}/admin.sock", socket_dir.display()),
            )
            .replace(
                "admin_socket_group = 810",
                &format!("admin_socket_group = {group}"),
            )
    };
    let ours = settings(&text(uid, gid));
    assert_eq!(prepare_socket_directory(&ours), Ok(()));
    // Another owner, another group.
    assert_eq!(
        prepare_socket_directory(&settings(&text(uid + 1, gid))),
        Err(StartupError::SocketDirectoryPermissions)
    );
    assert_eq!(
        prepare_socket_directory(&settings(&text(uid, gid + 1))),
        Err(StartupError::SocketDirectoryPermissions)
    );
    // Group write, other access.
    for mode in [0o770, 0o751, 0o755] {
        std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            prepare_socket_directory(&ours),
            Err(StartupError::SocketDirectoryPermissions),
            "{mode:o}"
        );
    }
}

/// Task R11c (docs/52 C13; docs/questions Q-532 item 1, A-109): a missing
/// socket directory is created by descriptor with mode 0750, admind's
/// account and `admin_socket_group`; a symbolic link at its name is refused
/// and nothing is changed through it. The test account stands in for
/// admind's, its scratch directory's group for the configured group.
#[test]
fn the_socket_directory_is_created_by_descriptor_and_never_through_a_link() {
    let dir = ScratchDir::new("adm-sock").unwrap();
    let uid = dir.uid().unwrap();
    if uid == 0 {
        return;
    }
    let gid = std::fs::metadata(dir.path()).unwrap().gid();
    let text = |socket_dir: &Path| {
        ADMIND
            .replace("run_as_uid = 806", &format!("run_as_uid = {uid}"))
            .replace(
                "admin_socket = /run/admind/admin.sock",
                &format!("admin_socket = {}/admin.sock", socket_dir.display()),
            )
            .replace(
                "admin_socket_group = 810",
                &format!("admin_socket_group = {gid}"),
            )
    };
    let created = dir.join("admind");
    assert_eq!(prepare_socket_directory(&settings(&text(&created))), Ok(()));
    let metadata = std::fs::symlink_metadata(&created).unwrap();
    assert_eq!(metadata.mode() & 0o7777, SOCKET_DIRECTORY_MODE);
    assert_eq!((metadata.uid(), metadata.gid()), (uid, gid));

    let real = dir.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(
        prepare_socket_directory(&settings(&text(&link))),
        Err(StartupError::SocketDirectoryPermissions)
    );
    assert_eq!(std::fs::metadata(&real).unwrap().mode() & 0o7777, 0o700);
}
