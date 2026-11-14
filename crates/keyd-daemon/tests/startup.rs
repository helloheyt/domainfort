//! The start-up steps before the runtime (no sockets, no privilege): the
//! configuration checks, the daemon parameters, the socket directory check
//! and keyd's hardening plan.
//!
//! Every test names its source. Configuration texts are hand-written in the
//! docs/50 §7.1 format (as crates/config's own samples); no vector comes from
//! any other implementation.

mod support;

use config::KeydSettings;
use daemon_sandbox::Step;
use keyd::Role;
use keyd_daemon::startup::{
    hardening_plan, prepare_socket_directory, read_settings, read_settings_owned_by, realm,
    StartupError, LOCKED_MEMORY_LIMIT, OPEN_FILES_HEADROOM,
};
use keyd_daemon::{DaemonParams, IntentAckBudget, ENGINE_QUEUE_CAPACITY, INTENT_ACK_BUDGET};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;
use support::{my_uid, TempDir};
// The configuration files the tests read through crates/protected-file live
// in a scratch directory the walk from `/` accepts (crates/test-scratch,
// Q-480); sockets stay in `TempDir`.
use test_scratch::ScratchDir;

/// keyd, every key present (docs/50 §2.4, R50-3, R50-18, §3.6, §7.1).
const KEYD: &str = "\
run_as_uid = 801
run_as_gid = 801
realm = EXAMPLE.TEST
keyd_socket = /run/keyd/keyd.sock
uid_roles = 803:Kdc, 806:Directory, 807:Admin, 802:Ldap
key_store = insecure-development
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
frame_timeout = 4s
max_connections_per_uid = 6
";

fn settings(text: &str) -> KeydSettings {
    KeydSettings::parse(text.as_bytes()).unwrap()
}

/// docs/50 R50-14, §6.1, §6.4 (keyd: the baseline plus `mlockall` with its
/// MEMLOCK limit and a small nofile); docs/questions/Q-235 (A-61): the plan
/// drops to `run_as_uid` / `run_as_gid`, sets no_new_privs, drops every
/// capability, disables core dumps, makes the process not dumpable, sets
/// umask 077, locks memory, bounds open files by the connection quotas, and
/// has no chroot (docs/questions/Q-260 item 8).
#[test]
fn keyds_hardening_plan_is_the_baseline_plus_keyds_row() {
    let settings = settings(KEYD);
    let plan = hardening_plan(&settings).unwrap();
    let identity = plan.identity().unwrap();
    assert_eq!((identity.uid(), identity.gid()), (801, 801));
    assert!(plan.sets_no_new_privs());
    assert!(plan.drops_capabilities());
    assert!(plan.disables_core_dumps());
    assert!(plan.makes_not_dumpable());
    assert_eq!(plan.file_mode_mask(), Some(0o077));
    assert!(plan.locks_all_memory());
    assert_eq!(plan.locked_memory_limit(), Some(LOCKED_MEMORY_LIMIT));
    assert_eq!(plan.open_files_limit(), Some(4 * 6 + OPEN_FILES_HEADROOM));
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

/// docs/50 §7.1, R50-3, §3.6; docs/questions/Q-230 item 4 (numbers docs/50
/// does not give are daemon constants): the daemon's parameters are the
/// file's values, with the uid map as keyd roles.
#[test]
fn daemon_parameters_come_from_the_file() {
    let settings = settings(KEYD);
    let params = DaemonParams::from_settings(&settings).unwrap();
    assert_eq!(params.keyd_socket, Path::new("/run/keyd/keyd.sock"));
    assert_eq!(params.audit.socket, Path::new("/run/auditd/audit.sock"));
    assert_eq!(params.audit.uid, 805);
    assert_eq!(params.frame_timeout, Duration::from_secs(4));
    assert_eq!(params.max_connections_per_uid, 6);
    assert_eq!(params.queue_capacity, ENGINE_QUEUE_CAPACITY);
    assert_eq!(params.callers.caller(803).map(|c| c.role), Some(Role::Kdc));
    assert_eq!(params.callers.caller(802).map(|c| c.role), Some(Role::Ldap));
    assert_eq!(params.callers.caller(801), None, "keyd's own uid");
    assert_eq!(params.callers.caller(805), None, "auditd's uid");
    assert!(realm(&settings).is_ok());
    // The intent budget is the production constant, whatever the file says
    // (docs/questions/Q-365 / A-88, Q-415).
    assert_eq!(params.intent_ack_budget, IntentAckBudget::PRODUCTION);
    assert_eq!(params.intent_ack_budget.get(), INTENT_ACK_BUDGET);
}

/// docs/questions/Q-415 (decision A-93's follow-up F5: "no configuration-file
/// key, so an operator cannot widen it"): keyd's closed key table has no key
/// for the intent budget, and a file naming one is refused as an unknown key.
#[test]
fn no_configuration_key_sets_the_intent_budget() {
    assert!(KeydSettings::KEYS
        .iter()
        .all(|key| !key.contains("intent") && !key.contains("budget")));
    let text = format!("{KEYD}intent_ack_budget = 2s\n");
    assert_eq!(
        KeydSettings::parse(text.as_bytes()).err().map(|e| e.kind()),
        Some(config::ErrorKind::UnknownKey)
    );
}

/// docs/50 §7.1 ("file root:0644"; the daemon checks modes): a
/// configuration file that is not owned by root, or is group/other-writable,
/// is refused before it is parsed; a missing file is unreadable.
#[test]
fn a_configuration_file_not_owned_by_root_is_refused() {
    let dir = ScratchDir::new("kdd-startup").unwrap();
    let path = dir.join("keyd.conf");
    std::fs::write(&path, KEYD).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    if dir.uid().unwrap() == 0 {
        // As root the owner check passes; the mode check must refuse.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    }
    assert_eq!(
        read_settings(&path).err(),
        Some(StartupError::ConfigPermissions)
    );
    // A missing file is unreadable (asked with the test account standing in
    // for root: with root's expectation the walk refuses the test account's
    // own scratch directory first — task T, Q-468).
    assert_eq!(
        read_settings_owned_by(&dir.join("missing.conf"), dir.uid().unwrap()).err(),
        Some(StartupError::ConfigUnreadable)
    );
}

/// docs/50 §3.1 ("each socket in its own directory, owned by the server's
/// uid, mode 0750"): an existing socket directory is accepted only when it is
/// owned by keyd's account with no group write and no access for others.
#[test]
fn an_existing_socket_directory_must_belong_to_keyd() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if uid == 0 {
        return; // run_as_uid may not be 0 (docs/50 §6.1).
    }
    let socket_dir = dir.join("run");
    std::fs::create_dir(&socket_dir).unwrap();
    let text = |run_as: u32| {
        format!(
            "run_as_uid = {run_as}\nrun_as_gid = {run_as}\nrealm = EXAMPLE.TEST\n\
             keyd_socket = {}/keyd.sock\nuid_roles = {}:Kdc\n\
             key_store = insecure-development\naudit_socket = {}/audit.sock\n\
             auditd_uid = {}\n",
            socket_dir.display(),
            run_as + 1,
            dir.path().display(),
            run_as + 2
        )
    };
    let mine = settings(&text(uid));
    std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(prepare_socket_directory(&mine), Ok(()));
    std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o757)).unwrap();
    assert_eq!(
        prepare_socket_directory(&mine),
        Err(StartupError::SocketDirectoryPermissions)
    );
    std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(
        prepare_socket_directory(&mine),
        Err(StartupError::SocketDirectoryPermissions)
    );
    std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    let someone_else = settings(&text(uid + 10));
    assert_eq!(
        prepare_socket_directory(&someone_else),
        Err(StartupError::SocketDirectoryPermissions)
    );
}

/// Task F7 (A-86 follow-up, "O_NOFOLLOW in every reader"): with the test
/// account standing in for root, the configuration file is read through its
/// own path, and a symbolic link to the same file is refused as
/// `ConfigPermissions` (not a regular file) — never followed.
#[test]
fn a_symbolic_link_to_a_valid_configuration_is_refused() {
    let dir = ScratchDir::new("kdd-startup").unwrap();
    let path = dir.join("keyd.conf");
    std::fs::write(&path, KEYD).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let owner = dir.uid().unwrap();
    assert_eq!(
        read_settings_owned_by(&path, owner).unwrap(),
        settings(KEYD)
    );
    let link = dir.join("link.conf");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(
        read_settings_owned_by(&link, owner).err(),
        Some(StartupError::ConfigPermissions)
    );
    assert_eq!(
        read_settings(&link).err(),
        Some(StartupError::ConfigPermissions)
    );
}

/// Task T (docs/52 R11; Q-468 options 1, 2(b), A-102): every directory on
/// the configuration's path is checked — a symbolic link in a directory
/// component, or a directory writable by group or others, is refused as
/// `ConfigPermissions`; the file through real, unwritable directories is
/// read.
#[test]
fn a_link_or_a_writable_directory_on_the_path_is_refused() {
    let dir = ScratchDir::new("kdd-startup").unwrap();
    let owner = dir.uid().unwrap();
    let real = dir.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = real.join("keyd.conf");
    std::fs::write(&path, KEYD).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_settings_owned_by(&path, owner).is_ok());
    std::os::unix::fs::symlink(&real, dir.join("via")).unwrap();
    assert_eq!(
        read_settings_owned_by(&dir.join("via/keyd.conf"), owner).err(),
        Some(StartupError::ConfigPermissions)
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o702)).unwrap();
    assert_eq!(
        read_settings_owned_by(&path, owner).err(),
        Some(StartupError::ConfigPermissions)
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(read_settings_owned_by(&path, owner).is_ok());
}
