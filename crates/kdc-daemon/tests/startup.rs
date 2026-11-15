//! Tier 1 (docs/50 §9: in-process): the kdc daemon's start-up inputs —
//! the configuration's owner check and its explicit development policy
//! format, the policy file through the shared loader (owner, mode, format
//! 2), the serving parameters derived from a configuration, the listeners'
//! port (88 only — task DN10c), and the hardening plan.
//!
//! The root-owned case cannot be made by an unprivileged test: the reading
//! functions take the expected owner, and `main` passes uid 0. Nothing here
//! binds a port: the file names port 88 only, so the binding per address is
//! tested in-crate on a system-chosen loopback port (src/startup_tests.rs).
//!
//! Sources: docs/50 R50-9, R50-14, R50-15, §4.1, §6.2, §6.4, §7.1, §7.2;
//! RFC 4120 §7.2.3.2; docs/questions/Q-230 (A-60), Q-270 item 2, A-68,
//! Q-1024. Hand-made values.

mod common_policy {
    //! The minimal shared policy of these tests (format 2, A-68).
    use pdp::{PolicyVersion, RuleId};
    use policy_store::{DevelopmentPolicy, MandatoryFast};

    pub fn policy(version: u64) -> DevelopmentPolicy {
        DevelopmentPolicy {
            version: PolicyVersion(version),
            principals: Default::default(),
            subtrees: Vec::new(),
            mandatory_fast: MandatoryFast {
                bootstrap_group: dtyp::Sid::new(dtyp::SECURITY_NT_AUTHORITY, &[21, 7, 8, 9, 1500])
                    .unwrap(),
                first_rule_id: RuleId(100),
            },
            rules: Vec::new(),
            anonymous: Vec::new(),
        }
    }
}

use config::KdcSettings;
use core::time::Duration;
use kdc_daemon::startup::{hardening_plan, read_policy, read_settings, StartupError};
use kdc_daemon::{DaemonParams, AS_QUEUE_CAPACITY, TGS_QUEUE_CAPACITY};
use pdp::IpScope;
use policy_store::{LoadError, PolicyError, MARKER, SUPERSEDED_FORMAT};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use test_scratch::ScratchDir;

/// A unique scratch directory (0700) inside the workspace (crates/
/// test-scratch: the protected-file walk from `/` accepts it; Q-480),
/// removed on drop. No socket is bound in it.
struct TempDir(PathBuf, #[allow(dead_code)] ScratchDir);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let dir = ScratchDir::new(&format!("kdcs-{tag}")).unwrap();
        TempDir(dir.path().to_path_buf(), dir)
    }
}

fn write(path: &Path, octets: &[u8], mode: u32) {
    std::fs::write(path, octets).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A kdc configuration (docs/50 §7.1) with `listen` as given (inside the
/// zone table, which also holds the loopback network the port test uses —
/// docs/50 R50-9, task R15b); account 61003.
fn kdc_config(listen: &str) -> String {
    format!(
        "\
run_as_uid = 61003
run_as_gid = 61003
listen = {listen}
internal_networks = 10.0.0.0/8, fd00::/16, 127.0.0.0/8
keyd_socket = /run/keyd/keyd.sock
keyd_uid = 61001
dird_kdc_socket = /run/dird/kdc/dird-kdc.sock
dird_uid = 61002
policy_store_path = /etc/domain/policy.store
policy_store_format = unsigned-development
audit_socket = /run/auditd/audit.sock
auditd_uid = 61005
max_tcp_connections = 512
max_tcp_connections_per_source = 8
tcp_frame_timeout = 5s
max_requests_per_tcp_connection = 32
dird_deadline = 1s
"
    )
}

/// docs/50 §3.6, §4.1, §7.1; Q-230 item 4 (A-60: limits without a number
/// are daemon constants): the parameters come from the configuration and
/// the daemon's constants; the zone table classifies by the configured
/// networks (docs/50 §4.1).
#[test]
fn parameters_from_the_configuration() {
    let settings = KdcSettings::parse(kdc_config("10.0.0.5:88").as_bytes()).unwrap();
    // docs/52 C18 (task R15): the product parameters carry only the file's
    // values; the constants the product `serve` adds are read back through
    // the test seam's conversion (the one `serve` uses).
    let p = kdc_daemon::test_seams::DaemonParams::from(DaemonParams::from_settings(&settings));
    assert_eq!((p.keyd_uid, p.dird_uid, p.audit.uid), (61001, 61002, 61005));
    assert_eq!(p.audit.socket, Path::new("/run/auditd/audit.sock"));
    assert_eq!(p.keyd_deadline, Duration::from_secs(2));
    assert_eq!(p.dird_deadline, Duration::from_secs(1));
    assert_eq!(p.tcp.max_connections, 512);
    assert_eq!(p.tcp.max_per_source, 8);
    assert_eq!(p.tcp.first_frame_timeout, Duration::from_secs(10));
    assert_eq!(p.tcp.frame_timeout, Duration::from_secs(5));
    assert_eq!(p.tcp.idle_timeout, Duration::from_secs(30));
    assert_eq!(p.tcp.max_requests, 32);
    assert_eq!(p.as_queue_capacity, AS_QUEUE_CAPACITY);
    assert_eq!(p.tgs_queue_capacity, TGS_QUEUE_CAPACITY);
    assert_eq!(p.udp_max_reply_len, kdc::DEFAULT_UDP_MAX_REPLY_LEN);
    assert_eq!(p.zones.len(), 3);
    assert_eq!(
        p.zones.scope("10.9.8.7".parse().unwrap()),
        IpScope::Internal
    );
    assert_eq!(p.zones.scope("fd00::1".parse().unwrap()), IpScope::Internal);
    assert_eq!(
        p.zones.scope("192.0.2.1".parse().unwrap()),
        IpScope::External
    );
}

/// docs/50 R50-14, §6.1, §6.4 (kdc: "capabilities only until the bind"; no
/// key, so no mlockall): the plan is the baseline for the kdc's account with
/// an open-files limit above the TCP connection bound, and no memory
/// locking.
#[test]
fn the_hardening_plan() {
    let settings = KdcSettings::parse(kdc_config("10.0.0.5:88").as_bytes()).unwrap();
    let plan = hardening_plan(&settings).unwrap();
    let identity = plan.identity().unwrap();
    assert_eq!((identity.uid(), identity.gid()), (61003, 61003));
    assert!(plan.sets_no_new_privs());
    assert!(plan.drops_capabilities());
    assert!(plan.disables_core_dumps());
    assert!(plan.makes_not_dumpable());
    assert!(!plan.locks_all_memory());
    assert_eq!(plan.file_mode_mask(), Some(0o077));
    assert!(plan.open_files_limit().is_some_and(|n| n > 512));
}

/// docs/50 §7.1 ("file root:0644"); A-68: a configuration not owned by the
/// expected owner, or writable by group / others, is refused before it is
/// parsed; one without the explicit development format is refused.
#[test]
fn the_configuration_owner_and_format() {
    let dir = TempDir::new("conf");
    let uid = std::fs::metadata(&dir.0).unwrap().uid();
    let path = dir.0.join("kdc.conf");
    write(&path, kdc_config("10.0.0.5:88").as_bytes(), 0o644);
    assert!(read_settings(&path, uid).is_ok());
    assert_eq!(
        read_settings(&path, uid + 1).err(),
        Some(StartupError::ConfigPermissions)
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert_eq!(
        read_settings(&path, uid).err(),
        Some(StartupError::ConfigPermissions)
    );
    let without =
        kdc_config("10.0.0.5:88").replace("policy_store_format = unsigned-development\n", "");
    write(&path, without.as_bytes(), 0o644);
    assert!(matches!(
        read_settings(&path, uid),
        Err(StartupError::Config(_))
    ));
    assert_eq!(
        read_settings(&dir.0.join("absent"), uid).err(),
        Some(StartupError::ConfigUnreadable)
    );
}

/// docs/50 §7.2 (the same file as dird; absent or invalid ⇒ no start);
/// A-68 (format 2; format 1 refused): the policy file is read through the
/// shared loader.
#[test]
fn the_policy_file_through_the_shared_loader() {
    let dir = TempDir::new("pol");
    let uid = std::fs::metadata(&dir.0).unwrap().uid();
    let path = dir.0.join("policy.store");
    let policy = common_policy::policy(9);
    write(&path, &policy.encode().unwrap(), 0o644);
    let loaded = read_policy(&path, uid).unwrap();
    assert_eq!(loaded, policy);
    assert_eq!(loaded.snapshot().unwrap().version(), pdp::PolicyVersion(9));
    assert_eq!(
        read_policy(&path, uid + 1).err(),
        Some(StartupError::Policy(LoadError::Permissions))
    );
    let mut v1 = MARKER.to_vec();
    v1.push(SUPERSEDED_FORMAT);
    v1.extend_from_slice(&[0; 16]);
    write(&path, &v1, 0o644);
    assert_eq!(
        read_policy(&path, uid).err(),
        Some(StartupError::Policy(LoadError::Policy(
            PolicyError::Superseded
        )))
    );
    assert_eq!(
        read_policy(&dir.0.join("absent"), uid).err(),
        Some(StartupError::Policy(LoadError::Unreadable))
    );
}

/// Task F7 (A-86 follow-up, "O_NOFOLLOW in every reader"): the kdc's
/// configuration and policy files are read through their own paths, and a
/// symbolic link to either is refused as a permissions error (not a regular
/// file) — never followed.
#[test]
fn a_symbolic_link_to_a_valid_configuration_or_policy_is_refused() {
    let dir = TempDir::new("link");
    let uid = std::fs::metadata(&dir.0).unwrap().uid();
    let config = dir.0.join("kdc.conf");
    write(&config, kdc_config("10.0.0.5:88").as_bytes(), 0o644);
    assert!(read_settings(&config, uid).is_ok());
    let config_link = dir.0.join("kdc-link.conf");
    std::os::unix::fs::symlink(&config, &config_link).unwrap();
    assert_eq!(
        read_settings(&config_link, uid).err(),
        Some(StartupError::ConfigPermissions)
    );
    let policy = dir.0.join("policy.store");
    write(&policy, &common_policy::policy(9).encode().unwrap(), 0o644);
    assert!(read_policy(&policy, uid).is_ok());
    let policy_link = dir.0.join("policy-link.store");
    std::os::unix::fs::symlink(&policy, &policy_link).unwrap();
    assert_eq!(
        read_policy(&policy_link, uid).err(),
        Some(StartupError::Policy(LoadError::Permissions))
    );
}

/// Task T (docs/52 R11; Q-468 options 1, 2(b), A-102): every directory on
/// the configuration's and the policy's path is checked — a symbolic link in
/// a directory component, or a directory writable by group or others, is
/// refused as the file's permissions error; both files through real,
/// unwritable directories are read.
#[test]
fn a_link_or_a_writable_directory_on_the_path_is_refused() {
    let dir = TempDir::new("dirs");
    let uid = std::fs::metadata(&dir.0).unwrap().uid();
    let real = dir.0.join("real");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&real)
        .unwrap();
    let config = real.join("kdc.conf");
    write(&config, kdc_config("10.0.0.5:88").as_bytes(), 0o644);
    let policy = real.join("policy.store");
    write(&policy, &common_policy::policy(9).encode().unwrap(), 0o644);
    assert!(read_settings(&config, uid).is_ok());
    assert!(read_policy(&policy, uid).is_ok());
    std::os::unix::fs::symlink(&real, dir.0.join("via")).unwrap();
    assert_eq!(
        read_settings(&dir.0.join("via/kdc.conf"), uid).err(),
        Some(StartupError::ConfigPermissions)
    );
    assert_eq!(
        read_policy(&dir.0.join("via/policy.store"), uid).err(),
        Some(StartupError::Policy(LoadError::Permissions))
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(
        read_settings(&config, uid).err(),
        Some(StartupError::ConfigPermissions)
    );
    assert_eq!(
        read_policy(&policy, uid).err(),
        Some(StartupError::Policy(LoadError::Permissions))
    );
}

/// Task DN10c (docs/questions/Q-1016 item 4, A-176; Q-1024): the zone
/// advertises the KDC on port 88 (RFC 4120 §7.2.3.2), so the file the kdc
/// binds from can name no other port — refused at start-up, before any bind
/// (`StartupError::Config` naming `listen`); every address of an accepted
/// file is on 88. The binding itself is tested in-crate on a system-chosen
/// loopback port (src/startup_tests.rs); nothing here binds port 88.
#[test]
fn the_kdc_binds_only_port_88() {
    let dir = TempDir::new("port");
    let uid = std::fs::metadata(&dir.0).unwrap().uid();
    let path = dir.0.join("kdc.conf");
    write(&path, kdc_config("127.0.0.1:1088").as_bytes(), 0o644);
    match read_settings(&path, uid) {
        Err(StartupError::Config(error)) => {
            assert!(error.contains("`listen`"), "{error}");
            assert!(!error.contains("1088"), "no echo: {error}");
        }
        other => panic!("{other:?}"),
    }
    let settings = KdcSettings::parse(kdc_config("127.0.0.1:88, 10.0.0.5:88").as_bytes()).unwrap();
    assert!(settings
        .listen()
        .iter()
        .all(|address| address.port() == config::StandardPort::Kerberos.number()));
    assert_eq!(config::StandardPort::Kerberos.number(), 88);
}
