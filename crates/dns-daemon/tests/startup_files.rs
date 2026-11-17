//! dnsd's start-up steps before the runtime: the configuration file read
//! through crates/protected-file, its refusals (no file content echoed),
//! and the port rule — a file naming any port but 53 is refused before any
//! bind (task DN10d). The binding itself is tested in-crate
//! (src/startup.rs), on a loopback port the system picks: no product path
//! and no test seam binds an address that is not from a file dnsd's schema
//! accepted (docs/questions/Q-1025 item 1).
//!
//! Sources: docs/54 §4.7 ("root ⇒ reading the configuration (protected-file,
//! R11b) ⇒ `bind` UDP+TCP 53 for every configured address"); docs/50 R50-15,
//! §7.1 ("file root:0644"; errors never echo a value — A-60); RFC 1035 §4.2
//! ("server port 53 (decimal)"). The files are hand-made; the owner is the
//! test's own uid (the daemon passes root's).

use dns_daemon::startup::{read_settings, StartupError};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use test_scratch::ScratchDir;

/// A hand-made dnsd file listening on `listen`.
fn file(listen: &str) -> String {
    format!(
        "\
run_as_uid = 808
run_as_gid = 808
listen = {listen}
internal_networks = 127.0.0.0/8
dird_dns_socket = /run/dird/dns/dird-dns.sock
dird_uid = 802
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
"
    )
}

fn write(path: &Path, text: &str, mode: u32) {
    std::fs::write(path, text).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
}

struct Scratch {
    dir: ScratchDir,
    uid: u32,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = ScratchDir::new(&format!("dnsd-{tag}")).expect("scratch");
        let uid = std::fs::metadata(dir.path()).expect("metadata").uid();
        Scratch { dir, uid }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

/// docs/54 §4.7; docs/50 §7.1: a regular file of the owner, 0644, parses
/// into dnsd's settings.
#[test]
fn a_protected_configuration_file_is_read() {
    let scratch = Scratch::new("ok");
    let path = scratch.path("dnsd.conf");
    write(&path, &file("127.0.0.1:53"), 0o644);
    let settings = read_settings(&path, scratch.uid).expect("read");
    assert_eq!(settings.listen().len(), 1);
    assert_eq!(settings.dird().uid(), 802);
    assert_eq!(settings.audit().uid(), 805);
}

/// docs/50 §7.1 (root:0644, not writable by group or others); task F7
/// (no link followed): a group-writable file, a symbolic link, a missing
/// file — each refused with its kind; a refused value is never echoed.
#[test]
fn unprotected_or_invalid_files_are_refused() {
    let scratch = Scratch::new("refused");
    let writable = scratch.path("writable.conf");
    write(&writable, &file("127.0.0.1:53"), 0o664);
    assert_eq!(
        read_settings(&writable, scratch.uid).map(drop),
        Err(StartupError::ConfigPermissions)
    );
    let target = scratch.path("target.conf");
    write(&target, &file("127.0.0.1:53"), 0o644);
    let link = scratch.path("link.conf");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    assert_eq!(
        read_settings(&link, scratch.uid).map(drop),
        Err(StartupError::ConfigPermissions)
    );
    assert_eq!(
        read_settings(&scratch.path("absent.conf"), scratch.uid).map(drop),
        Err(StartupError::ConfigUnreadable)
    );
    let outside = scratch.path("outside.conf");
    write(&outside, &file("198.51.100.53:53"), 0o644);
    match read_settings(&outside, scratch.uid) {
        Err(StartupError::Config(message)) => {
            assert!(!message.contains("198.51.100.53"), "{message}");
        }
        other => panic!("expected a configuration refusal, got {other:?}"),
    }
}

/// Task DN10d (A-178 on docs/questions/Q-1025 item 1; RFC 1035 §4.2 —
/// "server port 53 (decimal)"; the NS record names the DC as the zone's name
/// server, docs/54 §3.1): a file naming another port is refused at start-up,
/// before any bind, naming `listen` and never echoing the port; the
/// addresses dnsd binds are all on port 53, crates/config's one definition.
#[test]
fn dnsd_binds_only_port_53() {
    let scratch = Scratch::new("port");
    for listen in ["127.0.0.1:5353", "127.0.0.1:53, 127.0.0.2:1053"] {
        let path = scratch.path("dnsd-port.conf");
        write(&path, &file(listen), 0o644);
        match read_settings(&path, scratch.uid) {
            Err(StartupError::Config(message)) => {
                assert!(message.contains("`listen`"), "{message}");
                assert!(!message.contains("5353"), "no echo: {message}");
                assert!(!message.contains("1053"), "no echo: {message}");
            }
            other => panic!("expected a configuration refusal, got {other:?}"),
        }
        std::fs::remove_file(&path).expect("remove");
    }
    let settings =
        config::DnsdSettings::parse(file("127.0.0.1:53, 127.0.0.2:53").as_bytes()).expect("valid");
    assert!(settings
        .listen()
        .iter()
        .all(|address| address.port() == config::StandardPort::Dns.number()));
    assert_eq!(config::StandardPort::Dns.number(), 53);
}
