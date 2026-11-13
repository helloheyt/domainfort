//! Tier 3 of task P12 (docs/50 R50-19, §9: "only as root in an isolated
//! environment, `#[ignore]` by default"): the five daemons with **distinct
//! uids**, which the single-uid harness of tier 2 cannot show
//! (docs/questions/Q-310):
//!
//! * auditd labels each record with the source its map gives the
//!   connection's uid — keyd's records `Keyd` with keyd's uid, the kdc's
//!   `Kdc` with the kdc's uid, dird's `Dird` with dird's uid (docs/50 §3.2:
//!   "the source is set from the uid, not from the event body");
//! * keyd records the kdc's uid as the Kdc caller (R50-3, §3.2);
//! * on Linux the kdc reaches keyd and dird through the **production**
//!   connectors (`ipc_keyd::UnixConnector`, `ipc_directory::UnixConnector`:
//!   rustix `socket_peercred`, the server uid checked — R50-3), which the
//!   macOS run of tier 2 replaces by a tokio-based test connector (Q-245
//!   item 11).
//!
//! # How the uids are made (never run by the author — Q-310)
//!
//! One test process, run as root on Linux. Each daemon is started from a
//! thread that first sets **its own** credentials — supplementary groups
//! cleared, gid set to one shared test group, uid set to the daemon's test
//! account — with rustix `thread::set_thread_groups`,
//! `thread::set_thread_res_gid`, `thread::set_thread_res_uid`, which per
//! their docs.rs pages act on the calling thread (docs/50 §6.1; the same
//! calls as crates/daemon-sandbox). Every thread the daemon's runner then
//! spawns (its runtime, its engine) is created by that thread. The shared
//! group lets each daemon reach the others' sockets (0660, docs/50 §3.1:
//! the group is the channel's clients); identity remains the uid (R50-3).
//! The test's own thread stays root: it plays the client and reads the log.
//! The fixtures dird and auditd read as root (the policy file, the key
//! file) are root-owned, as in production (docs/50 §6.2, §7.1).
//!
//! The uids and gid (61100-61105) are project choices for an isolated test
//! machine.
//!
//! Sources: docs/50 R50-3, R50-17, R50-19, §3.1, §3.2, §6.1, §6.2, §8.1,
//! §9; docs/questions Q-245 item 11; RFC 4120 §7.2.1, §7.2.2; RFC 4511
//! §4.5.1. Every value is made here.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use audit_log::Source;
use common::*;
use core::time::Duration;
use directory_daemon::{SharedClock, StoreSource};
use ipc_audit::{decode_event, EventBody, KeydRole};
use keyd::Role;
use keyd_daemon::CallerMap;
use std::os::unix::fs::{chown, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use support::kdcd::{message, tcp_send, udp_send, Handles, HeldClock, Kdcd};
use support::ldap_client::{root_dse, tcp, tls_over, LdapReader};
use support::tls::{client_config, p256_key, placeholder_server_config};
use support::*;

const AUDITD_UID: u32 = 61101;
const KEYD_UID: u32 = 61102;
const DIRD_UID: u32 = 61103;
const KDC_UID: u32 = 61104;
const FRONT_UID: u32 = 61105;
/// The one group of every daemon thread (module documentation).
const SHARED_GID: u32 = 61100;

/// docs/50 R50-19 tier 3; Q-310: distinct uids per daemon — each record of
/// auditd's verified log carries its sender's uid and the source auditd's
/// map gives it; keyd recorded the kdc's uid as its Kdc caller; the login
/// and an LDAPS rootDSE succeed through the production peer-credential
/// connectors.
#[test]
#[ignore = "tier 3: requires root on Linux in an isolated environment (it runs daemon threads \
            under distinct uids, docs/50 R50-19); run with -- --ignored"]
fn distinct_uids_each_daemon_is_its_own_audit_source() {
    within(TEST_BOUND, || {
        if let Err(message) = run() {
            panic!("{message}");
        }
    });
}

/// Set the calling thread's credentials (module documentation).
/// Spec: docs/50 §6.1 (rustix 1.1.6 `thread::set_thread_groups`,
/// `set_thread_res_gid`, `set_thread_res_uid`: "of the calling thread");
/// crates/daemon-sandbox linux.rs (the same calls, the same order).
#[cfg(target_os = "linux")]
fn become_account(uid: u32, gid: u32) -> Result<(), String> {
    use rustix::thread::{self, Gid, Uid};
    thread::set_thread_groups(&[]).map_err(|e| format!("set_thread_groups: {e:?}"))?;
    let gid = Gid::from_raw(gid);
    thread::set_thread_res_gid(gid, gid, gid).map_err(|e| format!("set_thread_res_gid: {e:?}"))?;
    let uid = Uid::from_raw(uid);
    thread::set_thread_res_uid(uid, uid, uid).map_err(|e| format!("set_thread_res_uid: {e:?}"))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn become_account(_uid: u32, _gid: u32) -> Result<(), String> {
    Err(String::from(
        "tier 3 needs Linux: per-thread credentials (rustix `thread`)",
    ))
}

/// Run `start` on a new thread that first becomes `uid` (with the shared
/// group); the daemon handle it returns is handed back.
fn as_account<T: Send + 'static>(
    uid: u32,
    start: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    std::thread::spawn(move || {
        become_account(uid, SHARED_GID)?;
        start()
    })
    .join()
    .map_err(|_| format!("the start of uid {uid} panicked"))?
}

/// A directory owned by `uid` (mode 0755) inside `base`.
fn owned_dir(base: &Path, name: &str, uid: u32) -> Result<PathBuf, String> {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    chown(&dir, Some(uid), Some(SHARED_GID)).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn run() -> Result<(), String> {
    // As root only: the base directory (0755, root-owned) proves it.
    let base = std::env::temp_dir().join(format!("e2e-t3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    if std::fs::metadata(&base).map_err(|e| e.to_string())?.uid() != 0 {
        let _ = std::fs::remove_dir_all(&base);
        return Err(String::from("tier 3 must run as root (docs/50 R50-19)"));
    }
    let result = deploy_and_check(&base);
    let _ = std::fs::remove_dir_all(&base);
    result
}

fn deploy_and_check(base: &Path) -> Result<(), String> {
    let audit_dir = owned_dir(base, "audit", AUDITD_UID)?;
    let keyd_dir = owned_dir(base, "keyd", KEYD_UID)?;
    let dird_dir = owned_dir(base, "dird", DIRD_UID)?;
    let audit_socket = audit_dir.join("a.sock");
    let audit_log = audit_dir.join("audit.log");
    let keyd_socket = keyd_dir.join("k.sock");
    let dird_kdc_socket = dird_dir.join("d.sock");
    let dird_ldap_socket = dird_dir.join("l.sock");

    // Fixtures: dird's own file (owned by dird, 0600), a root reference copy
    // for the handles, the root-owned key and policy files.
    let database = dird_dir.join("r.redb");
    drop(dird::Directory::standard(&database));
    chown(&database, Some(DIRD_UID), Some(SHARED_GID)).map_err(|e| e.to_string())?;
    let local = dird::Directory::standard(&base.join("l.redb"));
    let handles = Handles::read(&local.store);
    let key_path = base.join("integrity.key");
    write_file(&key_path, &dird::TEST_KEY, 0o400);
    let policy_path = base.join("policy.store");
    write_policy(&policy_path, POLICY_VERSION);

    // 1. auditd, its map naming every sender's own uid.
    let text = format!(
        "run_as_uid = {AUDITD_UID}\nrun_as_gid = {SHARED_GID}\naudit_socket = {}\n\
         audit_log_path = {}\nuid_sources = {KEYD_UID}:keyd, {DIRD_UID}:dird, \
         {KDC_UID}:kdc, {FRONT_UID}:ldap-front\nframe_timeout = 5s\n",
        audit_socket.display(),
        audit_log.display()
    );
    let settings = config::AuditdSettings::parse(text.as_bytes()).map_err(|e| e.to_string())?;
    let listener = audit_daemon::listener::ListenerConfig::from_settings(&settings);
    let auditd = as_account(AUDITD_UID, move || {
        Ok(support::auditd::Server::start(
            &settings, listener, 64, true,
        ))
    })?;
    let audit = |socket: &Path| keyd_daemon::AuditEndpoint {
        socket: socket.to_path_buf(),
        uid: AUDITD_UID,
    };

    // 2. keyd: the kdc's uid is its Kdc caller.
    let keyd_params = keyd_daemon::DaemonParams {
        keyd_socket: keyd_socket.clone(),
        callers: CallerMap::new(&[(KDC_UID, Role::Kdc)]).map_err(|e| e.to_string())?,
        audit: audit(&audit_socket),
        frame_timeout: Duration::from_secs(1),
        max_connections_per_uid: 8,
        queue_capacity: 16,
        window: ipc_audit::WindowConfig::DEFAULT,
    };
    let keyd_clock = TestClock::at(keyd_started());
    let clock = keyd_clock.clone();
    let keyd = as_account(KEYD_UID, move || {
        keyd_support::Daemon::start(keyd_params, clock, move |started| {
            support::kdcd::directory_keyd(started, handles)
        })
    })?;
    keyd_clock.set(now());

    // 3. dird: its kdc channel for the kdc's uid, its LDAP channel for the
    //    front's; the key and the policy read as root before it starts.
    // (the values of crates/directory-daemon support `params`, every uid
    // its own)
    let dird_params = directory_daemon::DaemonParams {
        kdc_socket: dird_kdc_socket.clone(),
        kdc_uid: KDC_UID,
        audit: directory_daemon::AuditEndpoint {
            socket: audit_socket.clone(),
            uid: AUDITD_UID,
        },
        frame_timeout: Duration::from_secs(1),
        view_lifetime: Duration::from_secs(5),
        max_views: 4,
        max_connections: 8,
        queue_capacity: directory_daemon::ENGINE_QUEUE_CAPACITY,
        naming_context: dird::naming_context(),
        keyd: dird::keyd_config(),
        ldap_socket: dird_ldap_socket.clone(),
        ldap_front_uid: FRONT_UID,
        max_ldap_sessions: directory_daemon::MAX_LDAP_SESSIONS,
        ldap_queue_capacity: directory_daemon::LDAP_QUEUE_CAPACITY,
        dns_host_name: String::from(DNS_HOST_NAME),
        zones: loopback_internal(),
        audit_window: ipc_audit::WindowConfig::DEFAULT,
        clock: SharedClock::new(FixedTime),
    };
    let key =
        directory_daemon::startup::read_integrity_key(&key_path, 0).map_err(|e| e.to_string())?;
    let dird_policy =
        directory_daemon::startup::read_policy(&policy_path, 0).map_err(|e| e.to_string())?;
    let source = StoreSource::File {
        path: database,
        key,
        owner_uid: DIRD_UID,
    };
    let dird = as_account(DIRD_UID, move || {
        dird::Dird::start(dird_params, source, dird_policy)
    })?;

    // 4. the kdc: keyd, dird and auditd each with its own uid.
    let mut kdc_params = support::kdcd::kdc_params(&audit_socket, AUDITD_UID);
    kdc_params.keyd_uid = KEYD_UID;
    kdc_params.dird_uid = DIRD_UID;
    let kdc_policy =
        kdc_daemon::startup::read_policy(&policy_path, 0).map_err(|e| e.to_string())?;
    let (keyd_path, dird_path) = (keyd_socket.clone(), dird_kdc_socket.clone());
    let kdcd = as_account(KDC_UID, move || {
        Kdcd::start(
            kdc_params,
            kdc_policy,
            &keyd_path,
            &dird_path,
            HeldClock::at(now()),
        )
    })?;

    // 5. ldap-front.
    let tls_key = p256_key();
    let tls = placeholder_server_config(&tls_key);
    let front_params = ldap_front::FrontParams {
        dird: ldap_front::Endpoint {
            socket: dird_ldap_socket,
            uid: DIRD_UID,
        },
        audit: ldap_front::Endpoint {
            socket: audit_socket,
            uid: AUDITD_UID,
        },
        timeouts: front_timeouts(),
        limits: ldap_front::ConnectionLimits::DEFAULT,
    };
    let front = as_account(FRONT_UID, move || Front::start(front_params, tls))?;

    // The client: the bootstrap, the armored AS and the TGS over UDP then
    // TCP (RFC 4120 §7.2.1, §7.2.2), and an LDAPS rootDSE.
    let exchange = |request: &[u8]| -> Vec<u8> {
        let _ = udp_send(kdcd.udp, request, Duration::from_secs(5));
        message(tcp_send(kdcd.tcp, request))
    };
    let machine_tgt = open_as_rep(
        &exchange(
            &AsReqSpec::machine()
                .with_timestamp(&machine_key(AES256))
                .encode(),
        ),
        &machine_key(AES256),
    );
    let armor = Armor::new(&machine_tgt, now(), 1);
    let alice = AsReqSpec::alice()
        .with_challenge(&alice_key(AES256))
        .encode_armored(&armor, now());
    let tgt = open_fast_as_rep(&exchange(&alice), &armor.key, &alice_key(AES256));
    let spec = TgsReqSpec::service();
    let (tgs, _) = spec.encode(&tgt);
    let (rep, _) = open_tgs_rep(&exchange(&tgs), &tgt, &spec);
    if open_ticket(&rep.0.ticket, &service_key()).cname != alice_name() {
        return Err(String::from("the service ticket does not name alice"));
    }
    let client = client_config(&tls_key);
    let mut stream = tls_over(tcp(front.ldaps), &client)?;
    std::io::Write::write_all(&mut stream, &root_dse(1)).map_err(|e| e.to_string())?;
    let mut reader = LdapReader::default();
    reader.next(&mut stream).ok_or("no rootDSE entry")?;
    reader.next(&mut stream).ok_or("no rootDSE done")?;
    drop(stream);

    // Stop: senders first (each flushes its window), then auditd.
    front.stop()?;
    kdcd.stop()?;
    dird.stop()?;
    keyd.stop()?;
    if let Some(writer) = auditd.stop() {
        writer.map_err(|e| format!("auditd's writer: {e:?}"))?;
    }

    // The verified log: each sender its own source and uid.
    let (_, records) = verified_log(&audit_log)?;
    let mut seen = Vec::new();
    for record in &records {
        if record.source == Source::Auditd {
            continue;
        }
        let expected_uid = match record.source {
            Source::Keyd => KEYD_UID,
            Source::Dird => DIRD_UID,
            Source::Kdc => KDC_UID,
            Source::LdapFront => FRONT_UID,
            other => return Err(format!("unexpected source {other:?}")),
        };
        if record.source_uid != expected_uid {
            return Err(format!(
                "a {:?} record from uid {}",
                record.source, record.source_uid
            ));
        }
        let event = decode_event(&record.payload).map_err(|e| format!("{e:?}"))?;
        match (&event, record.source) {
            (EventBody::Keyd(keyd_record), Source::Keyd) => {
                if keyd_record.caller_uid != KDC_UID || keyd_record.caller_role != KeydRole::Kdc {
                    return Err(String::from("keyd recorded another caller than the kdc"));
                }
            }
            (EventBody::Kdc(_), Source::Kdc)
            | (EventBody::Ldap(_), Source::Dird)
            | (EventBody::WindowSummary(_), _) => {}
            _ => {
                return Err(format!(
                    "a {:?} event under {:?}",
                    event.shape(),
                    record.source
                ))
            }
        }
        if !seen.contains(&record.source) {
            seen.push(record.source);
        }
    }
    for source in [Source::Keyd, Source::Kdc, Source::Dird] {
        if !seen.contains(&source) {
            return Err(format!("no record from {source:?}"));
        }
    }
    Ok(())
}
