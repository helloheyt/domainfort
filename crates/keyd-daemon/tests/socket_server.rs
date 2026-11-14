//! Tier 2 (docs/50 §9): the real daemon (`keyd_daemon::serve`) on a real
//! Unix socket in a temporary directory, with the development keyd and the
//! system clock, an injected `uid → Role` map naming the test's own uid, real
//! peer credentials (tokio `UnixStream::peer_cred`) on both the keyd socket
//! and the audit socket, and a minimal auditd (tests/support).
//!
//! Every test names its source. Every value is constructed by hand for these
//! tests; no vector comes from any other implementation.

mod support;

use ipc::Refused;
use ipc_audit::{EventBody, KeydOperation};
use ipc_keyd::{Answer, Call};
use keyd::{AuthnError, Error, KeyHandle, KeyPurpose, PrincipalId, Role};
use keyd_daemon::startup::development_keyd;
use keyd_daemon::{CallerMap, DaemonParams, SystemClock};
use krb_proto::{PaData, Realm};
use std::time::{Duration, Instant};
use support::{
    eventually, my_uid, params, skip_as_root, Daemon, FakeAuditd, RawClient, Received, TempDir,
};

fn realm() -> Realm {
    Realm::new("EXAMPLE.ORG").unwrap()
}

fn start(params: DaemonParams) -> Result<Daemon, String> {
    Daemon::start(params, SystemClock, development_keyd(realm()))
}

fn verify_preauth() -> Call {
    Call::VerifyPreauth {
        client: KeyHandle::new(
            PrincipalId::from_bytes([0xA1; 16]),
            KeyPurpose::PrincipalLongterm,
        ),
        padata: PaData {
            padata_type: 2,
            padata_value: vec![0x30, 0x00],
        },
        armor: None,
    }
}

/// A daemon whose map gives the test's uid `role` (or maps only another
/// uid when `role` is `None`), with a running fake auditd.
struct World {
    dir: TempDir,
    auditd: FakeAuditd,
    daemon: Daemon,
}

fn world(role: Option<Role>, adjust: impl FnOnce(&mut DaemonParams)) -> Option<World> {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return None;
    }
    let entries = match role {
        Some(role) => vec![(uid, role)],
        None => vec![(uid.wrapping_add(1000).max(1), Role::Kdc)],
    };
    let mut params = params(&dir, CallerMap::new(&entries).unwrap(), uid);
    adjust(&mut params);
    let auditd = FakeAuditd::start(&params.audit.socket);
    let daemon = start(params).unwrap();
    Some(World {
        dir,
        auditd,
        daemon,
    })
}

/// docs/50 R50-3, §3.2: a peer uid that is not in the map gets no role; the
/// connection is closed without any reply.
#[test]
fn an_unmapped_uid_is_closed_with_no_reply() {
    let Some(world) = world(None, |_| {}) else {
        return;
    };
    let mut client = RawClient::connect(&world.daemon.socket);
    client.send(&Call::Ping);
    assert_eq!(client.receive(), Received::Closed);
    world.daemon.stop().unwrap();
}

/// docs/50 R50-3, §3.4, §7.5: a mapped Kdc uid can `ping` and
/// `describe_config` over the socket, several requests on one connection
/// (strict request → reply, R50-7).
#[test]
fn a_mapped_kdc_uid_can_ping_and_describe_config() {
    let Some(world) = world(Some(Role::Kdc), |_| {}) else {
        return;
    };
    let mut client = RawClient::connect(&world.daemon.socket);
    for _ in 0..3 {
        assert!(matches!(
            client.call(&Call::Ping),
            Some(Ok(Answer::Ping(Ok(Role::Kdc))))
        ));
    }
    match client.call(&Call::DescribeConfig) {
        Some(Ok(Answer::DescribeConfig(Ok(described)))) => {
            assert_eq!(described.description.realm, realm());
            assert_eq!(described.caller_role, Role::Kdc);
        }
        other => panic!("{other:?}"),
    }
    world.daemon.stop().unwrap();
}

/// docs/50 §3.2 (the role comes from keyd's `uid → Role` map), §3.4
/// (`DescribeConfig` — Kdc, Ldap); docs/questions/Q-351 (A-87: the reply
/// carries the caller's role as keyd resolved it from the peer uid): the
/// same peer uid mapped to Ldap is answered the same description, naming
/// the caller role Ldap.
#[test]
fn describe_config_names_the_role_keyd_mapped_the_peer_uid_to() {
    let Some(world) = world(Some(Role::Ldap), |_| {}) else {
        return;
    };
    let mut client = RawClient::connect(&world.daemon.socket);
    match client.call(&Call::DescribeConfig) {
        Some(Ok(Answer::DescribeConfig(Ok(described)))) => {
            assert_eq!(described.description.realm, realm());
            assert_eq!(described.caller_role, Role::Ldap);
        }
        other => panic!("{other:?}"),
    }
    world.daemon.stop().unwrap();
}

/// docs/10 §2 (I2: keyd's capability table decides) and docs/50 §3.2 (the
/// role comes from the map): a uid mapped to Directory asking for
/// `describe_config` gets keyd's uniform `Denied`; its `ping` is served.
#[test]
fn a_wrong_role_gets_keyds_authorization_result() {
    let Some(world) = world(Some(Role::Directory), |_| {}) else {
        return;
    };
    let mut client = RawClient::connect(&world.daemon.socket);
    assert!(matches!(
        client.call(&Call::DescribeConfig),
        Some(Ok(Answer::DescribeConfig(Err(Error::Denied))))
    ));
    assert!(matches!(
        client.call(&Call::Ping),
        Some(Ok(Answer::Ping(Ok(Role::Directory))))
    ));
    world.daemon.stop().unwrap();
}

/// docs/50 §3.6: "a frame that has started must finish within 5 s (here the
/// configured 1 s) … otherwise close; an idle connection is allowed".
#[test]
fn a_started_frame_must_finish_within_the_frame_timeout() {
    let Some(world) = world(Some(Role::Kdc), |_| {}) else {
        return;
    };
    // Idle longer than the frame timeout: still served.
    let mut idle = RawClient::connect(&world.daemon.socket);
    std::thread::sleep(Duration::from_millis(1500));
    assert!(matches!(
        idle.call(&Call::Ping),
        Some(Ok(Answer::Ping(Ok(_))))
    ));
    // Two octets of a length prefix, then nothing: closed after ~1 s.
    let mut slow = RawClient::connect(&world.daemon.socket);
    let start = Instant::now();
    slow.send_raw(&[0x00, 0x00]);
    assert_eq!(slow.receive(), Received::Closed);
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(900), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    world.daemon.stop().unwrap();
}

/// docs/50 §3.3, §3.6: a declared length over the request bound
/// (`REQUEST_LIMIT`, 80 KiB) is refused before any body octet is read —
/// the connection closes at once, no reply.
#[test]
fn an_oversized_frame_is_closed_before_its_body() {
    let Some(world) = world(Some(Role::Kdc), |_| {}) else {
        return;
    };
    let mut client = RawClient::connect(&world.daemon.socket);
    client.send_raw(&(1u32 << 30).to_be_bytes());
    assert_eq!(client.receive(), Received::Closed);
    world.daemon.stop().unwrap();
}

/// docs/50 §3.6 ("a connection quota per uid"): with a quota of 2, a third
/// connection of the same uid is closed without a reply; once one closes, a
/// new one is served.
#[test]
fn the_connection_quota_per_uid_is_enforced() {
    let Some(world) = world(Some(Role::Kdc), |params| {
        params.max_connections_per_uid = 2;
    }) else {
        return;
    };
    let mut first = RawClient::connect(&world.daemon.socket);
    let mut second = RawClient::connect(&world.daemon.socket);
    for client in [&mut first, &mut second] {
        assert!(matches!(
            client.call(&Call::Ping),
            Some(Ok(Answer::Ping(Ok(_))))
        ));
    }
    let mut third = RawClient::connect(&world.daemon.socket);
    assert_eq!(third.call(&Call::Ping), None);
    drop(first);
    assert!(eventually(Duration::from_secs(5), || {
        RawClient::connect(&world.daemon.socket)
            .call(&Call::Ping)
            .is_some()
    }));
    drop(second);
    world.daemon.stop().unwrap();
}

/// docs/questions/Q-218 (A-57), Q-252 item 8 (A-64), task P7: while auditd
/// is reachable, an issuance-path operation is served (here keyd's own
/// answer is the startup hold-down's `Unavailable` — RFC 4120 §3.2.3, A-62 —
/// since this keyd just started on the system clock) and its record reaches
/// auditd; once auditd is gone it is refused `Busy` while `ping` and
/// `describe_config` still work; when auditd is back it is served again.
#[test]
fn audit_unreachable_refuses_issuance_while_ping_and_describe_work() {
    let Some(mut world) = world(Some(Role::Kdc), |_| {}) else {
        return;
    };
    let mut client = RawClient::connect(&world.daemon.socket);
    assert!(matches!(
        client.call(&verify_preauth()),
        Some(Ok(Answer::VerifyPreauth(Err(AuthnError::Unavailable))))
    ));
    assert!(eventually(Duration::from_secs(5), || {
        world.auditd.events().iter().any(|event| {
            matches!(event, EventBody::Keyd(record) if record.op == KeydOperation::VerifyPreauth)
        })
    }));

    world.auditd.stop();
    assert!(eventually(Duration::from_secs(10), || {
        matches!(client.call(&verify_preauth()), Some(Err(Refused::Busy)))
    }));
    assert!(matches!(
        client.call(&Call::Ping),
        Some(Ok(Answer::Ping(Ok(_))))
    ));
    assert!(matches!(
        client.call(&Call::DescribeConfig),
        Some(Ok(Answer::DescribeConfig(Ok(_))))
    ));

    world.auditd = FakeAuditd::start(&world.dir.join("a.sock"));
    assert!(eventually(Duration::from_secs(15), || {
        matches!(
            client.call(&verify_preauth()),
            Some(Ok(Answer::VerifyPreauth(Err(AuthnError::Unavailable))))
        )
    }));
    world.daemon.stop().unwrap();
}

/// docs/50 R50-16, §7.5 ("exits with an error code on any start-up failure";
/// auditd first): without auditd the daemon does not start and nothing
/// listens.
#[test]
fn start_up_fails_closed_without_auditd() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let params = params(&dir, CallerMap::new(&[(uid, Role::Kdc)]).unwrap(), uid);
    let socket = params.keyd_socket.clone();
    assert!(start(params).is_err());
    assert!(!socket.exists());
}

/// docs/50 R50-3 ("the client verifies the server's uid"): an audit socket
/// served by another uid than `auditd_uid` is refused before any event is
/// sent; the daemon does not start.
#[test]
fn an_auditd_of_the_wrong_uid_is_refused() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let params = params(
        &dir,
        CallerMap::new(&[(uid, Role::Kdc)]).unwrap(),
        uid.wrapping_add(1000).max(1),
    );
    let auditd = FakeAuditd::start(&params.audit.socket);
    let error = start(params).err().unwrap();
    assert!(error.contains("auditd uid"), "{error}");
    assert!(auditd.events().is_empty());
}

/// docs/50 §3.1 (the daemon manages the socket file explicitly): a stale
/// socket file is replaced, but a file that is not a socket is never
/// removed — the daemon does not start.
#[test]
fn a_non_socket_file_at_the_socket_path_is_refused() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let params = params(&dir, CallerMap::new(&[(uid, Role::Kdc)]).unwrap(), uid);
    std::fs::write(&params.keyd_socket, b"not a socket").unwrap();
    let _auditd = FakeAuditd::start(&params.audit.socket);
    let socket = params.keyd_socket.clone();
    assert!(start(params).is_err());
    assert_eq!(std::fs::read(&socket).unwrap(), b"not a socket");
}

/// Task P7 ("drain the queue and close"): a stop removes the socket file,
/// joins the engine thread, and a stale socket left behind is replaced at
/// the next start (docs/50 §3.1).
#[test]
fn stop_removes_the_socket_and_a_restart_replaces_a_stale_one() {
    let Some(world) = world(Some(Role::Kdc), |_| {}) else {
        return;
    };
    let socket = world.daemon.socket.clone();
    let mut client = RawClient::connect(&socket);
    assert!(matches!(
        client.call(&Call::Ping),
        Some(Ok(Answer::Ping(Ok(_))))
    ));
    world.daemon.stop().unwrap();
    assert!(!socket.exists());
    assert_eq!(client.receive(), Received::Closed);

    // A stale socket file (bound, then abandoned) is replaced.
    let stale = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    drop(stale);
    assert!(socket.exists());
    let uid = my_uid(&world.dir);
    let params = params(
        &world.dir,
        CallerMap::new(&[(uid, Role::Kdc)]).unwrap(),
        uid,
    );
    let daemon = start(params).unwrap();
    let mut client = RawClient::connect(&daemon.socket);
    assert!(matches!(
        client.call(&Call::Ping),
        Some(Ok(Answer::Ping(Ok(_))))
    ));
    daemon.stop().unwrap();
}
