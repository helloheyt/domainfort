//! Tier 2 (docs/50 §9: real servers in the test's threads, Unix sockets in
//! a temporary directory, TCP on loopback at system-chosen ports): the real
//! ldap-front between a rustls / plain TCP client and the real dird and
//! auditd.
//!
//! * the anonymous rootDSE over LDAPS and over StartTLS, octet for octet
//!   the in-process engine's (and a non-canonical wire message relayed as
//!   the canonical one);
//! * StartTLS with cleartext behind it (in the same segment, or after the
//!   response) ⇒ closed, no TLS (R49-15);
//! * a TLS 1.2-only ClientHello ⇒ a protocol_version alert, no handshake;
//! * a client holding a certificate ⇒ never asked, the session works;
//! * a password bind over TLS ⇒ authMethodNotSupported (7);
//! * dird down ⇒ a Notice of Disconnection (unavailable), then close;
//! * not LDAP / over the bound ⇒ notice (protocolError) or silent close;
//! * limits (per source, unauthenticated pool) and timeouts
//!   (InitRecvTimeout, MaxConnIdleTime, the handshake bound);
//! * the start-up checks (auditd, dird, the TLS profile) refuse to serve.
//!
//! The client side: rustls itself (docs/50 §9) with its standard verifier
//! trusting the per-run test CA (tests/common/cert.rs, tests/common/tls.rs); LDAP messages from parse-ldap's canonical encoder or by
//! hand from RFC 4511; the TLS 1.2 ClientHello by hand from RFC 8446.
//!
//! Sources: docs/50 R50-10, R50-11, R50-16, §3.7, §4.2, §4.3, §7.5, §9;
//! docs/49 R49-15, R49-16, §4.4; RFC 4511 §4.1.1, §4.2, §4.4.1, §4.14,
//! §5.2, App. A; RFC 4513 §3.1.1; RFC 8446 §4, §4.1.2, §4.2, §4.2.1, §5.1,
//! §6, App. D.2; [MS-ADTS] 3.1.1.3.4.6 as crates/parse-ldap cites it.
//! Every value is made here.

#[path = "common/cert.rs"]
mod cert_support;

#[path = "common/tls.rs"]
mod tls_support;

#[path = "common/world.rs"]
mod world;

use core::time::Duration;
use ipc_ldap::{notice_of_disconnection, ChannelFailure, TransportError};
use ldap_front::relay::{take_message, WireBuffer};
use ldap_front::{counts, DaemonError, Endpoint, FrontParams};
use parse_ldap::{AuthState, ProtocolOp, ResultCode};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Instant;
use world::*;

/// docs/50 R50-10, §4.2, §4.3 step 6; docs/49 §5.2 (R49-10), R49-16: the
/// anonymous rootDSE over LDAPS — the responses are octet for octet the
/// engine's over the same store, policy and time (a TLS session from the
/// first octet); the same search sent with a four-octet long-form length
/// (A-45) gets the same answer (the front relayed it canonical).
#[test]
fn the_root_dse_over_ldaps() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    let mut stream = tls_over(tcp(w.front.ldaps), &w.client).unwrap();
    stream.write_all(&root_dse(1)).unwrap();
    let mut reader = LdapReader::default();
    let entry = reader.next(&mut stream).unwrap();
    let done = reader.next(&mut stream).unwrap();
    assert_eq!(result_code(&done), ResultCode::Success);
    let mut session = ldap::Session::new(1, ldap::Listener::Ldaps);
    let outcome = direct(&w, &mut session, &root_dse(1), true, false);
    assert_eq!(vec![entry.clone(), done.clone()], outcome.responses);

    // The same message, outer length in the long form: 30 84 00 00 00 LL.
    let canonical = root_dse(2);
    assert!(canonical[1] < 0x80, "short form in the canonical encoding");
    let mut long_form = vec![0x30, 0x84, 0x00, 0x00, 0x00, canonical[1]];
    long_form.extend_from_slice(&canonical[2..]);
    stream.write_all(&long_form).unwrap();
    let entry_2 = reader.next(&mut stream).unwrap();
    let done_2 = reader.next(&mut stream).unwrap();
    let outcome_2 = direct(&w, &mut session, &canonical, true, false);
    assert_eq!(vec![entry_2, done_2], outcome_2.responses);
}

/// docs/50 §4.3 (the hand-over order); RFC 4511 §4.14.1-§4.14.2; RFC 4513
/// §3.1.1: StartTLS on the cleartext listener — the StartTLS response is
/// the engine's, the TLS handshake follows on the same connection, and the
/// rootDSE over it is the engine's for a session after StartTLS.
#[test]
fn the_root_dse_over_start_tls() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    let mut plain = tcp(w.front.ldap);
    plain.write_all(&start_tls(1)).unwrap();
    let mut reader = LdapReader::default();
    let started = reader.next(&mut plain).unwrap();
    assert!(reader.is_empty());
    let mut session = ldap::Session::new(1, ldap::Listener::Ldap);
    let outcome = direct(&w, &mut session, &start_tls(1), false, false);
    assert_eq!(vec![started.clone()], outcome.responses);
    assert_eq!(result_code(&started), ResultCode::Success);

    let mut stream = tls_over(plain, &w.client).unwrap();
    stream.write_all(&root_dse(2)).unwrap();
    let entry = reader.next(&mut stream).unwrap();
    let done = reader.next(&mut stream).unwrap();
    let outcome = direct(&w, &mut session, &root_dse(2), true, false);
    assert_eq!(vec![entry, done.clone()], outcome.responses);
    assert_eq!(result_code(&done), ResultCode::Success);
}

/// docs/49 §4.4 (R49-15: octets left in the framer after the StartTLS PDU
/// ⇒ close); RFC 4511 §4.14.1 ("The client MUST NOT send any LDAP PDUs …
/// following this request until it receives a StartTLS Extended
/// response"); docs/50 §4.3 steps 1-2: StartTLS and a rootDSE in one write
/// — the front reports `input_pending`, the engine answers operationsError
/// (the engine's own octets) and the connection closes, without TLS and
/// without an answer to the injected search.
#[test]
fn start_tls_with_cleartext_behind_it_is_closed() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    let mut plain = tcp(w.front.ldap);
    let mut both = start_tls(1);
    both.extend_from_slice(&root_dse(2));
    plain.write_all(&both).unwrap();
    let mut reader = LdapReader::default();
    let refused = reader.next(&mut plain).unwrap();
    assert_eq!(result_code(&refused), ResultCode::OperationsError);
    let mut session = ldap::Session::new(1, ldap::Listener::Ldap);
    let outcome = direct(&w, &mut session, &start_tls(1), false, true);
    assert_eq!(vec![refused], outcome.responses);
    assert!(reader.is_empty());
    assert_eq!(closed(&mut plain), Ok(()));
}

/// docs/50 §4.3 step 3 ("a cleartext octet injected after the response is
/// parsed as TLS and fails ⇒ close"): after a successful StartTLS response
/// the client sends a cleartext search instead of a ClientHello — no LDAP
/// answer comes, only (at most) a TLS alert record (RFC 8446 §5.1:
/// ContentType alert(21)), and the connection closes.
#[test]
fn cleartext_after_the_start_tls_response_is_not_ldap() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    let before = counts().handshake_failed;
    let mut plain = tcp(w.front.ldap);
    plain.write_all(&start_tls(1)).unwrap();
    let mut reader = LdapReader::default();
    let started = reader.next(&mut plain).unwrap();
    assert_eq!(result_code(&started), ResultCode::Success);
    plain.write_all(&root_dse(2)).unwrap();
    let mut received = Vec::new();
    let _ = plain.read_to_end(&mut received);
    if let Some(&first) = received.first() {
        assert_eq!(first, 21, "only a TLS alert may come back");
    }
    assert!(counts().handshake_failed > before);
}

/// A ClientHello (RFC 8446 §4.1.2) in a handshake message (§4: type 1,
/// uint24 length) in a TLSPlaintext record (§5.1: type 22, version 0x0303,
/// uint16 length), offering TLS_AES_128_GCM_SHA256 {0x13,0x01} (App. B.4),
/// supported_groups (10) = secp256r1 (0x0017), signature_algorithms (13) =
/// ecdsa_secp256r1_sha256 (0x0403) (§4.2, §4.2.3, §4.2.7), and — if
/// `versions` is given — supported_versions (43) with those versions
/// (§4.2.1: `ProtocolVersion versions<2..254>`). legacy_version is 0x0303
/// (TLS 1.2); the random is a fixed test value.
fn client_hello(versions: Option<&[[u8; 2]]>) -> Vec<u8> {
    let mut extensions = Vec::new();
    // supported_groups: NamedGroupList named_group_list<2..2^16-1>.
    extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17]);
    // signature_algorithms: SignatureSchemeList <2..2^16-2>.
    extensions.extend_from_slice(&[0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03]);
    if let Some(versions) = versions {
        let list_len = (versions.len() * 2) as u8;
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, list_len + 1, list_len]);
        for version in versions {
            extensions.extend_from_slice(version);
        }
    }
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x11; 32]);
    body.push(0x00); // legacy_session_id: empty
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
    body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods: null
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// docs/50 R50-11 (TLS 1.3 only); RFC 8446 App. D.2 ("If the
/// "supported_versions" extension is absent and the server only supports
/// versions greater than ClientHello.legacy_version, the server MUST abort
/// the handshake with a "protocol_version" alert"), §4.2.1 ("Servers MUST
/// only select a version of TLS present in that extension"), §6 (Alert:
/// level, description; fatal(2), protocol_version(70)): a TLS 1.2-only
/// ClientHello on the LDAPS listener gets an alert record — never a
/// ServerHello — and the connection closes.
#[test]
fn tls_1_2_is_refused() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    let before = counts().handshake_failed;
    // No supported_versions: App. D.2's protocol_version alert.
    let mut stream = tcp(w.front.ldaps);
    stream.write_all(&client_hello(None)).unwrap();
    let mut received = Vec::new();
    let _ = stream.read_to_end(&mut received);
    assert_eq!(
        received.get(..7),
        Some(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46][..]),
        "a fatal protocol_version alert"
    );
    // supported_versions = {TLS 1.2}: an alert, no ServerHello.
    let mut stream = tcp(w.front.ldaps);
    stream
        .write_all(&client_hello(Some(&[[0x03, 0x03]])))
        .unwrap();
    let mut received = Vec::new();
    let _ = stream.read_to_end(&mut received);
    assert_eq!(received.first(), Some(&0x15), "an alert record");
    assert!(counts().handshake_failed >= before + 2);
}

/// docs/50 R50-11 ("no client certificate"); RFC 8446 §4.3.2, §4.4.2: a
/// client that holds a certificate is never asked for it — the handshake
/// completes and the session serves (ignored, not refused).
#[test]
fn a_client_certificate_is_ignored() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    let config = tls_support::client_config_with(
        tls_support::client_provider(
            tls_support::all_tls13_suites(),
            tls_support::profile_groups(),
        ),
        &w.pki,
        true,
    );
    let mut stream = tls_over(tcp(w.front.ldaps), &config).unwrap();
    stream.write_all(&root_dse(1)).unwrap();
    let mut reader = LdapReader::default();
    let _entry = reader.next(&mut stream).unwrap();
    assert_eq!(
        result_code(&reader.next(&mut stream).unwrap()),
        ResultCode::Success
    );
}

/// RFC 4511 §4.2 (a simple bind with a password); crates/ldap's table
/// ("simple bind with a password | authMethodNotSupported (7), before any
/// lookup, never keyd" — P-14; AGENTS.md §6: cleartext simple bind has no
/// code path): over TLS the bind is refused with 7, octet for octet the
/// engine's answer to the canonical message the front relays (the password
/// replaced by the decoder's placeholder, A-52).
#[test]
fn a_password_bind_over_tls_is_refused() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    // 30 16 02 01 01 60 11 02 01 03 04 04 "cn=x" 80 06 "secret" (RFC 4511
    // §4.2: version 3, name, simple [0]).
    let mut bind = vec![
        0x30, 0x16, 0x02, 0x01, 0x01, 0x60, 0x11, 0x02, 0x01, 0x03, 0x04, 0x04,
    ];
    bind.extend_from_slice(b"cn=x");
    bind.extend_from_slice(&[0x80, 0x06]);
    bind.extend_from_slice(b"secret");
    let mut stream = tls_over(tcp(w.front.ldaps), &w.client).unwrap();
    stream.write_all(&bind).unwrap();
    let mut reader = LdapReader::default();
    let response = reader.next(&mut stream).unwrap();
    assert!(matches!(
        tls_support_free_decoded(&response),
        ProtocolOp::BindResponse(_)
    ));
    assert_eq!(result_code(&response), ResultCode::AuthMethodNotSupported);
    let mut wire = WireBuffer::new();
    wire.extend(&bind).unwrap();
    let canonical = take_message(&mut wire, AuthState::Unauthenticated)
        .unwrap()
        .unwrap()
        .canonical;
    let mut session = ldap::Session::new(1, ldap::Listener::Ldaps);
    let outcome = direct(&w, &mut session, &canonical, true, false);
    assert_eq!(vec![response], outcome.responses);
}

fn tls_support_free_decoded(response: &[u8]) -> ProtocolOp {
    decoded(response).protocol_op
}

/// docs/50 §3.7 ("ldap-front without dird ⇒ the connection is closed (no
/// answer without a PEP)"); RFC 4511 §4.4.1 (Notice of Disconnection), App.
/// A (unavailable 52): with dird stopped, an open LDAPS session's next
/// request is answered by the notice over TLS, then the session closes; a
/// new cleartext connection gets the notice in cleartext, then closes.
#[test]
fn dird_down_notice_then_close() {
    let Some(mut w) = world(|_| {}) else {
        return;
    };
    let mut stream = tls_over(tcp(w.front.ldaps), &w.client).unwrap();
    stream.write_all(&root_dse(1)).unwrap();
    let mut reader = LdapReader::default();
    let _ = reader.next(&mut stream).unwrap();
    let _ = reader.next(&mut stream).unwrap();
    w.dird.take().unwrap().stop().unwrap();

    stream.write_all(&root_dse(2)).unwrap();
    let unavailable = notice(ResultCode::Unavailable);
    assert_eq!(reader.next(&mut stream), Some(unavailable.clone()));
    assert_eq!(
        notice_of_disconnection(&ChannelFailure::Transport(TransportError::Connect)),
        Some(unavailable.clone())
    );
    assert_eq!(closed(&mut stream), Ok(()));

    let mut plain = tcp(w.front.ldap);
    let mut reader = LdapReader::default();
    assert_eq!(reader.next(&mut plain), Some(unavailable));
    assert_eq!(closed(&mut plain), Ok(()));
}

/// RFC 4511 §4.1.1 ("the LDAPMessage SEQUENCE tag cannot be recognized … the
/// server SHOULD return the Notice of Disconnection … protocolError, and
/// MUST immediately terminate"): a TLS ClientHello sent to the cleartext
/// listener is not LDAP — the notice (protocolError), then close.
/// [MS-ADTS] 3.1.1.3.4.6 as crates/parse-ldap cites it ("drop the
/// connection"): a message announcing more than the unauthenticated bound
/// is closed without any response, before its contents.
#[test]
fn not_ldap_and_over_the_bound() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    let mut plain = tcp(w.front.ldap);
    plain.write_all(&client_hello(None)).unwrap();
    let mut reader = LdapReader::default();
    assert_eq!(
        reader.next(&mut plain),
        Some(notice(ResultCode::ProtocolError))
    );
    assert_eq!(closed(&mut plain), Ok(()));

    let mut plain = tcp(w.front.ldap);
    let length = parse_ldap::MAX_PREAUTH_MESSAGE_OCTETS - 5 + 1;
    plain
        .write_all(&[
            0x30,
            0x83,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ])
        .unwrap();
    assert_eq!(closed(&mut plain), Ok(()));
}

/// docs/50 §4.1 ("a counter per source address"), §4.2 ("a connection
/// quota per source"): with a quota of two, a third connection from the
/// same address is closed at once without a byte, while the first two
/// serve.
#[test]
fn the_per_source_limit() {
    let Some(w) = world(|p| p.limits.max_per_source = 2) else {
        return;
    };
    let before = counts().connection_limited;
    let mut first = tcp(w.front.ldap);
    let mut second = tcp(w.front.ldap);
    for (stream, id) in [(&mut first, 1), (&mut second, 2)] {
        stream.write_all(&root_dse(id)).unwrap();
        let mut reader = LdapReader::default();
        let _ = reader.next(stream).unwrap();
        assert_eq!(
            result_code(&reader.next(stream).unwrap()),
            ResultCode::Success
        );
    }
    let mut third = tcp(w.front.ldap);
    assert_eq!(closed(&mut third), Ok(()));
    assert!(counts().connection_limited > before);
    drop(first);
    assert!(eventually(LONG, || {
        let mut again = tcp(w.front.ldap);
        let _ = again.write_all(&root_dse(3));
        let mut reader = LdapReader::default();
        reader.next(&mut again).is_some()
    }));
}

/// docs/50 §4.2 ("a separate pool for unauthenticated connections");
/// docs/07 §1: with a pool of one, a second unauthenticated connection is
/// closed at once.
#[test]
fn the_unauthenticated_pool() {
    let Some(w) = world(|p| p.limits.max_unauthenticated = 1) else {
        return;
    };
    let mut first = tcp(w.front.ldap);
    first.write_all(&root_dse(1)).unwrap();
    let mut reader = LdapReader::default();
    assert!(reader.next(&mut first).is_some());
    let mut second = tcp(w.front.ldap);
    assert_eq!(closed(&mut second), Ok(()));
}

/// docs/50 §4.2 (InitRecvTimeout): a connection that sends nothing is
/// closed once the first-message bound passes.
#[test]
fn init_recv_timeout() {
    let Some(w) = world(|p| p.timeouts.init_recv = Duration::from_millis(500)) else {
        return;
    };
    let before = counts().timed_out;
    let mut plain = tcp(w.front.ldap);
    let start = Instant::now();
    assert_eq!(closed(&mut plain), Ok(()));
    assert!(start.elapsed() < LONG);
    assert!(counts().timed_out > before);
}

/// docs/50 §4.2 (MaxConnIdleTime): after an answer, a connection that sends
/// nothing more is closed once the idle bound passes.
#[test]
fn max_conn_idle_time() {
    let Some(w) = world(|p| p.timeouts.max_idle = Duration::from_millis(500)) else {
        return;
    };
    let mut plain = tcp(w.front.ldap);
    plain.write_all(&root_dse(1)).unwrap();
    let mut reader = LdapReader::default();
    assert!(reader.next(&mut plain).is_some());
    assert!(reader.next(&mut plain).is_some());
    assert_eq!(closed(&mut plain), Ok(()));
}

/// docs/50 §4.2 ("TLS handshake within 10 s"): an LDAPS connection that
/// never sends a ClientHello is closed once the handshake bound passes.
#[test]
fn tls_handshake_timeout() {
    let Some(w) = world(|p| p.timeouts.tls_handshake = Duration::from_millis(500)) else {
        return;
    };
    let before = counts().handshake_failed;
    let mut stream = tcp(w.front.ldaps);
    let start = Instant::now();
    assert_eq!(closed(&mut stream), Ok(()));
    assert!(start.elapsed() < LONG);
    assert!(counts().handshake_failed > before);
}

/// docs/50 R50-16 ("a daemon does not bind a network port until its
/// dependencies are verified"), §7.5: without auditd, `serve` fails and
/// serves nothing; with an auditd that records the front under another
/// source (dird's listener), the same — task R9b, docs/questions/Q-560
/// item 5 (attack); with auditd but without dird, the same; with both up
/// but a TLS configuration outside R50-11, the same.
#[test]
fn the_start_up_checks() {
    let dir = world::dird_support::TempDir::new();
    let uid = world::dird_support::my_uid(&dir);
    if world::dird_support::skip_as_root(uid) {
        return;
    }
    let pki = tls_support::pki();
    let params = FrontParams {
        dird: Endpoint {
            socket: dir.join("l.sock"),
            uid,
        },
        audit: Endpoint {
            socket: front_audit_socket(&dir),
            uid,
        },
        timeouts: test_timeouts(),
        limits: ldap_front::ConnectionLimits::DEFAULT,
        internal_networks: world::loopback_internal(),
    };
    let no_auditd = Front::start(params.clone(), tls_support::server_config_for(&pki));
    assert!(no_auditd.err().unwrap().contains("auditd"));

    let logs = auditd_support::TempDir::new();
    let _auditd = start_auditd(&dir, &logs, uid);
    let cross_wired = FrontParams {
        audit: Endpoint {
            socket: dir.join("a.sock"),
            uid,
        },
        ..params.clone()
    };
    let refused = Front::start(cross_wired, tls_support::server_config_for(&pki));
    assert!(
        refused
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("another source")),
        "{:?}",
        refused.err()
    );
    let no_dird = Front::start(params.clone(), tls_support::server_config_for(&pki));
    assert!(no_dird.err().unwrap().contains("dird"));

    let mut weak = (*tls_support::server_config_for(&pki)).clone();
    weak.send_tls13_tickets = 2;
    let refused = Front::start(params, Arc::new(weak));
    assert_eq!(
        refused.err(),
        Some(DaemonError::TlsPolicy(ldap_front::tls::PolicyField::Tickets).to_string())
    );
}

/// docs/52 §7 R14; A-102 on docs/questions/Q-469 (b) ("one front per zone;
/// external LDAP connections are not in phase 1"): a listener whose local
/// address is outside every internal network is not served — `serve`
/// refuses before it contacts anything, whoever bound the listener (here
/// the test, on loopback, with a zone table of 10.0.0.0/8 only — test
/// data).
#[test]
fn a_listener_outside_the_internal_networks_is_not_served() {
    let dir = world::dird_support::TempDir::new();
    let uid = world::dird_support::my_uid(&dir);
    if world::dird_support::skip_as_root(uid) {
        return;
    }
    let pki = tls_support::pki();
    let params = FrontParams {
        dird: Endpoint {
            socket: dir.join("l.sock"),
            uid,
        },
        audit: Endpoint {
            socket: dir.join("a.sock"),
            uid,
        },
        timeouts: test_timeouts(),
        limits: ldap_front::ConnectionLimits::DEFAULT,
        internal_networks: vec![config::Network::new(
            core::net::IpAddr::V4(core::net::Ipv4Addr::new(10, 0, 0, 0)),
            8,
        )
        .unwrap()],
    };
    let refused = Front::start(params, tls_support::server_config_for(&pki));
    assert_eq!(
        refused.err(),
        Some(DaemonError::ListenerNotInternal.to_string())
    );
}

/// docs/52 §7 R14; A-102 on docs/questions/Q-469 (b); docs/50 §4.1 (CIDR →
/// Internal): with a zone table of exactly 127.0.0.1/32 (test data), a
/// client whose source is 127.0.0.1 is served, and one whose source is
/// 127.0.0.2 — outside the table — is closed at once without a byte and
/// counted (`source_not_internal`), before any slot or dird session.
/// 127.0.0.2 is a local address where the whole 127/8 is (Linux); where it
/// is not (macOS has only 127.0.0.1 without extra configuration), only the
/// served half runs. tokio 1.54.1 docs.rs: `net::TcpSocket::{new_v4, bind,
/// connect}`, `net::TcpStream::into_std`.
#[test]
fn a_source_outside_the_internal_networks_is_closed() {
    let host = |last| core::net::IpAddr::V4(core::net::Ipv4Addr::new(127, 0, 0, last));
    let Some(w) = world(|p| {
        p.internal_networks = vec![config::Network::new(host(1), 32).unwrap()];
    }) else {
        return;
    };
    let mut inside = tcp(w.front.ldap);
    inside.write_all(&root_dse(1)).unwrap();
    let mut reader = LdapReader::default();
    let _ = reader.next(&mut inside).unwrap();
    assert_eq!(
        result_code(&reader.next(&mut inside).unwrap()),
        ResultCode::Success
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    if socket.bind(core::net::SocketAddr::new(host(2), 0)).is_err() {
        return; // no second loopback address on this host
    }
    let before = counts().source_not_internal;
    let outside = runtime.block_on(socket.connect(w.front.ldap)).unwrap();
    let mut outside = outside.into_std().unwrap();
    outside.set_nonblocking(false).unwrap();
    outside.set_read_timeout(Some(LONG)).unwrap();
    let _ = outside.write_all(&root_dse(2));
    assert_eq!(closed(&mut outside), Ok(()));
    assert!(counts().source_not_internal > before);
}

/// Repeat `attempt` until it returns `true` or `limit` passes.
fn eventually(limit: Duration, mut attempt: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if attempt() {
            return true;
        }
        if start.elapsed() > limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
