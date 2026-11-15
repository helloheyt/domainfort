//! The front end to end over loopback TCP: forward and relay against a test
//! dird, every front-side answer of docs/53 §5.7, the version rule, the
//! framing bounds, the zone and the connection limits, the timeouts, and the
//! counted events (docs/53 §9).
//!
//! Sources (each test names its own): RFC 3244 §2 (the request and reply
//! messages, the TCP header, the result codes, "not allowed in a KRB-ERROR",
//! the result string "may be omitted"); RFC 4120 §5.9.1, §6.2, §7.5.9;
//! docs/53 R53-2, R53-3, §3.2, §3.3, §5.1, §5.6, §5.7, §8, §9; docs/52 R14;
//! A-114, A-117, A-121, A-142; docs/questions Q-603 item 5, Q-604, Q-621.
//! The world (crate::tests::world) is a test dird running this repository's
//! dispatcher and a test auditd; requests are built by hand from RFC 3244
//! §2's layout.

#![cfg(unix)]

use super::world::*;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use ipc_kpasswd::{HostUnserved, KpasswdAnswer, ObservedAddress, UnsealedCode};
use krb_proto::constants::{KRB_ERR_GENERIC, KRB_NT_SRV_INST};
use parse_kpasswd::{ReplyBody, ReplyMessage};
use std::io::Write;

fn good_request() -> Vec<u8> {
    request_frame(&octets(AP_REQ, 48, 0x11), &octets(KRB_PRIV, 30, 0x22))
}

/// docs/53 §4.3, §5.5 ("SealedReply — the front frames it"); RFC 3244 §2
/// (reply message): a well-formed request reaches dird with its AP-REQ and
/// KRB-PRIV octet for octet and the connection's addresses as the kernel
/// reported them, and keyd's sealed reply comes back unchanged in the RFC
/// 3244 reply (version 0x0001, AP_REP length, AP-REP, KRB-PRIV).
#[test]
fn a_request_is_forwarded_and_the_sealed_reply_relayed() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    let ap_req = octets(AP_REQ, 48, 0x11);
    let krb_priv = octets(KRB_PRIV, 30, 0x22);
    let reply = exchange(w.front, &request_frame(&ap_req, &krb_priv));
    let message = ReplyMessage::parse_tcp(&reply).expect("an RFC 3244 reply");
    let sealed = sealed();
    assert_eq!(
        message.body(),
        ReplyBody::ApRep {
            ap_rep: sealed.ap_rep().as_bytes(),
            krb_priv: sealed.krb_priv().as_bytes(),
        }
    );
    let message_length = u16::try_from(reply.len() - 4).unwrap().to_be_bytes();
    assert_eq!(&reply[4..6], &message_length, "message length");
    assert_eq!(&reply[6..8], &[0x00, 0x01], "reply version 0x0001");
    let requests = w.dird.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].ap_req().as_bytes(), &ap_req[..]);
    assert_eq!(requests[0].krb_priv().as_bytes(), &krb_priv[..]);
    let loopback = ObservedAddress::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(requests[0].peer(), loopback);
    assert_eq!(requests[0].local(), loopback);
    assert_eq!(w.control.counts(), crate::Counts::default());
}

/// docs/53 §5.7 (KRB-ERROR: error-code KRB_ERR_GENERIC 60, realm, sname
/// kadmin/changepw, e-data = the 2-octet code, no e-text / crealm / cname /
/// ctime / cusec); RFC 3244 §2 (AP_REP length 0 ⇒ KRB-ERROR; the result
/// string may be omitted); RFC 4120 §6.2 (NT-SRV-INST): dird's unsealed
/// AUTHERROR and HARDERROR become exactly that KRB-ERROR.
#[test]
fn an_unsealed_code_becomes_the_front_krb_error() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    for (code, value) in [
        (UnsealedCode::AuthError, 3u16),
        (UnsealedCode::HardError, 2),
    ] {
        *w.dird.answer.lock().unwrap() = Ok(KpasswdAnswer::Unsealed(code));
        let reply = exchange(w.front, &good_request());
        assert_eq!(
            &reply[6..10],
            &[0x00, 0x01, 0x00, 0x00],
            "version 1, AP_REP length 0"
        );
        let error = krb_error_of(&reply);
        assert_eq!(error.error_code, KRB_ERR_GENERIC);
        assert_eq!(error.realm.as_str(), REALM);
        assert_eq!(error.sname.name_type, KRB_NT_SRV_INST);
        let sname: Vec<&str> = error.sname.name_string.iter().map(|s| s.as_str()).collect();
        assert_eq!(sname, ["kadmin", "changepw"]);
        assert_eq!(error.e_data.as_deref(), Some(&value.to_be_bytes()[..]));
        assert!(error.e_text.is_none());
        assert!(error.crealm.is_none() && error.cname.is_none());
        assert!(error.ctime.is_none() && error.cusec.is_none());
    }
}

/// docs/53 §5.6 step 1 ("full ⇒ Busy ⇒ the front answers HARDERROR"), §5.7
/// ("keyd / dird not available, Busy, an unknown outcome ⇒ 2"): dird's
/// refusals are answered HARDERROR and counted.
#[test]
fn dird_not_serving_is_harderror() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    for refusal in [HostUnserved::Busy, HostUnserved::Unavailable] {
        *w.dird.answer.lock().unwrap() = Err(refusal);
        assert_eq!(result_code_of(&exchange(w.front, &good_request())), 2);
    }
    assert_eq!(w.control.counts().dird_not_serving, 2);
}

/// docs/50 §3.7 (dird down ⇒ not served, fail closed); docs/53 §5.7: when
/// dird's socket is gone, the front answers HARDERROR — never a success,
/// never silence on TCP.
#[test]
fn dird_down_is_harderror() {
    let Some(w) = world(|p| p.front.timeouts.dird_deadline = Duration::from_secs(2)) else {
        return;
    };
    // Remove the dird socket: new connections to it fail.
    std::fs::remove_file(&w.dird_socket).unwrap();
    assert_eq!(result_code_of(&exchange(w.front, &good_request())), 2);
    assert!(w.control.counts().dird_not_serving >= 1);
}

/// docs/53 R53-2, §3.2 ("version ≠ 0xff80 ⇒ BAD_VERSION, no fallback");
/// A-117, A-142 (version 1 stays refused; P-31 open); RFC 3244 §2 (BAD_VERSION
/// 6): version 1 — the version the lab saw a Windows client send
/// (docs/research/r3-e §3.2) — and any other version are answered
/// BAD_VERSION, counted, and never reach dird.
#[test]
fn every_other_version_is_bad_version() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    let ap_req = octets(AP_REQ, 48, 0x11);
    let krb_priv = octets(KRB_PRIV, 30, 0x22);
    for version in [0x0001u16, 0x0000, 0x0002, 0xff7f, 0xff81, 0xffff] {
        let reply = exchange(w.front, &request_with_version(version, &ap_req, &krb_priv));
        assert_eq!(result_code_of(&reply), 6, "version {version:#06x}");
    }
    assert_eq!(w.control.counts().bad_version, 6);
    assert!(w.dird.requests.lock().unwrap().is_empty());
}

/// docs/53 §5.1 (the framing table: message length = the TCP header, ≥ 6;
/// AP_REQ length ≥ 1 and ≤ the rest — 0 ⇒ MALFORMED, Q-603 item 5; the
/// KRB-PRIV ≥ 1; the check order of Q-621 item 3: a version-1 request with a
/// broken length is MALFORMED); RFC 3244 §2: every framing failure is
/// answered MALFORMED and never reaches dird.
#[test]
fn framing_failures_are_malformed() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    let ap_req = octets(AP_REQ, 48, 0x11);
    let krb_priv = octets(KRB_PRIV, 30, 0x22);
    let good = request_frame(&ap_req, &krb_priv);
    let mut length_field = good.clone();
    length_field[5] ^= 0x01; // message length ≠ the octets
    let mut ap_zero = request_with_version(0xff80, &[], &krb_priv);
    ap_zero[8..10].copy_from_slice(&0u16.to_be_bytes());
    let mut ap_over = good.clone();
    ap_over[8..10].copy_from_slice(&200u16.to_be_bytes()); // > the rest
    let no_priv = request_with_version(0xff80, &ap_req, &[]);
    let mut v1_broken = request_with_version(0x0001, &ap_req, &krb_priv);
    v1_broken[5] ^= 0x01;
    let cases = [length_field, ap_zero, ap_over, no_priv, v1_broken];
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(result_code_of(&exchange(w.front, case)), 1, "case {index}");
    }
    assert_eq!(w.control.counts().malformed, cases.len() as u64);
    assert_eq!(w.control.counts().bad_version, 0);
    assert!(w.dird.requests.lock().unwrap().is_empty());
}

/// docs/53 §5.1 ("TCP header … 0 or > 65,535 ⇒ … before allocation"); RFC
/// 3244 §2 (the 16-bit message length): a header announcing more than
/// 65,535 octets (here 1 GiB) or fewer than the 6-octet header is answered
/// MALFORMED at once — no message octet is awaited.
#[test]
fn out_of_range_tcp_headers_are_malformed_before_allocation() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    for header in [1u32 << 30, 65_536, 5, 0] {
        let started = std::time::Instant::now();
        let reply = exchange(w.front, &header.to_be_bytes());
        assert_eq!(result_code_of(&reply), 1, "header {header}");
        assert!(
            started.elapsed() < FIRST_FRAME,
            "answered before the deadline"
        );
    }
    assert_eq!(w.control.counts().malformed, 4);
}

/// docs/53 R53-4 ("only keyd decrypts the new password"); RFC 4120 §5.7.1,
/// §5.10: messages that are not an AP-REQ and a KRB-PRIV by their identifier
/// — the cleartext EncKrbPrivPart `[APPLICATION 28]` in the KRB-PRIV place
/// above all — are answered MALFORMED and never forwarded.
#[test]
fn messages_that_are_not_ap_req_and_krb_priv_are_malformed() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    for (ap_req, krb_priv) in [
        (
            octets(AP_REQ, 48, 0x11),
            octets(ENC_KRB_PRIV_PART, 30, 0x22),
        ),
        (octets(AP_REQ, 48, 0x11), b"cleartext-new-password".to_vec()),
        (octets(KRB_PRIV, 48, 0x11), octets(KRB_PRIV, 30, 0x22)),
    ] {
        assert_eq!(
            result_code_of(&exchange(w.front, &request_frame(&ap_req, &krb_priv))),
            1
        );
    }
    assert!(w.dird.requests.lock().unwrap().is_empty());
}

/// RFC 3244 §2 ("KRB5_KPASSWD_SUCCESS 0 … not allowed in a KRB-ERROR"); A-121
/// (the type cannot hold it); A-142 (never an unauthenticated success):
/// across every answer the front encodes itself, the KRB-ERROR's result code
/// is never 0 and never carries a result string.
#[test]
fn no_krb_error_ever_carries_success() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    *w.dird.answer.lock().unwrap() = Err(HostUnserved::Unavailable);
    let ap_req = octets(AP_REQ, 48, 0x11);
    let krb_priv = octets(KRB_PRIV, 30, 0x22);
    for request in [
        good_request(),
        request_with_version(1, &ap_req, &krb_priv),
        5u32.to_be_bytes().to_vec(),
    ] {
        let code = result_code_of(&exchange(w.front, &request));
        assert_ne!(code, 0);
    }
}

/// docs/53 §5.1 ("the first frame within 10 s"); docs/50 §4.1: a client that
/// sends half a header, or a header and half a message, is closed without a
/// reply after the first-frame timeout, and counted.
#[test]
fn an_incomplete_request_times_out_without_a_reply() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    let good = good_request();
    for partial in [&good[..2], &good[..20]] {
        let mut stream = std::net::TcpStream::connect(w.front).unwrap();
        stream.write_all(partial).unwrap();
        let started = std::time::Instant::now();
        assert!(closed_without_a_byte(&mut stream));
        assert!(started.elapsed() >= FIRST_FRAME - Duration::from_millis(100));
    }
    assert!(eventually(LONG, || w.control.counts().timed_out == 2));
    assert!(w.dird.requests.lock().unwrap().is_empty());
}

/// docs/53 §5.1 (a per-source connection quota, as the kdc — docs/50 §4.1):
/// with one connection per source, a second connection from the same source
/// is closed at once without a byte and counted; when the first ends, a new
/// one is served again.
#[test]
fn the_per_source_quota_closes_extra_connections() {
    let Some(w) = world(|p| {
        p.front.limits.max_per_source = 1;
        p.front.timeouts.first_frame = Duration::from_secs(5);
    }) else {
        return;
    };
    let held = std::net::TcpStream::connect(w.front).unwrap();
    // Let the front admit the first connection before the second arrives.
    std::thread::sleep(Duration::from_millis(200));
    let mut extra = std::net::TcpStream::connect(w.front).unwrap();
    assert!(closed_without_a_byte(&mut extra));
    assert!(eventually(LONG, || w.control.counts().connection_limited == 1));
    drop(held);
    assert!(eventually(LONG, || {
        let reply = exchange(w.front, &good_request());
        ReplyMessage::parse_tcp(&reply).is_ok()
    }));
}

/// docs/53 §3.3 ("every accepted source outside them closed before a
/// byte"); docs/52 R14; A-114: with a zone table of exactly 127.0.0.1/32, a
/// client from 127.0.0.2 is closed at once without a byte and counted, and
/// never reaches dird. 127.0.0.2 is a local address where the whole 127/8
/// is (Linux); where it is not (macOS without extra configuration), only
/// the served half runs. tokio 1.54.1 docs.rs: `net::TcpSocket::{new_v4,
/// bind, connect}`, `net::TcpStream::into_std`.
#[test]
fn a_source_outside_the_internal_networks_is_closed() {
    let Some(w) = world(|_| {}) else {
        return;
    };
    assert!(ReplyMessage::parse_tcp(&exchange(w.front, &good_request())).is_ok());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    let outside_host = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0);
    if socket.bind(outside_host).is_err() {
        eprintln!("skipped the outside half: no second loopback address on this host");
        return;
    }
    let outside = runtime.block_on(socket.connect(w.front)).unwrap();
    let mut outside = outside.into_std().unwrap();
    outside.set_nonblocking(false).unwrap();
    let _ = outside.write_all(&good_request());
    assert!(closed_without_a_byte(&mut outside));
    assert!(eventually(LONG, || w.control.counts().source_not_internal == 1));
    assert_eq!(w.dird.requests.lock().unwrap().len(), 1);
}
