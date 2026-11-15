//! Transport rules and robustness: TCP framing, UDP silence, the UDP size
//! rule, and "never panic on any input".
//!
//! Sources: RFC 4120 5.1.4, 7.2.1, 7.2.2, 7.5.9, 3.1.2; main-session
//! decisions 1, 11, 12; docs/CLEAN-ROOM.md (bounded parsers, fail closed). All
//! inputs hand-made or derived from the test's own valid requests.

mod common;

use common::*;
use kdc::{
    tcp_decode_frame, tcp_encode_frame, AuditOutcome, AuditReason, FramingError, KdcConfig,
    KdcReply, Peer, TcpFrame, Transport, MAX_REQUEST_LEN,
};
use krb_proto::constants::{
    KDC_ERR_BAD_PVNO, KRB_AP_ERR_MSG_TYPE, KRB_ERR_FIELD_TOOLONG, KRB_ERR_GENERIC,
    KRB_ERR_RESPONSE_TOO_BIG,
};
use krb_proto::{AsRep, KrbError, TgsRep};

/// RFC 4120 7.2.2: a length above the implementation's bound is refused as
/// soon as the 4 octets are read — KRB_ERR_FIELD_TOOLONG, then close
/// (decision 12). No allocation from the attacker's length.
#[test]
fn oversize_tcp_length_is_field_toolong_and_close() {
    let too_long = u32::try_from(MAX_REQUEST_LEN + 1).unwrap().to_be_bytes();
    assert_eq!(tcp_decode_frame(&too_long), Err(FramingError::TooLong));
    let mut f = Fixture::new();
    match f.kdc.reject_frame(
        FramingError::TooLong,
        Peer {
            transport: Transport::Tcp,
            src_net: pdp::IpScope::Internal,
        },
        now(),
    ) {
        KdcReply::SendAndClose(bytes) => {
            let error = KrbError::decode(&bytes).unwrap();
            assert_eq!(error.error_code, KRB_ERR_FIELD_TOOLONG);
            assert_eq!(error.realm, realm());
            assert_eq!(error.sname, krbtgt_name());
        }
        other => panic!("expected SendAndClose, got {other:?}"),
    }
    assert_eq!(f.events()[0].reason, AuditReason::RequestTooLong);
}

/// RFC 4120 7.2.2: "If a KDC that does not understand how to interpret a set
/// high bit of the length encoding receives a request with the high order bit
/// of the length set, it MUST return a KRB-ERROR message with the error
/// KRB_ERR_FIELD_TOOLONG and MUST close the TCP stream."
#[test]
fn reserved_length_bit_is_field_toolong_and_close() {
    for prefix in [[0x80, 0, 0, 0], [0x80, 0, 0, 5], [0xFF, 0xFF, 0xFF, 0xFF]] {
        assert_eq!(tcp_decode_frame(&prefix), Err(FramingError::ReservedBitSet));
    }
    let mut f = Fixture::new();
    let reply = f.kdc.reject_frame(
        FramingError::ReservedBitSet,
        Peer {
            transport: Transport::Tcp,
            src_net: pdp::IpScope::Internal,
        },
        now(),
    );
    let KdcReply::SendAndClose(bytes) = reply else {
        panic!("expected SendAndClose");
    };
    assert_eq!(
        KrbError::decode(&bytes).unwrap().error_code,
        KRB_ERR_FIELD_TOOLONG
    );
    assert_eq!(f.events()[0].reason, AuditReason::ReservedLengthBit);
}

/// RFC 4120 7.2.2 framing: a truncated prefix or message is incomplete
/// (read more), never an error or a panic; records follow each other.
#[test]
fn truncated_frames_are_incomplete() {
    assert_eq!(tcp_decode_frame(&[]), Ok(TcpFrame::Incomplete));
    assert_eq!(tcp_decode_frame(&[0, 0, 0]), Ok(TcpFrame::Incomplete));
    assert_eq!(
        tcp_decode_frame(&[0, 0, 0, 5, 1, 2]),
        Ok(TcpFrame::Incomplete)
    );
    assert_eq!(
        tcp_decode_frame(&[0, 0, 0, 0, 9]),
        Ok(TcpFrame::Complete {
            message: &[],
            rest: &[9]
        })
    );
    let request = AsReqSpec::alice().encode();
    let framed = tcp_encode_frame(&request).unwrap();
    for cut in 0..framed.len() {
        assert_eq!(tcp_decode_frame(&framed[..cut]), Ok(TcpFrame::Incomplete));
    }
    assert_eq!(
        tcp_decode_frame(&framed),
        Ok(TcpFrame::Complete {
            message: &request,
            rest: &[]
        })
    );
}

/// RFC 4120 5.1.4: an unknown message tag gets KRB_AP_ERR_MSG_TYPE over TCP
/// and no reply over UDP; other undecodable input gets KRB_ERR_GENERIC over
/// TCP (no other code fits, decision 11) and no reply over UDP; a protocol
/// version other than 5 gets KDC_ERR_BAD_PVNO (7.5.9).
#[test]
fn undecodable_input_over_udp_and_tcp() {
    let mut f = Fixture::new();
    // A KRB-ERROR sent to the KDC: a valid message of an unexpected type.
    let not_a_request = sent(f.send(&AsReqSpec::alice().encode()));
    let cases: Vec<(Vec<u8>, i32)> = vec![
        (not_a_request, KRB_AP_ERR_MSG_TYPE),
        (vec![0x30, 0x00], KRB_AP_ERR_MSG_TYPE),
        (b"GET / HTTP/1.1\r\n\r\n".to_vec(), KRB_ERR_GENERIC),
        (vec![0x6A, 0x05, 0x01], KRB_ERR_GENERIC),
        (Vec::new(), KRB_ERR_GENERIC),
    ];
    for (bytes, code) in cases {
        assert_eq!(f.send_at(&bytes, Transport::Udp, now()), KdcReply::Silent);
        let error = error_of(f.send(&bytes));
        assert_eq!(error.error_code, code);
        assert!(error.e_text.is_none());
        assert!(error.cname.is_none());
        assert_eq!(error.realm, realm());
    }
    // pvno 4: change the INTEGER 5 after the [1] tag of a valid AS-REQ.
    let mut request = AsReqSpec::alice().encode();
    let position = request
        .windows(5)
        .position(|w| w == [0xA1, 0x03, 0x02, 0x01, 0x05])
        .unwrap();
    request[position + 4] = 0x04;
    assert_eq!(code_of(f.send(&request)), KDC_ERR_BAD_PVNO);
    // Truncated AS-REQ.
    let request = AsReqSpec::alice().encode();
    assert_eq!(
        code_of(f.send(&request[..request.len() - 3])),
        KRB_ERR_GENERIC
    );
    for event in f.events().iter().skip(1) {
        assert!(event.exchange.is_none());
        if event.transport == Transport::Udp {
            assert_eq!(event.outcome, AuditOutcome::Dropped);
        }
    }
}

/// Decision 12 / RFC 4120 7.2.2: a request longer than the bound handed to
/// `handle` directly: TCP → KRB_ERR_FIELD_TOOLONG and close; UDP → nothing.
#[test]
fn oversize_request_through_handle() {
    let mut f = Fixture::new();
    let big = vec![0x6A; MAX_REQUEST_LEN + 1];
    match f.send(&big) {
        KdcReply::SendAndClose(bytes) => assert_eq!(
            KrbError::decode(&bytes).unwrap().error_code,
            KRB_ERR_FIELD_TOOLONG
        ),
        other => panic!("expected SendAndClose, got {other:?}"),
    }
    assert_eq!(f.send_at(&big, Transport::Udp, now()), KdcReply::Silent);
}

/// RFC 4120 7.2.1: a reply too large for UDP is replaced by
/// KRB_ERR_RESPONSE_TOO_BIG; RFC 4120 3.1.2: the client's identical retry
/// over TCP gets the reply generated the first time (from the retransmit
/// cache), so neither the armored AS-REQ retry (its armor AP-REQ is in keyd's
/// replay cache, docs/48 §3.3) nor the TGS-REQ retry is refused as a replay.
#[test]
fn udp_response_too_big_then_tcp_retry() {
    let mut setup = Setup::new();
    // The smallest limit the configuration accepts is the size of the KDC's
    // own RESPONSE_TOO_BIG error; 200 octets is above it and below any
    // AS-REP / TGS-REP.
    setup.kdc = KdcConfig {
        udp_max_reply_len: 200,
        ..setup.kdc
    };
    let mut f = setup.build();
    let key = alice_key(AES256);
    let (request, armor) = f.fast_as_request(&AsReqSpec::alice().with_challenge(&key), now());
    let error = error_of(f.send_at(&request, Transport::Udp, now()));
    assert_eq!(error.error_code, KRB_ERR_RESPONSE_TOO_BIG);
    assert!(!f.events()[0].armor.reply_armored);
    let bytes = sent(f.send_at(&request, Transport::Tcp, at(1)));
    let tgt = open_fast_as_rep(&bytes, &armor.key, &key);
    AsRep::decode(&bytes).unwrap();

    let spec = TgsReqSpec::service();
    let (tgs_request, _) = spec.encode(&tgt);
    let error = error_of(f.send_at(&tgs_request, Transport::Udp, at(2)));
    assert_eq!(error.error_code, KRB_ERR_RESPONSE_TOO_BIG);
    let bytes = sent(f.send_at(&tgs_request, Transport::Tcp, at(3)));
    open_tgs_rep(&bytes, &tgt, &spec);
    let reasons: Vec<AuditReason> = f.events().iter().map(|e| e.reason).collect();
    assert_eq!(
        reasons,
        vec![
            AuditReason::ReplyTooBigForUdp,
            AuditReason::Retransmission,
            AuditReason::ReplyTooBigForUdp,
            AuditReason::Retransmission,
        ]
    );
}

/// RFC 4120 7.2.1: the configured UDP limit must at least carry the KDC's own
/// RESPONSE_TOO_BIG error (fail closed at construction).
#[test]
fn udp_limit_below_own_error_is_refused() {
    let mut setup = Setup::new();
    setup.kdc.udp_max_reply_len = 40;
    assert_eq!(
        setup.kdc.validate(&setup.keyd.description()),
        Err(kdc::ConfigError::UdpReplyLimit)
    );
    setup.kdc.udp_max_reply_len = 200;
    assert_eq!(setup.kdc.validate(&setup.keyd.description()), Ok(()));
}

/// RFC 4120 7.2.2: several records on one stream are answered in turn.
#[test]
fn several_records_on_one_stream() {
    let mut f = Fixture::new();
    let mut stream = tcp_encode_frame(&AsReqSpec::alice().encode()).unwrap();
    let mut second = AsReqSpec::alice();
    second.cname = Some(bob_name());
    stream.extend(tcp_encode_frame(&second.encode()).unwrap());
    let mut rest: &[u8] = &stream;
    let mut answered = 0;
    while let Ok(TcpFrame::Complete {
        message,
        rest: next,
    }) = tcp_decode_frame(rest)
    {
        let error = error_of(f.send(message));
        assert!(error.e_data.is_some());
        answered += 1;
        rest = next;
    }
    assert_eq!(answered, 2);
    assert!(rest.is_empty());
}

/// docs/CLEAN-ROOM.md (never panic; bounded; fail closed): thousands of mutated
/// versions of valid AS-REQ and TGS-REQ messages — single-octet changes,
/// truncations, insertions — over both transports. Every reply is either
/// nothing (UDP) or a message that decodes as AS-REP, TGS-REP or KRB-ERROR,
/// and every KRB-ERROR is terse (no e-text). The mutation sequence is a
/// fixed, hand-written linear congruential walk (deterministic).
#[test]
fn mutated_requests_never_panic() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    // Unarmored and armored (RFC 6113 5.4.2) AS-REQs, the bootstrap, and an
    // armored TGS-REQ: the mutations reach the FAST paths too.
    let armored_as = f
        .fast_as_request(
            &AsReqSpec::alice().with_challenge(&alice_key(AES256)),
            now(),
        )
        .0;
    let seeds = [
        AsReqSpec::alice().encode(),
        AsReqSpec::machine()
            .with_timestamp(&machine_key(AES256))
            .encode(),
        armored_as,
        TgsReqSpec::service().encode(&tgt).0,
    ];
    let mut state: u32 = 0x1234_5678;
    let mut next = || {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        state >> 8
    };
    for round in 0..4000u32 {
        let seed = &seeds[(round as usize) % seeds.len()];
        let mut message = seed.clone();
        match next() % 4 {
            0 => {
                let i = next() as usize % message.len();
                message[i] ^= (next() % 255 + 1) as u8;
            }
            1 => {
                let cut = next() as usize % message.len();
                message.truncate(cut);
            }
            2 => {
                let i = next() as usize % message.len();
                message.insert(i, next() as u8);
            }
            _ => {
                let i = next() as usize % message.len();
                message[i] = 0xFF;
                let j = next() as usize % message.len();
                message[j] = 0x00;
            }
        }
        let transport = if round % 2 == 0 {
            Transport::Tcp
        } else {
            Transport::Udp
        };
        match f.send_at(&message, transport, now()) {
            KdcReply::Silent => assert_eq!(transport, Transport::Udp),
            KdcReply::Send(bytes) | KdcReply::SendAndClose(bytes) => {
                if let Ok(error) = KrbError::decode(&bytes) {
                    assert!(error.e_text.is_none());
                } else {
                    assert!(AsRep::decode(&bytes).is_ok() || TgsRep::decode(&bytes).is_ok());
                }
            }
        }
    }
    // One audit event per request (decision 14).
    assert_eq!(f.events().len(), 4001);
}
