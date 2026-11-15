//! Structure and round-trip tests for the RFC 3244 §2 request and reply
//! messages and the TCP header. Every message is built by hand from the RFC
//! 3244 §2 diagrams (`common/mod.rs`) — RFC 3244 has no examples; none comes
//! from any other implementation.

mod common;

use common::*;
use parse_kpasswd::{
    tcp_message_length, ReplyBody, ReplyMessage, RequestMessage, MAX_MESSAGE_LEN,
    MESSAGE_HEADER_LEN, REPLY_PROTOCOL_VERSION, REQUEST_PROTOCOL_VERSION, TCP_HEADER_LEN,
};

#[test]
fn protocol_constants() {
    // RFC 3244 §2: request version "the hex constant 0xff80", reply version
    // "the hex constant 0x0001"; three 16-bit header fields; a 4-octet TCP
    // header; `message length` is 16 bits, so ≤ 65,535 octets.
    assert_eq!(REQUEST_PROTOCOL_VERSION, 0xFF80);
    assert_eq!(REPLY_PROTOCOL_VERSION, 0x0001);
    assert_eq!(MESSAGE_HEADER_LEN, 6);
    assert_eq!(TCP_HEADER_LEN, 4);
    assert_eq!(MAX_MESSAGE_LEN, 65_535);
}

#[test]
fn request_field_order_and_big_endian() {
    // RFC 3244 §2 Request Message: message length | protocol version number |
    // AP_REQ length | AP_REQ data | KRB-PRIV message; 16-bit fields
    // big-endian; message length counts "the number of bytes in the message
    // including this field".
    let ap_req = ap_req_octets(); // 18 octets
    let krb_priv = krb_priv_octets(); // 14 octets
    let bytes = request(&ap_req, &krb_priv);
    assert_eq!(&bytes[..6], &[0x00, 0x26, 0xFF, 0x80, 0x00, 0x12]); // 38, 0xff80, 18
    assert_eq!(bytes.len(), 38);

    let parsed = RequestMessage::parse(&bytes).unwrap();
    assert_eq!(parsed.ap_req(), ap_req.as_slice());
    assert_eq!(parsed.krb_priv(), krb_priv.as_slice());
    // The slices borrow from the input (no copy).
    assert!(core::ptr::eq(parsed.ap_req().as_ptr(), bytes[6..].as_ptr()));
}

#[test]
fn request_round_trips() {
    // encode(parse(b)) == b and parse(encode(x)) == x (docs/50 §3.3).
    let ap_req = ap_req_octets();
    let krb_priv = krb_priv_octets();
    let bytes = request(&ap_req, &krb_priv);
    let parsed = RequestMessage::parse(&bytes).unwrap();
    assert_eq!(parsed.encode(), bytes);
    let built = RequestMessage::new(&ap_req, &krb_priv).unwrap();
    assert_eq!(built, parsed);
    assert_eq!(built.encode(), bytes);
    assert_eq!(RequestMessage::parse(&built.encode()).unwrap(), built);
}

#[test]
fn request_minimal_and_maximal_sizes() {
    // RFC 3244 §2 / docs/53 §5.1: one octet of AP-REQ and one of KRB-PRIV is
    // the smallest request (8 octets); 65,535 octets the largest.
    let bytes = request(&[0x6E], &[0x75]);
    assert_eq!(bytes, [0x00, 0x08, 0xFF, 0x80, 0x00, 0x01, 0x6E, 0x75]);
    let parsed = RequestMessage::parse(&bytes).unwrap();
    assert_eq!(parsed.encode(), bytes);

    let ap_req = vec![0xAA; 40_000];
    let krb_priv = vec![0xBB; MAX_MESSAGE_LEN - MESSAGE_HEADER_LEN - 40_000];
    let bytes = request(&ap_req, &krb_priv);
    assert_eq!(bytes.len(), MAX_MESSAGE_LEN);
    assert_eq!(&bytes[..2], &[0xFF, 0xFF]);
    let parsed = RequestMessage::parse(&bytes).unwrap();
    assert_eq!(parsed.ap_req().len(), 40_000);
    assert_eq!(parsed.encode(), bytes);
}

#[test]
fn request_ap_req_of_maximal_length() {
    // A 16-bit AP_REQ length can describe an AP-REQ up to the whole message
    // less the header and one KRB-PRIV octet.
    let ap_len = MAX_MESSAGE_LEN - MESSAGE_HEADER_LEN - 1;
    let ap_req = vec![0x6E; ap_len];
    let bytes = request(&ap_req, &[0x75]);
    let parsed = RequestMessage::parse(&bytes).unwrap();
    assert_eq!(parsed.ap_req().len(), ap_len);
    assert_eq!(parsed.krb_priv(), &[0x75]);
}

#[test]
fn reply_with_ap_rep_and_krb_priv() {
    // RFC 3244 §2 Reply Message: message length | version 0x0001 | AP_REP
    // length | AP-REP data | KRB-PRIV message.
    let ap_rep = ap_rep_octets(); // 10
    let krb_priv = krb_priv_octets(); // 14
    let bytes = reply(&ap_rep, &krb_priv);
    assert_eq!(&bytes[..6], &[0x00, 0x1E, 0x00, 0x01, 0x00, 0x0A]); // 30, 1, 10
    let parsed = ReplyMessage::parse(&bytes).unwrap();
    assert_eq!(
        parsed.body(),
        ReplyBody::ApRep {
            ap_rep: &ap_rep,
            krb_priv: &krb_priv
        }
    );
    assert_eq!(parsed.encode(), bytes);
    let built = ReplyMessage::ap_rep(&ap_rep, &krb_priv).unwrap();
    assert_eq!(built, parsed);
    assert_eq!(built.encode(), bytes);
}

#[test]
fn reply_with_krb_error() {
    // RFC 3244 §2: "If the length is zero, then the last field contains a
    // KRB-ERROR message instead of a KRB-PRIV message" — "sent back without
    // any encapsulation".
    let krb_error = krb_error_octets(); // 8
    let bytes = error_reply(&krb_error);
    assert_eq!(&bytes[..6], &[0x00, 0x0E, 0x00, 0x01, 0x00, 0x00]); // 14, 1, 0
    let parsed = ReplyMessage::parse(&bytes).unwrap();
    assert_eq!(
        parsed.body(),
        ReplyBody::KrbError {
            krb_error: &krb_error
        }
    );
    assert_eq!(parsed.encode(), bytes);
    let built = ReplyMessage::krb_error(&krb_error).unwrap();
    assert_eq!(built, parsed);
    assert_eq!(built.encode(), bytes);
}

#[test]
fn tcp_header_precedes_the_message() {
    // RFC 3244 §2: "For TCP transport, there is a 4 octet header in network
    // byte order that precedes the message and specifies the length of the
    // message." docs/53 §5.1: the message length field equals it.
    let bytes = request(&ap_req_octets(), &krb_priv_octets());
    let frame = tcp(&bytes);
    assert_eq!(&frame[..4], &[0x00, 0x00, 0x00, 0x26]);
    assert_eq!(tcp_message_length([0x00, 0x00, 0x00, 0x26]), Ok(38));
    let parsed = RequestMessage::parse_tcp(&frame).unwrap();
    assert_eq!(parsed, RequestMessage::parse(&bytes).unwrap());
    assert_eq!(parsed.encode_tcp(), frame);

    let reply_bytes = error_reply(&krb_error_octets());
    let reply_frame = tcp(&reply_bytes);
    let parsed = ReplyMessage::parse_tcp(&reply_frame).unwrap();
    assert_eq!(parsed.encode_tcp(), reply_frame);
    assert_eq!(parsed.encode(), reply_bytes);
}

#[test]
fn tcp_message_length_bounds() {
    // docs/53 §5.1: value 0 or > 65,535 ⇒ close before allocation; the
    // message is at least its 6-octet header.
    assert_eq!(tcp_message_length([0, 0, 0, 6]), Ok(6));
    assert_eq!(tcp_message_length([0, 0, 0xFF, 0xFF]), Ok(65_535));
}

#[test]
fn debug_shows_lengths_not_octets() {
    // docs/53 §8–§9: the AP-REQ / KRB-PRIV octets never reach a log; Debug
    // prints lengths only.
    let ap_req = vec![0xAB; 3];
    let krb_priv = vec![0xCD; 5];
    let bytes = request(&ap_req, &krb_priv);
    let text = format!("{:?}", RequestMessage::parse(&bytes).unwrap());
    assert_eq!(
        text,
        "RequestMessage { ap_req: <3 octets>, krb_priv: <5 octets> }"
    );
    let text = format!("{:?}", ReplyMessage::krb_error(&krb_priv).unwrap());
    assert!(
        text.contains("<5 octets>") && !text.contains("205"),
        "{text}"
    );
    let text = format!("{:?}", ReplyMessage::ap_rep(&ap_req, &krb_priv).unwrap());
    assert!(!text.contains("171") && !text.contains("205"), "{text}");
}

#[test]
fn request_carries_krb_proto_messages_opaquely() {
    // The KRB-PRIV slice handed out is exactly the octets keyd decodes with
    // krb-proto (RFC 4120 5.7.1); the framing neither changes nor inspects
    // them. KRB-PRIV built by krb-proto here for illustration.
    let krb_priv = krb_proto::KrbPriv {
        enc_part: krb_proto::EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0x11; 24],
        },
    }
    .encode()
    .unwrap();
    let bytes = request(&ap_req_octets(), &krb_priv);
    let parsed = RequestMessage::parse(&bytes).unwrap();
    assert_eq!(parsed.krb_priv(), krb_priv.as_slice());
    assert!(krb_proto::KrbPriv::decode(parsed.krb_priv()).is_ok());
}
