//! Stream framing on split and concatenated buffers.
//!
//! Source: RFC 4511 §5.2 (PDUs mapped directly onto the TCP byte stream, one
//! after another), §4.1.1 (an unrecognisable LDAPMessage tag or incorrect
//! lengths are malformed); X.690 8.1.3; A-45; docs/49 §2.4 (the bound is
//! applied to the announced size before waiting for contents).

mod common;

use common::{message, search_with_filter, tlv, wire_request, PRESENT_A};
use parse_ldap::{
    decode_message, frame_length, AuthState, Error, Frame, ProtocolOp, MAX_AUTH_MESSAGE_OCTETS,
    MAX_PREAUTH_MESSAGE_OCTETS,
};

const PRE: AuthState = AuthState::Unauthenticated;

/// UnbindRequest, messageID 6 (RFC 4511 §4.3): 30 05 02 01 06 42 00.
const UNBIND: [u8; 7] = [0x30, 0x05, 0x02, 0x01, 0x06, 0x42, 0x00];

#[test]
fn empty_and_partial_buffers_need_more() {
    assert_eq!(frame_length(&[], PRE), Ok(Frame::NeedMore));
    assert_eq!(frame_length(&[0x30], PRE), Ok(Frame::NeedMore));
    assert_eq!(frame_length(&[0x30, 0x84, 0x00], PRE), Ok(Frame::NeedMore));
    assert_eq!(frame_length(&UNBIND[..6], PRE), Ok(Frame::NeedMore));
    assert_eq!(
        frame_length(&UNBIND, PRE),
        Ok(Frame::Complete { length: 7 })
    );
}

#[test]
fn every_split_point() {
    // A message arriving in two pieces at any boundary: NeedMore until whole.
    let bytes = search_with_filter(&tlv(0xA0, &PRESENT_A.repeat(60)));
    assert!(bytes.len() > 128, "exercise the long-form length");
    for cut in 0..bytes.len() {
        assert_eq!(frame_length(&bytes[..cut], PRE), Ok(Frame::NeedMore));
    }
    assert_eq!(
        frame_length(&bytes, PRE),
        Ok(Frame::Complete {
            length: bytes.len()
        })
    );
}

#[test]
fn concatenated_messages() {
    // Three PDUs back to back (RFC 4511 §5.2): frame, decode, advance.
    let bind = message(&tlv(0x60, &[0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]));
    let search = search_with_filter(&PRESENT_A);
    let stream = [bind.as_slice(), &search, &UNBIND].concat();
    let mut rest = stream.as_slice();
    let mut ops = Vec::new();
    while !rest.is_empty() {
        let Frame::Complete { length } = frame_length(rest, PRE).unwrap() else {
            panic!("a whole message is buffered");
        };
        let (pdu, tail) = rest.split_at(length);
        ops.push(decode_message(pdu, &wire_request()).unwrap().protocol_op);
        rest = tail;
    }
    assert!(matches!(ops[0], ProtocolOp::BindRequest(_)));
    assert!(matches!(ops[1], ProtocolOp::SearchRequest(_)));
    assert_eq!(ops[2], ProtocolOp::UnbindRequest);
    // A whole message followed by a partial one: the first is complete.
    let partial = [UNBIND.as_slice(), &UNBIND[..3]].concat();
    assert_eq!(
        frame_length(&partial, PRE),
        Ok(Frame::Complete { length: 7 })
    );
}

#[test]
fn non_minimal_length_accepted_up_to_four_octets() {
    // A-45; X.690 8.1.3.5 NOTE 2; [MS-ADTS] 6.3.3 uses `84 00 00 00 nn`.
    let four = [
        0x30, 0x84, 0x00, 0x00, 0x00, 0x05, 0x02, 0x01, 0x06, 0x42, 0x00,
    ];
    assert_eq!(frame_length(&four, PRE), Ok(Frame::Complete { length: 11 }));
    let five = [0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x05];
    assert_eq!(frame_length(&five, PRE), Err(Error::TooManyLengthOctets));
    // Refused as soon as the length octet count is seen.
    assert_eq!(
        frame_length(&[0x30, 0x85], PRE),
        Err(Error::TooManyLengthOctets)
    );
}

#[test]
fn bad_envelopes_rejected() {
    // RFC 4511 §5.1 / X.690 8.1.3.6: indefinite form.
    assert_eq!(
        frame_length(&[0x30, 0x80], PRE),
        Err(Error::IndefiniteLength)
    );
    // X.690 8.1.3.5 c): reserved.
    assert_eq!(
        frame_length(&[0x30, 0xFF], PRE),
        Err(Error::ReservedLengthOctet)
    );
    // RFC 4511 §4.1.1: not a SEQUENCE.
    assert_eq!(frame_length(&[0x31, 0x00], PRE), Err(Error::UnexpectedTag));
    assert_eq!(frame_length(&[0x61, 0x00], PRE), Err(Error::UnexpectedTag));
    assert_eq!(
        frame_length(&[0x10, 0x00], PRE),
        Err(Error::PrimitiveConstructedMismatch)
    );
    // X.690 8.1.2.4, 8.1.5.
    assert_eq!(frame_length(&[0x1F], PRE), Err(Error::HighTagNumber));
    assert_eq!(frame_length(&[0x00], PRE), Err(Error::EndOfContents));
}

#[test]
fn bound_applied_before_contents_arrive() {
    // docs/49 §2.4; [MS-ADTS] 3.1.1.3.4.6: the announced size alone decides.
    // 30 83 01 00 00 announces 65,536 contents octets: over 64 KiB with the
    // header, refused with only the five header octets present.
    let header = [0x30, 0x83, 0x01, 0x00, 0x00];
    assert_eq!(frame_length(&header, PRE), Err(Error::MessageTooLarge));
    assert_eq!(
        frame_length(&header, AuthState::Authenticated),
        Ok(Frame::NeedMore)
    );
    // Exactly at the bound: accepted (contents = bound - 4 header octets).
    let at_bound = (MAX_PREAUTH_MESSAGE_OCTETS - 4) as u32;
    let header = [0x30, 0x82, (at_bound >> 8) as u8, at_bound as u8];
    assert_eq!(frame_length(&header, PRE), Ok(Frame::NeedMore));
    // The largest four-octet length is refused even when authenticated.
    let huge = [0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
    assert_eq!(
        frame_length(&huge, AuthState::Authenticated),
        Err(Error::MessageTooLarge)
    );
    // Exactly at the authenticated bound (contents = bound - 5 header octets):
    // accepted when authenticated, one octet over is refused.
    let at_auth_bound = (MAX_AUTH_MESSAGE_OCTETS - 5) as u32;
    let header = [
        0x30,
        0x83,
        (at_auth_bound >> 16) as u8,
        (at_auth_bound >> 8) as u8,
        at_auth_bound as u8,
    ];
    assert_eq!(
        frame_length(&header, AuthState::Authenticated),
        Ok(Frame::NeedMore)
    );
    let over = at_auth_bound + 1;
    let header = [
        0x30,
        0x83,
        (over >> 16) as u8,
        (over >> 8) as u8,
        over as u8,
    ];
    assert_eq!(
        frame_length(&header, AuthState::Authenticated),
        Err(Error::MessageTooLarge)
    );
}
