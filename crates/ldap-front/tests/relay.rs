//! Tier 1 (docs/50 §9: in-process, no sockets): the framer with dird's
//! framing state and the wire → canonical re-encoding (docs/49 R49-16;
//! docs/50 §4.2, §4.3 step 1).
//!
//! The LDAP messages are written by hand from RFC 4511 §4.1.1
//! (LDAPMessage), §4.2 (BindRequest), §4.5.1 (SearchRequest), §4.14.1
//! (StartTLS) and the BER of X.690 as RFC 4511 §5.1 profiles it (definite
//! lengths; a long-form length of up to four octets accepted on the wire —
//! A-45). The canonical forms are the minimal encodings parse-ldap's
//! encoder produces (docs/49 §2.3). Every octet is derived in the comments;
//! no vector from any other implementation.

use ldap_front::relay::{take_message, FrameFailure, WireBuffer, MAX_BUFFERED_OCTETS};
use parse_ldap::{
    decode_message, AuthState, DecodeOptions, Direction, Profile, ProtocolOp,
    MAX_AUTH_MESSAGE_OCTETS, MAX_PREAUTH_MESSAGE_OCTETS,
};

/// The rootDSE search (RFC 4511 §4.5.1; RFC 4512 §5.1) with messageID 1,
/// minimal lengths:
///
/// ```text
/// 30 25                      LDAPMessage SEQUENCE, 37 octets
///   02 01 01                 messageID 1
///   63 20                    [APPLICATION 3] SearchRequest, 32 octets
///     04 00                  baseObject ""
///     0a 01 00               scope baseObject (0)
///     0a 01 00               derefAliases neverDerefAliases (0)
///     02 01 00               sizeLimit 0
///     02 01 00               timeLimit 0
///     01 01 00               typesOnly FALSE
///     87 0b "objectClass"    filter present [7]
///     30 00                  attributes (empty)
/// ```
fn root_dse_body() -> Vec<u8> {
    let mut search = vec![
        0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01,
        0x01, 0x00, 0x87, 0x0b,
    ];
    search.extend_from_slice(b"objectClass");
    search.extend_from_slice(&[0x30, 0x00]);
    assert_eq!(search.len(), 0x20);
    let mut body = vec![0x02, 0x01, 0x01, 0x63, 0x20];
    body.extend_from_slice(&search);
    assert_eq!(body.len(), 0x25);
    body
}

fn root_dse_canonical() -> Vec<u8> {
    let mut message = vec![0x30, 0x25];
    message.extend_from_slice(&root_dse_body());
    message
}

/// The same message with the outer length in the four-octet long form
/// (X.690 8.1.3.5: `84` then four length octets; non-minimal, accepted on
/// the wire — A-45, [MS-ADTS] 6.3.3 as parse-ldap cites it).
fn root_dse_long_form() -> Vec<u8> {
    let mut message = vec![0x30, 0x84, 0x00, 0x00, 0x00, 0x25];
    message.extend_from_slice(&root_dse_body());
    message
}

/// StartTLS (RFC 4511 §4.14.1), messageID 2:
///
/// ```text
/// 30 1d                      LDAPMessage, 29 octets
///   02 01 02                 messageID 2
///   77 18                    [APPLICATION 23] ExtendedRequest, 24 octets
///     80 16 "1.3.6.1.4.1.1466.20037"   requestName [0], 22 octets
/// ```
fn start_tls() -> Vec<u8> {
    let mut message = vec![0x30, 0x1d, 0x02, 0x01, 0x02, 0x77, 0x18, 0x80, 0x16];
    message.extend_from_slice(b"1.3.6.1.4.1.1466.20037");
    assert_eq!(message.len(), 2 + 0x1d);
    message
}

/// A simple bind with a password (RFC 4511 §4.2), messageID 3, version 3,
/// name "cn=x", password "secret":
///
/// ```text
/// 30 16                      LDAPMessage, 22 octets
///   02 01 03                 messageID 3
///   60 11                    [APPLICATION 0] BindRequest, 17 octets
///     02 01 03               version 3
///     04 04 "cn=x"           name
///     80 06 "secret"         simple [0]
/// ```
fn password_bind() -> Vec<u8> {
    let mut message = vec![
        0x30, 0x16, 0x02, 0x01, 0x03, 0x60, 0x11, 0x02, 0x01, 0x03, 0x04, 0x04,
    ];
    message.extend_from_slice(b"cn=x");
    message.extend_from_slice(&[0x80, 0x06]);
    message.extend_from_slice(b"secret");
    assert_eq!(message.len(), 2 + 0x16);
    message
}

fn canonical_options(auth: AuthState) -> DecodeOptions {
    DecodeOptions::canonical_request(auth)
}

fn buffer_with(octets: &[u8]) -> WireBuffer {
    let mut buffer = WireBuffer::new();
    buffer.extend(octets).unwrap();
    buffer
}

/// docs/49 R49-16; docs/50 §4.2 ("the front decodes with `Profile::Wire`
/// and encodes with `encode_message`; the engine decodes with
/// `Profile::Canonical` only"); A-45: a valid but non-canonical wire message
/// (a four-octet long-form length) is relayed as its minimal encoding — the
/// form dird's engine accepts — while the wire form itself would be refused
/// by the canonical profile.
#[test]
fn a_long_form_length_is_relayed_canonical() {
    let mut buffer = buffer_with(&root_dse_long_form());
    let framed = take_message(&mut buffer, AuthState::Unauthenticated)
        .unwrap()
        .unwrap();
    assert_eq!(framed.canonical.as_slice(), root_dse_canonical().as_slice());
    assert!(!framed.start_tls);
    assert!(!framed.input_pending);
    assert!(buffer.is_empty());
    assert!(decode_message(
        &framed.canonical,
        &canonical_options(AuthState::Unauthenticated)
    )
    .is_ok());
    assert!(decode_message(
        &root_dse_long_form(),
        &canonical_options(AuthState::Unauthenticated)
    )
    .is_err());
}

/// docs/50 §4.2 ("compares the announced size with the bound for the
/// session's authentication state before any allocation or wait for
/// contents"); docs/49 §2.4: a header announcing one octet more than the
/// unauthenticated bound is refused with only its five octets present; the
/// same header under the authenticated state waits for the contents.
#[test]
fn the_framing_state_bounds_the_announced_size() {
    // 30 83 LL LL LL: total = 1 + 4 + length.
    let length = MAX_PREAUTH_MESSAGE_OCTETS - 5 + 1;
    let header = [
        0x30,
        0x83,
        (length >> 16) as u8,
        (length >> 8) as u8,
        length as u8,
    ];
    let mut unauthenticated = buffer_with(&header);
    assert_eq!(
        take_message(&mut unauthenticated, AuthState::Unauthenticated).err(),
        Some(FrameFailure::TooLarge)
    );
    let mut authenticated = buffer_with(&header);
    assert!(take_message(&mut authenticated, AuthState::Authenticated)
        .unwrap()
        .is_none());
    const { assert!(MAX_PREAUTH_MESSAGE_OCTETS < MAX_AUTH_MESSAGE_OCTETS) };
}

/// RFC 4511 §5.2 (one PDU after another); docs/50 §4.3 step 1
/// (`input_pending` = octets after the PDU): a StartTLS request followed by
/// another message — the first is recognised as StartTLS with input
/// pending; the second has none.
#[test]
fn start_tls_and_input_pending() {
    let mut octets = start_tls();
    octets.extend_from_slice(&root_dse_canonical());
    let mut buffer = buffer_with(&octets);
    let first = take_message(&mut buffer, AuthState::Unauthenticated)
        .unwrap()
        .unwrap();
    assert!(first.start_tls);
    assert!(first.input_pending);
    assert_eq!(first.canonical.as_slice(), start_tls().as_slice());
    let second = take_message(&mut buffer, AuthState::Unauthenticated)
        .unwrap()
        .unwrap();
    assert!(!second.start_tls);
    assert!(!second.input_pending);
    assert!(buffer.is_empty());
}

/// RFC 4511 §5.2: an incomplete message is not cut (read more); once its
/// last octet arrives it is.
#[test]
fn an_incomplete_message_waits() {
    let message = root_dse_canonical();
    let (head, tail) = message.split_at(10);
    let mut buffer = buffer_with(head);
    assert!(take_message(&mut buffer, AuthState::Unauthenticated)
        .unwrap()
        .is_none());
    assert_eq!(buffer.len(), 10);
    buffer.extend(tail).unwrap();
    assert!(take_message(&mut buffer, AuthState::Unauthenticated)
        .unwrap()
        .is_some());
}

/// RFC 4511 §4.1.1 (a tag that cannot be recognised, or incorrect
/// structures ⇒ Notice of Disconnection protocolError and terminate):
/// a TLS record sent to the cleartext port (first octet 0x16, RFC 8446
/// §5.1 handshake(22)) is not LDAP; a well-framed SEQUENCE whose contents
/// are not an LDAPMessage does not decode (and its octets leave the
/// buffer).
#[test]
fn not_ldap_and_not_decodable() {
    let mut tls_record = buffer_with(&[0x16, 0x03, 0x01, 0x00, 0x05]);
    assert_eq!(
        take_message(&mut tls_record, AuthState::Unauthenticated).err(),
        Some(FrameFailure::NotLdap)
    );
    // 30 03 04 01 41: a SEQUENCE holding an OCTET STRING — no messageID.
    let mut garbage = buffer_with(&[0x30, 0x03, 0x04, 0x01, 0x41]);
    assert_eq!(
        take_message(&mut garbage, AuthState::Unauthenticated).err(),
        Some(FrameFailure::NotDecodable)
    );
    assert!(garbage.is_empty());
}

/// docs/49 §2.3, A-52 ("the simple bind password is never retained — a
/// placeholder"): the canonical message dird receives does not carry the
/// password, and the wire octets that did are gone from the buffer.
#[test]
fn a_bind_password_never_reaches_dird() {
    let mut buffer = buffer_with(&password_bind());
    let framed = take_message(&mut buffer, AuthState::Unauthenticated)
        .unwrap()
        .unwrap();
    assert!(buffer.is_empty());
    assert!(!framed
        .canonical
        .windows(b"secret".len())
        .any(|window| window == b"secret"));
    let decoded = decode_message(
        &framed.canonical,
        &canonical_options(AuthState::Unauthenticated),
    )
    .unwrap();
    assert!(matches!(decoded.protocol_op, ProtocolOp::BindRequest(_)));
    // The canonical form is a request the engine's profile accepts.
    assert!(decode_message(
        &framed.canonical,
        &DecodeOptions {
            direction: Direction::Request,
            profile: Profile::Canonical,
            max_message_octets: MAX_PREAUTH_MESSAGE_OCTETS,
        }
    )
    .is_ok());
}

/// docs/CLEAN-ROOM.md (no unbounded allocation): the buffer refuses to grow past
/// its bound, and appends nothing when it refuses.
#[test]
fn the_buffer_is_bounded() {
    let mut buffer = WireBuffer::new();
    buffer.extend(&vec![0u8; MAX_BUFFERED_OCTETS]).unwrap();
    assert!(buffer.extend(&[0u8]).is_err());
    assert_eq!(buffer.len(), MAX_BUFFERED_OCTETS);
    buffer.wipe();
    assert!(buffer.is_empty());
}
