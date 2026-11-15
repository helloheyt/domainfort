//! Refusal tests: one test per bound and per malformed form of RFC 3244 §2 /
//! docs/53 §5.1 — truncation, length mismatches, trailing octets, wrong
//! version, oversized input, AP length 0 / too long, missing last field — each
//! mapped to its distinct `Error` and to the result code the front answers
//! with (docs/53 §5.7). Messages built by hand from the RFC 3244 §2 layout
//! (`common/mod.rs`); none from any other implementation.

mod common;

use common::*;
use parse_kpasswd::{
    tcp_message_length, Error, NonZeroResultCode, ReplyMessage, RequestMessage, MAX_MESSAGE_LEN,
};

// ---------------------------------------------------------------------------
// TCP header — RFC 3244 §2; docs/53 §5.1
// ---------------------------------------------------------------------------

#[test]
fn tcp_header_over_65535_is_refused_before_allocation() {
    // docs/53 §5.1: "> 65,535 ⇒ close before allocation" — the 16-bit message
    // length field cannot describe a longer message.
    assert_eq!(
        tcp_message_length([0x00, 0x01, 0x00, 0x00]),
        Err(Error::TcpLengthTooLarge)
    );
    assert_eq!(
        tcp_message_length([0xFF, 0xFF, 0xFF, 0xFF]),
        Err(Error::TcpLengthTooLarge)
    );
    // The same through parse_tcp, with no message octets present at all: the
    // header alone decides.
    assert_eq!(
        RequestMessage::parse_tcp(&[0x80, 0x00, 0x00, 0x00]),
        Err(Error::TcpLengthTooLarge)
    );
}

#[test]
fn tcp_header_zero_or_below_the_message_header_is_refused() {
    // docs/53 §5.1: value 0 ⇒ close; "message length ≥ 6".
    for n in 0u8..6 {
        assert_eq!(
            tcp_message_length([0, 0, 0, n]),
            Err(Error::TcpLengthTooSmall)
        );
    }
}

#[test]
fn tcp_frame_truncated_or_with_trailing_octets() {
    // RFC 3244 §2: the header "specifies the length of the message"; one
    // request per connection (docs/53 §5.1) — so the frame must hold exactly
    // the announced octets.
    let bytes = request(&ap_req_octets(), &krb_priv_octets());
    let frame = tcp(&bytes);
    let mut trailing = frame.clone();
    trailing.push(0x00);
    assert_eq!(
        RequestMessage::parse_tcp(&trailing),
        Err(Error::TcpLengthMismatch)
    );
    assert_eq!(
        RequestMessage::parse_tcp(&frame[..frame.len() - 1]),
        Err(Error::TcpLengthMismatch)
    );
    for len in 0..4 {
        assert_eq!(
            RequestMessage::parse_tcp(&frame[..len]),
            Err(Error::Truncated)
        );
    }
    let reply_frame = tcp(&error_reply(&krb_error_octets()));
    let mut trailing = reply_frame.clone();
    trailing.extend_from_slice(&[1, 2, 3]);
    assert_eq!(
        ReplyMessage::parse_tcp(&trailing),
        Err(Error::TcpLengthMismatch)
    );
}

#[test]
fn tcp_header_disagreeing_with_message_length() {
    // docs/53 §5.1: message length = the TCP header. A header announcing one
    // octet more than the message, with one octet appended, leaves the message
    // length field short of the octets given.
    let mut bytes = request(&ap_req_octets(), &krb_priv_octets());
    bytes.push(0x00);
    let frame = tcp(&bytes);
    assert_eq!(
        RequestMessage::parse_tcp(&frame),
        Err(Error::MessageLengthMismatch)
    );
}

// ---------------------------------------------------------------------------
// message length — RFC 3244 §2
// ---------------------------------------------------------------------------

#[test]
fn message_shorter_than_its_header() {
    // RFC 3244 §2: three 16-bit fields precede the data.
    let bytes = request(&ap_req_octets(), &krb_priv_octets());
    for len in 0..6 {
        assert_eq!(RequestMessage::parse(&bytes[..len]), Err(Error::Truncated));
        assert_eq!(ReplyMessage::parse(&bytes[..len]), Err(Error::Truncated));
    }
}

#[test]
fn message_length_field_mismatch_truncation_and_trailing_octets() {
    // RFC 3244 §2: message length "contains the number of bytes in the
    // message including this field". Truncated input and trailing octets both
    // break it.
    let bytes = request(&ap_req_octets(), &krb_priv_octets());
    for len in 6..bytes.len() {
        assert_eq!(
            RequestMessage::parse(&bytes[..len]),
            Err(Error::MessageLengthMismatch),
            "prefix {len}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0x00);
    assert_eq!(
        RequestMessage::parse(&trailing),
        Err(Error::MessageLengthMismatch)
    );
    // A field one too large and one too small over the right octets.
    let ap = ap_req_octets();
    let pr = krb_priv_octets();
    let n = u16::try_from(bytes.len()).unwrap();
    for wrong in [n - 1, n + 1, 0, 6] {
        let m = raw_message(wrong, 0xFF80, u16::try_from(ap.len()).unwrap(), &[&ap, &pr]);
        assert_eq!(RequestMessage::parse(&m), Err(Error::MessageLengthMismatch));
    }
    // Little-endian length (wrong byte order) is a mismatch, not a reading.
    let mut swapped = bytes.clone();
    swapped.swap(0, 1);
    assert_eq!(
        RequestMessage::parse(&swapped),
        Err(Error::MessageLengthMismatch)
    );
}

#[test]
fn reply_length_mismatches() {
    // RFC 3244 §2: the same message length rule in the reply.
    let bytes = reply(&ap_rep_octets(), &krb_priv_octets());
    let mut trailing = bytes.clone();
    trailing.push(0xEE);
    assert_eq!(
        ReplyMessage::parse(&trailing),
        Err(Error::MessageLengthMismatch)
    );
    assert_eq!(
        ReplyMessage::parse(&bytes[..bytes.len() - 1]),
        Err(Error::MessageLengthMismatch)
    );
}

#[test]
fn oversized_message_is_refused() {
    // RFC 3244 §2 / docs/53 §5.9: ≤ 65,535 octets. A 65,536-octet input is
    // refused before its header is read.
    let huge = vec![0xFF; MAX_MESSAGE_LEN + 1];
    assert_eq!(RequestMessage::parse(&huge), Err(Error::MessageTooLarge));
    assert_eq!(ReplyMessage::parse(&huge), Err(Error::MessageTooLarge));
}

// ---------------------------------------------------------------------------
// protocol version number — RFC 3244 §2; docs/53 R53-2
// ---------------------------------------------------------------------------

#[test]
fn request_version_other_than_0xff80_is_bad_version() {
    // RFC 3244 §2: 0xff80. docs/53 R53-2 / §3.2: every other version —
    // including 1, the original protocol (Q-607) — ⇒ BAD_VERSION, no fallback.
    let ap = ap_req_octets();
    let pr = krb_priv_octets();
    for version in [0x0001u16, 0x0000, 0x80FF, 0xFF81, 0xFF7F, 0xFFFF] {
        let m = message(version, &ap, &pr);
        let err = RequestMessage::parse(&m).unwrap_err();
        assert_eq!(err, Error::BadVersion, "version {version:#06x}");
        assert_eq!(err.result_code(), NonZeroResultCode::BadVersion);
    }
}

#[test]
fn reply_version_other_than_0x0001_is_bad_version() {
    // RFC 3244 §2: the reply's version is 0x0001 — a request version (0xff80)
    // in a reply is refused, as is any other.
    let ap = ap_rep_octets();
    let pr = krb_priv_octets();
    for version in [0xFF80u16, 0x0000, 0x0100, 0x0002] {
        assert_eq!(
            ReplyMessage::parse(&message(version, &ap, &pr)),
            Err(Error::BadVersion)
        );
    }
}

#[test]
fn length_is_checked_before_version() {
    // docs/53 §5.1 order: framing (message length) before version — a
    // version-1 message with a broken length is MALFORMED, not BAD_VERSION.
    let mut m = message(0x0001, &ap_req_octets(), &krb_priv_octets());
    m.push(0x00);
    let err = RequestMessage::parse(&m).unwrap_err();
    assert_eq!(err, Error::MessageLengthMismatch);
    assert_eq!(err.result_code(), NonZeroResultCode::Malformed);
}

// ---------------------------------------------------------------------------
// AP_REQ / AP_REP length and the last field — RFC 3244 §2
// ---------------------------------------------------------------------------

#[test]
fn request_ap_req_length_zero_is_malformed() {
    // RFC 3244 §2: length 0 ⇒ "the last field contains a KRB-ERROR message";
    // docs/53 §5.1 / Q-603 item 5: a request with AP_REQ length 0 ⇒ MALFORMED
    // (a server never parses a client's KRB-ERROR).
    let m = request(&[], &krb_error_octets());
    let err = RequestMessage::parse(&m).unwrap_err();
    assert_eq!(err, Error::ApReqLengthZero);
    assert_eq!(err.result_code(), NonZeroResultCode::Malformed);
    assert_eq!(
        RequestMessage::new(&[], &krb_priv_octets()),
        Err(Error::ApReqLengthZero)
    );
}

#[test]
fn ap_length_beyond_the_message() {
    // docs/53 §5.1: AP_REQ length ≤ the remainder.
    let ap = ap_req_octets();
    let pr = krb_priv_octets();
    let total = u16::try_from(6 + ap.len() + pr.len()).unwrap();
    let too_long = u16::try_from(ap.len() + pr.len() + 1).unwrap();
    let m = raw_message(total, 0xFF80, too_long, &[&ap, &pr]);
    assert_eq!(
        RequestMessage::parse(&m),
        Err(Error::ApLengthExceedsMessage)
    );
    let m = raw_message(total, 0xFF80, 0xFFFF, &[&ap, &pr]);
    assert_eq!(
        RequestMessage::parse(&m),
        Err(Error::ApLengthExceedsMessage)
    );
    let m = raw_message(total, 0x0001, too_long, &[&ap, &pr]);
    assert_eq!(ReplyMessage::parse(&m), Err(Error::ApLengthExceedsMessage));
}

#[test]
fn request_without_krb_priv_is_malformed() {
    // docs/53 §5.1: the remainder after the AP-REQ is the KRB-PRIV, ≥ 1 octet
    // (AP_REQ length = the whole remainder ⇒ nothing left).
    let ap = ap_req_octets();
    let m = request(&ap, &[]);
    assert_eq!(RequestMessage::parse(&m), Err(Error::MissingKrbPriv));
    assert_eq!(RequestMessage::new(&ap, &[]), Err(Error::MissingKrbPriv));
    // A header alone, AP_REQ length 0 and nothing else.
    let m = raw_message(6, 0xFF80, 0, &[]);
    assert_eq!(RequestMessage::parse(&m), Err(Error::ApReqLengthZero));
}

#[test]
fn reply_without_last_field_is_malformed() {
    // RFC 3244 §2: AP-REP then KRB-PRIV, or (length 0) a KRB-ERROR — never
    // nothing.
    let m = reply(&ap_rep_octets(), &[]);
    assert_eq!(ReplyMessage::parse(&m), Err(Error::MissingKrbPriv));
    let m = raw_message(6, 0x0001, 0, &[]);
    assert_eq!(ReplyMessage::parse(&m), Err(Error::MissingKrbError));
    assert_eq!(ReplyMessage::krb_error(&[]), Err(Error::MissingKrbError));
    assert_eq!(
        ReplyMessage::ap_rep(&ap_rep_octets(), &[]),
        Err(Error::MissingKrbPriv)
    );
}

#[test]
fn reply_with_empty_ap_rep_cannot_be_built() {
    // RFC 3244 §2: AP_REP length 0 means "KRB-ERROR instead of KRB-PRIV", so an
    // "AP-REP + KRB-PRIV" reply with an empty AP-REP would be misread — it is
    // refused at construction.
    assert_eq!(
        ReplyMessage::ap_rep(&[], &krb_priv_octets()),
        Err(Error::ApRepLengthZero)
    );
}

#[test]
fn constructors_refuse_oversized_messages() {
    // RFC 3244 §2: nothing longer than the 16-bit message length can count.
    let big = vec![0u8; MAX_MESSAGE_LEN];
    assert_eq!(
        RequestMessage::new(&big, &[0x75]),
        Err(Error::MessageTooLarge)
    );
    assert_eq!(
        ReplyMessage::ap_rep(&big, &[0x75]),
        Err(Error::MessageTooLarge)
    );
    assert_eq!(ReplyMessage::krb_error(&big), Err(Error::MessageTooLarge));
    // One octet under the bound still fits (6 + 65,528 + 1 = 65,535).
    let fits = vec![0u8; MAX_MESSAGE_LEN - 7];
    assert!(RequestMessage::new(&fits, &[0x75]).is_ok());
    assert!(ReplyMessage::krb_error(&vec![0u8; MAX_MESSAGE_LEN - 6]).is_ok());
}

// ---------------------------------------------------------------------------
// Result codes — RFC 3244 §2; docs/53 §5.7
// ---------------------------------------------------------------------------

#[test]
fn every_framing_failure_maps_to_malformed_or_bad_version() {
    // docs/53 §5.1 / §5.7: framing ⇒ 1 MALFORMED; version ⇒ 6 BAD_VERSION;
    // never 0 (the type cannot hold it — RFC 3244 §2).
    let malformed = [
        Error::TcpLengthTooLarge,
        Error::TcpLengthTooSmall,
        Error::TcpLengthMismatch,
        Error::Truncated,
        Error::MessageTooLarge,
        Error::MessageLengthMismatch,
        Error::ApReqLengthZero,
        Error::ApRepLengthZero,
        Error::ApLengthExceedsMessage,
        Error::MissingKrbPriv,
        Error::MissingKrbError,
    ];
    for err in malformed {
        assert_eq!(err.result_code(), NonZeroResultCode::Malformed, "{err:?}");
        assert_eq!(err.result_code().value(), 1);
    }
    assert_eq!(Error::BadVersion.result_code().value(), 6);
}

#[test]
fn errors_carry_no_message_octets() {
    // AGENTS.md §6: errors are unit variants; nothing of the input can appear
    // in Debug or Display.
    let m = message(0x1234, &[0xAB; 4], &[0xCD; 4]);
    let err = RequestMessage::parse(&m).unwrap_err();
    for text in [format!("{err:?}"), err.to_string()] {
        assert!(!text.contains("171") && !text.contains("ab"), "{text}");
    }
}
