//! Context-establishment token framing — one test per statement of RFC 2743
//! §3.1, RFC 4121 §4.1 and [MS-KILE] 1.9.1 / 3.1.1.7 that the decoder or the
//! encoder enforces, and per row of docs/60 §10.1 for these sections.
//!
//! Tokens are built by hand from the RFC 2743 §3.1 layout (`common/mod.rs`);
//! the specifications carry no token test vectors (docs/60 §10.1).

mod common;

use common::*;
use gss_token::{
    ContextEstablishmentToken, Error, TokId, KERBEROS_V5_MECHANISM_ARCS,
    KERBEROS_V5_MECHANISM_OID_OCTETS, MAX_CONTEXT_TOKEN_LEN, TRUNCATED_KERBEROS_OID_ARCS,
    TRUNCATED_KERBEROS_OID_OCTETS,
};

// ---------------------------------------------------------------------------
// [MS-KILE] 1.9.1, 3.1.1.7 — the mechanism OIDs; RFC 2743 §3.1 element 5
// ---------------------------------------------------------------------------

/// [MS-KILE] 1.9.1 assigns 1.2.840.113554.1.2.2; the crate's octets equal the
/// hand derivation by RFC 2743 §3.1 5a/5b (`common::KRB5_OID`).
#[test]
fn kerberos_v5_oid_octets_follow_from_ms_kile_1_9_1_by_rfc2743_element_5() {
    assert_eq!(KERBEROS_V5_MECHANISM_ARCS, [1, 2, 840, 113554, 1, 2, 2]);
    assert_eq!(KERBEROS_V5_MECHANISM_OID_OCTETS, &KRB5_OID);
}

/// [MS-KILE] 3.1.1.7: the truncated OID 1.2.840.48018.1.2.2, by the same
/// rules.
#[test]
fn truncated_oid_octets_follow_from_ms_kile_3_1_1_7() {
    assert_eq!(TRUNCATED_KERBEROS_OID_ARCS, [1, 2, 840, 48018, 1, 2, 2]);
    assert_eq!(TRUNCATED_KERBEROS_OID_OCTETS, &TRUNCATED_OID);
}

/// docs/60 §10.1 row [MS-KILE] 1.9.1: the Kerberos V5 OID ⇒ accepted.
#[test]
fn a_token_with_the_kerberos_v5_oid_is_accepted() {
    let message = ap_req_stand_in(40);
    let token = frame(TOK_AP_REQ, &message);
    let decoded = ContextEstablishmentToken::decode(&token, TokId::KrbApReq).unwrap();
    assert_eq!(decoded.tok_id(), TokId::KrbApReq);
    assert_eq!(decoded.kerberos_message(), &message[..]);
}

/// docs/60 §10.1 row [MS-KILE] 3.1.1.7: the truncated OID ⇒ refused in
/// phase 1, reported distinctly.
#[test]
fn the_truncated_kerberos_oid_is_refused() {
    let mut inner = TOK_AP_REQ.to_vec();
    inner.extend(ap_req_stand_in(10));
    let token = frame_with_oid(&TRUNCATED_OID, &inner);
    assert_eq!(
        ContextEstablishmentToken::decode(&token, TokId::KrbApReq),
        Err(Error::TruncatedKerberosOid)
    );
}

/// docs/60 §10.1: any other OID ⇒ refused — a different last arc, a shorter
/// prefix, a longer OID, an empty OID.
#[test]
fn any_other_oid_is_refused() {
    let mut inner = TOK_AP_REQ.to_vec();
    inner.extend(ap_req_stand_in(10));
    let mut last_arc = KRB5_OID;
    last_arc[8] = 0x03; // 1.2.840.113554.1.2.3
    let mut longer = KRB5_OID.to_vec();
    longer.push(0x01);
    for oid in [&last_arc[..], &KRB5_OID[..8], &longer[..], &[][..]] {
        assert_eq!(
            ContextEstablishmentToken::decode(&frame_with_oid(oid, &inner), TokId::KrbApReq),
            Err(Error::UnsupportedMechanism),
            "OID {oid:02x?}"
        );
    }
}

// ---------------------------------------------------------------------------
// RFC 2743 §3.1 — tag, lengths, no trailing octets
// ---------------------------------------------------------------------------

/// RFC 2743 §3.1 element 1: 0x60 only.
#[test]
fn only_tag_0x60_is_accepted() {
    let good = frame(TOK_AP_REQ, &ap_req_stand_in(8));
    for tag in [0x00u8, 0x30, 0x61, 0x40, 0x7F, 0xE0, 0xFF, 0x05] {
        let mut token = good.clone();
        token[0] = tag;
        assert_eq!(
            ContextEstablishmentToken::decode(&token, TokId::KrbApReq),
            Err(Error::BadTokenTag),
            "tag {tag:#04x}"
        );
    }
}

/// RFC 2743 §3.1 2a: a token length below 128 written in the long form ⇒
/// refused ("it shall be represented in a single octet").
#[test]
fn a_short_token_length_in_the_long_form_is_refused() {
    let good = frame(TOK_AP_REQ, &ap_req_stand_in(8));
    assert!(good[1] < 0x80);
    let mut token = vec![0x60, 0x81, good[1]];
    token.extend_from_slice(&good[2..]);
    assert_eq!(
        ContextEstablishmentToken::decode(&token, TokId::KrbApReq),
        Err(Error::NonMinimalLength)
    );
}

/// RFC 2743 §3.1 2b: "no octets representing leading zeros" ⇒ a padded long
/// form is refused.
#[test]
fn a_long_token_length_with_a_leading_zero_is_refused() {
    let good = frame(TOK_AP_REQ, &ap_req_stand_in(200));
    assert_eq!(&good[1..2], &[0x81]);
    let mut token = vec![0x60, 0x82, 0x00, good[2]];
    token.extend_from_slice(&good[3..]);
    assert_eq!(
        ContextEstablishmentToken::decode(&token, TokId::KrbApReq),
        Err(Error::NonMinimalLength)
    );
}

/// RFC 2743 §3.1 2b: the long form is "two or more octets" ⇒ 0x80 alone (the
/// BER indefinite form) is refused.
#[test]
fn length_octet_0x80_is_refused() {
    let good = frame(TOK_AP_REQ, &ap_req_stand_in(8));
    let mut token = vec![0x60, 0x80];
    token.extend_from_slice(&good[2..]);
    assert_eq!(
        ContextEstablishmentToken::decode(&token, TokId::KrbApReq),
        Err(Error::MalformedLength)
    );
}

/// RFC 2743 §3.1 element 4 is "encoded per rules as described in 2a. and
/// 2b." ⇒ a non-minimal OID length is refused.
#[test]
fn a_non_minimal_oid_length_is_refused() {
    let mut body = vec![0x06, 0x81, 0x09];
    body.extend_from_slice(&KRB5_OID);
    body.extend_from_slice(&TOK_AP_REQ);
    body.extend(ap_req_stand_in(8));
    let mut token = vec![0x60];
    token.extend(length(body.len()));
    token.extend(body);
    assert_eq!(
        ContextEstablishmentToken::decode(&token, TokId::KrbApReq),
        Err(Error::NonMinimalLength)
    );
}

/// RFC 2743 §3.1 element 3: the OID tag 0x06 only.
#[test]
fn the_oid_tag_must_be_0x06() {
    let good = frame(TOK_AP_REQ, &ap_req_stand_in(8));
    let oid_tag_at = 2; // 0x60, one length octet, then element 3
    for tag in [0x00u8, 0x04, 0x05, 0x07, 0x0D, 0x26, 0x86] {
        let mut token = good.clone();
        token[oid_tag_at] = tag;
        assert_eq!(
            ContextEstablishmentToken::decode(&token, TokId::KrbApReq),
            Err(Error::BadOidTag),
            "tag {tag:#04x}"
        );
    }
}

/// RFC 2743 §3.1 element 2 counts all subsequent data; docs/60 §3.4 step 2:
/// no trailing octets ⇒ anything after the counted octets is refused.
#[test]
fn trailing_octets_are_refused() {
    let mut token = frame(TOK_AP_REQ, &ap_req_stand_in(8));
    token.push(0x00);
    assert_eq!(
        ContextEstablishmentToken::decode(&token, TokId::KrbApReq),
        Err(Error::TrailingOctets)
    );
}

/// RFC 2743 §3.1 element 2: a token length past the octets present ⇒ refused
/// (every truncation of a valid token is refused, never misread).
#[test]
fn every_truncation_is_refused() {
    let token = frame(TOK_AP_REQ, &ap_req_stand_in(200));
    for cut in 0..token.len() {
        let result = ContextEstablishmentToken::decode(&token[..cut], TokId::KrbApReq);
        assert!(
            matches!(
                result,
                Err(Error::Truncated | Error::LengthExceedsInput | Error::MalformedLength)
            ),
            "cut at {cut}: {result:?}"
        );
    }
}

/// RFC 2743 §3.1 element 4: an OID length past the end of the token ⇒
/// refused.
#[test]
fn an_oid_length_past_the_token_is_refused() {
    let body = [0x06, 0x7F, 0x2A, 0x86];
    let mut token = vec![0x60, body.len() as u8];
    token.extend_from_slice(&body);
    assert_eq!(
        ContextEstablishmentToken::decode(&token, TokId::KrbApReq),
        Err(Error::LengthExceedsInput)
    );
}

// ---------------------------------------------------------------------------
// RFC 4121 §4.1 — TOK_ID and the Kerberos message
// ---------------------------------------------------------------------------

/// docs/60 §10.1 row RFC 4121 §4.1: only TOK_ID 01 00 in an initial token.
/// Every other value — the AP-REP's 02 00, KRB_ERROR's 03 00, the
/// per-message 04 04 / 05 04, unassigned values — is refused. RFC 4121 §4.1
/// would answer an unknown TOK_ID with a KRB_ERROR token and CONTINUE_NEEDED;
/// this profile refuses instead (recorded deviation: docs/60 §3.4 step 2,
/// R60-8; Q-1093 item 9).
#[test]
fn only_tok_id_01_00_is_accepted_in_an_initial_token() {
    let message = ap_req_stand_in(8);
    for tok_id in [
        TOK_AP_REP,
        TOK_KRB_ERROR,
        [0x04, 0x04],
        [0x05, 0x04],
        [0x00, 0x00],
        [0x01, 0x01],
        [0x00, 0x01],
        [0xFF, 0xFF],
        [0x60, 0x00],
    ] {
        assert_eq!(
            ContextEstablishmentToken::decode(&frame(tok_id, &message), TokId::KrbApReq),
            Err(Error::UnexpectedTokId),
            "TOK_ID {tok_id:02x?}"
        );
    }
}

/// RFC 4121 §4.1: TOK_IDs are "expressed in big-endian order".
#[test]
fn tok_id_octets_are_big_endian() {
    assert_eq!(TokId::KrbApReq.octets(), TOK_AP_REQ);
    assert_eq!(TokId::KrbApRep.octets(), TOK_AP_REP);
}

/// docs/60 R60-8 / Q-1093 item 9: no KRB_ERROR token is ever produced — the
/// TOK_ID type has no KRB_ERROR value (this exhaustive match stops compiling
/// if one is added).
#[test]
fn no_tok_id_value_produces_krb_error() {
    for tok_id in [TokId::KrbApReq, TokId::KrbApRep] {
        match tok_id {
            TokId::KrbApReq | TokId::KrbApRep => assert_ne!(tok_id.octets(), TOK_KRB_ERROR),
        }
    }
}

/// RFC 4121 §4.1: the TOK_ID is "followed by a Kerberos message" ⇒ a token
/// that ends after its TOK_ID, or a TOK_ID cut short, is refused.
#[test]
fn a_token_without_a_kerberos_message_is_refused() {
    assert_eq!(
        ContextEstablishmentToken::decode(&frame(TOK_AP_REQ, &[]), TokId::KrbApReq),
        Err(Error::MissingKerberosMessage)
    );
    assert_eq!(
        ContextEstablishmentToken::decode(&frame_with_oid(&KRB5_OID, &[0x01]), TokId::KrbApReq),
        Err(Error::Truncated)
    );
    assert_eq!(
        ContextEstablishmentToken::new(TokId::KrbApRep, &[]),
        Err(Error::MissingKerberosMessage)
    );
}

/// docs/60 §10.1 row RFC 4121 §4.1: the AP-REP goes out with TOK_ID 02 00,
/// framed by RFC 2743 §3.1 — the encoder writes exactly the hand-built
/// layout, with a short (2a) and a long (2b) token length.
#[test]
fn the_ap_rep_token_is_framed_with_tok_id_02_00() {
    for len in [1usize, 50, 114, 115, 200, 300, 4000] {
        let ap_rep = ap_req_stand_in(len);
        let token = ContextEstablishmentToken::new(TokId::KrbApRep, &ap_rep).unwrap();
        let encoded = token.encode();
        assert_eq!(encoded, frame(TOK_AP_REP, &ap_rep), "message length {len}");
        assert_eq!(encoded.len(), token.encoded_len());
    }
}

/// docs/60 §10.1 row RFC 2743 §3.1: round trip of the encoding — decode
/// (encode(x)) = x, and an accepted token re-encodes to the same octets.
#[test]
fn encoding_round_trips() {
    for (tok_id, len) in [
        (TokId::KrbApReq, 1usize),
        (TokId::KrbApRep, 128),
        (TokId::KrbApReq, 1000),
    ] {
        let message = ap_req_stand_in(len);
        let token = ContextEstablishmentToken::new(tok_id, &message).unwrap();
        let encoded = token.encode();
        let decoded = ContextEstablishmentToken::decode(&encoded, tok_id).unwrap();
        assert_eq!(decoded, token);
        assert_eq!(decoded.encode(), encoded);
    }
}

/// RFC 2743 §3.1 element 2 at the 2a/2b boundary: the encoder switches to the
/// long form exactly when the counted octets reach 128.
#[test]
fn the_token_length_switches_to_the_long_form_at_128() {
    // Counted octets: 1 (0x06) + 1 (OID length) + 9 (OID) + 2 (TOK_ID) + message.
    let short = ContextEstablishmentToken::new(TokId::KrbApReq, &ap_req_stand_in(114))
        .unwrap()
        .encode();
    assert_eq!(short[1], 127);
    let long = ContextEstablishmentToken::new(TokId::KrbApReq, &ap_req_stand_in(115))
        .unwrap()
        .encode();
    assert_eq!(&long[1..3], &[0x81, 128]);
}

// ---------------------------------------------------------------------------
// docs/60 R60-11 — the size bound
// ---------------------------------------------------------------------------

/// docs/60 R60-11: a token over 64 KiB is refused before any octet is read
/// (even its tag); a well-formed token of exactly the bound is accepted; the
/// encoder refuses a message that would not fit.
#[test]
fn the_64_kib_bound_is_checked_first_and_exactly() {
    let oversized = vec![0x00u8; MAX_CONTEXT_TOKEN_LEN + 1];
    assert_eq!(
        ContextEstablishmentToken::decode(&oversized, TokId::KrbApReq),
        Err(Error::ContextTokenTooLong)
    );
    // Overhead at this size: 0x60, 0x82 + 2 length octets, 0x06, 0x09, the
    // 9 OID octets, the 2 TOK_ID octets = 17 octets.
    let largest = ap_req_stand_in(MAX_CONTEXT_TOKEN_LEN - 17);
    let token = frame(TOK_AP_REQ, &largest);
    assert_eq!(token.len(), MAX_CONTEXT_TOKEN_LEN);
    assert!(ContextEstablishmentToken::decode(&token, TokId::KrbApReq).is_ok());
    assert_eq!(
        ContextEstablishmentToken::new(TokId::KrbApReq, &largest)
            .unwrap()
            .encode(),
        token
    );
    let one_more = ap_req_stand_in(MAX_CONTEXT_TOKEN_LEN - 16);
    assert_eq!(
        ContextEstablishmentToken::new(TokId::KrbApReq, &one_more),
        Err(Error::ContextTokenTooLong)
    );
    assert_eq!(
        ContextEstablishmentToken::decode(&frame(TOK_AP_REQ, &one_more), TokId::KrbApReq),
        Err(Error::ContextTokenTooLong)
    );
}

/// AGENTS.md §6 / docs/60 §7: `Debug` shows no message octets.
#[test]
fn debug_shows_no_message_octets() {
    let message = [0x6E, 0xAB, 0xCD, 0xEF];
    let token = ContextEstablishmentToken::new(TokId::KrbApReq, &message).unwrap();
    let shown = format!("{token:?}");
    assert!(shown.contains("kerberos_message_len: 4"), "{shown}");
    // Neither a byte list nor any of the message's octet values appears.
    for needle in ["[", "110", "171", "205", "239"] {
        assert!(!shown.contains(needle), "{shown}");
    }
}
