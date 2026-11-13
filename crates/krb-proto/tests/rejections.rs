//! Message-level rejection tests: wrong tag / class, wrong pvno / msg-type,
//! missing / out-of-order / unknown components, constraint violations,
//! over-limit SEQUENCE OF, trailing data. Each malformed input maps to one
//! specific `Error` variant. Vectors are hand-derived from the named RFC 4120
//! clauses (X.690 (02/2021) encodings); none comes from another implementation.

mod common;

use common::*;
use krb_proto::{
    limits, ApReq, AsRep, AsReq, Authenticator, EncAsRepPart, EncTgsRepPart, EncTicketPart, Error,
    EtypeInfo2, KdcReqBody, KdcRequest, KrbError, LastReq, MethodData, TgsReq, Ticket,
};

// ---------------------------------------------------------------------------
// Builders (RFC 4120 5.4.1, 5.5.1, 5.9.1, 5.3)
// ---------------------------------------------------------------------------

/// Minimal KDC-REQ-BODY components, each separately so tests can drop or
/// reorder them. RFC 4120 5.4.1.
fn body_parts() -> Vec<Vec<u8>> {
    vec![
        ctx(0, &flags32([0x40, 0x00, 0x00, 0x00])),
        ctx(2, &gstring(b"EXAMPLE.ORG")),
        ctx(3, &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"])),
        ctx(5, &gtime(b"20261114000000Z")),
        ctx(7, &int(&[0x01])),
        ctx(8, &seq(&[&int(&[0x12])])),
    ]
}

fn body_from(parts: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    seq(&refs)
}

/// `[APPLICATION tag] KDC-REQ` with the given pvno / msg-type contents and
/// optional padata. RFC 4120 5.4.1.
fn kdc_req(tag: u8, pvno: &[u8], msg_type: &[u8], padata: Option<&[u8]>) -> Vec<u8> {
    let body = body_from(&body_parts());
    let mut parts = vec![ctx(1, &int(pvno)), ctx(2, &int(msg_type))];
    if let Some(pa) = padata {
        parts.push(ctx(3, pa));
    }
    parts.push(ctx(4, &body));
    app(tag, &body_from(&parts))
}

fn one_pa_data() -> Vec<u8> {
    seq(&[&ctx(1, &int(&[0x02])), &ctx(2, &octets(&[0x00]))])
}

/// Minimal KRB-ERROR components. RFC 4120 5.9.1.
fn krb_error_parts() -> Vec<Vec<u8>> {
    vec![
        ctx(0, &int(&[0x05])),
        ctx(1, &int(&[0x1E])),
        ctx(4, &gtime(b"20261113090000Z")),
        ctx(5, &int(&[0x00])),
        ctx(6, &int(&[0x19])),
        ctx(9, &gstring(b"EXAMPLE.ORG")),
        ctx(10, &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"])),
    ]
}

/// Minimal Authenticator components. RFC 4120 5.5.1.
fn authenticator_parts() -> Vec<Vec<u8>> {
    vec![
        ctx(0, &int(&[0x05])),
        ctx(1, &gstring(b"EXAMPLE.ORG")),
        ctx(2, &pname_der(&[0x01], &["alice"])),
        ctx(4, &int(&[0x00])),
        ctx(5, &gtime(b"20261113090512Z")),
    ]
}

/// Minimal EncTicketPart components with a given flags encoding. RFC 4120 5.3.
fn enc_ticket_part_with_flags(flags: &[u8]) -> Vec<u8> {
    let key: Vec<u8> = (0..32).collect();
    app(
        3,
        &seq(&[
            &ctx(0, flags),
            &ctx(1, &seq(&[&ctx(0, &int(&[0x12])), &ctx(1, &octets(&key))])),
            &ctx(2, &gstring(b"EXAMPLE.ORG")),
            &ctx(3, &pname_der(&[0x01], &["bob"])),
            &ctx(4, &seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &octets(&[]))])),
            &ctx(5, &gtime(b"20261113090000Z")),
            &ctx(7, &gtime(b"20261113190000Z")),
        ]),
    )
}

// ---------------------------------------------------------------------------
// Wrong tag / class — RFC 4120 5.10, 5.1.4, 5.1.5
// ---------------------------------------------------------------------------

#[test]
fn as_req_and_tgs_req_tags_are_not_interchangeable() {
    // RFC 4120 5.10: AS-REQ is [APPLICATION 10], TGS-REQ [APPLICATION 12].
    let as_req = kdc_req(10, &[0x05], &[0x0A], None);
    let tgs_req = kdc_req(12, &[0x05], &[0x0C], None);
    assert!(AsReq::decode(&as_req).is_ok());
    assert!(TgsReq::decode(&tgs_req).is_ok());
    assert_eq!(
        TgsReq::decode(&as_req),
        Err(Error::UnexpectedApplicationTag)
    );
    assert_eq!(
        AsReq::decode(&tgs_req),
        Err(Error::UnexpectedApplicationTag)
    );
}

#[test]
fn kdc_request_dispatch_rejects_other_tags() {
    // RFC 4120 5.1.4: an unrecognized / unexpected message tag is answered
    // with an error (KRB_AP_ERR_MSG_TYPE over TCP). An AP-REQ ([APPLICATION
    // 14]) is not a KDC request; a universal SEQUENCE is not a message.
    let (ticket, _) = tgt();
    let ap_req = app(
        14,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x0E])),
            &ctx(2, &flags32([0, 0, 0, 0])),
            &ctx(3, &ticket),
            &ctx(4, &enc_data_der(&[0x12], None, &[0x01])),
        ]),
    );
    assert!(ApReq::decode(&ap_req).is_ok());
    assert_eq!(
        KdcRequest::decode(&ap_req),
        Err(Error::UnexpectedApplicationTag)
    );
    assert_eq!(
        KdcRequest::decode(&pname_der(&[0x01], &["a"])),
        Err(Error::ExpectedApplicationTag)
    );
    // RFC 4120 5.1.5: a tag number > 30 ([APPLICATION 31], high-tag form
    // 7F 1F) is an unrecognized message — an error, not a crash.
    let inner = seq(&[]);
    let mut high = vec![0x7F, 0x1F, inner.len() as u8];
    high.extend_from_slice(&inner);
    assert_eq!(
        KdcRequest::decode(&high),
        Err(Error::UnexpectedApplicationTag)
    );
}

#[test]
fn ticket_requires_application_1() {
    // RFC 4120 5.3 / 5.10: Ticket ::= [APPLICATION 1] SEQUENCE. The bare
    // SEQUENCE (no application tag) and [APPLICATION 3] are rejected.
    let (der, _) = tgt();
    // Strip the 2-octet application header (length < 128 in this vector).
    assert_eq!(der[0], 0x61);
    let bare = der[2..].to_vec();
    assert_eq!(Ticket::decode(&bare), Err(Error::ExpectedApplicationTag));
    let mut wrong = der.clone();
    wrong[0] = 0x63;
    assert_eq!(Ticket::decode(&wrong), Err(Error::UnexpectedApplicationTag));
}

#[test]
fn enc_kdc_rep_part_tag_check_not_relaxed() {
    // RFC 4120 5.4.2 compatibility note: implementations MAY relax the check
    // on the EncASRepPart (25) / EncTGSRepPart (26) tag. Not taken: each type
    // accepts only its own tag (fail closed).
    let key: Vec<u8> = (0..32).collect();
    let inner = seq(&[
        &ctx(0, &seq(&[&ctx(0, &int(&[0x12])), &ctx(1, &octets(&key))])),
        &ctx(1, &seq(&[])),
        &ctx(2, &int(&[0x01])),
        &ctx(4, &flags32([0, 0, 0, 0])),
        &ctx(5, &gtime(b"20261113090000Z")),
        &ctx(7, &gtime(b"20261113190000Z")),
        &ctx(9, &gstring(b"EXAMPLE.ORG")),
        &ctx(10, &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"])),
    ]);
    assert!(EncAsRepPart::decode(&app(25, &inner)).is_ok());
    assert!(EncTgsRepPart::decode(&app(26, &inner)).is_ok());
    assert_eq!(
        EncAsRepPart::decode(&app(26, &inner)),
        Err(Error::UnexpectedApplicationTag)
    );
    assert_eq!(
        EncTgsRepPart::decode(&app(25, &inner)),
        Err(Error::UnexpectedApplicationTag)
    );
}

// ---------------------------------------------------------------------------
// pvno / msg-type — RFC 4120 5.2.4, 5.4.1, Appendix A
// ---------------------------------------------------------------------------

#[test]
fn rejects_wrong_pvno() {
    // RFC 4120 5.2.4: pvno / tkt-vno / authenticator-vno is always 5.
    assert_eq!(
        AsReq::decode(&kdc_req(10, &[0x04], &[0x0A], None)),
        Err(Error::InvalidPvno)
    );
    let (mut ticket, _) = tgt();
    // tkt-vno is the first INTEGER: 61 L 30 L A0 03 02 01 05 → patch the 05.
    assert_eq!(&ticket[4..9], &[0xA0, 0x03, 0x02, 0x01, 0x05]);
    ticket[8] = 0x06;
    assert_eq!(Ticket::decode(&ticket), Err(Error::InvalidPvno));
    let mut parts = authenticator_parts();
    parts[0] = ctx(0, &int(&[0x04]));
    assert_eq!(
        Authenticator::decode(&app(2, &body_from(&parts))),
        Err(Error::InvalidPvno)
    );
}

#[test]
fn rejects_wrong_msg_type() {
    // RFC 4120 Appendix A: KDC-REQ msg-type INTEGER (10 | 12). 13 is outside
    // the constraint; 12 inside an [APPLICATION 10] AS-REQ contradicts the
    // tag (5.4.1).
    assert_eq!(
        AsReq::decode(&kdc_req(10, &[0x05], &[0x0D], None)),
        Err(Error::InvalidMsgType)
    );
    assert_eq!(
        AsReq::decode(&kdc_req(10, &[0x05], &[0x0C], None)),
        Err(Error::MsgTypeMismatch)
    );
    assert_eq!(
        TgsReq::decode(&kdc_req(12, &[0x05], &[0x0A], None)),
        Err(Error::MsgTypeMismatch)
    );
    // KRB-ERROR msg-type INTEGER (30): 31 is rejected.
    let mut parts = krb_error_parts();
    parts[1] = ctx(1, &int(&[0x1F]));
    assert_eq!(
        KrbError::decode(&app(30, &body_from(&parts))),
        Err(Error::InvalidMsgType)
    );
}

// ---------------------------------------------------------------------------
// Components — X.690 8.9.2 / 8.9.3; RFC 4120 1.5.1, Appendix A
// ---------------------------------------------------------------------------

#[test]
fn rejects_missing_required_components() {
    // RFC 4120 5.4.1: till [5], nonce [7] and etype [8] are not OPTIONAL.
    for missing in [5u8, 7, 8] {
        let parts: Vec<Vec<u8>> = body_parts()
            .into_iter()
            .filter(|p| p[0] != (0xA0 | missing))
            .collect();
        assert_eq!(
            KdcReqBody::decode(&body_from(&parts)),
            Err(Error::MissingField),
            "missing [{missing}]"
        );
    }
    // RFC 4120 5.4.1: KDC-REQ req-body [4] is not OPTIONAL.
    let no_body = app(10, &seq(&[&ctx(1, &int(&[0x05])), &ctx(2, &int(&[0x0A]))]));
    assert_eq!(AsReq::decode(&no_body), Err(Error::MissingField));
    // RFC 4120 5.9.1: KRB-ERROR stime [4] is not OPTIONAL.
    let parts: Vec<Vec<u8>> = krb_error_parts()
        .into_iter()
        .filter(|p| p[0] != 0xA4)
        .collect();
    assert_eq!(
        KrbError::decode(&app(30, &body_from(&parts))),
        Err(Error::MissingField)
    );
}

#[test]
fn rejects_out_of_order_components() {
    // X.690 8.9.2/8.9.3: components in definition order. Swap till [5] and
    // nonce [7] in KDC-REQ-BODY.
    let mut parts = body_parts();
    parts.swap(3, 4);
    assert_eq!(
        KdcReqBody::decode(&body_from(&parts)),
        Err(Error::FieldOutOfOrder)
    );
    // Duplicate realm [2].
    let mut parts = body_parts();
    parts.insert(2, ctx(2, &gstring(b"EXAMPLE.ORG")));
    assert_eq!(
        KdcReqBody::decode(&body_from(&parts)),
        Err(Error::DuplicateField)
    );
}

#[test]
fn rejects_unknown_components() {
    // RFC 4120 5.4.1: KDC-REQ has no [0] ("first tag is [1], not [0]").
    let body = body_from(&body_parts());
    let with_zero = app(
        10,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x05])),
            &ctx(2, &int(&[0x0A])),
            &ctx(4, &body),
        ]),
    );
    assert_eq!(AsReq::decode(&with_zero), Err(Error::UnknownField));
    // RFC 4120 1.5.1 / Appendix A: KDC-REQ-BODY defines [0]..[11]; [12] is
    // not an extension point.
    let mut parts = body_parts();
    parts.push(ctx(12, &int(&[0x00])));
    assert_eq!(
        KdcReqBody::decode(&body_from(&parts)),
        Err(Error::UnknownField)
    );
    // RFC 4120 5.3: Ticket defines [0]..[3]; [4] is rejected.
    let (ticket, _) = tgt();
    let inner = &ticket[2..];
    let mut contents = inner[2..].to_vec();
    contents.extend_from_slice(&ctx(4, &int(&[0x00])));
    assert_eq!(
        Ticket::decode(&app(1, &tlv(0x30, &contents))),
        Err(Error::UnknownField)
    );
}

// ---------------------------------------------------------------------------
// Value constraints
// ---------------------------------------------------------------------------

#[test]
fn rejects_kerberos_flags_of_wrong_length() {
    // RFC 4120 5.2.8: KerberosFlags ::= BIT STRING (SIZE (32..MAX)); exactly
    // 32 bits accepted (fewer: "MAY accept" not taken; more: no defined use).
    assert!(EncTicketPart::decode(&enc_ticket_part_with_flags(&flags32([0, 0, 0, 0]))).is_ok());
    for bad in [
        tlv(0x03, &[0x00, 0x40, 0x00, 0x00]),             // 24 bits
        tlv(0x03, &[0x00, 0x40, 0x00, 0x00, 0x00, 0x00]), // 40 bits
        tlv(0x03, &[0x07, 0x40, 0x00, 0x00, 0x00, 0x80]), // 33 bits (7 unused)
        tlv(0x03, &[0x00]),                               // 0 bits
    ] {
        assert_eq!(
            EncTicketPart::decode(&enc_ticket_part_with_flags(&bad)),
            Err(Error::KerberosFlagsLength)
        );
    }
    assert_eq!(
        EncTicketPart::decode(&enc_ticket_part_with_flags(&octets(&[0, 0, 0, 0]))),
        Err(Error::ExpectedBitString)
    );
}

#[test]
fn rejects_fractional_time_in_messages() {
    // RFC 4120 5.2.3 inside KDC-REQ-BODY till [5].
    let mut parts = body_parts();
    parts[3] = ctx(5, &gtime(b"20261114000000.1Z"));
    assert_eq!(
        KdcReqBody::decode(&body_from(&parts)),
        Err(Error::FractionalKerberosTime)
    );
}

#[test]
fn rejects_out_of_range_integers_in_messages() {
    // RFC 4120 5.4.1 nonce [7] UInt32: 2^32 = 01 00 00 00 00.
    let mut parts = body_parts();
    parts[4] = ctx(7, &int(&[0x01, 0x00, 0x00, 0x00, 0x00]));
    assert_eq!(
        KdcReqBody::decode(&body_from(&parts)),
        Err(Error::UInt32OutOfRange)
    );
    // RFC 4120 5.4.1 etype [8] SEQUENCE OF Int32: 2^31 = 00 80 00 00 00.
    let mut parts = body_parts();
    parts[5] = ctx(8, &seq(&[&int(&[0x00, 0x80, 0x00, 0x00, 0x00])]));
    assert_eq!(
        KdcReqBody::decode(&body_from(&parts)),
        Err(Error::Int32OutOfRange)
    );
    // RFC 4120 5.5.1 cusec [4] Microseconds: 1000000 = 0F 42 40.
    let mut parts = authenticator_parts();
    parts[3] = ctx(4, &int(&[0x0F, 0x42, 0x40]));
    assert_eq!(
        Authenticator::decode(&app(2, &body_from(&parts))),
        Err(Error::MicrosecondsOutOfRange)
    );
    // RFC 4120 5.5.1 seq-number [7] UInt32: -1 = FF (the "MAY accept the
    // equivalent negative number" leniency is not taken).
    let mut parts = authenticator_parts();
    parts.push(ctx(7, &int(&[0xFF])));
    assert_eq!(
        Authenticator::decode(&app(2, &body_from(&parts))),
        Err(Error::UInt32OutOfRange)
    );
    // RFC 4120 5.9.1 susec [5] Microseconds: -1.
    let mut parts = krb_error_parts();
    parts[3] = ctx(5, &int(&[0xFF]));
    assert_eq!(
        KrbError::decode(&app(30, &body_from(&parts))),
        Err(Error::MicrosecondsOutOfRange)
    );
}

// ---------------------------------------------------------------------------
// Over-limit SEQUENCE OF — resource bounds (crate::limits)
// ---------------------------------------------------------------------------

#[test]
fn rejects_over_limit_padata() {
    // limits::MAX_PADATA on RFC 4120 5.4.1 padata.
    let pa = one_pa_data();
    let at: Vec<&[u8]> = vec![pa.as_slice(); limits::MAX_PADATA];
    let over: Vec<&[u8]> = vec![pa.as_slice(); limits::MAX_PADATA + 1];
    assert!(AsReq::decode(&kdc_req(10, &[0x05], &[0x0A], Some(&seq(&at)))).is_ok());
    assert_eq!(
        AsReq::decode(&kdc_req(10, &[0x05], &[0x0A], Some(&seq(&over)))),
        Err(Error::TooManyElements)
    );
    // Same bound on METHOD-DATA (RFC 4120 5.9.1).
    assert_eq!(MethodData::decode(&seq(&over)), Err(Error::TooManyElements));
}

#[test]
fn rejects_over_limit_etype_and_additional_tickets() {
    // limits::MAX_ETYPES on RFC 4120 5.4.1 etype [8].
    let one = int(&[0x12]);
    let over: Vec<&[u8]> = vec![one.as_slice(); limits::MAX_ETYPES + 1];
    let mut parts = body_parts();
    parts[5] = ctx(8, &seq(&over));
    assert_eq!(
        KdcReqBody::decode(&body_from(&parts)),
        Err(Error::TooManyElements)
    );
    // limits::MAX_ADDITIONAL_TICKETS on additional-tickets [11].
    let (ticket, _) = tgt();
    let over: Vec<&[u8]> = vec![ticket.as_slice(); limits::MAX_ADDITIONAL_TICKETS + 1];
    let mut parts = body_parts();
    parts.push(ctx(11, &seq(&over)));
    assert_eq!(
        KdcReqBody::decode(&body_from(&parts)),
        Err(Error::TooManyElements)
    );
}

#[test]
fn rejects_over_limit_last_req_and_etype_info2() {
    // limits::MAX_LAST_REQ on RFC 4120 5.4.2 LastReq.
    let entry = seq(&[&ctx(0, &int(&[0x00])), &ctx(1, &gtime(b"20261113090000Z"))]);
    let over: Vec<&[u8]> = vec![entry.as_slice(); limits::MAX_LAST_REQ + 1];
    assert_eq!(LastReq::decode(&seq(&over)), Err(Error::TooManyElements));
    // limits::MAX_ETYPE_INFO2_ENTRIES on RFC 4120 5.2.7.5 ETYPE-INFO2.
    let entry = seq(&[&ctx(0, &int(&[0x12]))]);
    let over: Vec<&[u8]> = vec![entry.as_slice(); limits::MAX_ETYPE_INFO2_ENTRIES + 1];
    assert_eq!(EtypeInfo2::decode(&seq(&over)), Err(Error::TooManyElements));
}

#[test]
fn rejects_empty_etype_info2() {
    // RFC 4120 5.2.7.5: ETYPE-INFO2 ::= SEQUENCE SIZE (1..MAX) OF ... — empty
    // is invalid on decode and on encode.
    assert_eq!(
        EtypeInfo2::decode(&[0x30, 0x00]),
        Err(Error::EmptySequenceOf)
    );
    assert_eq!(EtypeInfo2(vec![]).encode(), Err(Error::EmptySequenceOf));
}

// ---------------------------------------------------------------------------
// Framing — X.690 8.1, 8.14.3 (via parse-asn1)
// ---------------------------------------------------------------------------

#[test]
fn rejects_trailing_data() {
    // Strict framing: nothing after the top-level message …
    let mut bytes = kdc_req(10, &[0x05], &[0x0A], None);
    bytes.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(
        AsReq::decode(&bytes),
        Err(Error::Der(parse_asn1::Error::TrailingData))
    );
    // … nor after the single value inside an explicit tag (X.690 8.14.3).
    let mut parts = body_parts();
    parts[4] = ctx(7, &cat(&[&int(&[0x01]), &int(&[0x02])]));
    assert_eq!(
        KdcReqBody::decode(&body_from(&parts)),
        Err(Error::Der(parse_asn1::Error::TrailingData))
    );
}

#[test]
fn rejects_truncated_message() {
    // X.690 8.1.3.3: the declared length must be present.
    let bytes = kdc_req(10, &[0x05], &[0x0A], None);
    let truncated = &bytes[..bytes.len() - 1];
    assert_eq!(
        AsReq::decode(truncated),
        Err(Error::Der(parse_asn1::Error::LengthExceedsInput))
    );
    assert!(AsReq::decode(&[]).is_err());
}

#[test]
fn rejects_wrong_reply_type_for_message() {
    // RFC 4120 5.10: a KDC-REP needs [APPLICATION 11] / [13]; an AS-REQ is
    // not an AS-REP.
    assert_eq!(
        AsRep::decode(&kdc_req(10, &[0x05], &[0x0A], None)),
        Err(Error::UnexpectedApplicationTag)
    );
}
