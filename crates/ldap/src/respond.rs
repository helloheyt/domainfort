//! Building the canonical response messages.
//!
//! Every response is encoded by parse-ldap's canonical encoder (docs/49 §11:
//! the codec lives in parse-ldap). Every LDAPResult the engine sends has an
//! empty matchedDN and an empty diagnosticMessage (R49-13; RFC 4511 §4.1.9:
//! "If the server chooses not to return a textual diagnostic, the
//! diagnosticMessage field MUST be empty").
//!
//! # The responses to Modify / Add / Delete / ModifyDN / Compare
//!
//! parse-ldap recognises these requests by tag only and models no typed
//! response for them (A-52, docs/questions/Q-185 item 6 — it offers
//! `UnsupportedOp::response_tag_number`). Their responses are all
//! `[APPLICATION n] LDAPResult` (RFC 4511 §4.6-§4.10, App. B:
//! ModifyResponse 7, AddResponse 9, DelResponse 11, ModifyDNResponse 13,
//! CompareResponse 15), exactly like `SearchResultDone ::= [APPLICATION 5]
//! LDAPResult` (§4.5.2). Under implicit tagging the contents octets are
//! those of the base encoding (X.690 8.14.4 b)) and the form is that of the
//! base type — constructed, LDAPResult being a SEQUENCE (8.14.4 a)). So the
//! encodings differ only in the identifier octet of the protocolOp: the
//! engine encodes a SearchResultDone with parse-ldap and replaces that one
//! octet, after checking it is the SearchResultDone identifier where the
//! canonical encoding puts it. Follow-up (docs/questions/Q-190 item 1): a
//! typed response in parse-ldap would remove this octet step.
//!
//! Spec: RFC 4511 §4.1.1, §4.1.9, §4.4.1, §4.5.2, §4.6-§4.10, §4.12, App. B;
//! X.690 (02/2021) 8.1.2.2, 8.1.2.5, 8.1.3.4, 8.1.3.5, 8.14.4; X.680
//! (02/2021) Table 1; docs/49 §9 (R49-13), §11.

use parse_ldap::{
    encode_message, BindResponse, ExtendedResponse, LdapMessage, LdapResult, MessageId, ProtocolOp,
    ResultCode, SearchResultEntry, UnsupportedOp, START_TLS_OID,
};

/// The encoder refused a value (cannot happen for what the engine builds;
/// the caller fails closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncodeFailure;

/// Which response answers a request. Spec: RFC 4511 §4.1.1 (each request's
/// response), App. B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseKind {
    /// BindResponse. Spec: RFC 4511 §4.2.2.
    Bind,
    /// SearchResultDone. Spec: RFC 4511 §4.5.2.
    SearchDone,
    /// ExtendedResponse to StartTLS: responseName is the StartTLS OID.
    /// Spec: RFC 4511 §4.14.2 ("The responseName is
    /// '1.3.6.1.4.1.1466.20037' when provided").
    StartTls,
    /// ExtendedResponse to an unrecognised requestName: no responseName.
    /// Spec: RFC 4511 §4.12 ("The field will be absent ... when the
    /// requestName ... is not recognized").
    ExtendedUnrecognized,
    /// The `[APPLICATION n] LDAPResult` response of an operation phase 1
    /// does not perform. Spec: RFC 4511 §4.6-§4.10; A-48.
    NotSupported(UnsupportedOp),
}

/// `LDAPMessage { messageID, <kind> LDAPResult(code, "", "") }`.
/// Spec: RFC 4511 §4.1.1, §4.1.9; R49-13.
pub(crate) fn result(
    message_id: MessageId,
    kind: ResponseKind,
    code: ResultCode,
) -> Result<Vec<u8>, EncodeFailure> {
    let result = LdapResult::new(code);
    let protocol_op = match kind {
        ResponseKind::Bind => ProtocolOp::BindResponse(BindResponse {
            result,
            // "If the client bound with the simple choice, or the SASL
            // mechanism does not require the server to return information
            // to the client, then this field SHALL NOT be included".
            // Spec: RFC 4511 §4.2.2.
            server_sasl_creds: None,
        }),
        ResponseKind::SearchDone => ProtocolOp::SearchResultDone(result),
        ResponseKind::StartTls => ProtocolOp::ExtendedResponse(ExtendedResponse {
            result,
            response_name: Some(START_TLS_OID.to_owned()),
            // "The responseValue is always absent." Spec: RFC 4511 §4.14.2.
            response_value: None,
        }),
        ResponseKind::ExtendedUnrecognized => ProtocolOp::ExtendedResponse(ExtendedResponse {
            result,
            response_name: None,
            response_value: None,
        }),
        ResponseKind::NotSupported(op) => {
            return ldap_result_response(message_id, op.response_tag_number(), result)
        }
    };
    encode(&LdapMessage {
        message_id,
        protocol_op,
        controls: None,
    })
}

/// A SearchResultEntry. Spec: RFC 4511 §4.5.2.
pub(crate) fn entry(
    message_id: MessageId,
    entry: SearchResultEntry,
) -> Result<Vec<u8>, EncodeFailure> {
    encode(&LdapMessage {
        message_id,
        protocol_op: ProtocolOp::SearchResultEntry(entry),
        controls: None,
    })
}

/// The Notice of Disconnection with `code` (MessageID zero, responseName
/// 1.3.6.1.4.1.1466.20036, no responseValue). Spec: RFC 4511 §4.4,
/// §4.4.1; [MS-ADTS] 5.1.1.6.
pub(crate) fn notice(code: ResultCode) -> Result<Vec<u8>, EncodeFailure> {
    encode(&LdapMessage::notice_of_disconnection(code))
}

fn encode(message: &LdapMessage) -> Result<Vec<u8>, EncodeFailure> {
    encode_message(message).map_err(|_| EncodeFailure)
}

/// Identifier octet of a constructed APPLICATION-class element with a tag
/// number in 0..=30: bits 8-7 = `01` (Application), bit 6 = 1
/// (constructed), bits 5-1 = the number. Spec: X.690 8.1.2.2 (Table 1),
/// 8.1.2.5.
const fn application_constructed(number: u8) -> u8 {
    0b0110_0000 | (number & 0b0001_1111)
}

/// Highest tag number of the single-octet identifier form. Spec: X.690
/// 8.1.2.2.
const MAX_LOW_TAG_NUMBER: u8 = 30;

/// `SEQUENCE` (UNIVERSAL 16, constructed): bits 8-7 = `00`, bit 6 = 1.
/// Spec: X.680 Table 1; X.690 8.1.2.2, 8.1.2.5, 8.9.1.
const SEQUENCE_IDENTIFIER: u8 = 0b0011_0000;

/// `INTEGER` (UNIVERSAL 2, primitive). Spec: X.680 Table 1; X.690 8.1.2.2,
/// 8.3.1.
const INTEGER_IDENTIFIER: u8 = 0b0000_0010;

/// `LDAPMessage { messageID, [APPLICATION tag_number] LDAPResult }` (module
/// documentation). Spec: RFC 4511 §4.6-§4.10, App. B; X.690 8.14.4.
fn ldap_result_response(
    message_id: MessageId,
    tag_number: u8,
    result: LdapResult,
) -> Result<Vec<u8>, EncodeFailure> {
    if tag_number > MAX_LOW_TAG_NUMBER {
        return Err(EncodeFailure);
    }
    let mut octets = encode(&LdapMessage {
        message_id,
        protocol_op: ProtocolOp::SearchResultDone(result),
        controls: None,
    })?;
    let at = protocol_op_offset(&octets).ok_or(EncodeFailure)?;
    let identifier = octets.get_mut(at).ok_or(EncodeFailure)?;
    // "SearchResultDone ::= [APPLICATION 5] LDAPResult". Spec: RFC 4511
    // §4.5.2.
    if *identifier != application_constructed(5) {
        return Err(EncodeFailure);
    }
    *identifier = application_constructed(tag_number);
    Ok(octets)
}

/// The offset of the protocolOp identifier in a canonical LDAPMessage: after
/// the outer SEQUENCE identifier and length octets and the whole messageID
/// INTEGER element. Spec: RFC 4511 §4.1.1 ("LDAPMessage ::= SEQUENCE {
/// messageID MessageID, protocolOp CHOICE ..."); X.690 8.1.3.4, 8.1.3.5.
pub(crate) fn protocol_op_offset(octets: &[u8]) -> Option<usize> {
    if *octets.first()? != SEQUENCE_IDENTIFIER {
        return None;
    }
    let (_, id_at) = length_at(octets, 1)?;
    if *octets.get(id_at)? != INTEGER_IDENTIFIER {
        return None;
    }
    let (id_len, id_contents) = length_at(octets, id_at.checked_add(1)?)?;
    id_contents.checked_add(id_len)
}

/// Read the length octets starting at `at`: `(length, offset of the
/// contents)`. Short form: one octet with bit 8 zero; long form: an initial
/// octet with bit 8 one and bits 7-1 the count of subsequent octets (never
/// `0xFF`). Spec: X.690 8.1.3.4, 8.1.3.5.
fn length_at(octets: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *octets.get(at)?;
    let next = at.checked_add(1)?;
    if first & 0x80 == 0 {
        return Some((usize::from(first), next));
    }
    let count = usize::from(first & 0x7F);
    // 8.1.3.5 c): "the value 11111111 shall not be used"; a usize holds at
    // most 8 length octets.
    if first == 0xFF || count == 0 || count > core::mem::size_of::<usize>() {
        return None;
    }
    let mut length = 0usize;
    for i in 0..count {
        let b = *octets.get(next.checked_add(i)?)?;
        length = length.checked_mul(256)?.checked_add(usize::from(b))?;
    }
    Some((length, next.checked_add(count)?))
}
