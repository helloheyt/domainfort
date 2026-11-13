//! Building the canonical response messages.
//!
//! Every response is encoded by parse-ldap's canonical encoder (docs/49 §11:
//! the codec lives in parse-ldap). Every LDAPResult the engine sends has an
//! empty matchedDN and an empty diagnosticMessage (R49-13; RFC 4511 §4.1.9:
//! "If the server chooses not to return a textual diagnostic, the
//! diagnosticMessage field MUST be empty").
//!
//! The responses to Modify / Add / Delete / ModifyDN / Compare are
//! parse-ldap's typed `ProtocolOp::UnsupportedResponse` (`[APPLICATION n]
//! LDAPResult`, RFC 4511 §4.6-§4.10, App. B): the engine no longer touches
//! encoded octets (docs/questions/Q-190 item 1, A-54).
//!
//! Spec: RFC 4511 §4.1.1, §4.1.9, §4.4.1, §4.5.2, §4.6-§4.10, §4.12, App. B;
//! docs/49 §9 (R49-13), §11; Q-190 item 1 (A-54).

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
        // ModifyResponse 7, AddResponse 9, DelResponse 11, ModifyDNResponse
        // 13, CompareResponse 15. Spec: RFC 4511 App. B; Q-190 item 1.
        ResponseKind::NotSupported(op) => ProtocolOp::UnsupportedResponse { op, result },
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
