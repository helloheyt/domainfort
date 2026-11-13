//! StartTLS sequencing and the transport state (docs/49 §4.4, R49-15).
//!
//! Sources (each test names its own): RFC 4511 §4.12, §4.14.1, §4.14.2,
//! §4.14.3, A.2; RFC 4513 §3.1.1; [MS-ADTS] 3.1.1.3.4.2 (the extended
//! operation OIDs); docs/49 §4.4. Hand-made requests.

mod common;

use common::*;
use ldap::{AuditOperation, AuditReason, AuditTransport, ConnectionAction, Listener};
use parse_ldap::{ProtocolOp, ResultCode, START_TLS_OID};
use pdp::{IpScope, TransportSec};

/// The StartTLS ExtendedResponse: responseName is the StartTLS OID and
/// responseValue is absent. Spec: RFC 4511 §4.14.2.
fn start_tls_code(outcome: &ldap::Outcome) -> ResultCode {
    match only_response(outcome).protocol_op {
        ProtocolOp::ExtendedResponse(e) => {
            assert_eq!(e.response_name.as_deref(), Some(START_TLS_OID));
            assert_eq!(e.response_value, None);
            e.result.result_code
        }
        other => panic!("not an ExtendedResponse: {other:?}"),
    }
}

/// RFC 4511 §4.14.2 ("returns the StartTLS response with the resultCode set
/// to success"); docs/49 §4.4: the front installs TLS, and the next request
/// arrives over it — the session's channel becomes StartTLS.
#[test]
fn start_tls_succeeds_and_the_next_request_runs_over_tls() {
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(&start_tls(1), cleartext());
    assert_eq!(start_tls_code(&outcome), ResultCode::Success);
    assert_eq!(outcome.action, ConnectionAction::StartTls);
    assert_eq!(outcome.audit.reason, AuditReason::StartTlsAccepted);
    assert_eq!(outcome.audit.transport, AuditTransport::Ldap);
    assert!(h.session.start_tls_pending());
    assert!(!h.session.tls_established());

    let next = h.send(&root_dse_search(2, &[]), tls());
    assert_eq!(next.action, ConnectionAction::Continue);
    assert_eq!(next.responses.len(), 2);
    assert_eq!(next.audit.transport, AuditTransport::StartTls);
    // An anonymous session over TLS: encrypted only (docs/49 §4.3).
    assert_eq!(
        next.audit.transport_sec,
        TransportSec {
            encrypted: true,
            sealed: false,
            channel_bound: false
        }
    );
    assert!(h.session.tls_established());
    assert!(!h.session.start_tls_pending());
}

/// RFC 4513 §3.1.1 (not "when TLS is currently established on the
/// session"); RFC 4511 §4.14.1, A.2 (operationsError "if a TLS layer was
/// already installed"): on LDAPS and after a completed StartTLS.
#[test]
fn start_tls_on_an_established_tls_layer_is_operations_error() {
    let mut ldaps = Harness::new(Listener::Ldaps);
    let outcome = ldaps.send(&start_tls(1), tls());
    assert_eq!(start_tls_code(&outcome), ResultCode::OperationsError);
    assert_eq!(outcome.action, ConnectionAction::Continue);
    assert_eq!(outcome.audit.reason, AuditReason::TlsAlreadyEstablished);

    let mut upgraded = Harness::new(Listener::Ldap);
    upgraded.send(&start_tls(1), cleartext());
    let again = upgraded.send(&start_tls(2), tls());
    assert_eq!(start_tls_code(&again), ResultCode::OperationsError);
    assert_eq!(again.action, ConnectionAction::Continue);
}

/// RFC 4513 §3.1.1 (not "when there are outstanding responses for operation
/// requests previously issued"); RFC 4511 §4.14.1 ("The client MUST NOT send
/// any LDAP PDUs ... following this request until it receives a StartTLS
/// Extended response"): operationsError, and the connection closes so the
/// cleartext octets are never processed (docs/49 §4.4).
#[test]
fn start_tls_with_outstanding_input_is_operations_error_and_closes() {
    let mut h = Harness::new(Listener::Ldap);
    let mut transport = cleartext();
    transport.input_pending = true;
    let outcome = h.send(&start_tls(1), transport);
    assert_eq!(start_tls_code(&outcome), ResultCode::OperationsError);
    assert_eq!(outcome.action, ConnectionAction::Close);
    assert_eq!(outcome.audit.reason, AuditReason::StartTlsWithPendingInput);
    assert!(h.session.is_closed());
    assert!(!h.session.tls_established());
}

/// docs/49 §4.4 (R49-15) and RFC 4511 §4.14.1: a request that reaches the
/// engine after a successful StartTLS response but in cleartext closes the
/// connection, without a response — whatever the request.
#[test]
fn a_request_while_start_tls_is_pending_closes() {
    for msg in [
        root_dse_search(2, &[]),
        simple_bind(2, "", true),
        unbind(2),
        abandon(2, 1),
        start_tls(2),
    ] {
        let mut h = Harness::new(Listener::Ldap);
        h.send(&start_tls(1), cleartext());
        let outcome = h.send(&msg, cleartext());
        assert!(outcome.responses.is_empty());
        assert_eq!(outcome.action, ConnectionAction::Close);
        assert_eq!(outcome.audit.reason, AuditReason::RequestDuringStartTls);
        assert!(h.session.is_closed());
    }
}

/// docs/49 §4.4 (injection protection): cleartext octets after a successful
/// StartTLS response are never parsed — even garbage closes silently, with
/// no Notice of Disconnection (which a malformed message would otherwise
/// get, RFC 4511 §4.1.1).
#[test]
fn cleartext_octets_while_start_tls_is_pending_are_not_decoded() {
    let mut h = Harness::new(Listener::Ldap);
    h.send(&start_tls(1), cleartext());
    let outcome = h.send_octets(&[0x30, 0x02, 0xFF], cleartext());
    assert!(outcome.responses.is_empty());
    assert_eq!(outcome.action, ConnectionAction::Close);
    assert_eq!(outcome.audit.operation, AuditOperation::NotDecoded);
    assert_eq!(outcome.audit.message_id, None);
    assert_eq!(outcome.audit.reason, AuditReason::RequestDuringStartTls);
}

/// RFC 4511 §4.14.1: "the requestValue field is always absent"; §4.12 ("The
/// server may return protocolError in other cases").
#[test]
fn start_tls_with_a_request_value_is_protocol_error() {
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(&extended(1, START_TLS_OID, Some(vec![0])), cleartext());
    assert_eq!(start_tls_code(&outcome), ResultCode::ProtocolError);
    assert_eq!(outcome.action, ConnectionAction::Continue);
    assert!(!h.session.start_tls_pending());
}

/// RFC 4511 §4.12: "Where the requestName is not recognized, the server
/// returns protocolError", with no responseName; the OIDs of [MS-ADTS]
/// 3.1.1.3.4.2 other than StartTLS have no code path (docs/49 §5.1).
#[test]
fn other_extended_operations_are_protocol_error() {
    for oid in [
        "1.2.840.113556.1.4.1781",
        "1.3.6.1.4.1.1466.101.119.1",
        "1.3.6.1.4.1.4203.1.11.3",
        "1.2.840.113556.1.4.2212",
        "1.3.6.1.4.1.1466.20036",
    ] {
        let mut h = Harness::new(Listener::Ldaps);
        let outcome = h.send(&extended(1, oid, None), tls());
        match only_response(&outcome).protocol_op {
            ProtocolOp::ExtendedResponse(e) => {
                assert_eq!(e.result.result_code, ResultCode::ProtocolError, "{oid}");
                assert_eq!(e.response_name, None);
                assert_eq!(e.response_value, None);
            }
            other => panic!("not an ExtendedResponse: {other:?}"),
        }
        assert_eq!(
            outcome.audit.reason,
            AuditReason::ExtendedOperationUnrecognized
        );
        assert_eq!(outcome.action, ConnectionAction::Continue);
    }
}

/// docs/49 §4.4: the TLS state changes only through LDAPS or StartTLS; a
/// front report that disagrees — TLS claimed on a cleartext session, or TLS
/// gone from a TLS session (RFC 4511 §4.14.3; "always close") — closes.
#[test]
fn a_transport_report_that_disagrees_with_the_session_closes() {
    let mut cleartext_session = Harness::new(Listener::Ldap);
    let outcome = cleartext_session.send(&root_dse_search(1, &[]), tls());
    assert!(outcome.responses.is_empty());
    assert_eq!(outcome.action, ConnectionAction::Close);
    assert_eq!(outcome.audit.reason, AuditReason::TransportMismatch);

    let mut ldaps = Harness::new(Listener::Ldaps);
    let outcome = ldaps.send(&root_dse_search(1, &[]), report(IpScope::Internal, false));
    assert!(outcome.responses.is_empty());
    assert_eq!(outcome.action, ConnectionAction::Close);
    assert_eq!(outcome.audit.reason, AuditReason::TransportMismatch);
}
