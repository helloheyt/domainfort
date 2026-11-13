//! The refusal paths: unsupported operations, controls, malformed input,
//! Unbind and Abandon (docs/49 §5, §9).
//!
//! Sources (each test names its own): RFC 4511 §4.1.1, §4.1.11, §4.3,
//! §4.4.1, §4.6-§4.11, §5.1, App. B; X.690 (02/2021) 8.1.3.4, 8.1.3.5, 10.1;
//! [MS-ADTS] 3.1.1.3.4.1 (control OIDs), 3.1.1.3.4.6; docs/49 §2.4, §5.1,
//! §5.3, §8.1, §9, §11 (R49-16); A-48; A-52. Hand-made requests and octets.

mod common;

use common::*;
use ldap::{AuditOperation, AuditReason, ConnectionAction, Listener};
use parse_ldap::{
    encode_message, LdapMessage, ProtocolOp, ResultCode, UnsupportedOp, NOTICE_OF_DISCONNECTION_OID,
};

/// Assert `outcome` is exactly a Notice of Disconnection with `code` and a
/// close. Spec: RFC 4511 §4.4.1 (MessageID zero, responseName
/// 1.3.6.1.4.1.1466.20036, no responseValue).
fn assert_notice(outcome: &ldap::Outcome, code: ResultCode) {
    let msg = only_response(outcome);
    assert_eq!(msg.message_id.get(), 0);
    match msg.protocol_op {
        ProtocolOp::ExtendedResponse(e) => {
            assert_eq!(e.result.result_code, code);
            assert_eq!(
                e.response_name.as_deref(),
                Some(NOTICE_OF_DISCONNECTION_OID)
            );
            assert_eq!(e.response_value, None);
        }
        other => panic!("not a Notice of Disconnection: {other:?}"),
    }
    assert_eq!(outcome.action, ConnectionAction::Close);
    assert_eq!(outcome.audit.notice, Some(code));
}

/// A-48 / docs/49 §5.1, §8.1 / Q-167: Modify, Add, Delete, ModifyDN and
/// Compare are refused with unwillingToPerform in the matching response —
/// ModifyResponse [APPLICATION 7], AddResponse 9, DelResponse 11,
/// ModifyDNResponse 13, CompareResponse 15 (RFC 4511 §4.6-§4.10, App. B).
#[test]
fn unsupported_operations_are_unwilling_to_perform_with_the_matching_tag() {
    let cases = [
        (UnsupportedOp::ModifyRequest, 7),
        (UnsupportedOp::AddRequest, 9),
        (UnsupportedOp::DelRequest, 11),
        (UnsupportedOp::ModifyDnRequest, 13),
        (UnsupportedOp::CompareRequest, 15),
    ];
    for (op, tag) in cases {
        for (listener, transport) in [(Listener::Ldap, cleartext()), (Listener::Ldaps, tls())] {
            let mut h = Harness::new(listener);
            let outcome = h.send(&unsupported(40, op), transport);
            assert_eq!(outcome.responses.len(), 1);
            let msg = decode_ldap_result_response(&outcome.responses[0], tag);
            assert_eq!(msg.message_id, id(40));
            match msg.protocol_op {
                ProtocolOp::SearchResultDone(r) => {
                    assert_eq!(r.result_code, ResultCode::UnwillingToPerform);
                }
                other => panic!("unexpected: {other:?}"),
            }
            assert_eq!(outcome.action, ConnectionAction::Continue);
            assert_eq!(outcome.audit.operation, AuditOperation::NotSupported(op));
            assert_eq!(outcome.audit.reason, AuditReason::OperationNotSupported);
            assert_eq!(
                outcome.audit.result_code,
                Some(ResultCode::UnwillingToPerform)
            );
        }
    }
}

/// RFC 4511 §4.1.11: a critical control the server does not recognise — and
/// phase 1 recognises none (docs/49 §5.3, R49-8) — "MUST NOT perform the
/// operation ... MUST return with the resultCode set to
/// unavailableCriticalExtension", in the operation's own response. Control
/// OIDs from [MS-ADTS] 3.1.1.3.4.1 and a made-up one.
#[test]
fn a_critical_control_is_unavailable_critical_extension() {
    let critical = vec![
        control("1.2.840.113556.1.4.319", false),
        control("1.2.840.113556.1.4.801", true),
    ];
    // Search (the rootDSE would otherwise be returned).
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(
        &with_controls(root_dse_search(1, &[]), critical.clone()),
        cleartext(),
    );
    match only_response(&outcome).protocol_op {
        ProtocolOp::SearchResultDone(r) => {
            assert_eq!(r.result_code, ResultCode::UnavailableCriticalExtension);
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert_eq!(
        outcome.audit.reason,
        AuditReason::UnavailableCriticalControl
    );
    assert_eq!(h.rate.calls, 0, "the operation was not performed");

    // Bind.
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(
        &with_controls(simple_bind(2, "", true), critical.clone()),
        cleartext(),
    );
    assert!(matches!(
        only_response(&outcome).protocol_op,
        ProtocolOp::BindResponse(ref b) if b.result.result_code == ResultCode::UnavailableCriticalExtension
    ));

    // StartTLS: not performed, no TLS.
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(&with_controls(start_tls(3), critical.clone()), cleartext());
    assert_eq!(
        only_code(&outcome),
        ResultCode::UnavailableCriticalExtension
    );
    assert_eq!(outcome.action, ConnectionAction::Continue);
    assert!(!h.session.start_tls_pending());

    // An unsupported operation: its own response tag.
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(
        &with_controls(unsupported(4, UnsupportedOp::DelRequest), critical),
        cleartext(),
    );
    let msg = decode_ldap_result_response(&outcome.responses[0], 11);
    assert!(matches!(
        msg.protocol_op,
        ProtocolOp::SearchResultDone(ref r) if r.result_code == ResultCode::UnavailableCriticalExtension
    ));
}

/// RFC 4511 §4.1.11: a non-critical control the server does not recognise
/// "MUST" be ignored — the rootDSE is returned as without it.
#[test]
fn non_critical_controls_are_ignored() {
    let mut h = Harness::new(Listener::Ldap);
    let msg = with_controls(
        root_dse_search(5, &[]),
        vec![
            control("1.2.840.113556.1.4.319", false),
            control("1.2.840.113556.1.4.529", false),
            control("9.9.9", false),
        ],
    );
    let outcome = h.send(&msg, cleartext());
    assert_eq!(outcome.responses.len(), 2);
    assert_eq!(outcome.audit.reason, AuditReason::RootDseReturned);

    // Present but empty Controls: the same.
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(&with_controls(root_dse_search(6, &[]), vec![]), cleartext());
    assert_eq!(outcome.responses.len(), 2);
}

/// RFC 4511 §4.1.11: for the UnbindRequest the criticality "MUST be
/// ignored" — a critical control does not stop the Unbind.
#[test]
fn unbind_ignores_critical_controls() {
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(
        &with_controls(unbind(7), vec![control("1.2.3", true)]),
        cleartext(),
    );
    assert!(outcome.responses.is_empty());
    assert_eq!(outcome.action, ConnectionAction::Close);
    assert_eq!(outcome.audit.reason, AuditReason::Unbind);
}

/// RFC 4511 §4.3 (the server, upon receipt of the UnbindRequest, terminates
/// the session; there is no response); [MS-ADTS] 3.1.1.3.1.12 ("the Active
/// Directory DC closes the connection"). Afterwards nothing is processed
/// (RFC 4511 §5.3).
#[test]
fn unbind_closes_without_a_response() {
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(&unbind(8), cleartext());
    assert!(outcome.responses.is_empty());
    assert_eq!(outcome.action, ConnectionAction::Close);
    assert_eq!(outcome.audit.result_code, None);
    assert_eq!(outcome.audit.notice, None);
    assert!(h.session.is_closed());

    let after = h.send(&root_dse_search(9, &[]), cleartext());
    assert!(after.responses.is_empty());
    assert_eq!(after.action, ConnectionAction::Close);
    assert_eq!(after.audit.operation, AuditOperation::NotDecoded);
    assert_eq!(after.audit.reason, AuditReason::SessionClosed);
}

/// RFC 4511 §4.11: "There is no response defined in the Abandon operation";
/// "Servers MUST discard Abandon requests for messageIDs they do not
/// recognize". The session continues.
#[test]
fn abandon_is_silent() {
    for target in [1, 9, 2_147_483_647] {
        let mut h = Harness::new(Listener::Ldap);
        let outcome = h.send(&abandon(10, target), cleartext());
        assert!(outcome.responses.is_empty());
        assert_eq!(outcome.action, ConnectionAction::Continue);
        assert_eq!(outcome.audit.reason, AuditReason::Abandon);
        assert_eq!(outcome.audit.operation, AuditOperation::Abandon);
        assert!(!h.session.is_closed());
    }
}

/// R49-16 (the engine accepts only the canonical profile) and RFC 4511
/// §4.1.1 (incorrect encoding → Notice of Disconnection with protocolError,
/// then terminate): a valid BER encoding with a non-minimal long-form length
/// (X.690 8.1.3.5 instead of the short form of 8.1.3.4 / 10.1) is refused.
#[test]
fn a_non_canonical_message_is_protocol_error_and_close() {
    let canonical = encode_message(&root_dse_search(11, &[])).expect("encodes");
    assert!(canonical[1] < 0x80);
    let mut long_form = vec![canonical[0], 0x81];
    long_form.extend_from_slice(&canonical[1..]);
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send_octets(&long_form, cleartext());
    assert_notice(&outcome, ResultCode::ProtocolError);
    assert_eq!(outcome.audit.operation, AuditOperation::Malformed);
    assert!(matches!(outcome.audit.reason, AuditReason::Malformed(_)));
    assert_eq!(outcome.audit.message_id, None);
    assert!(h.session.is_closed());
}

/// RFC 4511 §4.1.1: truncated octets, a wrong outer tag, a response
/// operation sent as a request, trailing octets — all Notice of
/// Disconnection (protocolError) and close.
#[test]
fn undecodable_messages_are_protocol_error_and_close() {
    let done = message(
        12,
        ProtocolOp::SearchResultDone(parse_ldap::LdapResult::new(ResultCode::Success)),
    );
    let mut with_trailer = encode_message(&root_dse_search(12, &[])).expect("encodes");
    with_trailer.push(0x00);
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x30, 0x05, 0x02, 0x01],
        vec![0x31, 0x03, 0x02, 0x01, 0x01],
        encode_message(&done).expect("encodes"),
        with_trailer,
    ];
    for octets in cases {
        let mut h = Harness::new(Listener::Ldap);
        let outcome = h.send_octets(&octets, cleartext());
        assert_notice(&outcome, ResultCode::ProtocolError);
    }
}

/// A-52 / docs/49 §2.3: simple-bind password octets never reach the engine —
/// the canonical profile carries only an empty password or the one-octet
/// placeholder. A front that forwards the real password is refused like any
/// non-canonical input. Octets built by hand from RFC 4511 App. B:
/// LDAPMessage { 1, BindRequest { 3, "cn=x", simple "secret" } }.
#[test]
fn password_octets_from_the_front_are_refused() {
    let octets: Vec<u8> = vec![
        0x30, 0x16, // LDAPMessage SEQUENCE, 22 octets
        0x02, 0x01, 0x01, // messageID 1
        0x60, 0x11, // [APPLICATION 0] BindRequest, 17 octets
        0x02, 0x01, 0x03, // version 3
        0x04, 0x04, b'c', b'n', b'=', b'x', // name
        0x80, 0x06, b's', b'e', b'c', b'r', b'e', b't', // simple [0] "secret"
    ];
    let mut h = Harness::new(Listener::Ldaps);
    let outcome = h.send_octets(&octets, tls());
    assert_notice(&outcome, ResultCode::ProtocolError);
    assert!(!format!("{outcome:?}").contains("secret"));
    assert_eq!(h.accounts.calls.get(), 0);
}

/// [MS-ADTS] 3.1.1.3.4.6 ("If the server receives a request that is larger
/// than this, it will drop the connection"); docs/49 §2.4, §9: more than the
/// unauthenticated bound → close with no response.
#[test]
fn an_oversized_message_is_dropped_without_a_response() {
    let mut octets = vec![0x30, 0x83, 0x01, 0x10, 0x00];
    octets.resize(parse_ldap::MAX_PREAUTH_MESSAGE_OCTETS + 1, 0);
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send_octets(&octets, cleartext());
    assert!(outcome.responses.is_empty());
    assert_eq!(outcome.action, ConnectionAction::Close);
    assert_eq!(outcome.audit.reason, AuditReason::Oversized);
}

/// R49-13: every response the engine sends has empty matchedDN and
/// diagnosticMessage (checked by `decode` on every response of a mixed
/// session).
#[test]
fn every_response_has_empty_matched_dn_and_diagnostic_message() {
    let mut h = Harness::new(Listener::Ldap);
    let script: Vec<LdapMessage> = vec![
        simple_bind(1, "CN=x", false),
        simple_bind(2, "CN=x", true),
        sasl_bind(3, "GSSAPI", None),
        root_dse_search(4, &[]),
        search(
            5,
            "DC=example,DC=org",
            parse_ldap::Scope::WholeSubtree,
            object_class_present(),
            &[],
        ),
        extended(6, "1.2.3.4", None),
    ];
    for msg in &script {
        let outcome = h.send(msg, cleartext());
        for octets in &outcome.responses {
            decode(octets);
        }
    }
}
