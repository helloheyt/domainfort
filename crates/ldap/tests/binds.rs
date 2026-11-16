//! Every bind path and its result code (docs/49 §3.1, R49-4).
//!
//! Sources (each test names its own): RFC 4511 §4.2, §4.2.1, §4.2.2;
//! RFC 4513 §4, §5.1.1, §5.1.2, §5.1.3, §6.1; RFC 4752 §3; docs/49 §3.1;
//! P-14 (Q-166); AGENTS.md §6. Hand-made requests.

mod common;

use common::*;
use ldap::{AuditReason, AuditText, BindMechanism, ConnectionAction, Listener};
use parse_ldap::{AuthState, AuthenticationChoice, ProtocolOp, ResultCode};

fn bind_code(h: &mut Harness, msg: &parse_ldap::LdapMessage, tls_up: bool) -> ResultCode {
    let transport = if tls_up { tls() } else { cleartext() };
    let outcome = h.send(msg, transport);
    assert_eq!(outcome.action, ConnectionAction::Continue);
    let response = only_response(&outcome);
    assert_eq!(response.message_id, msg.message_id);
    match response.protocol_op {
        ProtocolOp::BindResponse(b) => {
            // "If the client bound with the simple choice, or the SASL
            // mechanism does not require the server to return information
            // ... this field SHALL NOT be included". Spec: RFC 4511 §4.2.2.
            assert!(b.server_sasl_creds.is_none());
            b.result.result_code
        }
        other => panic!("not a BindResponse: {other:?}"),
    }
}

/// RFC 4513 §5.1.1 (anonymous: empty name, empty password) and §2 ("MUST
/// support the anonymous authentication mechanism"): success; RFC 4513 §4:
/// the session stays anonymous.
#[test]
fn anonymous_simple_bind_succeeds_and_stays_anonymous() {
    for (listener, tls_up) in [(Listener::Ldap, false), (Listener::Ldaps, true)] {
        let mut h = Harness::new(listener);
        let outcome = h.send(&simple_bind(1, "", true), report_for(tls_up));
        assert_eq!(only_code(&outcome), ResultCode::Success);
        assert_eq!(outcome.audit.reason, AuditReason::AnonymousBind);
        assert_eq!(outcome.audit.principal, None);
        assert_eq!(h.session.auth_state(), AuthState::Unauthenticated);
        let bind = outcome.audit.bind.expect("bind facts");
        assert_eq!(bind.mechanism, BindMechanism::SimpleAnonymous);
        assert_eq!(bind.name, None);
        assert_eq!(h.subjects.calls.get(), 0);
    }
}

fn report_for(tls_up: bool) -> ldap::TransportReport {
    if tls_up {
        tls()
    } else {
        cleartext()
    }
}

/// P-14 / AGENTS.md §6 (no code path for simple bind with a password, even
/// over TLS); docs/49 §3.1 ("authMethodNotSupported (7) ... before any
/// lookup of the name and without keyd"). The account source is never asked
/// (no name lookup), and nothing else in the engine can reach keyd.
#[test]
fn simple_bind_with_password_is_auth_method_not_supported_without_lookup() {
    for (listener, tls_up) in [(Listener::Ldap, false), (Listener::Ldaps, true)] {
        let mut h = Harness::new(listener);
        let code = bind_code(
            &mut h,
            &simple_bind(2, "CN=alice,DC=example,DC=org", false),
            tls_up,
        );
        assert_eq!(code, ResultCode::AuthMethodNotSupported);
        assert_eq!(h.subjects.calls.get(), 0, "no name lookup");
        assert_eq!(h.session.auth_state(), AuthState::Unauthenticated);
    }
}

/// RFC 4513 §5.1.3: an empty name with a password is "undefined"; docs/49
/// §3.1: authMethodNotSupported (7).
#[test]
fn empty_name_with_password_is_auth_method_not_supported() {
    let mut h = Harness::new(Listener::Ldaps);
    let code = bind_code(&mut h, &simple_bind(3, "", false), true);
    assert_eq!(code, ResultCode::AuthMethodNotSupported);
    assert_eq!(h.subjects.calls.get(), 0);
}

/// RFC 4513 §5.1.2: "Servers SHOULD by default fail Unauthenticated Bind
/// requests with a resultCode of unwillingToPerform"; the name is kept for
/// trace only (docs/49 §10.1).
#[test]
fn unauthenticated_bind_is_unwilling_to_perform() {
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(
        &simple_bind(4, "CN=bob,DC=example,DC=org", true),
        cleartext(),
    );
    assert_eq!(only_code(&outcome), ResultCode::UnwillingToPerform);
    assert_eq!(outcome.audit.reason, AuditReason::UnauthenticatedBind);
    let bind = outcome.audit.bind.expect("bind facts");
    assert_eq!(bind.mechanism, BindMechanism::SimpleUnauthenticated);
    assert_eq!(
        bind.name,
        Some(AuditText::Text("CN=bob,DC=example,DC=org".to_owned()))
    );
    assert_eq!(h.subjects.calls.get(), 0);
}

/// docs/49 §10.1: a client string that is not printable ASCII, or longer than
/// 256 octets, is recorded as a fixed marker.
#[test]
fn unprintable_or_long_bind_names_are_withheld_from_audit() {
    let long = "a".repeat(257);
    for name in ["CN=a\u{7}b", "CN=caf\u{e9}", long.as_str()] {
        let mut h = Harness::new(Listener::Ldap);
        let outcome = h.send(&simple_bind(5, name, true), cleartext());
        assert_eq!(only_code(&outcome), ResultCode::UnwillingToPerform);
        assert_eq!(
            outcome.audit.bind.expect("bind facts").name,
            Some(AuditText::Withheld)
        );
    }
}

/// docs/49 §3.1: every SASL mechanism other than GSSAPI has no code path —
/// authMethodNotSupported (7), with or without TLS.
#[test]
fn other_sasl_mechanisms_are_auth_method_not_supported() {
    for mechanism in ["DIGEST-MD5", "GSS-SPNEGO", "EXTERNAL", "PLAIN", "gssapi"] {
        for (listener, tls_up) in [(Listener::Ldap, false), (Listener::Ldaps, true)] {
            let mut h = Harness::new(listener);
            let outcome = h.send(
                &sasl_bind(6, mechanism, Some(vec![1, 2, 3])),
                report_for(tls_up),
            );
            assert_eq!(
                only_code(&outcome),
                ResultCode::AuthMethodNotSupported,
                "{mechanism}"
            );
            assert_eq!(outcome.audit.reason, AuditReason::SaslMechanismUnsupported);
        }
    }
}

/// RFC 4511 §4.2.1: "If the client sends a BindRequest with the sasl
/// mechanism field as an empty string, the server MUST return ...
/// authMethodNotSupported" — before any TLS consideration.
#[test]
fn empty_sasl_mechanism_is_auth_method_not_supported() {
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(&sasl_bind(7, "", None), cleartext());
    assert_eq!(only_code(&outcome), ResultCode::AuthMethodNotSupported);
    assert_eq!(outcome.audit.reason, AuditReason::SaslEmptyMechanism);
}

/// docs/49 §3.1 ("SASL bind in a session without TLS → confidentialityRequired
/// (13), refused before keyd"); RFC 4513 §6.1; RFC 4752 §3 (the mechanism
/// name "GSSAPI").
#[test]
fn gssapi_without_tls_is_confidentiality_required() {
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(&sasl_bind(8, "GSSAPI", Some(vec![0x60, 0x00])), cleartext());
    assert_eq!(only_code(&outcome), ResultCode::ConfidentialityRequired);
    assert_eq!(outcome.audit.reason, AuditReason::SaslWithoutTls);
    assert_eq!(h.subjects.calls.get(), 0);
}

/// docs/49 §12: the GSSAPI bind is task L7, blocked on P-13; until then it is
/// authMethodNotSupported (7) over TLS too.
#[test]
fn gssapi_over_tls_is_not_yet_supported() {
    let mut h = Harness::new(Listener::Ldaps);
    let outcome = h.send(&sasl_bind(9, "GSSAPI", Some(vec![0x60, 0x00])), tls());
    assert_eq!(only_code(&outcome), ResultCode::AuthMethodNotSupported);
    assert_eq!(outcome.audit.reason, AuditReason::SaslGssapiNotAvailable);
    assert_eq!(h.session.auth_state(), AuthState::Unauthenticated);
    assert_eq!(h.subjects.calls.get(), 0);
}

/// RFC 4511 §4.2: "If the server does not support the specified version, it
/// MUST respond with a BindResponse where the resultCode is set to
/// protocolError" (no LDAPv2 — R49-17).
#[test]
fn version_other_than_3_is_protocol_error() {
    for version in [1, 2, 4, 127] {
        let mut h = Harness::new(Listener::Ldap);
        let msg = bind(
            10,
            version,
            "",
            AuthenticationChoice::Simple {
                password_empty: true,
            },
        );
        assert_eq!(bind_code(&mut h, &msg, false), ResultCode::ProtocolError);
    }
}

/// RFC 4511 §4.2: "Servers that do not support a choice supplied by a client
/// return a BindResponse with the resultCode set to authMethodNotSupported"
/// — the reserved [1]/[2] and the Sicily [9]-[11] of docs/49 §3.1.
#[test]
fn unrecognized_authentication_choice_is_auth_method_not_supported() {
    for tag_number in [1, 2, 9, 10, 11] {
        let mut h = Harness::new(Listener::Ldaps);
        let msg = bind(11, 3, "", AuthenticationChoice::Unrecognized { tag_number });
        let outcome = h.send(&msg, tls());
        assert_eq!(only_code(&outcome), ResultCode::AuthMethodNotSupported);
        assert_eq!(
            outcome.audit.bind.expect("bind facts").mechanism,
            BindMechanism::Unrecognized { tag_number }
        );
    }
}

/// RFC 4513 §4: a refused bind leaves the session anonymous and usable; the
/// next request is processed (here the anonymous rootDSE read, docs/49
/// §5.2).
#[test]
fn a_refused_bind_leaves_the_session_open_and_anonymous() {
    let mut h = Harness::new(Listener::Ldap);
    let refused = h.send(&simple_bind(12, "CN=x", false), cleartext());
    assert_eq!(refused.action, ConnectionAction::Continue);
    let outcome = h.send(&root_dse_search(13, &[]), cleartext());
    assert_eq!(outcome.responses.len(), 2, "entry + done");
    assert_eq!(outcome.audit.principal, None);
}
