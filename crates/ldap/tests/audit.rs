//! Audit: exactly one event per message, with no credential anywhere
//! (docs/49 §10.1, R49-14).
//!
//! Sources (each test names its own): docs/49 §10.1, §11 (the engine returns
//! the audit event with the responses); docs/CLEAN-ROOM.md (secrets never in logs,
//! panics, debug output or errors); RFC 4511 §4.2 (SaslCredentials).
//! Hand-made requests.

mod common;

use common::*;
use ldap::{AuditOperation, AuditText, AuditTransport, BindMechanism, ConnectionAction, Listener};
use parse_ldap::{ResultCode, UnsupportedOp};
use pdp::IpScope;

/// docs/49 §10.1 ("exactly one event per LDAP operation") and §11: every call
/// returns one event describing that message — a whole scripted session,
/// including the message after the close.
#[test]
fn exactly_one_event_per_message() {
    let mut h = Harness::new(Listener::Ldap);
    let script = [
        (root_dse_search(1, &[]), AuditOperation::Search),
        (simple_bind(2, "", true), AuditOperation::Bind),
        (abandon(3, 1), AuditOperation::Abandon),
        (extended(4, "1.2.3", None), AuditOperation::Extended),
        (
            unsupported(5, UnsupportedOp::CompareRequest),
            AuditOperation::NotSupported(UnsupportedOp::CompareRequest),
        ),
        (start_tls(6), AuditOperation::StartTls),
    ];
    for (msg, operation) in script {
        let outcome = h.send(&msg, cleartext());
        assert_eq!(outcome.audit.operation, operation);
        assert_eq!(outcome.audit.message_id, Some(msg.message_id));
        assert_eq!(outcome.audit.connection_id, 7);
        assert_eq!(outcome.audit.time, now());
        assert_eq!(outcome.audit.source_zone, IpScope::Internal);
        assert_eq!(outcome.audit.transport, AuditTransport::Ldap);
        assert_eq!(outcome.audit.action, outcome.action);
    }
    let unbound = h.send(&unbind(7), tls());
    assert_eq!(unbound.audit.operation, AuditOperation::Unbind);
    assert_eq!(unbound.audit.transport, AuditTransport::StartTls);
    let after = h.send(&root_dse_search(8, &[]), tls());
    assert_eq!(after.audit.operation, AuditOperation::NotDecoded);
    assert_eq!(after.action, ConnectionAction::Close);
}

/// docs/CLEAN-ROOM.md; docs/49 §10.1 ("no SASL tokens"): SASL credentials appear
/// nowhere in the outcome — not in a response, not in the audit event, not
/// in any Debug output — on every path a SASL bind can take.
#[test]
fn sasl_credentials_never_appear_in_responses_or_audit() {
    let marker: Vec<u8> = b"CREDENTIAL-MARKER-7f3a".to_vec();
    for (listener, transport, mechanism) in [
        (Listener::Ldap, cleartext(), "GSSAPI"),
        (Listener::Ldaps, tls(), "GSSAPI"),
        (Listener::Ldaps, tls(), "DIGEST-MD5"),
        (Listener::Ldaps, tls(), ""),
    ] {
        let mut h = Harness::new(listener);
        let outcome = h.send(&sasl_bind(1, mechanism, Some(marker.clone())), transport);
        for octets in &outcome.responses {
            assert!(!contains(octets, &marker));
        }
        let debug = format!("{outcome:?}");
        assert!(!debug.contains("CREDENTIAL-MARKER"));
        assert!(!contains(debug.as_bytes(), &marker));
        // Only the mechanism name is recorded (docs/49 §10.1).
        let bind = outcome.audit.bind.expect("bind facts");
        assert_eq!(
            bind.mechanism,
            BindMechanism::Sasl {
                mechanism: AuditText::Text(mechanism.to_owned())
            }
        );
    }
}

/// A-52: a simple-bind password is reduced to "non-empty" before the engine;
/// the audit records only the mechanism class, never a value.
#[test]
fn a_simple_bind_records_only_the_mechanism_class() {
    let mut h = Harness::new(Listener::Ldaps);
    let outcome = h.send(&simple_bind(1, "CN=carol,DC=example,DC=org", false), tls());
    assert_eq!(only_code(&outcome), ResultCode::AuthMethodNotSupported);
    let bind = outcome.audit.bind.expect("bind facts");
    assert_eq!(bind.mechanism, BindMechanism::SimplePassword);
    assert_eq!(bind.version, 3);
}

/// docs/49 §10.1: a SASL mechanism name that is not printable ASCII is
/// withheld.
#[test]
fn unprintable_mechanism_names_are_withheld() {
    let mut h = Harness::new(Listener::Ldaps);
    let outcome = h.send(&sasl_bind(1, "GSS\u{1b}[2J", None), tls());
    assert_eq!(only_code(&outcome), ResultCode::AuthMethodNotSupported);
    assert_eq!(
        outcome.audit.bind.expect("bind facts").mechanism,
        BindMechanism::Sasl {
            mechanism: AuditText::Withheld
        }
    );
}
