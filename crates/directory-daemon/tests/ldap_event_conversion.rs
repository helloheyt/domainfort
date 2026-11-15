//! The conversion from the LDAP engine's audit event to its wire shape
//! (`directory_daemon::ldap_event`): every field carried, details in their
//! own fields, client strings under the printable-ASCII rule, names
//! identical to the source variants, the reported client address beside the
//! event, and the converted events round-trip.
//!
//! Moved from crates/ipc-audit `tests/conversions.rs` (this project's test
//! code) by task IB1 (docs/questions/Q-851, A-144), with the conversion it
//! tests: only the call changed (`LdapEvent::from_engine(e, p)` →
//! `ldap_event(e, p)`).
//!
//! Source: crates/ldap audit.rs, engine.rs; crates/pdp model.rs;
//! crates/parse-ldap error.rs, message.rs (the field lists); docs/50 §8.1,
//! §8.2; docs/37 §2; docs/52 §7 R14. Values are made up here.

use directory_daemon::ldap_event;
use ipc_audit::{
    decode_event, encode_event, BindMechanism, CodecErrorCode, CodecLimit, EventBody, IpZone,
    LdapAction, LdapEvent, LdapOperation, LdapReason, LdapTarget, LdapTransport, PdpReasonCode,
    ReportedAddress, SearchScope, UnsupportedOpCode,
};
use krb_proto::KerberosTime;

fn ktime() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 8, 0, 1).unwrap()
}

fn round_trip(event: EventBody) {
    let bytes = encode_event(&event).unwrap();
    assert_eq!(decode_event(bytes.as_bytes()).unwrap(), event);
}

fn ldap_source() -> ldap::AuditEvent {
    ldap::AuditEvent {
        time: ktime(),
        connection_id: 99,
        source_zone: pdp::IpScope::External,
        transport: ldap::AuditTransport::Ldaps,
        transport_sec: pdp::TransportSec {
            encrypted: true,
            sealed: false,
            channel_bound: false,
        },
        operation: ldap::AuditOperation::Search,
        message_id: Some(parse_ldap::MessageId::new(12).unwrap()),
        principal: Some(dtyp::Sid::new([0, 0, 0, 0, 0, 5], &[21, 10, 20, 30, 500]).unwrap()),
        bind: None,
        target: Some(ldap::AuditTarget::DirObject(dtyp::Guid::from_packet(
            &[0x10; 16],
        ))),
        search: Some(ldap::SearchAudit {
            scope: ldap::AuditScope::SingleLevel,
            entries_returned: 2,
            candidates_visited: 9,
            pruned_subtrees: 1,
            filter_attrs: vec!["cn", "servicePrincipalName"],
        }),
        result_code: Some(parse_ldap::ResultCode::Success),
        notice: None,
        action: ldap::ConnectionAction::Continue,
        reason: ldap::AuditReason::SearchCompleted,
    }
}

/// The client address ldap-front reported (test data): dird passes it
/// beside the engine's event (docs/52 R14).
fn reported() -> ReportedAddress {
    ReportedAddress::new(core::net::IpAddr::V6(core::net::Ipv6Addr::new(
        0xfd00, 0x1234, 0, 0, 0, 0, 0, 9,
    )))
}

/// The conversion of `event` with [`reported`].
fn convert(event: &ldap::AuditEvent) -> LdapEvent {
    ldap_event(event, reported())
}

/// crates/ldap `AuditEvent` → `LdapEvent`: every field, and the reported
/// client address beside it (docs/52 R14: an unverified observation, kept
/// as given and independent of the zone).
#[test]
fn ldap_event_converts() {
    let wire = convert(&ldap_source());
    assert_eq!(wire.connection_id, 99);
    assert_eq!(wire.source_zone, IpZone::External);
    assert_eq!(wire.reported_peer, reported());
    assert_eq!(wire.transport, LdapTransport::Ldaps);
    assert!(wire.transport_sec.encrypted);
    assert!(!wire.transport_sec.sealed);
    assert_eq!(wire.operation, LdapOperation::Search);
    assert_eq!(wire.message_id, Some(12));
    let sid = wire.principal.as_ref().unwrap();
    assert_eq!(sid.authority(), [0, 0, 0, 0, 0, 5]);
    assert_eq!(sid.sub_authorities(), &[21, 10, 20, 30, 500]);
    assert_eq!(wire.target, Some(LdapTarget::DirObject([0x10; 16])));
    let search = wire.search.as_ref().unwrap();
    assert_eq!(search.scope, SearchScope::SingleLevel);
    assert_eq!(
        (
            search.entries_returned,
            search.candidates_visited,
            search.pruned_subtrees
        ),
        (2, 9, 1)
    );
    let names: Vec<_> = search.filter_attrs().iter().map(|t| t.as_text()).collect();
    assert_eq!(names, vec![Some("cn"), Some("servicePrincipalName")]);
    assert_eq!(wire.result_code, Some(0));
    assert_eq!(wire.action, LdapAction::Continue);
    assert_eq!(wire.reason, LdapReason::SearchCompleted);
    round_trip(EventBody::Ldap(Box::new(wire)));
}

/// Bind facts: the mechanism and the trace name, never a credential; a
/// withheld client string stays withheld.
#[test]
fn ldap_bind_converts() {
    let source = ldap::AuditEvent {
        operation: ldap::AuditOperation::Bind,
        bind: Some(ldap::BindAudit {
            version: 3,
            mechanism: ldap::BindMechanism::Sasl {
                mechanism: ldap::AuditText::Withheld,
            },
            name: Some(ldap::AuditText::Text("cn=trace".to_owned())),
        }),
        reason: ldap::AuditReason::SaslWithoutTls,
        ..ldap_source()
    };
    let wire = convert(&source);
    let bind = wire.bind.as_ref().unwrap();
    assert_eq!(bind.version, 3);
    match &bind.mechanism {
        BindMechanism::Sasl { mechanism } => assert!(mechanism.is_withheld()),
        other => panic!("{other:?}"),
    }
    assert_eq!(bind.name.as_ref().unwrap().as_text(), Some("cn=trace"));
    assert_eq!(wire.reason, LdapReason::SaslWithoutTls);
    round_trip(EventBody::Ldap(Box::new(wire)));

    let source = ldap::AuditEvent {
        bind: Some(ldap::BindAudit {
            version: 3,
            mechanism: ldap::BindMechanism::SimplePassword,
            name: None,
        }),
        reason: ldap::AuditReason::SimplePasswordBind,
        ..ldap_source()
    };
    let wire = convert(&source);
    assert_eq!(
        wire.bind.as_ref().unwrap().mechanism,
        BindMechanism::SimplePassword
    );
}

/// Reason details: a codec error (with its limit) and a PDP reason travel
/// in their own fields; an unsupported operation keeps which one.
#[test]
fn ldap_details_convert() {
    let source = ldap::AuditEvent {
        operation: ldap::AuditOperation::Malformed,
        reason: ldap::AuditReason::Malformed(parse_ldap::Error::LimitExceeded(
            parse_ldap::Limit::FilterNodes,
        )),
        ..ldap_source()
    };
    let wire = convert(&source);
    assert_eq!(wire.reason, LdapReason::Malformed);
    let codec = wire.codec_error.unwrap();
    assert_eq!(codec.error, CodecErrorCode::LimitExceeded);
    assert_eq!(codec.limit, Some(CodecLimit::FilterNodes));
    assert_eq!(wire.policy_reason, None);

    let source = ldap::AuditEvent {
        reason: ldap::AuditReason::Malformed(parse_ldap::Error::NonCanonical),
        ..ldap_source()
    };
    let codec = convert(&source).codec_error.unwrap();
    assert_eq!(codec.error, CodecErrorCode::NonCanonical);
    assert_eq!(codec.limit, None);

    let source = ldap::AuditEvent {
        operation: ldap::AuditOperation::NotSupported(parse_ldap::UnsupportedOp::DelRequest),
        reason: ldap::AuditReason::PolicyDenied(pdp::ReasonCode::Acl),
        ..ldap_source()
    };
    let wire = convert(&source);
    assert_eq!(
        wire.operation,
        LdapOperation::NotSupported(UnsupportedOpCode::DelRequest)
    );
    assert_eq!(wire.reason, LdapReason::PolicyDenied);
    assert_eq!(wire.policy_reason.unwrap().code, PdpReasonCode::Acl);
    assert_eq!(wire.codec_error, None);
    round_trip(EventBody::Ldap(Box::new(wire)));
}

/// More than 16 filter attribute names: the first 16 are kept and the
/// search is marked truncated.
#[test]
fn ldap_filter_attrs_truncate() {
    let mut source = ldap_source();
    source.search.as_mut().unwrap().filter_attrs = vec!["cn"; 20];
    let wire = convert(&source);
    let search = wire.search.as_ref().unwrap();
    assert_eq!(search.filter_attrs().len(), ipc_audit::MAX_FILTER_ATTRS);
    assert!(search.filter_attrs_truncated());
    round_trip(EventBody::Ldap(Box::new(wire)));
}

/// LDAP reason names match the source variants (test-only `Debug` check).
#[test]
fn ldap_reason_names_match_the_source() {
    use ldap::AuditReason as R;
    for reason in [
        R::SessionClosed,
        R::Oversized,
        R::RequestDuringStartTls,
        R::IdentityRevoked,
        R::SaslGssapiNotAvailable,
        R::StartTlsWithPendingInput,
        R::BaseNotVisible,
        R::VisitBudgetExceeded,
        R::UnrepresentableDn,
        R::SubjectUnavailable,
        R::InternalFailure,
    ] {
        let event = ldap::AuditEvent {
            reason,
            ..ldap_source()
        };
        assert_eq!(convert(&event).reason.name(), format!("{reason:?}"));
    }
}
