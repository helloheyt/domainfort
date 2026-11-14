//! Conversions from the source crates' audit types (features `kdc`, `keyd`,
//! `ldap`): every field carried, details in their own fields, client
//! strings under the printable-ASCII rule, names identical to the source
//! variants, and the converted events round-trip.
//!
//! Source: crates/kdc audit.rs, accounts.rs; crates/keyd audit.rs,
//! authz.rs, model.rs; crates/ldap audit.rs, engine.rs; crates/pdp model.rs;
//! crates/parse-ldap error.rs, message.rs (the field lists); docs/50 §8.1,
//! §8.2; docs/37 §2. Values are made up here.
#![cfg(all(feature = "kdc", feature = "keyd", feature = "ldap"))]

use ipc_audit::{
    decode_event, encode_event, BindMechanism, CodecErrorCode, CodecLimit, EventBody, IpZone,
    KdcEvent, KdcExchange, KdcOutcome, KdcReason, KdcTransport, KeyPurposeCode, KeydOperation,
    KeydOutcome, KeydReason, KeydRecord, KeydRole, LdapAction, LdapEvent, LdapOperation,
    LdapReason, LdapTarget, LdapTransport, PdpReasonCode, SearchScope, UnsupportedOpCode,
};
use krb_proto::{KerberosString, KerberosTime, PrincipalName};

fn ktime() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 8, 0, 1).unwrap()
}

fn named(realm: &str, parts: &[&str]) -> kdc::NamedPrincipal {
    kdc::NamedPrincipal {
        realm: KerberosString::new(realm).unwrap(),
        name: PrincipalName {
            name_type: 1,
            name_string: parts
                .iter()
                .map(|p| KerberosString::new(p).unwrap())
                .collect(),
        },
    }
}

fn round_trip(event: EventBody) {
    let bytes = encode_event(&event).unwrap();
    assert_eq!(decode_event(bytes.as_bytes()).unwrap(), event);
}

/// crates/kdc `AuditEvent` → [`KdcEvent`]: every field.
#[test]
fn kdc_event_converts() {
    let source = kdc::AuditEvent {
        time: ktime(),
        transport: kdc::Transport::Udp,
        exchange: Some(kdc::Exchange::Tgs),
        client: Some(named("EXAMPLE.TEST", &["alice"])),
        service: Some(named("EXAMPLE.TEST", &["host", "web1.example.test"])),
        armor: kdc::ArmorAudit {
            principal: Some(named("EXAMPLE.TEST", &["web1$"])),
            reply_armored: true,
        },
        outcome: kdc::AuditOutcome::Refused { error_code: 24 },
        reason: kdc::AuditReason::PreauthDenied,
    };
    let wire = KdcEvent::from(&source);
    assert_eq!(
        (
            wire.time.year(),
            wire.time.month(),
            wire.time.day(),
            wire.time.hour(),
            wire.time.minute(),
            wire.time.second()
        ),
        (2026, 11, 13, 8, 0, 1)
    );
    assert_eq!(wire.transport, KdcTransport::Udp);
    assert_eq!(wire.exchange, Some(KdcExchange::Tgs));
    let client = wire.client.as_ref().unwrap();
    assert_eq!(client.realm().as_text(), Some("EXAMPLE.TEST"));
    assert_eq!(client.name_type(), 1);
    assert_eq!(client.components().unwrap()[0].as_text(), Some("alice"));
    assert_eq!(
        wire.service.as_ref().unwrap().components().unwrap().len(),
        2
    );
    assert_eq!(
        wire.armor_principal.as_ref().unwrap().components().unwrap()[0].as_text(),
        Some("web1$")
    );
    assert!(wire.reply_armored);
    assert_eq!(wire.outcome, KdcOutcome::Refused { error_code: 24 });
    assert_eq!(wire.reason, KdcReason::PreauthDenied);
    assert_eq!(wire.policy_reason, None);
    round_trip(EventBody::Kdc(Box::new(wire)));
}

/// The PDP reason travels in its own field; a coarse deny keeps its rule.
#[test]
fn kdc_policy_reason_converts() {
    let source = kdc::AuditEvent {
        time: ktime(),
        transport: kdc::Transport::Tcp,
        exchange: Some(kdc::Exchange::As),
        client: None,
        service: None,
        armor: kdc::ArmorAudit::default(),
        outcome: kdc::AuditOutcome::Issued,
        reason: kdc::AuditReason::PolicyDenied(pdp::ReasonCode::CoarseDeny(pdp::RuleId(31))),
    };
    let wire = KdcEvent::from(&source);
    assert_eq!(wire.reason, KdcReason::PolicyDenied);
    let policy = wire.policy_reason.unwrap();
    assert_eq!(policy.code, PdpReasonCode::CoarseDeny);
    assert_eq!(policy.rule, Some(31));

    let source = kdc::AuditEvent {
        reason: kdc::AuditReason::PolicyDenied(pdp::ReasonCode::TierViolation),
        ..source
    };
    let policy = KdcEvent::from(&source).policy_reason.unwrap();
    assert_eq!(policy.code, PdpReasonCode::TierViolation);
    assert_eq!(policy.rule, None);
}

/// Client strings pass the printable-ASCII ≤ 256 rule again (docs/50 §8.2):
/// a realm of 300 characters is withheld; a name of five components is
/// withheld as a whole.
#[test]
fn kdc_long_strings_are_withheld() {
    let long = "R".repeat(300);
    let source = kdc::AuditEvent {
        time: ktime(),
        transport: kdc::Transport::Tcp,
        exchange: None,
        client: Some(named(&long, &["a", "b", "c", "d", "e"])),
        service: None,
        armor: kdc::ArmorAudit::default(),
        outcome: kdc::AuditOutcome::Dropped,
        reason: kdc::AuditReason::Malformed,
    };
    let wire = KdcEvent::from(&source);
    let client = wire.client.as_ref().unwrap();
    assert!(client.realm().is_withheld());
    assert!(client.components().is_none());
    round_trip(EventBody::Kdc(Box::new(wire)));
}

/// Table names are the source variant names (checked through the sources'
/// derived `Debug`, test-only).
#[test]
fn kdc_reason_names_match_the_source() {
    use kdc::AuditReason as R;
    for reason in [
        R::Issued,
        R::Retransmission,
        R::CrossRealm,
        R::AccountSourceUnavailable,
        R::CustodyUnavailable,
        R::PreauthSkew,
        R::AuthenticatorReplay,
        R::RateLimited,
        R::FastRequired,
        R::ArmorPrincipalRevoked,
        R::FastContextMissing,
    ] {
        let event = kdc::AuditEvent {
            time: ktime(),
            transport: kdc::Transport::Tcp,
            exchange: None,
            client: None,
            service: None,
            armor: kdc::ArmorAudit::default(),
            outcome: kdc::AuditOutcome::Dropped,
            reason,
        };
        assert_eq!(KdcEvent::from(&event).reason.name(), format!("{reason:?}"));
    }
}

/// crates/keyd `AuditRecord` → [`KeydRecord`]: every field.
#[test]
fn keyd_record_converts() {
    let p = |b: u8| keyd::PrincipalId::from_bytes([b; 16]);
    let source = keyd::AuditRecord {
        ts: ktime(),
        caller_role: keyd::Role::Admin,
        caller_uid: 807,
        op: keyd::Operation::RotateKrbtgt,
        principal: Some(p(1)),
        purpose: Some(keyd::KeyPurpose::Krbtgt),
        kvno: Some(keyd::Kvno::new(4)),
        secondary: Some(keyd::AuditKeyRef {
            principal: p(2),
            purpose: keyd::KeyPurpose::Service,
            kvno: None,
        }),
        approvers: Some([p(3), p(4)]),
        result: keyd::AuditOutcome::Denied,
        reason: keyd::AuditReason::DualControlRejected,
    };
    let wire = KeydRecord::from(&source);
    assert_eq!(wire.caller_role, KeydRole::Admin);
    assert_eq!(wire.caller_uid, 807);
    assert_eq!(wire.op, KeydOperation::RotateKrbtgt);
    assert_eq!(wire.principal, Some([1; 16]));
    assert_eq!(wire.purpose, Some(KeyPurposeCode::Krbtgt));
    assert_eq!(wire.kvno, Some(4));
    let secondary = wire.secondary.unwrap();
    assert_eq!(secondary.principal, [2; 16]);
    assert_eq!(secondary.purpose, KeyPurposeCode::Service);
    assert_eq!(secondary.kvno, None);
    assert_eq!(wire.approvers, Some([[3; 16], [4; 16]]));
    assert_eq!(wire.result, KeydOutcome::Denied);
    assert_eq!(wire.reason, KeydReason::DualControlRejected);
    round_trip(EventBody::Keyd(Box::new(wire)));
}

/// Decision A-86 (docs/questions/Q-365): keyd's five outcomes map to their
/// same-named codes, and none maps to the two phase codes keyd-daemon
/// writes itself (`Intent`, `NotPerformed`) — a record keyd emitted can
/// never read as an intent.
#[test]
fn keyd_outcomes_never_map_to_a_phase_code() {
    for outcome in [
        keyd::AuditOutcome::Success,
        keyd::AuditOutcome::Denied,
        keyd::AuditOutcome::BadTemplate,
        keyd::AuditOutcome::Unavailable,
        keyd::AuditOutcome::RateLimited,
    ] {
        let record = keyd::AuditRecord {
            ts: ktime(),
            caller_role: keyd::Role::Admin,
            caller_uid: 1,
            op: keyd::Operation::CreateKey,
            principal: None,
            purpose: None,
            kvno: None,
            secondary: None,
            approvers: None,
            result: outcome,
            reason: keyd::AuditReason::None,
        };
        let wire = KeydRecord::from(&record).result;
        assert_eq!(wire.name(), format!("{outcome:?}"));
        assert!(!matches!(
            wire,
            KeydOutcome::Intent | KeydOutcome::NotPerformed
        ));
    }
}

/// Task A15a (docs/questions/Q-452 item 4): the four grant reasons map to
/// their own same-named codes, never `Unlisted`.
#[test]
fn keyd_grant_reasons_match() {
    for reason in [
        keyd::AuditReason::NoGrant,
        keyd::AuditReason::GrantMismatch,
        keyd::AuditReason::GrantInvalid,
        keyd::AuditReason::GrantTableFull,
    ] {
        let record = keyd::AuditRecord {
            ts: ktime(),
            caller_role: keyd::Role::Directory,
            caller_uid: 1,
            op: keyd::Operation::SetSecret,
            principal: None,
            purpose: None,
            kvno: None,
            secondary: None,
            approvers: None,
            result: keyd::AuditOutcome::Denied,
            reason,
        };
        let wire = KeydRecord::from(&record).reason;
        assert_eq!(wire.name(), format!("{reason:?}"));
        assert_ne!(wire, KeydReason::Unlisted);
    }
}

/// Every keyd operation and role maps to the same-named code.
#[test]
fn keyd_operations_and_roles_match() {
    for op in keyd::Operation::ALL {
        let record = keyd::AuditRecord {
            ts: ktime(),
            caller_role: keyd::Role::Kdc,
            caller_uid: 1,
            op,
            principal: None,
            purpose: None,
            kvno: None,
            secondary: None,
            approvers: None,
            result: keyd::AuditOutcome::Success,
            reason: keyd::AuditReason::StartupHoldDown,
        };
        let wire = KeydRecord::from(&record);
        assert_eq!(wire.op.name(), format!("{op:?}"));
        assert_eq!(wire.reason, KeydReason::StartupHoldDown);
    }
    for role in [
        keyd::Role::Kdc,
        keyd::Role::Directory,
        keyd::Role::Admin,
        keyd::Role::Ldap,
    ] {
        let record = keyd::AuditRecord {
            ts: ktime(),
            caller_role: role,
            caller_uid: 1,
            op: keyd::Operation::Ping,
            principal: None,
            purpose: None,
            kvno: None,
            secondary: None,
            approvers: None,
            result: keyd::AuditOutcome::Unavailable,
            reason: keyd::AuditReason::None,
        };
        assert_eq!(
            KeydRecord::from(&record).caller_role.name(),
            format!("{role:?}")
        );
    }
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

/// crates/ldap `AuditEvent` → [`LdapEvent`]: every field.
#[test]
fn ldap_event_converts() {
    let wire = LdapEvent::from(&ldap_source());
    assert_eq!(wire.connection_id, 99);
    assert_eq!(wire.source_zone, IpZone::External);
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
    let wire = LdapEvent::from(&source);
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
    let wire = LdapEvent::from(&source);
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
    let wire = LdapEvent::from(&source);
    assert_eq!(wire.reason, LdapReason::Malformed);
    let codec = wire.codec_error.unwrap();
    assert_eq!(codec.error, CodecErrorCode::LimitExceeded);
    assert_eq!(codec.limit, Some(CodecLimit::FilterNodes));
    assert_eq!(wire.policy_reason, None);

    let source = ldap::AuditEvent {
        reason: ldap::AuditReason::Malformed(parse_ldap::Error::NonCanonical),
        ..ldap_source()
    };
    let codec = LdapEvent::from(&source).codec_error.unwrap();
    assert_eq!(codec.error, CodecErrorCode::NonCanonical);
    assert_eq!(codec.limit, None);

    let source = ldap::AuditEvent {
        operation: ldap::AuditOperation::NotSupported(parse_ldap::UnsupportedOp::DelRequest),
        reason: ldap::AuditReason::PolicyDenied(pdp::ReasonCode::Acl),
        ..ldap_source()
    };
    let wire = LdapEvent::from(&source);
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
    let wire = LdapEvent::from(&source);
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
        assert_eq!(LdapEvent::from(&event).reason.name(), format!("{reason:?}"));
    }
}
