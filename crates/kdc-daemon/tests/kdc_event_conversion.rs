//! The conversion from the KDC's audit event to its wire shape
//! (`kdc_daemon::kdc_event`): every field carried, details in their own
//! fields, client strings under the printable-ASCII rule, names identical to
//! the source variants, and the converted events round-trip.
//!
//! Moved from crates/ipc-audit `tests/conversions.rs` (this project's test
//! code) by task IB1 (docs/questions/Q-851, A-144), with the conversion it
//! tests: only the call changed (`KdcEvent::from(&e)` → `kdc_event(&e)`).
//!
//! Source: crates/kdc audit.rs, accounts.rs; crates/pdp model.rs (the field
//! lists); docs/50 §8.1, §8.2; docs/37 §2. Values are made up here.

use ipc_audit::{
    decode_event, encode_event, EventBody, KdcExchange, KdcOutcome, KdcReason, KdcTransport,
    PdpReasonCode,
};
use kdc_daemon::kdc_event;
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

/// crates/kdc `AuditEvent` → `KdcEvent`: every field.
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
    let wire = kdc_event(&source);
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
    let wire = kdc_event(&source);
    assert_eq!(wire.reason, KdcReason::PolicyDenied);
    let policy = wire.policy_reason.unwrap();
    assert_eq!(policy.code, PdpReasonCode::CoarseDeny);
    assert_eq!(policy.rule, Some(31));

    let source = kdc::AuditEvent {
        reason: kdc::AuditReason::PolicyDenied(pdp::ReasonCode::TierViolation),
        ..source
    };
    let policy = kdc_event(&source).policy_reason.unwrap();
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
    let wire = kdc_event(&source);
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
        assert_eq!(kdc_event(&event).reason.name(), format!("{reason:?}"));
    }
}
