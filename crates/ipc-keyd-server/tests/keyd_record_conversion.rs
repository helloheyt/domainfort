//! The conversion from keyd's audit record to its wire shape
//! (`ipc_keyd_server::keyd_record`): every field carried, names identical to
//! the source variants, and the converted records round-trip.
//!
//! Moved from crates/ipc-audit `tests/conversions.rs` (this project's test
//! code) by task IB1 (docs/questions/Q-851, A-144), with the conversion it
//! tests: only the call changed (`KeydRecord::from(&r)` → `keyd_record(&r)`).
//!
//! Source: crates/keyd audit.rs, authz.rs, model.rs (the field lists);
//! docs/50 §8.1, §8.2; docs/37 §2; decision A-86 (docs/questions/Q-365);
//! docs/questions/Q-452 item 4. Values are made up here.

use ipc_audit::{
    decode_event, encode_event, EventBody, KeyPurposeCode, KeydOperation, KeydOutcome, KeydReason,
    KeydRole,
};
use ipc_keyd_server::keyd_record;
use krb_proto::KerberosTime;

fn ktime() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 8, 0, 1).unwrap()
}

fn round_trip(event: EventBody) {
    let bytes = encode_event(&event).unwrap();
    assert_eq!(decode_event(bytes.as_bytes()).unwrap(), event);
}

/// crates/keyd `AuditRecord` → `KeydRecord`: every field.
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
        decision: Some(keyd::DecisionId::new(0x0123_4567_89AB_CDEF)),
        result: keyd::AuditOutcome::Denied,
        reason: keyd::AuditReason::DualControlRejected,
    };
    let wire = keyd_record(&source);
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
    assert_eq!(wire.decision, Some(0x0123_4567_89AB_CDEF));
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
            decision: None,
            result: outcome,
            reason: keyd::AuditReason::None,
        };
        let wire = keyd_record(&record).result;
        assert_eq!(wire.name(), format!("{outcome:?}"));
        assert!(!matches!(
            wire,
            KeydOutcome::Intent | KeydOutcome::NotPerformed
        ));
    }
}

/// Task A15a (docs/questions/Q-452 item 4): the four grant reasons map to
/// their own same-named codes, never `Unlisted`; likewise the seven decision
/// reasons appended by A-102 (docs/52 §4.5) and the two operation-binding
/// reasons of R2 (docs/52 §5 item 3), and the two revocation reasons of task
/// F3 (docs/questions/Q-976).
#[test]
fn keyd_grant_reasons_match() {
    for reason in [
        keyd::AuditReason::DecisionRevoked,
        keyd::AuditReason::DecisionExecuted,
        keyd::AuditReason::NoGrant,
        keyd::AuditReason::GrantMismatch,
        keyd::AuditReason::GrantInvalid,
        keyd::AuditReason::GrantTableFull,
        keyd::AuditReason::NoDecision,
        keyd::AuditReason::DecisionMismatch,
        keyd::AuditReason::DecisionInvalid,
        keyd::AuditReason::DecisionTableFull,
        keyd::AuditReason::DecisionConflict,
        keyd::AuditReason::DecisionReplayed,
        keyd::AuditReason::CeremonySealed,
        keyd::AuditReason::OperationDigestMissing,
        keyd::AuditReason::OperationDigestMismatch,
        keyd::AuditReason::SecretDecisionDiscarded,
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
            decision: None,
            result: keyd::AuditOutcome::Denied,
            reason,
        };
        let wire = keyd_record(&record).reason;
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
            decision: None,
            result: keyd::AuditOutcome::Success,
            reason: keyd::AuditReason::StartupHoldDown,
        };
        let wire = keyd_record(&record);
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
            decision: None,
            result: keyd::AuditOutcome::Unavailable,
            reason: keyd::AuditReason::None,
        };
        assert_eq!(keyd_record(&record).caller_role.name(), format!("{role:?}"));
    }
}
