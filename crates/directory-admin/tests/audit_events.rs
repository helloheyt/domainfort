//! The exact `DirAdmin` events the write PEP plans.
//!
//! Sources: A-85 (crate ipc-audit admin.rs: `DirAdminEvent` field use per
//! operation; decision before the commit, outcome after it; Q-340 items
//! 1, 4, 5 — the operation id shared by both events, the names kept as
//! `AuditText`, and the three request values); docs/51 §5.7 (R51-12: only
//! identifiers and metadata — no description, password or key); docs/37 §2
//! as cited there. Fixtures: tests/common; each expected event is written
//! out field by field.

mod common;

use common::*;
use directory_admin::{CreateGroup, CreateUser, Membership, Operation, SetEnabled};
use ipc_audit::{
    AdminFailure, AdminNameKind, AdminRefusal, Allocation, AuditText, BoundedSeq, CalendarTime,
    DecisionResult, DirAdminEvent, DirAdminOperation, DirAdminStage, EnableDirection,
    GroupTypeCode, OutcomeResult, PdpReason, PdpReasonCode, SidValue, TargetName,
};

fn sid_value(id: u32) -> SidValue {
    SidValue::new(dtyp::SECURITY_NT_AUTHORITY, vec![21, 1, 2, 3, rid(id)]).unwrap()
}

fn at_now() -> CalendarTime {
    CalendarTime::new(2026, 11, 13, 10, 0, 0).unwrap()
}

fn allowed() -> Option<PdpReason> {
    Some(PdpReason {
        code: PdpReasonCode::Allowed,
        rule: None,
    })
}

fn name(kind: AdminNameKind, text: &str) -> TargetName {
    TargetName {
        kind,
        text: AuditText::from_client(text),
    }
}

/// A-85: a `CreateUser` plans a `Decision` (`Proceed`) event and an
/// `Outcome` (`Committed`, with the allocated GUID and RID) event carrying
/// the same operation id; the parent by GUID, the requester's SID, the
/// PDP's `Allowed`, the sAMAccountName and UPN as `AuditText` — and never
/// the description (docs/51 §5.7 item 1).
#[test]
fn create_user_events_are_exact() {
    let mut d = Domain::new("events-create");
    let op = Operation::CreateUser(CreateUser {
        parent: guid(STAFF_OU),
        sam: "carol".into(),
        upn: Some("carol@example.test".into()),
        description: Some("not for the log".into()),
    });
    let (decision, applied) = d.run(op, "admin1", &[]).applied();
    let expected = DirAdminEvent {
        time: at_now(),
        operation_id: 1,
        operation: DirAdminOperation::CreateUser,
        stage: DirAdminStage::Decision(DecisionResult::Proceed),
        target: None,
        parent: Some(guid(STAFF_OU).to_packet()),
        member: None,
        requester: Some(sid_value(ADMIN1)),
        approvers: BoundedSeq::empty(),
        pdp: allowed(),
        names: BoundedSeq::new(vec![
            name(AdminNameKind::SamAccountName, "carol"),
            name(AdminNameKind::UserPrincipalName, "carol@example.test"),
        ])
        .unwrap(),
        enable: None,
        account_expires: None,
        group_type: None,
        key_request: None,
        key_operation: None,
        reported_kvnos: BoundedSeq::empty(),
    };
    assert_eq!(decision, expected);
    assert_eq!(
        applied.outcome_event(),
        &DirAdminEvent {
            stage: DirAdminStage::Outcome(OutcomeResult::Committed {
                allocated: Some(Allocation {
                    guid: drawn_guid(1).to_packet(),
                    rid: Some(FIRST_ADMIN_RID),
                }),
            }),
            ..expected.clone()
        }
    );
    assert_eq!(
        applied.commit_failure_event(),
        &DirAdminEvent {
            stage: DirAdminStage::Outcome(OutcomeResult::Failed(AdminFailure::StoreFailure)),
            ..expected
        }
    );
    // The event encodes canonically (crate ipc-audit codec).
    let body = ipc_audit::EventBody::DirAdmin(Box::new(decision));
    let bytes = ipc_audit::encode_event(&body).unwrap();
    assert_eq!(ipc_audit::decode_event(bytes.as_bytes()).unwrap(), body);
}

/// A-85: a refused `SetEnabled` plans one `Decision` event: refused, the
/// PDP's reason (bob has no write rule — NoGrant), the target by GUID, the
/// requested direction.
#[test]
fn a_refusal_event_is_exact() {
    let mut d = Domain::new("events-refused");
    let r = d
        .run(
            Operation::SetEnabled(SetEnabled {
                target: guid(ALICE),
                enabled: false,
            }),
            "bob",
            &[],
        )
        .refused();
    assert_eq!(
        r.event(),
        &DirAdminEvent {
            time: at_now(),
            operation_id: 1,
            operation: DirAdminOperation::SetEnabled,
            stage: DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::PolicyDenied)),
            target: Some(guid(ALICE).to_packet()),
            parent: None,
            member: None,
            requester: Some(sid_value(BOB)),
            approvers: BoundedSeq::empty(),
            pdp: Some(PdpReason {
                code: PdpReasonCode::NoGrant,
                rule: None,
            }),
            names: BoundedSeq::empty(),
            enable: Some(EnableDirection::Disable),
            account_expires: None,
            group_type: None,
            key_request: None,
            key_operation: None,
            reported_kvnos: BoundedSeq::empty(),
        }
    );
}

/// A-85 / docs/51 §5.6: a dual-controlled membership change names the group
/// as target, the member, the requester and the verified approver; a
/// `CreateGroup` records its groupType code (Q-340 item 5).
#[test]
fn dual_control_and_group_type_events_are_exact() {
    let mut d = Domain::new("events-dual");
    let (decision, applied) = d
        .run(
            Operation::AddMember(Membership {
                group: guid(TIER0_GROUP),
                member: guid(ALICE),
            }),
            "admin1",
            &["admin2"],
        )
        .applied();
    let expected = DirAdminEvent {
        time: at_now(),
        operation_id: 1,
        operation: DirAdminOperation::AddMember,
        stage: DirAdminStage::Decision(DecisionResult::Proceed),
        target: Some(guid(TIER0_GROUP).to_packet()),
        parent: None,
        member: Some(guid(ALICE).to_packet()),
        requester: Some(sid_value(ADMIN1)),
        approvers: BoundedSeq::new(vec![sid_value(ADMIN2)]).unwrap(),
        pdp: allowed(),
        names: BoundedSeq::empty(),
        enable: None,
        account_expires: None,
        group_type: None,
        key_request: None,
        key_operation: None,
        reported_kvnos: BoundedSeq::empty(),
    };
    assert_eq!(decision, expected);
    assert_eq!(
        applied.outcome_event(),
        &DirAdminEvent {
            stage: DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None }),
            ..expected
        }
    );
    let (decision, _) = d
        .run(
            Operation::CreateGroup(CreateGroup {
                parent: guid(STAFF_OU),
                sam: "ops".into(),
                group_type: Some(0x8000_0008),
            }),
            "admin1",
            &[],
        )
        .applied();
    assert_eq!(
        decision.group_type,
        Some(GroupTypeCode::SecurityUniversalGroup)
    );
    assert_eq!(decision.operation_id, 2);
    // Default groupType: GROUP_TYPE_SECURITY_ACCOUNT ([MS-SAMR] 3.1.1.8.1
    // item 2.2).
    let (decision, _) = d
        .run(
            Operation::CreateGroup(CreateGroup {
                parent: guid(STAFF_OU),
                sam: "ops2".into(),
                group_type: None,
            }),
            "admin1",
            &[],
        )
        .applied();
    assert_eq!(
        decision.group_type,
        Some(GroupTypeCode::SecurityAccountGroup)
    );
}

/// A name that is not printable ASCII never reaches the log: it is replaced
/// by the `AuditText` marker (docs/50 §8.2 as cited in crate ipc-audit) —
/// and the request is refused anyway (P-6).
#[test]
fn unprintable_names_are_withheld() {
    let mut d = Domain::new("events-withheld");
    let r = d
        .run(
            Operation::CreateUser(CreateUser {
                parent: guid(STAFF_OU),
                sam: "car\u{1}ol".into(),
                upn: None,
                description: None,
            }),
            "admin1",
            &[],
        )
        .refused();
    assert_eq!(r.event().names.as_slice()[0].text, AuditText::WITHHELD);
}
