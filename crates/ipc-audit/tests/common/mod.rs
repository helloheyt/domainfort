//! Sample events for the tests: typical ones, and the largest of each shape.
//!
//! Values are made up here from the field types the source crates expose
//! (crates/kdc, keyd, ldap audit.rs) and, for the admin-plane shapes, from
//! the operations and fields of docs/51 §5.2, §5.7, §7.3, §7.6; no fixture
//! comes from any other implementation.
#![allow(dead_code)]

use ipc_audit::{AccountExpiresValue, EnableDirection, GroupTypeCode};
use ipc_audit::{
    AdminFailure, AdminNameKind, AdminRefusal, AdmindActivity, AdmindEvent, Allocation, BoundedSeq,
    ConnectionRefusal, DecisionResult, DirAdminEvent, DirAdminOperation, DirAdminStage,
    ForwardDecision, FrameErrorCode, KeyadmOperation, OutcomeResult, PasswordFailure,
    PasswordResult, PasswordStep, TargetName, MAX_APPROVERS, MAX_REPORTED_KVNOS, MAX_TARGET_NAMES,
};
use ipc_audit::{
    AuditText, BindMechanism, CalendarTime, CodecError, CodecErrorCode, CodecLimit, EventBody,
    IpZone, KdcEvent, KdcExchange, KdcOutcome, KdcReason, KdcTransport, KeyPurposeCode, KeyRef,
    KeydOperation, KeydOutcome, KeydReason, KeydRecord, KeydRole, LdapAction, LdapBind, LdapEvent,
    LdapOperation, LdapReason, LdapSearch, LdapTarget, LdapTransport, PdpReason, PdpReasonCode,
    Principal, ReportedAddress, SearchScope, SidValue, TransportSecurity, UnsupportedOpCode,
    WindowSummary, MAX_FILTER_ATTRS, MAX_NAME_COMPONENTS, MAX_SID_SUB_AUTHORITIES, MAX_TEXT_OCTETS,
};

pub fn time() -> CalendarTime {
    CalendarTime::new(2026, 11, 13, 9, 30, 15).unwrap()
}

pub fn text(s: &str) -> AuditText {
    let kept = AuditText::from_client(s);
    assert!(!kept.is_withheld());
    kept
}

/// A string of the longest kept length.
pub fn longest_text(fill: char) -> AuditText {
    text(&fill.to_string().repeat(MAX_TEXT_OCTETS))
}

pub fn principal(name: &str) -> Principal {
    Principal::new(text("EXAMPLE.TEST"), 1, vec![text(name)])
}

pub fn largest_principal(fill: char) -> Principal {
    Principal::new(
        longest_text(fill),
        i32::MIN,
        (0..MAX_NAME_COMPONENTS)
            .map(|_| longest_text(fill))
            .collect(),
    )
}

pub fn kdc_event() -> KdcEvent {
    KdcEvent {
        time: time(),
        transport: KdcTransport::Tcp,
        exchange: Some(KdcExchange::As),
        client: Some(principal("alice")),
        service: Some(Principal::new(
            text("EXAMPLE.TEST"),
            2,
            vec![text("krbtgt"), text("EXAMPLE.TEST")],
        )),
        armor_principal: Some(principal("host1$")),
        reply_armored: true,
        outcome: KdcOutcome::Issued,
        reason: KdcReason::Issued,
        policy_reason: None,
    }
}

pub fn kdc_policy_denied() -> KdcEvent {
    KdcEvent {
        outcome: KdcOutcome::Refused { error_code: 12 },
        reason: KdcReason::PolicyDenied,
        policy_reason: Some(PdpReason {
            code: PdpReasonCode::CoarseDeny,
            rule: Some(7),
        }),
        ..kdc_event()
    }
}

pub fn largest_kdc_event() -> KdcEvent {
    KdcEvent {
        time: time(),
        transport: KdcTransport::Udp,
        exchange: Some(KdcExchange::Tgs),
        client: Some(largest_principal('c')),
        service: Some(largest_principal('s')),
        armor_principal: Some(largest_principal('a')),
        reply_armored: false,
        outcome: KdcOutcome::Refused {
            error_code: i32::MAX,
        },
        reason: KdcReason::PolicyDenied,
        policy_reason: Some(PdpReason {
            code: PdpReasonCode::CoarseDeny,
            rule: Some(u32::MAX),
        }),
    }
}

pub fn keyd_record() -> KeydRecord {
    KeydRecord {
        ts: time(),
        caller_role: KeydRole::Kdc,
        caller_uid: 803,
        op: KeydOperation::IssueAsRep,
        principal: Some([0x11; 16]),
        purpose: Some(KeyPurposeCode::PrincipalLongterm),
        kvno: Some(3),
        secondary: Some(KeyRef {
            principal: [0x22; 16],
            purpose: KeyPurposeCode::Krbtgt,
            kvno: Some(9),
        }),
        approvers: None,
        result: KeydOutcome::Success,
        reason: KeydReason::None,
        decision: None,
    }
}

/// keyd-daemon's intent record of a key-state change (decision A-86):
/// `SetSecret` by the directory, before keyd runs it — no kvno (keyd chooses
/// it), reason `None`.
pub fn keyd_intent_record() -> KeydRecord {
    KeydRecord {
        ts: time(),
        caller_role: KeydRole::Directory,
        caller_uid: 806,
        op: KeydOperation::SetSecret,
        principal: Some([0x55; 16]),
        purpose: Some(KeyPurposeCode::PrincipalLongterm),
        kvno: None,
        secondary: None,
        approvers: None,
        result: KeydOutcome::Intent,
        reason: KeydReason::None,
        decision: None,
    }
}

/// keyd-daemon's not-performed outcome of a key-state change whose intent
/// was not acknowledged in time (decision A-86): `RetireKvno` by the admin,
/// naming kvno 4.
pub fn keyd_not_performed_record() -> KeydRecord {
    KeydRecord {
        caller_role: KeydRole::Admin,
        caller_uid: 807,
        op: KeydOperation::RetireKvno,
        purpose: Some(KeyPurposeCode::Service),
        kvno: Some(4),
        result: KeydOutcome::NotPerformed,
        ..keyd_intent_record()
    }
}

pub fn largest_keyd_record() -> KeydRecord {
    KeydRecord {
        approvers: Some([[0x33; 16], [0x44; 16]]),
        op: KeydOperation::RotateKrbtgt,
        caller_role: KeydRole::Admin,
        result: KeydOutcome::Denied,
        reason: KeydReason::DualControlRejected,
        decision: Some(u64::MAX),
        ..keyd_record()
    }
}

pub fn ldap_event() -> LdapEvent {
    LdapEvent {
        time: time(),
        connection_id: 4242,
        source_zone: IpZone::Internal,
        reported_peer: ReportedAddress::new(core::net::IpAddr::V4(core::net::Ipv4Addr::new(
            10, 0, 0, 9,
        ))),
        transport: LdapTransport::StartTls,
        transport_sec: TransportSecurity {
            encrypted: true,
            sealed: false,
            channel_bound: false,
        },
        operation: LdapOperation::Search,
        message_id: Some(7),
        principal: Some(SidValue::new([0, 0, 0, 0, 0, 5], vec![21, 1, 2, 3, 1104]).unwrap()),
        bind: None,
        target: Some(LdapTarget::DirObject([0x5A; 16])),
        search: Some(LdapSearch::new(
            SearchScope::WholeSubtree,
            3,
            40,
            1,
            vec![text("servicePrincipalName"), text("objectClass")],
        )),
        result_code: Some(0),
        notice: None,
        action: LdapAction::Continue,
        reason: LdapReason::SearchCompleted,
        policy_reason: None,
        codec_error: None,
    }
}

pub fn ldap_malformed() -> LdapEvent {
    LdapEvent {
        operation: LdapOperation::Malformed,
        message_id: None,
        principal: None,
        target: None,
        search: None,
        result_code: None,
        notice: Some(2),
        action: LdapAction::Close,
        reason: LdapReason::Malformed,
        codec_error: Some(CodecError {
            error: CodecErrorCode::LimitExceeded,
            limit: Some(CodecLimit::FilterDepth),
        }),
        ..ldap_event()
    }
}

pub fn largest_ldap_event() -> LdapEvent {
    LdapEvent {
        time: time(),
        connection_id: u64::MAX,
        source_zone: IpZone::External,
        // The longer family (docs/52 R14: 1 + 16 octets).
        reported_peer: ReportedAddress::new(core::net::IpAddr::V6(core::net::Ipv6Addr::new(
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ))),
        transport: LdapTransport::Ldaps,
        transport_sec: TransportSecurity {
            encrypted: true,
            sealed: true,
            channel_bound: true,
        },
        operation: LdapOperation::NotSupported(UnsupportedOpCode::ModifyDnRequest),
        message_id: Some(u32::MAX),
        principal: Some(SidValue::new([0xFF; 6], vec![u32::MAX; MAX_SID_SUB_AUTHORITIES]).unwrap()),
        bind: Some(LdapBind {
            version: 3,
            mechanism: BindMechanism::Sasl {
                mechanism: longest_text('m'),
            },
            name: Some(longest_text('n')),
        }),
        target: Some(LdapTarget::DirObject([0xFF; 16])),
        search: Some(LdapSearch::new(
            SearchScope::Unrecognized,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            (0..MAX_FILTER_ATTRS + 5)
                .map(|_| longest_text('f'))
                .collect(),
        )),
        result_code: Some(u8::MAX),
        notice: Some(u8::MAX),
        action: LdapAction::Close,
        reason: LdapReason::PolicyDenied,
        policy_reason: Some(PdpReason {
            code: PdpReasonCode::CoarseDeny,
            rule: Some(u32::MAX),
        }),
        codec_error: Some(CodecError {
            error: CodecErrorCode::LimitExceeded,
            limit: Some(CodecLimit::Unlisted),
        }),
    }
}

pub fn summary() -> WindowSummary {
    WindowSummary {
        suppressed_noise: 12,
        refused_gating: 3,
        unrecorded_outcomes: 2,
    }
}

// ---- the admin plane (docs/51 §5.7) -----------------------------------------

/// A domain SID ‖ RID, made up here (the form S-1-5-21-r1-r2-r3-RID quoted
/// from [MS-DTYP] 2.4.2.4 in docs/51 §0.1 / R51-3).
pub fn domain_sid(rid: u32) -> SidValue {
    SidValue::new([0, 0, 0, 0, 0, 5], vec![21, 1001, 2002, 3003, rid]).unwrap()
}

/// The largest SID: authority all-ones, 15 sub-authorities of all-ones.
pub fn largest_sid() -> SidValue {
    SidValue::new([0xFF; 6], vec![u32::MAX; MAX_SID_SUB_AUTHORITIES]).unwrap()
}

pub fn name(kind: AdminNameKind, s: &str) -> TargetName {
    TargetName {
        kind,
        text: text(s),
    }
}

/// docs/51 §5.2 row 1: `CreateUser {parent, sam, upn?}` — the decision,
/// allowed, before the commit (no target yet: the object does not exist).
pub fn dir_admin_create_decision() -> DirAdminEvent {
    DirAdminEvent {
        time: time(),
        operation_id: 41,
        operation: DirAdminOperation::CreateUser,
        stage: DirAdminStage::Decision(DecisionResult::Proceed),
        target: None,
        parent: Some([0x0A; 16]),
        member: None,
        requester: Some(domain_sid(1105)),
        approvers: BoundedSeq::empty(),
        pdp: Some(PdpReason {
            code: PdpReasonCode::Allowed,
            rule: None,
        }),
        names: BoundedSeq::new(vec![
            name(AdminNameKind::SamAccountName, "carol"),
            name(AdminNameKind::UserPrincipalName, "carol@example.test"),
        ])
        .unwrap(),
        enable: None,
        account_expires: None,
        group_type: None,
        pending_request: None,
        key_operation: None,
        reported_kvnos: BoundedSeq::empty(),
        operation_digest: [0x9C; 32],
        proposed: None,
        reason_ref: None,
    }
}

/// docs/51 §5.2 row 6: `SetEnabled` disabling an account (Q-340 item 5:
/// the direction is recorded).
pub fn dir_admin_disable() -> DirAdminEvent {
    DirAdminEvent {
        operation_id: 45,
        operation: DirAdminOperation::SetEnabled,
        target: Some([0x0F; 16]),
        parent: None,
        names: BoundedSeq::empty(),
        enable: Some(EnableDirection::Disable),
        ..dir_admin_create_decision()
    }
}

/// docs/51 §5.2 row 7: `SetAccountExpires` at a FILETIME (Q-340 item 5).
pub fn dir_admin_expires_at() -> DirAdminEvent {
    DirAdminEvent {
        operation_id: 46,
        operation: DirAdminOperation::SetAccountExpires,
        target: Some([0x0F; 16]),
        parent: None,
        names: BoundedSeq::empty(),
        account_expires: Some(AccountExpiresValue::at(0x01DC_5000_0000_0000)),
        ..dir_admin_create_decision()
    }
}

/// docs/51 §5.2 row 3: `CreateGroup` with groupType SECURITY_ENABLED |
/// ACCOUNT (`0x80000002`, the default there) (Q-340 item 5).
pub fn dir_admin_create_group() -> DirAdminEvent {
    DirAdminEvent {
        operation_id: 47,
        operation: DirAdminOperation::CreateGroup,
        names: BoundedSeq::new(vec![name(AdminNameKind::SamAccountName, "ops")]).unwrap(),
        group_type: Some(GroupTypeCode::SecurityAccountGroup),
        ..dir_admin_create_decision()
    }
}

/// The same operation's outcome: committed, with the GUID and RID dird
/// allocated (docs/51 §7.4 step 5, §8.3).
pub fn dir_admin_create_outcome() -> DirAdminEvent {
    DirAdminEvent {
        stage: DirAdminStage::Outcome(OutcomeResult::Committed {
            allocated: Some(Allocation {
                guid: [0xC7; 16],
                rid: Some(1106),
            }),
        }),
        ..dir_admin_create_decision()
    }
}

/// docs/51 §5.2 row 8 + §5.6: `AddMember` to a tier-0 group, refused
/// because the approval is missing.
pub fn dir_admin_refused() -> DirAdminEvent {
    DirAdminEvent {
        operation_id: 42,
        operation: DirAdminOperation::AddMember,
        stage: DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::ApprovalRequired)),
        target: Some([0x0B; 16]),
        parent: None,
        member: Some([0x0C; 16]),
        names: BoundedSeq::empty(),
        ..dir_admin_create_decision()
    }
}

/// docs/51 §7.4 step 1: the requester's AP-REQ could not be verified
/// because keyd did not answer — no requester, no PDP decision.
pub fn dir_admin_failed() -> DirAdminEvent {
    DirAdminEvent {
        operation_id: 43,
        operation: DirAdminOperation::Delete,
        stage: DirAdminStage::Decision(DecisionResult::Failed(AdminFailure::KeydUnavailable)),
        target: Some([0x0D; 16]),
        parent: None,
        requester: None,
        pdp: None,
        names: BoundedSeq::empty(),
        ..dir_admin_create_decision()
    }
}

/// docs/51 §6: keyadm's `Complete` of an approved krbtgt rotation, with the
/// kvno keyadm reports and the approver.
pub fn dir_admin_key_complete() -> DirAdminEvent {
    DirAdminEvent {
        operation_id: 44,
        operation: DirAdminOperation::Complete,
        stage: DirAdminStage::Decision(DecisionResult::Proceed),
        target: Some([0x0E; 16]),
        parent: None,
        approvers: BoundedSeq::new(vec![domain_sid(1107)]).unwrap(),
        names: BoundedSeq::empty(),
        pending_request: Some(9),
        key_operation: Some(KeydOperation::RotateKrbtgt),
        reported_kvnos: BoundedSeq::new(vec![3]).unwrap(),
        ..dir_admin_create_decision()
    }
}

/// The largest `DirAdmin` event: every optional field present, every
/// sequence at its bound, every SID at 15 sub-authorities, every name at
/// 256 octets.
pub fn largest_dir_admin() -> DirAdminEvent {
    DirAdminEvent {
        time: time(),
        operation_id: u64::MAX,
        operation: DirAdminOperation::ListPendingDestruction,
        stage: DirAdminStage::Outcome(OutcomeResult::Committed {
            allocated: Some(Allocation {
                guid: [0xFF; 16],
                rid: Some(u32::MAX),
            }),
        }),
        target: Some([0xFF; 16]),
        parent: Some([0xFE; 16]),
        member: Some([0xFD; 16]),
        requester: Some(largest_sid()),
        approvers: BoundedSeq::new(vec![largest_sid(); MAX_APPROVERS]).unwrap(),
        pdp: Some(PdpReason {
            code: PdpReasonCode::CoarseDeny,
            rule: Some(u32::MAX),
        }),
        names: BoundedSeq::new(
            (0..MAX_TARGET_NAMES)
                .map(|_| TargetName {
                    kind: AdminNameKind::DistinguishedName,
                    text: longest_text('d'),
                })
                .collect(),
        )
        .unwrap(),
        enable: Some(EnableDirection::Disable),
        account_expires: Some(AccountExpiresValue::at(u64::MAX)),
        group_type: Some(GroupTypeCode::SecurityUniversalGroup),
        pending_request: Some(u64::MAX),
        key_operation: Some(KeydOperation::Ping),
        reported_kvnos: BoundedSeq::new(vec![u32::MAX; MAX_REPORTED_KVNOS]).unwrap(),
        operation_digest: [0xFF; 32],
        proposed: Some(DirAdminOperation::ShowRequest),
        reason_ref: Some(longest_text('r')),
    }
}

/// docs/51 §5.7 item 3: a refused `admin.sock` connection (noise).
pub fn admind_connection_refused() -> AdmindEvent {
    AdmindEvent {
        time: time(),
        peer_uid: Some(1500),
        activity: AdmindActivity::ConnectionRefused {
            reason: ConnectionRefusal::ConnectionLimit,
        },
    }
}

/// docs/51 §5.7 item 3: a malformed `admin.sock` frame (noise), class
/// only.
pub fn admind_malformed() -> AdmindEvent {
    AdmindEvent {
        peer_uid: None,
        activity: AdmindActivity::MalformedFrame {
            error: FrameErrorCode::TrailingBytes,
        },
        ..admind_connection_refused()
    }
}

/// docs/51 §5.2 row 5, §7.6: a computer's `SetPassword` completed — two
/// `set_secret` calls, two kvnos.
pub fn admind_set_password() -> AdmindEvent {
    AdmindEvent {
        activity: AdmindActivity::SetPassword {
            target: [0x5E; 16],
            operation_digest: [0x9C; 32],
            kvnos: BoundedSeq::new(vec![4, 2]).unwrap(),
            result: PasswordResult::Completed,
        },
        ..admind_connection_refused()
    }
}

/// docs/51 §9 ("password set" row): the second `set_secret` (Service) of a
/// computer failed — one kvno recorded.
pub fn admind_set_password_failed() -> AdmindEvent {
    AdmindEvent {
        activity: AdmindActivity::SetPassword {
            target: [0x5E; 16],
            operation_digest: [0x9C; 32],
            kvnos: BoundedSeq::new(vec![5]).unwrap(),
            result: PasswordResult::Failed {
                step: PasswordStep::SetSecret(KeyPurposeCode::Service),
                cause: PasswordFailure::Unavailable,
            },
        },
        ..admind_connection_refused()
    }
}

/// docs/51 §6: `FetchApproved` from a uid that is not `keyadm_uid`.
pub fn admind_keyadm_refused() -> AdmindEvent {
    AdmindEvent {
        activity: AdmindActivity::KeyadmForward {
            operation: KeyadmOperation::FetchApproved,
            decision: ForwardDecision::PeerNotKeyadm,
        },
        ..admind_connection_refused()
    }
}

/// Task F6 (docs/questions/Q-406 item 3): a frame dropped by the per-uid
/// request rate (noise).
pub fn admind_rate_limited() -> AdmindEvent {
    AdmindEvent {
        activity: AdmindActivity::RateLimited,
        ..admind_connection_refused()
    }
}

/// The largest `Admind` event.
pub fn largest_admind() -> AdmindEvent {
    AdmindEvent {
        time: time(),
        peer_uid: Some(u32::MAX),
        activity: AdmindActivity::SetPassword {
            target: [0xFF; 16],
            operation_digest: [0x9C; 32],
            kvnos: BoundedSeq::new(vec![u32::MAX; MAX_REPORTED_KVNOS]).unwrap(),
            result: PasswordResult::Failed {
                step: PasswordStep::SetSecret(KeyPurposeCode::PrincipalLongterm),
                cause: PasswordFailure::VersionMismatch,
            },
        },
    }
}

/// One admin-plane event of every variant (every stage and result of
/// `DirAdmin`, every activity of `Admind`).
pub fn admin_samples() -> Vec<EventBody> {
    let dir_admin = [
        dir_admin_create_decision(),
        dir_admin_create_outcome(),
        dir_admin_refused(),
        dir_admin_failed(),
        dir_admin_key_complete(),
        largest_dir_admin(),
        dir_admin_disable(),
        dir_admin_expires_at(),
        dir_admin_create_group(),
        DirAdminEvent {
            enable: Some(EnableDirection::Enable),
            ..dir_admin_disable()
        },
        DirAdminEvent {
            account_expires: Some(AccountExpiresValue::NEVER),
            ..dir_admin_expires_at()
        },
        DirAdminEvent {
            // A refused request records the value it named (0 is refused,
            // docs/51 §5.2 row 7).
            stage: DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::ValueInvalid)),
            account_expires: Some(AccountExpiresValue::at(0)),
            ..dir_admin_expires_at()
        },
        DirAdminEvent {
            stage: DirAdminStage::Outcome(OutcomeResult::Refused(AdminRefusal::Conflict)),
            ..dir_admin_create_decision()
        },
        DirAdminEvent {
            stage: DirAdminStage::Outcome(OutcomeResult::Failed(AdminFailure::StoreFailure)),
            ..dir_admin_create_decision()
        },
        DirAdminEvent {
            stage: DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None }),
            operation: DirAdminOperation::SetEnabled,
            ..dir_admin_refused()
        },
        // Task A10 (Q-421): the appended key-request codes.
        DirAdminEvent {
            stage: DirAdminStage::Decision(DecisionResult::Refused(
                AdminRefusal::OperationMismatch,
            )),
            operation: DirAdminOperation::Approve,
            ..dir_admin_key_complete()
        },
        DirAdminEvent {
            stage: DirAdminStage::Outcome(OutcomeResult::Refused(
                AdminRefusal::KeyOperationRefused,
            )),
            ..dir_admin_key_complete()
        },
        DirAdminEvent {
            stage: DirAdminStage::Outcome(OutcomeResult::Failed(
                AdminFailure::KeyOperationNotPerformed,
            )),
            ..dir_admin_key_complete()
        },
        DirAdminEvent {
            stage: DirAdminStage::Outcome(OutcomeResult::Failed(
                AdminFailure::KeyOperationOutcomeUnknown,
            )),
            ..dir_admin_key_complete()
        },
    ];
    let admind = [
        admind_connection_refused(),
        admind_malformed(),
        admind_set_password(),
        admind_set_password_failed(),
        admind_keyadm_refused(),
        largest_admind(),
        AdmindEvent {
            activity: AdmindActivity::KeyadmForward {
                operation: KeyadmOperation::ListPendingDestruction,
                decision: ForwardDecision::Forwarded,
            },
            ..admind_connection_refused()
        },
        AdmindEvent {
            activity: AdmindActivity::SetPassword {
                target: [1; 16],
                operation_digest: [0x9C; 32],
                kvnos: BoundedSeq::empty(),
                result: PasswordResult::Failed {
                    step: PasswordStep::Validation,
                    cause: PasswordFailure::PasswordPolicy,
                },
            },
            ..admind_connection_refused()
        },
        // Task F6 (A-94, Q-406): the three appended codes.
        admind_rate_limited(),
        AdmindEvent {
            activity: AdmindActivity::MalformedFrame {
                error: FrameErrorCode::ValueRefused,
            },
            ..admind_connection_refused()
        },
        AdmindEvent {
            activity: AdmindActivity::SetPassword {
                target: [2; 16],
                operation_digest: [0x9C; 32],
                kvnos: BoundedSeq::empty(),
                result: PasswordResult::Failed {
                    step: PasswordStep::SetSecret(KeyPurposeCode::PrincipalLongterm),
                    cause: PasswordFailure::OutcomeUnknown,
                },
            },
            ..admind_connection_refused()
        },
    ];
    dir_admin
        .into_iter()
        .map(|e| EventBody::DirAdmin(Box::new(e)))
        .chain(admind.into_iter().map(|e| EventBody::Admind(Box::new(e))))
        .collect()
}

/// One event of every shape, typical and largest.
pub fn all_samples() -> Vec<EventBody> {
    vec![
        EventBody::Kdc(Box::new(kdc_event())),
        EventBody::Kdc(Box::new(kdc_policy_denied())),
        EventBody::Kdc(Box::new(largest_kdc_event())),
        EventBody::Keyd(Box::new(keyd_record())),
        EventBody::Keyd(Box::new(largest_keyd_record())),
        EventBody::Keyd(Box::new(keyd_intent_record())),
        EventBody::Keyd(Box::new(keyd_not_performed_record())),
        EventBody::Ldap(Box::new(ldap_event())),
        EventBody::Ldap(Box::new(ldap_malformed())),
        EventBody::Ldap(Box::new(largest_ldap_event())),
        EventBody::WindowSummary(summary()),
    ]
    .into_iter()
    .chain(admin_samples())
    .collect()
}
