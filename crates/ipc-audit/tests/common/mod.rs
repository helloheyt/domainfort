//! Sample events for the tests: typical ones, and the largest of each shape.
//!
//! Values are made up here from the field types the source crates expose
//! (crates/kdc, keyd, ldap audit.rs); no fixture comes from any other
//! implementation.
#![allow(dead_code)]

use ipc_audit::{
    AuditText, BindMechanism, CalendarTime, CodecError, CodecErrorCode, CodecLimit, EventBody,
    IpZone, KdcEvent, KdcExchange, KdcOutcome, KdcReason, KdcTransport, KeyPurposeCode, KeyRef,
    KeydOperation, KeydOutcome, KeydReason, KeydRecord, KeydRole, LdapAction, LdapBind, LdapEvent,
    LdapOperation, LdapReason, LdapSearch, LdapTarget, LdapTransport, PdpReason, PdpReasonCode,
    Principal, SearchScope, SidValue, TransportSecurity, UnsupportedOpCode, WindowSummary,
    MAX_FILTER_ATTRS, MAX_NAME_COMPONENTS, MAX_SID_SUB_AUTHORITIES, MAX_TEXT_OCTETS,
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
    }
}

pub fn largest_keyd_record() -> KeydRecord {
    KeydRecord {
        approvers: Some([[0x33; 16], [0x44; 16]]),
        op: KeydOperation::RotateKrbtgt,
        caller_role: KeydRole::Admin,
        result: KeydOutcome::Denied,
        reason: KeydReason::DualControlRejected,
        ..keyd_record()
    }
}

pub fn ldap_event() -> LdapEvent {
    LdapEvent {
        time: time(),
        connection_id: 4242,
        source_zone: IpZone::Internal,
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
    }
}

/// One event of every shape, typical and largest.
pub fn all_samples() -> Vec<EventBody> {
    vec![
        EventBody::Kdc(Box::new(kdc_event())),
        EventBody::Kdc(Box::new(kdc_policy_denied())),
        EventBody::Kdc(Box::new(largest_kdc_event())),
        EventBody::Keyd(Box::new(keyd_record())),
        EventBody::Keyd(Box::new(largest_keyd_record())),
        EventBody::Ldap(Box::new(ldap_event())),
        EventBody::Ldap(Box::new(ldap_malformed())),
        EventBody::Ldap(Box::new(largest_ldap_event())),
        EventBody::WindowSummary(summary()),
    ]
}
