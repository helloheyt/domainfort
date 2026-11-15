//! The admin-plane shapes `DirAdmin` (dird) and `Admind` (admind): round
//! trips of every variant, the exact wire layout, every bound, the closed
//! code tables, strict decoding, the noise rule, and `peek_shape`.
//!
//! Source: docs/51 §5.7 (R51-12, decided A-72: dird is the source of the
//! admin write events — decision acknowledged before the commit, outcome
//! after; admind records refused connections, malformed frames and
//! `SetPassword`), §5.6 (approvers), §6 and §7.3 (operations, keyadm-only
//! requests), §7.6 (`SetPassword` steps), §8.3 (RID); docs/50 §3.3 (exact
//! version, closed kinds, no trailing octet, one encoding per value), §8.2;
//! docs/37 §2; docs/questions/Q-218 (A-57), Q-252 item 8 (A-64). The
//! expected octets are assembled here from this crate's documented layout
//! (crate::admin); no fixture comes from any other implementation.

mod common;

use common::*;
use ipc_audit::{
    decode_event, encode_event, event_round_trip_is_canonical, peek_shape, AdminFailure,
    AdminNameKind, AdminRefusal, AdmindActivity, AdmindEvent, BoundedSeq, ConnectionRefusal,
    DecisionResult, DirAdminEvent, DirAdminOperation, DirAdminStage, EventBody, EventError,
    EventShape, FrameErrorCode, KeyPurposeCode, NoiseAdmission, OutcomeResult, PasswordFailure,
    PasswordResult, PasswordStep, PdpReason, PdpReasonCode, SendWindow, SidValue, TargetName,
    WindowConfig, WindowSummary, EVENT_FORMAT, MAX_APPROVERS, MAX_EVENT_OCTETS, MAX_REPORTED_KVNOS,
    MAX_TARGET_NAMES,
};
use ipc_audit::{AccountExpiresValue, EnableDirection, GroupTypeCode};

const TIME: [u8; 7] = [0x07, 0xEA, 11, 13, 9, 30, 15];

fn codec(error: ipc::Error) -> Result<EventBody, EventError> {
    Err(EventError::Codec(error))
}

/// docs/50 §3.3: every admin-plane variant decodes to itself and re-encodes
/// to the same octets; the envelope carries the format and the shape.
#[test]
fn every_admin_variant_round_trips() {
    for event in admin_samples() {
        let bytes = encode_event(&event).unwrap();
        assert_eq!(bytes.as_bytes()[0], EVENT_FORMAT);
        assert_eq!(bytes.as_bytes()[1], event.shape().code());
        assert_eq!(decode_event(bytes.as_bytes()).unwrap(), event);
        assert_eq!(event_round_trip_is_canonical(bytes.as_bytes()), Ok(true));
    }
}

// ---- DirAdmin: the exact layout ------------------------------------------------

/// A small `DirAdmin` event: `Delete` refused because the target was not
/// found (docs/51 §5.2 rows 9, 10).
fn delete_refused() -> DirAdminEvent {
    DirAdminEvent {
        time: time(),
        operation_id: 0x0102_0304_0506_0708,
        operation: DirAdminOperation::Delete,
        stage: DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::NotFound)),
        target: Some([0xAA; 16]),
        parent: None,
        member: None,
        requester: Some(SidValue::new([0, 0, 0, 0, 0, 5], vec![21, 7]).unwrap()),
        approvers: BoundedSeq::empty(),
        pdp: Some(PdpReason {
            code: PdpReasonCode::Allowed,
            rule: None,
        }),
        names: BoundedSeq::new(vec![name(AdminNameKind::SamAccountName, "ab")]).unwrap(),
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

/// Offsets of the fields the strictness tests patch.
struct DirAdminAt {
    operation: usize,
    phase: usize,
    result: usize,
    detail: usize,
    requester_count: usize,
    approvers_count: usize,
    names_count: usize,
    name_kind: usize,
    name_len: usize,
    name_text: usize,
    /// The marker of `enable`; `account_expires` and `group_type` follow,
    /// each one octet when absent.
    enable: usize,
    kvnos_count: usize,
    /// The operation digest (32 octets, task D2-c).
    digest: usize,
    /// The marker of `proposed`; `reason_ref`'s follows.
    proposed: usize,
}

/// The octets of [`delete_refused`], assembled field by field from the
/// layout in crate::admin.
fn delete_refused_octets() -> (Vec<u8>, DirAdminAt) {
    let mut x = vec![EVENT_FORMAT, 5]; // format, shape DirAdmin
    x.extend(TIME);
    x.extend(0x0102_0304_0506_0708u64.to_be_bytes()); // operation_id
    let operation = x.len();
    x.push(12); // Delete
    let phase = x.len();
    x.push(1); // Decision
    let result = x.len();
    x.push(2); // Refused
    let detail = x.len();
    x.push(12); // NotFound
    x.push(1); // target present
    x.extend([0xAA; 16]);
    x.push(0); // parent absent
    x.push(0); // member absent
    x.push(1); // requester present
    x.extend([0, 0, 0, 0, 0, 5]); // identifier authority
    let requester_count = x.len();
    x.extend(2u32.to_be_bytes()); // sub-authority count
    x.extend(21u32.to_be_bytes());
    x.extend(7u32.to_be_bytes());
    let approvers_count = x.len();
    x.extend(0u32.to_be_bytes()); // no approver
    x.extend([1, 1, 0]); // pdp present: Allowed, no rule id
    let names_count = x.len();
    x.extend(1u32.to_be_bytes()); // one name
    let name_kind = x.len();
    x.push(1); // SamAccountName
    x.push(1); // text kept
    let name_len = x.len();
    x.extend(2u32.to_be_bytes());
    let name_text = x.len();
    x.extend(b"ab");
    let enable = x.len();
    x.push(0); // enable absent
    x.push(0); // account_expires absent
    x.push(0); // group_type absent
    x.push(0); // pending_request absent
    x.push(0); // key_operation absent
    let kvnos_count = x.len();
    x.extend(0u32.to_be_bytes()); // no kvno
    let digest = x.len();
    x.extend([0x9C; 32]); // operation_digest (task D2-c, Q-888)
    let proposed = x.len();
    x.push(0); // proposed absent
    x.push(0); // reason_ref absent
    let at = DirAdminAt {
        operation,
        phase,
        result,
        detail,
        requester_count,
        approvers_count,
        names_count,
        name_kind,
        name_len,
        name_text,
        enable,
        kvnos_count,
        digest,
        proposed,
    };
    (x, at)
}

/// The documented positional layout, octet for octet.
#[test]
fn dir_admin_wire_layout() {
    let event = EventBody::DirAdmin(Box::new(delete_refused()));
    let (expected, _) = delete_refused_octets();
    assert_eq!(encode_event(&event).unwrap().as_bytes(), &expected[..]);
    assert_eq!(decode_event(&expected).unwrap(), event);

    // An outcome that committed a create: phase 2, result 1, then the
    // allocation (GUID, RID).
    let committed = DirAdminEvent {
        stage: DirAdminStage::Outcome(OutcomeResult::Committed {
            allocated: Some(ipc_audit::Allocation {
                guid: [0xC7; 16],
                rid: Some(1106),
            }),
        }),
        ..delete_refused()
    };
    let (base, at) = delete_refused_octets();
    let mut expected = base[..at.phase].to_vec();
    expected.extend([2, 1, 1]);
    expected.extend([0xC7; 16]);
    expected.push(1);
    expected.extend(1106u32.to_be_bytes());
    expected.extend(&base[at.detail + 1..]);
    let event = EventBody::DirAdmin(Box::new(committed));
    assert_eq!(encode_event(&event).unwrap().as_bytes(), &expected[..]);
    assert_eq!(decode_event(&expected).unwrap(), event);
}

/// Q-340 item 5: the request values, each an optional positional field after
/// `names` — `enable` (`00` | `01 ‖ Enable 1 / Disable 2`), `account_expires`
/// (`00` | `01 ‖ Never 1` | `01 ‖ At 2 ‖ filetime u64`), `group_type`
/// (`00` | `01 ‖ code 1..6`) — octet for octet.
#[test]
fn dir_admin_request_values_layout() {
    let (base, at) = delete_refused_octets();
    let with = |values: &[u8]| {
        // `base` has the three markers 00 00 00 at `at.enable`.
        let mut x = base[..at.enable].to_vec();
        x.extend(values);
        x.extend(&base[at.enable + 3..]);
        x
    };
    let ft: u64 = 0x01DC_5000_0000_0000;
    let cases: Vec<(DirAdminEvent, Vec<u8>)> = vec![
        (
            DirAdminEvent {
                enable: Some(EnableDirection::Enable),
                ..delete_refused()
            },
            with(&[1, 1, 0, 0]),
        ),
        (
            DirAdminEvent {
                enable: Some(EnableDirection::Disable),
                ..delete_refused()
            },
            with(&[1, 2, 0, 0]),
        ),
        (
            DirAdminEvent {
                account_expires: Some(AccountExpiresValue::NEVER),
                ..delete_refused()
            },
            with(&[0, 1, 1, 0]),
        ),
        (
            DirAdminEvent {
                account_expires: Some(AccountExpiresValue::at(ft)),
                ..delete_refused()
            },
            with(&[[0u8, 1, 2].as_slice(), &ft.to_be_bytes(), &[0]].concat()),
        ),
        (
            DirAdminEvent {
                group_type: Some(GroupTypeCode::SecurityAccountGroup),
                ..delete_refused()
            },
            with(&[0, 0, 1, 4]),
        ),
        (
            DirAdminEvent {
                enable: Some(EnableDirection::Disable),
                account_expires: Some(AccountExpiresValue::at(0)),
                group_type: Some(GroupTypeCode::UniversalGroup),
                ..delete_refused()
            },
            with(&[[1u8, 2, 1, 2].as_slice(), &0u64.to_be_bytes(), &[1, 3]].concat()),
        ),
    ];
    for (event, expected) in cases {
        let event = EventBody::DirAdmin(Box::new(event));
        assert_eq!(encode_event(&event).unwrap().as_bytes(), &expected[..]);
        assert_eq!(decode_event(&expected).unwrap(), event);
    }
}

/// Q-340 item 5, strictness: unknown direction / expiry / groupType codes
/// are refused; "never" has one spelling (`At 0x7FFFFFFFFFFFFFFF` is
/// refused, and `at()` of that value is `NEVER`); a group type outside the
/// six is not representable.
#[test]
fn dir_admin_request_values_strict() {
    let (base, at) = delete_refused_octets();
    let with = |values: &[u8]| {
        let mut x = base[..at.enable].to_vec();
        x.extend(values);
        x.extend(&base[at.enable + 3..]);
        x
    };
    for bad in [
        with(&[1, 0, 0, 0]),
        with(&[1, 3, 0, 0]),
        with(&[1, 0xFF, 0, 0]),
        with(&[0, 1, 0, 0]),
        with(&[0, 1, 3, 0]),
        with(&[0, 0, 1, 0]),
        with(&[0, 0, 1, 7]),
        with(&[0, 0, 1, 0xFF]),
    ] {
        assert_eq!(decode_event(&bad), codec(ipc::Error::UnknownCode));
    }
    // A marker that is not 00 / 01.
    assert_eq!(
        decode_event(&with(&[2, 0, 0])),
        codec(ipc::Error::InvalidBoolean)
    );
    // "never" spelled as At: a second encoding of the same meaning.
    let never_at = with(
        &[
            [0u8, 1, 2].as_slice(),
            &0x7FFF_FFFF_FFFF_FFFFu64.to_be_bytes(),
            &[0],
        ]
        .concat(),
    );
    assert_eq!(decode_event(&never_at), codec(ipc::Error::UnknownCode));
    assert_eq!(
        AccountExpiresValue::at(0x7FFF_FFFF_FFFF_FFFF),
        AccountExpiresValue::NEVER
    );
    assert!(AccountExpiresValue::NEVER.is_never());
    assert_eq!(AccountExpiresValue::NEVER.filetime(), None);
    assert_eq!(AccountExpiresValue::at(0).filetime(), Some(0));
    assert_eq!(AccountExpiresValue::at(u64::MAX).filetime(), Some(u64::MAX));
    // Encoding at() of the never value gives the Never spelling.
    let event = EventBody::DirAdmin(Box::new(DirAdminEvent {
        account_expires: Some(AccountExpiresValue::at(0x7FFF_FFFF_FFFF_FFFF)),
        ..delete_refused()
    }));
    assert_eq!(
        encode_event(&event).unwrap().as_bytes(),
        &with(&[0, 1, 1, 0])[..]
    );
    // An At truncated inside its FILETIME.
    let short = with(&[0, 1, 2, 0, 0, 0]);
    assert!(decode_event(&short[..at.enable + 6]).is_err());
}

/// The six groupType codes are exactly the values the repository already
/// allows: crates/ad-schema `flags::group_type::ALLOWED_VALUES` ([MS-ADTS]
/// 2.2.12 as cited there; docs/46 §8.2, R46-6), in the same order; and
/// docs/51 §5.2 row 3's default `0x80000002` is one of them.
#[test]
fn group_type_codes_match_the_schema() {
    let ours: Vec<u32> = GroupTypeCode::ALL.iter().map(|c| c.group_type()).collect();
    let schema: Vec<u32> = ad_schema::flags::group_type::ALLOWED_VALUES
        .iter()
        .map(|v| u32::from_be_bytes(v.to_be_bytes()))
        .collect();
    assert_eq!(ours, schema);
    assert_eq!(
        GroupTypeCode::from_group_type(0x8000_0002),
        Some(GroupTypeCode::SecurityAccountGroup)
    );
    for code in GroupTypeCode::ALL {
        assert_eq!(
            GroupTypeCode::from_group_type(code.group_type()),
            Some(*code)
        );
    }
    // BUILTIN_LOCAL, APP_BASIC, APP_QUERY, combinations, 0: not one of six.
    for value in [0u32, 1, 0x10, 0x20, 0x8000_0001, 0x6, 0x8000_0000, u32::MAX] {
        assert_eq!(GroupTypeCode::from_group_type(value), None, "{value:#x}");
    }
}

/// Each phase has its own closed result table: a code outside it is
/// refused, and reading one phase's octets as the other's is either refused
/// or a different, canonical event — never a second encoding.
#[test]
fn dir_admin_phase_and_result_tables() {
    let (good, at) = delete_refused_octets();
    let patched = |position: usize, value: u8| {
        let mut b = good.clone();
        b[position] = value;
        b
    };
    for phase in [0u8, 3, 0xFF] {
        assert_eq!(
            decode_event(&patched(at.phase, phase)),
            codec(ipc::Error::UnknownCode)
        );
    }
    for result in [0u8, 4, 0xFF] {
        assert_eq!(
            decode_event(&patched(at.result, result)),
            codec(ipc::Error::UnknownCode)
        );
    }
    // Decision ‖ Failed ‖ 12: no failure code 12 (the table has 6 since task
    // F4 appended two, A-91).
    assert_eq!(
        decode_event(&patched(at.result, 3)),
        codec(ipc::Error::UnknownCode)
    );
    // Decision ‖ Failed ‖ 2 = StoreFailure.
    let mut b = patched(at.result, 3);
    b[at.detail] = 2;
    match decode_event(&b).unwrap() {
        EventBody::DirAdmin(e) => assert_eq!(
            e.stage,
            DirAdminStage::Decision(DecisionResult::Failed(AdminFailure::StoreFailure))
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(event_round_trip_is_canonical(&b), Ok(true));
    // Outcome ‖ Refused ‖ NotFound: valid, canonical.
    let b = patched(at.phase, 2);
    match decode_event(&b).unwrap() {
        EventBody::DirAdmin(e) => assert_eq!(
            e.stage,
            DirAdminStage::Outcome(OutcomeResult::Refused(AdminRefusal::NotFound))
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(event_round_trip_is_canonical(&b), Ok(true));
    // Outcome ‖ Committed reads an allocation marker where the refusal code
    // was (12): not a marker.
    let mut b = patched(at.phase, 2);
    b[at.result] = 1;
    assert_eq!(decode_event(&b), codec(ipc::Error::InvalidBoolean));
    // Codes past the refusal table (19 entries since task A3 appended
    // `SelfLockout`, 20 since task F4 appended `ObligationRefused`, A-91,
    // 22 since task A10 appended `OperationMismatch` and
    // `KeyOperationRefused`, Q-421, 25 since task D2-c appended
    // `ApprovalNotNeeded`, `RequestStale`, `RequesterLimit`, Q-938).
    for code in [0u8, 26, 0xFF] {
        assert_eq!(
            decode_event(&patched(at.detail, code)),
            codec(ipc::Error::UnknownCode)
        );
    }
    // The appended codes decode and re-encode canonically in place: refusal
    // 20 after `Decision ‖ Refused`, failures 5 and 6 after `Decision ‖
    // Failed` (Q-397).
    match decode_event(&patched(at.detail, 20)).unwrap() {
        EventBody::DirAdmin(e) => assert_eq!(
            e.stage,
            DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::ObligationRefused))
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        event_round_trip_is_canonical(&patched(at.detail, 20)),
        Ok(true)
    );
    for (code, failure) in [
        (5u8, AdminFailure::ViewUnavailable),
        (6, AdminFailure::AuditUnacknowledged),
    ] {
        let mut b = patched(at.result, 3);
        b[at.detail] = code;
        match decode_event(&b).unwrap() {
            EventBody::DirAdmin(e) => assert_eq!(
                e.stage,
                DirAdminStage::Decision(DecisionResult::Failed(failure))
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(event_round_trip_is_canonical(&b), Ok(true));
    }
    // Failures 7 and 8 (task A10, Q-421) decode; 9 is past the table.
    for (code, failure) in [
        (7u8, AdminFailure::KeyOperationNotPerformed),
        (8, AdminFailure::KeyOperationOutcomeUnknown),
    ] {
        let mut b = patched(at.result, 3);
        b[at.detail] = code;
        match decode_event(&b).unwrap() {
            EventBody::DirAdmin(e) => assert_eq!(
                e.stage,
                DirAdminStage::Decision(DecisionResult::Failed(failure))
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(event_round_trip_is_canonical(&b), Ok(true));
    }
    let mut b = patched(at.result, 3);
    b[at.detail] = 9;
    assert_eq!(decode_event(&b), codec(ipc::Error::UnknownCode));
}

/// docs/50 §3.3: unknown operation and name-kind codes are refused (task
/// A16 appended `ChangePolicy` = 19 and `PolicyChange` = 7; task D2-c
/// appended `Propose` .. `ShowRequest` = 20..24 — docs/questions/Q-938 —;
/// task K6 appended `ChangePassword` = 25 (docs/53 §9) — so the first
/// unknown codes are 26 and 8).
#[test]
fn dir_admin_unknown_codes() {
    let (good, at) = delete_refused_octets();
    for (position, codes) in [
        (at.operation, [0u8, 26, 0xFF]),
        (at.name_kind, [0u8, 8, 0xFF]),
    ] {
        for code in codes {
            let mut b = good.clone();
            b[position] = code;
            assert_eq!(
                decode_event(&b),
                codec(ipc::Error::UnknownCode),
                "{position}"
            );
        }
    }
    // Every operation code decodes.
    for op in DirAdminOperation::ALL {
        let mut b = good.clone();
        b[at.operation] = op.code();
        assert!(decode_event(&b).is_ok(), "{}", op.name());
    }
    // Every name-kind code decodes (task A16's `PolicyChange` included).
    for kind in AdminNameKind::ALL {
        let mut b = good.clone();
        b[at.name_kind] = kind.code();
        assert!(decode_event(&b).is_ok(), "{}", kind.name());
    }
}

/// Every bound of the shape: approvers ≤ 2, names ≤ 4, reported kvnos ≤ 2,
/// SID sub-authorities ≤ 15, a name ≤ 256 printable octets — refused when
/// decoding before any item is read, and unbuildable when encoding.
#[test]
fn dir_admin_bounds() {
    // Unbuildable over the bound.
    assert!(BoundedSeq::<SidValue, MAX_APPROVERS>::new(vec![domain_sid(1); 3]).is_none());
    assert!(BoundedSeq::<SidValue, MAX_APPROVERS>::new(vec![domain_sid(1); 2]).is_some());
    let names = |n| {
        (0..n)
            .map(|_| name(AdminNameKind::Name, "x"))
            .collect::<Vec<_>>()
    };
    assert!(BoundedSeq::<TargetName, MAX_TARGET_NAMES>::new(names(5)).is_none());
    assert!(BoundedSeq::<TargetName, MAX_TARGET_NAMES>::new(names(4)).is_some());
    assert!(BoundedSeq::<u32, MAX_REPORTED_KVNOS>::new(vec![1, 2, 3]).is_none());

    // Refused when decoding.
    let (good, at) = delete_refused_octets();
    let with_count = |position: usize, count: u32| {
        let mut b = good.clone();
        b[position..position + 4].copy_from_slice(&count.to_be_bytes());
        b
    };
    for (position, over) in [
        (at.approvers_count, 3u32),
        (at.names_count, 5),
        (at.kvnos_count, 3),
        (at.requester_count, 16),
    ] {
        assert_eq!(
            decode_event(&with_count(position, over)),
            codec(ipc::Error::CountOverBound),
            "{position}"
        );
        assert_eq!(
            decode_event(&with_count(position, u32::MAX)),
            codec(ipc::Error::CountOverBound),
            "{position}"
        );
    }
    // A name longer than 256 octets.
    assert_eq!(
        decode_event(&with_count(at.name_len, 257)),
        codec(ipc::Error::LengthOverBound)
    );
    // A name with a control octet (docs/07 §8: no log injection).
    let mut b = good.clone();
    b[at.name_text] = b'\n';
    assert_eq!(decode_event(&b), Err(EventError::InvalidText));
    // A name that is not printable ASCII is kept as the marker.
    let withheld = DirAdminEvent {
        names: BoundedSeq::new(vec![TargetName {
            kind: AdminNameKind::SamAccountName,
            text: ipc_audit::AuditText::from_client("caf\u{e9}"),
        }])
        .unwrap(),
        ..delete_refused()
    };
    assert!(withheld.names.as_slice()[0].text.is_withheld());
    let bytes = encode_event(&EventBody::DirAdmin(Box::new(withheld.clone()))).unwrap();
    assert_eq!(
        decode_event(bytes.as_bytes()).unwrap(),
        EventBody::DirAdmin(Box::new(withheld))
    );
}

/// docs/50 §3.3: exact format version, no trailing octet, no truncation.
#[test]
fn dir_admin_strict_envelope() {
    let (good, _) = delete_refused_octets();
    let mut b = good.clone();
    b[0] = EVENT_FORMAT + 1;
    assert_eq!(decode_event(&b), Err(EventError::UnsupportedFormat));
    let mut b = good.clone();
    b.push(0);
    assert_eq!(decode_event(&b), codec(ipc::Error::TrailingBytes));
    for len in 0..good.len() {
        assert!(decode_event(&good[..len]).is_err(), "{len}");
    }
}

// ---- Admind: the exact layout --------------------------------------------------

/// Offsets of the fields the strictness tests patch.
struct AdmindAt {
    peer_marker: usize,
    activity: usize,
    kvnos_count: usize,
    result: usize,
    step: usize,
    purpose: usize,
    cause: usize,
}

/// The octets of `admind_set_password_failed` with peer uid 1000.
fn set_password_failed_octets() -> (AdmindEvent, Vec<u8>, AdmindAt) {
    let event = AdmindEvent {
        peer_uid: Some(1000),
        ..admind_set_password_failed()
    };
    let mut x = vec![EVENT_FORMAT, 6]; // format, shape Admind
    x.extend(TIME);
    let peer_marker = x.len();
    x.push(1);
    x.extend(1000u32.to_be_bytes());
    let activity = x.len();
    x.push(3); // SetPassword
    x.extend([0x5E; 16]); // target
    x.extend([0x9C; 32]); // operation_digest (task D2-c, Q-888)
    let kvnos_count = x.len();
    x.extend(1u32.to_be_bytes());
    x.extend(5u32.to_be_bytes());
    let result = x.len();
    x.push(2); // Failed
    let step = x.len();
    x.push(3); // SetSecret
    let purpose = x.len();
    x.push(3); // Service
    let cause = x.len();
    x.push(5); // Unavailable
    let at = AdmindAt {
        peer_marker,
        activity,
        kvnos_count,
        result,
        step,
        purpose,
        cause,
    };
    (event, x, at)
}

/// The documented positional layout of every activity, octet for octet.
#[test]
fn admind_wire_layout() {
    let (event, expected, _) = set_password_failed_octets();
    let event = EventBody::Admind(Box::new(event));
    assert_eq!(encode_event(&event).unwrap().as_bytes(), &expected[..]);
    assert_eq!(decode_event(&expected).unwrap(), event);

    let head = |peer: Option<u32>| {
        let mut x = vec![EVENT_FORMAT, 6];
        x.extend(TIME);
        match peer {
            None => x.push(0),
            Some(uid) => {
                x.push(1);
                x.extend(uid.to_be_bytes());
            }
        }
        x
    };
    let cases: [(AdmindEvent, Vec<u8>); 4] = [
        (
            AdmindEvent {
                time: time(),
                peer_uid: None,
                activity: AdmindActivity::ConnectionRefused {
                    reason: ConnectionRefusal::PeerUnidentified,
                },
            },
            [head(None), vec![1, 1]].concat(),
        ),
        (
            admind_malformed(),
            [head(None), vec![2, 7]].concat(), // TrailingBytes = 7
        ),
        (
            admind_keyadm_refused(),
            [head(Some(1500)), vec![4, 1, 2]].concat(), // FetchApproved, PeerNotKeyadm
        ),
        (
            admind_set_password(),
            [
                head(Some(1500)),
                vec![3],
                vec![0x5E; 16],
                vec![0x9C; 32], // operation_digest (task D2-c)
                2u32.to_be_bytes().to_vec(),
                4u32.to_be_bytes().to_vec(),
                2u32.to_be_bytes().to_vec(),
                vec![1], // Completed
            ]
            .concat(),
        ),
    ];
    for (event, expected) in cases {
        let event = EventBody::Admind(Box::new(event));
        assert_eq!(encode_event(&event).unwrap().as_bytes(), &expected[..]);
        assert_eq!(decode_event(&expected).unwrap(), event);
    }
}

/// docs/50 §3.3: unknown codes, the kvno bound, the optional marker, the
/// exact format, trailing octets.
#[test]
fn admind_strict_decoding() {
    let (_, good, at) = set_password_failed_octets();
    let patched = |position: usize, value: u8| {
        let mut b = good.clone();
        b[position] = value;
        b
    };
    for (position, codes) in [
        // Activity 5 (`RateLimited`) and cause 8 (`OutcomeUnknown`) were
        // appended by task F6 (Q-406).
        (at.activity, [0u8, 6, 0xFF]),
        (at.result, [0, 3, 0xFF]),
        (at.step, [0, 5, 0xFF]),
        // Purpose 4 (`AdminService`) was appended by R2 (A-102), purpose 5
        // (`ChangePasswordService`) by task K3 (docs/53 §5.2).
        (at.purpose, [0, 6, 0xFF]),
        (at.cause, [0, 9, 0xFF]),
    ] {
        for code in codes {
            assert_eq!(
                decode_event(&patched(position, code)),
                codec(ipc::Error::UnknownCode),
                "{position}: {code}"
            );
        }
    }
    // Validation carries no purpose: the purpose octet is read as the cause
    // and the cause octet is left over.
    assert_eq!(
        decode_event(&patched(at.step, 1)),
        codec(ipc::Error::TrailingBytes)
    );
    assert_eq!(
        decode_event(&patched(at.peer_marker, 2)),
        codec(ipc::Error::InvalidBoolean)
    );
    let mut b = good.clone();
    b[at.kvnos_count..at.kvnos_count + 4].copy_from_slice(&3u32.to_be_bytes());
    assert_eq!(decode_event(&b), codec(ipc::Error::CountOverBound));
    let mut b = good.clone();
    b[0] = 0;
    assert_eq!(decode_event(&b), Err(EventError::UnsupportedFormat));
    let mut b = good.clone();
    b.push(0);
    assert_eq!(decode_event(&b), codec(ipc::Error::TrailingBytes));

    // The other activities' codes.
    let short = |activity: u8, rest: &[u8]| {
        let mut x = vec![EVENT_FORMAT, 6];
        x.extend(TIME);
        x.push(0);
        x.push(activity);
        x.extend(rest);
        x
    };
    for bad in [
        short(1, &[0]),
        short(1, &[3]),    // ConnectionRefusal has 2 codes
        short(2, &[17]),   // FrameErrorCode has 16 (F6: ValueRefused)
        short(4, &[4, 1]), // KeyadmOperation has 3
        short(4, &[1, 3]), // ForwardDecision has 2
    ] {
        assert_eq!(decode_event(&bad), codec(ipc::Error::UnknownCode));
    }
    assert!(decode_event(&short(1, &[2])).is_ok());
    assert!(decode_event(&short(2, &[15])).is_ok()); // Unlisted
    assert!(decode_event(&short(2, &[16])).is_ok()); // ValueRefused (F6)
    assert!(decode_event(&short(5, &[])).is_ok()); // RateLimited (F6)
    assert_eq!(
        decode_event(&short(5, &[0])),
        codec(ipc::Error::TrailingBytes)
    );
    assert!(decode_event(&short(4, &[3, 1])).is_ok());
}

// ---- size ---------------------------------------------------------------------

/// docs/50 §3.3 ("audit ≤ 8 KiB per event"): the largest admin events fit,
/// with a wide margin.
#[test]
fn largest_admin_events_fit() {
    let dir_admin = encode_event(&EventBody::DirAdmin(Box::new(largest_dir_admin())))
        .unwrap()
        .len();
    let admind = encode_event(&EventBody::Admind(Box::new(largest_admind())))
        .unwrap()
        .len();
    // Computed from the layout: DirAdmin 2 + 7 + 8 + 1 + 24 (stage with
    // allocation) + 3 × 17 (GUIDs) + 71 (SID) + 4 + 2 × 70 (approvers) + 7
    // (PDP) + 4 + 4 × 262 (names) + 2 (enable) + 10 (account_expires At) +
    // 2 (group_type) + 9 + 2 + 12 = 1404, + 32 (operation_digest) + 2
    // (proposed) + 262 (reason_ref) since task D2-c = 1700; Admind 2 + 7 +
    // 5 + 1 + 16 + 32 (operation_digest, task D2-c) + 12 + 4 = 79.
    assert_eq!(dir_admin, 1700);
    assert_eq!(admind, 79);
    assert!(dir_admin <= MAX_EVENT_OCTETS as usize);
}

// ---- the noise rule -----------------------------------------------------------

/// A-57 / Q-218 (a): an admind event is noise exactly when it records a
/// refused connection or a malformed frame; everything else it records is
/// gating.
#[test]
fn admind_noise_classification() {
    assert!(admind_connection_refused().is_noise());
    assert!(admind_malformed().is_noise());
    assert!(!admind_set_password().is_noise());
    assert!(!admind_set_password_failed().is_noise());
    assert!(!admind_keyadm_refused().is_noise());
    // Task F6 (Q-406 item 3): a rate-limited frame is noise.
    assert!(admind_rate_limited().is_noise());
    assert!(!largest_admind().is_noise());
}

/// A-57: "no unaudited issuance, and log overflow does not turn into
/// shutdown". A flood of refused connections and malformed frames, offered
/// as noise, holds at most the noise share of admind's window: every slot
/// a gating event (`SetPassword`, a keyadm forward) needs stays free, the
/// rest of the flood is counted, and the count is reported in a
/// `WindowSummary` once the window drains.
#[test]
fn admind_noise_flood_never_blocks_gating() {
    let config = WindowConfig::new(8, 2).unwrap();
    let mut window = SendWindow::new(config);
    let flood = [admind_connection_refused(), admind_malformed()];
    let mut queued = 0u64;
    for i in 0..1000 {
        let event = &flood[i % 2];
        assert!(event.is_noise());
        match window
            .offer_noise(&EventBody::Admind(Box::new(event.clone())))
            .unwrap()
        {
            NoiseAdmission::Queued { .. } => queued += 1,
            NoiseAdmission::Counted => {}
        }
    }
    assert_eq!(queued, 2, "noise holds only its share");
    assert_eq!(window.suppressed_noise(), 998);
    // Every remaining slot is available to gating events.
    for _ in 0..6 {
        let slot = window.reserve().expect("the flood took no gating slot");
        window
            .commit(slot, &EventBody::Admind(Box::new(admind_set_password())))
            .unwrap();
    }
    // The window is now full of gating events: the next gating operation is
    // refused (A-64: admind answers Busy), noise is still only counted, and
    // nothing stops.
    assert!(window.reserve().is_err());
    assert_eq!(
        window
            .offer_noise(&EventBody::Admind(Box::new(admind_malformed())))
            .unwrap(),
        NoiseAdmission::Counted
    );
    // Drain: the batch is acknowledged, and the next batch carries the
    // summary of what was counted and refused.
    let batch = window.next_batch().unwrap();
    assert_eq!(batch.events().len(), 8);
    window
        .acknowledge(&ipc_audit::Ack {
            through_seq: batch.last_seq(),
            head_hash: [0; 32],
        })
        .unwrap();
    let batch = window.next_batch().unwrap();
    assert_eq!(
        decode_event(batch.events()[0].as_bytes()).unwrap(),
        EventBody::WindowSummary(WindowSummary {
            suppressed_noise: 999,
            refused_gating: 1,
            unrecorded_outcomes: 0,
        })
    );
}

// ---- the frame-error table ----------------------------------------------------

/// `FrameErrorCode` mirrors `ipc::Error` by variant name (Q-252 item 3).
#[test]
fn frame_error_code_mirrors_ipc_error() {
    let all = [
        ipc::Error::FrameTooShort,
        ipc::Error::FrameTooLarge,
        ipc::Error::WrongMagic,
        ipc::Error::VersionMismatch,
        ipc::Error::UnknownKind,
        ipc::Error::Truncated,
        ipc::Error::TrailingBytes,
        ipc::Error::InvalidBoolean,
        ipc::Error::InvalidOptionMarker,
        ipc::Error::LengthOverBound,
        ipc::Error::CountOverBound,
        ipc::Error::UnknownCode,
        ipc::Error::NestingTooDeep,
        ipc::Error::BodyOverBound,
    ];
    for error in all {
        let code = FrameErrorCode::of(error);
        assert_eq!(code.name(), format!("{error:?}"));
        assert_ne!(code, FrameErrorCode::Unlisted);
        assert_ne!(code, FrameErrorCode::ValueRefused);
    }
    // `Unlisted` keeps code 15; `ValueRefused` (task F6, Q-406 item 3) is
    // appended after it as 16 — no earlier code moved.
    assert_eq!(FrameErrorCode::ALL.len(), all.len() + 2);
    assert_eq!(FrameErrorCode::Unlisted.code(), 15);
    assert_eq!(FrameErrorCode::ValueRefused.code(), 16);
}

/// Task F6 (A-94; docs/questions/Q-406): the three appended admind codes
/// take the next free code of their tables; every earlier code is unchanged.
#[test]
fn f6_codes_are_appended() {
    assert_eq!(PasswordFailure::VersionMismatch.code(), 7);
    assert_eq!(PasswordFailure::OutcomeUnknown.code(), 8);
    assert_eq!(PasswordFailure::ALL.len(), 8);
    assert_eq!(ipc_audit::AdmindActivityCode::KeyadmForward.code(), 4);
    assert_eq!(ipc_audit::AdmindActivityCode::RateLimited.code(), 5);
    assert_eq!(ipc_audit::AdmindActivityCode::ALL.len(), 5);
    // The rate-limited activity is noise and carries no field.
    assert!(admind_rate_limited().is_noise());
    let bytes = encode_event(&EventBody::Admind(Box::new(admind_rate_limited()))).unwrap();
    assert_eq!(
        decode_event(bytes.as_bytes()).unwrap(),
        EventBody::Admind(Box::new(admind_rate_limited()))
    );
    // time(7) ‖ peer marker + uid ‖ activity 5, nothing after it.
    assert_eq!(bytes.as_bytes().len(), 2 + 7 + 5 + 1);
    assert_eq!(bytes.as_bytes().last(), Some(&5));
}

/// Task A10 (docs/questions/Q-421): the key-request codes appended to the
/// DirAdmin tables take the next free codes; earlier codes are unchanged.
#[test]
fn a10_codes_are_appended() {
    assert_eq!(AdminRefusal::ObligationRefused.code(), 20);
    assert_eq!(AdminRefusal::OperationMismatch.code(), 21);
    assert_eq!(AdminRefusal::KeyOperationRefused.code(), 22);
    assert!(AdminRefusal::ALL.len() >= 22);
    assert_eq!(AdminFailure::AuditUnacknowledged.code(), 6);
    assert_eq!(AdminFailure::KeyOperationNotPerformed.code(), 7);
    assert_eq!(AdminFailure::KeyOperationOutcomeUnknown.code(), 8);
    assert_eq!(AdminFailure::ALL.len(), 8);
}

/// Task D2-c (docs/questions/Q-882, Q-888, Q-938): the request-queue codes
/// are appended — operations `Propose` .. `ShowRequest` (20..24), refusals
/// `ApprovalNotNeeded`, `RequestStale`, `RequesterLimit` (23..25) — and no
/// earlier code moved; the retired `RequestKeyOperation` keeps code 14.
#[test]
fn d2c_codes_are_appended() {
    assert_eq!(DirAdminOperation::RequestKeyOperation.code(), 14);
    assert_eq!(DirAdminOperation::Approve.code(), 15);
    assert_eq!(DirAdminOperation::ChangePolicy.code(), 19);
    assert_eq!(DirAdminOperation::Propose.code(), 20);
    assert_eq!(DirAdminOperation::Reject.code(), 21);
    assert_eq!(DirAdminOperation::Withdraw.code(), 22);
    assert_eq!(DirAdminOperation::ListRequests.code(), 23);
    assert_eq!(DirAdminOperation::ShowRequest.code(), 24);
    // Task K6 appended `ChangePassword` (docs/53 §9): no earlier code moved.
    assert_eq!(DirAdminOperation::ChangePassword.code(), 25);
    assert_eq!(DirAdminOperation::ALL.len(), 25);
    assert_eq!(AdminRefusal::ApprovalNotNeeded.code(), 23);
    assert_eq!(AdminRefusal::RequestStale.code(), 24);
    assert_eq!(AdminRefusal::RequesterLimit.code(), 25);
    assert_eq!(AdminRefusal::ALL.len(), 25);
}

/// Task D2-c (docs/questions/Q-888): the operation digest, `proposed` and
/// `reason_ref` are appended to the `DirAdmin` layout after the reported
/// kvnos — 32 octets, then `00` | `01 ‖ operation code`, then `00` | `01 ‖
/// AuditText` — octet for octet; an unknown `proposed` code and a short
/// digest are refused.
#[test]
fn dir_admin_digest_and_request_fields_layout() {
    let (base, at) = delete_refused_octets();
    assert_eq!(&base[at.digest..at.digest + 32], &[0x9C; 32]);
    assert_eq!(&base[at.proposed..], &[0, 0]);
    let event = DirAdminEvent {
        operation: DirAdminOperation::Approve,
        pending_request: Some(0x1122_3344_5566_7788),
        operation_digest: [0x3B; 32],
        proposed: Some(DirAdminOperation::SetEnabled),
        reason_ref: Some(ipc_audit::AuditText::from_client("CHG-1182")),
        ..delete_refused()
    };
    let mut expected = base[..at.operation].to_vec();
    expected.push(15); // Approve
    expected.extend(&base[at.operation + 1..at.enable + 3]);
    expected.push(1); // pending_request present
    expected.extend(0x1122_3344_5566_7788u64.to_be_bytes());
    expected.extend(&base[at.enable + 4..at.digest]);
    expected.extend([0x3B; 32]);
    expected.extend([1, 8]); // proposed: SetEnabled
    expected.extend([1, 1]); // reason_ref present, text kept
    expected.extend(8u32.to_be_bytes());
    expected.extend(b"CHG-1182");
    let event = EventBody::DirAdmin(Box::new(event));
    assert_eq!(encode_event(&event).unwrap().as_bytes(), &expected[..]);
    assert_eq!(decode_event(&expected).unwrap(), event);
    // An unknown `proposed` code (task K6 appended `ChangePassword` = 25,
    // so 26 is the first unknown one); a digest cut short.
    let mut bad = base.clone();
    bad[at.proposed] = 1;
    bad.insert(at.proposed + 1, 26);
    assert_eq!(decode_event(&bad), codec(ipc::Error::UnknownCode));
    assert!(decode_event(&base[..at.digest + 31]).is_err());
}

// ---- peek_shape ---------------------------------------------------------------

/// `peek_shape` reads the format and shape octets only: it names the shape
/// of every encoded event, refuses a wrong format or an unknown shape, and
/// does not decode the rest.
#[test]
fn peek_shape_reads_two_octets_only() {
    for event in all_samples() {
        let bytes = encode_event(&event).unwrap();
        assert_eq!(peek_shape(bytes.as_bytes()), Some(event.shape()));
    }
    assert_eq!(peek_shape(&[]), None);
    assert_eq!(peek_shape(&[EVENT_FORMAT]), None);
    assert_eq!(peek_shape(&[EVENT_FORMAT, 0]), None);
    assert_eq!(peek_shape(&[EVENT_FORMAT, 7]), None);
    assert_eq!(peek_shape(&[EVENT_FORMAT + 1, 5]), None);
    assert_eq!(peek_shape(&[0xAD, 0x02]), None); // auditd's own record format
    assert_eq!(peek_shape(&[EVENT_FORMAT, 5]), Some(EventShape::DirAdmin));
    assert!(decode_event(&[EVENT_FORMAT, 5]).is_err());
    assert_eq!(
        peek_shape(&[EVENT_FORMAT, 6, 0xFF]),
        Some(EventShape::Admind)
    );
}

/// The detail types: a computer's two key purposes, every step, every
/// failure class round-trip inside a `SetPassword`.
#[test]
fn every_password_step_and_cause_round_trips() {
    let steps = [
        PasswordStep::Validation,
        PasswordStep::BeginPasswordSet,
        PasswordStep::SetSecret(KeyPurposeCode::PrincipalLongterm),
        PasswordStep::SetSecret(KeyPurposeCode::Service),
        PasswordStep::CompletePasswordSet,
    ];
    for step in steps {
        for cause in PasswordFailure::ALL {
            let event = EventBody::Admind(Box::new(AdmindEvent {
                activity: AdmindActivity::SetPassword {
                    target: [7; 16],
                    operation_digest: [0x9C; 32],
                    kvnos: BoundedSeq::empty(),
                    result: PasswordResult::Failed {
                        step,
                        cause: *cause,
                    },
                },
                ..admind_connection_refused()
            }));
            let bytes = encode_event(&event).unwrap();
            assert_eq!(decode_event(bytes.as_bytes()).unwrap(), event);
        }
    }
    for refusal in AdminRefusal::ALL {
        for stage in [
            DirAdminStage::Decision(DecisionResult::Refused(*refusal)),
            DirAdminStage::Outcome(OutcomeResult::Refused(*refusal)),
        ] {
            let event = EventBody::DirAdmin(Box::new(DirAdminEvent {
                stage,
                ..delete_refused()
            }));
            let bytes = encode_event(&event).unwrap();
            assert_eq!(decode_event(bytes.as_bytes()).unwrap(), event);
        }
    }
    for failure in AdminFailure::ALL {
        for stage in [
            DirAdminStage::Decision(DecisionResult::Failed(*failure)),
            DirAdminStage::Outcome(OutcomeResult::Failed(*failure)),
        ] {
            let event = EventBody::DirAdmin(Box::new(DirAdminEvent {
                stage,
                ..delete_refused()
            }));
            let bytes = encode_event(&event).unwrap();
            assert_eq!(decode_event(bytes.as_bytes()).unwrap(), event);
        }
    }
}
