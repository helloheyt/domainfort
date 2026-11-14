//! The event encoding: round trips, canonical form, the size bound of every
//! shape's largest event, the client-string rule, the closed code tables,
//! and the inventory of fields (none secret).
//!
//! Source: docs/50 §3.3 (one encoding per value; strict decoding; "audit ≤
//! 8 KiB per event"), §8.2 (client strings: printable ASCII ≤ 256 bytes,
//! else a fixed marker; no secrets), §8.1; docs/37 §2 ("only identifiers
//! and metadata"); docs/10 I8; docs/49 §10.1; crates/kdc, keyd, ldap
//! audit.rs (the source field lists).

mod common;

use common::*;
use ipc_audit::{
    decode_event, encode_event, event_round_trip_is_canonical, AuditText, CalendarTime, EventBody,
    EventError, KdcEvent, KdcReason, KeydOutcome, KeydRecord, LdapEvent, LdapReason, Principal,
    SidValue, EVENT_FORMAT, MAX_EVENT_OCTETS, MAX_FILTER_ATTRS, MAX_NAME_COMPONENTS,
};

/// docs/50 §3.3: every sample decodes to itself and re-encodes to the same
/// octets.
#[test]
fn every_shape_round_trips() {
    for event in all_samples() {
        let bytes = encode_event(&event).unwrap();
        assert_eq!(bytes.as_bytes()[0], EVENT_FORMAT);
        assert_eq!(bytes.as_bytes()[1], event.shape().code());
        assert_eq!(decode_event(bytes.as_bytes()).unwrap(), event);
        assert_eq!(event_round_trip_is_canonical(bytes.as_bytes()), Ok(true));
    }
}

/// docs/50 §3.3 ("audit ≤ 8 KiB per event"): the largest event of every
/// shape — every optional field present, every string at 256 octets, every
/// sequence at its bound — fits, so encoding an event built from these types
/// cannot fail on size.
#[test]
fn largest_events_fit_the_bound() {
    let largest = [
        EventBody::Kdc(Box::new(largest_kdc_event())),
        EventBody::Keyd(Box::new(largest_keyd_record())),
        EventBody::Ldap(Box::new(largest_ldap_event())),
        EventBody::WindowSummary(summary()),
        EventBody::DirAdmin(Box::new(largest_dir_admin())),
        EventBody::Admind(Box::new(largest_admind())),
    ];
    for event in largest {
        let len = encode_event(&event).unwrap().len();
        assert!(
            len <= MAX_EVENT_OCTETS as usize,
            "{:?}: {len} octets",
            event.shape()
        );
    }
    // Measured at the time of writing: KDC 3971, keyd 97, LDAP 4856,
    // summary 26 octets (18 before F4 appended its third counter) — the LDAP
    // shape is the largest (17 octets more since docs/52 R14 added the
    // reported client address, an IPv6 one here); keep the margin visible.
    let ldap = encode_event(&EventBody::Ldap(Box::new(largest_ldap_event())))
        .unwrap()
        .len();
    assert!(ldap <= 5 * 1024, "{ldap}");
}

/// docs/50 §8.2: a client string is kept only as printable ASCII of at most
/// 256 octets; otherwise the fixed marker.
#[test]
fn client_strings_rule() {
    assert!(!AuditText::from_client(&"x".repeat(256)).is_withheld());
    assert!(AuditText::from_client(&"x".repeat(257)).is_withheld());
    assert!(AuditText::from_client("line\nbreak").is_withheld());
    assert!(AuditText::from_client("tab\there").is_withheld());
    assert!(AuditText::from_client("del\u{7f}").is_withheld());
    assert!(AuditText::from_client("caf\u{e9}").is_withheld());
    assert_eq!(AuditText::from_client("a b~").as_text(), Some("a b~"));
    assert_eq!(AuditText::from_client("").as_text(), Some(""));
}

/// A decoder refuses a non-printable octet smuggled into a text field
/// (docs/07 §8: no log injection).
#[test]
fn decoder_refuses_non_printable_text() {
    let event = EventBody::Kdc(Box::new(KdcEvent {
        client: Some(Principal::new(text("EXAMPLE.TEST"), 1, vec![text("zzzzz")])),
        ..kdc_event()
    }));
    let mut bytes = encode_event(&event).unwrap().into_vec();
    let at = bytes
        .windows(5)
        .position(|w| w == b"zzzzz")
        .expect("component present");
    bytes[at + 2] = b'\n';
    assert_eq!(decode_event(&bytes), Err(EventError::InvalidText));
    bytes[at + 2] = 0xC3;
    assert_eq!(decode_event(&bytes), Err(EventError::InvalidText));
}

/// A name of more than four components is withheld as a whole (bounded
/// size, docs/questions/Q-252 item 5).
#[test]
fn long_names_are_withheld() {
    let components: Vec<AuditText> = (0..=MAX_NAME_COMPONENTS).map(|_| text("x")).collect();
    let p = Principal::new(text("R"), 1, components);
    assert!(p.components().is_none());
    let event = EventBody::Kdc(Box::new(KdcEvent {
        client: Some(p),
        ..kdc_event()
    }));
    let bytes = encode_event(&event).unwrap();
    assert_eq!(decode_event(bytes.as_bytes()).unwrap(), event);
}

/// Filter attribute names beyond 16 are dropped and marked truncated.
#[test]
fn filter_attrs_are_bounded() {
    let search = largest_ldap_event().search.unwrap();
    assert_eq!(search.filter_attrs().len(), MAX_FILTER_ATTRS);
    assert!(search.filter_attrs_truncated());
    let search = ldap_event().search.unwrap();
    assert_eq!(search.filter_attrs().len(), 2);
    assert!(!search.filter_attrs_truncated());
}

/// SIDs hold at most 15 sub-authorities ([MS-DTYP] 2.4.2 via crates/dtyp).
#[test]
fn sid_bound() {
    assert!(SidValue::new([0; 6], vec![1; 15]).is_some());
    assert!(SidValue::new([0; 6], vec![1; 16]).is_none());
}

/// Calendar fields are range-checked when built and when decoded.
#[test]
fn calendar_time_ranges() {
    assert!(CalendarTime::new(9999, 12, 31, 23, 59, 59).is_some());
    assert!(CalendarTime::new(10000, 1, 1, 0, 0, 0).is_none());
    assert!(CalendarTime::new(2026, 13, 1, 0, 0, 0).is_none());
    assert!(CalendarTime::new(2026, 0, 1, 0, 0, 0).is_none());
    assert!(CalendarTime::new(2026, 1, 0, 0, 0, 0).is_none());
    assert!(CalendarTime::new(2026, 1, 32, 0, 0, 0).is_none());
    assert!(CalendarTime::new(2026, 1, 1, 24, 0, 0).is_none());
    assert!(CalendarTime::new(2026, 1, 1, 0, 60, 0).is_none());
    assert!(CalendarTime::new(2026, 1, 1, 0, 0, 60).is_none());

    let mut bytes = encode_event(&EventBody::Keyd(Box::new(keyd_record())))
        .unwrap()
        .into_vec();
    // The time follows the format and shape octets: year(2) month(1) …
    bytes[4] = 13;
    assert_eq!(decode_event(&bytes), Err(EventError::InvalidTime));
}

/// Strict decoding: exact format, closed shape table, no trailing octet,
/// no truncation, bounded size.
#[test]
fn strict_decoding() {
    let good = encode_event(&EventBody::WindowSummary(summary()))
        .unwrap()
        .into_vec();
    let mut b = good.clone();
    b[0] = EVENT_FORMAT + 1;
    assert_eq!(decode_event(&b), Err(EventError::UnsupportedFormat));
    // Shapes 5 (DirAdmin) and 6 (Admind) were appended for the admin plane
    // (docs/51 §5.7); 7 is the first code outside the closed table.
    for shape in [0u8, 7, 0xFF] {
        let mut b = good.clone();
        b[1] = shape;
        assert_eq!(
            decode_event(&b),
            Err(EventError::Codec(ipc::Error::UnknownCode))
        );
    }
    let mut b = good.clone();
    b.push(0);
    assert_eq!(
        decode_event(&b),
        Err(EventError::Codec(ipc::Error::TrailingBytes))
    );
    assert_eq!(
        decode_event(&good[..good.len() - 1]),
        Err(EventError::Codec(ipc::Error::Truncated))
    );
    assert_eq!(
        decode_event(&[]),
        Err(EventError::Codec(ipc::Error::Truncated))
    );
    let huge = vec![EVENT_FORMAT; MAX_EVENT_OCTETS as usize + 1];
    assert_eq!(
        decode_event(&huge),
        Err(EventError::Codec(ipc::Error::LengthOverBound))
    );
    // A non-canonical optional marker.
    let mut b = encode_event(&EventBody::Keyd(Box::new(keyd_record())))
        .unwrap()
        .into_vec();
    // format, shape, time(7), role(1), uid(4), op(1) → the principal marker.
    let marker = 2 + 7 + 1 + 4 + 1;
    assert_eq!(b[marker], 1);
    b[marker] = 2;
    assert_eq!(
        decode_event(&b),
        Err(EventError::Codec(ipc::Error::InvalidBoolean))
    );
}

/// Decision A-86 (docs/questions/Q-365): the intent and not-performed
/// records use keyd's record layout unchanged — the same record with
/// `result` = `Intent` differs from one with `Success` in exactly the
/// outcome octet (the third from the end: outcome, reason, then the absent
/// decision's marker — A-102) — and the first
/// code past the table (8) is refused (docs/50 §3.3: closed tables).
#[test]
fn keyd_phase_codes_change_only_the_outcome_octet() {
    let intent = keyd_intent_record();
    let success = KeydRecord {
        result: KeydOutcome::Success,
        ..intent.clone()
    };
    let encode = |r: &KeydRecord| {
        encode_event(&EventBody::Keyd(Box::new(r.clone())))
            .unwrap()
            .into_vec()
    };
    let (a, b) = (encode(&success), encode(&intent));
    assert_eq!(a.len(), b.len());
    let differing: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
    assert_eq!(differing, [a.len() - 3]);
    let at = a.len() - 3;
    assert_eq!(b[at], KeydOutcome::Intent.code());
    let mut other = b.clone();
    other[at] = KeydOutcome::NotPerformed.code();
    assert_eq!(
        decode_event(&other).unwrap(),
        EventBody::Keyd(Box::new(KeydRecord {
            result: KeydOutcome::NotPerformed,
            ..intent
        }))
    );
    other[at] = KeydOutcome::NotPerformed.code() + 1;
    assert!(decode_event(&other).is_err());
}

/// docs/50 §3.3 ("enum = u8 from a closed table"): every table's codes are
/// position + 1, 0 and past-the-end are refused, names are unique.
#[test]
fn code_tables_are_closed() {
    fn check(all: &[(u8, &'static str)]) {
        let mut names = std::collections::HashSet::new();
        for (i, (code, name)) in all.iter().enumerate() {
            assert_eq!(*code as usize, i + 1, "{name}");
            assert!(names.insert(*name), "duplicate {name}");
        }
    }
    macro_rules! table {
        ($t:ty) => {{
            let all: Vec<(u8, &'static str)> =
                <$t>::ALL.iter().map(|v| (v.code(), v.name())).collect();
            check(&all);
            assert_eq!(<$t>::from_code(0), None);
            assert_eq!(<$t>::from_code(all.len() as u8 + 1), None);
            for v in <$t>::ALL {
                assert_eq!(<$t>::from_code(v.code()), Some(*v));
            }
            all.len()
        }};
    }
    use ipc_audit::*;
    assert_eq!(table!(KdcReason), 66);
    // Task A15a appended the four grant reasons before `Unlisted`
    // (docs/questions/Q-452 item 4); A-102 the seven decision reasons
    // (docs/52 §4.5); R2 the two operation-binding reasons (docs/52 §5);
    // R6b the discard of a deleted principal's set-secret entries
    // (docs/questions/Q-520), `Unlisted` last (80).
    assert_eq!(table!(KeydReason), 80);
    assert_eq!(KeydReason::NoGrant.code(), 66);
    assert_eq!(KeydReason::GrantTableFull.code(), 69);
    assert_eq!(KeydReason::NoDecision.code(), 70);
    assert_eq!(KeydReason::CeremonySealed.code(), 76);
    assert_eq!(KeydReason::OperationDigestMissing.code(), 77);
    assert_eq!(KeydReason::OperationDigestMismatch.code(), 78);
    assert_eq!(KeydReason::SecretDecisionDiscarded.code(), 79);
    assert_eq!(KeydReason::Unlisted.code(), 80);
    assert_eq!(table!(LdapReason), 53);
    assert_eq!(table!(CodecErrorCode), 35);
    assert_eq!(table!(CodecLimit), 12);
    assert_eq!(table!(PdpReasonCode), 12);
    // `GrantSetSecret` (17) appended by task A15a; `RegisterDecision`,
    // `SealCeremony`, `ListDestroyDecisions` (18-20) by A-102 (docs/52 §4);
    // 1-16 keep their codes.
    assert_eq!(table!(KeydOperation), 20);
    assert_eq!(KeydOperation::GrantSetSecret.code(), 17);
    assert_eq!(KeydOperation::RegisterDecision.code(), 18);
    assert_eq!(KeydOperation::ListDestroyDecisions.code(), 20);
    assert_eq!(KeydOperation::Ping.code(), 16);
    table!(KdcTransport);
    table!(KdcExchange);
    table!(KdcOutcomeCode);
    table!(IpZone);
    table!(KeydRole);
    // R2 appended `AdminService` (4); 1-3 keep their codes.
    assert_eq!(table!(KeyPurposeCode), 4);
    assert_eq!(KeyPurposeCode::Service.code(), 3);
    assert_eq!(KeyPurposeCode::AdminService.code(), 4);
    // keyd's five outcomes keep their codes; A-86 appended two phases.
    assert_eq!(table!(KeydOutcome), 7);
    assert_eq!(
        KeydOutcome::ALL
            .iter()
            .map(|o| o.name())
            .collect::<Vec<_>>(),
        [
            "Success",
            "Denied",
            "BadTemplate",
            "Unavailable",
            "RateLimited",
            "Intent",
            "NotPerformed"
        ]
    );
    assert_eq!(KeydOutcome::RateLimited.code(), 5);
    assert_eq!(KeydOutcome::Intent.code(), 6);
    assert_eq!(KeydOutcome::NotPerformed.code(), 7);
    table!(LdapTransport);
    table!(UnsupportedOpCode);
    table!(SearchScope);
    table!(LdapAction);
    table!(LdapOperationCode);
    table!(BindMechanismCode);
    table!(LdapTargetCode);
    // The first four shapes keep their codes; the admin plane appended two.
    assert_eq!(table!(EventShape), 6);
    assert_eq!(
        EventShape::ALL.iter().map(|s| s.code()).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6]
    );
    assert_eq!(EventShape::Kdc.code(), 1);
    assert_eq!(EventShape::WindowSummary.code(), 4);
    assert_eq!(EventShape::DirAdmin.code(), 5);
    assert_eq!(EventShape::Admind.code(), 6);
    assert_eq!(table!(DirAdminOperation), 18);
    // Task A3 appended `SelfLockout` (Q-295 item 4, P-22); task F4
    // appended `ObligationRefused` (A-91, Q-388 item 1, Q-397); task A10
    // appended `OperationMismatch` and `KeyOperationRefused` (Q-421).
    assert_eq!(table!(AdminRefusal), 22);
    assert_eq!(AdminRefusal::SelfLockout.code(), 19);
    assert_eq!(AdminRefusal::ObligationRefused.code(), 20);
    assert_eq!(AdminRefusal::OperationMismatch.code(), 21);
    assert_eq!(
        AdminRefusal::ALL.last(),
        Some(&AdminRefusal::KeyOperationRefused)
    );
    // Task F4 appended `ViewUnavailable` and `AuditUnacknowledged`; the
    // first four keep their codes (A-91, Q-397; append only).
    // Task A10 appended `KeyOperationNotPerformed` and
    // `KeyOperationOutcomeUnknown` (Q-421).
    assert_eq!(table!(AdminFailure), 8);
    assert_eq!(
        AdminFailure::ALL
            .iter()
            .map(|f| (f.code(), f.name()))
            .collect::<Vec<_>>(),
        [
            (1, "KeydUnavailable"),
            (2, "StoreFailure"),
            (3, "IntegrityFailure"),
            (4, "InternalFailure"),
            (5, "ViewUnavailable"),
            (6, "AuditUnacknowledged"),
            (7, "KeyOperationNotPerformed"),
            (8, "KeyOperationOutcomeUnknown"),
        ]
    );
    // `ipc::Error` mirrored (1-14), `Unlisted` (15), then `ValueRefused`
    // (16) appended by task F6 after it — not an `ipc::Error` variant, so
    // the mirror and its `Unlisted` keep their codes (Q-406 item 3).
    assert_eq!(table!(FrameErrorCode), 16);
    table!(AdminPhase);
    table!(DecisionResultCode);
    table!(OutcomeResultCode);
    table!(AdminNameKind);
    table!(AdmindActivityCode);
    table!(ConnectionRefusal);
    table!(PasswordResultCode);
    table!(PasswordStepCode);
    table!(PasswordFailure);
    table!(KeyadmOperation);
    table!(ForwardDecision);
    table!(EnableDirection);
    table!(AccountExpiresCode);
    assert_eq!(table!(GroupTypeCode), 6);
    assert_eq!(FrameErrorCode::Unlisted.code(), 15);
    assert_eq!(
        FrameErrorCode::ALL.last(),
        Some(&FrameErrorCode::ValueRefused)
    );
    // Non-exhaustive sources end in Unlisted.
    assert_eq!(KdcReason::ALL.last(), Some(&KdcReason::Unlisted));
    assert_eq!(LdapReason::ALL.last(), Some(&LdapReason::Unlisted));
    assert_eq!(KeydReason::ALL.last().map(|r| r.name()), Some("Unlisted"));
}

/// docs/37 §2, docs/10 I8, AGENTS.md §6: the complete field inventory of
/// every shape. Each binding below is destructured exhaustively, so adding
/// a field to a shape stops this test from compiling until the field is
/// classified here. Every field is an identifier, a code, a count, a time,
/// a flag, or a client string under the printable-ASCII rule — **no field
/// can hold a key, a password, a ticket, a PAC, a plaintext, a ciphertext,
/// an attribute value or request octets**.
#[test]
fn field_inventory_holds_no_secret() {
    let KdcEvent {
        time: _,            // caller time (calendar fields)
        transport: _,       // code
        exchange: _,        // code
        client: _,          // principal name (printable-ASCII rule)
        service: _,         // principal name
        armor_principal: _, // principal name (docs/48 §2.4: not secret)
        reply_armored: _,   // flag
        outcome: _,         // code (+ RFC 4120 error code)
        reason: _,          // code
        policy_reason: _,   // code (+ rule id)
    } = kdc_event();
    let KeydRecord {
        ts: _,          // caller time
        caller_role: _, // code
        caller_uid: _,  // uid
        op: _,          // code
        principal: _,   // 16-octet principal id (an identifier, docs/10 §10)
        purpose: _,     // code
        kvno: _,        // key version number (not key material)
        secondary: _,   // principal id, purpose, kvno
        approvers: _,   // principal ids
        result: _,      // code
        reason: _,      // code
        decision: _,    // decision id (an identifier dird assigned, A-102)
    } = keyd_record();
    let LdapEvent {
        time: _,          // caller time
        connection_id: _, // identifier
        source_zone: _,   // code
        reported_peer: _, // IP address as ldap-front reported it (an endpoint identifier)
        transport: _,     // code
        transport_sec: _, // flags
        operation: _,     // code
        message_id: _,    // LDAP MessageID
        principal: _,     // SID
        bind: _,          // version, mechanism code / name, bind name (rule)
        target: _,        // rootDSE or objectGUID
        search: _,        // scope code, counts, schema attribute names
        result_code: _,   // RFC 4511 resultCode
        notice: _,        // RFC 4511 resultCode
        action: _,        // code
        reason: _,        // code
        policy_reason: _, // code (+ rule id)
        codec_error: _,   // code (+ limit code)
    } = ldap_event();
    // A simple bind with a password is recorded as a mechanism only — the
    // shape has no field where the password could go.
    let _ = ipc_audit::BindMechanism::SimplePassword;
    // docs/51 §5.7 item 1: "only names as AuditText, no other attribute
    // values and no password".
    let ipc_audit::DirAdminEvent {
        time: _,            // dird's time
        operation_id: _,    // dird's operation number
        operation: _,       // code
        stage: _,           // phase code + result code (+ refusal / failure code, or GUID + RID)
        target: _,          // objectGUID
        parent: _,          // objectGUID
        member: _,          // objectGUID
        requester: _,       // SID
        approvers: _,       // SIDs (≤ 2)
        pdp: _,             // code (+ rule id)
        names: _,           // name-kind code + name (printable-ASCII rule), ≤ 4
        enable: _,          // code (Enable / Disable) — request metadata, Q-340 item 5
        account_expires: _, // code + FILETIME (never / a time) — request metadata
        group_type: _,      // code (one of six groupType values) — request metadata
        key_request: _,     // dird's request number
        key_operation: _,   // code
        reported_kvnos: _,  // key version numbers (not key material), ≤ 2
    } = dir_admin_create_outcome();
    // docs/51 §5.7 item 3, §7.6: the password never reaches the event.
    let ipc_audit::AdmindEvent {
        time: _,     // admind's time
        peer_uid: _, // uid (peer credentials)
        activity: _, // below
    } = admind_set_password();
    for activity in [
        admind_connection_refused().activity,
        admind_malformed().activity,
        admind_set_password().activity,
        admind_keyadm_refused().activity,
        admind_rate_limited().activity,
    ] {
        match activity {
            ipc_audit::AdmindActivity::ConnectionRefused { reason: _ } => {} // code
            ipc_audit::AdmindActivity::MalformedFrame { error: _ } => {}     // code, never octets
            ipc_audit::AdmindActivity::SetPassword {
                target: _, // objectGUID
                kvnos: _,  // key version numbers
                result: _, // codes (step, purpose, failure class)
            } => {}
            ipc_audit::AdmindActivity::KeyadmForward {
                operation: _, // code
                decision: _,  // code
            } => {}
            ipc_audit::AdmindActivity::RateLimited => {} // no field (task F6)
        }
    }
    // Every sender's window summary: three counters, nothing else (A-57;
    // A-88 appended the third, Q-395).
    let ipc_audit::WindowSummary {
        suppressed_noise: _,    // count
        refused_gating: _,      // count
        unrecorded_outcomes: _, // count
    } = summary();
}

/// docs/50 §3.3 (fixed width, big-endian; one encoding per value; strict
/// decoding) and the layout decided for task F4 (A-88; docs/questions/Q-366
/// option (a), Q-395): `WindowSummary := suppressed_noise:u64 ‖
/// refused_gating:u64 ‖ unrecorded_outcomes:u64` after the format and shape
/// octets. The octets are assembled here by hand from that layout; every
/// counter value, the extremes included, round-trips canonically and in its
/// own position; the 16-octet form of before F4, every other truncation and
/// a trailing octet are refused.
#[test]
fn window_summary_layout_and_bounds() {
    let expected = |noise: u64, refused: u64, lost: u64| {
        let mut out = vec![EVENT_FORMAT, 4];
        out.extend_from_slice(&noise.to_be_bytes());
        out.extend_from_slice(&refused.to_be_bytes());
        out.extend_from_slice(&lost.to_be_bytes());
        out
    };
    for (noise, refused, lost) in [
        (0, 0, 0),
        (12, 3, 2),
        (0, 0, 1),
        (u64::MAX, 0, 0),
        (0, u64::MAX, 0),
        (0, 0, u64::MAX),
        (u64::MAX, u64::MAX, u64::MAX),
        (
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
        ),
    ] {
        let summary = EventBody::WindowSummary(ipc_audit::WindowSummary {
            suppressed_noise: noise,
            refused_gating: refused,
            unrecorded_outcomes: lost,
        });
        let bytes = encode_event(&summary).unwrap();
        assert_eq!(bytes.as_bytes(), expected(noise, refused, lost).as_slice());
        assert_eq!(bytes.len(), 2 + 3 * 8);
        assert_eq!(decode_event(bytes.as_bytes()).unwrap(), summary);
        assert_eq!(event_round_trip_is_canonical(bytes.as_bytes()), Ok(true));
    }
    let good = expected(12, 3, 2);
    // Every shorter form — the two-counter layout of before F4 (18 octets)
    // among them — is truncated.
    for len in 0..good.len() {
        let refused = decode_event(&good[..len]);
        assert!(refused.is_err(), "{len} octets accepted");
        if len >= 2 {
            assert_eq!(refused, Err(EventError::Codec(ipc::Error::Truncated)));
        }
    }
    let mut longer = good.clone();
    longer.push(0);
    assert_eq!(
        decode_event(&longer),
        Err(EventError::Codec(ipc::Error::TrailingBytes))
    );
    // The counters are not interchangeable: each lands in its own field.
    let EventBody::WindowSummary(decoded) = decode_event(&expected(1, 2, 3)).unwrap() else {
        panic!("not a summary");
    };
    assert_eq!(
        (
            decoded.suppressed_noise,
            decoded.refused_gating,
            decoded.unrecorded_outcomes
        ),
        (1, 2, 3)
    );
}

/// Reasons with detail: the detail travels in its own optional field.
#[test]
fn reason_details_round_trip() {
    let kdc = kdc_policy_denied();
    assert_eq!(kdc.reason, KdcReason::PolicyDenied);
    let ldap = ldap_malformed();
    assert_eq!(ldap.reason, LdapReason::Malformed);
    for event in [
        EventBody::Kdc(Box::new(kdc)),
        EventBody::Ldap(Box::new(ldap)),
    ] {
        let bytes = encode_event(&event).unwrap();
        assert_eq!(decode_event(bytes.as_bytes()).unwrap(), event);
    }
}

/// docs/52 §7 R14 (the client address ldap-front reported, kept as an
/// unverified observation); docs/50 §3.3 (a closed code table, one encoding
/// per value): `family:u8 (4 | 6) ‖ 4 | 16 octets` right after the zone
/// code; an IPv6 address is 12 octets longer than an IPv4 one; another
/// family code is refused; the address survives the round trip as given.
#[test]
fn reported_address_layout() {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let v4 = ldap_event();
    let v4_bytes = encode_event(&EventBody::Ldap(Box::new(v4.clone()))).unwrap();
    let needle = [4u8, 10, 0, 0, 9];
    let at = v4_bytes
        .as_bytes()
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("family 4 then the octets");
    let v6 = LdapEvent {
        reported_peer: ipc_audit::ReportedAddress::new(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 9,
        ))),
        ..v4.clone()
    };
    let v6_bytes = encode_event(&EventBody::Ldap(Box::new(v6.clone()))).unwrap();
    assert_eq!(v6_bytes.len(), v4_bytes.len() + 12);
    assert_eq!(v6_bytes.as_bytes()[at], 6);
    assert_eq!(
        decode_event(v6_bytes.as_bytes()).unwrap(),
        EventBody::Ldap(Box::new(v6))
    );
    let mut wrong = v4_bytes.as_bytes().to_vec();
    wrong[at] = 5;
    assert!(decode_event(&wrong).is_err());
    match decode_event(v4_bytes.as_bytes()).unwrap() {
        EventBody::Ldap(event) => assert_eq!(
            event.reported_peer.address(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))
        ),
        other => panic!("{other:?}"),
    }
}
