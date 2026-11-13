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
    EventError, KdcEvent, KdcReason, KeydRecord, LdapEvent, LdapReason, Principal, SidValue,
    EVENT_FORMAT, MAX_EVENT_OCTETS, MAX_FILTER_ATTRS, MAX_NAME_COMPONENTS,
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
    // summary 18 octets — the LDAP shape is the largest; keep the margin
    // visible.
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
    for shape in [0u8, 5, 0xFF] {
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
    assert_eq!(table!(KeydReason), 66);
    assert_eq!(table!(LdapReason), 53);
    assert_eq!(table!(CodecErrorCode), 35);
    assert_eq!(table!(CodecLimit), 12);
    assert_eq!(table!(PdpReasonCode), 12);
    assert_eq!(table!(KeydOperation), 16);
    table!(KdcTransport);
    table!(KdcExchange);
    table!(KdcOutcomeCode);
    table!(IpZone);
    table!(KeydRole);
    table!(KeyPurposeCode);
    table!(KeydOutcome);
    table!(LdapTransport);
    table!(UnsupportedOpCode);
    table!(SearchScope);
    table!(LdapAction);
    table!(LdapOperationCode);
    table!(BindMechanismCode);
    table!(LdapTargetCode);
    table!(EventShape);
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
    } = keyd_record();
    let LdapEvent {
        time: _,          // caller time
        connection_id: _, // identifier
        source_zone: _,   // code
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
