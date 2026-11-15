//! Tests of the sealed key store's persisted format (task KL1).
//!
//! Source: this project's design document docs/research/r4-c-key-lifecycle.md
//! §3.3 (the record and header fields), §8.3 (unknown ids refused), §9.1
//! (C39) and the layout written in crates/keyd-types/src/sealed_store.rs
//! from it; RFC 3962 §6, §7 and RFC 8009 §2, §5, §7 (key lengths); RFC 4120
//! §5.2.2, §5.2.9; docs/CLEAN-ROOM.md (strict, bounded parsers). No specification
//! defines this format, so there is no external vector: the expected octets
//! below are hand-derived from the layout. No other implementation was
//! consulted or recalled.

use keyd_types::sealed_store::{
    encode_body_into, encode_header, encode_record, parse_body, root_digest_input, FormatError,
    KeyRecord, KeyRecordAad, KeySource, ParsedHeader, RecordVersion, SealingSuite, StoreHeader,
    MAX_KEY_RECORDS, MAX_KEY_RECORD_OCTETS, MAX_NAME_OCTETS, MAX_SALT_OCTETS,
    MAX_STORE_HEADER_OCTETS,
};
use keyd_types::{
    CeremonyState, EncTypeId, KeyHandle, KeyPurpose, Kvno, PrincipalBinding, PrincipalId, StoreId,
};
use krb_proto::{KerberosString, PrincipalName, Realm};

/// A test registry: two suites with distinct lengths, every other code
/// unknown (test data — no real algorithm is named).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestSuite {
    A,
    B,
}

impl SealingSuite for TestSuite {
    fn from_code(code: u16) -> Option<Self> {
        match code {
            0x7F01 => Some(TestSuite::A),
            0x7F02 => Some(TestSuite::B),
            _ => None,
        }
    }
    fn code(self) -> u16 {
        match self {
            TestSuite::A => 0x7F01,
            TestSuite::B => 0x7F02,
        }
    }
    fn seal_overhead(self) -> usize {
        match self {
            TestSuite::A => 28,
            TestSuite::B => 0,
        }
    }
    fn digest_len(self) -> usize {
        match self {
            TestSuite::A => 32,
            TestSuite::B => 48,
        }
    }
}

/// A registry whose one suite declares an overhead over the codec's bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Oversized;

impl SealingSuite for Oversized {
    fn from_code(code: u16) -> Option<Self> {
        (code == 1).then_some(Oversized)
    }
    fn code(self) -> u16 {
        1
    }
    fn seal_overhead(self) -> usize {
        65
    }
    fn digest_len(self) -> usize {
        32
    }
}

fn name(parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: 1,
        name_string: parts
            .iter()
            .map(|p| KerberosString::new(p).unwrap())
            .collect(),
    }
}

fn binding(parts: &[&str]) -> PrincipalBinding {
    PrincipalBinding::new(Realm::new("EXAMPLE.ORG").unwrap(), name(parts))
}

fn store() -> StoreId {
    StoreId::from_bytes([0x5A; 16])
}

/// A one-version record of a Service key set keyd drew (two enctypes).
fn drawn_aad() -> KeyRecordAad<TestSuite> {
    KeyRecordAad {
        suite: TestSuite::A,
        store_id: store(),
        handle: KeyHandle::new(PrincipalId::from_bytes([0x11; 16]), KeyPurpose::Service),
        binding: binding(&["ldap", "dc1.example.org"]),
        current: RecordVersion {
            kvno: Kvno::new(3),
            source: KeySource::KeydDrawn,
            enctypes: vec![
                EncTypeId::Aes256CtsHmacSha384192,
                EncTypeId::Aes128CtsHmacSha196,
            ],
        },
        previous: None,
    }
}

/// A two-version record of a user's key set: current password-derived with
/// explicit parameters, previous keyd-drawn.
fn two_version_aad() -> KeyRecordAad<TestSuite> {
    KeyRecordAad {
        suite: TestSuite::B,
        store_id: store(),
        handle: KeyHandle::new(
            PrincipalId::from_bytes([0x22; 16]),
            KeyPurpose::PrincipalLongterm,
        ),
        binding: binding(&["alice"]),
        current: RecordVersion {
            kvno: Kvno::new(9),
            source: KeySource::PasswordDerived {
                salt: String::from("EXAMPLE.ORGalice"),
                s2k_params: Some([0, 0, 0x80, 0]),
            },
            enctypes: vec![EncTypeId::Aes256CtsHmacSha196],
        },
        previous: Some(RecordVersion {
            kvno: Kvno::new(8),
            source: KeySource::KeydDrawn,
            enctypes: vec![
                EncTypeId::Aes128CtsHmacSha256128,
                EncTypeId::Aes256CtsHmacSha196,
            ],
        }),
    }
}

/// A sealed body of the right length (test octets; the format treats it as
/// opaque).
fn sealed_for(aad: &KeyRecordAad<TestSuite>) -> Vec<u8> {
    (0..aad.sealed_len()).map(|i| (i % 251) as u8).collect()
}

fn record_octets(aad: &KeyRecordAad<TestSuite>) -> Vec<u8> {
    encode_record(aad, &sealed_for(aad)).unwrap()
}

fn header() -> StoreHeader<TestSuite> {
    StoreHeader {
        suite: TestSuite::A,
        store_id: store(),
        generation: 7,
        ceremony: CeremonyState::Operational,
        record_count: 2,
        root_digest: vec![0xD1; 32],
    }
}

fn header_octets(h: &StoreHeader<TestSuite>) -> Vec<u8> {
    encode_header(h, &vec![0xEE; h.sealed_len()]).unwrap()
}

/// r4-c §3.3: a record round-trips — the associated data, its exact octets
/// and the sealed body come back, and re-encoding gives the input.
#[test]
fn records_round_trip() {
    for aad in [drawn_aad(), two_version_aad()] {
        let octets = record_octets(&aad);
        let record = KeyRecord::<TestSuite>::parse(&octets).unwrap();
        assert_eq!(record.aad(), &aad);
        assert_eq!(record.aad_octets(), aad.encode().unwrap().as_slice());
        assert_eq!(record.sealed(), sealed_for(&aad).as_slice());
        assert_eq!(
            encode_record(record.aad(), record.sealed()).unwrap(),
            octets
        );
    }
}

/// The layout, octet for octet, of the one-version record (hand-derived
/// from the layout in sealed_store.rs).
#[test]
fn record_layout_is_pinned() {
    let mut expected = Vec::new();
    expected.extend_from_slice(b"KYDR"); // magic
    expected.extend_from_slice(&[0x00, 0x01]); // format_version 1
    expected.extend_from_slice(&[0x7F, 0x01]); // suite A
    expected.extend_from_slice(&[0x5A; 16]); // store_id
    expected.extend_from_slice(&[0x11; 16]); // principal id
    expected.push(2); // purpose Service
    expected.extend_from_slice(&[0x00, 0x0B]); // realm length 11
    expected.extend_from_slice(b"EXAMPLE.ORG");
    expected.extend_from_slice(&[0, 0, 0, 1]); // name-type 1
    expected.push(2); // two components
    expected.extend_from_slice(&[0x00, 0x04]);
    expected.extend_from_slice(b"ldap");
    expected.extend_from_slice(&[0x00, 0x0F]);
    expected.extend_from_slice(b"dc1.example.org");
    expected.push(1); // one version
    expected.extend_from_slice(&[0, 0, 0, 3]); // kvno 3
    expected.push(1); // KeydDrawn
    expected.push(2); // two enctypes
    expected.extend_from_slice(&[0, 0, 0, 20]);
    expected.extend_from_slice(&[0, 0, 0, 17]);
    let aad = drawn_aad();
    assert_eq!(aad.encode().unwrap(), expected);
    // 32 + 16 key octets, plus suite A's 28.
    assert_eq!(aad.body_len(), 48);
    assert_eq!(aad.sealed_len(), 76);
}

/// The password-derived source carries its salt and parameter block; the
/// previous version follows the current one.
#[test]
fn password_source_layout_is_pinned() {
    let aad = two_version_aad();
    let octets = aad.encode().unwrap();
    let mut tail = Vec::new();
    tail.push(2); // two versions
    tail.extend_from_slice(&[0, 0, 0, 9]); // kvno 9
    tail.push(2); // PasswordDerived
    tail.extend_from_slice(&[0x00, 0x10]);
    tail.extend_from_slice(b"EXAMPLE.ORGalice");
    tail.push(1); // parameters present
    tail.extend_from_slice(&[0, 0, 0x80, 0]);
    tail.push(1);
    tail.extend_from_slice(&[0, 0, 0, 18]);
    tail.extend_from_slice(&[0, 0, 0, 8]); // previous kvno 8
    tail.push(1); // KeydDrawn
    tail.push(2);
    tail.extend_from_slice(&[0, 0, 0, 19]);
    tail.extend_from_slice(&[0, 0, 0, 18]);
    assert!(octets.ends_with(&tail));
    // 32 (current) + 16 + 32 (previous); suite B adds nothing.
    assert_eq!(aad.body_len(), 80);
    assert_eq!(aad.sealed_len(), 80);
}

/// RFC 3962 §6 / RFC 8009 §2: the body is the key octets in version and
/// enctype order, with no length field; it round-trips through views, and a
/// view's Debug shows no octet (docs/CLEAN-ROOM.md).
#[test]
fn body_round_trips_as_views() {
    let aad = two_version_aad();
    let current = [[0xA1u8; 32]];
    let previous = ([0xB1u8; 16], [0xB2u8; 32]);
    let mut out = vec![0u8; aad.body_len()];
    encode_body_into(
        &aad,
        &[&current[0][..]],
        Some(&[&previous.0[..], &previous.1[..]]),
        &mut out,
    )
    .unwrap();
    let body = parse_body(&aad, &out).unwrap();
    let got: Vec<_> = body.current.iter().collect();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].enctype, EncTypeId::Aes256CtsHmacSha196);
    assert_eq!(got[0].octets, &current[0][..]);
    let got: Vec<_> = body.previous.unwrap().iter().collect();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].enctype, EncTypeId::Aes128CtsHmacSha256128);
    assert_eq!(got[0].octets, &previous.0[..]);
    assert_eq!(got[1].octets, &previous.1[..]);
    let debug = format!("{body:?}");
    // 0xA1 = 161, 0xB1 = 177, 0xB2 = 178: no key octet is printed.
    assert!(!debug.contains("161") && !debug.contains("177") && !debug.contains("178"));
    assert!(debug.contains("len: 32"));
    // Wrong lengths are refused.
    assert_eq!(
        parse_body(&aad, &out[..out.len() - 1]),
        Err(FormatError::BadLength)
    );
    let mut longer = out.clone();
    longer.push(0);
    assert_eq!(parse_body(&aad, &longer), Err(FormatError::BadLength));
    let mut short = vec![0u8; aad.body_len()];
    assert_eq!(
        encode_body_into(
            &aad,
            &[&[0u8; 16][..]],
            Some(&[&previous.0[..], &previous.1[..]]),
            &mut short
        ),
        Err(FormatError::BadLength)
    );
    assert_eq!(
        encode_body_into(&aad, &[&current[0][..]], None, &mut short),
        Err(FormatError::BadLength)
    );
    let one = drawn_aad();
    let mut buf = vec![0u8; one.body_len()];
    assert_eq!(
        encode_body_into(&one, &[&[0u8; 32][..], &[0u8; 16][..]], Some(&[]), &mut buf),
        Err(FormatError::BadLength)
    );
}

/// r4-c §3.3: the header round-trips, and its layout is pinned.
#[test]
fn header_round_trips_and_layout_is_pinned() {
    let h = header();
    let octets = header_octets(&h);
    let parsed = ParsedHeader::<TestSuite>::parse(&octets).unwrap();
    assert_eq!(parsed.header(), &h);
    assert_eq!(parsed.field_octets(), h.encode_fields().unwrap().as_slice());
    assert_eq!(parsed.sealed(), &[0xEE; 28][..]);
    assert_eq!(
        encode_header(parsed.header(), parsed.sealed()).unwrap(),
        octets
    );
    let mut expected = Vec::new();
    expected.extend_from_slice(b"KYDH");
    expected.extend_from_slice(&[0x00, 0x01, 0x7F, 0x01]);
    expected.extend_from_slice(&[0x5A; 16]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]); // G = 7
    expected.push(2); // sealed
    expected.extend_from_slice(&[0, 0, 0, 2]); // two records
    expected.extend_from_slice(&[0xD1; 32]);
    assert_eq!(h.encode_fields().unwrap(), expected);
    let provisioning = StoreHeader {
        ceremony: CeremonyState::Provisioning,
        ..header()
    };
    let octets = header_octets(&provisioning);
    assert_eq!(octets[32], 1);
    assert_eq!(
        ParsedHeader::<TestSuite>::parse(&octets)
            .unwrap()
            .header()
            .ceremony,
        CeremonyState::Provisioning
    );
}

/// Replace `len` octets at `at`.
fn patched(octets: &[u8], at: usize, with: &[u8]) -> Vec<u8> {
    let mut out = octets.to_vec();
    out[at..at + with.len()].copy_from_slice(with);
    out
}

/// r4-c §3.3, §8.3: an unknown or downgraded format version, an unknown
/// suite, a wrong magic, an unknown purpose — refused (the floor).
#[test]
fn unknown_codes_are_refused() {
    let octets = record_octets(&drawn_aad());
    let parse = |o: &[u8]| KeyRecord::<TestSuite>::parse(o).map(|_| ());
    for version in [[0, 0], [0, 2], [0xFF, 0xFF]] {
        assert_eq!(
            parse(&patched(&octets, 4, &version)),
            Err(FormatError::UnsupportedFormatVersion)
        );
    }
    for suite in [[0, 0], [0x7F, 0x03], [0xFF, 0xFF]] {
        assert_eq!(
            parse(&patched(&octets, 6, &suite)),
            Err(FormatError::UnknownSuite)
        );
    }
    assert_eq!(
        parse(&patched(&octets, 0, b"KYDH")),
        Err(FormatError::BadMagic)
    );
    for purpose in [5u8, 0x80, 0xFF] {
        assert_eq!(
            parse(&patched(&octets, 40, &[purpose])),
            Err(FormatError::UnknownPurpose)
        );
    }
    // A header is never a record and a record never a header.
    let h = header_octets(&header());
    assert_eq!(parse(&h), Err(FormatError::BadMagic));
    assert_eq!(
        ParsedHeader::<TestSuite>::parse(&octets[..60]).map(|_| ()),
        Err(FormatError::BadMagic)
    );
}

/// Offset of the first version's source octet in `drawn_aad()`'s encoding.
const DRAWN_SOURCE_AT: usize = 41 + 2 + 11 + 4 + 1 + 2 + 4 + 2 + 15 + 1 + 4;

/// r4-c §3.3, C39 (§9.1): the key source is a closed code — `MachineGenerated`
/// (Q-905) and every unassigned code are refused; an unknown encryption type
/// (a DES / RC4 number included) is refused; a repeated one is non-canonical.
#[test]
fn sources_and_enctypes_are_closed() {
    let octets = record_octets(&drawn_aad());
    assert_eq!(octets[DRAWN_SOURCE_AT], 1);
    let parse = |o: &[u8]| KeyRecord::<TestSuite>::parse(o).map(|_| ());
    for source in [0u8, 3, 4, 0xFF] {
        assert_eq!(
            parse(&patched(&octets, DRAWN_SOURCE_AT, &[source])),
            Err(FormatError::UnknownKeySource),
            "{source}"
        );
    }
    let etype_at = DRAWN_SOURCE_AT + 2;
    for number in [0i32, 1, 3, 16, 21, 23, 24, -1] {
        assert_eq!(
            parse(&patched(&octets, etype_at, &number.to_be_bytes())),
            Err(FormatError::UnknownEncType),
            "{number}"
        );
    }
    assert_eq!(
        parse(&patched(&octets, etype_at + 4, &20i32.to_be_bytes())),
        Err(FormatError::NonCanonical)
    );
    // The encoder refuses what the parser refuses.
    let mut aad = drawn_aad();
    aad.current.enctypes = vec![EncTypeId::Aes128CtsHmacSha196; 2];
    assert_eq!(aad.encode(), Err(FormatError::NonCanonical));
    aad.current.enctypes = Vec::new();
    assert_eq!(aad.encode(), Err(FormatError::BadLength));
}

/// docs/10 §1, §7 (A-35: keyd assigns kvnos with `next`): the previous kvno
/// must be below the current one; a parameter flag is 0 or 1.
#[test]
fn version_order_and_flags_are_canonical() {
    let mut aad = two_version_aad();
    aad.previous.as_mut().unwrap().kvno = Kvno::new(9);
    assert_eq!(aad.encode(), Err(FormatError::NonCanonical));
    aad.previous.as_mut().unwrap().kvno = Kvno::new(10);
    assert_eq!(aad.encode(), Err(FormatError::NonCanonical));
    // Patch the encoded previous kvno up to the current one.
    let octets = record_octets(&two_version_aad());
    let at = octets
        .windows(5)
        .position(|w| w == [0, 0, 0, 8, 1])
        .unwrap();
    assert_eq!(
        KeyRecord::<TestSuite>::parse(&patched(&octets, at, &[0, 0, 0, 9])).map(|_| ()),
        Err(FormatError::NonCanonical)
    );
    // The parameter flag.
    let flag_at = octets
        .windows(5)
        .position(|w| w == [1, 0, 0, 0x80, 0])
        .unwrap();
    assert_eq!(
        KeyRecord::<TestSuite>::parse(&patched(&octets, flag_at, &[2])).map(|_| ()),
        Err(FormatError::NonCanonical)
    );
    // Without parameters the flag is 0 and no block follows.
    let mut aad = two_version_aad();
    aad.current.source = KeySource::PasswordDerived {
        salt: String::new(),
        s2k_params: None,
    };
    let octets = record_octets(&aad);
    assert_eq!(KeyRecord::<TestSuite>::parse(&octets).unwrap().aad(), &aad);
    // A version count other than 1 or 2.
    let count_at = 41 + 2 + 11 + 4 + 1 + 2 + 5;
    for count in [0u8, 3, 0xFF] {
        assert_eq!(
            KeyRecord::<TestSuite>::parse(&patched(&octets, count_at, &[count])).map(|_| ()),
            Err(FormatError::BadLength)
        );
    }
}

/// RFC 4120 §5.2.1, §5.2.2 (krb-proto's KerberosString rule): names are
/// checked; 1 ..= 16 components; bounded lengths; the salt is UTF-8.
#[test]
fn names_and_salts_are_checked() {
    let parse = |o: &[u8]| KeyRecord::<TestSuite>::parse(o).map(|_| ());
    let octets = record_octets(&drawn_aad());
    // A control character and a non-IA5 octet in the realm.
    assert_eq!(
        parse(&patched(&octets, 43, &[0x07])),
        Err(FormatError::BadName)
    );
    assert_eq!(
        parse(&patched(&octets, 43, &[0xC3])),
        Err(FormatError::BadName)
    );
    // Component count 0 and 17.
    for count in [0u8, 17] {
        assert_eq!(
            parse(&patched(&octets, 41 + 2 + 11 + 4, &[count])),
            Err(FormatError::BadName)
        );
    }
    // A realm length over the bound.
    let over = u16::try_from(MAX_NAME_OCTETS + 1).unwrap().to_be_bytes();
    assert_eq!(
        parse(&patched(&octets, 41, &over)),
        Err(FormatError::TooLarge)
    );
    // The encoder: no component, too many, too long.
    let mut aad = drawn_aad();
    aad.binding.name.name_string.clear();
    assert_eq!(aad.encode(), Err(FormatError::BadName));
    aad.binding = binding(&["x"; 17]);
    assert_eq!(aad.encode(), Err(FormatError::BadName));
    let long = "a".repeat(MAX_NAME_OCTETS + 1);
    aad.binding = binding(&[&long]);
    assert_eq!(aad.encode(), Err(FormatError::TooLarge));
    aad.binding = binding(&[&"a".repeat(MAX_NAME_OCTETS)]);
    let ok = record_octets(&aad);
    assert_eq!(KeyRecord::<TestSuite>::parse(&ok).unwrap().aad(), &aad);
    // A salt over its bound, and a salt that is not UTF-8.
    let mut aad = two_version_aad();
    aad.current.source = KeySource::PasswordDerived {
        salt: "s".repeat(MAX_SALT_OCTETS + 1),
        s2k_params: None,
    };
    assert_eq!(aad.encode(), Err(FormatError::TooLarge));
    let octets = record_octets(&two_version_aad());
    let salt_at = octets.windows(5).position(|w| w == b"EXAMP").unwrap();
    let salt_at = octets[salt_at + 1..]
        .windows(5)
        .position(|w| w == b"EXAMP")
        .map(|p| p + salt_at + 1)
        .unwrap();
    assert_eq!(
        parse(&patched(&octets, salt_at, &[0xFF])),
        Err(FormatError::BadSalt)
    );
}

/// r4-c §3.3: the sealed body is exactly the body plus the suite's
/// overhead; nothing trails; the whole input is bounded first.
#[test]
fn sealed_length_is_exact_and_input_bounded() {
    let aad = drawn_aad();
    let octets = record_octets(&aad);
    let parse = |o: &[u8]| KeyRecord::<TestSuite>::parse(o).map(|_| ());
    assert_eq!(
        parse(&octets[..octets.len() - 1]),
        Err(FormatError::BadLength)
    );
    let mut longer = octets.clone();
    longer.push(0);
    assert_eq!(parse(&longer), Err(FormatError::BadLength));
    assert_eq!(
        encode_record(&aad, &sealed_for(&aad)[1..]),
        Err(FormatError::BadLength)
    );
    assert_eq!(
        parse(&vec![0u8; MAX_KEY_RECORD_OCTETS + 1]),
        Err(FormatError::TooLarge)
    );
    for cut in 0..aad.encode().unwrap().len() {
        assert_eq!(parse(&octets[..cut]), Err(FormatError::Truncated), "{cut}");
    }
    assert_eq!(parse(&[]), Err(FormatError::Truncated));
}

/// r4-c §3.6, §3.7: G ≥ 1; the ceremony code is closed; the record count
/// is bounded; the root digest has the suite's length; the tail is exact.
#[test]
fn header_rules() {
    let octets = header_octets(&header());
    let parse = |o: &[u8]| ParsedHeader::<TestSuite>::parse(o).map(|_| ());
    assert_eq!(
        parse(&patched(&octets, 24, &[0; 8])),
        Err(FormatError::NonCanonical)
    );
    for code in [0u8, 3, 0xFF] {
        assert_eq!(
            parse(&patched(&octets, 32, &[code])),
            Err(FormatError::UnknownCeremonyState)
        );
    }
    let over = u32::try_from(MAX_KEY_RECORDS + 1).unwrap().to_be_bytes();
    assert_eq!(
        parse(&patched(&octets, 33, &over)),
        Err(FormatError::TooLarge)
    );
    assert_eq!(
        parse(&octets[..octets.len() - 1]),
        Err(FormatError::BadLength)
    );
    let mut longer = octets.clone();
    longer.push(0);
    assert_eq!(parse(&longer), Err(FormatError::BadLength));
    assert_eq!(
        parse(&[0u8; MAX_STORE_HEADER_OCTETS + 1]),
        Err(FormatError::TooLarge)
    );
    assert_eq!(
        parse(&patched(&octets, 4, &[0, 2])),
        Err(FormatError::UnsupportedFormatVersion)
    );
    // The encoder.
    let mut h = header();
    h.generation = 0;
    assert_eq!(h.encode_fields(), Err(FormatError::NonCanonical));
    let mut h = header();
    h.root_digest.pop();
    assert_eq!(h.encode_fields(), Err(FormatError::BadLength));
    let mut h = header();
    h.record_count = u32::try_from(MAX_KEY_RECORDS + 1).unwrap();
    assert_eq!(h.encode_fields(), Err(FormatError::TooLarge));
    assert_eq!(
        encode_header(&header(), &[0; 27]),
        Err(FormatError::BadLength)
    );
}

/// A registry that declares lengths over the codec's bounds is refused
/// (docs/CLEAN-ROOM.md: the codec's bounds do not depend on the registry).
#[test]
fn a_suite_over_the_bounds_is_refused() {
    let mut octets = record_octets(&drawn_aad());
    octets[6..8].copy_from_slice(&[0, 1]);
    assert_eq!(
        KeyRecord::<Oversized>::parse(&octets).map(|_| ()),
        Err(FormatError::BadSuiteParameters)
    );
    assert_eq!(
        root_digest_input(Oversized, &[]),
        Err(FormatError::BadSuiteParameters)
    );
}

/// r4-c §3.3: the root-digest list is in one canonical order whatever the
/// order given; a repeated handle and a wrong digest length are refused.
#[test]
fn root_digest_input_is_canonical() {
    let a = KeyHandle::new(PrincipalId::from_bytes([1; 16]), KeyPurpose::Service);
    let b = KeyHandle::new(PrincipalId::from_bytes([1; 16]), KeyPurpose::Krbtgt);
    let c = KeyHandle::new(PrincipalId::from_bytes([0; 16]), KeyPurpose::AdminService);
    let (da, db, dc) = ([0xAA; 32], [0xBB; 32], [0xCC; 32]);
    let one = root_digest_input(TestSuite::A, &[(a, &da), (b, &db), (c, &dc)]).unwrap();
    let two = root_digest_input(TestSuite::A, &[(c, &dc), (a, &da), (b, &db)]).unwrap();
    assert_eq!(one, two);
    let mut expected = Vec::new();
    expected.extend_from_slice(b"KYDL");
    expected.extend_from_slice(&[0, 1, 0x7F, 0x01, 0, 0, 0, 3]);
    for (principal, purpose, digest) in [(0u8, 3u8, 0xCCu8), (1, 1, 0xBB), (1, 2, 0xAA)] {
        expected.extend_from_slice(&[principal; 16]);
        expected.push(purpose);
        expected.extend_from_slice(&[digest; 32]);
    }
    assert_eq!(one, expected);
    assert_eq!(
        root_digest_input(TestSuite::A, &[(a, &da), (a, &db)]),
        Err(FormatError::NonCanonical)
    );
    assert_eq!(
        root_digest_input(TestSuite::A, &[(a, &da[..31])]),
        Err(FormatError::BadLength)
    );
    // The list is bound to the suite: another suite, other octets.
    let empty_a = root_digest_input(TestSuite::A, &[]).unwrap();
    let empty_b = root_digest_input(TestSuite::B, &[]).unwrap();
    assert_ne!(empty_a, empty_b);
}

/// The never-panic property of the fuzz target
/// (crates/keyd-types/fuzz/fuzz_targets/sealed_store_parse.rs), run
/// deterministically while the harness awaits owner approval (P-1): every
/// truncation and single-octet substitution of each seed is parsed; nothing
/// panics, and whatever is accepted re-encodes to the identical octets.
#[test]
fn mutated_inputs_never_panic_and_accepted_ones_round_trip() {
    let seeds = [
        record_octets(&drawn_aad()),
        record_octets(&two_version_aad()),
        header_octets(&header()),
    ];
    let mut accepted = 0usize;
    for seed in &seeds {
        let mut inputs: Vec<Vec<u8>> = (0..=seed.len()).map(|n| seed[..n].to_vec()).collect();
        for at in 0..seed.len() {
            for value in [0x00u8, 0x01, 0x7F, 0x80, 0xFF, seed[at] ^ 0x01] {
                inputs.push(patched(seed, at, &[value]));
            }
        }
        for input in inputs {
            if let Ok(record) = KeyRecord::<TestSuite>::parse(&input) {
                accepted += 1;
                assert_eq!(encode_record(record.aad(), record.sealed()).unwrap(), input);
                let plain = vec![0u8; record.aad().body_len()];
                assert!(parse_body(record.aad(), &plain).is_ok());
            }
            if let Ok(parsed) = ParsedHeader::<TestSuite>::parse(&input) {
                accepted += 1;
                assert_eq!(
                    encode_header(parsed.header(), parsed.sealed()).unwrap(),
                    input
                );
            }
        }
    }
    // Positive control: the unmodified seeds and the field substitutions
    // that stay valid (ids, kvnos, digest octets) are accepted.
    assert!(accepted > seeds.len(), "{accepted}");
}
