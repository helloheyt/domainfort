//! SID tests: packet representation and string form.
//!
//! Every vector names its source. Sources (AGENTS.md §3/§4.5): the string
//! forms listed in [MS-DTYP] v20241119 2.4.2.4 (well-known SIDs) and 2.4.1
//! (identifier authorities), SID bytes that appear in the worked example of
//! [MS-DTYP] 2.5.1.4, byte sequences hand-derived from [MS-DTYP] 2.4.2.1 /
//! 2.4.2.2 / 2.4.6 (little-endian), and string forms hand-derived from the
//! 2.4.2.1 ABNF read with RFC 5234 §2.3 / Appendix B.1. No vector comes from
//! any other implementation.

use dtyp::{
    Error, Sid, CREATOR_SID_AUTHORITY, NULL_SID_AUTHORITY, SECURITY_APP_PACKAGE_AUTHORITY,
    SECURITY_AUTHENTICATION_AUTHORITY, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_NT_AUTHORITY,
    SID_MAX_SUB_AUTHORITIES, WORLD_SID_AUTHORITY,
};

/// Parse `text`, check its parts, format it back, and round-trip the packet.
fn check_string(text: &str, authority: [u8; 6], sub_authority: &[u32]) {
    let sid = Sid::parse_sid_string(text).expect("spec string form must parse");
    assert_eq!(sid.identifier_authority(), authority, "{text}");
    assert_eq!(sid.sub_authority(), sub_authority, "{text}");
    assert_eq!(sid.to_sid_string(), text);
    let packet = sid.encode();
    assert_eq!(packet.len(), sid.encoded_len());
    assert_eq!(Sid::decode(&packet).unwrap(), sid);
}

#[test]
fn well_known_sid_strings_from_the_table() {
    // Source: [MS-DTYP] 2.4.2.4 table (constant / value), with the authority
    // bytes from the [MS-DTYP] 2.4.1 identifier-authority table.
    check_string("S-1-0-0", NULL_SID_AUTHORITY, &[0]); // NULL
    check_string("S-1-1-0", WORLD_SID_AUTHORITY, &[0]); // EVERYONE
    check_string("S-1-3-0", CREATOR_SID_AUTHORITY, &[0]); // CREATOR_OWNER
    check_string("S-1-5-18", SECURITY_NT_AUTHORITY, &[18]); // LOCAL_SYSTEM
    check_string("S-1-5-32-544", SECURITY_NT_AUTHORITY, &[32, 544]); // BUILTIN_ADMINISTRATORS
    check_string(
        "S-1-5-84-0-0-0-0-0",
        SECURITY_NT_AUTHORITY,
        &[84, 0, 0, 0, 0, 0],
    ); // USER_MODE_DRIVERS
    check_string("S-1-15-2-1", SECURITY_APP_PACKAGE_AUTHORITY, &[2, 1]); // ALL_APP_PACKAGES
    check_string("S-1-16-12288", SECURITY_MANDATORY_LABEL_AUTHORITY, &[12288]); // ML_HIGH
    check_string("S-1-18-1", SECURITY_AUTHENTICATION_AUTHORITY, &[1]); // AUTH...ASSERTED_IDENTITY
}

#[test]
fn well_known_sids_without_sub_authority() {
    // Source: [MS-DTYP] 2.4.2.4 rows CREATOR_AUTHORITY "S-1-3" and
    // NT_AUTHORITY "S-1-5" ("A SID containing only the SECURITY_NT_AUTHORITY
    // identifier authority"); 2.4.2.2 sets only a maximum for
    // SubAuthorityCount. Accepted despite the ABNF's 1*SubAuthority (Q-020).
    check_string("S-1-3", CREATOR_SID_AUTHORITY, &[]);
    check_string("S-1-5", SECURITY_NT_AUTHORITY, &[]);
    // Packet hand-derived from [MS-DTYP] 2.4.2.2: Revision 1, count 0,
    // IdentifierAuthority {0,0,0,0,0,5}.
    let packet = [1u8, 0, 0, 0, 0, 0, 0, 5];
    let sid = Sid::decode(&packet).unwrap();
    assert_eq!(sid.sub_authority_count(), 0);
    assert_eq!(sid.encode(), packet);
    assert_eq!(sid.to_sid_string(), "S-1-5");
    assert_eq!(Sid::parse_sid_string("S-1-5").unwrap(), sid);
}

#[test]
fn constructed_domain_sid_from_the_text_example() {
    // Source: [MS-DTYP] 2.4.2.4 — "S-1-5-21-<domain>-513" with domain
    // sub-authorities 1, 2, 3 is "S-1-5-21-1-2-3-513".
    check_string(
        "S-1-5-21-1-2-3-513",
        SECURITY_NT_AUTHORITY,
        &[21, 1, 2, 3, 513],
    );
}

#[test]
fn service_sid_with_large_sub_authorities() {
    // Source: [MS-DTYP] 2.4.2.4 table — the NT SERVICE\DPS SID
    // S-1-5-80-2970612574-78537857-698502321-558674196-1451644582
    // (2970612574 exceeds 2^31: SubAuthority is unsigned 32-bit, 2.4.2.2).
    let text = "S-1-5-80-2970612574-78537857-698502321-558674196-1451644582";
    check_string(
        text,
        SECURITY_NT_AUTHORITY,
        &[80, 2970612574, 78537857, 698502321, 558674196, 1451644582],
    );
    // Packet hand-derived from [MS-DTYP] 2.4.2.2 with little-endian
    // SubAuthority values (2.4.6).
    let expected: Vec<u8> = vec![
        0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Revision, Count, Authority
        0x50, 0x00, 0x00, 0x00, // 80
        0x5e, 0xf3, 0x0f, 0xb1, // 2970612574
        0x81, 0x64, 0xae, 0x04, // 78537857
        0xb1, 0x4c, 0xa2, 0x29, // 698502321
        0x14, 0xb1, 0x4c, 0x21, // 558674196
        0xa6, 0x56, 0x86, 0x56, // 1451644582
    ];
    assert_eq!(Sid::parse_sid_string(text).unwrap().encode(), expected);
}

#[test]
fn sid_packets_from_the_worked_example() {
    // Source: [MS-DTYP] 2.5.1.4 — the owner/group SID "BA" at offset 0x90,
    // and the trustee SIDs of the DACL ACEs (BU, SY, CO) and SACL ACE (WD).
    let cases: [(&[u8], &str); 5] = [
        (
            &[1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 0x02, 0, 0],
            "S-1-5-32-544",
        ),
        (
            &[1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x21, 0x02, 0, 0],
            "S-1-5-32-545",
        ),
        (&[1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0], "S-1-5-18"),
        (&[1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0], "S-1-3-0"),
        (&[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0], "S-1-1-0"),
    ];
    for (bytes, text) in cases {
        let sid = Sid::decode(bytes).unwrap();
        assert_eq!(sid.to_sid_string(), text);
        assert_eq!(sid.encode(), bytes);
        assert_eq!(Sid::parse_sid_string(text).unwrap(), sid);
    }
}

#[test]
fn fifteen_sub_authorities_is_the_maximum() {
    // Source: [MS-DTYP] 2.4.2.2 — "The maximum number of elements allowed is 15".
    let subs: Vec<u32> = (1..=15).collect();
    let sid = Sid::new(SECURITY_NT_AUTHORITY, &subs).unwrap();
    assert_eq!(
        usize::from(sid.sub_authority_count()),
        SID_MAX_SUB_AUTHORITIES
    );
    assert_eq!(sid.encoded_len(), 8 + 4 * 15);
    let text = sid.to_sid_string();
    assert_eq!(Sid::parse_sid_string(&text).unwrap(), sid);
    assert_eq!(Sid::decode(&sid.encode()).unwrap(), sid);

    let sixteen: Vec<u32> = (1..=16).collect();
    assert_eq!(
        Sid::new(SECURITY_NT_AUTHORITY, &sixteen),
        Err(Error::SidTooManySubAuthorities)
    );
    let mut long = text.clone();
    long.push_str("-16");
    assert_eq!(
        Sid::parse_sid_string(&long),
        Err(Error::SidTooManySubAuthorities)
    );
}

#[test]
fn multi_byte_identifier_authority_is_big_endian() {
    // Source: [MS-DTYP] 2.1 — multi-byte integers default to big-endian
    // ("Network Byte Order"); 2.4.1 shows {0,0,0,0,0,1} as authority 1.
    // Hand-derived: {0,0,0,0,0x01,0x00} is authority 256.
    let sid = Sid::new([0, 0, 0, 0, 0x01, 0x00], &[7]).unwrap();
    assert_eq!(sid.identifier_authority_value(), 256);
    assert_eq!(sid.to_sid_string(), "S-1-256-7");
    assert_eq!(Sid::parse_sid_string("S-1-256-7").unwrap(), sid);
    // The largest decimal authority, 2^32 - 1.
    let max = Sid::parse_sid_string("S-1-4294967295-1").unwrap();
    assert_eq!(max.identifier_authority(), [0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn hexadecimal_authority_form() {
    // Source: [MS-DTYP] 2.4.2.1 — IdentifierAuthorityHex = "0x" 12HEXDIG,
    // used iff the authority is >= 2^32; "All hexadecimal digits must be
    // output". Hand-derived values; HEXDIG per RFC 5234 Appendix B.1.
    //
    // 2^32: authority bytes {0,1,0,0,0,0}.
    check_string("S-1-0x000100000000-1", [0, 1, 0, 0, 0, 0], &[1]);
    // Largest 48-bit authority, no SubAuthority.
    check_string("S-1-0xFFFFFFFFFFFF", [0xFF; 6], &[]);
    // Mixed digits and letters, emitted with the HEXDIG letters as spelled in
    // RFC 5234 Appendix B.1 ("A"-"F").
    check_string(
        "S-1-0x123456789ABC-21-7",
        [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
        &[21, 7],
    );
    let big = Sid::new([0, 1, 0, 0, 0, 0], &[1]).unwrap();
    assert_eq!(big.identifier_authority_value(), 1u64 << 32);
    assert_eq!(Sid::decode(&big.encode()).unwrap(), big);
}

#[test]
fn quoted_literals_and_hexdig_are_case_insensitive() {
    // Source: RFC 5234 §2.3 — "ABNF strings are case insensitive and the
    // character set for these strings is US-ASCII"; Appendix B.1 — HEXDIG is
    // DIGIT / "A" / "B" / "C" / "D" / "E" / "F" (quoted, so a-f match too).
    // Applied to the [MS-DTYP] 2.4.2.1 literals "S-1-" and "0x".
    let upper = Sid::parse_sid_string("S-1-5-18").unwrap();
    assert_eq!(Sid::parse_sid_string("s-1-5-18").unwrap(), upper);
    // Output is the canonical spelling.
    assert_eq!(upper.to_sid_string(), "S-1-5-18");

    let hex = Sid::parse_sid_string("S-1-0x123456789ABC-7").unwrap();
    for variant in [
        "s-1-0x123456789abc-7",
        "S-1-0X123456789ABC-7",
        "S-1-0x123456789aBc-7",
        "s-1-0X123456789AbC-7",
    ] {
        assert_eq!(Sid::parse_sid_string(variant).unwrap(), hex, "{variant}");
    }
    assert_eq!(hex.to_sid_string(), "S-1-0x123456789ABC-7");
}

#[test]
fn reject_bad_packets() {
    // Source: [MS-DTYP] 2.4.2.2 — Revision MUST be 0x01.
    assert_eq!(
        Sid::decode(&[2, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0]),
        Err(Error::SidRevision)
    );
    // Source: [MS-DTYP] 2.4.2.2 — at most 15 elements (count 16, followed by
    // enough bytes that only the count rule can fail).
    let mut sixteen = vec![1u8, 16, 0, 0, 0, 0, 0, 5];
    sixteen.extend_from_slice(&[0u8; 64]);
    assert_eq!(Sid::decode(&sixteen), Err(Error::SidTooManySubAuthorities));
    // Source: [MS-DTYP] 2.4.2.2 — the packet is 8 + 4*SubAuthorityCount bytes.
    let good = [1u8, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 0x02, 0, 0];
    for cut in 0..good.len() {
        assert_eq!(
            Sid::decode(&good[..cut]),
            Err(Error::SidTruncated),
            "cut {cut}"
        );
    }
    // Strict framing: nothing may follow a stand-alone SID.
    let mut trailing = good.to_vec();
    trailing.push(0);
    assert_eq!(Sid::decode(&trailing), Err(Error::TrailingData));
}

#[test]
fn reject_bad_strings() {
    // Source: [MS-DTYP] 2.4.2.1 ABNF with RFC 5234 §2.3 / Appendix B.1, rule by
    // rule (hand-derived).
    let syntax = [
        "",
        "S",
        "S-1-",
        "S-1-5-",
        "S-1-5--1",
        "S-2-5-1",               // literal prefix is "S-1-"
        "T-1-5-18",              // literal prefix is "S-1-"
        "S-1-5-18 ",             // nothing after the last SubAuthority
        " S-1-5-18",             // nothing before the prefix
        "S-1-5-+18",             // DIGIT only
        "S-1-5-1a",              // DIGIT only
        "S-1-5-0x12",            // SubAuthority is always decimal
        "S-1--5-18",             // no sign
        "S-1-5-18-",             // dangling separator
        "S-1-12345678901-1",     // 1*10DIGIT
        "S-1-5-12345678901",     // 1*10DIGIT
        "S-1-0x",                // 12HEXDIG: none
        "S-1-0x00010000000-1",   // 12HEXDIG: 11 digits
        "S-1-0x0001000000000-1", // 12HEXDIG: 13 digits
        "S-1-0x00010000000G-1",  // not HEXDIG
        "S-1-0x 000100000000",   // not HEXDIG
        "S-1-x000100000000-1",   // "0x" required
    ];
    for text in syntax {
        assert_eq!(
            Sid::parse_sid_string(text),
            Err(Error::SidStringSyntax),
            "{text:?}"
        );
    }
    // "No leading "0" characters are allowed" (a lone "0" is fine: S-1-0-0).
    for text in ["S-1-05-18", "S-1-5-018", "S-1-5-00", "S-1-00-0"] {
        assert_eq!(
            Sid::parse_sid_string(text),
            Err(Error::SidStringLeadingZero),
            "{text:?}"
        );
    }
    // SubAuthority is unsigned 32-bit (2.4.2.2).
    assert_eq!(
        Sid::parse_sid_string("S-1-5-4294967296"),
        Err(Error::SidStringValueOutOfRange)
    );
    assert!(Sid::parse_sid_string("S-1-5-4294967295").is_ok());
    // Only the canonical authority form for the value (2.4.2.1 comments):
    // decimal iff < 2^32, hexadecimal iff >= 2^32.
    for text in [
        "S-1-4294967296-1",     // decimal form of 2^32
        "S-1-9999999999-1",     // decimal form above 2^32
        "S-1-0x000000000005-1", // hexadecimal form of 5
        "S-1-0x0000FFFFFFFF-1", // hexadecimal form of 2^32 - 1
    ] {
        assert_eq!(
            Sid::parse_sid_string(text),
            Err(Error::SidStringNonCanonicalAuthority),
            "{text:?}"
        );
    }
}
