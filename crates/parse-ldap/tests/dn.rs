//! Tests for `parse_ldap::dn` (docs/49 R49-11, task L5).
//!
//! Every test names its source. The DN strings come from the examples printed
//! in RFC 4514 §4, RFC 4517 §3.3.9, [MS-ADTS] v20261026 3.1.1.1.4,
//! 3.1.1.3.1.2.1, 3.1.1.3.1.2.3 and 3.1.1.3.4.1.5, or are built here from the
//! RFC 4514 §3 grammar and the project rules (Q-080, Q-090, docs/49 §2.4,
//! docs/46 §8.3). No vector comes from any other implementation or test suite
//! (docs/CLEAN-ROOM.md).

use parse_ldap::dn::{parse_ldap_dn, AttributeType, Dn, DnError, LdapDn, Rdn, OBJECT_GUID_OCTETS};
use parse_ldap::{MAX_DN_RDNS, MAX_LDAPDN_OCTETS, MAX_RDN_VALUE_OCTETS};

fn parse(s: &str) -> Result<Dn, DnError> {
    Dn::parse(s)
}

/// `(attributeType, value)` of each RDN, leaf first.
fn pairs(dn: &Dn) -> Vec<(String, String)> {
    dn.rdns()
        .iter()
        .map(|r| (r.attribute_type().as_str().to_owned(), r.value().to_owned()))
        .collect()
}

fn owned(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(a, v)| ((*a).to_owned(), (*v).to_owned()))
        .collect()
}

fn rdn(att: &str, value: &str) -> Rdn {
    Rdn::new(AttributeType::new(att).unwrap(), value).unwrap()
}

/// `parse(s)` succeeds and its canonical encoding is `s` again.
fn assert_canonical(s: &str) -> Dn {
    let dn = parse(s).unwrap();
    assert_eq!(dn.encode(), s);
    assert_eq!(parse(&dn.encode()).unwrap(), dn);
    dn
}

// ---- RFC 4514 §4 examples ---------------------------------------------------

// Source: RFC 4514 §4, first example (also RFC 4517 §3.3.9): three RDNs.
#[test]
fn rfc4514_example_three_rdns() {
    let dn = assert_canonical("UID=jsmith,DC=example,DC=net");
    assert_eq!(
        pairs(&dn),
        owned(&[("UID", "jsmith"), ("DC", "example"), ("DC", "net")])
    );
}

// Source: RFC 4514 §4, second example (also RFC 4517 §3.3.9): "the first RDN
// is multi-valued". Refused: [MS-ADTS] 3.1.1.3.1.2.3 ("MAX equals 1");
// docs/49 §7.
#[test]
fn rfc4514_example_multi_valued_rdn_refused() {
    assert_eq!(
        parse("OU=Sales+CN=J.  Smith,DC=example,DC=net"),
        Err(DnError::MultiValuedRdn)
    );
    assert_eq!(
        parse("OU=Sales+CN=J. Smith,DC=example,DC=net"),
        Err(DnError::MultiValuedRdn)
    );
}

// Source: RFC 4514 §4, third example ("escaping of a special characters");
// RFC 4517 §3.3.9 gives the variant without the quotes.
#[test]
fn rfc4514_example_escaped_specials() {
    let dn = assert_canonical(r#"CN=James \"Jim\" Smith\, III,DC=example,DC=net"#);
    assert_eq!(
        pairs(&dn),
        owned(&[
            ("CN", r#"James "Jim" Smith, III"#),
            ("DC", "example"),
            ("DC", "net")
        ])
    );
    let dn = assert_canonical(r"CN=John Smith\, III,DC=example,DC=net");
    assert_eq!(dn.rdns()[0].value(), "John Smith, III");
}

// Source: RFC 4514 §4, fourth example (a carriage return as `\0d`). The
// escape is well-formed, but 0x0D is not printable ASCII: refused (Q-080
// item 1; docs/49 §7).
#[test]
fn rfc4514_example_carriage_return_refused() {
    assert_eq!(
        parse(r"CN=Before\0dAfter,DC=example,DC=net"),
        Err(DnError::ValueNotPrintableAscii)
    );
}

// Source: RFC 4514 §4, fifth example (unrecognised type, BER value as a
// hexstring); RFC 4517 §3.3.9 adds ",DC=example,DC=com". Refused: no handler
// for BER-encoded values in phase 1 (Q-195 item 12).
#[test]
fn rfc4514_example_hexstring_refused() {
    assert_eq!(
        parse("1.3.6.1.4.1.1466.0=#04024869"),
        Err(DnError::HexStringValue)
    );
    assert_eq!(
        parse("1.3.6.1.4.1.1466.0=#04024869,DC=example,DC=com"),
        Err(DnError::HexStringValue)
    );
}

// Source: RFC 4514 §4, last example (UTF-8 octets escaped as hexpairs).
// Non-ASCII after unescaping: refused (Q-080 item 1, P-9).
#[test]
fn rfc4514_example_non_ascii_refused() {
    assert_eq!(
        parse(r"CN=Lu\C4\8Di\C4\87"),
        Err(DnError::ValueNotPrintableAscii)
    );
    // The same letters unescaped (RFC 4514 §3 UTFMB) are refused alike.
    assert_eq!(
        parse("CN=Lu\u{10D}i\u{107}"),
        Err(DnError::ValueNotPrintableAscii)
    );
}

// ---- [MS-ADTS] examples -----------------------------------------------------

// Source: [MS-ADTS] 3.1.1.1.4 — "cn=Peter Houston,ou=NTDEV,dc=microsoft,dc=com",
// and the RDN written with the attributeID: "2.5.4.3=Peter Houston".
#[test]
fn adts_examples_descr_and_numericoid() {
    let dn = assert_canonical("cn=Peter Houston,ou=NTDEV,dc=microsoft,dc=com");
    assert_eq!(dn.rdns().len(), 4);
    let dn = assert_canonical("2.5.4.3=Peter Houston");
    assert!(dn.rdns()[0].attribute_type().is_numericoid());
    assert_eq!(dn.rdns()[0].value(), "Peter Houston");
}

// Source: [MS-ADTS] 3.1.1.3.1.2.3 — "F=John Smith+F=David Jones,
// OU=Users,DC=Fabrikam,DC=com". As printed it has a space after the first
// comma, which the RFC 4514 §3 grammar does not allow (an attributeType
// begins with ALPHA or DIGIT): a syntax error, which takes precedence over
// the multi-valued refusal (Q-195 items 3, 7). Without that space it is refused as
// multi-valued, as [MS-ADTS] requires.
#[test]
fn adts_multi_valued_examples() {
    assert_eq!(
        parse("F=John Smith+F=David Jones, OU=Users,DC=Fabrikam,DC=com"),
        Err(DnError::InvalidAttributeType)
    );
    assert_eq!(
        parse("F=John Smith+F=David Jones,OU=Users,DC=Fabrikam,DC=com"),
        Err(DnError::MultiValuedRdn)
    );
    assert_eq!(
        parse("F=John Smith+l=Redmond,OU=Users,DC=Fabrikam,DC=com"),
        Err(DnError::MultiValuedRdn)
    );
}

// Source: [MS-ADTS] 3.1.1.3.4.1.5 prints the DN part of an extended DN as
// "CN=Administrator, CN=Users,DC=Fabrikam,DC=com" — again with a space after
// a comma: refused by the RFC 4514 §3 grammar (Q-195 item 3).
#[test]
fn space_after_comma_refused() {
    assert_eq!(
        parse("CN=Administrator, CN=Users,DC=Fabrikam,DC=com"),
        Err(DnError::InvalidAttributeType)
    );
    assert!(parse("CN=Administrator,CN=Users,DC=Fabrikam,DC=com").is_ok());
}

// ---- the comparison key -----------------------------------------------------

// Source: [MS-ADTS] 3.1.1.3.1.2.1 — "CN=Abc,OU=Users,DC=Fabrikam,DC=com" and
// "L=Abc,OU=Users,DC=Fabrikam,DC=com" cannot coexist: the value parts are
// what must be unique among siblings, so the key ignores the attributeType.
// Q-080 item 2: A–Z folded.
#[test]
fn comparison_key_ignores_attribute_type() {
    let a = parse("CN=Abc,OU=Users,DC=Fabrikam,DC=com").unwrap();
    let b = parse("L=Abc,OU=Users,DC=Fabrikam,DC=com").unwrap();
    assert_eq!(a.rdns()[0].comparison_key(), b"abc");
    assert_eq!(a.rdns()[0].comparison_key(), b.rdns()[0].comparison_key());
    // The value itself is never folded.
    assert_eq!(a.rdns()[0].value(), "Abc");
}

// Source: dirstore's documented RDN-key rule (crates/dirstore/src/comparison.rs
// module doc; Q-080 items 1-2; docs/46 §8.3 item 3): printable ASCII
// 0x20..=0x7E only, A–Z folded to a–z, every other byte kept. dirstore's key
// functions are crate-private, so the cross-check is against that rule,
// exhaustively over the printable range, and on dirstore's own documented
// samples ("Peter Houston", "A-Z[]_`az~").
#[test]
fn comparison_key_matches_dirstore_rule() {
    for b in 0x20u8..=0x7E {
        let value = [b'x', b, b'X'];
        let value = core::str::from_utf8(&value).unwrap();
        let expected: Vec<u8> = vec![b'x', if b.is_ascii_uppercase() { b + 32 } else { b }, b'x'];
        assert_eq!(rdn("cn", value).comparison_key(), expected, "byte {b:#04x}");
    }
    assert_eq!(
        rdn("cn", "Peter Houston").comparison_key(),
        b"peter houston"
    );
    assert_eq!(rdn("cn", "A-Z[]_`az~").comparison_key(), b"a-z[]_`az~");
}

// Source: the same rule's refusals (dirstore comparison.rs: RdnKeyEmpty,
// RdnForbiddenCharacter for 0x00 / 0x0A, RdnNotAscii otherwise; [MS-ADTS]
// 3.1.1.5.1.2): a value dirstore cannot key is refused by the parser too.
#[test]
fn values_dirstore_cannot_key_are_refused() {
    assert_eq!(parse("cn="), Err(DnError::EmptyValue));
    assert_eq!(parse(r"cn=a\0Ab"), Err(DnError::ValueNotPrintableAscii));
    assert_eq!(parse(r"cn=a\00b"), Err(DnError::ValueNotPrintableAscii));
    assert_eq!(parse(r"cn=a\09b"), Err(DnError::ValueNotPrintableAscii));
    assert_eq!(parse(r"cn=a\7Fb"), Err(DnError::ValueNotPrintableAscii));
    assert_eq!(parse("cn=a\tb"), Err(DnError::ValueNotPrintableAscii));
    assert_eq!(parse("cn=\u{e9}"), Err(DnError::ValueNotPrintableAscii));
    assert_eq!(parse(r"cn=\C3\A9"), Err(DnError::ValueNotPrintableAscii));
    assert_eq!(
        Rdn::new(AttributeType::new("cn").unwrap(), ""),
        Err(DnError::EmptyValue)
    );
    assert_eq!(
        Rdn::new(AttributeType::new("cn").unwrap(), "a\nb"),
        Err(DnError::ValueNotPrintableAscii)
    );
}

// ---- escapes ------------------------------------------------------------------

// Source: RFC 4514 §2.4 (the characters that may be prefixed by a backslash:
// ' ', '"', '#', '+', ',', ';', '<', '=', '>', '\') and §3 (pair = ESC ( ESC /
// special / hexpair ); unescaping). For each one: the `\c` form and the
// `\xx` hexpair form (both hex cases) unescape to the same value, and the
// value round-trips through the canonical encoder.
#[test]
fn escape_round_trip_for_each_special() {
    let specials = [' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\'];
    for c in specials {
        let value = format!("a{c}b");
        let by_char = parse(&format!("cn=a\\{c}b")).unwrap();
        let by_hex_upper = parse(&format!("cn=a\\{:02X}b", c as u8)).unwrap();
        let by_hex_lower = parse(&format!("cn=a\\{:02x}b", c as u8)).unwrap();
        assert_eq!(by_char.rdns()[0].value(), value, "{c:?}");
        assert_eq!(by_hex_upper, by_char, "{c:?}");
        assert_eq!(by_hex_lower, by_char, "{c:?}");
        assert_eq!(parse(&by_char.encode()).unwrap(), by_char, "{c:?}");
    }
}

// Source: RFC 4514 §2.4 (required escapes) and §3 (LUTF1 / SUTF1 / TUTF1):
// every printable character, alone and at the leading, middle and trailing
// position, survives encode → parse; and the encoder escapes exactly the
// required set.
#[test]
fn canonical_encoder_round_trips_every_printable_position() {
    for b in 0x20u8..=0x7E {
        let c = char::from(b);
        for value in [
            c.to_string(),
            format!("{c}a"),
            format!("a{c}a"),
            format!("a{c}"),
        ] {
            let dn = Dn::new(vec![rdn("cn", &value), rdn("dc", "x")]).unwrap();
            let text = dn.encode();
            assert_eq!(parse(&text).unwrap(), dn, "{text:?}");
        }
    }
    let dn = Dn::new(vec![rdn("cn", " #a=b# "), rdn("ou", r#""+,;<>\"#)]).unwrap();
    assert_eq!(dn.encode(), r#"cn=\ #a=b#\ ,ou=\"\+\,\;\<\>\\"#);
}

// Source: RFC 4514 §3 — '=' and a non-leading '#' are allowed unescaped in a
// value (LUTF1 / SUTF1 / TUTF1 include %x3D; SUTF1 / TUTF1 include %x23); a
// space is allowed in the middle (SUTF1 includes %x20).
#[test]
fn unescaped_equals_sharp_and_inner_space_accepted() {
    let dn = assert_canonical("cn=a=b,ou=x#,dc=a b#c");
    assert_eq!(
        pairs(&dn),
        owned(&[("cn", "a=b"), ("ou", "x#"), ("dc", "a b#c")])
    );
}

// Source: RFC 4514 §3 — `pair = ESC ( ESC / special / hexpair )`.
#[test]
fn bad_escapes_rejected() {
    for s in [
        r"cn=a\",
        r"cn=a\4",
        r"cn=a\4g",
        r"cn=a\x",
        r"cn=a\4,dc=b",
        r"cn=\ga",
    ] {
        assert_eq!(parse(s), Err(DnError::InvalidEscape), "{s:?}");
    }
}

// ---- grammar rejections -----------------------------------------------------

// Source: RFC 4514 §3 — `distinguishedName = [ relativeDistinguishedName
// *( COMMA relativeDistinguishedName ) ]`: an RDN (or an AVA after PLUS) may
// not be empty.
#[test]
fn trailing_leading_and_doubled_separators_rejected() {
    assert_eq!(parse("cn=a,"), Err(DnError::EmptyRdn));
    assert_eq!(parse(",cn=a"), Err(DnError::EmptyRdn));
    assert_eq!(parse("cn=a,,dc=b"), Err(DnError::EmptyRdn));
    assert_eq!(parse("cn=a+"), Err(DnError::EmptyRdn));
    assert_eq!(parse(","), Err(DnError::EmptyRdn));
}

// Source: RFC 4514 §3 — `attributeTypeAndValue = attributeType EQUALS
// attributeValue`.
#[test]
fn missing_equals_rejected() {
    assert_eq!(parse("cn"), Err(DnError::MissingEquals));
    assert_eq!(parse("cn,dc=b"), Err(DnError::MissingEquals));
    assert_eq!(parse("cn=a,dc"), Err(DnError::MissingEquals));
    assert_eq!(parse("cn=a+ou"), Err(DnError::MissingEquals));
}

// Source: RFC 4514 §3 (`attributeType = descr / numericoid`; no attribute
// options); RFC 4512 §1.4 (`descr = keystring`; `numericoid = number 1*( DOT
// number )`; `number = DIGIT / ( LDIGIT 1*DIGIT )`).
#[test]
fn attribute_type_grammar() {
    for ok in [
        "cn",
        "C",
        "x-foo2",
        "2.5.4.3",
        "0.9.2342.19200300.100.1.25",
        "1.0",
    ] {
        assert!(parse(&format!("{ok}=v")).is_ok(), "{ok:?}");
    }
    for bad in [
        "=v",
        "-cn=v",
        "cn;lang-en=v",
        "c_n=v",
        "cn =v",
        " cn=v",
        "2=v",
        "01.2=v",
        "1..2=v",
        "1.2.=v",
        ".1.2=v",
        "1.a=v",
        "2abc=v",
        "c.n=v",
        "c\u{e9}=v",
    ] {
        assert_eq!(parse(bad), Err(DnError::InvalidAttributeType), "{bad:?}");
    }
    let long = "a".repeat(257);
    assert_eq!(
        AttributeType::new(&long),
        Err(DnError::AttributeTypeTooLong)
    );
    assert!(AttributeType::new(&"a".repeat(256)).is_ok());
}

// Source: RFC 4514 §3 — NUL, '"', ';', '<', '>' are in none of LUTF1 / SUTF1
// / TUTF1; SPACE is not in LUTF1 (leading) or TUTF1 (trailing).
#[test]
fn unescaped_characters_rejected() {
    for s in [
        "cn=a\"b",
        "cn=a;b",
        "cn=a<b",
        "cn=a>b",
        "cn=a\u{0}b",
        "cn= a",
        "cn=a ",
        "cn= ",
        "cn=a ,dc=b",
        "cn=a +ou=b",
    ] {
        assert_eq!(parse(s), Err(DnError::UnescapedCharacter), "{s:?}");
    }
}

// Source: RFC 4514 §3 — `hexstring = SHARP 1*hexpair`. A malformed
// hexstring is a syntax error; a well-formed one is a phase-1 refusal.
#[test]
fn hexstring_grammar() {
    for s in [
        "cn=#",
        "cn=#0",
        "cn=#0g",
        "cn=#abc",
        "cn=#ab cd",
        "cn=#,dc=x",
    ] {
        assert_eq!(parse(s), Err(DnError::InvalidHexString), "{s:?}");
    }
    assert_eq!(parse("cn=#0A0b"), Err(DnError::HexStringValue));
    // An escaped leading '#' is the string form.
    assert_eq!(parse(r"cn=\#0A").unwrap().rdns()[0].value(), "#0A");
}

// Source: Q-195 item 7 — the whole input is checked against the grammar
// first; a phase-1 refusal is reported only for a syntactically valid DN, and
// then the leftmost one.
#[test]
fn syntax_errors_take_precedence_over_refusals() {
    assert_eq!(parse("cn=\u{e9},dc=a b "), Err(DnError::UnescapedCharacter));
    assert_eq!(parse("cn=#00,dc"), Err(DnError::MissingEquals));
    assert_eq!(
        parse("cn=\u{e9},ou=a+ou=b"),
        Err(DnError::ValueNotPrintableAscii)
    );
    assert_eq!(parse("cn=a+ou=b,dc=\u{e9}"), Err(DnError::MultiValuedRdn));
    assert_eq!(parse("cn=,dc=#00"), Err(DnError::EmptyValue));
}

// ---- bounds ------------------------------------------------------------------

// Source: docs/49 §2.4 (MAX_LDAPDN_OCTETS = 2048).
#[test]
fn overlong_input_rejected() {
    // 9 RDNs: 7 values of 252, one of 200, one of 49 → exactly 2048 octets.
    let mut parts: Vec<String> = (0..7).map(|_| format!("cn={}", "v".repeat(252))).collect();
    parts.push(format!("cn={}", "v".repeat(200)));
    parts.push(format!("cn={}", "v".repeat(49)));
    let exact = parts.join(",");
    assert_eq!(exact.len(), MAX_LDAPDN_OCTETS);
    assert_eq!(parse(&exact).unwrap().rdns().len(), 9);
    let over = format!("{exact}v");
    assert_eq!(parse(&over), Err(DnError::TooLong));
    assert_eq!(parse_ldap_dn(&over), Err(DnError::TooLong));
    let over_guid = format!("<GUID={}>", "0".repeat(MAX_LDAPDN_OCTETS));
    assert_eq!(parse_ldap_dn(&over_guid), Err(DnError::TooLong));
}

// Source: docs/49 §2.4 (RDN count anchored to directory_pip::MAX_DN_DEPTH = 64).
#[test]
fn too_many_rdns_rejected() {
    let at_limit = vec!["a=b"; MAX_DN_RDNS].join(",");
    assert_eq!(parse(&at_limit).unwrap().rdns().len(), MAX_DN_RDNS);
    let over = vec!["a=b"; MAX_DN_RDNS + 1].join(",");
    assert_eq!(parse(&over), Err(DnError::TooManyRdns));
    let rdns = vec![rdn("a", "b"); MAX_DN_RDNS + 1];
    assert_eq!(Dn::new(rdns), Err(DnError::TooManyRdns));
}

// Source: [MS-ADTS] 3.1.1.5.1.2 ("The RDN size MUST be less than 255
// characters"), strict reading of Q-090 / A-30 (att=val counted whole, value
// unescaped); the shortest attributeType has one character (RFC 4512 §1.4),
// so a value over 252 octets can name no object.
#[test]
fn rdn_value_size_bound() {
    let max = "v".repeat(MAX_RDN_VALUE_OCTETS);
    assert_eq!(parse(&format!("L={max}")).unwrap().rdns()[0].value(), max);
    let over = "v".repeat(MAX_RDN_VALUE_OCTETS + 1);
    assert_eq!(parse(&format!("L={over}")), Err(DnError::ValueTooLong));
    // Counted unescaped: 252 escaped commas (504 input octets) are accepted.
    let commas = r"\,".repeat(MAX_RDN_VALUE_OCTETS);
    assert_eq!(
        parse(&format!("cn={commas}")).unwrap().rdns()[0]
            .value()
            .len(),
        MAX_RDN_VALUE_OCTETS
    );
    assert_eq!(
        Rdn::new(AttributeType::new("cn").unwrap(), &over),
        Err(DnError::ValueTooLong)
    );
}

// Source: docs/49 §2.4 — a constructed Dn must also encode within
// MAX_LDAPDN_OCTETS, so that it parses back (5 RDNs of 252 escaped quotes
// encode to 5 * 507 + 4 octets).
#[test]
fn constructed_dn_encoding_bounded() {
    let quotes = "\"".repeat(MAX_RDN_VALUE_OCTETS);
    let rdns = vec![rdn("cn", &quotes); 5];
    assert_eq!(Dn::new(rdns), Err(DnError::TooLong));
    let rdns = vec![rdn("cn", &quotes); 4];
    let dn = Dn::new(rdns).unwrap();
    assert_eq!(parse(&dn.encode()).unwrap(), dn);
}

// ---- the empty DN -------------------------------------------------------------

// Source: RFC 4514 §2.1 ("If the RDNSequence is an empty sequence, the result
// is the empty or zero-length string") and §3 (the optional RDN list);
// docs/49 §5.2 (base "" is the rootDSE).
#[test]
fn empty_dn() {
    let dn = parse("").unwrap();
    assert!(dn.is_empty());
    assert_eq!(dn.encode(), "");
    assert_eq!(parse_ldap_dn(""), Ok(LdapDn::Distinguished(Dn::default())));
    assert_eq!(Dn::new(vec![]).unwrap(), dn);
}

// ---- <GUID=…> -----------------------------------------------------------------

/// The octets of the [MS-ADTS] 3.1.1.3.4.1.5 example GUID.
const ADTS_EXAMPLE_GUID: [u8; OBJECT_GUID_OCTETS] = [
    0xb3, 0xd4, 0xbf, 0xbd, 0x3c, 0x45, 0xee, 0x42, 0x98, 0xe2, 0x7b, 0x4a, 0x69, 0x8a, 0x61, 0xb8,
];

// Source: [MS-ADTS] 3.1.1.3.1.2.4 (`<GUID=object_guid>`, "the hexadecimal
// representation of the binary form of a GUID ([MS-DTYP] section 2.3.4)") and
// the example of 3.1.1.3.4.1.5, which prints one GUID as
// "b3d4bfbd3c45ee4298e27b4a698a61b8" (hexadecimal form) and as
// "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8" (dashed form). Read as the
// [MS-DTYP] 2.3.4.2 packet (Data1, Data2, Data3 little-endian, Data4 in
// order), the 16 octets give exactly the members the dashed form shows —
// consistent with A-31's mapping (Q-100 item 1).
#[test]
fn guid_form_valid() {
    let parsed = parse_ldap_dn("<GUID=b3d4bfbd3c45ee4298e27b4a698a61b8>").unwrap();
    assert_eq!(parsed, LdapDn::ObjectGuid(ADTS_EXAMPLE_GUID));
    let LdapDn::ObjectGuid(g) = parsed else {
        unreachable!()
    };
    assert_eq!(u32::from_le_bytes([g[0], g[1], g[2], g[3]]), 0xbdbf_d4b3);
    assert_eq!(u16::from_le_bytes([g[4], g[5]]), 0x453c);
    assert_eq!(u16::from_le_bytes([g[6], g[7]]), 0x42ee);
    assert_eq!(&g[8..], &[0x98, 0xe2, 0x7b, 0x4a, 0x69, 0x8a, 0x61, 0xb8]);
}

// Source: [MS-ADTS] 3.1.1.3.1.2.4 gives no letter case for the hexadecimal
// digits (its example in 3.1.1.3.4.1.5 is lowercase); RFC 4512 §1.4 `HEX`
// admits both cases: both accepted, same octets (Q-195 item 1). The literal
// "GUID" is matched as printed (only "TTL" has a case-insensitive rule).
#[test]
fn guid_form_letter_case() {
    assert_eq!(
        parse_ldap_dn("<GUID=B3D4BFBD3C45EE4298E27B4A698A61B8>"),
        Ok(LdapDn::ObjectGuid(ADTS_EXAMPLE_GUID))
    );
    assert_eq!(
        parse_ldap_dn("<GUID=B3d4BfBd3c45EE4298e27b4a698a61B8>"),
        Ok(LdapDn::ObjectGuid(ADTS_EXAMPLE_GUID))
    );
    assert_eq!(
        parse_ldap_dn("<guid=b3d4bfbd3c45ee4298e27b4a698a61b8>"),
        Err(DnError::UnsupportedExtendedForm)
    );
}

// Source: [MS-ADTS] 3.1.1.3.1.2.4; [MS-DTYP] 2.3.4 ("a 16-byte structure"):
// exactly 32 hexadecimal digits. The dashed form is defined only by RFC 4122
// (not an allowed source; docs/49 §7): refused.
#[test]
fn guid_form_wrong_length_or_not_hex() {
    for s in [
        "<GUID=>",
        "<GUID=b3d4bfbd3c45ee4298e27b4a698a61b>",
        "<GUID=b3d4bfbd3c45ee4298e27b4a698a61b8b>",
        "<GUID=b3d4bfbd3c45ee4298e27b4a698a61b800>",
        "<GUID=b3d4bfbd3c45ee4298e27b4a698a61bg>",
        "<GUID=b3d4bfbd3c45ee4298e27b4a698a61b8",
        "<GUID= b3d4bfbd3c45ee4298e27b4a698a61b8>",
        "<GUID=bdbfd4b3-453c-42ee-98e2-7b4a698a61b8>",
        "<GUID={bdbfd4b3-453c-42ee-98e2-7b4a698a61b8}>",
    ] {
        assert_eq!(parse_ldap_dn(s), Err(DnError::InvalidObjectGuid), "{s:?}");
    }
}

// Source: [MS-ADTS] 3.1.1.3.1.2.4 (the other alternative forms: `<SID=sid>`,
// `<WKGUID=guid, object_DN>`, the TTL-DN `<TTL=seconds,<dn>>`) and
// 3.1.1.3.4.1.5 (the extended DN, "not accepted as a means of specifying DNs
// in requests"); docs/49 §7, §14: no code path in phase 1.
#[test]
fn other_extended_forms_refused() {
    for s in [
        "<SID=01050000000000051500000061eb5b8c50ef705befda808bf4010000>",
        "<SID=S-1-5-21-2354834273-1534127952-2340477679-500>",
        "<WKGUID=b3d4bfbd3c45ee4298e27b4a698a61b8,DC=Fabrikam,DC=com>",
        "<TTL=60,<CN=x,DC=Fabrikam,DC=com>>",
        "<GUID=b3d4bfbd3c45ee4298e27b4a698a61b8>;CN=Administrator,CN=Users,DC=Fabrikam,DC=com",
        "<",
        "<>",
    ] {
        assert_eq!(
            parse_ldap_dn(s),
            Err(DnError::UnsupportedExtendedForm),
            "{s:?}"
        );
    }
    // Dn::parse knows no alternative form: '<' cannot begin an attributeType.
    assert_eq!(
        parse("<GUID=b3d4bfbd3c45ee4298e27b4a698a61b8>"),
        Err(DnError::InvalidAttributeType)
    );
}

// Source: RFC 4514 §3; docs/49 R49-11 — parse_ldap_dn returns the RFC 4514
// form for an ordinary DN.
#[test]
fn ldap_dn_dispatches_to_rfc4514() {
    assert_eq!(
        parse_ldap_dn("cn=Peter Houston,ou=NTDEV,dc=microsoft"),
        Ok(LdapDn::Distinguished(
            parse("cn=Peter Houston,ou=NTDEV,dc=microsoft").unwrap()
        ))
    );
}

// ---- the directory's canonical form (directory-pip dn_of) ------------------

// Source: crates/directory-pip/src/view.rs `DirectoryView::dn_of` (leaf first,
// each component `<lDAPDisplayName of the RDN attribute>=<stored RDN value>`,
// unescaped), on the objects of the [MS-ADTS] 3.1.1.1.4 example as dirstore
// holds them (dc "microsoft" with no parent, ou "NTDEV", cn "Peter Houston";
// lDAPDisplayNames cn / ou / dc from crates/ad-schema). The encoder's output
// is those components joined with ',', and parses back to the same
// (type, value) pairs. directory-pip is not a dependency of this crate, so the
// components are written out here.
#[test]
fn encoder_matches_dn_of_form() {
    let dn_of = ["cn=Peter Houston", "ou=NTDEV", "dc=microsoft"];
    let dn = Dn::from_directory_rdns(&dn_of).unwrap();
    assert_eq!(dn.encode(), dn_of.join(","));
    let back = parse(&dn.encode()).unwrap();
    assert_eq!(back, dn);
    for (component, r) in dn_of.iter().zip(back.rdns()) {
        assert_eq!(
            format!("{}={}", r.attribute_type().as_str(), r.value()),
            *component
        );
    }
}

// Source: RFC 4514 §2.4 (required escapes) vs dn_of (unescaped components):
// the two differ exactly when a stored value holds a character that must be
// escaped (Q-195 item 8). The (type, value) pairs still match the components.
#[test]
fn encoder_escapes_where_dn_of_does_not() {
    let dn_of = ["cn=Smith, John", "ou=#1 R+D ", "dc=a=b"];
    let dn = Dn::from_directory_rdns(&dn_of).unwrap();
    assert_eq!(dn.encode(), r"cn=Smith\, John,ou=\#1 R\+D\ ,dc=a=b");
    assert_ne!(dn.encode(), dn_of.join(","));
    let back = parse(&dn.encode()).unwrap();
    assert_eq!(back, dn);
    assert_eq!(back.rdns()[0].value(), "Smith, John");
    assert_eq!(back.rdns()[1].value(), "#1 R+D ");
    assert_eq!(back.rdns()[2].value(), "a=b");
}

// Source: [MS-ADTS] 3.1.1.1.4 (RDN = "att=val"); RFC 4512 §1.4 (an
// attributeType holds no '='); docs/49 §2.4.
#[test]
fn from_directory_rdns_rejections() {
    assert_eq!(
        Dn::from_directory_rdns(&["cn"]),
        Err(DnError::MissingEquals)
    );
    assert_eq!(
        Dn::from_directory_rdns(&["c n=x"]),
        Err(DnError::InvalidAttributeType)
    );
    assert_eq!(Dn::from_directory_rdns(&["cn="]), Err(DnError::EmptyValue));
    assert_eq!(
        Dn::from_directory_rdns(&["cn=\u{e9}"]),
        Err(DnError::ValueNotPrintableAscii)
    );
    let too_many = vec!["cn=x"; MAX_DN_RDNS + 1];
    assert_eq!(
        Dn::from_directory_rdns(&too_many),
        Err(DnError::TooManyRdns)
    );
    assert!(Dn::from_directory_rdns::<&str>(&[]).unwrap().is_empty());
}

// ---- errors carry no input --------------------------------------------------

// Source: docs/CLEAN-ROOM.md (nothing attacker-supplied in errors); the Display
// strings are fixed.
#[test]
fn error_display_is_fixed_text() {
    let e = parse("cn=secret\u{e9}").unwrap_err();
    assert!(!e.to_string().contains("secret"));
}
