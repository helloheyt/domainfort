//! MakeAttid over NewPrefixTable(), and the 45 phase-1 identifiers.
//!
//! Source: [MS-DRSR] v20260309 5.16.4 — every OID ↔ ATTRTYP example printed
//! after NewPrefixTable() (13), and 5.16.3.8 (2.5.6.5 → 0x00010005); the
//! 5.16.4 procedure text for the refusals; docs/46 §3.3 (R46-3: refuse an
//! OID outside the table); docs/46 §4.2 and §5.2 (the 45 derived ids, which
//! docs/46 computed independently from the same procedure).

use ad_schema::{make_attid, phase1, OidError, MAX_OID_LEN};
use dirstore::{AttrId, ClassId};

#[test]
fn drsr_5_16_4_printed_examples() {
    // Source: [MS-DRSR] 5.16.4, the examples "using the PrefixTable returned
    // by the procedure NewPrefixTable", in printed order.
    let examples = [
        ("2.5.4.6", 0x0000_0006),                    // countryName
        ("2.5.6.2", 0x0001_0002),                    // country class
        ("1.2.840.113556.1.2.1", 0x0002_0001),       // instanceType
        ("1.2.840.113556.1.3.23", 0x0003_0017),      // container class
        ("2.5.5.1", 0x0008_0001),                    // DN syntax
        ("1.2.840.113556.1.4.1", 0x0009_0001),       // RDN attribute
        ("1.2.840.113556.1.5.1", 0x000a_0001),       // securityObject
        ("0.9.2342.19200300.100.1.1", 0x0015_0001),  // uid
        ("2.16.840.1.113730.3.1.1", 0x0016_0001),    // carLicense
        ("1.2.840.113556.1.5.7000.53", 0x0017_0035), // crossRefContainer
        ("2.5.21.2", 0x0018_0002),                   // ditContentRules
        ("2.5.18.1", 0x0019_0001),                   // createTimeStamp
        ("2.5.20.1", 0x001a_0001),                   // subSchema
    ];
    assert_eq!(examples.len(), 13);
    for (oid, attrtyp) in examples {
        assert_eq!(make_attid(oid), Ok(attrtyp), "{oid}");
    }
}

#[test]
fn drsr_5_16_3_8_example() {
    // Source: [MS-DRSR] 5.16.3.8 — "LDAP value: 2.5.6.5 / This corresponds
    // to ATTRTYP value: 0x00010005".
    assert_eq!(make_attid("2.5.6.5"), Ok(0x0001_0005));
}

#[test]
fn prefix_outside_new_prefix_table_is_refused() {
    // Source: docs/46 §3.3 (R46-3) — no AddPrefixTableEntry; docs/46 §4.3
    // names the RFC 2307 auxiliary classes (1.3.6.1.1.1.2.x) as outside the
    // table. [MS-DRSR] 5.16.4 procedure: with lastValue ≥ 16384 the two-byte
    // cut leaves part of the last arc in the prefix (never a table prefix);
    // a two-arc OID's last arc is packed into the first subidentifier.
    for oid in [
        "1.3.6.1.1.1.2.0",
        "1.3.6.1.1.1.2.6",
        "2.999.3",
        "1.2.840.113556.1.6.1",
        "1.2.840.113556.1.4.16384",
        "1.2.840.113556.1.4.4294967295",
        "2.5",
        "2.200",
    ] {
        assert_eq!(make_attid(oid), Err(OidError::PrefixNotInTable), "{oid}");
    }
    // The largest last arc below 16384 still maps (lowerWord = lastValue).
    assert_eq!(make_attid("1.2.840.113556.1.4.16383"), Ok(0x0009_3FFF));
}

#[test]
fn malformed_oids_are_refused() {
    // Source: X.690 8.19.4 and its NOTE (first arc 0..2; second arc ≤ 39
    // under 0 and 1); the project's strict dotted-decimal form (attid.rs).
    let too_long = format!("2.5.4.{}", "1".repeat(MAX_OID_LEN));
    for oid in [
        "",
        "2",
        "2.",
        ".2.5",
        "2..5",
        "2.5.4.06",
        "2.5.4.+6",
        "2.5.4.-6",
        "2.5.4. 6",
        "2.5.4.x",
        "3.1.2",
        "1.40.1",
        "0.40",
        "2.5.4.4294967296",
        "２.5.4.6",
        too_long.as_str(),
    ] {
        assert_eq!(make_attid(oid), Err(OidError::Malformed), "{oid:?}");
    }
}

/// docs/46 §4.2 — the ClassId column, by lDAPDisplayName.
const DOCS46_CLASS_IDS: [(&str, u32); 10] = [
    ("top", 0x0001_0000),
    ("domain", 0x000A_0042),
    ("domainDNS", 0x000A_0043),
    ("organizationalUnit", 0x0001_0005),
    ("container", 0x0003_0017),
    ("person", 0x0001_0006),
    ("organizationalPerson", 0x0001_0007),
    ("user", 0x000A_0009),
    ("computer", 0x0003_001E),
    ("group", 0x000A_0008),
];

/// docs/46 §5.2 — the ATTRTYP column, by lDAPDisplayName.
const DOCS46_ATTRIBUTE_IDS: [(&str, u32); 35] = [
    ("objectClass", 0x0000_0000),
    ("objectCategory", 0x0009_030E),
    ("nTSecurityDescriptor", 0x0002_0119),
    ("instanceType", 0x0002_0001),
    ("cn", 0x0000_0003),
    ("dc", 0x0015_0019),
    ("ou", 0x0000_000B),
    ("sAMAccountName", 0x0009_00DD),
    ("objectSid", 0x0009_0092),
    ("groupType", 0x0009_02EE),
    ("objectGUID", 0x0009_0002),
    ("name", 0x0009_0001),
    ("distinguishedName", 0x0000_0031),
    ("userPrincipalName", 0x0009_0290),
    ("servicePrincipalName", 0x0009_0303),
    ("dNSHostName", 0x0009_026B),
    ("userAccountControl", 0x0009_0008),
    ("accountExpires", 0x0009_009F),
    ("pwdLastSet", 0x0009_0060),
    ("member", 0x0000_001F),
    ("memberOf", 0x0002_0066),
    ("whenCreated", 0x0002_0002),
    ("whenChanged", 0x0002_0003),
    ("description", 0x0000_000D),
    ("currentValue", 0x0009_001B),
    ("dBCSPwd", 0x0009_0037),
    ("initialAuthIncoming", 0x0009_021B),
    ("initialAuthOutgoing", 0x0009_021C),
    ("lmPwdHistory", 0x0009_00A0),
    ("ntPwdHistory", 0x0009_005E),
    ("priorValue", 0x0009_0064),
    ("supplementalCredentials", 0x0009_007D),
    ("trustAuthIncoming", 0x0009_0081),
    ("trustAuthOutgoing", 0x0009_0087),
    ("unicodePwd", 0x0009_005A),
];

#[test]
fn computed_ids_equal_docs46_all_45() {
    // Source: docs/46 §4.2 (ClassId) and §5.2 (ATTRTYP) — the ids computed
    // here with MakeAttid from the [MS-ADSC] / [MS-ADA*] OIDs must equal
    // the ones docs/46 derived.
    let p1 = phase1().unwrap();
    assert_eq!(p1.classes().count(), DOCS46_CLASS_IDS.len());
    assert_eq!(p1.attributes().count(), DOCS46_ATTRIBUTE_IDS.len());
    for (name, id) in DOCS46_CLASS_IDS {
        assert_eq!(p1.class_by_name(name), Some(ClassId(id)), "{name}");
        let info = p1.class(ClassId(id)).unwrap();
        assert_eq!(info.entry.ldap_display_name, name);
        assert_eq!(make_attid(info.entry.governs_id), Ok(id), "{name}");
    }
    for (name, id) in DOCS46_ATTRIBUTE_IDS {
        assert_eq!(p1.attribute_by_name(name), Some(AttrId(id)), "{name}");
        let info = p1.attribute(AttrId(id)).unwrap();
        assert_eq!(info.entry.ldap_display_name, name);
        assert_eq!(make_attid(info.entry.attribute_id), Ok(id), "{name}");
    }
    // objectClass is AttrId(0) — a valid id, not a sentinel (docs/46 §8.6).
    let object_class = p1.attribute(AttrId(0)).unwrap();
    assert_eq!(object_class.entry.ldap_display_name, "objectClass");
}
