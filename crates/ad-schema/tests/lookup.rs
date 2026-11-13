//! The lookups for the PDP and the LDAP layer (docs/46 §7).
//!
//! Source: docs/46 §5.2 (schemaIdGuid and property-set column), §4.2
//! (class schemaIdGuid, defaultObjectCategory), §7; A-28 / Q-081 (the
//! shared-GUID flag: dNSHostName's property set equals its schemaIdGuid,
//! [MS-ADA1] 2.185; most specific class as the tree root); [MS-ADTS]
//! v20261026 3.1.1.2.3.3 (property-set table), 3.1.1.2.4.3 (objectClass
//! order), 3.1.1.4.2 (CLASSATTS); Q-080 (ASCII, case-insensitive names).
//! Expected GUID packets are written out from the printed strings with the
//! [MS-DTYP] 2.3.4.2 packet layout (Data1 / Data2 / Data3 little-endian,
//! Data4 in order).

use ad_schema::{phase1, LookupError, Phase1Schema};
use dirstore::{AttrClass, AttrId, ClassId};

fn p1() -> Phase1Schema {
    phase1().unwrap()
}

#[test]
fn shared_guid_flag_is_true_only_for_dns_host_name() {
    // Source: A-28 / Q-081 item 2; [MS-ADA1] 2.185 (dNSHostName:
    // attributeSecurityGuid = schemaIdGuid = 72e39547-…); docs/46 §5.2 (PS
    // column).
    let p1 = p1();
    let dns = p1.attribute_by_name("dNSHostName").unwrap();
    let ps = p1.property_set(dns).unwrap().unwrap();
    assert!(ps.is_attribute_guid);
    assert_eq!(ps.guid, p1.attribute_schema_id_guid(dns).unwrap());
    let mut with_ps = 0;
    for a in p1.attributes() {
        match p1.property_set(a.id).unwrap() {
            Some(ps) if a.id != dns => {
                with_ps += 1;
                assert!(!ps.is_attribute_guid, "{}", a.entry.ldap_display_name);
            }
            Some(_) => with_ps += 1,
            None => assert!(a.entry.attribute_security_guid.is_none()),
        }
    }
    // docs/46 §5.2: PI 10, GI 2, AR 3, GM 2, DH 1.
    assert_eq!(with_ps, 18);
    // An unknown attribute is an error (the PDP denies).
    assert_eq!(
        p1.property_set(AttrId(0x7FFF_FFFF)),
        Err(LookupError::UnknownAttribute(AttrId(0x7FFF_FFFF)))
    );
}

#[test]
fn property_set_guids_per_docs46() {
    // Source: docs/46 §5.2 (PS legend: PI e48d0154-bcf8-11d1-8702-
    // 00c04fb96050, GI 59ba2f42-…, AR 4c164200-…, GM bc0ac240-…, DH
    // 72e39547-…); [MS-ADTS] 3.1.1.2.3.3 (the same GUIDs, upper case).
    let p1 = p1();
    let packet = |name: &str| {
        let id = p1.attribute_by_name(name).unwrap();
        p1.property_set(id).unwrap().unwrap().guid.to_packet()
    };
    let pi = [
        0x54, 0x01, 0x8d, 0xe4, 0xf8, 0xbc, 0xd1, 0x11, 0x87, 0x02, 0x00, 0xc0, 0x4f, 0xb9, 0x60,
        0x50,
    ];
    let gi = [
        0x42, 0x2f, 0xba, 0x59, 0xa2, 0x79, 0xd0, 0x11, 0x90, 0x20, 0x00, 0xc0, 0x4f, 0xc2, 0xd3,
        0xcf,
    ];
    let ar = [
        0x00, 0x42, 0x16, 0x4c, 0xc0, 0x20, 0xd0, 0x11, 0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05,
        0x29,
    ];
    let gm = [
        0x40, 0xc2, 0x0a, 0xbc, 0xa9, 0x79, 0xd0, 0x11, 0x90, 0x20, 0x00, 0xc0, 0x4f, 0xc2, 0xd4,
        0xcf,
    ];
    assert_eq!(packet("cn"), pi);
    assert_eq!(packet("objectClass"), pi);
    assert_eq!(packet("sAMAccountName"), gi);
    assert_eq!(packet("objectSid"), gi);
    assert_eq!(packet("userAccountControl"), ar);
    assert_eq!(packet("pwdLastSet"), ar);
    assert_eq!(packet("member"), gm);
    assert_eq!(packet("memberOf"), gm);
    for name in [
        "nTSecurityDescriptor",
        "dc",
        "groupType",
        "whenCreated",
        "unicodePwd",
    ] {
        let id = p1.attribute_by_name(name).unwrap();
        assert_eq!(p1.property_set(id), Ok(None), "{name}");
    }
}

#[test]
fn schema_id_guids() {
    // Source: docs/46 §5.2 / [MS-ADA3] 2.40 (objectClass bf9679e5-0de6-
    // 11d0-a285-00aa003049e2); docs/46 §4.2 / [MS-ADSC] 2.21 (computer
    // bf967a86-0de6-11d0-a285-00aa003049e2).
    let p1 = p1();
    assert_eq!(
        p1.attribute_schema_id_guid(AttrId(0)).unwrap().to_packet(),
        [
            0xe5, 0x79, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30,
            0x49, 0xe2
        ]
    );
    let computer = p1.class_by_name("computer").unwrap();
    assert_eq!(
        p1.class_schema_id_guid(computer).unwrap().to_packet(),
        [
            0x86, 0x7a, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30,
            0x49, 0xe2
        ]
    );
    assert_eq!(
        p1.class_schema_id_guid(ClassId(0x7FFF_FFFF)),
        Err(LookupError::UnknownClass(ClassId(0x7FFF_FFFF)))
    );
    // All 45 schemaIDGUIDs are distinct ([MS-ADTS] 3.1.1.2.3 "Unique").
    let mut all: Vec<_> = p1
        .attributes()
        .map(|a| a.schema_id_guid)
        .chain(p1.classes().map(|c| c.schema_id_guid))
        .collect();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), 45);
}

#[test]
fn class_chain_of_a_class_set() {
    // Source: [MS-ADTS] 3.1.1.2.4.3 ("[ top, person, organizationalPerson,
    // user ]"; computer adds itself last); A-28 (most specific = root).
    let p1 = p1();
    let c = |n: &str| p1.class_by_name(n).unwrap();
    let set = [
        c("user"),
        c("top"),
        c("computer"),
        c("organizationalPerson"),
        c("person"),
    ];
    let chain = p1.class_chain(&set).unwrap();
    assert_eq!(chain.most_specific.id, c("computer"));
    assert_eq!(
        chain.most_specific.schema_id_guid,
        p1.class_schema_id_guid(c("computer")).unwrap()
    );
    let supers: Vec<ClassId> = chain.superclasses.iter().map(|s| s.id).collect();
    assert_eq!(
        supers,
        vec![c("top"), c("person"), c("organizationalPerson"), c("user")]
    );
    for s in &chain.superclasses {
        assert_eq!(s.schema_id_guid, p1.class_schema_id_guid(s.id).unwrap());
    }
    // objectClass order on the class itself.
    assert_eq!(
        p1.class(c("user")).unwrap().object_class,
        vec![c("top"), c("person"), c("organizationalPerson"), c("user")]
    );
    // domainDNS: top, domain, domainDNS.
    let chain = p1
        .class_chain(&[c("domainDNS"), c("domain"), c("top")])
        .unwrap();
    assert_eq!(chain.most_specific.id, c("domainDNS"));
    // Not one chain: a gap, two leaves, a repeat, an unknown id, empty.
    for bad in [
        vec![c("top"), c("user")],
        vec![c("top"), c("group"), c("container")],
        vec![c("top"), c("top"), c("group")],
        vec![c("top"), ClassId(0x7FFF_FFFF)],
        vec![],
    ] {
        assert_eq!(
            p1.class_chain(&bad),
            Err(LookupError::InvalidClassChain),
            "{bad:?}"
        );
    }
}

#[test]
fn names_are_ascii_case_insensitive() {
    // Source: Q-080 (ASCII, A–Z fold), as applied to lDAPDisplayName.
    let p1 = p1();
    assert_eq!(p1.attribute_by_name("objectClass"), Some(AttrId(0)));
    assert_eq!(p1.attribute_by_name("OBJECTCLASS"), Some(AttrId(0)));
    assert_eq!(p1.attribute_by_name("objectclass"), Some(AttrId(0)));
    assert_eq!(
        p1.attribute_by_name("SAMACCOUNTNAME"),
        p1.attribute_by_name("sAMAccountName")
    );
    assert!(p1.class_by_name("ORGANIZATIONALUNIT").is_some());
    assert_eq!(p1.class_by_name("DomainDns"), p1.class_by_name("domainDNS"));
    // Unknown, non-ASCII, class-vs-attribute, too long.
    assert_eq!(p1.attribute_by_name("displayName"), None);
    assert_eq!(p1.attribute_by_name("c\u{f6}"), None);
    assert_eq!(p1.attribute_by_name("user"), None);
    assert_eq!(p1.class_by_name("cn"), None);
    assert_eq!(p1.attribute_by_name(&"a".repeat(10_000)), None);
    assert_eq!(p1.attribute_by_name(""), None);
}

#[test]
fn class_attributes_are_classatts() {
    // Source: [MS-ADTS] 3.1.1.4.2 (CLASSATTS over SUPCLASSES and
    // AUXCLASSES); docs/46 §7 (cut to the 35 definitions, derived and
    // secret included).
    let p1 = p1();
    let a = |n: &str| p1.attribute_by_name(n).unwrap();
    let names = |c: &str| -> Vec<&str> {
        let id = p1.class_by_name(c).unwrap();
        let mut v: Vec<&str> = p1
            .class_attributes(id)
            .unwrap()
            .iter()
            .map(|x| p1.attribute(*x).unwrap().entry.ldap_display_name)
            .collect();
        v.sort_unstable();
        v
    };
    let top = names("top");
    assert_eq!(top.len(), 12);
    // computer: top's 12 + user's (incl. aux) + ou (organizationalPerson) +
    // dNSHostName.
    let computer = names("computer");
    for n in [
        "objectClass",
        "dNSHostName",
        "ou",
        "sAMAccountName",
        "unicodePwd",
        "supplementalCredentials",
        "userAccountControl",
        "memberOf",
    ] {
        assert!(computer.contains(&n), "computer lacks {n}");
    }
    assert!(!computer.contains(&"member"));
    assert!(!computer.contains(&"groupType"));
    let group = names("group");
    assert!(group.contains(&"member") && group.contains(&"groupType"));
    assert!(!group.contains(&"userAccountControl") && !group.contains(&"dNSHostName"));
    let domain_dns = names("domainDNS");
    assert!(domain_dns.contains(&"dc") && domain_dns.contains(&"objectSid"));
    // Secrets no phase-1 class allows appear in no CLASSATTS.
    for c in p1.classes() {
        for s in [
            "currentValue",
            "priorValue",
            "trustAuthIncoming",
            "initialAuthOutgoing",
        ] {
            assert!(!c.class_attributes.contains(&a(s)), "{s}");
        }
    }
    assert_eq!(
        p1.class_attributes(ClassId(0x7FFF_FFFF)),
        Err(LookupError::UnknownClass(ClassId(0x7FFF_FFFF)))
    );
}

#[test]
fn attr_class_and_default_object_category() {
    // Source: docs/46 §6 (AttrClass), §4.2 (defaultObjectCategory: user →
    // CN=Person, domain → CN=Domain-DNS), R46-5.
    let p1 = p1();
    let a = |n: &str| p1.attribute_by_name(n).unwrap();
    let c = |n: &str| p1.class_by_name(n).unwrap();
    assert_eq!(p1.attr_class(a("unicodePwd")), Ok(AttrClass::Secret));
    assert_eq!(p1.attr_class(a("cn")), Ok(AttrClass::Normal));
    assert_eq!(
        p1.class(c("user")).unwrap().default_object_category,
        c("person")
    );
    assert_eq!(
        p1.class(c("organizationalPerson"))
            .unwrap()
            .default_object_category,
        c("person")
    );
    assert_eq!(
        p1.class(c("domain")).unwrap().default_object_category,
        c("domainDNS")
    );
    assert_eq!(
        p1.class(c("computer")).unwrap().default_object_category,
        c("computer")
    );
    assert_eq!(
        p1.class(c("top")).unwrap().default_object_category,
        c("top")
    );
    // Instantiable: the six structural classes.
    let mut inst: Vec<_> = p1
        .classes()
        .filter(|x| x.instantiable)
        .map(|x| x.entry.ldap_display_name)
        .collect();
    inst.sort_unstable();
    assert_eq!(
        inst,
        vec![
            "computer",
            "container",
            "domainDNS",
            "group",
            "organizationalUnit",
            "user"
        ]
    );
}
