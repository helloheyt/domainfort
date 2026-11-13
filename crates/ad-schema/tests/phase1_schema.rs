//! `phase1()` builds, `dirstore::Schema::new` accepts it, and the dirstore
//! definitions carry every docs/46 decision.
//!
//! Source: docs/46 §4.4 (class definitions), §5.1 (35 = 17 stored + 7
//! derived + 11 secret), §5.4 (per-attribute mapping), §6 (AttrClass), §8.2
//! (R46-6 constraints), §8.5 (unique), §8.6 (R46-7), §10 (R46-4, R46-8,
//! R46-9; A-29); [MS-ADTS] v20261026 3.1.1.1.4 (the secret set), 2.2.12,
//! 2.2.16; Q-090 (rdn_att_len); Q-091 item 10 (printable ASCII).

use ad_schema::flags::{group_type, user_account_control};
use ad_schema::{phase1, Form, Phase1Schema, ATTRIBUTES, CLASSES, SECRET_ATTRIBUTES};
use dirstore::{
    AttrClass, AttrId, Link, Multiplicity, Storage, ValueConstraint, ValueRange, ValueSyntax,
};

fn p1() -> Phase1Schema {
    phase1().expect("phase-1 schema builds and Schema::new accepts it")
}

fn id(p1: &Phase1Schema, name: &str) -> AttrId {
    p1.attribute_by_name(name).expect(name)
}

fn names_where(
    p1: &Phase1Schema,
    pred: impl Fn(&dirstore::AttributeDefinition) -> bool,
) -> Vec<&'static str> {
    let mut v: Vec<_> = p1
        .attributes()
        .filter(|a| pred(p1.schema().attribute(a.id).unwrap()))
        .map(|a| a.entry.ldap_display_name)
        .collect();
    v.sort_unstable();
    v
}

fn sorted(mut v: Vec<&'static str>) -> Vec<&'static str> {
    v.sort_unstable();
    v
}

#[test]
fn builds_with_35_attributes_and_10_classes() {
    // Source: docs/46 §5.1 ("35 definitions = 17 stored + 7 derived + 11
    // secret"), §4.1 / R46-9 (10 classes).
    let p1 = p1();
    assert_eq!(ATTRIBUTES.len(), 35);
    assert_eq!(CLASSES.len(), 10);
    assert_eq!(p1.attributes().count(), 35);
    assert_eq!(p1.classes().count(), 10);
    let stored = names_where(&p1, |d| {
        d.storage == Storage::Stored && d.class != AttrClass::Secret
    });
    let derived = names_where(&p1, |d| d.storage == Storage::Derived);
    let secret = names_where(&p1, |d| d.class == AttrClass::Secret);
    assert_eq!((stored.len(), derived.len(), secret.len()), (17, 7, 11));
    // Source: docs/46 R46-4 — the seven derived attributes.
    assert_eq!(
        derived,
        sorted(vec![
            "objectClass",
            "objectCategory",
            "instanceType",
            "objectGUID",
            "name",
            "distinguishedName",
            "memberOf"
        ])
    );
    // Source: [MS-ADTS] 3.1.1.1.4 — the secret set, all AttrClass::Secret.
    assert_eq!(secret, sorted(SECRET_ATTRIBUTES.to_vec()));
    // Source: docs/46 §6 — no phase-1 attribute has fCONFIDENTIAL, so none
    // is Sensitive.
    assert!(names_where(&p1, |d| d.class == AttrClass::Sensitive).is_empty());
}

#[test]
fn member_of_is_the_derived_back_link_of_member() {
    // Source: docs/46 §2.3 items 2-3, §5.4; [MS-ADA2] 2.43 (member linkID 2),
    // 2.45 (memberOf linkID 3); [MS-ADTS] 3.1.1.2.3 (back = forward + 1).
    let p1 = p1();
    let member = p1.schema().attribute(id(&p1, "member")).unwrap();
    let member_of = p1.schema().attribute(id(&p1, "memberOf")).unwrap();
    assert_eq!(member.link, Some(Link::Forward { link_id: 2 }));
    assert_eq!(member.syntax, ValueSyntax::ObjectRef);
    assert_eq!(member.storage, Storage::Stored);
    assert_eq!(member.multiplicity, Multiplicity::MultiValued);
    assert_eq!(member_of.link, Some(Link::Back { link_id: 3 }));
    assert_eq!(member_of.storage, Storage::Derived);
    // No other attribute is a link.
    assert_eq!(
        names_where(&p1, |d| d.link.is_some()),
        sorted(vec!["member", "memberOf"])
    );
}

#[test]
fn value_constraints_per_r46_6() {
    // Source: docs/46 §8.2 / R46-6 / A-29; [MS-ADTS] 2.2.16, 2.2.12.
    let p1 = p1();
    let uac = p1
        .schema()
        .attribute(id(&p1, "userAccountControl"))
        .unwrap();
    assert_eq!(uac.syntax, ValueSyntax::Integer32);
    assert_eq!(
        uac.constraint,
        Some(ValueConstraint::AllowedBits(user_account_control::ALLOWED))
    );
    // ND allowed; each of the ten refused bits outside the mask.
    assert_ne!(
        user_account_control::ALLOWED & user_account_control::ADS_UF_NOT_DELEGATED,
        0
    );
    for bit in user_account_control::REFUSED {
        assert_eq!(user_account_control::ALLOWED & bit, 0, "{bit:#x}");
    }
    assert_eq!(user_account_control::ALLOWED, 0x0095_324A);
    let gt = p1.schema().attribute(id(&p1, "groupType")).unwrap();
    assert_eq!(
        gt.constraint,
        Some(ValueConstraint::AllowedValues(vec![
            2,
            4,
            8,
            i32::MIN | 2,
            i32::MIN | 4,
            i32::MIN | 8
        ]))
    );
    assert_eq!(group_type::ALLOWED_VALUES.len(), 6);
}

#[test]
fn unique_ascii_and_rdn_labels() {
    // Source: docs/46 §8.5 (unique: objectSid, sAMAccountName,
    // userPrincipalName, servicePrincipalName); Q-091 item 10 + Q-080 item 1
    // (printable ASCII on dNSHostName and the naming / unique strings;
    // description stays free text, Q-080 item 3); Q-090 (rdn_att_len on cn,
    // ou, dc = the length of the lDAPDisplayName, 2).
    let p1 = p1();
    assert_eq!(
        names_where(&p1, |d| d.unique),
        sorted(vec![
            "objectSid",
            "sAMAccountName",
            "userPrincipalName",
            "servicePrincipalName"
        ])
    );
    assert_eq!(
        names_where(&p1, |d| d.constraint
            == Some(ValueConstraint::AsciiPrintable)),
        sorted(vec![
            "cn",
            "dc",
            "ou",
            "sAMAccountName",
            "userPrincipalName",
            "servicePrincipalName",
            "dNSHostName"
        ])
    );
    assert_eq!(
        names_where(&p1, |d| d.rdn_att_len.is_some()),
        sorted(vec!["cn", "dc", "ou"])
    );
    for name in ["cn", "dc", "ou"] {
        assert_eq!(
            p1.schema().attribute(id(&p1, name)).unwrap().rdn_att_len,
            Some(2)
        );
    }
}

#[test]
fn ranges_bounds_and_multiplicity_per_docs46_5_4() {
    // Source: docs/46 §5.4 (max_value_len, ranges, Single / Multi), R46-7
    // (nTSecurityDescriptor capped at 65536), R46-8 (ou and description
    // single-valued; rangeLower 1 on sAMAccountName / UPN / SPN); docs/47
    // R47-13 (servicePrincipalName single-valued in phase 1).
    let p1 = p1();
    let r = |lower, upper| Some(ValueRange { lower, upper });
    let expect: [(&str, ValueSyntax, Multiplicity, usize, Option<ValueRange>); 17] = [
        (
            "nTSecurityDescriptor",
            ValueSyntax::SecurityDescriptor,
            Multiplicity::SingleValued,
            65536,
            None,
        ),
        (
            "cn",
            ValueSyntax::Utf8String,
            Multiplicity::SingleValued,
            192,
            r(1, 64),
        ),
        (
            "dc",
            ValueSyntax::Utf8String,
            Multiplicity::SingleValued,
            765,
            r(1, 255),
        ),
        (
            "ou",
            ValueSyntax::Utf8String,
            Multiplicity::SingleValued,
            192,
            r(1, 64),
        ),
        (
            "sAMAccountName",
            ValueSyntax::Utf8String,
            Multiplicity::SingleValued,
            768,
            r(1, 256),
        ),
        (
            "objectSid",
            ValueSyntax::Sid,
            Multiplicity::SingleValued,
            28,
            None,
        ),
        (
            "groupType",
            ValueSyntax::Integer32,
            Multiplicity::SingleValued,
            4,
            None,
        ),
        (
            "userPrincipalName",
            ValueSyntax::Utf8String,
            Multiplicity::SingleValued,
            3072,
            r(1, 1024),
        ),
        (
            "servicePrincipalName",
            ValueSyntax::Utf8String,
            Multiplicity::SingleValued,
            3072,
            r(1, 1024),
        ),
        (
            "dNSHostName",
            ValueSyntax::Utf8String,
            Multiplicity::SingleValued,
            6144,
            r(0, 2048),
        ),
        (
            "userAccountControl",
            ValueSyntax::Integer32,
            Multiplicity::SingleValued,
            4,
            None,
        ),
        (
            "accountExpires",
            ValueSyntax::Integer,
            Multiplicity::SingleValued,
            8,
            r(0, i64::MAX),
        ),
        (
            "pwdLastSet",
            ValueSyntax::Integer,
            Multiplicity::SingleValued,
            8,
            r(0, i64::MAX),
        ),
        (
            "member",
            ValueSyntax::ObjectRef,
            Multiplicity::MultiValued,
            16,
            None,
        ),
        (
            "whenCreated",
            ValueSyntax::DsTime,
            Multiplicity::SingleValued,
            8,
            None,
        ),
        (
            "whenChanged",
            ValueSyntax::DsTime,
            Multiplicity::SingleValued,
            8,
            None,
        ),
        (
            "description",
            ValueSyntax::Utf8String,
            Multiplicity::SingleValued,
            3072,
            r(0, 1024),
        ),
    ];
    for (name, syntax, multiplicity, max_value_len, range) in expect {
        let d = p1.schema().attribute(id(&p1, name)).unwrap();
        assert_eq!(d.storage, Storage::Stored, "{name}");
        assert_eq!(d.class, AttrClass::Normal, "{name}");
        assert_eq!(d.syntax, syntax, "{name}");
        assert_eq!(d.multiplicity, multiplicity, "{name}");
        assert_eq!(d.max_value_len, max_value_len, "{name}");
        assert_eq!(d.range, range, "{name}");
    }
    // The dirstore multiplicity differs from isSingleValued only for ou and
    // description (R46-8) and servicePrincipalName (R47-13).
    let mut deviations = Vec::new();
    for a in p1.attributes() {
        let d = p1.schema().attribute(a.id).unwrap();
        let single = d.multiplicity == Multiplicity::SingleValued;
        if single != a.entry.is_single_valued {
            deviations.push(a.entry.ldap_display_name);
        }
    }
    assert_eq!(
        sorted(deviations),
        vec!["description", "ou", "servicePrincipalName"]
    );
    // isSingleValued is kept as printed in [MS-ADA3] 2.253.
    let spn = p1
        .attribute(id(&p1, "servicePrincipalName"))
        .unwrap()
        .entry
        .is_single_valued;
    assert!(!spn);
    // Secret attributes: OctetString, Utf8String for initialAuth*
    // (docs/46 §5.4).
    for a in p1.attributes().filter(|a| a.entry.form == Form::Secret) {
        let d = p1.schema().attribute(a.id).unwrap();
        let expected = if a.entry.ldap_display_name.starts_with("initialAuth") {
            ValueSyntax::Utf8String
        } else {
            ValueSyntax::OctetString
        };
        assert_eq!(d.syntax, expected, "{}", a.entry.ldap_display_name);
    }
}

#[test]
fn class_definitions_per_docs46_4_4() {
    // Source: docs/46 §4.4 (must / may / poss_superiors / rdn_attr), §4.1
    // (instantiable: domainDNS as NC root, OU, container, user, computer,
    // group), §8.3 (superclass, nc_root); docs/47 R47-13
    // (servicePrincipalName in computer's may only).
    let p1 = p1();
    let class = |n: &str| p1.class_by_name(n).expect(n);
    let attrs = |names: &[&str]| -> Vec<AttrId> { names.iter().map(|n| id(&p1, n)).collect() };
    let classes =
        |names: &[&str]| -> Vec<dirstore::ClassId> { names.iter().map(|n| class(n)).collect() };
    type Row<'a> = (
        &'a str,
        Option<&'a str>,
        bool,
        &'a str,
        &'a [&'a str],
        &'a [&'a str],
        &'a [&'a str],
        bool,
    );
    let rows: [Row; 10] = [
        (
            "top",
            None,
            false,
            "cn",
            &["nTSecurityDescriptor"],
            &["description", "cn", "whenCreated", "whenChanged"],
            &[],
            false,
        ),
        ("domain", Some("top"), false, "dc", &["dc"], &[], &[], false),
        (
            "domainDNS",
            Some("domain"),
            true,
            "dc",
            &[],
            &["objectSid"],
            &[],
            true,
        ),
        (
            "organizationalUnit",
            Some("top"),
            true,
            "ou",
            &["ou"],
            &[],
            &["organizationalUnit", "domainDNS"],
            false,
        ),
        (
            "container",
            Some("top"),
            true,
            "cn",
            &["cn"],
            &[],
            &["domainDNS", "container", "organizationalUnit"],
            false,
        ),
        ("person", Some("top"), false, "cn", &["cn"], &[], &[], false),
        (
            "organizationalPerson",
            Some("person"),
            false,
            "cn",
            &[],
            &[],
            &[],
            false,
        ),
        (
            "user",
            Some("organizationalPerson"),
            true,
            "cn",
            &["cn", "sAMAccountName", "objectSid"],
            &[
                "userPrincipalName",
                "userAccountControl",
                "accountExpires",
                "pwdLastSet",
                "unicodePwd",
                "ntPwdHistory",
                "lmPwdHistory",
                "dBCSPwd",
                "supplementalCredentials",
            ],
            &["organizationalUnit", "domainDNS", "container"],
            false,
        ),
        (
            "computer",
            Some("user"),
            true,
            "cn",
            &[],
            &["dNSHostName", "servicePrincipalName"],
            &["container", "organizationalUnit", "domainDNS"],
            false,
        ),
        (
            "group",
            Some("top"),
            true,
            "cn",
            &["groupType", "cn", "sAMAccountName", "objectSid"],
            &["member", "supplementalCredentials"],
            &["container", "organizationalUnit", "domainDNS"],
            false,
        ),
    ];
    for (name, superclass, instantiable, rdn, must, may, poss, nc_root) in rows {
        let d = p1.schema().class(class(name)).unwrap();
        assert_eq!(d.superclass, superclass.map(class), "{name}");
        assert_eq!(d.instantiable, instantiable, "{name}");
        assert_eq!(d.rdn_attr, id(&p1, rdn), "{name}");
        assert_eq!(d.must, attrs(must), "{name}");
        assert_eq!(d.may, attrs(may), "{name}");
        assert_eq!(d.poss_superiors, classes(poss), "{name}");
        assert_eq!(d.nc_root, nc_root, "{name}");
    }
}

#[test]
fn dirstore_must_and_may_are_within_classatts() {
    // Source: docs/46 §4.4 — must / may = (own ∪ AUXCLASSES) ∩ stored
    // attributes (+ the allowed Secret ones), minus the one deliberate
    // omission (ou on organizationalPerson); so every dirstore must / may
    // attribute of a class is in its CLASSATTS ([MS-ADTS] 3.1.1.4.2).
    let p1 = p1();
    for c in p1.classes() {
        let d = p1.schema().class(c.id).unwrap();
        for a in d.must.iter().chain(&d.may) {
            assert!(
                c.class_attributes.contains(a),
                "{} allows {}",
                c.entry.ldap_display_name,
                p1.attribute(*a).unwrap().entry.ldap_display_name
            );
        }
    }
}
