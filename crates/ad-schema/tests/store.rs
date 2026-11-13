//! The phase-1 schema in a real (temporary) dirstore.
//!
//! Source: docs/46 §4.1 / §4.4 (instantiable classes, possible superiors,
//! domainDNS as NC root only), §2.3 (member / memberOf, referential
//! integrity on delete), §5.4, §6 (Secret: every write refused, D44), §8.2
//! (R46-6: userAccountControl bits, groupType values), §8.5 (unique, Q-080
//! case fold); Q-091 item 10 (dNSHostName printable ASCII); [MS-ADTS]
//! v20261026 2.2.12, 2.2.16, 3.1.1.1.4, 3.1.1.1.6, 3.1.1.5.2.2. Test data:
//! tests/common.

mod common;

use ad_schema::flags::user_account_control as uac;
use ad_schema::SECRET_ATTRIBUTES;
use common::*;
use dirstore::{AttributeChange, Error, NewObject, Violation};

#[test]
fn creates_the_phase1_tree() {
    // Source: docs/46 §4.4 — domainDNS (NC root) → organizationalUnit →
    // user, computer, group; a container under the root holding a user.
    let f = Fixture::new("tree");
    f.tree();
    f.create(f.user(
        10,
        guid(2),
        "alice",
        &[
            ("userPrincipalName", vec![b"alice@example.test".to_vec()]),
            ("userAccountControl", vec![bits(uac::ADS_UF_NORMAL_ACCOUNT)]),
            ("description", vec!["d\u{e9}veloppeuse".as_bytes().to_vec()]),
        ],
    ))
    .unwrap();
    f.create(f.computer(
        11,
        guid(2),
        "ws01",
        &[
            ("dNSHostName", vec![b"ws01.example.test".to_vec()]),
            (
                "servicePrincipalName",
                vec![b"HOST/ws01.example.test".to_vec()],
            ),
            (
                "userAccountControl",
                vec![bits(uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT)],
            ),
        ],
    ))
    .unwrap();
    f.create(f.group(
        12,
        guid(2),
        "staff",
        &[("member", vec![ref_to(10), ref_to(11)])],
    ))
    .unwrap();
    f.create(f.user(13, guid(3), "bob", &[])).unwrap();
    // A nested OU and a container in a container.
    f.create(f.object(
        14,
        Some(guid(2)),
        "organizationalUnit",
        &[("ou", vec![b"Sub".to_vec()])],
    ))
    .unwrap();
    f.create(f.object(
        15,
        Some(guid(3)),
        "container",
        &[("cn", vec![b"Inner".to_vec()])],
    ))
    .unwrap();
    let snap = f.store.snapshot().unwrap();
    for n in [1, 2, 3, 10, 11, 12, 13, 14, 15] {
        assert!(snap.get_object(guid(n)).unwrap().is_some(), "object {n}");
    }
    assert_eq!(
        snap.lookup_child(Some(guid(2)), b"ALICE").unwrap(),
        Some(guid(10))
    );
}

#[test]
fn non_instantiable_classes_cannot_be_created() {
    // Source: docs/46 §4.1 (top, domain abstract; person,
    // organizationalPerson 88 classes blocked in phase 1, D104); [MS-ADTS]
    // 3.1.1.2.4.8 (objectClassCategory).
    let f = Fixture::new("not-instantiable");
    f.tree();
    for (class, parent) in [
        ("top", Some(guid(2))),
        ("domain", None),
        ("person", Some(guid(2))),
        ("organizationalPerson", Some(guid(2))),
    ] {
        let obj = f.object(20, parent, class, &[("cn", vec![b"x".to_vec()])]);
        assert_eq!(
            f.refused(obj),
            Violation::ClassNotInstantiable(f.class(class)),
            "{class}"
        );
    }
}

#[test]
fn wrong_parent_class_is_refused() {
    // Source: docs/46 §4.4 (poss_superiors), §8.3 item 2 (NC root has no
    // parent; every other object has one); [MS-ADTS] 3.1.1.5.2.2.
    let f = Fixture::new("wrong-parent");
    f.tree();
    f.create(f.user(10, guid(2), "alice", &[])).unwrap();
    // A user under a user; an OU under a container; a group under a user.
    assert_eq!(
        f.refused(f.user(20, guid(10), "carol", &[])),
        Violation::ParentClassNotAllowed(f.class("user"))
    );
    assert_eq!(
        f.refused(f.object(
            21,
            Some(guid(3)),
            "organizationalUnit",
            &[("ou", vec![b"X".to_vec()])]
        )),
        Violation::ParentClassNotAllowed(f.class("container"))
    );
    assert_eq!(
        f.refused(f.group(22, guid(10), "g", &[])),
        Violation::ParentClassNotAllowed(f.class("user"))
    );
    // domainDNS only as the NC root (child domains are outside phase 1).
    assert_eq!(
        f.refused(f.object(
            23,
            Some(guid(1)),
            "domainDNS",
            &[("dc", vec![b"child".to_vec()])]
        )),
        Violation::NcRootHasParent
    );
    // Every other class needs a parent.
    assert_eq!(
        f.refused(f.user(24, guid(1), "dave", &[]).with_parent(None)),
        Violation::ParentRequired
    );
}

trait WithParent {
    fn with_parent(self, parent: Option<dtyp::Guid>) -> NewObject;
}

impl WithParent for NewObject {
    fn with_parent(mut self, parent: Option<dtyp::Guid>) -> NewObject {
        self.parent = parent;
        self
    }
}

#[test]
fn every_secret_attribute_write_is_refused() {
    // Source: [MS-ADTS] 3.1.1.1.4 (the secret set); docs/46 §6 (Secret:
    // every write refused, even where [MS-ADSC] allows the attribute); D44.
    let f = Fixture::new("secrets");
    f.tree();
    f.create(f.user(10, guid(2), "alice", &[])).unwrap();
    assert_eq!(SECRET_ATTRIBUTES.len(), 11);
    for (n, name) in (100u32..).zip(SECRET_ATTRIBUTES) {
        let a = f.attr(name);
        // On create.
        let obj = f.user(n, guid(2), &format!("u{n}"), &[(name, vec![b"x".to_vec()])]);
        assert_eq!(f.refused(obj), Violation::SecretAttribute(a), "{name}");
        // On modify, including a removal.
        for values in [vec![b"x".to_vec()], vec![]] {
            let mut txn = f.store.begin_write().unwrap();
            let result = txn.modify_object(
                guid(10),
                vec![AttributeChange::Replace { id: a, values }],
                &f.origin(),
            );
            assert!(
                matches!(result, Err(Error::Rejected(Violation::SecretAttribute(x))) if x == a),
                "{name}"
            );
        }
    }
}

#[test]
fn derived_attribute_write_is_refused() {
    // Source: docs/46 §5.4 / R46-4 (derived: never stored, writes refused);
    // [MS-ADTS] 3.1.1.1.6 (servers MUST reject writes to a back link).
    let f = Fixture::new("derived");
    f.tree();
    for (n, name) in (30u32..).zip([
        "objectClass",
        "objectCategory",
        "instanceType",
        "objectGUID",
        "name",
        "distinguishedName",
        "memberOf",
    ]) {
        let obj = f.user(n, guid(2), &format!("u{n}"), &[(name, vec![ref_to(1)])]);
        assert_eq!(
            f.refused(obj),
            Violation::DerivedAttribute(f.attr(name)),
            "{name}"
        );
    }
}

#[test]
fn user_account_control_bits() {
    // Source: docs/46 §8.2 (R46-6; A-29: ND allowed); [MS-ADTS] 2.2.16.
    let f = Fixture::new("uac");
    f.tree();
    let a = f.attr("userAccountControl");
    for (n, bit) in (40u32..).zip(uac::REFUSED) {
        let obj = f.user(
            n,
            guid(2),
            &format!("u{n}"),
            &[(
                "userAccountControl",
                vec![bits(uac::ADS_UF_NORMAL_ACCOUNT | bit)],
            )],
        );
        assert_eq!(f.refused(obj), Violation::DisallowedBits(a), "{bit:#x}");
    }
    // An unused ("X: Unused. Must be zero") bit is refused too.
    let obj = f.user(
        60,
        guid(2),
        "x1",
        &[("userAccountControl", vec![bits(0x0000_0001)])],
    );
    assert_eq!(f.refused(obj), Violation::DisallowedBits(a));
    // ND is accepted, and so is every allowed bit together.
    f.create(f.user(
        61,
        guid(2),
        "nd",
        &[(
            "userAccountControl",
            vec![bits(uac::ADS_UF_NORMAL_ACCOUNT | uac::ADS_UF_NOT_DELEGATED)],
        )],
    ))
    .unwrap();
    f.create(f.user(
        62,
        guid(2),
        "all",
        &[("userAccountControl", vec![bits(uac::ALLOWED)])],
    ))
    .unwrap();
}

#[test]
fn group_type_values() {
    // Source: docs/46 §8.2 (the six allowed values); [MS-ADTS] 2.2.12
    // (BUILTIN_LOCAL "cannot be set by clients"; APP_BASIC / APP_QUERY "not
    // used by Active Directory"; ACCOUNT / RESOURCE / UNIVERSAL mutually
    // exclusive, "only one value MUST be set").
    let f = Fixture::new("group-type");
    f.tree();
    let a = f.attr("groupType");
    let group = |n: u32, v: i32| f.principal_with_group_type(n, v);
    for (n, v) in (70u32..).zip([2, 4, 8, i32::MIN | 2, i32::MIN | 4, i32::MIN | 8]) {
        f.create(group(n, v)).unwrap();
    }
    for (n, v) in (80u32..).zip([
        0,
        1,
        6,
        0x10,
        0x20,
        i32::MIN,
        i32::MIN | 1,
        i32::MIN | 0x10,
        i32::MIN | 6,
        -1,
    ]) {
        assert_eq!(
            f.refused(group(n, v)),
            Violation::ValueNotAllowed(a),
            "{v:#x}"
        );
    }
}

trait GroupTypeFixture {
    fn principal_with_group_type(&self, id: u32, value: i32) -> NewObject;
}

impl GroupTypeFixture for Fixture {
    fn principal_with_group_type(&self, id: u32, value: i32) -> NewObject {
        let name = format!("g{id}");
        let mut obj = self.group(id, guid(2), &name, &[]);
        let gt = self.attr("groupType");
        for (attr, values) in &mut obj.attributes {
            if *attr == gt {
                *values = vec![int32(value)];
            }
        }
        obj
    }
}

#[test]
fn duplicates_are_refused_under_case_fold() {
    // Source: docs/46 §8.5 (unique sAMAccountName, userPrincipalName,
    // servicePrincipalName; comparison key per Q-080: ASCII, A–Z folded);
    // docs/47 R47-13 (servicePrincipalName single-valued, on computers).
    let f = Fixture::new("unique");
    f.tree();
    f.create(f.user(
        10,
        guid(2),
        "alice",
        &[("userPrincipalName", vec![b"alice@example.test".to_vec()])],
    ))
    .unwrap();
    f.create(f.computer(
        11,
        guid(2),
        "web0",
        &[(
            "servicePrincipalName",
            vec![b"HTTP/web.example.test".to_vec()],
        )],
    ))
    .unwrap();
    let sam = f.attr("sAMAccountName");
    let upn = f.attr("userPrincipalName");
    let spn = f.attr("servicePrincipalName");
    // sAMAccountName, also across classes (a group), under another parent.
    let mut obj = f.group(20, guid(3), "other", &[]);
    for (attr, values) in &mut obj.attributes {
        if *attr == sam {
            *values = vec![b"ALICE".to_vec()];
        }
    }
    assert!(matches!(f.create(obj), Err(Error::ValueNotUnique(a)) if a == sam));
    // userPrincipalName.
    let obj = f.user(
        21,
        guid(2),
        "carol",
        &[("userPrincipalName", vec![b"Alice@Example.TEST".to_vec()])],
    );
    assert!(matches!(f.create(obj), Err(Error::ValueNotUnique(a)) if a == upn));
    // servicePrincipalName, on a computer.
    let obj = f.computer(
        22,
        guid(2),
        "web",
        &[(
            "servicePrincipalName",
            vec![b"http/WEB.example.test".to_vec()],
        )],
    );
    assert!(matches!(f.create(obj), Err(Error::ValueNotUnique(a)) if a == spn));
    // Two values on one object: refused by the single-valued rule (R47-13)
    // before any comparison key is computed.
    let obj = f.computer(
        23,
        guid(2),
        "web2",
        &[(
            "servicePrincipalName",
            vec![b"HOST/web2".to_vec(), b"host/WEB2".to_vec()],
        )],
    );
    assert_eq!(f.refused(obj), Violation::MultipleValuesOnSingleValued(spn));
    // Distinct names are fine.
    f.create(f.user(
        24,
        guid(2),
        "dave",
        &[("userPrincipalName", vec![b"dave@example.test".to_vec()])],
    ))
    .unwrap();
}

#[test]
fn service_principal_name_only_on_computers_and_single_valued() {
    // Source: docs/47 R47-13 (A-38) — servicePrincipalName single-valued, and
    // allowed on computer only, in phase 1 (stricter than [MS-ADSC] 2.269 /
    // [MS-ADA3] 2.253; Q-112 / A-37).
    let f = Fixture::new("spn-computer-only");
    f.tree();
    let spn = f.attr("servicePrincipalName");
    // Refused on a user, on create and on modify.
    let obj = f.user(
        10,
        guid(2),
        "svc",
        &[(
            "servicePrincipalName",
            vec![b"http/svc.example.test".to_vec()],
        )],
    );
    assert_eq!(f.refused(obj), Violation::AttributeNotAllowed(spn));
    f.create(f.user(11, guid(2), "plain", &[])).unwrap();
    let mut txn = f.store.begin_write().unwrap();
    let result = txn.modify_object(
        guid(11),
        vec![AttributeChange::Replace {
            id: spn,
            values: vec![b"http/plain.example.test".to_vec()],
        }],
        &f.origin(),
    );
    assert!(matches!(
        result,
        Err(Error::Rejected(Violation::AttributeNotAllowed(a))) if a == spn
    ));
    drop(txn);
    // Accepted on a computer, one value.
    f.create(f.computer(
        12,
        guid(2),
        "ws12$",
        &[(
            "servicePrincipalName",
            vec![b"host/ws12.example.test".to_vec()],
        )],
    ))
    .unwrap();
    // A second distinct value is refused.
    let mut txn = f.store.begin_write().unwrap();
    let result = txn.modify_object(
        guid(12),
        vec![AttributeChange::Replace {
            id: spn,
            values: vec![
                b"host/ws12.example.test".to_vec(),
                b"cifs/ws12.example.test".to_vec(),
            ],
        }],
        &f.origin(),
    );
    assert!(matches!(
        result,
        Err(Error::Rejected(Violation::MultipleValuesOnSingleValued(a))) if a == spn
    ));
}

#[test]
fn member_of_through_back_links_and_delete() {
    // Source: docs/46 §2.3 items 3-4, §8.4 (memberOf answered from the
    // reverse-link index; deleting a member removes it from every group);
    // [MS-ADTS] 3.1.1.1.6 ("any forward link reference to o is removed").
    let f = Fixture::new("member-of");
    f.tree();
    f.create(f.user(10, guid(2), "alice", &[])).unwrap();
    f.create(f.user(11, guid(2), "bob", &[])).unwrap();
    f.create(f.group(
        20,
        guid(2),
        "staff",
        &[("member", vec![ref_to(10), ref_to(11)])],
    ))
    .unwrap();
    f.create(f.group(21, guid(2), "admins", &[("member", vec![ref_to(10)])]))
        .unwrap();
    let member = f.attr("member");
    let member_of = f.attr("memberOf");
    let snap = f.store.snapshot().unwrap();
    assert_eq!(
        snap.back_links(guid(10), member_of).unwrap(),
        vec![guid(20), guid(21)]
    );
    assert_eq!(
        snap.back_links(guid(11), member_of).unwrap(),
        vec![guid(20)]
    );
    drop(snap);
    // Delete alice: she leaves both groups in the same transaction.
    let mut txn = f.store.begin_write().unwrap();
    txn.delete_object(guid(10), &f.origin()).unwrap();
    txn.commit().unwrap();
    let snap = f.store.snapshot().unwrap();
    let staff = snap.get_object(guid(20)).unwrap().unwrap();
    let values: Vec<_> = staff
        .attribute(member)
        .unwrap()
        .values
        .iter()
        .map(|v| v.value.clone())
        .collect();
    assert_eq!(values, vec![ref_to(11)]);
    let admins = snap.get_object(guid(21)).unwrap().unwrap();
    assert!(admins.attribute(member).is_none());
    // A reference to a deleted object is refused.
    let obj = f.group(22, guid(2), "late", &[("member", vec![ref_to(10)])]);
    assert!(matches!(f.create(obj), Err(Error::NoSuchTarget(a)) if a == member));
}

#[test]
fn dns_host_name_must_be_printable_ascii() {
    // Source: Q-091 item 10 (A-30) + Q-080 item 1 — dNSHostName printable
    // ASCII (0x20..=0x7E); a non-ASCII or control byte is refused.
    let f = Fixture::new("dns-host-name");
    f.tree();
    let a = f.attr("dNSHostName");
    for (n, bad) in (30u32..).zip([
        "h\u{f6}st.example.test".as_bytes(),
        b"host\t.example.test",
        b"host\n.example.test",
        b"host\x7f.example.test",
        b"host\x00.example.test",
    ]) {
        let obj = f.computer(
            n,
            guid(2),
            &format!("c{n}"),
            &[("dNSHostName", vec![bad.to_vec()])],
        );
        assert_eq!(f.refused(obj), Violation::ValueNotAsciiPrintable(a));
    }
    f.create(f.computer(
        40,
        guid(2),
        "ok",
        &[("dNSHostName", vec![b"ok.example.test".to_vec()])],
    ))
    .unwrap();
}

#[test]
fn rdn_and_naming_rules_apply() {
    // Source: [MS-ADTS] 3.1.1.5.1.2 (RDN under 255 characters, counted as
    // "att=val", Q-090); docs/46 §5.4 (cn 1..64 characters); Q-080 item 1
    // (names printable ASCII). dc: "dc=" + 251 = 254 < 255.
    let f = Fixture::new("naming");
    let long_dc = vec![b'd'; 251];
    f.create(f.object(1, None, "domainDNS", &[("dc", vec![long_dc])]))
        .unwrap();
    let too_long = vec![b'd'; 252];
    assert_eq!(
        f.refused(f.object(9, None, "domainDNS", &[("dc", vec![too_long])])),
        Violation::RdnTooLong
    );
    let cn = f.attr("cn");
    assert_eq!(
        f.refused(f.object(
            2,
            Some(guid(1)),
            "container",
            &[("cn", vec![vec![b'c'; 65]])]
        )),
        Violation::ValueOutOfRange(cn)
    );
    assert_eq!(
        f.refused(f.object(
            3,
            Some(guid(1)),
            "container",
            &[("cn", vec!["\u{e9}".as_bytes().to_vec()])]
        )),
        Violation::ValueNotAsciiPrintable(cn)
    );
}
