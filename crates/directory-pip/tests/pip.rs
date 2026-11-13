//! The directory-object methods of the PIP (docs/47 §8.2).
//!
//! Sources (named per test): docs/47 §8.2 (the data source of every
//! method; DN resolution); A-28 (object classes, property sets); docs/46
//! §6, §7; [MS-ADTS] 3.1.1.2.3.3, 3.1.1.2.4.3, 5.1.3.1; D40 (any PIP failure
//! ⇒ Deny); Q-170 item 7 (A-51: the nTSecurityDescriptor GUID cross-check).
//! Test data: tests/common.

mod common;

use common::*;
use directory_pip::{DirectoryContext, ViewError};
use dirstore::{IntegrityKey, Store};
use pdp::{AttrClass, AttrId, Dn, ObjClass, Pip, PipError};

fn class_guid(d: &Dir, name: &str) -> ObjClass {
    ObjClass(d.p1.class_schema_id_guid(d.class(name)).unwrap())
}

fn attr_guid(d: &Dir, name: &str) -> AttrId {
    AttrId(d.p1.attribute_schema_id_guid(d.attr(name)).unwrap())
}

/// docs/47 §8.2 (DN resolution): the directory's own DN form — leaf first,
/// `<RDN attribute>=<stored value>` — resolves back to the object; any
/// other spelling (case, attribute label, missing component) is NotFound.
#[test]
fn dn_round_trip_and_strict_resolution() {
    let d = Dir::standard("dn");
    let view = d.view();
    let alice = view.dn_of(guid(ALICE)).unwrap().unwrap();
    assert_eq!(
        alice.rdns(),
        &[
            "cn=alice".to_string(),
            "ou=Staff".into(),
            "dc=example".into()
        ]
    );
    assert_eq!(view.object_sid(&alice), Ok(Some(sid_of(ALICE))));
    assert_eq!(view.dn_of(guid(9999)), Ok(None));
    for bad in [
        vec!["cn=Alice", "ou=Staff", "dc=example"],
        vec!["CN=alice", "ou=Staff", "dc=example"],
        vec!["cn=alice", "ou=staff", "dc=example"],
        vec!["ou=alice", "ou=Staff", "dc=example"],
        vec!["cn=alice", "dc=example"],
        vec!["cn=alice", "ou=Staff"],
        vec!["alice", "ou=Staff", "dc=example"],
        vec!["cn=", "ou=Staff", "dc=example"],
        vec![],
    ] {
        let dn = Dn::new(bad.iter().map(|s| s.to_string()).collect());
        assert_eq!(view.object_sid(&dn), Err(PipError::NotFound), "{bad:?}");
    }
}

/// docs/47 §8.2: `security_descriptor` = the stored nTSecurityDescriptor
/// ([MS-ADTS] 5.1.3.1: "Every object in Active Directory has an
/// nTSecurityDescriptor attribute").
#[test]
fn security_descriptor() {
    let d = Dir::standard("sd");
    let view = d.view();
    let ou = view.dn_of(guid(STAFF_OU)).unwrap().unwrap();
    assert_eq!(view.security_descriptor(&ou), Ok(sd()));
    let ghost = Dn::new(vec!["ou=Ghost".into(), "dc=example".into()]);
    assert_eq!(view.security_descriptor(&ghost), Err(PipError::NotFound));
}

/// docs/47 §8.2; A-28; [MS-ADTS] 3.1.1.2.4.3: `object_classes` = the most
/// specific class and the rest of its superclass chain, as schemaIDGUIDs.
#[test]
fn object_classes() {
    let d = Dir::standard("classes");
    let view = d.view();
    let ws01 = view.dn_of(guid(WS01)).unwrap().unwrap();
    let chain = view.object_classes(&ws01).unwrap();
    assert_eq!(chain.most_specific, class_guid(&d, "computer"));
    let mut supers = chain.superclasses.clone();
    supers.sort();
    let mut expected: Vec<ObjClass> = ["top", "person", "organizationalPerson", "user"]
        .iter()
        .map(|n| class_guid(&d, n))
        .collect();
    expected.sort();
    assert_eq!(supers, expected);
    let ou = view.dn_of(guid(STAFF_OU)).unwrap().unwrap();
    let chain = view.object_classes(&ou).unwrap();
    assert_eq!(chain.most_specific, class_guid(&d, "organizationalUnit"));
    assert_eq!(chain.superclasses, vec![class_guid(&d, "top")]);
}

/// docs/47 §8.2: `object_sid` — the objectSid, or None (an OU has none).
#[test]
fn object_sid() {
    let d = Dir::standard("object-sid");
    let view = d.view();
    let staff = view.dn_of(guid(STAFF)).unwrap().unwrap();
    assert_eq!(view.object_sid(&staff), Ok(Some(sid_of(STAFF))));
    let ou = view.dn_of(guid(STAFF_OU)).unwrap().unwrap();
    assert_eq!(view.object_sid(&ou), Ok(None));
    let root = view.dn_of(guid(ROOT)).unwrap().unwrap();
    assert_eq!(view.object_sid(&root), Ok(Some(domain_sid())));
}

/// docs/47 §8.2; docs/46 §6: `attr_class` by schemaIDGUID — the eleven
/// secret attributes are Secret, the rest Normal (no phase-1 attribute is
/// fCONFIDENTIAL); an unknown GUID is NotFound.
#[test]
fn attr_class() {
    let d = Dir::standard("attr-class");
    let view = d.view();
    assert_eq!(
        view.attr_class(&attr_guid(&d, "sAMAccountName")),
        Ok(AttrClass::Normal)
    );
    for secret in ad_schema::SECRET_ATTRIBUTES {
        assert_eq!(
            view.attr_class(&attr_guid(&d, secret)),
            Ok(AttrClass::Secret),
            "{secret}"
        );
    }
    assert_eq!(
        view.attr_class(&AttrId(guid(9999))),
        Err(PipError::NotFound)
    );
}

/// docs/47 §8.2; A-28 item 2; [MS-ADTS] 3.1.1.2.3.3: `property_set` —
/// sAMAccountName is in General Information; dNSHostName's set GUID is its
/// own schemaIDGUID (`is_attribute_guid`); nTSecurityDescriptor has none.
#[test]
fn property_set() {
    let d = Dir::standard("property-set");
    let view = d.view();
    let sam = view
        .property_set(&attr_guid(&d, "sAMAccountName"))
        .unwrap()
        .unwrap();
    assert_eq!(
        Some(sam.guid),
        d.p1.property_set(d.attr("sAMAccountName"))
            .unwrap()
            .map(|p| p.guid)
    );
    assert!(!sam.is_attribute_guid);
    let dns = view
        .property_set(&attr_guid(&d, "dNSHostName"))
        .unwrap()
        .unwrap();
    assert_eq!(AttrId(dns.guid), attr_guid(&d, "dNSHostName"));
    assert!(dns.is_attribute_guid);
    assert_eq!(
        view.property_set(&attr_guid(&d, "nTSecurityDescriptor")),
        Ok(None)
    );
    assert_eq!(
        view.property_set(&AttrId(guid(9999))),
        Err(PipError::NotFound)
    );
}

/// Q-170 item 7 (A-51); docs/46 §7 (`pdp::AttrId` is the schemaIDGUID; the
/// schema-table bridge is one-to-one, both identifiers "Unique" per
/// [MS-ADTS] 3.1.1.2.3). pdp recognises nTSecurityDescriptor by its own
/// constant `AttrId::NT_SECURITY_DESCRIPTOR` ([MS-ADA3] 2.37, A-31), not
/// through the PIP, and pdp does not depend on ad-schema — nothing else
/// ties the two together. The constant equals the schemaIDGUID that
/// `ad_schema::phase1()` reports for nTSecurityDescriptor, and no other
/// phase-1 attribute carries that GUID, so the PDP's stricter rule cannot
/// drift onto another attribute, or off this one, without this test failing.
#[test]
fn nt_security_descriptor_guid_matches_the_schema() {
    let p1 = ad_schema::phase1().unwrap();
    let id = p1.attribute_by_name("nTSecurityDescriptor").unwrap();
    assert_eq!(
        p1.attribute_schema_id_guid(id),
        Ok(AttrId::NT_SECURITY_DESCRIPTOR.0)
    );
    let carriers: Vec<&str> = p1
        .attributes()
        .filter(|a| a.schema_id_guid == AttrId::NT_SECURITY_DESCRIPTOR.0)
        .map(|a| a.entry.ldap_display_name)
        .collect();
    assert_eq!(carriers, ["nTSecurityDescriptor"]);
}

/// docs/47 §8.1: a view is taken only over a store opened with the
/// context's schema (fail closed).
#[test]
fn view_refuses_a_store_with_another_schema() {
    let d = Dir::new("schema-mismatch");
    // A store opened with a different (empty) schema.
    let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "directory-pip-mismatch-{}.redb",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let store = Store::open(
        &path,
        IntegrityKey::from_bytes(&[1; 32]),
        dirstore::Schema::new(Vec::new(), Vec::new()).unwrap(),
    )
    .unwrap();
    let tiers = directory_pip::TierMap::empty();
    assert!(matches!(
        d.ctx.view(&store, &tiers),
        Err(ViewError::SchemaMismatch)
    ));
    drop(store);
    let _ = std::fs::remove_file(&path);
    // And keyd's configuration must be valid.
    let mut bad = keyd_config();
    bad.enctypes.clear();
    assert!(matches!(
        DirectoryContext::new(d.p1.clone(), &bad),
        Err(ViewError::KeydConfig)
    ));
}
