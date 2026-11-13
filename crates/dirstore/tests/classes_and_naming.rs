//! Object validation against class chains, the tree shape and the RDN rules.
//!
//! Source: docs/46 §8.3 items 1-3 (full chain of one instantiable class;
//! parent's most specific class in poss_superiors; NC root has no parent; RDN
//! attribute with exactly one value, no 0x00 / 0x0A, under the size limit,
//! key computed by dirstore with the Q-080 interim rule), §8.6 (AttrId(0) is
//! a valid id); [MS-ADTS] v20261026 §3.1.1.5.2.2 (single most specific
//! structural class; possSuperiors), §3.1.1.1.4 / §3.1.1.3.1.2.1 (exactly one
//! RDN value; RDN values unique among siblings), §3.1.1.5.1.2 (0x00 / 0x0A;
//! "The RDN size MUST be less than 255 characters" — strict reading, Q-090),
//! §3.1.1.5.3.2 (the naming attribute cannot be modified); Q-080. Test data
//! is hand-made (tests/common).

mod common;

use common::*;
use dirstore::{
    AttrClass, AttrId, AttributeChange, ClassDefinition, Error, NewObject, Schema, Store, Violation,
};

/// Create `obj` in a store holding root(1) and container(2) under it; return
/// the error and check that nothing was written for it.
fn create_error(test: &str, obj: NewObject) -> Error {
    let dir = TempDir::new(test);
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root"), container(2, guid(1), "box")]);
    let guid = obj.guid;
    let mut txn = store.begin_write().unwrap();
    let err = txn
        .create_object(obj, &origin(NODE_1, 1, 1))
        .expect_err("must be rejected");
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.get_object(guid).unwrap(), None);
    assert_eq!(snap.get_tombstone(guid).unwrap(), None);
    err
}

fn rejected(err: Error) -> Violation {
    match err {
        Error::Rejected(v) => v,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

// ------------------------------------------------------------- class chain --

#[test]
fn classes_must_be_the_full_chain_of_one_class() {
    // Source: docs/46 §8.3 item 1; [MS-ADTS] 3.1.1.5.2.2 ("a single, most
    // specific structural objectClass"), 3.1.1.2.4.3 (the stored value is the
    // whole superclass chain).
    let with_classes = |classes| NewObject {
        classes,
        ..principal(9, guid(1), "p")
    };
    // A gap in the chain (PERSON missing).
    assert_eq!(
        rejected(create_error(
            "chain-gap",
            with_classes(vec![CLASS_TOP, CLASS_PRINCIPAL])
        )),
        Violation::InvalidClassChain
    );
    // Only the most specific class.
    assert_eq!(
        rejected(create_error(
            "chain-only-leaf",
            with_classes(vec![CLASS_PRINCIPAL])
        )),
        Violation::InvalidClassChain
    );
    // Two structural classes.
    assert_eq!(
        rejected(create_error(
            "chain-two-structural",
            with_classes(vec![
                CLASS_TOP,
                CLASS_PERSON,
                CLASS_PRINCIPAL,
                CLASS_CONTAINER
            ])
        )),
        Violation::InvalidClassChain
    );
    assert_eq!(
        rejected(create_error(
            "chain-two-siblings",
            NewObject {
                classes: vec![CLASS_TOP, CLASS_CONTAINER, CLASS_LOOSE],
                ..container(9, guid(1), "c")
            }
        )),
        Violation::InvalidClassChain
    );
    // A chain whose most specific class is not instantiable.
    assert_eq!(
        rejected(create_error(
            "chain-abstract",
            with_classes(vec![CLASS_TOP, CLASS_PERSON])
        )),
        Violation::ClassNotInstantiable(CLASS_PERSON)
    );
    // Class order in the request does not matter; the stored order is the
    // canonical ascending one.
    let dir = TempDir::new("chain-order");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            root(1, "root"),
            with_classes(vec![CLASS_PRINCIPAL, CLASS_TOP, CLASS_PERSON]),
        ],
    );
    let obj = store
        .snapshot()
        .unwrap()
        .get_object(guid(9))
        .unwrap()
        .unwrap();
    assert_eq!(obj.classes, PRINCIPAL_CHAIN.to_vec());
    assert_eq!(
        store.schema().most_specific_class(&obj.classes),
        Some(CLASS_PRINCIPAL)
    );
}

// --------------------------------------------------------------- tree shape --

#[test]
fn parent_class_must_be_a_possible_superior() {
    // Source: docs/46 §8.3 item 2; [MS-ADTS] 3.1.1.5.2.2 ("The objectClass
    // being created satisfies the possSuperiors schema constraint ... for the
    // objectClass of the parent object").
    let dir = TempDir::new("poss-superiors");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            root(1, "root"),
            container(2, guid(1), "box"),
            principal(3, guid(1), "alice"),
            ou(4, guid(1), "unit"),
        ],
    );
    let mut txn = store.begin_write().unwrap();
    // A principal is not a possible superior of anything.
    assert!(matches!(
        txn.create_object(principal(5, guid(3), "bob"), &origin(NODE_1, 1, 1)),
        Err(Error::Rejected(Violation::ParentClassNotAllowed(
            CLASS_PRINCIPAL
        )))
    ));
    // An OU may live under the domain or an OU, not under a container.
    assert!(matches!(
        txn.create_object(ou(6, guid(2), "sub"), &origin(NODE_1, 1, 2)),
        Err(Error::Rejected(Violation::ParentClassNotAllowed(
            CLASS_CONTAINER
        )))
    ));
    // Allowed placements succeed in the same transaction.
    txn.create_object(ou(7, guid(4), "sub"), &origin(NODE_1, 1, 3))
        .unwrap();
    txn.create_object(principal(8, guid(7), "carol"), &origin(NODE_1, 1, 4))
        .unwrap();
    txn.create_object(principal(9, guid(2), "dave"), &origin(NODE_1, 1, 5))
        .unwrap();
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.get_object(guid(5)).unwrap(), None);
    assert_eq!(snap.get_object(guid(6)).unwrap(), None);
    assert!(snap.get_object(guid(8)).unwrap().is_some());
}

#[test]
fn nc_root_has_no_parent_and_others_need_one() {
    // Source: docs/46 §8.3 item 2 ("if nc_root — parent must be None;
    // otherwise parent must exist").
    assert_eq!(
        rejected(create_error(
            "ncroot-with-parent",
            NewObject {
                parent: Some(guid(1)),
                ..root(9, "inner")
            }
        )),
        Violation::NcRootHasParent
    );
    assert_eq!(
        rejected(create_error(
            "parent-required",
            NewObject {
                parent: None,
                ..container(9, guid(1), "loose")
            }
        )),
        Violation::ParentRequired
    );
}

// --------------------------------------------------------------------- RDN --

#[test]
fn rdn_attribute_needs_exactly_one_value() {
    // Source: docs/46 §8.3 item 3; [MS-ADTS] 3.1.1.1.4 ("the RDN attribute of
    // an object always has exactly one value"), 3.1.1.3.1.2.1 (no
    // multivalued RDNs). CLASS_LOOSE allows its RDN attribute only as "may";
    // CLASS_OU's RDN attribute is multi-valued in the schema.
    assert_eq!(
        rejected(create_error(
            "rdn-missing",
            NewObject {
                guid: guid(9),
                parent: Some(guid(1)),
                classes: vec![CLASS_TOP, CLASS_LOOSE],
                attributes: vec![(ATTR_NOTE, vec![b"no name".to_vec()])],
            }
        )),
        Violation::RdnAttributeMissing(ATTR_NAME)
    );
    assert_eq!(
        rejected(create_error(
            "rdn-multi",
            NewObject {
                attributes: vec![(ATTR_OU, vec![b"one".to_vec(), b"two".to_vec()])],
                ..ou(9, guid(1), "x")
            }
        )),
        Violation::RdnAttributeMultiValued(ATTR_OU)
    );
}

#[test]
fn rdn_value_character_rules() {
    // Source: [MS-ADTS] 3.1.1.5.1.2 ("The RDN MUST not contain a character
    // with value 0xA" / "… 0x0"); Q-080 item 1 (phase 1: printable ASCII only
    // in every RDN value; non-ASCII refused, never folded by a guessed rule).
    for (i, name) in ["a\nb", "a\0b", "\n"].iter().enumerate() {
        assert_eq!(
            rejected(create_error(
                &format!("rdn-forbidden-{i}"),
                principal(9, guid(1), name)
            )),
            Violation::RdnForbiddenCharacter
        );
    }
    for (i, name) in [
        "caf\u{e9}",
        "\u{5e9}\u{5dc}\u{5d5}\u{5dd}",
        "a\tb",
        "a\x7Fb",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            rejected(create_error(
                &format!("rdn-non-ascii-{i}"),
                principal(9, guid(1), name)
            )),
            Violation::RdnNotAscii
        );
    }
    // Lookup applies the same rule.
    let dir = TempDir::new("rdn-lookup-ascii");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root")]);
    assert!(matches!(
        store
            .snapshot()
            .unwrap()
            .lookup_child(Some(guid(1)), "caf\u{e9}".as_bytes()),
        Err(Error::Rejected(Violation::RdnNotAscii))
    ));
}

#[test]
fn rdn_size_limit_strict_reading() {
    // Source: [MS-ADTS] 3.1.1.5.1.2 ("The RDN size MUST be less than 255
    // characters"), read strictly as the whole `att=val` (docs/46 §8.3 item
    // 3; Q-090). ATTR_DC has an RDN label of 2 characters and a range of
    // 1..=255, so "xx=" + 251 = 254 is the longest accepted value: the size
    // rule is stricter than the attribute's range (docs/46 §8.3: "this changes
    // only dc").
    let dc_root = |len: usize| NewObject {
        guid: guid(9),
        parent: None,
        classes: vec![CLASS_TOP, CLASS_DC_ROOT],
        attributes: vec![(ATTR_DC, vec![vec![b'd'; len]])],
    };
    assert_eq!(
        rejected(create_error("rdn-size-252", dc_root(252))),
        Violation::RdnTooLong
    );
    assert_eq!(
        rejected(create_error("rdn-size-255", dc_root(255))),
        Violation::RdnTooLong
    );
    let dir = TempDir::new("rdn-size-251");
    let store = open_store(&dir);
    create_all(&store, vec![dc_root(251)]);
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .lookup_child(None, &[b'D'; 251])
            .unwrap(),
        Some(guid(9))
    );
}

#[test]
fn rdn_attribute_cannot_be_modified() {
    // Source: [MS-ADTS] 3.1.1.5.3.2 ("Updates to the name attribute, as well
    // as updates to the object's naming attribute ... are disallowed"); docs/46
    // §8.3 item 3 (the RDN key follows the RDN value, so it may not drift).
    let dir = TempDir::new("rdn-modify");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            root(1, "root"),
            principal(2, guid(1), "alice"),
            ou(3, guid(1), "unit"),
        ],
    );
    let before = store.snapshot().unwrap().get_object(guid(2)).unwrap();
    let mut txn = store.begin_write().unwrap();
    for (target, id, value) in [
        (2, ATTR_NAME, b"bob".to_vec()),
        (2, ATTR_NAME, b"alice".to_vec()),
        (3, ATTR_OU, b"other".to_vec()),
    ] {
        assert!(matches!(
            txn.modify_object(
                guid(target),
                vec![AttributeChange::Replace {
                    id,
                    values: vec![value]
                }],
                &origin(NODE_1, 2, 2)
            ),
            Err(Error::Rejected(Violation::RdnAttributeNotModifiable(x))) if x == id
        ));
    }
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.get_object(guid(2)).unwrap(), before);
    assert_eq!(
        snap.lookup_child(Some(guid(1)), b"alice").unwrap(),
        Some(guid(2))
    );
}

#[test]
fn stored_rdn_key_is_rechecked_on_read() {
    // Source: docs/14 D60 (re-validate before use) with docs/46 §8.3 item 3:
    // the stored RDN key must equal the key computed from the RDN value under
    // the schema given at open. Here the reopening schema names principals by
    // ATTR_TEXT instead of ATTR_NAME, so the stored key no longer matches.
    let dir = TempDir::new("rdn-recheck");
    {
        let store = open_store(&dir);
        create_all(
            &store,
            vec![
                root(1, "root"),
                principal_with(
                    2,
                    guid(1),
                    "alice",
                    vec![(ATTR_TEXT, vec![b"bob".to_vec()])],
                ),
            ],
        );
    }
    let attrs = attribute_definitions(AttrClass::Secret)
        .into_iter()
        .map(|mut d| {
            if d.id == ATTR_TEXT {
                d.rdn_att_len = Some(RDN_LABEL);
            }
            d
        })
        .collect();
    let classes = class_definitions()
        .into_iter()
        .map(|c| {
            if c.id == CLASS_PRINCIPAL {
                ClassDefinition {
                    rdn_attr: ATTR_TEXT,
                    ..c
                }
            } else {
                c
            }
        })
        .collect();
    let store = Store::open(dir.db_path(), key_a(), Schema::new(attrs, classes).unwrap()).unwrap();
    let snap = store.snapshot().unwrap();
    assert!(matches!(
        snap.get_object(guid(2)),
        Err(Error::StoredObjectRejected(Violation::RdnKeyMismatch))
    ));
    assert!(snap.get_object(guid(1)).unwrap().is_some());
}

// -------------------------------------------------------------------- ids --

#[test]
fn attr_id_zero_is_an_ordinary_id() {
    // Source: docs/46 §8.6 — AttrId(0) is objectClass in the AD content
    // (ATTRTYP 0, docs/46 §3.3), so 0 is a valid id and never a sentinel. In
    // the test schema ATTR_NAME is AttrId(0) and CLASS_TOP is ClassId(0).
    assert_eq!(ATTR_NAME, AttrId(0));
    let dir = TempDir::new("attr-zero");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root"), principal(2, guid(1), "zero")]);
    let obj = store
        .snapshot()
        .unwrap()
        .get_object(guid(2))
        .unwrap()
        .unwrap();
    assert_eq!(obj.attributes[0].id, AttrId(0));
    assert_eq!(obj.attribute(AttrId(0)).unwrap().values[0].value, b"zero");
    assert_eq!(obj.classes[0], CLASS_TOP);
    assert!(store.schema().attribute(AttrId(0)).is_some());
    assert!(store.schema().class(CLASS_TOP).is_some());
}
