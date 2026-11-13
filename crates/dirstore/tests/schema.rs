//! Schema as data: write validation, Secret attributes, schema defects.
//!
//! Source: docs/32 §4 (schema is data; every write validated: type, must,
//! singularity); docs/12 D44 and docs/32 §1 (no secret material in the
//! readable store); docs/11 §6 (AttrClass Normal | Sensitive | Secret);
//! docs/14 D60 (strict validation; re-validate before use). The schema is the
//! hand-made TEST schema of tests/common, not AD content.

mod common;

use common::*;
use dirstore::{
    AttrClass, AttrId, AttributeChange, AttributeDefinition, ClassDefinition, ClassId, Error,
    Multiplicity, NewObject, Schema, SchemaDefect, Store, ValueSyntax, Violation, MAX_VALUE_LEN,
};

/// Try to create `obj` under a fresh root; return the error, and check that
/// nothing at all was written for it.
fn create_error(test: &str, obj: NewObject) -> Error {
    let dir = TempDir::new(test);
    let store = open_store(&dir);
    create_all(&store, vec![container(1, None, "root")]);
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

fn with_attrs(attrs: Vec<(AttrId, Vec<Vec<u8>>)>) -> NewObject {
    NewObject {
        attributes: attrs,
        ..principal(2, guid(1), "p")
    }
}

fn base_attrs() -> Vec<(AttrId, Vec<Vec<u8>>)> {
    vec![
        (ATTR_NAME, vec![b"p".to_vec()]),
        (ATTR_SID, vec![sid_value(7)]),
    ]
}

#[test]
fn missing_must_attribute() {
    // Source: docs/32 §4 ("must").
    let err = create_error(
        "missing-must",
        with_attrs(vec![(ATTR_NAME, vec![b"p".to_vec()])]),
    );
    assert!(matches!(
        err,
        Error::Rejected(Violation::MissingMustAttribute(ATTR_SID))
    ));
}

#[test]
fn must_attribute_of_every_class_is_required() {
    // Source: docs/32 §4 — classes are additive; CLASS_FLAGGED adds a must.
    let obj = NewObject {
        classes: vec![CLASS_PRINCIPAL, CLASS_FLAGGED],
        ..with_attrs(base_attrs())
    };
    let err = create_error("must-every-class", obj);
    assert!(matches!(
        err,
        Error::Rejected(Violation::MissingMustAttribute(ATTR_FLAG))
    ));
}

#[test]
fn unknown_attribute() {
    // Source: docs/32 §4.
    let mut attrs = base_attrs();
    attrs.push((AttrId(999), vec![b"x".to_vec()]));
    let err = create_error("unknown-attr", with_attrs(attrs));
    assert!(matches!(
        err,
        Error::Rejected(Violation::UnknownAttribute(AttrId(999)))
    ));
}

#[test]
fn attribute_not_allowed_by_class() {
    // Source: docs/32 §4 (must / may).
    let mut attrs = base_attrs();
    attrs.push((ATTR_ORPHAN, vec![b"x".to_vec()]));
    let err = create_error("not-allowed", with_attrs(attrs));
    assert!(matches!(
        err,
        Error::Rejected(Violation::AttributeNotAllowed(ATTR_ORPHAN))
    ));
}

#[test]
fn unknown_and_duplicate_and_missing_classes() {
    // Source: docs/32 §4.
    let err = create_error(
        "unknown-class",
        NewObject {
            classes: vec![CLASS_PRINCIPAL, ClassId(77)],
            ..with_attrs(base_attrs())
        },
    );
    assert!(matches!(
        err,
        Error::Rejected(Violation::UnknownClass(ClassId(77)))
    ));
    let err = create_error(
        "dup-class",
        NewObject {
            classes: vec![CLASS_PRINCIPAL, CLASS_PRINCIPAL],
            ..with_attrs(base_attrs())
        },
    );
    assert!(matches!(
        err,
        Error::Rejected(Violation::DuplicateClass(CLASS_PRINCIPAL))
    ));
    let err = create_error(
        "no-class",
        NewObject {
            classes: vec![],
            ..with_attrs(base_attrs())
        },
    );
    assert!(matches!(err, Error::Rejected(Violation::NoObjectClass)));
}

#[test]
fn multiple_values_on_single_valued() {
    // Source: docs/32 §4 ("singularity").
    let mut attrs = base_attrs();
    attrs[0] = (ATTR_NAME, vec![b"p".to_vec(), b"q".to_vec()]);
    let err = create_error("multi-on-single", with_attrs(attrs));
    assert!(matches!(
        err,
        Error::Rejected(Violation::MultipleValuesOnSingleValued(ATTR_NAME))
    ));
}

#[test]
fn oversize_value() {
    // Source: docs/32 §4, §8 — ATTR_NAME's schema bound is NAME_MAX bytes.
    let mut attrs = base_attrs();
    attrs[0] = (ATTR_NAME, vec![vec![b'n'; NAME_MAX + 1]]);
    let err = create_error("oversize", with_attrs(attrs));
    assert!(matches!(
        err,
        Error::Rejected(Violation::ValueTooLarge(ATTR_NAME))
    ));
    // Exactly at the bound is fine.
    let dir = TempDir::new("oversize-ok");
    let store = open_store(&dir);
    create_all(&store, vec![container(1, None, "root")]);
    let mut attrs = base_attrs();
    attrs[0] = (ATTR_NAME, vec![vec![b'n'; NAME_MAX]]);
    let mut txn = store.begin_write().unwrap();
    txn.create_object(with_attrs(attrs), &origin(NODE_1, 1, 1))
        .unwrap();
    txn.commit().unwrap();
}

#[test]
fn duplicate_value_and_attribute_and_empty_attribute() {
    // Source: docs/29 §4 (values form a set); docs/32 §4.
    let mut attrs = base_attrs();
    attrs.push((ATTR_NOTE, vec![b"a".to_vec(), b"a".to_vec()]));
    assert!(matches!(
        create_error("dup-value", with_attrs(attrs)),
        Error::Rejected(Violation::DuplicateValue(ATTR_NOTE))
    ));
    let mut attrs = base_attrs();
    attrs.push((ATTR_NOTE, vec![b"a".to_vec()]));
    attrs.push((ATTR_NOTE, vec![b"b".to_vec()]));
    assert!(matches!(
        create_error("dup-attr", with_attrs(attrs)),
        Error::Rejected(Violation::DuplicateAttribute(ATTR_NOTE))
    ));
    let mut attrs = base_attrs();
    attrs.push((ATTR_NOTE, vec![]));
    assert!(matches!(
        create_error("empty-attr", with_attrs(attrs)),
        Error::Rejected(Violation::EmptyAttribute(ATTR_NOTE))
    ));
}

#[test]
fn value_syntax_is_enforced() {
    // Source: docs/32 §4 ("type"); docs/14 D60. SID / SD validity is decided
    // by our `dtyp` crate's decoders (dirstore adds only "canonical form").
    let cases: Vec<(&str, AttrId, Vec<u8>)> = vec![
        ("syn-utf8", ATTR_NOTE, vec![0xFF, 0xFE]),
        ("syn-bool", ATTR_FLAG, vec![0x02]),
        ("syn-bool-len", ATTR_FLAG, vec![]),
        ("syn-int", ATTR_COUNTER, vec![0; 7]),
        ("syn-guid", ATTR_MEMBER, vec![0; 15]),
        ("syn-sd", ATTR_SD, vec![1, 0, 0, 0]),
    ];
    for (test, id, value) in cases {
        let mut attrs = base_attrs();
        attrs.push((id, vec![value]));
        assert!(
            matches!(
                create_error(test, with_attrs(attrs)),
                Error::Rejected(Violation::InvalidValueSyntax(x)) if x == id
            ),
            "{test}"
        );
    }
    // SID whose first (revision) byte is 2: `dtyp::Sid::decode` refuses it
    // (dtyp::Error::SidRevision), so the value is not a valid SID.
    let mut bad_sid = sid_value(7);
    bad_sid[0] = 2;
    let mut attrs = base_attrs();
    attrs[1] = (ATTR_SID, vec![bad_sid]);
    assert!(matches!(
        create_error("syn-sid", with_attrs(attrs)),
        Error::Rejected(Violation::InvalidValueSyntax(ATTR_SID))
    ));
}

#[test]
fn modify_is_validated_as_a_whole() {
    // Source: docs/32 §4 — the object after the change must satisfy the schema.
    let dir = TempDir::new("modify-validate");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![container(1, None, "root"), principal(2, guid(1), "p")],
    );
    let before = store.snapshot().unwrap().get_object(guid(2)).unwrap();
    let mut txn = store.begin_write().unwrap();
    let cases = vec![
        (
            AttributeChange::Replace {
                id: ATTR_SID,
                values: vec![],
            },
            Violation::MissingMustAttribute(ATTR_SID),
        ),
        (
            AttributeChange::Replace {
                id: ATTR_ORPHAN,
                values: vec![b"x".to_vec()],
            },
            Violation::AttributeNotAllowed(ATTR_ORPHAN),
        ),
        (
            AttributeChange::Replace {
                id: ATTR_NAME,
                values: vec![b"a".to_vec(), b"b".to_vec()],
            },
            Violation::MultipleValuesOnSingleValued(ATTR_NAME),
        ),
        (
            AttributeChange::Replace {
                id: AttrId(4242),
                values: vec![],
            },
            Violation::UnknownAttribute(AttrId(4242)),
        ),
    ];
    for (change, expected) in cases {
        match txn.modify_object(guid(2), vec![change], &origin(NODE_1, 2, 2)) {
            Err(Error::Rejected(v)) => assert_eq!(v, expected),
            other => panic!("expected rejection {expected:?}, got {other:?}"),
        }
    }
    // The same attribute twice in one request.
    assert!(matches!(
        txn.modify_object(
            guid(2),
            vec![
                AttributeChange::Replace {
                    id: ATTR_NOTE,
                    values: vec![b"a".to_vec()]
                },
                AttributeChange::Replace {
                    id: ATTR_NOTE,
                    values: vec![b"b".to_vec()]
                },
            ],
            &origin(NODE_1, 2, 3)
        ),
        Err(Error::Rejected(Violation::DuplicateAttribute(ATTR_NOTE)))
    ));
    txn.commit().unwrap();
    assert_eq!(
        store.snapshot().unwrap().get_object(guid(2)).unwrap(),
        before
    );
}

#[test]
fn secret_attribute_write_is_rejected() {
    // Source: docs/12 D44; docs/32 §1 — secret material is never written to
    // the readable store, even though a class lists it as "may".
    let mut attrs = base_attrs();
    attrs.push((ATTR_KEY_MATERIAL, vec![b"k".to_vec()]));
    assert!(matches!(
        create_error("secret-create", with_attrs(attrs)),
        Error::Rejected(Violation::SecretAttribute(ATTR_KEY_MATERIAL))
    ));
    // Even when the value would also break other rules, the Secret refusal
    // comes first.
    let mut attrs = base_attrs();
    attrs.push((
        ATTR_KEY_MATERIAL,
        vec![vec![0; MAX_VALUE_LEN + 1], vec![0; MAX_VALUE_LEN + 1]],
    ));
    assert!(matches!(
        create_error("secret-create-first", with_attrs(attrs)),
        Error::Rejected(Violation::SecretAttribute(ATTR_KEY_MATERIAL))
    ));

    let dir = TempDir::new("secret-modify");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![container(1, None, "root"), principal(2, guid(1), "p")],
    );
    let before = store.snapshot().unwrap().get_object(guid(2)).unwrap();
    let mut txn = store.begin_write().unwrap();
    for values in [vec![b"k".to_vec()], vec![]] {
        assert!(matches!(
            txn.modify_object(
                guid(2),
                vec![AttributeChange::Replace {
                    id: ATTR_KEY_MATERIAL,
                    values
                }],
                &origin(NODE_1, 3, 3)
            ),
            Err(Error::Rejected(Violation::SecretAttribute(
                ATTR_KEY_MATERIAL
            )))
        ));
    }
    txn.commit().unwrap();
    assert_eq!(
        store.snapshot().unwrap().get_object(guid(2)).unwrap(),
        before
    );
}

#[test]
fn stored_attribute_later_classified_secret_is_never_returned() {
    // Source: docs/14 D60 (re-validate before use) and docs/12 D44: if the
    // schema given at open classifies a stored attribute as Secret, the
    // object is refused on read rather than returned with it.
    let dir = TempDir::new("secret-reclass");
    {
        let store = Store::open(
            dir.db_path(),
            key_a(),
            test_schema_with_key_material(AttrClass::Sensitive),
        )
        .unwrap();
        let mut attrs = base_attrs();
        attrs.push((ATTR_KEY_MATERIAL, vec![b"k".to_vec()]));
        create_all(&store, vec![container(1, None, "root"), with_attrs(attrs)]);
    }
    let store = open_store(&dir); // ATTR_KEY_MATERIAL is Secret here
    let snap = store.snapshot().unwrap();
    assert!(matches!(
        snap.get_object(guid(2)),
        Err(Error::StoredObjectRejected(Violation::SecretAttribute(
            ATTR_KEY_MATERIAL
        )))
    ));
    assert!(snap.get_object(guid(1)).unwrap().is_some());
    assert_eq!(
        store.schema().attr_class(ATTR_KEY_MATERIAL),
        Some(AttrClass::Secret)
    );
}

#[test]
fn schema_definition_defects() {
    // Source: docs/32 §4 (schema is data — and validated); docs/12 D44.
    let def = |id: u32, max: usize, class: AttrClass| AttributeDefinition {
        id: AttrId(id),
        syntax: ValueSyntax::OctetString,
        multiplicity: Multiplicity::SingleValued,
        max_value_len: max,
        class,
    };
    let class = |id: u32, must: Vec<u32>, may: Vec<u32>| ClassDefinition {
        id: ClassId(id),
        must: must.into_iter().map(AttrId).collect(),
        may: may.into_iter().map(AttrId).collect(),
    };
    let check = |attrs, classes, expected: SchemaDefect| match Schema::new(attrs, classes) {
        Err(Error::InvalidSchema(d)) => assert_eq!(d, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    };
    check(
        vec![def(1, 8, AttrClass::Normal), def(1, 8, AttrClass::Normal)],
        vec![],
        SchemaDefect::DuplicateAttributeDefinition(AttrId(1)),
    );
    check(
        vec![def(1, 0, AttrClass::Normal)],
        vec![],
        SchemaDefect::ValueBoundOutOfRange(AttrId(1)),
    );
    check(
        vec![def(1, MAX_VALUE_LEN + 1, AttrClass::Normal)],
        vec![],
        SchemaDefect::ValueBoundOutOfRange(AttrId(1)),
    );
    check(
        vec![def(1, 8, AttrClass::Normal)],
        vec![class(1, vec![2], vec![])],
        SchemaDefect::UndefinedAttributeInClass(ClassId(1), AttrId(2)),
    );
    check(
        vec![def(1, 8, AttrClass::Normal)],
        vec![class(1, vec![1], vec![1])],
        SchemaDefect::DuplicateAttributeInClass(ClassId(1), AttrId(1)),
    );
    check(
        vec![def(1, 8, AttrClass::Secret)],
        vec![class(1, vec![1], vec![])],
        SchemaDefect::SecretMustAttribute(ClassId(1), AttrId(1)),
    );
    check(
        vec![def(1, 8, AttrClass::Normal)],
        vec![class(1, vec![1], vec![]), class(1, vec![], vec![1])],
        SchemaDefect::DuplicateClassDefinition(ClassId(1)),
    );
    // A Secret attribute may be *defined* (so the PDP knows its class) and
    // even listed as "may": it is the write that is refused.
    assert!(Schema::new(
        vec![def(1, 8, AttrClass::Normal), def(2, 8, AttrClass::Secret)],
        vec![class(1, vec![1], vec![2])],
    )
    .is_ok());
}
