//! Documented resource bounds, enforced on write (and on lookup input).
//!
//! Source: docs/32 §8 (bounded inputs, allocation ceiling, D138); the bound
//! values are the crate's documented constants (src/lib.rs). Read-side
//! enforcement of the same bounds by the decoder is in tests/record.rs.

mod common;

use common::*;
use dirstore::{
    AttrClass, AttrId, AttributeDefinition, ClassDefinition, ClassId, Error, Multiplicity,
    NewObject, Schema, Store, ValueSyntax, Violation, MAX_ATTRIBUTES_PER_OBJECT,
    MAX_CLASSES_PER_OBJECT, MAX_RDN_KEY_LEN, MAX_VALUES_PER_ATTRIBUTE, MAX_VALUE_LEN,
};

fn reject(store: &Store, obj: NewObject) -> Violation {
    let mut txn = store.begin_write().unwrap();
    match txn.create_object(obj, &origin(NODE_1, 1, 1)) {
        Err(Error::Rejected(v)) => v,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

fn with_blob(values: Vec<Vec<u8>>) -> NewObject {
    let mut obj = principal(2, guid(1), "p");
    obj.attributes.push((ATTR_BLOB, values));
    obj
}

/// `n` distinct small values.
fn distinct_values(n: usize, len: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let mut v = vec![0u8; len.max(4)];
            v[..4].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
            v
        })
        .collect()
}

#[test]
fn value_size_bound() {
    // Source: docs/32 §8 — MAX_VALUE_LEN.
    let dir = TempDir::new("bound-value");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root")]);
    assert_eq!(
        reject(&store, with_blob(vec![vec![7; MAX_VALUE_LEN + 1]])),
        Violation::ValueTooLarge(ATTR_BLOB)
    );
    let mut txn = store.begin_write().unwrap();
    txn.create_object(
        with_blob(vec![vec![7; MAX_VALUE_LEN]]),
        &origin(NODE_1, 1, 1),
    )
    .unwrap();
    txn.commit().unwrap();
    let back = store
        .snapshot()
        .unwrap()
        .get_object(guid(2))
        .unwrap()
        .unwrap();
    assert_eq!(
        back.attribute(ATTR_BLOB).unwrap().values[0].value.len(),
        MAX_VALUE_LEN
    );
}

#[test]
fn values_per_attribute_bound() {
    // Source: docs/32 §8 — MAX_VALUES_PER_ATTRIBUTE.
    let dir = TempDir::new("bound-values");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root")]);
    assert_eq!(
        reject(
            &store,
            with_blob(distinct_values(MAX_VALUES_PER_ATTRIBUTE + 1, 4))
        ),
        Violation::TooManyValues(ATTR_BLOB)
    );
    let mut txn = store.begin_write().unwrap();
    txn.create_object(
        with_blob(distinct_values(MAX_VALUES_PER_ATTRIBUTE, 4)),
        &origin(NODE_1, 1, 1),
    )
    .unwrap();
    txn.commit().unwrap();
    let back = store
        .snapshot()
        .unwrap()
        .get_object(guid(2))
        .unwrap()
        .unwrap();
    assert_eq!(
        back.attribute(ATTR_BLOB).unwrap().values.len(),
        MAX_VALUES_PER_ATTRIBUTE
    );
}

#[test]
fn record_size_bound() {
    // Source: docs/32 §8 — MAX_RECORD_BODY_LEN caps an object whatever the
    // other bounds allow: 300 values of 64 KiB exceed 16 MiB.
    let dir = TempDir::new("bound-record");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root")]);
    assert_eq!(
        reject(&store, with_blob(distinct_values(300, MAX_VALUE_LEN))),
        Violation::RecordTooLarge
    );
}

#[test]
fn rdn_key_bounds() {
    // Source: docs/32 §2, §8 — the RDN key has at least one byte, and lookup
    // input is bounded by MAX_RDN_KEY_LEN before any work; the key of a
    // created object is computed from its RDN value (docs/46 §8.3), so it is
    // bounded by the attribute's own bound (here NAME_MAX).
    let dir = TempDir::new("bound-rdn");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root")]);
    let longest = "r".repeat(NAME_MAX);
    create_all(&store, vec![principal(2, guid(1), &longest)]);
    let snap = store.snapshot().unwrap();
    assert_eq!(
        snap.lookup_child(Some(guid(1)), longest.as_bytes())
            .unwrap(),
        Some(guid(2))
    );
    // Lookup input is bounded too.
    assert!(matches!(
        snap.lookup_child(Some(guid(1)), &vec![b'r'; MAX_RDN_KEY_LEN + 1]),
        Err(Error::Rejected(Violation::RdnKeyTooLong))
    ));
    assert!(matches!(
        snap.lookup_child(Some(guid(1)), b""),
        Err(Error::Rejected(Violation::RdnKeyEmpty))
    ));
    // A name longer than any stored one is simply not found.
    assert_eq!(
        snap.lookup_child(Some(guid(1)), &vec![b'r'; MAX_RDN_KEY_LEN])
            .unwrap(),
        None
    );
}

#[test]
fn classes_per_object_bound() {
    // Source: docs/32 §8 — MAX_CLASSES_PER_OBJECT (checked before lookups).
    let dir = TempDir::new("bound-classes");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root")]);
    let classes = (0..=MAX_CLASSES_PER_OBJECT)
        .map(|i| ClassId(u32::try_from(i).unwrap() + 100))
        .collect();
    assert_eq!(
        reject(
            &store,
            NewObject {
                classes,
                ..principal(2, guid(1), "p")
            }
        ),
        Violation::TooManyClasses
    );
}

#[test]
fn attributes_per_object_bound() {
    // Source: docs/32 §8 — MAX_ATTRIBUTES_PER_OBJECT. A dedicated test schema
    // with more attributes than one object may hold, split over a two-class
    // chain (a single class may not list more than the bound either), plus a
    // naming attribute 0 (docs/46 §8.3: an object needs its RDN attribute).
    let total = MAX_ATTRIBUTES_PER_OBJECT + 1;
    let mut attributes: Vec<AttributeDefinition> = (1..=total)
        .map(|i| {
            AttributeDefinition::new(
                AttrId(u32::try_from(i).unwrap()),
                ValueSyntax::OctetString,
                Multiplicity::SingleValued,
                8,
                AttrClass::Normal,
            )
        })
        .collect();
    attributes.push(AttributeDefinition {
        rdn_att_len: Some(1),
        ..AttributeDefinition::new(
            AttrId(0),
            ValueSyntax::Utf8String,
            Multiplicity::SingleValued,
            8,
            AttrClass::Normal,
        )
    });
    let half = total / 2;
    let classes = vec![
        ClassDefinition {
            id: ClassId(1),
            superclass: None,
            instantiable: false,
            rdn_attr: AttrId(0),
            poss_superiors: vec![],
            nc_root: false,
            must: vec![AttrId(0)],
            may: (1..=half)
                .map(|i| AttrId(u32::try_from(i).unwrap()))
                .collect(),
        },
        ClassDefinition {
            id: ClassId(2),
            superclass: Some(ClassId(1)),
            instantiable: true,
            rdn_attr: AttrId(0),
            poss_superiors: vec![],
            nc_root: true,
            must: vec![],
            may: (half + 1..=total)
                .map(|i| AttrId(u32::try_from(i).unwrap()))
                .collect(),
        },
    ];
    let schema = Schema::new(attributes, classes).unwrap();
    let dir = TempDir::new("bound-attrs");
    let store = Store::open(dir.db_path(), key_a(), schema).unwrap();
    // `n` attributes in all: the name plus n - 1 others.
    let all = |n: usize| NewObject {
        guid: guid(1),
        parent: None,
        classes: vec![ClassId(1), ClassId(2)],
        attributes: core::iter::once((AttrId(0), vec![b"x".to_vec()]))
            .chain((1..n).map(|i| (AttrId(u32::try_from(i).unwrap()), vec![vec![1]])))
            .collect(),
    };
    assert_eq!(reject(&store, all(total)), Violation::TooManyAttributes);
    let mut txn = store.begin_write().unwrap();
    txn.create_object(all(MAX_ATTRIBUTES_PER_OBJECT), &origin(NODE_1, 1, 1))
        .unwrap();
    txn.commit().unwrap();
    let back = store
        .snapshot()
        .unwrap()
        .get_object(guid(1))
        .unwrap()
        .unwrap();
    assert_eq!(back.attributes.len(), MAX_ATTRIBUTES_PER_OBJECT);
}
