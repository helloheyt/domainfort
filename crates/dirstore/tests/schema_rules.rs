//! `Schema::new` rejects defective link, range, constraint, uniqueness,
//! Derived and class definitions.
//!
//! Source: docs/46 §8.2 (storage, link, range, constraint, unique), §8.3
//! (superclass, instantiable, rdn_attr, poss_superiors, nc_root), §2.3
//! (phase 1: ObjectRef ⇔ Forward; back links Derived); [MS-ADTS] v20261026
//! §3.1.1.2.3 (linkID: zero means no link, even means forward, odd means
//! back and equals the forward id plus one, unique; rangeLower / rangeUpper
//! not applicable to Boolean and Object(DS-DN)), §3.1.1.1.6 (a back link
//! needs its forward link, not vice versa), §3.1.1.3.1.2.1 (the RDN
//! attribute MUST be String(Unicode)), §3.1.1.4.2 (SUPCLASSES); Q-090 (RDN
//! label length). The schemas are tiny, hand-made test data.

mod common;

use common::class_def;
use dirstore::{
    AttrClass, AttrId, AttributeDefinition, ClassDefinition, ClassId, Error, Link, Multiplicity,
    Schema, SchemaDefect, Storage, ValueConstraint, ValueRange, ValueSyntax,
    MAX_CLASSES_PER_OBJECT, MAX_RDN_ATT_LEN,
};

const NAME: AttrId = AttrId(0);
const ROOT: ClassId = ClassId(0);

fn plain(id: u32, syntax: ValueSyntax) -> AttributeDefinition {
    AttributeDefinition::new(
        AttrId(id),
        syntax,
        Multiplicity::MultiValued,
        64,
        AttrClass::Normal,
    )
}

/// A usable RDN attribute (id 0).
fn name_attr() -> AttributeDefinition {
    AttributeDefinition {
        rdn_att_len: Some(2),
        ..plain(0, ValueSyntax::Utf8String)
    }
}

/// An NC-root class (id 0) named by attribute 0, allowing `may`.
fn root_class(may: Vec<AttrId>) -> ClassDefinition {
    ClassDefinition {
        nc_root: true,
        ..class_def(ROOT, None, NAME, vec![NAME], may)
    }
}

/// `Schema::new` over the name attribute + `attrs`, and the root class
/// allowing every extra attribute + `classes`.
fn build(attrs: Vec<AttributeDefinition>, classes: Vec<ClassDefinition>) -> Result<Schema, Error> {
    let may = attrs.iter().map(|a| a.id).collect();
    let mut all_attrs = vec![name_attr()];
    all_attrs.extend(attrs);
    let mut all_classes = vec![root_class(may)];
    all_classes.extend(classes);
    Schema::new(all_attrs, all_classes)
}

fn expect(result: Result<Schema, Error>, expected: SchemaDefect) {
    match result {
        Err(Error::InvalidSchema(d)) => assert_eq!(d, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

fn forward(id: u32, link_id: u32) -> AttributeDefinition {
    AttributeDefinition {
        link: Some(Link::Forward { link_id }),
        ..plain(id, ValueSyntax::ObjectRef)
    }
}

fn back(id: u32, link_id: u32) -> AttributeDefinition {
    AttributeDefinition {
        storage: Storage::Derived,
        link: Some(Link::Back { link_id }),
        ..plain(id, ValueSyntax::ObjectRef)
    }
}

#[test]
fn baseline_schema_is_valid() {
    // Source: docs/46 §8.2 — a forward link with its back link, and a forward
    // link with none ("A forward link attribute can exist with no
    // corresponding back link attribute", [MS-ADTS] 3.1.1.1.6). Ids 0 are
    // ordinary ids (docs/46 §8.6).
    assert!(build(vec![forward(1, 2), back(2, 3), forward(3, 4)], vec![]).is_ok());
    // The test schema of tests/common is valid too.
    let _ = common::test_schema();
}

#[test]
fn bad_link_definitions() {
    // Source: [MS-ADTS] 3.1.1.2.3 (linkID parity / zero / uniqueness);
    // docs/46 §2.3, §8.2.
    let a = AttrId(1);
    expect(
        build(vec![forward(1, 3)], vec![]),
        SchemaDefect::InvalidLinkId(a),
    );
    expect(
        build(vec![forward(1, 0)], vec![]),
        SchemaDefect::InvalidLinkId(a),
    );
    expect(
        build(vec![forward(2, 2), back(1, 4)], vec![]),
        SchemaDefect::InvalidLinkId(a),
    );
    // A forward link must be a Stored ObjectRef.
    expect(
        build(
            vec![AttributeDefinition {
                link: Some(Link::Forward { link_id: 2 }),
                ..plain(1, ValueSyntax::Guid)
            }],
            vec![],
        ),
        SchemaDefect::InvalidForwardLink(a),
    );
    expect(
        build(
            vec![AttributeDefinition {
                storage: Storage::Derived,
                ..forward(1, 2)
            }],
            vec![],
        ),
        SchemaDefect::InvalidForwardLink(a),
    );
    // A back link must be Derived ("a Back without Derived").
    expect(
        build(
            vec![
                forward(2, 2),
                AttributeDefinition {
                    storage: Storage::Stored,
                    ..back(1, 3)
                },
            ],
            vec![],
        ),
        SchemaDefect::BackLinkNotDerived(a),
    );
    // A back link needs its forward link.
    expect(
        build(vec![back(1, 5)], vec![]),
        SchemaDefect::BackLinkWithoutForward(a),
    );
    expect(
        build(vec![forward(2, 2), back(1, 5)], vec![]),
        SchemaDefect::BackLinkWithoutForward(a),
    );
    // Link ids are unique.
    expect(
        build(vec![forward(1, 2), forward(2, 2)], vec![]),
        SchemaDefect::DuplicateLinkId(AttrId(2)),
    );
    expect(
        build(vec![forward(1, 2), back(2, 3), back(3, 3)], vec![]),
        SchemaDefect::DuplicateLinkId(AttrId(3)),
    );
    // Phase 1: a stored ObjectRef is a forward link ("an ObjectRef without
    // Forward").
    expect(
        build(vec![plain(1, ValueSyntax::ObjectRef)], vec![]),
        SchemaDefect::ObjectRefWithoutForwardLink(a),
    );
    // A class may not require a forward link (referential integrity can
    // remove its last value).
    expect(
        Schema::new(
            vec![name_attr(), forward(1, 2)],
            vec![ClassDefinition {
                nc_root: true,
                ..class_def(ROOT, None, NAME, vec![NAME, a], vec![])
            }],
        ),
        SchemaDefect::LinkMustAttribute(ROOT, a),
    );
}

#[test]
fn bad_ranges() {
    // Source: docs/46 §8.2; [MS-ADTS] 3.1.1.2.3.
    let a = AttrId(1);
    let ranged = |syntax, lower, upper| AttributeDefinition {
        range: Some(ValueRange { lower, upper }),
        ..plain(1, syntax)
    };
    expect(
        build(vec![ranged(ValueSyntax::Integer, 5, 4)], vec![]),
        SchemaDefect::InvalidRange(a),
    );
    // "rangeLower does not affect the allowed values for syntax Boolean and
    // Object(DS-DN)".
    expect(
        build(vec![ranged(ValueSyntax::Boolean, 0, 1)], vec![]),
        SchemaDefect::RangeNotApplicable(a),
    );
    expect(
        build(
            vec![AttributeDefinition {
                range: Some(ValueRange { lower: 0, upper: 1 }),
                ..forward(1, 2)
            }],
            vec![],
        ),
        SchemaDefect::RangeNotApplicable(a),
    );
    // Unsatisfiable by the syntax / the byte bound.
    let above_i32 = i64::from(i32::MAX) + 1;
    expect(
        build(
            vec![ranged(ValueSyntax::Integer32, above_i32, above_i32 + 1)],
            vec![],
        ),
        SchemaDefect::InvalidRange(a),
    );
    expect(
        build(vec![ranged(ValueSyntax::DsTime, -5, -1)], vec![]),
        SchemaDefect::InvalidRange(a),
    );
    expect(
        build(vec![ranged(ValueSyntax::Utf8String, -1, 4)], vec![]),
        SchemaDefect::InvalidRange(a),
    );
    expect(
        build(vec![ranged(ValueSyntax::OctetString, 65, 70)], vec![]),
        SchemaDefect::InvalidRange(a),
    );
    // Sound ranges pass.
    assert!(build(
        vec![
            ranged(ValueSyntax::Integer32, -1, 1),
            AttributeDefinition {
                range: Some(ValueRange {
                    lower: 0,
                    upper: 64
                }),
                ..plain(2, ValueSyntax::Utf8String)
            },
        ],
        vec![]
    )
    .is_ok());
}

#[test]
fn bad_constraints() {
    // Source: docs/46 §8.2 — constraints are for Integer32; an empty
    // allowed-value list could never be met.
    let a = AttrId(1);
    expect(
        build(
            vec![AttributeDefinition {
                constraint: Some(ValueConstraint::AllowedBits(1)),
                ..plain(1, ValueSyntax::Integer)
            }],
            vec![],
        ),
        SchemaDefect::InvalidConstraint(a),
    );
    expect(
        build(
            vec![AttributeDefinition {
                constraint: Some(ValueConstraint::AllowedValues(vec![])),
                ..plain(1, ValueSyntax::Integer32)
            }],
            vec![],
        ),
        SchemaDefect::InvalidConstraint(a),
    );
    assert!(build(
        vec![AttributeDefinition {
            constraint: Some(ValueConstraint::AllowedValues(vec![2, 4])),
            ..plain(1, ValueSyntax::Integer32)
        }],
        vec![]
    )
    .is_ok());
}

#[test]
fn derived_unique_and_rdn_label_rules() {
    // Source: docs/46 §8.2 (Derived: no stored-value rules, never in must),
    // §8.5 (unique on stored values only); Q-090 / [MS-ADTS] 3.1.1.5.1.2
    // (RDN label length leaves room under 255 characters).
    let a = AttrId(1);
    let derived = |d: AttributeDefinition| AttributeDefinition {
        storage: Storage::Derived,
        ..d
    };
    expect(
        build(
            vec![derived(AttributeDefinition {
                range: Some(ValueRange { lower: 0, upper: 1 }),
                ..plain(1, ValueSyntax::Integer)
            })],
            vec![],
        ),
        SchemaDefect::DerivedAttributeRule(a),
    );
    expect(
        build(
            vec![derived(AttributeDefinition {
                unique: true,
                ..plain(1, ValueSyntax::OctetString)
            })],
            vec![],
        ),
        SchemaDefect::DerivedAttributeRule(a),
    );
    expect(
        Schema::new(
            vec![name_attr(), derived(plain(1, ValueSyntax::OctetString))],
            vec![ClassDefinition {
                nc_root: true,
                ..class_def(ROOT, None, NAME, vec![NAME, a], vec![])
            }],
        ),
        SchemaDefect::DerivedMustAttribute(ROOT, a),
    );
    expect(
        build(
            vec![AttributeDefinition {
                unique: true,
                class: AttrClass::Secret,
                ..plain(1, ValueSyntax::OctetString)
            }],
            vec![],
        ),
        SchemaDefect::UniqueNotApplicable(a),
    );
    expect(
        build(
            vec![AttributeDefinition {
                unique: true,
                ..forward(1, 2)
            }],
            vec![],
        ),
        SchemaDefect::UniqueNotApplicable(a),
    );
    for bad in [0, MAX_RDN_ATT_LEN + 1] {
        expect(
            build(
                vec![AttributeDefinition {
                    rdn_att_len: Some(bad),
                    ..plain(1, ValueSyntax::Utf8String)
                }],
                vec![],
            ),
            SchemaDefect::InvalidRdnAttLen(a),
        );
    }
    assert!(build(
        vec![AttributeDefinition {
            rdn_att_len: Some(MAX_RDN_ATT_LEN),
            ..plain(1, ValueSyntax::Utf8String)
        }],
        vec![]
    )
    .is_ok());
}

#[test]
fn bad_class_definitions() {
    // Source: docs/46 §8.3; [MS-ADTS] 3.1.1.4.2 (SUPCLASSES), 3.1.1.3.1.2.1
    // (RDN attribute of String(Unicode) syntax), 3.1.1.2.4.4 (possSuperiors).
    let c = ClassId(1);
    let child = |superclass, rdn, may, poss: Vec<ClassId>| ClassDefinition {
        poss_superiors: poss,
        ..class_def(c, superclass, rdn, vec![], may)
    };
    // Unknown superclass.
    expect(
        build(
            vec![],
            vec![child(Some(ClassId(9)), NAME, vec![NAME], vec![ROOT])],
        ),
        SchemaDefect::UnknownSuperclass(c, ClassId(9)),
    );
    // A cycle: 1 -> 2 -> 1.
    expect(
        build(
            vec![],
            vec![
                child(Some(ClassId(2)), NAME, vec![NAME], vec![ROOT]),
                ClassDefinition {
                    poss_superiors: vec![ROOT],
                    ..class_def(ClassId(2), Some(c), NAME, vec![], vec![NAME])
                },
            ],
        ),
        SchemaDefect::InvalidClassChain(c),
    );
    // A chain longer than an object may list: classes 1..=MAX+1, each the
    // superclass of the next.
    let long: Vec<ClassDefinition> = (1..=u32::try_from(MAX_CLASSES_PER_OBJECT).unwrap() + 1)
        .map(|i| ClassDefinition {
            poss_superiors: vec![ROOT],
            ..class_def(
                ClassId(i),
                (i > 1).then(|| ClassId(i - 1)),
                NAME,
                vec![],
                vec![NAME],
            )
        })
        .collect();
    let deepest = ClassId(u32::try_from(MAX_CLASSES_PER_OBJECT).unwrap() + 1);
    expect(
        build(vec![], long),
        SchemaDefect::InvalidClassChain(deepest),
    );
    // RDN attribute: undefined, not Utf8String, without a label, not allowed.
    expect(
        build(vec![], vec![child(None, AttrId(7), vec![NAME], vec![ROOT])]),
        SchemaDefect::UndefinedRdnAttribute(c, AttrId(7)),
    );
    expect(
        build(
            vec![plain(1, ValueSyntax::OctetString)],
            vec![child(None, AttrId(1), vec![AttrId(1)], vec![ROOT])],
        ),
        SchemaDefect::InvalidRdnAttribute(c, AttrId(1)),
    );
    expect(
        build(
            vec![plain(1, ValueSyntax::Utf8String)],
            vec![child(None, AttrId(1), vec![AttrId(1)], vec![ROOT])],
        ),
        SchemaDefect::InvalidRdnAttribute(c, AttrId(1)),
    );
    expect(
        build(vec![], vec![child(None, NAME, vec![], vec![ROOT])]),
        SchemaDefect::RdnAttributeNotAllowed(c, NAME),
    );
    // Possible superiors: unknown, repeated.
    expect(
        build(
            vec![],
            vec![child(None, NAME, vec![NAME], vec![ClassId(9)])],
        ),
        SchemaDefect::UnknownPossSuperior(c, ClassId(9)),
    );
    expect(
        build(
            vec![],
            vec![child(None, NAME, vec![NAME], vec![ROOT, ROOT])],
        ),
        SchemaDefect::DuplicatePossSuperior(c, ROOT),
    );
    // NC roots: no possible superiors, must be instantiable.
    expect(
        build(
            vec![],
            vec![ClassDefinition {
                nc_root: true,
                ..child(None, NAME, vec![NAME], vec![ROOT])
            }],
        ),
        SchemaDefect::InvalidNcRoot(c),
    );
    expect(
        build(
            vec![],
            vec![ClassDefinition {
                nc_root: true,
                instantiable: false,
                ..child(None, NAME, vec![NAME], vec![])
            }],
        ),
        SchemaDefect::InvalidNcRoot(c),
    );
    // An instantiable non-root class with nowhere to live.
    expect(
        build(vec![], vec![child(None, NAME, vec![NAME], vec![])]),
        SchemaDefect::NoPossSuperiors(c),
    );
    // A non-instantiable class needs neither.
    assert!(build(
        vec![],
        vec![ClassDefinition {
            instantiable: false,
            ..child(None, NAME, vec![], vec![])
        }]
    )
    .is_ok());
}
