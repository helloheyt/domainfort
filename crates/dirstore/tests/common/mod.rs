//! Shared test fixtures: a temporary directory, a small TEST schema, and
//! helpers.
//!
//! Source: the test schema is hand-made for these tests from the mechanism of
//! docs/32 §4 (attribute id / syntax / multiplicity / bound / class, and class
//! must / may) and docs/46 §8.1-§8.5 (storage, links, ranges, constraints,
//! uniqueness, RDN labels; superclass, instantiable, RDN attribute, possible
//! superiors, NC root). It is NOT AD schema content (that is the separate
//! `ad-schema` crate, docs/46 R46-1): its ids, labels and shape are this
//! project's own test data. AttrId(0) and ClassId(0) are used on purpose:
//! every id is valid, none is a sentinel (docs/46 §8.6). SID and
//! security-descriptor values are built with our own `dtyp` crate's public
//! constructors and encoders (`dtyp::Sid::new`,
//! `dtyp::SecurityDescriptor::encode`).

#![allow(dead_code)]

use dirstore::{
    AttrClass, AttrId, AttributeDefinition, ClassDefinition, ClassId, IntegrityKey, Link,
    Multiplicity, NewObject, NodeId, Origin, Schema, Storage, Store, Timestamp, ValueConstraint,
    ValueRange, ValueSyntax, MAX_VALUE_LEN,
};
use dtyp::{Control, Guid, SecurityDescriptor, Sid};
use std::path::{Path, PathBuf};

/// A per-test directory under cargo's integration-test scratch area,
/// removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(test_name: &str) -> TempDir {
        let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let dir = base.join(format!("dirstore-{test_name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    pub fn db_path(&self) -> PathBuf {
        self.0.join("store.redb")
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---- TEST schema (docs/32 §4, docs/46 §8 mechanism; not AD content) ----

/// Single-valued UTF-8 name, 1..=64 UTF-16 units; the RDN attribute of most
/// classes (RDN label length 2). Id 0 on purpose (docs/46 §8.6).
pub const ATTR_NAME: AttrId = AttrId(0);
/// Multi-valued UTF-8 note.
pub const ATTR_NOTE: AttrId = AttrId(2);
/// Multi-valued object reference: forward link, link id 2.
pub const ATTR_MEMBER: AttrId = AttrId(3);
/// Single-valued SID, unique.
pub const ATTR_SID: AttrId = AttrId(4);
/// Single-valued security descriptor.
pub const ATTR_SD: AttrId = AttrId(5);
/// Single-valued Sensitive octet string.
pub const ATTR_PHONE: AttrId = AttrId(6);
/// Single-valued SECRET octet string (allowed by a class, never writable).
pub const ATTR_KEY_MATERIAL: AttrId = AttrId(7);
/// Single-valued boolean.
pub const ATTR_FLAG: AttrId = AttrId(8);
/// Single-valued integer.
pub const ATTR_COUNTER: AttrId = AttrId(9);
/// Multi-valued octet string with the largest allowed value bound.
pub const ATTR_BLOB: AttrId = AttrId(10);
/// Defined in the schema but allowed by no class.
pub const ATTR_ORPHAN: AttrId = AttrId(11);
/// Derived back link of ATTR_MEMBER (link id 3).
pub const ATTR_MEMBER_OF: AttrId = AttrId(12);
/// Single-valued UTF-8 login name, unique, 1..=256 UTF-16 units.
pub const ATTR_LOGIN: AttrId = AttrId(13);
/// Multi-valued UTF-8 service name, unique.
pub const ATTR_SPN: AttrId = AttrId(14);
/// Single-valued Integer32 with an allowed-value list (KIND_VALUES).
pub const ATTR_KIND: AttrId = AttrId(15);
/// Single-valued Integer32 with an allowed-bits mask (CONTROL_BITS).
pub const ATTR_CONTROL: AttrId = AttrId(16);
/// Single-valued DsTime.
pub const ATTR_CREATED: AttrId = AttrId(17);
/// Derived, not a link (computed by the layer above).
pub const ATTR_DISPLAY: AttrId = AttrId(18);
/// Multi-valued UTF-8, 1..=64 units: the RDN attribute of CLASS_OU (label 2).
pub const ATTR_OU: AttrId = AttrId(19);
/// Single-valued UTF-8, 1..=255 units: the RDN attribute of CLASS_DC_ROOT
/// (label 2).
pub const ATTR_DC: AttrId = AttrId(20);
/// Single-valued Integer32 with the value range -10..=10.
pub const ATTR_LEVEL: AttrId = AttrId(21);
/// Single-valued UTF-8 with the length range 0..=4 UTF-16 units.
pub const ATTR_TEXT: AttrId = AttrId(22);
/// Multi-valued object reference: forward link 4, with no back link.
pub const ATTR_SEE_ALSO: AttrId = AttrId(23);

/// RDN label length of ATTR_NAME, ATTR_OU and ATTR_DC.
pub const RDN_LABEL: usize = 2;
/// Forward link id of ATTR_MEMBER.
pub const MEMBER_LINK: u32 = 2;
/// Allowed values of ATTR_KIND.
pub const KIND_VALUES: [i32; 3] = [2, 4, i32::MIN | 2];
/// Allowed bits of ATTR_CONTROL.
pub const CONTROL_BITS: u32 = 0x0000_0202;

pub const CLASS_TOP: ClassId = ClassId(0);
pub const CLASS_DOMAIN: ClassId = ClassId(1);
pub const CLASS_CONTAINER: ClassId = ClassId(2);
pub const CLASS_OU: ClassId = ClassId(3);
pub const CLASS_PERSON: ClassId = ClassId(4);
pub const CLASS_PRINCIPAL: ClassId = ClassId(5);
/// Subclass of CLASS_PRINCIPAL that adds the must-attribute ATTR_FLAG.
pub const CLASS_FLAGGED: ClassId = ClassId(6);
/// NC-root class named by ATTR_DC.
pub const CLASS_DC_ROOT: ClassId = ClassId(7);
/// Class whose RDN attribute (ATTR_NAME) is only a may-attribute.
pub const CLASS_LOOSE: ClassId = ClassId(8);

/// The full class chain of CLASS_PRINCIPAL, ascending.
pub const PRINCIPAL_CHAIN: [ClassId; 3] = [CLASS_TOP, CLASS_PERSON, CLASS_PRINCIPAL];

/// Value bound of ATTR_NAME.
pub const NAME_MAX: usize = 64;

fn attr(
    id: AttrId,
    syntax: ValueSyntax,
    multiplicity: Multiplicity,
    max_value_len: usize,
    class: AttrClass,
) -> AttributeDefinition {
    AttributeDefinition::new(id, syntax, multiplicity, max_value_len, class)
}

fn range(lower: i64, upper: i64) -> Option<ValueRange> {
    Some(ValueRange { lower, upper })
}

pub fn attribute_definitions(key_material_class: AttrClass) -> Vec<AttributeDefinition> {
    use AttrClass::{Normal, Sensitive};
    use Multiplicity::{MultiValued, SingleValued};
    vec![
        AttributeDefinition {
            range: range(1, 64),
            rdn_att_len: Some(RDN_LABEL),
            ..attr(
                ATTR_NAME,
                ValueSyntax::Utf8String,
                SingleValued,
                NAME_MAX,
                Normal,
            )
        },
        attr(ATTR_NOTE, ValueSyntax::Utf8String, MultiValued, 256, Normal),
        AttributeDefinition {
            link: Some(Link::Forward {
                link_id: MEMBER_LINK,
            }),
            ..attr(ATTR_MEMBER, ValueSyntax::ObjectRef, MultiValued, 16, Normal)
        },
        AttributeDefinition {
            unique: true,
            ..attr(ATTR_SID, ValueSyntax::Sid, SingleValued, 68, Normal)
        },
        attr(
            ATTR_SD,
            ValueSyntax::SecurityDescriptor,
            SingleValued,
            4096,
            Normal,
        ),
        attr(
            ATTR_PHONE,
            ValueSyntax::OctetString,
            SingleValued,
            32,
            Sensitive,
        ),
        attr(
            ATTR_KEY_MATERIAL,
            ValueSyntax::OctetString,
            SingleValued,
            64,
            key_material_class,
        ),
        attr(ATTR_FLAG, ValueSyntax::Boolean, SingleValued, 1, Normal),
        attr(ATTR_COUNTER, ValueSyntax::Integer, SingleValued, 8, Normal),
        attr(
            ATTR_BLOB,
            ValueSyntax::OctetString,
            MultiValued,
            MAX_VALUE_LEN,
            Normal,
        ),
        attr(
            ATTR_ORPHAN,
            ValueSyntax::OctetString,
            SingleValued,
            8,
            Normal,
        ),
        AttributeDefinition {
            storage: Storage::Derived,
            link: Some(Link::Back {
                link_id: MEMBER_LINK + 1,
            }),
            ..attr(
                ATTR_MEMBER_OF,
                ValueSyntax::ObjectRef,
                MultiValued,
                16,
                Normal,
            )
        },
        AttributeDefinition {
            unique: true,
            range: range(1, 256),
            ..attr(
                ATTR_LOGIN,
                ValueSyntax::Utf8String,
                SingleValued,
                768,
                Normal,
            )
        },
        AttributeDefinition {
            unique: true,
            ..attr(ATTR_SPN, ValueSyntax::Utf8String, MultiValued, 1024, Normal)
        },
        AttributeDefinition {
            constraint: Some(ValueConstraint::AllowedValues(KIND_VALUES.to_vec())),
            ..attr(ATTR_KIND, ValueSyntax::Integer32, SingleValued, 4, Normal)
        },
        AttributeDefinition {
            constraint: Some(ValueConstraint::AllowedBits(CONTROL_BITS)),
            ..attr(
                ATTR_CONTROL,
                ValueSyntax::Integer32,
                SingleValued,
                4,
                Normal,
            )
        },
        attr(ATTR_CREATED, ValueSyntax::DsTime, SingleValued, 8, Normal),
        AttributeDefinition {
            storage: Storage::Derived,
            ..attr(
                ATTR_DISPLAY,
                ValueSyntax::Utf8String,
                SingleValued,
                256,
                Normal,
            )
        },
        AttributeDefinition {
            range: range(1, 64),
            rdn_att_len: Some(RDN_LABEL),
            ..attr(ATTR_OU, ValueSyntax::Utf8String, MultiValued, 192, Normal)
        },
        AttributeDefinition {
            range: range(1, 255),
            rdn_att_len: Some(RDN_LABEL),
            ..attr(ATTR_DC, ValueSyntax::Utf8String, SingleValued, 765, Normal)
        },
        AttributeDefinition {
            range: range(-10, 10),
            ..attr(ATTR_LEVEL, ValueSyntax::Integer32, SingleValued, 4, Normal)
        },
        AttributeDefinition {
            range: range(0, 4),
            ..attr(ATTR_TEXT, ValueSyntax::Utf8String, SingleValued, 64, Normal)
        },
        AttributeDefinition {
            link: Some(Link::Forward { link_id: 4 }),
            ..attr(
                ATTR_SEE_ALSO,
                ValueSyntax::ObjectRef,
                MultiValued,
                16,
                Normal,
            )
        },
    ]
}

/// An instantiable, non-NC-root class with no possible superiors; adjust the
/// other fields with struct-update syntax.
pub fn class_def(
    id: ClassId,
    superclass: Option<ClassId>,
    rdn_attr: AttrId,
    must: Vec<AttrId>,
    may: Vec<AttrId>,
) -> ClassDefinition {
    ClassDefinition {
        id,
        superclass,
        instantiable: true,
        rdn_attr,
        poss_superiors: vec![],
        nc_root: false,
        must,
        may,
    }
}

/// The possible superiors of containers and principals.
fn parents() -> Vec<ClassId> {
    vec![CLASS_DOMAIN, CLASS_CONTAINER, CLASS_OU]
}

pub fn class_definitions() -> Vec<ClassDefinition> {
    vec![
        ClassDefinition {
            instantiable: false,
            ..class_def(
                CLASS_TOP,
                None,
                ATTR_NAME,
                vec![],
                vec![ATTR_NOTE, ATTR_DISPLAY, ATTR_CREATED, ATTR_MEMBER_OF],
            )
        },
        ClassDefinition {
            nc_root: true,
            ..class_def(
                CLASS_DOMAIN,
                Some(CLASS_TOP),
                ATTR_NAME,
                vec![ATTR_NAME],
                vec![],
            )
        },
        ClassDefinition {
            poss_superiors: parents(),
            ..class_def(
                CLASS_CONTAINER,
                Some(CLASS_TOP),
                ATTR_NAME,
                vec![ATTR_NAME],
                vec![],
            )
        },
        ClassDefinition {
            poss_superiors: vec![CLASS_DOMAIN, CLASS_OU],
            ..class_def(CLASS_OU, Some(CLASS_TOP), ATTR_OU, vec![ATTR_OU], vec![])
        },
        ClassDefinition {
            instantiable: false,
            ..class_def(
                CLASS_PERSON,
                Some(CLASS_TOP),
                ATTR_NAME,
                vec![ATTR_NAME],
                vec![],
            )
        },
        ClassDefinition {
            poss_superiors: parents(),
            ..class_def(
                CLASS_PRINCIPAL,
                Some(CLASS_PERSON),
                ATTR_NAME,
                vec![ATTR_SID],
                vec![
                    ATTR_MEMBER,
                    ATTR_SD,
                    ATTR_PHONE,
                    ATTR_KEY_MATERIAL,
                    ATTR_FLAG,
                    ATTR_COUNTER,
                    ATTR_BLOB,
                    ATTR_LOGIN,
                    ATTR_SPN,
                    ATTR_KIND,
                    ATTR_CONTROL,
                    ATTR_LEVEL,
                    ATTR_TEXT,
                    ATTR_SEE_ALSO,
                ],
            )
        },
        ClassDefinition {
            poss_superiors: parents(),
            ..class_def(
                CLASS_FLAGGED,
                Some(CLASS_PRINCIPAL),
                ATTR_NAME,
                vec![ATTR_FLAG],
                vec![],
            )
        },
        ClassDefinition {
            nc_root: true,
            ..class_def(
                CLASS_DC_ROOT,
                Some(CLASS_TOP),
                ATTR_DC,
                vec![ATTR_DC],
                vec![],
            )
        },
        ClassDefinition {
            poss_superiors: parents(),
            ..class_def(
                CLASS_LOOSE,
                Some(CLASS_TOP),
                ATTR_NAME,
                vec![],
                vec![ATTR_NAME],
            )
        },
    ]
}

/// The TEST schema, with ATTR_KEY_MATERIAL of class Secret.
pub fn test_schema() -> Schema {
    Schema::new(
        attribute_definitions(AttrClass::Secret),
        class_definitions(),
    )
    .expect("test schema is valid")
}

/// The TEST schema with ATTR_KEY_MATERIAL reclassified (for the "a stored
/// attribute later classified Secret is never returned" test).
pub fn test_schema_with_key_material(class: AttrClass) -> Schema {
    Schema::new(attribute_definitions(class), class_definitions()).expect("test schema is valid")
}

// ---- keys, origins, ids ----

pub const KEY_A: [u8; 32] = [0x11; 32];
pub const KEY_B: [u8; 32] = [0x22; 32];

pub fn key_a() -> IntegrityKey {
    IntegrityKey::from_bytes(&KEY_A)
}

pub fn open_store(dir: &TempDir) -> Store {
    Store::open(dir.db_path(), key_a(), test_schema()).expect("open store")
}

pub const NODE_1: NodeId = NodeId([0xA1; 16]);
pub const NODE_2: NodeId = NodeId([0xB2; 16]);

pub fn origin(node: NodeId, wall_clock: u64, seq: u64) -> Origin {
    Origin {
        wall_clock: Timestamp(wall_clock),
        origin_node: node,
        origin_seq: seq,
    }
}

/// A distinct GUID per small integer.
pub fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0x1234,
        data3: 0x5678,
        data4: [1, 2, 3, 4, 5, 6, 7, 8],
    }
}

/// The ObjectRef value naming `guid(n)`.
pub fn ref_to(n: u32) -> Vec<u8> {
    guid(n).to_packet().to_vec()
}

/// SID value S-1-5-21-1-2-3-`rid`, packet form, built by `dtyp`.
pub fn sid_value(rid: u32) -> Vec<u8> {
    Sid::new([0, 0, 0, 0, 0, 5], &[21, 1, 2, 3, rid])
        .expect("valid SID")
        .encode()
}

/// A canonical self-relative security descriptor with owner and group, built
/// by `dtyp`.
pub fn sd_value() -> Vec<u8> {
    SecurityDescriptor {
        sbz1: 0,
        control: Control(Control::SELF_RELATIVE),
        owner_sid: Some(Sid::new([0, 0, 0, 0, 0, 5], &[18]).expect("valid SID")),
        group_sid: Some(Sid::new([0, 0, 0, 0, 0, 5], &[32, 544]).expect("valid SID")),
        sacl: None,
        dacl: None,
    }
    .encode()
    .expect("valid SD")
}

/// An NC root (CLASS_DOMAIN) named `name`.
pub fn root(id: u32, name: &str) -> NewObject {
    NewObject {
        guid: guid(id),
        parent: None,
        classes: vec![CLASS_TOP, CLASS_DOMAIN],
        attributes: vec![(ATTR_NAME, vec![name.as_bytes().to_vec()])],
    }
}

/// A container named `name` under `parent`.
pub fn container(id: u32, parent: Guid, name: &str) -> NewObject {
    NewObject {
        guid: guid(id),
        parent: Some(parent),
        classes: vec![CLASS_TOP, CLASS_CONTAINER],
        attributes: vec![(ATTR_NAME, vec![name.as_bytes().to_vec()])],
    }
}

/// An organizational unit (named by ATTR_OU) under `parent`.
pub fn ou(id: u32, parent: Guid, name: &str) -> NewObject {
    NewObject {
        guid: guid(id),
        parent: Some(parent),
        classes: vec![CLASS_TOP, CLASS_OU],
        attributes: vec![(ATTR_OU, vec![name.as_bytes().to_vec()])],
    }
}

/// A principal named `name` under `parent`, with SID ...-(1000 + id).
pub fn principal(id: u32, parent: Guid, name: &str) -> NewObject {
    NewObject {
        guid: guid(id),
        parent: Some(parent),
        classes: PRINCIPAL_CHAIN.to_vec(),
        attributes: vec![
            (ATTR_NAME, vec![name.as_bytes().to_vec()]),
            (ATTR_SID, vec![sid_value(1000 + id)]),
        ],
    }
}

/// `principal` with extra attributes.
pub fn principal_with(
    id: u32,
    parent: Guid,
    name: &str,
    extra: Vec<(AttrId, Vec<Vec<u8>>)>,
) -> NewObject {
    let mut obj = principal(id, parent, name);
    obj.attributes.extend(extra);
    obj
}

/// Create `objects` in one committed transaction.
pub fn create_all(store: &Store, objects: Vec<NewObject>) {
    let mut txn = store.begin_write().expect("begin write");
    for (i, obj) in objects.into_iter().enumerate() {
        let seq = u64::try_from(i).expect("small") + 1;
        txn.create_object(obj, &origin(NODE_1, 1000, seq))
            .expect("create object");
    }
    txn.commit().expect("commit");
}
