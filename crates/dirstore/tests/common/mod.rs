//! Shared test fixtures: a temporary directory, a small TEST schema, and
//! helpers.
//!
//! Source: the test schema is hand-made for these tests from the mechanism of
//! docs/32 §4 (attribute id / syntax / multiplicity / bound / class, and class
//! must / may). It is NOT AD schema content ([MS-ADSC] / [MS-ADA*] are out of
//! scope) and its names are this project's own. SID and security-descriptor
//! values are built with our own `dtyp` crate's public constructors and
//! encoders (`dtyp::Sid::new`, `dtyp::SecurityDescriptor::encode`).

#![allow(dead_code)]

use dirstore::{
    AttrClass, AttrId, AttributeDefinition, ClassDefinition, ClassId, IntegrityKey, Multiplicity,
    NewObject, NodeId, Origin, Schema, Store, Timestamp, ValueSyntax, MAX_VALUE_LEN,
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

// ---- TEST schema (docs/32 §4 mechanism; not AD content) ----

/// Single-valued UTF-8 name, must on every class.
pub const ATTR_NAME: AttrId = AttrId(1);
/// Multi-valued UTF-8 note.
pub const ATTR_NOTE: AttrId = AttrId(2);
/// Multi-valued GUID reference.
pub const ATTR_MEMBER: AttrId = AttrId(3);
/// Single-valued SID.
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

pub const CLASS_CONTAINER: ClassId = ClassId(1);
pub const CLASS_PRINCIPAL: ClassId = ClassId(2);
/// Auxiliary-style class that requires ATTR_FLAG.
pub const CLASS_FLAGGED: ClassId = ClassId(3);

/// Value bound of ATTR_NAME.
pub const NAME_MAX: usize = 64;

fn attr(
    id: AttrId,
    syntax: ValueSyntax,
    multiplicity: Multiplicity,
    max_value_len: usize,
    class: AttrClass,
) -> AttributeDefinition {
    AttributeDefinition {
        id,
        syntax,
        multiplicity,
        max_value_len,
        class,
    }
}

pub fn attribute_definitions(key_material_class: AttrClass) -> Vec<AttributeDefinition> {
    use AttrClass::{Normal, Sensitive};
    use Multiplicity::{MultiValued, SingleValued};
    vec![
        attr(
            ATTR_NAME,
            ValueSyntax::Utf8String,
            SingleValued,
            NAME_MAX,
            Normal,
        ),
        attr(ATTR_NOTE, ValueSyntax::Utf8String, MultiValued, 256, Normal),
        attr(ATTR_MEMBER, ValueSyntax::Guid, MultiValued, 16, Normal),
        attr(ATTR_SID, ValueSyntax::Sid, SingleValued, 68, Normal),
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
    ]
}

pub fn class_definitions() -> Vec<ClassDefinition> {
    vec![
        ClassDefinition {
            id: CLASS_CONTAINER,
            must: vec![ATTR_NAME],
            may: vec![ATTR_NOTE],
        },
        ClassDefinition {
            id: CLASS_PRINCIPAL,
            must: vec![ATTR_NAME, ATTR_SID],
            may: vec![
                ATTR_NOTE,
                ATTR_MEMBER,
                ATTR_SD,
                ATTR_PHONE,
                ATTR_KEY_MATERIAL,
                ATTR_FLAG,
                ATTR_COUNTER,
                ATTR_BLOB,
            ],
        },
        ClassDefinition {
            id: CLASS_FLAGGED,
            must: vec![ATTR_FLAG],
            may: vec![],
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

/// A container (root or child) named `name`.
pub fn container(id: u32, parent: Option<Guid>, name: &str) -> NewObject {
    NewObject {
        guid: guid(id),
        parent,
        rdn: name.as_bytes().to_vec(),
        classes: vec![CLASS_CONTAINER],
        attributes: vec![(ATTR_NAME, vec![name.as_bytes().to_vec()])],
    }
}

/// A principal named `name` under `parent`.
pub fn principal(id: u32, parent: Guid, name: &str) -> NewObject {
    NewObject {
        guid: guid(id),
        parent: Some(parent),
        rdn: name.as_bytes().to_vec(),
        classes: vec![CLASS_PRINCIPAL],
        attributes: vec![
            (ATTR_NAME, vec![name.as_bytes().to_vec()]),
            (ATTR_SID, vec![sid_value(1000 + id)]),
        ],
    }
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
