//! Shared test fixtures: a temporary dirstore opened with the phase-1
//! schema, name-based helpers, and value builders.
//!
//! Source: the object shapes follow docs/46 §4.4 (must / may / possible
//! superiors per class) and §5.4 (value forms); the names (`example`,
//! `alice`, …) are this project's own test data. SID and security-
//! descriptor values are built with our own `dtyp` crate's public
//! constructors and encoders (`dtyp::Sid::new`,
//! `dtyp::SecurityDescriptor::encode`).

#![allow(dead_code)]

use ad_schema::{phase1, Phase1Schema};
use dirstore::{
    AttrId, ClassId, Error, IntegrityKey, NewObject, NodeId, Origin, Store, Timestamp, Violation,
};
use dtyp::{Control, Guid, SecurityDescriptor, Sid};
use std::path::PathBuf;

/// A per-test directory under cargo's integration-test scratch area,
/// removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(test_name: &str) -> TempDir {
        let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let dir = base.join(format!("ad-schema-{test_name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    pub fn db_path(&self) -> PathBuf {
        self.0.join("store.redb")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A store opened with the phase-1 schema.
pub struct Fixture {
    pub p1: Phase1Schema,
    pub store: Store,
    seq: std::cell::Cell<u64>,
    _dir: TempDir,
}

impl Fixture {
    pub fn new(test_name: &str) -> Fixture {
        let p1 = phase1().expect("phase-1 schema builds");
        let dir = TempDir::new(test_name);
        let store = Store::open(
            dir.db_path(),
            IntegrityKey::from_bytes(&[0x5A; 32]),
            p1.schema().clone(),
        )
        .expect("open store");
        Fixture {
            p1,
            store,
            seq: std::cell::Cell::new(0),
            _dir: dir,
        }
    }

    pub fn attr(&self, name: &str) -> AttrId {
        self.p1.attribute_by_name(name).expect(name)
    }

    pub fn class(&self, name: &str) -> ClassId {
        self.p1.class_by_name(name).expect(name)
    }

    /// The full objectClass chain of the class `name`.
    pub fn chain(&self, name: &str) -> Vec<ClassId> {
        self.p1
            .class(self.class(name))
            .expect(name)
            .object_class
            .clone()
    }

    pub fn origin(&self) -> Origin {
        let seq = self.seq.get() + 1;
        self.seq.set(seq);
        Origin {
            wall_clock: Timestamp(1000 + seq),
            origin_node: NodeId([0xA1; 16]),
            origin_seq: seq,
        }
    }

    /// A new object of class `class` under `parent`, with `attrs` given by
    /// lDAPDisplayName; nTSecurityDescriptor (must on top) is added.
    pub fn object(
        &self,
        id: u32,
        parent: Option<Guid>,
        class: &str,
        attrs: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        let mut attributes: Vec<(AttrId, Vec<Vec<u8>>)> = attrs
            .iter()
            .map(|(n, v)| (self.attr(n), v.clone()))
            .collect();
        attributes.push((self.attr("nTSecurityDescriptor"), vec![sd_value()]));
        NewObject {
            guid: guid(id),
            parent,
            classes: self.chain(class),
            attributes,
        }
    }

    /// Create one object in its own committed transaction.
    pub fn create(&self, obj: NewObject) -> Result<(), Error> {
        let mut txn = self.store.begin_write().expect("begin write");
        let origin = self.origin();
        txn.create_object(obj, &origin)?;
        txn.commit().expect("commit");
        Ok(())
    }

    /// Create `obj`, which must be refused with `Rejected(violation)`.
    pub fn refused(&self, obj: NewObject) -> Violation {
        match self.create(obj) {
            Err(Error::Rejected(v)) => v,
            other => panic!("expected a Rejected write, got {other:?}"),
        }
    }

    /// The standard tree: domainDNS root (1) → OU (2); container (3) under
    /// the root.
    pub fn tree(&self) {
        self.create(self.object(
            1,
            None,
            "domainDNS",
            &[
                ("dc", vec![b"example".to_vec()]),
                ("objectSid", vec![domain_sid()]),
            ],
        ))
        .expect("root");
        self.create(self.object(
            2,
            Some(guid(1)),
            "organizationalUnit",
            &[("ou", vec![b"Staff".to_vec()])],
        ))
        .expect("ou");
        self.create(self.object(
            3,
            Some(guid(1)),
            "container",
            &[("cn", vec![b"Users".to_vec()])],
        ))
        .expect("container");
    }

    /// A user under `parent` with cn / sAMAccountName `name`, SID RID
    /// 1000 + id, and `extra` attributes.
    pub fn user(
        &self,
        id: u32,
        parent: Guid,
        name: &str,
        extra: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        self.principal("user", id, parent, name, extra)
    }

    /// A computer like [`Fixture::user`].
    pub fn computer(
        &self,
        id: u32,
        parent: Guid,
        name: &str,
        extra: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        self.principal("computer", id, parent, name, extra)
    }

    /// A security-enabled global group like [`Fixture::user`].
    pub fn group(
        &self,
        id: u32,
        parent: Guid,
        name: &str,
        extra: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        let mut attrs = vec![("groupType", vec![int32(i32::MIN | 2)])];
        attrs.extend(extra.iter().cloned());
        self.principal("group", id, parent, name, &attrs)
    }

    fn principal(
        &self,
        class: &str,
        id: u32,
        parent: Guid,
        name: &str,
        extra: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        let mut attrs = vec![
            ("cn", vec![name.as_bytes().to_vec()]),
            ("sAMAccountName", vec![name.as_bytes().to_vec()]),
            ("objectSid", vec![account_sid(1000 + id)]),
        ];
        attrs.extend(extra.iter().cloned());
        self.object(id, Some(parent), class, &attrs)
    }
}

/// A distinct, non-NULL GUID per small integer.
pub fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0x0AD5,
        data3: 0x0001,
        data4: [9, 8, 7, 6, 5, 4, 3, 2],
    }
}

/// The ObjectRef value naming `guid(n)`.
pub fn ref_to(n: u32) -> Vec<u8> {
    guid(n).to_packet().to_vec()
}

/// Integer32 value (4 bytes, big-endian — dirstore's canonical form).
pub fn int32(v: i32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// Integer32 value with these bits.
pub fn bits(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// The domain SID S-1-5-21-1-2-3, packet form.
pub fn domain_sid() -> Vec<u8> {
    Sid::new([0, 0, 0, 0, 0, 5], &[21, 1, 2, 3])
        .expect("valid SID")
        .encode()
}

/// An account SID S-1-5-21-1-2-3-`rid`, packet form.
pub fn account_sid(rid: u32) -> Vec<u8> {
    Sid::new([0, 0, 0, 0, 0, 5], &[21, 1, 2, 3, rid])
        .expect("valid SID")
        .encode()
}

/// A canonical self-relative security descriptor with owner and group.
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
