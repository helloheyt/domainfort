//! Shared fixtures: a temporary dirstore opened with the phase-1 schema, a
//! small directory built through it, the directory context, and the
//! Kerberos-client helpers of the AS → TGS round trip.
//!
//! Source of the shapes: docs/46 §4.4 (must / may / possible superiors per
//! class), §5.4 (value forms); docs/47 §1.3, §4, §5.3, §9.3 (what an account
//! object carries: sAMAccountName, objectSid, userAccountControl,
//! accountExpires, pwdLastSet, whenCreated, member; the krbtgt user with RID
//! 502). The SID layout S-1-5-21-1-2-3-<RID> follows the [MS-DTYP] 2.4.2.4
//! example ("three sub authority values of 1, 2, and 3"). Names, RIDs,
//! passwords and times are this project's own test data; every time value is
//! derived by hand in a comment. No vector or fixture comes from any other
//! implementation.
#![allow(dead_code)] // each test binary uses a different subset

use ad_schema::{phase1, Phase1Schema};
use directory_pip::{DirectoryContext, DirectoryView, NamingContext, TierMap};
use dirstore::{
    AttrId, AttributeChange, ClassId, IntegrityKey, NewObject, NodeId, Origin, Store, Timestamp,
};
use dtyp::{Control, Guid, SecurityDescriptor, Sid, SECURITY_NT_AUTHORITY};
use keyd::KeydConfig;
use krb_proto::{KerberosString, KerberosTime, PrincipalName, Realm};
use std::cell::Cell;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------------

/// The realm: the domain's DNS name in upper case (docs/47 §3.3 item 3).
pub const REALM: &str = "EXAMPLE.TEST";

/// userAccountControl bits ([MS-ADTS] 2.2.16).
pub use ad_schema::flags::user_account_control as uac;
/// groupType values ([MS-ADTS] 2.2.12), as the stored Integer32.
pub const GLOBAL_SECURITY: i32 = i32::MIN | 0x2;
pub const UNIVERSAL_SECURITY: i32 = i32::MIN | 0x8;
pub const LOCAL_SECURITY: i32 = i32::MIN | 0x4;
pub const GLOBAL_DISTRIBUTION: i32 = 0x2;

/// whenCreated of the standard accounts: 2026-11-01T00:00:00Z as DSTIME
/// (seconds since 1601-01-01, [MS-DRSR] 5.51). 1601-01-01 → 1970-01-01 =
/// 134 774 days (369 × 365 + 89 leap days: 92 multiples of 4 in 1604..1968
/// less 1700, 1800, 1900) = 11 644 473 600 s; 1970-01-01 → 2026-01-01 =
/// 56 × 365 + 14 leap days (1972..2024) = 20 454 days; January..October 2026
/// = 31+28+31+30+31+30+31+31+30+31 = 304 days; 20 758 days = 1 793 491 200 s.
/// Total 13 437 964 800.
pub const WHEN_CREATED: i64 = 13_437_964_800;

/// pwdLastSet of the standard accounts: 2026-11-05T12:00:00.5Z as FILETIME
/// (100-ns intervals since 1601-01-01, [MS-DTYP] 2.3.3). 20 758 + 4 = 20 762
/// days since 1970 = 1 793 836 800 s, + 12 h = 1 793 880 000 s, + 11 644 473
/// 600 = 13 438 353 600 s; × 10^7 + 5 000 000 (half a second).
pub const PWD_LAST_SET: i64 = 134_383_536_005_000_000;

/// accountExpires 2027-01-01T00:00:00Z as FILETIME: 1970 → 2027 is
/// 57 × 365 plus 14 leap days = 20 819 days = 1 798 761 600 s; adding
/// 11 644 473 600 gives 13 443 235 200 s; times 10^7.
pub const EXPIRES_2027: i64 = 134_432_352_000_000_000;

/// accountExpires 2026-01-01T00:00:00Z as FILETIME: 20 454 days =
/// 1 767 225 600 s; + 11 644 473 600 = 13 411 699 200 s; × 10^7.
pub const EXPIRES_2026: i64 = 134_116_992_000_000_000;

/// FILETIME of 2026-11-13T10:00:30Z (now + 30 s): 20 758 + 12 = 20 770 days
/// = 1 794 528 000 s, + 10 h 30 s = 1 794 564 030 s, + 11 644 473 600 =
/// 13 439 037 630 s; × 10^7.
pub const NOW_PLUS_30_FILETIME: i64 = 134_390_376_300_000_000;

/// Passwords of the round-trip accounts (test data).
pub const ALICE_PASSWORD: &str = "alice-directory-pip-pass";
pub const WS01_PASSWORD: &str = "ws01-machine-secret-for-tests";

/// The standard objects' small ids (GUID = guid(id)) and RIDs.
pub const ROOT: u32 = 1;
pub const STAFF_OU: u32 = 2;
pub const ADMINS_OU: u32 = 3;
pub const USERS_CN: u32 = 4;
pub const ALICE: u32 = 10;
pub const BOB: u32 = 11;
pub const ROOTADMIN: u32 = 12;
pub const WS01: u32 = 20;
pub const DC01: u32 = 21;
pub const STAFF: u32 = 30;
pub const ALLSTAFF: u32 = 31;
pub const MAIL: u32 = 32;
pub const HIDDEN: u32 = 33;
pub const TIER0: u32 = 34;
pub const KRBTGT: u32 = 40;

// ---------------------------------------------------------------------------
// Values.
// ---------------------------------------------------------------------------

/// A distinct, non-NULL GUID per small integer.
pub fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0xD1,
        data3: 0x0047,
        data4: [4, 7, 4, 7, 4, 7, 4, 7],
    }
}

pub fn ref_to(n: u32) -> Vec<u8> {
    guid(n).to_packet().to_vec()
}

pub fn int32(v: i32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

pub fn bits(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

pub fn int64(v: i64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// S-1-5-21-1-2-3 ([MS-DTYP] 2.4.2.4 example layout).
pub fn domain_sid() -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3]).unwrap()
}

/// S-1-5-21-1-2-3-`rid`.
pub fn account_sid(rid: u32) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, rid]).unwrap()
}

/// The RID of the standard object `id`: 1000 + id, except krbtgt (502,
/// [MS-SAMR] 2.2.1.14 DOMAIN_USER_RID_KRBTGT).
pub fn rid(id: u32) -> u32 {
    if id == KRBTGT {
        502
    } else {
        1000 + id
    }
}

pub fn sid_of(id: u32) -> Sid {
    account_sid(rid(id))
}

/// A canonical self-relative security descriptor with owner and group.
pub fn sd_value() -> Vec<u8> {
    sd().encode().unwrap()
}

pub fn sd() -> SecurityDescriptor {
    SecurityDescriptor {
        sbz1: 0,
        control: Control(Control::SELF_RELATIVE),
        owner_sid: Some(Sid::new(SECURITY_NT_AUTHORITY, &[18]).unwrap()),
        group_sid: Some(Sid::new(SECURITY_NT_AUTHORITY, &[32, 544]).unwrap()),
        sacl: None,
        dacl: None,
    }
}

pub fn realm() -> Realm {
    Realm::new(REALM).unwrap()
}

pub fn kstr(s: &str) -> KerberosString {
    KerberosString::new(s).unwrap()
}

pub fn name(name_type: i32, parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type,
        name_string: parts.iter().map(|p| kstr(p)).collect(),
    }
}

/// KerberosTime shorthand.
pub fn kt(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
    KerberosTime::new(y, mo, d, h, mi, s).unwrap()
}

/// The test "now".
pub fn now() -> KerberosTime {
    kt(2026, 11, 13, 10, 0, 0)
}

/// keyd's configuration: the default AES enctypes (aes256 then aes128) and
/// s2kparams (the enctype default).
pub fn keyd_config() -> KeydConfig {
    KeydConfig::new(realm())
}

/// The naming context dc=example,dc=test: the DNS name example.test, whose
/// upper case is [`REALM`] (A-53; [MS-ADTS] 3.1.1.1.5). Its first label is
/// the root object's dc value.
pub fn naming_context() -> NamingContext {
    NamingContext::new(&["example", "test"]).expect("naming context")
}

// ---------------------------------------------------------------------------
// The directory.
// ---------------------------------------------------------------------------

/// A per-test directory under cargo's integration-test scratch area.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(test_name: &str) -> TempDir {
        let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let dir = base.join(format!("directory-pip-{test_name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A store opened with the phase-1 schema, and the directory context.
pub struct Dir {
    pub p1: Phase1Schema,
    pub store: Store,
    pub ctx: DirectoryContext,
    pub empty_tiers: TierMap,
    seq: Cell<u64>,
    _dir: TempDir,
}

impl Dir {
    pub fn new(test_name: &str) -> Dir {
        let p1 = phase1().expect("phase-1 schema");
        let dir = TempDir::new(test_name);
        let store = Store::open(
            dir.0.join("store.redb"),
            IntegrityKey::from_bytes(&[0x47; 32]),
            p1.schema().clone(),
        )
        .expect("open store");
        let ctx =
            DirectoryContext::new(p1.clone(), &keyd_config(), naming_context()).expect("context");
        Dir {
            p1,
            store,
            ctx,
            empty_tiers: TierMap::empty(),
            seq: Cell::new(0),
            _dir: dir,
        }
    }

    /// The standard directory (module docs of each test file):
    /// - domainDNS dc=example (objectSid S-1-5-21-1-2-3)
    ///   - ou=Staff: alice (user), bob (user), ws01$ (computer, WT, SPN
    ///     host/ws01.example.test), dc01$ (computer, ST, SPN
    ///     ldap/dc01.example.test); groups staff (global security: alice),
    ///     allstaff (universal security: staff), mail (global distribution:
    ///     alice), hidden (local security: mail)
    ///   - ou=Admins: rootadmin (user); group tier0 (global security:
    ///     rootadmin)
    ///   - cn=Users: krbtgt (user, RID 502)
    pub fn standard(test_name: &str) -> Dir {
        let d = Dir::new(test_name);
        d.create_all(d.standard_objects());
        d
    }

    pub fn standard_objects(&self) -> Vec<NewObject> {
        let normal = || vec![bits(uac::ADS_UF_NORMAL_ACCOUNT)];
        vec![
            self.object(
                ROOT,
                None,
                "domainDNS",
                &[
                    ("dc", vec![b"example".to_vec()]),
                    ("objectSid", vec![domain_sid().encode()]),
                ],
            ),
            self.object(
                STAFF_OU,
                Some(guid(ROOT)),
                "organizationalUnit",
                &[("ou", vec![b"Staff".to_vec()])],
            ),
            self.object(
                ADMINS_OU,
                Some(guid(ROOT)),
                "organizationalUnit",
                &[("ou", vec![b"Admins".to_vec()])],
            ),
            self.object(
                USERS_CN,
                Some(guid(ROOT)),
                "container",
                &[("cn", vec![b"Users".to_vec()])],
            ),
            self.user(
                ALICE,
                STAFF_OU,
                "alice",
                &[
                    ("userAccountControl", normal()),
                    ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
                    ("userPrincipalName", vec![b"alice@example.test".to_vec()]),
                ],
            ),
            self.user(
                BOB,
                STAFF_OU,
                "bob",
                &[
                    ("userAccountControl", normal()),
                    ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
                ],
            ),
            self.user(
                ROOTADMIN,
                ADMINS_OU,
                "rootadmin",
                &[
                    ("userAccountControl", normal()),
                    ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
                ],
            ),
            self.computer(
                WS01,
                STAFF_OU,
                "ws01$",
                &[
                    (
                        "userAccountControl",
                        vec![bits(uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT)],
                    ),
                    ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
                    ("dNSHostName", vec![b"ws01.example.test".to_vec()]),
                    (
                        "servicePrincipalName",
                        vec![b"host/ws01.example.test".to_vec()],
                    ),
                ],
            ),
            self.computer(
                DC01,
                STAFF_OU,
                "dc01$",
                &[
                    (
                        "userAccountControl",
                        vec![bits(uac::ADS_UF_SERVER_TRUST_ACCOUNT)],
                    ),
                    (
                        "servicePrincipalName",
                        vec![b"ldap/dc01.example.test".to_vec()],
                    ),
                ],
            ),
            self.group(STAFF, STAFF_OU, "staff", GLOBAL_SECURITY, &[ALICE]),
            self.group(ALLSTAFF, STAFF_OU, "allstaff", UNIVERSAL_SECURITY, &[STAFF]),
            self.group(MAIL, STAFF_OU, "mail", GLOBAL_DISTRIBUTION, &[ALICE]),
            self.group(HIDDEN, STAFF_OU, "hidden", LOCAL_SECURITY, &[MAIL]),
            self.group(TIER0, ADMINS_OU, "tier0", GLOBAL_SECURITY, &[ROOTADMIN]),
            self.user(
                KRBTGT,
                USERS_CN,
                "krbtgt",
                &[
                    ("userAccountControl", normal()),
                    ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
                ],
            ),
        ]
    }

    pub fn attr(&self, name: &str) -> AttrId {
        self.p1.attribute_by_name(name).expect(name)
    }

    pub fn class(&self, name: &str) -> ClassId {
        self.p1.class_by_name(name).expect(name)
    }

    pub fn origin(&self) -> Origin {
        let seq = self.seq.get() + 1;
        self.seq.set(seq);
        Origin {
            wall_clock: Timestamp(1000 + seq),
            origin_node: NodeId([0xD1; 16]),
            origin_seq: seq,
        }
    }

    /// A new object of `class` with `attrs` (by lDAPDisplayName); the
    /// nTSecurityDescriptor (a must on top) is added.
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
            classes: self
                .p1
                .class(self.class(class))
                .expect(class)
                .object_class
                .clone(),
            attributes,
        }
    }

    /// A security principal: cn = sAMAccountName = `sam`, objectSid
    /// S-1-5-21-1-2-3-rid(id), and — for user / computer — whenCreated
    /// [`WHEN_CREATED`] unless `extra` names it.
    fn principal(
        &self,
        class: &str,
        id: u32,
        parent: u32,
        sam: &str,
        extra: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        let mut attrs = vec![
            ("cn", vec![sam.as_bytes().to_vec()]),
            ("sAMAccountName", vec![sam.as_bytes().to_vec()]),
            ("objectSid", vec![sid_of(id).encode()]),
        ];
        if class != "group" && !extra.iter().any(|(n, _)| *n == "whenCreated") {
            attrs.push(("whenCreated", vec![int64(WHEN_CREATED)]));
        }
        attrs.extend(extra.iter().filter(|(_, v)| !v.is_empty()).cloned());
        self.object(id, Some(guid(parent)), class, &attrs)
    }

    pub fn user(
        &self,
        id: u32,
        parent: u32,
        sam: &str,
        extra: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        self.principal("user", id, parent, sam, extra)
    }

    pub fn computer(
        &self,
        id: u32,
        parent: u32,
        sam: &str,
        extra: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        self.principal("computer", id, parent, sam, extra)
    }

    pub fn group(
        &self,
        id: u32,
        parent: u32,
        sam: &str,
        group_type: i32,
        members: &[u32],
    ) -> NewObject {
        let mut extra = vec![("groupType", vec![int32(group_type)])];
        if !members.is_empty() {
            extra.push(("member", members.iter().map(|m| ref_to(*m)).collect()));
        }
        self.principal("group", id, parent, sam, &extra)
    }

    /// Create every object in one committed transaction.
    pub fn create_all(&self, objects: Vec<NewObject>) {
        let mut txn = self.store.begin_write().expect("begin write");
        for obj in objects {
            let origin = self.origin();
            txn.create_object(obj, &origin).expect("create");
        }
        txn.commit().expect("commit");
    }

    /// Replace the values of one attribute (empty = remove it).
    pub fn set(&self, id: u32, attr: &str, values: Vec<Vec<u8>>) {
        let mut txn = self.store.begin_write().expect("begin write");
        let origin = self.origin();
        txn.modify_object(
            guid(id),
            vec![AttributeChange::Replace {
                id: self.attr(attr),
                values,
            }],
            &origin,
        )
        .expect("modify");
        txn.commit().expect("commit");
    }

    /// A view with no tier entries.
    pub fn view(&self) -> DirectoryView<'_> {
        self.ctx.view(&self.store, &self.empty_tiers).expect("view")
    }

    /// A view with `tiers`.
    pub fn view_with<'a>(&'a self, tiers: &'a TierMap) -> DirectoryView<'a> {
        self.ctx.view(&self.store, tiers).expect("view")
    }
}
