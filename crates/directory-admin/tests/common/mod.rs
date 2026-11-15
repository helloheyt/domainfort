//! Shared fixtures: a temporary dirstore opened with the phase-1 schema and
//! a small domain provisioned the way `provision domain` (task A4) will —
//! one `WriteTxn` that creates the two counters (RID `[1101, 0x3FFFFFFF)`,
//! change-seq), takes every principal's RID and every write's change-seq
//! from them, and gives every object a descriptor computed by
//! CreateSecurityDescriptor from the root's — plus the tier map, the policy
//! and the write PEP under test.
//!
//! Sources of the shapes: docs/51 §4.3 step 5 (what provisioning creates:
//! NC root with the domain SID and the root SD, a Tier-0 OU, krbtgt with RID
//! 502 and UAC N, the DC account with ST, the service objects with one SPN,
//! the Tier-0 group with the first administrators, the bootstrap group),
//! §4.3 step 6 (the tier map and the write rules for the Tier-0 group), §10
//! (the root SD: owner and group the Tier-0 group, inheritable ACEs granting
//! the rights the operations need); docs/46 §4.4, §5.4 (musts and value
//! forms); docs/47 §1.3, §4 (an account's state). The SID layout
//! S-1-5-21-1-2-3-<RID> follows the [MS-DTYP] 2.4.2.4 example layout as
//! used throughout this project's tests. Names, RIDs and times are this
//! project's own test data; every time value is derived in a comment. No
//! vector or fixture comes from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

/// A fake auditd and the real audit client linked to a gate: the only way a
/// test obtains the proof `apply` takes (task R15b, docs/questions/Q-630).
#[path = "../../../ipc-audit/tests/linked/mod.rs"]
pub mod linked;

use core::time::Duration;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ad_schema::flags::user_account_control as uac;
use ad_schema::{phase1, Phase1Schema};
use directory_admin::{
    wall_clock, AdminConfig, Applied, DirectoryAdmin, Operation, Prepared, ProtectedObjects,
    RandomError, RandomSource, Refusal, Request, VerifiedTicket, CHANGE_SEQ_COUNTER, RID_COUNTER,
    RID_END_EXCLUSIVE, RID_FIRST,
};
use directory_pip::{DirectoryContext, DirectoryView, NamingContext, TierMap};
use dirstore::{AttrId, IntegrityKey, NewObject, NodeId, Object, Origin, Store, WriteTxn};
use dtyp::{
    ace_flags, create_security_descriptor, AccessMask, Ace, Acl, AutoInheritFlags, Control,
    GenericMapping, Guid, MaskSidAce, SecurityDescriptor, Sid, Token, ACL_REVISION_DS,
    SECURITY_NT_AUTHORITY,
};
use ipc_audit::{AckedIntent, DirAdminEvent};
use keyd_types::KeydConfig;
use krb_proto::constants::KRB_NT_PRINCIPAL;
use krb_proto::{KerberosString, KerberosTime, PrincipalName, Realm};
use pdp::access_check::rights::{
    RIGHT_DELETE, RIGHT_DS_CONTROL_ACCESS, RIGHT_DS_CREATE_CHILD, RIGHT_DS_DELETE_CHILD,
    RIGHT_DS_LIST_CONTENTS, RIGHT_DS_READ_PROPERTY, RIGHT_DS_WRITE_PROPERTY, RIGHT_READ_CONTROL,
};
use pdp::{
    ActionMatch, AuthMatch, ContextMatch, Dn, Effect, Match, PolicySnapshot, PolicyVersion,
    ResourceMatch, Rule, RuleId, SubjectMatch, SubtreeBase, Tier,
};

// ---------------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------------

/// The realm: the domain's DNS name in upper case (docs/47 §3.3 item 3).
pub const REALM: &str = "EXAMPLE.TEST";

/// The ticket-age threshold of the tests (R51-10: a parameter of the
/// configuration; this value is test data).
pub const TICKET_AGE_MAX: Duration = Duration::from_secs(600);

/// The dual-control quorum (P-22: the requester plus one approver).
pub const QUORUM: usize = 2;

/// This DC's node-id (test data; docs/29 §2 as cited in docs/51 §4.6).
pub const NODE_ID: NodeId = NodeId([0xA3; 16]);

/// The rights the root SD grants the Tier-0 group (and the helpdesk
/// group), inheritable: what the operations of docs/51 §5.2 need — create
/// and delete child, read and write property, delete, control access (for
/// User-Force-Change-Password), list, read control (docs/51 §10).
pub const ADMIN_RIGHTS: u32 = RIGHT_DS_CREATE_CHILD
    | RIGHT_DS_DELETE_CHILD
    | RIGHT_DS_READ_PROPERTY
    | RIGHT_DS_WRITE_PROPERTY
    | RIGHT_DELETE
    | RIGHT_DS_CONTROL_ACCESS
    | RIGHT_DS_LIST_CONTENTS
    | RIGHT_READ_CONTROL;

/// The rights the root SD grants the readers group: read property, list,
/// read control.
pub const READ_RIGHTS: u32 = RIGHT_DS_READ_PROPERTY | RIGHT_DS_LIST_CONTENTS | RIGHT_READ_CONTROL;

/// Small ids of the provisioned objects (GUID = `guid(id)`).
pub const ROOT: u32 = 1;
pub const TIER0_OU: u32 = 2;
pub const STAFF_OU: u32 = 3;
pub const MANAGED_OU: u32 = 4;
pub const HIDDEN_OU: u32 = 5;
pub const KRBTGT: u32 = 10;
pub const DC01: u32 = 11;
pub const LDAP_SVC: u32 = 12;
pub const ADMIND_SVC: u32 = 13;
pub const TIER0_GROUP: u32 = 20;
pub const HELPDESK: u32 = 21;
pub const READERS: u32 = 22;
pub const BOOTSTRAP: u32 = 23;
pub const ADMIN1: u32 = 30;
pub const ADMIN2: u32 = 31;
pub const HELPER: u32 = 32;
pub const BOB: u32 = 33;
pub const SECRET: u32 = 34;
pub const DISABLED: u32 = 35;
pub const ALICE: u32 = 36;
pub const WS01: u32 = 37;

/// The principals in the order provisioning takes their RIDs from the RID
/// counter (krbtgt is RID 502, [MS-SAMR] 2.2.1.14, and takes none).
pub const RID_ORDER: [u32; 15] = [
    TIER0_GROUP,
    HELPDESK,
    READERS,
    BOOTSTRAP,
    ADMIN1,
    ADMIN2,
    HELPER,
    BOB,
    SECRET,
    DISABLED,
    ALICE,
    WS01,
    DC01,
    LDAP_SVC,
    ADMIND_SVC,
];

/// The first RID the admin plane hands out after provisioning: 1101 plus
/// the fifteen RIDs provisioning took.
pub const FIRST_ADMIN_RID: u32 = 1101 + 15;

/// The provisioning time: 2026-11-01T00:00:00Z.
pub fn provisioned_at() -> KerberosTime {
    kt(2026, 11, 1, 0, 0, 0)
}

/// whenCreated of the provisioned objects: 2026-11-01T00:00:00Z as DSTIME
/// (seconds since 1601-01-01, [MS-DRSR] 5.51 as cited in docs/46 §8.1).
/// 1601-01-01 → 1970-01-01 = 134 774 days = 11 644 473 600 s; 1970-01-01 →
/// 2026-01-01 = 56 × 365 + 14 leap days = 20 454 days; January..October 2026
/// = 304 days; 20 758 days = 1 793 491 200 s. Total 13 437 964 800.
pub const PROVISIONED_DSTIME: i64 = 13_437_964_800;

/// The test "now": 2026-11-13T10:00:00Z.
pub fn now() -> KerberosTime {
    kt(2026, 11, 13, 10, 0, 0)
}

/// DSTIME of [`now`]: 20 758 + 12 = 20 770 days since 1970 = 1 794 528 000
/// s, + 10 h = 1 794 564 000 s, + 11 644 473 600 = 13 439 037 600.
pub const NOW_DSTIME: i64 = 13_439_037_600;

/// FILETIME of [`now`]: [`NOW_DSTIME`] × 10^7 ([MS-DTYP] 2.3.3 as cited in
/// docs/47 §4.2: 100-ns intervals since 1601).
pub const NOW_FILETIME: i64 = 134_390_376_000_000_000;

/// The authtime of every test ticket: one minute before [`now`].
pub fn authtime() -> KerberosTime {
    kt(2026, 11, 13, 9, 59, 0)
}

// ---------------------------------------------------------------------------
// Values.
// ---------------------------------------------------------------------------

/// KerberosTime shorthand.
pub fn kt(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
    KerberosTime::new(y, mo, d, h, mi, s).unwrap()
}

/// A distinct, non-NULL GUID per small integer.
pub fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0xD1,
        data3: 0x00A3,
        data4: [0xA, 3, 0xA, 3, 0xA, 3, 0xA, 3],
    }
}

/// S-1-5-21-1-2-3 ([MS-DTYP] 2.4.2.4 example layout).
pub fn domain_sid() -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3]).unwrap()
}

/// S-1-5-21-1-2-3-`rid`.
pub fn account_sid(rid: u32) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, rid]).unwrap()
}

/// The RID of a provisioned principal.
pub fn rid(id: u32) -> u32 {
    if id == KRBTGT {
        return 502;
    }
    let position = RID_ORDER
        .iter()
        .position(|p| *p == id)
        .expect("a principal");
    1101 + u32::try_from(position).unwrap()
}

/// The objectSid of a provisioned principal.
pub fn sid_of(id: u32) -> Sid {
    account_sid(rid(id))
}

pub fn realm() -> Realm {
    Realm::new(REALM).unwrap()
}

/// The naming context dc=example,dc=test (A-53).
pub fn naming_context() -> NamingContext {
    NamingContext::new(&["example", "test"]).unwrap()
}

/// A DN in the directory's canonical form, leaf first.
pub fn dn(rdns: &[&str]) -> Dn {
    Dn::new(rdns.iter().map(|s| (*s).to_owned()).collect())
}

/// The NC root's DN.
pub fn nc_dn() -> Dn {
    dn(&["dc=example", "dc=test"])
}

/// The DN of a provisioned OU directly below the root.
pub fn ou_dn(name: &str) -> Dn {
    dn(&[&format!("ou={name}"), "dc=example", "dc=test"])
}

/// A verified ticket of the account `sam`, first authenticated at
/// [`authtime`] (the facts keyd's `verify_operation_ticket` returns, Q-523).
pub fn ticket(sam: &str) -> VerifiedTicket {
    ticket_bound_to(sam, Some(TEST_DIGEST))
}

/// The operation digest every test request carries, and every test ticket
/// is bound to unless a test says otherwise: these PEP tests run without
/// keyd and without the channel codec, so the digest is a made-up value —
/// what matters to the PEP is that the tickets' verified binding equals the
/// request's digest (R2, docs/52 §5 item 4).
pub const TEST_DIGEST: keyd_types::OperationDigest = keyd_types::OperationDigest::new([0x0D; 32]);

/// A ticket of `sam` whose AP-REQ keyd verified bound to `bound` (R2).
pub fn ticket_bound_to(sam: &str, bound: Option<keyd_types::OperationDigest>) -> VerifiedTicket {
    VerifiedTicket {
        crealm: realm(),
        cname: PrincipalName {
            name_type: KRB_NT_PRINCIPAL,
            name_string: vec![KerberosString::new(sam).unwrap()],
        },
        authtime: authtime(),
        bound_operation: bound,
    }
}

/// Big-endian encodings (docs/46 §8.1).
pub fn int64(v: i64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}
pub fn flags(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}
pub fn ref_to(id: u32) -> Vec<u8> {
    guid(id).to_packet().to_vec()
}

/// An allow ACE with CONTAINER_INHERIT_ACE ([MS-DTYP] 2.4.4.1, 2.4.4.2).
pub fn inheritable_allow(mask: u32, sid: Sid) -> Ace {
    Ace::AccessAllowed(MaskSidAce {
        ace_flags: ace_flags::CONTAINER_INHERIT_ACE,
        mask: AccessMask(mask),
        sid,
    })
}

/// A self-relative SD with owner and group `owner` and `aces` as its DACL
/// ([MS-DTYP] 2.4.6).
pub fn sd_with(owner: Sid, aces: Vec<Ace>) -> SecurityDescriptor {
    SecurityDescriptor {
        sbz1: 0,
        control: Control(Control::SELF_RELATIVE | Control::DACL_PRESENT),
        owner_sid: Some(owner),
        group_sid: Some(owner),
        sacl: None,
        dacl: Some(Acl {
            acl_revision: ACL_REVISION_DS,
            aces,
        }),
    }
}

/// The root SD (docs/51 §10): owner = group = the Tier-0 group; inheritable
/// allows for the Tier-0 group and the helpdesk group (the operations'
/// rights) and for the readers group (read only).
pub fn root_sd() -> SecurityDescriptor {
    sd_with(
        sid_of(TIER0_GROUP),
        vec![
            inheritable_allow(ADMIN_RIGHTS, sid_of(TIER0_GROUP)),
            inheritable_allow(ADMIN_RIGHTS, sid_of(HELPDESK)),
            inheritable_allow(READ_RIGHTS, sid_of(READERS)),
        ],
    )
}

/// A child's SD, computed as provisioning computes it (CreateSecurityDescriptor
/// from the parent's, the Tier-0 group as the token's owner — docs/51 §10;
/// A-76; [MS-ADTS] 6.1.3 item 5 inputs).
pub fn child_sd(parent: &SecurityDescriptor, class_guid: Guid) -> SecurityDescriptor {
    create_security_descriptor(
        Some(parent),
        None,
        true,
        Some(&[class_guid]),
        AutoInheritFlags::default(),
        &Token {
            owner: sid_of(TIER0_GROUP),
            primary_group: sid_of(TIER0_GROUP),
            default_dacl: None,
        },
        &GenericMapping::ACTIVE_DIRECTORY,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// The deterministic random source (tests only — A-15).
// ---------------------------------------------------------------------------

/// Deterministic GUID packets: eight 0xA3 octets then a counter, so every
/// draw is non-NULL and distinct, and none equals a fixture GUID.
#[derive(Debug, Default)]
pub struct CountingRandom {
    next: u64,
}

impl RandomSource for CountingRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        self.next += 1;
        let mut bytes = [0xA3u8; 16];
        bytes[8..].copy_from_slice(&self.next.to_be_bytes());
        for (i, o) in out.iter_mut().enumerate() {
            *o = bytes[i % 16];
        }
        Ok(())
    }
}

/// The GUID the `n`-th draw of [`CountingRandom`] produces (n from 1).
pub fn drawn_guid(n: u64) -> Guid {
    let mut bytes = [0xA3u8; 16];
    bytes[8..].copy_from_slice(&n.to_be_bytes());
    Guid::from_packet(&bytes)
}

// ---------------------------------------------------------------------------
// The domain.
// ---------------------------------------------------------------------------

/// A per-test directory under cargo's integration-test scratch area.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(test_name: &str) -> TempDir {
        let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let dir = base.join(format!(
            "directory-admin-{test_name}-{}",
            std::process::id()
        ));
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

/// How one request ended.
#[derive(Debug)]
pub enum Ran {
    /// `prepare` refused it (a `Decision` refusal event).
    Refused(Refusal),
    /// An operation that commits nothing: the prepared reply.
    Read(Box<Prepared>),
    /// Applied and committed.
    Applied {
        decision: Box<DirAdminEvent>,
        applied: Box<Applied>,
    },
    /// `apply` refused it (an `Outcome` refusal event); the transaction was
    /// aborted.
    ApplyRefused {
        decision: Box<DirAdminEvent>,
        refusal: Refusal,
    },
}

impl Ran {
    pub fn refused(self) -> Refusal {
        match self {
            Ran::Refused(r) => r,
            other => panic!("expected a refusal from prepare, got {other:?}"),
        }
    }

    pub fn applied(self) -> (DirAdminEvent, Applied) {
        match self {
            Ran::Applied { decision, applied } => (*decision, *applied),
            other => panic!("expected an applied write, got {other:?}"),
        }
    }

    pub fn read(self) -> Prepared {
        match self {
            Ran::Read(p) => *p,
            other => panic!("expected a read-only operation, got {other:?}"),
        }
    }
}

/// The provisioned domain and the PEP under test.
pub struct Domain {
    pub p1: Phase1Schema,
    pub store: Store,
    pub ctx: DirectoryContext,
    pub tiers: TierMap,
    pub policy: PolicySnapshot,
    pub admin: DirectoryAdmin<CountingRandom>,
    next_op: Cell<u64>,
    _dir: TempDir,
}

/// One object of the provisioning plan.
struct Planned {
    id: u32,
    parent: Option<u32>,
    class: &'static str,
    attrs: Vec<(&'static str, Vec<Vec<u8>>)>,
    /// An explicit SD instead of the inherited one.
    sd: Option<SecurityDescriptor>,
}

impl Domain {
    /// The standard domain (module documentation):
    /// - dc=example (domainDNS, objectSid S-1-5-21-1-2-3, the root SD)
    ///   - ou=Tier0 (tier-map subtree Tier0): krbtgt (RID 502, UAC N),
    ///     dc01$ (ST), ldap-svc$ and admind-svc$ (WT, one SPN each — the
    ///     service objects), admin1 and admin2 (enabled users), group tier0
    ///     (global security: admin1, admin2; tier map Tier0)
    ///   - ou=Staff (unclassified): helper, bob, disabled (UAC N|D), alice,
    ///     ws01$ (WT, SPN host/ws01.example.test); groups helpdesk (global
    ///     security: helper; tier map Tier1), readers (global security:
    ///     helper, bob, disabled, alice), bootstrap (global security, empty;
    ///     the policy's bootstrap group)
    ///   - ou=Managed (tier-map subtree Tier1)
    ///   - ou=Hidden (an explicit SD granting the Tier-0 group only): secret
    pub fn new(test_name: &str) -> Domain {
        Domain::with_options(test_name, QUORUM, Some(RID_END_EXCLUSIVE))
    }

    /// The standard domain with another dual-control quorum.
    pub fn with_quorum(test_name: &str, quorum: usize) -> Domain {
        Domain::with_options(test_name, quorum, Some(RID_END_EXCLUSIVE))
    }

    /// The standard domain whose RID counter ends at `rid_end` (exclusive)
    /// instead of `0x3FFFFFFF` — to exhaust it.
    pub fn with_rid_end(test_name: &str, rid_end: u32) -> Domain {
        Domain::with_options(test_name, QUORUM, Some(u64::from(rid_end)))
    }

    /// The standard domain provisioned WITHOUT the two counters (a store
    /// `provision domain` did not finish — A-83: the admin plane never
    /// creates them).
    pub fn without_counters(test_name: &str) -> Domain {
        Domain::with_options(test_name, QUORUM, None)
    }

    fn with_options(test_name: &str, quorum: usize, rid_end: Option<u64>) -> Domain {
        let p1 = phase1().expect("phase-1 schema");
        let dir = TempDir::new(test_name);
        let store = Store::open(
            dir.0.join("store.redb"),
            IntegrityKey::from_bytes(&[0xA3; 32]),
            p1.schema().clone(),
        )
        .expect("open store");
        let ctx = DirectoryContext::new(p1.clone(), &KeydConfig::new(realm()), naming_context())
            .expect("context");
        let tiers = TierMap::new(
            BTreeMap::from([
                (sid_of(TIER0_GROUP), Tier::Tier0),
                (sid_of(HELPDESK), Tier::Tier1),
            ]),
            vec![
                (ou_dn("Tier0"), Tier::Tier0),
                (ou_dn("Managed"), Tier::Tier1),
            ],
        )
        .expect("tier map");
        let allow = |id: u32, action: ActionMatch, subject: SubjectMatch| Rule {
            id: RuleId(id),
            effect: Effect::Allow,
            when: Match {
                action,
                resource: ResourceMatch::DirSubtree {
                    base: SubtreeBase::new(nc_dn()).unwrap(),
                },
                subject,
                context: ContextMatch::ANY,
                auth: AuthMatch::ANY,
            },
            obligations: vec![],
        };
        let policy = PolicySnapshot::new(
            PolicyVersion(1),
            vec![
                allow(
                    1,
                    ActionMatch::Class(pdp::ActionClass::Directory),
                    SubjectMatch::MemberOf(sid_of(TIER0_GROUP)),
                ),
                allow(
                    2,
                    ActionMatch::Class(pdp::ActionClass::Directory),
                    SubjectMatch::MemberOf(sid_of(HELPDESK)),
                ),
                allow(
                    3,
                    ActionMatch::AnyOf(vec![pdp::Action::DirRead, pdp::Action::DirList]),
                    SubjectMatch::MemberOf(sid_of(READERS)),
                ),
            ],
            vec![],
        );
        let config = AdminConfig::new(
            TICKET_AGE_MAX,
            quorum,
            realm(),
            naming_context(),
            NODE_ID,
            ProtectedObjects {
                service_objects: BTreeSet::from([guid(LDAP_SVC), guid(ADMIND_SVC)]),
                policy_principals: BTreeSet::from([sid_of(BOOTSTRAP)]),
            },
        )
        .expect("config");
        let admin = DirectoryAdmin::new(config, &p1, CountingRandom::default()).expect("admin");
        let domain = Domain {
            p1,
            store,
            ctx,
            tiers,
            policy,
            admin,
            next_op: Cell::new(0),
            _dir: dir,
        };
        domain.provision(rid_end);
        domain
    }

    pub fn attr(&self, name: &str) -> AttrId {
        self.p1.attribute_by_name(name).expect(name)
    }

    pub fn class_guid(&self, name: &str) -> Guid {
        let id = self.p1.class_by_name(name).expect(name);
        self.p1.class(id).unwrap().schema_id_guid
    }

    /// The provisioning plan, parents before children, members before
    /// groups.
    fn plan(&self) -> Vec<Planned> {
        let text = |s: &str| vec![s.as_bytes().to_vec()];
        let account = |id: u32, sam: &str, uac_value: u32| {
            vec![
                ("cn", text(sam)),
                ("sAMAccountName", text(sam)),
                ("objectSid", vec![sid_of(id).encode()]),
                ("userAccountControl", vec![flags(uac_value)]),
                ("accountExpires", vec![int64(i64::MAX)]),
                // pwdLastSet = the provisioning time (docs/51 §4.3 step 5).
                ("pwdLastSet", vec![int64(PROVISIONED_DSTIME * 10_000_000)]),
                ("whenCreated", vec![int64(PROVISIONED_DSTIME)]),
            ]
        };
        let group = |id: u32, sam: &str, members: &[u32]| {
            let mut attrs = vec![
                ("cn", text(sam)),
                ("sAMAccountName", text(sam)),
                ("objectSid", vec![sid_of(id).encode()]),
                ("groupType", vec![flags(0x8000_0002)]),
            ];
            if !members.is_empty() {
                attrs.push(("member", members.iter().map(|m| ref_to(*m)).collect()));
            }
            attrs
        };
        let ou = |name: &str| vec![("ou", text(name))];
        let n = uac::ADS_UF_NORMAL_ACCOUNT;
        let wt = uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT;
        let service = |id: u32, sam: &str, spn: &str| {
            let mut attrs = account(id, sam, wt);
            attrs.retain(|(name, _)| *name != "pwdLastSet");
            attrs.push(("dNSHostName", text("dc01.example.test")));
            attrs.push(("servicePrincipalName", text(spn)));
            attrs
        };
        let planned = |id, parent, class, attrs| Planned {
            id,
            parent,
            class,
            attrs,
            sd: None,
        };
        let mut krbtgt = account(KRBTGT, "krbtgt", n);
        krbtgt.retain(|(name, _)| *name != "pwdLastSet");
        let mut dc01 = account(DC01, "dc01$", uac::ADS_UF_SERVER_TRUST_ACCOUNT);
        dc01.retain(|(name, _)| *name != "pwdLastSet");
        dc01.push(("dNSHostName", text("dc01.example.test")));
        let mut ws01 = account(WS01, "ws01$", wt);
        ws01[0] = ("cn", text("ws01"));
        ws01.push(("dNSHostName", text("ws01.example.test")));
        ws01.push(("servicePrincipalName", text("host/ws01.example.test")));
        vec![
            Planned {
                id: ROOT,
                parent: None,
                class: "domainDNS",
                attrs: vec![
                    ("dc", text("example")),
                    ("objectSid", vec![domain_sid().encode()]),
                ],
                sd: Some(root_sd()),
            },
            planned(TIER0_OU, Some(ROOT), "organizationalUnit", ou("Tier0")),
            planned(STAFF_OU, Some(ROOT), "organizationalUnit", ou("Staff")),
            planned(MANAGED_OU, Some(ROOT), "organizationalUnit", ou("Managed")),
            Planned {
                id: HIDDEN_OU,
                parent: Some(ROOT),
                class: "organizationalUnit",
                attrs: ou("Hidden"),
                sd: Some(sd_with(
                    sid_of(TIER0_GROUP),
                    vec![inheritable_allow(ADMIN_RIGHTS, sid_of(TIER0_GROUP))],
                )),
            },
            planned(KRBTGT, Some(TIER0_OU), "user", krbtgt),
            planned(DC01, Some(TIER0_OU), "computer", dc01),
            planned(
                LDAP_SVC,
                Some(TIER0_OU),
                "computer",
                service(LDAP_SVC, "ldap-svc$", "ldap/dc01.example.test"),
            ),
            planned(
                ADMIND_SVC,
                Some(TIER0_OU),
                "computer",
                service(ADMIND_SVC, "admind-svc$", "admind/dc01.example.test"),
            ),
            planned(ADMIN1, Some(TIER0_OU), "user", account(ADMIN1, "admin1", n)),
            planned(ADMIN2, Some(TIER0_OU), "user", account(ADMIN2, "admin2", n)),
            planned(HELPER, Some(STAFF_OU), "user", account(HELPER, "helper", n)),
            planned(BOB, Some(STAFF_OU), "user", account(BOB, "bob", n)),
            planned(
                DISABLED,
                Some(STAFF_OU),
                "user",
                account(DISABLED, "disabled", n | uac::ADS_UF_ACCOUNT_DISABLE),
            ),
            planned(ALICE, Some(STAFF_OU), "user", account(ALICE, "alice", n)),
            planned(WS01, Some(STAFF_OU), "computer", ws01),
            planned(
                SECRET,
                Some(HIDDEN_OU),
                "user",
                account(SECRET, "secret", n),
            ),
            planned(
                TIER0_GROUP,
                Some(TIER0_OU),
                "group",
                group(TIER0_GROUP, "tier0", &[ADMIN1, ADMIN2]),
            ),
            planned(
                HELPDESK,
                Some(STAFF_OU),
                "group",
                group(HELPDESK, "helpdesk", &[HELPER]),
            ),
            planned(
                READERS,
                Some(STAFF_OU),
                "group",
                group(READERS, "readers", &[HELPER, BOB, DISABLED, ALICE]),
            ),
            planned(
                BOOTSTRAP,
                Some(STAFF_OU),
                "group",
                group(BOOTSTRAP, "bootstrap", &[]),
            ),
        ]
    }

    /// Provision the domain in ONE transaction (module documentation).
    fn provision(&self, rid_end: Option<u64>) {
        let mut txn = self.store.begin_write().expect("begin write");
        if let Some(rid_end) = rid_end {
            txn.create_counter(RID_COUNTER, RID_FIRST, rid_end)
                .expect("rid counter");
            txn.create_counter(CHANGE_SEQ_COUNTER, 1, u64::MAX)
                .expect("change-seq counter");
            for id in RID_ORDER {
                let taken = txn.take_counter_value(RID_COUNTER).expect("rid");
                assert_eq!(taken, u64::from(rid(id)));
            }
        }
        let mut sds: BTreeMap<u32, SecurityDescriptor> = BTreeMap::new();
        for (index, planned) in self.plan().into_iter().enumerate() {
            let class_id = self.p1.class_by_name(planned.class).expect(planned.class);
            let class = self.p1.class(class_id).unwrap();
            let sd = match planned.sd {
                Some(sd) => sd,
                None => child_sd(&sds[&planned.parent.unwrap()], class.schema_id_guid),
            };
            let mut attributes: Vec<(AttrId, Vec<Vec<u8>>)> = planned
                .attrs
                .iter()
                .map(|(name, values)| (self.attr(name), values.clone()))
                .collect();
            attributes.push((
                self.attr("nTSecurityDescriptor"),
                vec![sd.encode().unwrap()],
            ));
            let origin = if rid_end.is_some() {
                self.provision_origin(&mut txn)
            } else {
                Origin {
                    wall_clock: wall_clock(&provisioned_at()).unwrap(),
                    origin_node: NODE_ID,
                    origin_seq: u64::try_from(index).unwrap() + 1,
                }
            };
            txn.create_object(
                NewObject {
                    guid: guid(planned.id),
                    parent: planned.parent.map(guid),
                    classes: class.object_class.clone(),
                    attributes,
                },
                &origin,
            )
            .unwrap_or_else(|e| panic!("create {}: {e:?}", planned.id));
            sds.insert(planned.id, sd);
        }
        txn.commit().expect("commit");
    }

    fn provision_origin(&self, txn: &mut WriteTxn<'_>) -> Origin {
        Origin {
            wall_clock: wall_clock(&provisioned_at()).unwrap(),
            origin_node: NODE_ID,
            origin_seq: txn.take_counter_value(CHANGE_SEQ_COUNTER).unwrap(),
        }
    }

    /// A view of the committed state with the domain's tier map.
    pub fn view(&self) -> DirectoryView<'_> {
        self.ctx.view(&self.store, &self.tiers).expect("view")
    }

    /// A live object, read from a fresh snapshot.
    pub fn object(&self, g: Guid) -> Option<Object> {
        self.store.snapshot().unwrap().get_object(g).unwrap()
    }

    /// The next value the counter `name` would hand out.
    pub fn counter_next(&self, name: &str) -> u64 {
        self.store
            .snapshot()
            .unwrap()
            .counter(name)
            .unwrap()
            .unwrap()
            .next_value
    }

    /// A request by `requester` with `approvers`.
    pub fn request(&self, op: Operation, requester: &str, approvers: &[&str]) -> Request {
        let id = self.next_op.get() + 1;
        self.next_op.set(id);
        Request {
            operation_id: id,
            operation: op,
            operation_digest: TEST_DIGEST,
            requester: ticket(requester),
            approvals: approvers.iter().map(|a| ticket(a)).collect(),
        }
    }

    /// Run `op` end to end at [`now`]: begin the `WriteTxn`, take the view,
    /// prepare, then apply and commit (or abort on a refusal).
    pub fn run(&mut self, op: Operation, requester: &str, approvers: &[&str]) -> Ran {
        let request = self.request(op, requester, approvers);
        self.run_request(&request)
    }

    pub fn run_request(&mut self, request: &Request) -> Ran {
        let mut txn = self.store.begin_write().expect("begin write");
        let view = self.ctx.view(&self.store, &self.tiers).expect("view");
        let prepared = match self.admin.prepare(request, &view, &self.policy, &now()) {
            Ok(p) => p,
            Err(r) => return Ran::Refused(r),
        };
        drop(view);
        if !prepared.writes() {
            return Ran::Read(Box::new(prepared));
        }
        let decision = Box::new(prepared.decision_event().clone());
        match self.admin.apply(acknowledged(prepared), &mut txn, &now()) {
            Ok(applied) => {
                txn.commit().expect("commit");
                Ran::Applied {
                    decision,
                    applied: Box::new(applied),
                }
            }
            Err(refusal) => {
                txn.abort().expect("abort");
                Ran::ApplyRefused { decision, refusal }
            }
        }
    }
}

/// Play auditd for one prepared write (docs/51 §5.7 item 2, A-85; docs/52
/// §3.11 R6): commit its decision event into an `ipc_audit::AuditGate`
/// attached to the real audit client, which delivers it to a fake auditd
/// that acknowledges it as auditd does once it synced it (docs/50 §8.1),
/// and take the proof `apply` requires. The only way the tests obtain one is
/// the way dird does: through the client and the gate, after the
/// acknowledgement (task R15b — nothing else can acknowledge).
pub fn acknowledged(prepared: Prepared) -> AckedIntent<Prepared> {
    linked::acknowledged(prepared)
}
