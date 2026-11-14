//! Tier-2 support for admind (docs/50 §9: "real servers run in the test's
//! threads; Unix sockets in a unique temporary directory (0700); the uid map
//! is injected with the test's own uid for the role under test").
//!
//! The world of one test, all in this process over real sockets:
//!
//! * **auditd** — crates/audit-daemon's listener and writer (its tier-2
//!   harness, reused through `#[path]`), the test's uid mapped to the
//!   `admind` source, so the production binding table accepts admind's
//!   `Admind` events; they are read back from the verified log.
//! * **keyd** — crates/keyd-daemon's real daemon holding the admin
//!   service's key set `(admind-svc$, AdminService)` (R2), created by `create_key`
//!   from scripted test entropy so the test knows the key. On its socket
//!   the test's uid is **Role::Ldap**: dird verifies the administrators'
//!   AP-REQs through it (A-73) and registers the set_secret grant of every
//!   `BeginPasswordSet` (task A15a). On a **second socket of the same
//!   keyd** (`kd.sock`; keyd-daemon `ExtraListener`, tests only —
//!   docs/questions/Q-453) the test's uid is **Role::Directory**: admind's
//!   `set_secret` goes there (A-57) and is checked against the very grant
//!   table dird's grant went into. (One uid has one role per map, R50-3;
//!   before task A15a the harness ran two keyds, which a grant cannot
//!   cross.) Or, by option, `kd.sock` maps the uid to Admin (keyd refuses
//!   `set_secret`), or `kd.sock` is a silent server that accepts and never
//!   answers.
//! * **dird** — crates/directory-daemon's `serve_with_admin` with its admin
//!   service over a provisioned directory, its own fake auditd recording the
//!   `DirAdmin` events (crates/keyd-daemon's tier-2 `FakeAuditd`). In the
//!   recording-dird mode the same keyd runs (without the admin service's
//!   key set), and the recording dird registers bob's grant as dird would.
//! * **admind** — `admin_daemon::serve` on its own thread, its dird and keyd
//!   clients built from this crate's public `DirdLink` / `KeydLink` with the
//!   connectors of the host (Linux: the production connectors; elsewhere a
//!   connector that reads the server's uid through tokio
//!   `UnixStream::peer_cred`, as crates/directory-daemon's tests do).
//!
//! The AP-REQs are built here, as crates/directory-daemon's tier-2 tests
//! build them (accepted for tier 2 in A-91): the service ticket sealed under
//! the admin service key (RFC 4120 §5.3, key usage 2), the authenticator
//! under the session key (§5.5.1, key usage 11), with krb-crypto (a
//! dev-dependency) and the kdc integration fixtures.
//!
//! Sources: docs/51 §4.3, §5.2, §5.3, §7; docs/50 §3, §9; docs/47 §9.1;
//! RFC 4120 §3.2.3, §5.3, §5.5.1, §7.5.1; [MS-SAMR] 2.2.1.14; [MS-DTYP]
//! 2.4.2.4. Every value is constructed by hand for these tests (the times
//! are those of the kdc fixtures); no vector comes from any other
//! implementation.
#![allow(dead_code, unused_imports)]

#[path = "../../../kdc/tests/common/mod.rs"]
pub mod common;

#[path = "../../../directory-daemon/tests/support/mod.rs"]
pub mod dird;

#[path = "../../../audit-daemon/tests/common/mod.rs"]
pub mod auditd;

use ad_schema::flags::user_account_control as uac;
use ad_schema::{phase1, Phase1Schema};
use admin_daemon::{
    serve, AuditEndpoint, DaemonControl, DaemonParams, DirdLink, KeydLink, Limits,
    WORKER_QUEUE_CAPACITY,
};
use audit_daemon::listener::ListenerConfig;
use audit_log::Anchor;
use core::time::Duration;
use directory_admin::{wall_clock, CHANGE_SEQ_COUNTER, RID_COUNTER, RID_END_EXCLUSIVE, RID_FIRST};
use directory_daemon::policy::{DevelopmentPolicy, MandatoryFast};
use directory_daemon::{
    serve_with_admin, AdminParams, Clock, DaemonControl as DirdControl, DecisionAckDeadline,
    KeydTicketVerifier, SharedClock, StoreSource, TicketVerifier, VerifierFactory,
};
use dirstore::{AttrId, IntegrityKey, NewObject, NodeId, Origin, Store, WriteTxn};
use dtyp::{
    ace_flags, create_security_descriptor, AccessMask, Ace, Acl, AutoInheritFlags, Control,
    GenericMapping, Guid, MaskSidAce, SecurityDescriptor, Sid, Token, ACL_REVISION_DS,
    SECURITY_NT_AUTHORITY,
};
use ipc::{FrameReader, Refused};
use ipc_audit::{AdmindEvent, DirAdminEvent, EventBody, KeydRecord};
use ipc_dird_admin::Operation;
use keyd::{InMemoryKeyStore, Keyd, Role};
use keyd_daemon::{CallerMap, ExtraListener, RecordBuffer};
use krb_crypto::ProtocolKey;
use krb_proto::constants::{DOMAIN_X500_COMPRESS, KRB_NT_PRINCIPAL};
use krb_proto::{
    ApOptions, ApReq, Authenticator, EncTicketPart, EncryptedData, EncryptionKey, KerberosTime,
    KeyValue, Microseconds, PrincipalName, Ticket, TicketFlags, TransitedEncoding,
};
use pdp::access_check::rights::{
    RIGHT_DELETE, RIGHT_DS_CONTROL_ACCESS, RIGHT_DS_CREATE_CHILD, RIGHT_DS_DELETE_CHILD,
    RIGHT_DS_LIST_CONTENTS, RIGHT_DS_READ_PROPERTY, RIGHT_DS_WRITE_PROPERTY, RIGHT_READ_CONTROL,
};
use pdp::{
    ActionMatch, AuthMatch, ContextMatch, Dn, Effect, Match, PolicyVersion, ResourceMatch, Rule,
    RuleId, SubjectMatch, SubtreeBase, Tier,
};
use provision_manifest::{Manifest, ManifestFields};
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

pub use dird::{eventually, my_uid, skip_as_root, FakeAuditd, TempDir, TestClock};

// ---------------------------------------------------------------------------
// The domain (test data).
// ---------------------------------------------------------------------------

/// The DC's host name (dird's `dns_host_name` in the support `params`).
pub const DC_FQDN: &str = "dc1.example.org";

/// The admin service's key (scripted into keyd's `create_key`).
pub const ADMIN_SERVICE_KEY: [u8; 32] = [0xA9; 32];

/// The session key of the test tickets.
pub const SESSION_KEY: [u8; 32] = [0x5E; 32];

/// dird's node-id (test data).
pub const NODE_ID: NodeId = NodeId([0xA9; 16]);

pub const ROOT: u32 = 1;
pub const TIER0_OU: u32 = 2;
pub const STAFF_OU: u32 = 3;
pub const KRBTGT: u32 = 10;
pub const LDAP_SVC: u32 = 11;
pub const ADMIND_SVC: u32 = 12;
pub const ADMIN1: u32 = 13;
pub const ADMIN2: u32 = 14;
pub const TIER0_GROUP: u32 = 20;
pub const BOOTSTRAP: u32 = 21;
pub const BOB: u32 = 30;
pub const STAFF_GROUP: u32 = 31;
pub const WS9: u32 = 32;
pub const JO: u32 = 33;

/// The principals in the order provisioning takes their RIDs (krbtgt is
/// RID 502 and takes none).
const RID_ORDER: [u32; 10] = [
    TIER0_GROUP,
    BOOTSTRAP,
    ADMIN1,
    ADMIN2,
    BOB,
    STAFF_GROUP,
    LDAP_SVC,
    ADMIND_SVC,
    WS9,
    JO,
];

/// whenCreated / pwdLastSet: 2026-11-01T00:00:00Z as DSTIME (derivation in
/// crates/directory-admin tests/common `PROVISIONED_DSTIME`).
const PROVISIONED_DSTIME: i64 = 13_437_964_800;

/// A distinct, non-NULL GUID per small integer (test data).
pub fn g(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0xA9,
        data3: 0x00AD,
        data4: [0xA, 9, 0xA, 9, 0xA, 9, 0xA, 9],
    }
}

/// S-1-5-21-7-8-9 ([MS-DTYP] 2.4.2.4 layout).
pub fn domain_sid() -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 7, 8, 9]).unwrap()
}

pub fn rid(id: u32) -> u32 {
    if id == KRBTGT {
        return 502;
    }
    let position = RID_ORDER.iter().position(|p| *p == id).unwrap();
    1101 + u32::try_from(position).unwrap()
}

pub fn sid_of(id: u32) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 7, 8, 9, rid(id)]).unwrap()
}

fn dn(rdns: &[&str]) -> Dn {
    Dn::new(rdns.iter().map(|s| (*s).to_owned()).collect())
}

fn nc_dn() -> Dn {
    dn(&["dc=example", "dc=org"])
}

/// The rights the root SD grants the Tier-0 group, inheritable (docs/51
/// §10): the rights the operations of §5.2 need.
const ADMIN_RIGHTS: u32 = RIGHT_DS_CREATE_CHILD
    | RIGHT_DS_DELETE_CHILD
    | RIGHT_DS_READ_PROPERTY
    | RIGHT_DS_WRITE_PROPERTY
    | RIGHT_DELETE
    | RIGHT_DS_CONTROL_ACCESS
    | RIGHT_DS_LIST_CONTENTS
    | RIGHT_READ_CONTROL;

fn root_sd() -> SecurityDescriptor {
    SecurityDescriptor {
        sbz1: 0,
        control: Control(Control::SELF_RELATIVE | Control::DACL_PRESENT),
        owner_sid: Some(sid_of(TIER0_GROUP)),
        group_sid: Some(sid_of(TIER0_GROUP)),
        sacl: None,
        dacl: Some(Acl {
            acl_revision: ACL_REVISION_DS,
            aces: vec![Ace::AccessAllowed(MaskSidAce {
                ace_flags: ace_flags::CONTAINER_INHERIT_ACE,
                mask: AccessMask(ADMIN_RIGHTS),
                sid: sid_of(TIER0_GROUP),
            })],
        }),
    }
}

/// A child's SD as provisioning computes it ([MS-DTYP] 2.5.3.4 through
/// dtyp, A-84).
fn child_sd(parent: &SecurityDescriptor, class_guid: Guid) -> SecurityDescriptor {
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

struct Planned {
    id: u32,
    parent: Option<u32>,
    class: &'static str,
    attrs: Vec<(&'static str, Vec<Vec<u8>>)>,
}

fn text(s: &str) -> Vec<Vec<u8>> {
    vec![s.as_bytes().to_vec()]
}

fn int64(v: i64) -> Vec<Vec<u8>> {
    vec![v.to_be_bytes().to_vec()]
}

fn flags(v: u32) -> Vec<Vec<u8>> {
    vec![v.to_be_bytes().to_vec()]
}

/// The plan: the shape docs/51 §4.3 step 5 gives `provision domain`
/// (parents first, members before groups), plus the accounts these tests
/// set passwords for: bob (a user), ws9$ (a computer with one SPN) and jo
/// (a user whose sAMAccountName has two characters).
fn plan() -> Vec<Planned> {
    let account = |id: u32, sam: &str, uac_value: u32, password: bool| {
        let mut attrs = vec![
            ("cn", text(sam)),
            ("sAMAccountName", text(sam)),
            ("objectSid", vec![sid_of(id).encode()]),
            ("userAccountControl", flags(uac_value)),
            ("accountExpires", int64(i64::MAX)),
            ("whenCreated", int64(PROVISIONED_DSTIME)),
        ];
        if password {
            attrs.push(("pwdLastSet", int64(PROVISIONED_DSTIME * 10_000_000)));
        }
        attrs
    };
    let computer = |id: u32, sam: &str, host: &str, spn: &str| {
        let mut attrs = account(id, sam, uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT, false);
        attrs.push(("dNSHostName", text(host)));
        attrs.push(("servicePrincipalName", text(spn)));
        attrs
    };
    let group = |id: u32, sam: &str, members: &[u32]| {
        let mut attrs = vec![
            ("cn", text(sam)),
            ("sAMAccountName", text(sam)),
            ("objectSid", vec![sid_of(id).encode()]),
            ("groupType", flags(0x8000_0002)),
        ];
        if !members.is_empty() {
            attrs.push((
                "member",
                members.iter().map(|m| g(*m).to_packet().to_vec()).collect(),
            ));
        }
        attrs
    };
    let n = uac::ADS_UF_NORMAL_ACCOUNT;
    let p = |id, parent, class, attrs| Planned {
        id,
        parent,
        class,
        attrs,
    };
    vec![
        p(
            ROOT,
            None,
            "domainDNS",
            vec![
                ("dc", text("example")),
                ("objectSid", vec![domain_sid().encode()]),
            ],
        ),
        p(
            TIER0_OU,
            Some(ROOT),
            "organizationalUnit",
            vec![("ou", text("Tier0"))],
        ),
        p(
            STAFF_OU,
            Some(ROOT),
            "organizationalUnit",
            vec![("ou", text("Staff"))],
        ),
        p(
            KRBTGT,
            Some(TIER0_OU),
            "user",
            account(KRBTGT, "krbtgt", n, false),
        ),
        p(
            LDAP_SVC,
            Some(TIER0_OU),
            "computer",
            computer(LDAP_SVC, "ldap-svc$", DC_FQDN, "ldap/dc1.example.org"),
        ),
        p(
            ADMIND_SVC,
            Some(TIER0_OU),
            "computer",
            computer(ADMIND_SVC, "admind-svc$", DC_FQDN, "admind/dc1.example.org"),
        ),
        p(
            ADMIN1,
            Some(TIER0_OU),
            "user",
            account(ADMIN1, "admin1", n, true),
        ),
        p(
            ADMIN2,
            Some(TIER0_OU),
            "user",
            account(ADMIN2, "admin2", n, true),
        ),
        p(BOB, Some(STAFF_OU), "user", account(BOB, "bob", n, true)),
        p(
            WS9,
            Some(STAFF_OU),
            "computer",
            computer(WS9, "ws9$", "ws9.example.org", "host/ws9.example.org"),
        ),
        p(JO, Some(STAFF_OU), "user", account(JO, "jo", n, true)),
        p(
            TIER0_GROUP,
            Some(TIER0_OU),
            "group",
            group(TIER0_GROUP, "tier0", &[ADMIN1, ADMIN2]),
        ),
        p(
            BOOTSTRAP,
            Some(STAFF_OU),
            "group",
            group(BOOTSTRAP, "bootstrap", &[]),
        ),
        p(
            STAFF_GROUP,
            Some(STAFF_OU),
            "group",
            group(STAFF_GROUP, "staff", &[]),
        ),
    ]
}

fn provisioned_at() -> KerberosTime {
    common::kt("20261101000000Z")
}

fn origin(txn: &mut WriteTxn<'_>) -> Origin {
    Origin {
        wall_clock: wall_clock(&provisioned_at()).unwrap(),
        origin_node: NODE_ID,
        origin_seq: txn.take_counter_value(CHANGE_SEQ_COUNTER).unwrap(),
    }
}

/// Provision the directory in ONE transaction, with the two counters
/// (docs/51 §4.3 step 5, §8.3; A-83).
pub fn provision(path: &Path) -> Arc<Store> {
    let p1: Phase1Schema = phase1().unwrap();
    let store = Store::open(
        path,
        IntegrityKey::from_bytes(&dird::TEST_KEY),
        p1.schema().clone(),
    )
    .unwrap();
    let attr = |name: &str| -> AttrId { p1.attribute_by_name(name).unwrap() };
    let mut txn = store.begin_write().unwrap();
    txn.create_counter(RID_COUNTER, RID_FIRST, RID_END_EXCLUSIVE)
        .unwrap();
    txn.create_counter(CHANGE_SEQ_COUNTER, 1, u64::MAX).unwrap();
    for id in RID_ORDER {
        assert_eq!(
            txn.take_counter_value(RID_COUNTER).unwrap(),
            u64::from(rid(id))
        );
    }
    let mut sds: BTreeMap<u32, SecurityDescriptor> = BTreeMap::new();
    for planned in plan() {
        let class_id = p1.class_by_name(planned.class).unwrap();
        let class = p1.class(class_id).unwrap();
        let sd = match planned.parent {
            None => root_sd(),
            Some(parent) => child_sd(&sds[&parent], class.schema_id_guid),
        };
        let mut attributes: Vec<(AttrId, Vec<Vec<u8>>)> = planned
            .attrs
            .iter()
            .map(|(name, values)| (attr(name), values.clone()))
            .collect();
        attributes.push((attr("nTSecurityDescriptor"), vec![sd.encode().unwrap()]));
        let origin = origin(&mut txn);
        txn.create_object(
            NewObject {
                guid: g(planned.id),
                parent: planned.parent.map(g),
                classes: class.object_class.clone(),
                attributes,
            },
            &origin,
        )
        .unwrap();
        sds.insert(planned.id, sd);
    }
    txn.commit().unwrap();
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    Arc::new(store)
}

/// The policy: tier map {tier0 group → Tier0}, {ou=Tier0 → Tier0}; the
/// Tier-0 group may run every Directory action under the NC root and
/// `PolicyAdmin` on every policy scope (the key operations' `keys` scope
/// included — the rule `provision domain` writes, task A10, Q-420); the
/// bootstrap group is the FAST bootstrap set (docs/51 §4.3 step 6).
pub fn policy() -> DevelopmentPolicy {
    DevelopmentPolicy {
        version: PolicyVersion(1),
        principals: BTreeMap::from([(sid_of(TIER0_GROUP), Tier::Tier0)]),
        subtrees: vec![(dn(&["ou=Tier0", "dc=example", "dc=org"]), Tier::Tier0)],
        mandatory_fast: MandatoryFast {
            bootstrap_group: sid_of(BOOTSTRAP),
            first_rule_id: RuleId(100),
        },
        rules: vec![
            Rule {
                id: RuleId(1),
                effect: Effect::Allow,
                when: Match {
                    action: ActionMatch::Class(pdp::ActionClass::Directory),
                    resource: ResourceMatch::DirSubtree {
                        base: SubtreeBase::new(nc_dn()).unwrap(),
                    },
                    subject: SubjectMatch::MemberOf(sid_of(TIER0_GROUP)),
                    context: ContextMatch::ANY,
                    auth: AuthMatch::ANY,
                },
                obligations: vec![],
            },
            Rule {
                id: RuleId(2),
                effect: Effect::Allow,
                when: Match {
                    action: ActionMatch::Exact(pdp::Action::PolicyAdmin),
                    resource: ResourceMatch::Policy { scope: None },
                    subject: SubjectMatch::MemberOf(sid_of(TIER0_GROUP)),
                    context: ContextMatch::ANY,
                    auth: AuthMatch::ANY,
                },
                obligations: vec![],
            },
        ],
        anonymous: Vec::new(),
    }
}

/// The provisioning manifest of the domain (docs/51 §4.3 step 8).
pub fn manifest() -> Manifest {
    Manifest::new(&ManifestFields {
        realm: String::from(dird::REALM),
        domain_sid: domain_sid(),
        naming_context: vec![String::from("example"), String::from("org")],
        dc_fqdn: String::from(DC_FQDN),
        krbtgt: g(KRBTGT),
        ldap_service: g(LDAP_SVC),
        admin_service: g(ADMIND_SVC),
        first_admins: vec![
            (g(ADMIN1), String::from("admin1")),
            (g(ADMIN2), String::from("admin2")),
        ],
        // Required since A-105 (Q-473); obviously fake — these tests read
        // the manifest's service objects only.
        first_admin_salts: vec![
            String::from("test-salt-admin1"),
            String::from("test-salt-admin2"),
        ],
    })
    .unwrap()
}

// ---------------------------------------------------------------------------
// The Kerberos side (RFC 4120 §5.3, §5.5.1).
// ---------------------------------------------------------------------------

fn admin_service_key() -> ProtocolKey {
    common::aes256(&ADMIN_SERVICE_KEY)
}

/// When every test ticket was first authenticated: one minute before the
/// kdc fixtures' `now`.
fn authtime() -> KerberosTime {
    common::kt("20261113095900Z")
}

pub fn principal(sam: &str) -> PrincipalName {
    common::name(KRB_NT_PRINCIPAL, &[sam])
}

/// An AP-REQ of `sam` for the admin service: the ticket sealed under the
/// admin service key (usage 2); the authenticator at `now` with `cusec`,
/// under the session key (usage 11), its `cksum` — when `bound` is given —
/// the session key's MIC over `bound` (key usage 10, the session key's
/// required checksum type; R2: the operation digest of the dird request it
/// accompanies).
/// Spec: RFC 4120 §4, §5.3, §5.5.1, §7.5.1; RFC 3961 §3; docs/52 §5.
fn ap_req(sam: &str, cusec: u32, bound: Option<&[u8]>) -> Vec<u8> {
    let part = EncTicketPart {
        flags: TicketFlags::PRE_AUTHENT,
        key: EncryptionKey {
            keytype: common::AES256,
            keyvalue: KeyValue::from_slice(&SESSION_KEY),
        },
        crealm: common::realm(),
        cname: principal(sam),
        transited: TransitedEncoding {
            tr_type: DOMAIN_X500_COMPRESS,
            contents: Vec::new(),
        },
        authtime: authtime(),
        starttime: Some(authtime()),
        endtime: common::kt("20261113170000Z"),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let plain = part.encode().unwrap();
    let key = admin_service_key();
    let ticket = Ticket {
        realm: common::realm(),
        sname: manifest().admin_service().binding.name.clone(),
        enc_part: EncryptedData {
            etype: key.enc_type().number(),
            kvno: None,
            cipher: krb_crypto::encrypt(&key, common::usage(2), &[0x88; 16], &plain).unwrap(),
        },
    };
    let session = common::aes256(&SESSION_KEY);
    let cksumtype = session.enc_type().checksum_type();
    let cksum = bound.map(|data| krb_proto::Checksum {
        cksumtype: cksumtype.number(),
        checksum: krb_crypto::get_mic(&session, cksumtype, common::usage(10), data).unwrap(),
    });
    let authenticator = Authenticator {
        crealm: common::realm(),
        cname: principal(sam),
        cksum,
        cusec: Microseconds::new(cusec).unwrap(),
        ctime: common::now(),
        subkey: None,
        seq_number: None,
        authorization_data: None,
    }
    .encode()
    .unwrap();
    ApReq {
        ap_options: ApOptions::empty(),
        ticket,
        authenticator: EncryptedData {
            etype: session.enc_type().number(),
            kvno: None,
            cipher: krb_crypto::encrypt(&session, common::usage(11), &[0x77; 16], &authenticator)
                .unwrap(),
        },
    }
    .encode()
    .unwrap()
}

/// A fresh cusec for every AP-REQ (keyd's replay cache, RFC 4120 §3.2.3).
static CUSEC: AtomicU32 = AtomicU32::new(1);

/// A fresh AP-REQ of `sam` bound to the dird request `operation` (R2).
pub fn fresh(sam: &str, operation: &ipc_dird_admin::Operation) -> Vec<u8> {
    let digest = ipc_dird_admin::operation_digest(operation).unwrap();
    ap_req(
        sam,
        CUSEC.fetch_add(1, Ordering::SeqCst),
        Some(digest.as_bytes()),
    )
}

/// A fresh AP-REQ of `sam` with no `cksum` (an admin ticket bound to no
/// operation).
pub fn fresh_unbound(sam: &str) -> Vec<u8> {
    ap_req(sam, CUSEC.fetch_add(1, Ordering::SeqCst), None)
}

/// The auth field of `operation` by `requester` with `approvers`, every
/// AP-REQ bound to it (R2).
pub fn auth(
    requester: &str,
    approvers: &[&str],
    operation: &ipc_dird_admin::Operation,
) -> ipc_dird_admin::Auth {
    ipc_dird_admin::Auth {
        requester: fresh(requester, operation),
        approvals: approvers.iter().map(|a| fresh(a, operation)).collect(),
    }
}

/// A `Forward` of `operation` by `requester` with `approvers`.
pub fn forward(
    requester: &str,
    approvers: &[&str],
    operation: ipc_dird_admin::Operation,
) -> ipc_admin::Request {
    ipc_admin::Request::Forward {
        auth: auth(requester, approvers, &operation),
        operation,
    }
}

/// The `auth` of a `SetPassword` of `target`: bound to the
/// `BeginPasswordSet {target}` admind sends dird (docs/51 §7.6; R2).
pub fn begin_auth(requester: &str, approvers: &[&str], target: dtyp::Guid) -> ipc_dird_admin::Auth {
    auth(
        requester,
        approvers,
        &ipc_dird_admin::Operation::BeginPasswordSet { target },
    )
}

/// The `completion` AP-REQ of a `SetPassword` of `target`: bound to the
/// `CompletePasswordSet {target, …}` admind sends dird — its digest covers
/// the target only (the outcome and kvnos are admind's report, docs/52 §5
/// item 5), so any outcome stands in here.
pub fn completion(requester: &str, target: dtyp::Guid) -> Vec<u8> {
    fresh(
        requester,
        &ipc_dird_admin::Operation::CompletePasswordSet {
            target,
            outcome: ipc_dird_admin::PasswordSetOutcome::Completed,
            kvnos: Vec::new(),
        },
    )
}

/// keyd (Role::Ldap) with the admin service's key set (`create_key`,
/// docs/51 §4.3 step 11) — the scripted entropy gives it
/// [`ADMIN_SERVICE_KEY`] for each of keyd's enctypes.
fn admin_keyd(
    started: &KerberosTime,
    keyadm_keys: bool,
) -> Result<Keyd<InMemoryKeyStore, RecordBuffer, common::TestEntropy>, keyd::ConfigError> {
    let entropy = common::TestEntropy::default();
    let store = if keyadm_keys {
        InMemoryKeyStore::new_insecure_development_allowing_krbtgt(64)
    } else {
        InMemoryKeyStore::new(64)
    };
    let mut keyd = Keyd::with_entropy(
        dird::keyd_config(),
        store,
        RecordBuffer::new(),
        entropy.clone(),
        started,
    )?;
    let lengths: Vec<usize> = keyd
        .config()
        .enctypes
        .iter()
        .map(|e| {
            krb_crypto::EncType::from_number(e.number())
                .unwrap()
                .key_length()
        })
        .collect();
    for length in lengths {
        entropy.push(&ADMIN_SERVICE_KEY[..length]);
    }
    let service = manifest().admin_service().clone();
    keyd.create_key(
        &common::ADMIN,
        &service.handle,
        &service.binding,
        &common::now(),
    )
    .unwrap();
    if keyadm_keys {
        keyadm_key_sets(&mut keyd);
    }
    let _ = keyd.audit_sink_mut().take();
    Ok(keyd)
}

// ---------------------------------------------------------------------------
// Connectors: the host's way to read the server's uid.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub mod connectors {
    //! Linux: admind's own connectors (rustix peer credentials).
    use std::path::Path;

    pub type DirdAdminConnector = ipc_dird_admin::UnixConnector;
    pub type KeydConnector = ipc_keyd::UnixConnector;

    pub fn dird_admin(path: &Path) -> DirdAdminConnector {
        ipc_dird_admin::UnixConnector::new(path.to_path_buf())
    }

    pub fn keyd(path: &Path) -> KeydConnector {
        ipc_keyd::UnixConnector::new(path.to_path_buf())
    }
}

#[cfg(not(target_os = "linux"))]
pub mod connectors {
    //! Other hosts: the server's uid through tokio `UnixStream::peer_cred`
    //! (crates/directory-daemon tests support `connector::connect_checked`),
    //! then the blocking connection.
    use super::dird::connector::{connect_checked, runtime};
    use ipc::FrameLimit;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use zeroize::Zeroizing;

    pub use super::dird::connector::KeydConnector;

    pub fn keyd(path: &Path) -> KeydConnector {
        super::dird::connector::keyd(path)
    }

    pub struct DirdAdminConnector {
        path: PathBuf,
        runtime: tokio::runtime::Runtime,
    }

    pub struct DirdAdminChecked {
        uid: u32,
        inner: ipc_dird_admin::UnixConnection,
    }

    pub fn dird_admin(path: &Path) -> DirdAdminConnector {
        DirdAdminConnector {
            path: path.to_path_buf(),
            runtime: runtime(),
        }
    }

    impl ipc_dird_admin::Connector for DirdAdminConnector {
        type Connection = DirdAdminChecked;
        fn connect(&mut self) -> Result<DirdAdminChecked, ipc_dird_admin::TransportError> {
            let (uid, stream) = connect_checked(&self.path, &self.runtime)
                .ok_or(ipc_dird_admin::TransportError::Connect)?;
            Ok(DirdAdminChecked {
                uid,
                inner: ipc_dird_admin::UnixConnection::from_stream(stream),
            })
        }
    }

    impl ipc_dird_admin::Connection for DirdAdminChecked {
        fn peer_uid(&self) -> Result<u32, ipc_dird_admin::TransportError> {
            Ok(self.uid)
        }
        fn exchange(
            &mut self,
            frame: &[u8],
            reply_limit: FrameLimit,
            deadline: Duration,
        ) -> Result<Zeroizing<Vec<u8>>, ipc_dird_admin::TransportError> {
            ipc_dird_admin::Connection::exchange(&mut self.inner, frame, reply_limit, deadline)
        }
        fn check_idle(&mut self) -> Result<(), ipc_dird_admin::TransportError> {
            ipc_dird_admin::Connection::check_idle(&mut self.inner)
        }
    }
}

/// admind's client of dird at `socket` (the server must run as `uid`).
pub fn dird_link(socket: &Path, uid: u32) -> Box<dyn DirdLink> {
    Box::new(
        ipc_dird_admin::AdminClient::new(
            connectors::dird_admin(socket),
            uid,
            ipc_dird_admin::DEFAULT_DEADLINE,
        )
        .unwrap(),
    )
}

/// admind's client of keyd at `socket` (the server must run as `uid` and
/// resolve admind to Role::Directory — admind's own expectation, task R9).
pub fn keyd_link(socket: &Path, uid: u32, deadline: Duration) -> Box<dyn KeydLink> {
    Box::new(ipc_keyd::KeydClient::new(
        connectors::keyd(socket),
        admin_daemon::links::expected_keyd(uid).unwrap(),
        deadline,
    ))
}

// ---------------------------------------------------------------------------
// Fake servers: a silent keyd, a recording dird.
// ---------------------------------------------------------------------------

/// A "keyd" that accepts connections, answers each connection's first
/// request — the client's `Ping` probe (task R9) — naming the caller role
/// it was started with, then reads requests but never answers them (it
/// holds the connections open until dropped).
pub struct SilentServer {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    held: Arc<Mutex<Vec<UnixStream>>>,
    thread: Option<JoinHandle<()>>,
}

impl SilentServer {
    pub fn start(path: &Path, role: keyd::Role) -> SilentServer {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let held = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (stop, held) = (Arc::clone(&stop), Arc::clone(&held));
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            answer_the_probe(&mut stream, role);
                            held.lock().unwrap().push(stream);
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                }
            })
        };
        SilentServer {
            path: path.to_path_buf(),
            stop,
            held,
            thread: Some(thread),
        }
    }

    /// Connections accepted so far.
    pub fn accepted(&self) -> usize {
        self.held.lock().unwrap().len()
    }
}

impl Drop for SilentServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        for stream in self.held.lock().unwrap().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Answer the first request of a fresh keyd connection — the client's
/// `Ping` probe (task R9, docs/questions/Q-466) — with `role`; anything
/// else, or nothing within 2 s, is left unanswered.
fn answer_the_probe(stream: &mut UnixStream, role: keyd::Role) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let Some(body) = read_frame(stream, ipc_keyd::REQUEST_LIMIT) else {
        return;
    };
    if matches!(ipc_keyd::decode_request(&body), Ok(ipc_keyd::Call::Ping)) {
        let answer = ipc_keyd::Answer::Ping(Ok(role));
        if let Ok(frame) = ipc_keyd::encode_answer(&answer) {
            let _ = stream.write_all(frame.as_bytes());
        }
    }
}

/// Read one frame from a blocking stream with `limit`.
fn read_frame(stream: &mut UnixStream, limit: ipc::FrameLimit) -> Option<Vec<u8>> {
    let mut reader = FrameReader::new(limit);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(body) = reader.body() {
            return Some(body.to_vec());
        }
        let wanted = reader.wanted().min(chunk.len());
        if wanted == 0 {
            return None;
        }
        match stream.read(&mut chunk[..wanted]) {
            Ok(0) => return None,
            Ok(n) => {
                reader.push(&chunk[..n]).ok()?;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
}

/// A "dird" for the forwarding tests: records every request it receives
/// (decoded with dird's own channel decoder) and answers each operation
/// with `reply`, `Ping` with `Pong` — except, with `key_targets`,
/// `BeginPasswordSet`, answered as dird answers it for the user bob (one
/// `PrincipalLongterm` key set bound to `NT-PRINCIPAL [bob]`, the salt
/// `EXAMPLE.ORGbob` — docs/47 §9.1; [MS-KILE] 3.1.1.2 as cited there), and
/// `CompletePasswordSet`, answered `Done`.
///
/// With `grants` (keyd's socket where the test's uid is Role::Ldap), it
/// registers the set_secret grant of bob's key targets before it answers
/// `BeginPasswordSet` — as dird does after its PDP (task A15a).
pub struct RecordingDird {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    pub received: Arc<Mutex<Vec<ipc_dird_admin::Request>>>,
    held: Arc<Mutex<Vec<UnixStream>>>,
    thread: Option<JoinHandle<()>>,
}

impl RecordingDird {
    pub fn start(
        path: &Path,
        reply: ipc_dird_admin::Reply,
        key_targets: bool,
        grants: Option<(PathBuf, u32)>,
    ) -> RecordingDird {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let received = Arc::new(Mutex::new(Vec::new()));
        let held = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (stop, received, held) =
                (Arc::clone(&stop), Arc::clone(&received), Arc::clone(&held));
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            held.lock().unwrap().push(stream.try_clone().unwrap());
                            let (received, reply) = (Arc::clone(&received), reply.clone());
                            let grants = grants.clone();
                            std::thread::spawn(move || {
                                serve_dird(stream, &received, &reply, key_targets, grants)
                            });
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                }
            })
        };
        RecordingDird {
            path: path.to_path_buf(),
            stop,
            received,
            held,
            thread: Some(thread),
        }
    }
}

/// dird's `BeginPasswordSet` answer for the user bob (test data shaped as
/// docs/47 §9.1 gives it).
fn bob_key_targets(target: Guid) -> ipc_dird_admin::Reply {
    ipc_dird_admin::Reply::PasswordSet(ipc_dird_admin::PasswordSet {
        kind: ipc_dird_admin::AccountKind::User,
        keys: vec![ipc_dird_admin::KeyTarget {
            handle: keyd::KeyHandle::new(
                keyd::PrincipalId::from_bytes(target.to_packet()),
                keyd::KeyPurpose::PrincipalLongterm,
            ),
            binding: keyd::PrincipalBinding::new(common::realm(), principal("bob")),
        }],
        salt: krb_proto::KerberosString::new("EXAMPLE.ORGbob").unwrap(),
    })
}

/// The decision dird registers for a `PasswordSet` answer (task A15a;
/// A-102): keyd (Role::Ldap) `register_decision` of a `SetSecret` for
/// exactly its key targets and salt.
fn register_grant(grants: &(PathBuf, u32), answer: &ipc_dird_admin::Reply) {
    let ipc_dird_admin::Reply::PasswordSet(set) = answer else {
        return;
    };
    let kind = match set.kind {
        ipc_dird_admin::AccountKind::User => keyd::AccountKind::User,
        ipc_dird_admin::AccountKind::Computer => keyd::AccountKind::Computer,
    };
    let targets: Vec<keyd::SetSecretTarget> = set
        .keys
        .iter()
        .map(|k| keyd::SetSecretTarget {
            handle: k.handle,
            binding: k.binding.clone(),
            salt: set.salt.as_str().to_owned(),
        })
        .collect();
    // dird's role (Ldap) registers decisions (A-102; task R9: expected).
    let mut client = ipc_keyd::KeydClient::new(
        connectors::keyd(&grants.0),
        ipc_keyd::ExpectedPeer::new(grants.1, keyd::Role::Ldap).unwrap(),
        ipc_keyd::DEFAULT_DEADLINE,
    );
    client
        .register_decision(
            keyd::DecisionId::new(1),
            &keyd::DecidedOperation::SetSecret { kind, targets },
            &[],
            keyd::MAX_SET_SECRET_GRANT_SECS,
        )
        .unwrap()
        .unwrap();
}

fn serve_dird(
    mut stream: UnixStream,
    received: &Mutex<Vec<ipc_dird_admin::Request>>,
    reply: &ipc_dird_admin::Reply,
    key_targets: bool,
    grants: Option<(PathBuf, u32)>,
) {
    while let Some(body) = read_frame(&mut stream, ipc_dird_admin::REQUEST_LIMIT) {
        let Ok(request) = ipc_dird_admin::decode_request(&body) else {
            return;
        };
        let answer = match &request {
            ipc_dird_admin::Request::Ping => ipc_dird_admin::Reply::Pong,
            ipc_dird_admin::Request::Operation {
                operation: Operation::BeginPasswordSet { target },
                ..
            } if key_targets => {
                let answer = bob_key_targets(*target);
                if let Some(grants) = &grants {
                    register_grant(grants, &answer);
                }
                answer
            }
            ipc_dird_admin::Request::Operation {
                operation: Operation::CompletePasswordSet { .. },
                ..
            } if key_targets => ipc_dird_admin::Reply::Done,
            _ => reply.clone(),
        };
        received.lock().unwrap().push(request);
        let frame = ipc_dird_admin::encode_reply(&answer).unwrap();
        if stream.write_all(frame.as_bytes()).is_err() {
            return;
        }
    }
}

impl Drop for RecordingDird {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        for stream in self.held.lock().unwrap().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// dird and admind on their own threads.
// ---------------------------------------------------------------------------

/// dird's clock: the kdc fixtures' `now` (the tickets' time base).
struct FixedNow;

impl Clock for FixedNow {
    fn now(&self) -> Option<KerberosTime> {
        Some(common::now())
    }
}

/// dird with its admin service on its own thread.
pub struct DirdRun {
    control: DirdControl,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl DirdRun {
    fn start(
        params: directory_daemon::DaemonParams,
        admin: AdminParams,
        store: Arc<Store>,
    ) -> DirdRun {
        let control = DirdControl::new();
        let thread = {
            let control = control.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result = runtime.block_on(serve_with_admin(
                    params,
                    Some(admin),
                    StoreSource::Opened(store),
                    policy(),
                    control,
                ));
                drop(runtime);
                match result {
                    Ok(stopped) => stopped.join().map_err(|_| String::from("engine panicked")),
                    Err(error) => Err(error.to_string()),
                }
            })
        };
        let start = Instant::now();
        while !control.is_serving() {
            assert!(!thread.is_finished(), "dird did not start");
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "dird did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        DirdRun {
            control,
            thread: Some(thread),
        }
    }

    pub fn stop(mut self) -> Result<(), String> {
        self.control.stop();
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for DirdRun {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

/// admind on its own thread.
pub struct AdmindRun {
    control: DaemonControl,
    thread: Option<JoinHandle<Result<usize, String>>>,
}

impl AdmindRun {
    /// Start `serve` and wait until it listens; a start-up failure is
    /// returned as its message.
    pub fn start(params: DaemonParams) -> Result<AdmindRun, String> {
        let control = DaemonControl::new();
        let thread = {
            let control = control.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result = runtime.block_on(serve(params, control));
                drop(runtime);
                match result {
                    Ok(stopped) => {
                        let unacknowledged = stopped.unacknowledged_audit_events();
                        let failed = stopped.worker_failed();
                        stopped
                            .join()
                            .map_err(|_| String::from("worker panicked"))?;
                        if failed {
                            Err(String::from("worker stopped early"))
                        } else {
                            Ok(unacknowledged)
                        }
                    }
                    Err(error) => Err(error.to_string()),
                }
            })
        };
        let start = Instant::now();
        while !control.is_serving() {
            if thread.is_finished() {
                return Err(thread.join().unwrap().err().unwrap_or_default());
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "admind did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(AdmindRun {
            control,
            thread: Some(thread),
        })
    }

    /// Stop admind; the audit events it could not deliver (0 after a clean
    /// stop).
    pub fn stop(mut self) -> Result<usize, String> {
        self.control.stop();
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for AdmindRun {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

// ---------------------------------------------------------------------------
// The world.
// ---------------------------------------------------------------------------

/// How admind's keyd behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeydMode {
    /// A real keyd, the test's uid mapped to Role::Directory.
    Directory,
    /// A real keyd, the test's uid mapped to Role::Admin: `set_secret` is
    /// refused at keyd's authorization step.
    Admin,
    /// Accepts and never answers.
    Silent,
}

/// How admind's dird is played.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirdMode {
    /// The real dird with its admin service.
    Real,
    /// A recording fake answering every operation with this reply (and,
    /// when `key_targets`, the password-set steps as dird would for bob).
    Recording {
        /// The reply to every other operation.
        reply: ipc_dird_admin::Reply,
        /// Whether `BeginPasswordSet` gets bob's key targets.
        key_targets: bool,
    },
}

/// What a world is built with.
#[derive(Debug, Clone)]
pub struct Options {
    pub keyd: KeydMode,
    pub dird: DirdMode,
    pub limits: Limits,
    pub min_password_length: u32,
    pub keyd_deadline: Duration,
    pub frame_timeout: Duration,
    /// keyadm's view of the one keyd (task A10; A-102): one more socket on
    /// the same engine (`kk.sock`), the test's uid mapped to Role::Admin, so
    /// keyadm executes the decisions dird registers there; and the store
    /// accepts krbtgt and holds the krbtgt key set and ws9's two key sets
    /// (made with `create_key`, as the ceremony makes them).
    pub keyadm_keyd: bool,
    /// dird's pending key-operation request lifetime.
    pub key_request_lifetime: Duration,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            keyd: KeydMode::Directory,
            dird: DirdMode::Real,
            limits: Limits::DEFAULT,
            min_password_length: 12,
            keyd_deadline: Duration::from_secs(2),
            frame_timeout: Duration::from_secs(2),
            keyadm_keyd: false,
            key_request_lifetime: directory_admin::KEY_REQUEST_LIFETIME,
        }
    }
}

/// keyadm's key sets on the one keyd (task A10; A-102): the krbtgt key set
/// (`create_key`, as the ceremony makes it — docs/51 §4.3 step 11) and
/// ws9's `PrincipalLongterm` and `Service` key sets (made here with
/// `create_key` too: the test needs key sets to destroy, not their
/// passwords), all with drawn keys.
/// Spec: docs/10 §7; docs/47 §1.4, §9.1; A-19.
fn keyadm_key_sets(keyd: &mut Keyd<InMemoryKeyStore, RecordBuffer, common::TestEntropy>) {
    let krbtgt = manifest().krbtgt().clone();
    keyd.create_key(
        &common::ADMIN,
        &krbtgt.handle,
        &krbtgt.binding,
        &common::now(),
    )
    .unwrap();
    let ws9 = keyd_types::PrincipalId::from_bytes(g(WS9).to_packet());
    keyd.create_key(
        &common::ADMIN,
        &keyd_types::KeyHandle::new(ws9, keyd_types::KeyPurpose::PrincipalLongterm),
        &keyd_types::PrincipalBinding::new(
            common::realm(),
            common::name(KRB_NT_PRINCIPAL, &["ws9$"]),
        ),
        &common::now(),
    )
    .unwrap();
    keyd.create_key(
        &common::ADMIN,
        &keyd_types::KeyHandle::new(ws9, keyd_types::KeyPurpose::Service),
        &keyd_types::PrincipalBinding::new(
            common::realm(),
            common::name(
                krb_proto::constants::KRB_NT_SRV_HST,
                &["host", "ws9.example.org"],
            ),
        ),
        &common::now(),
    )
    .unwrap();
}

/// Everything of one test.
pub struct World {
    pub dir: TempDir,
    pub uid: u32,
    pub store: Option<Arc<Store>>,
    pub auditd_dir: auditd::TempDir,
    pub auditd: Option<auditd::Server>,
    pub dird_auditd: Option<FakeAuditd>,
    /// The fake auditd of the one keyd (both of its sockets).
    pub keyd_auditd: Option<FakeAuditd>,
    /// The one keyd: Role::Ldap on its socket, admind's role on `kd.sock`.
    pub keyd: Option<dird::keyd::Daemon>,
    /// The keyd's clock (the grant tests move it).
    pub keyd_clock: Option<TestClock>,
    pub silent_keyd: Option<SilentServer>,
    pub recording: Option<RecordingDird>,
    pub dird: Option<DirdRun>,
    pub admind: Option<AdmindRun>,
    pub admin_socket: PathBuf,
    /// The keyd socket where the test's uid is Role::Ldap (dird's).
    pub keyd_ldap_socket: PathBuf,
    /// The keyd socket where the test's uid is admind's role (or the silent
    /// server's).
    pub keyd_dir_socket: PathBuf,
    /// dird's admin socket (the real dird's or the recording one's).
    pub dird_socket: PathBuf,
    /// keyadm's socket on the one keyd (Role::Admin; task A10, A-102),
    /// when `Options::keyadm_keyd` (its records are the one keyd's,
    /// `keyd_auditd`).
    pub keyadm_keyd_socket: PathBuf,
    /// The KDC's socket on the one keyd (Role::Kdc): the tests' password
    /// check (`verify_preauth`, A-102 / docs/52 R4).
    pub keyd_kdc_socket: PathBuf,
}

impl World {
    /// Build the world; `None` when running as root (tier 2 needs a
    /// non-root uid: uid 0 is never mapped, R50-3).
    pub fn new(options: Options) -> Option<World> {
        let dir = TempDir::new();
        let uid = my_uid(&dir);
        if skip_as_root(uid) {
            return None;
        }
        // auditd for admind: the real listener and writer, the test's uid
        // mapped to `admind`.
        let auditd_dir = auditd::TempDir::new();
        let settings = auditd::settings_for(&auditd_dir, uid, "admind", 5);
        let auditd_server = auditd::Server::start(
            &settings,
            ListenerConfig::from_settings(&settings),
            64,
            true,
        );

        // The one keyd: Role::Ldap on its socket (dird's), admind's role
        // on `kd.sock` — unless admind's keyd is the silent server.
        let keyd_dir_socket = dir.join("kd.sock");
        let mut keyd_params =
            dird::keyd::params(&dir, CallerMap::new(&[(uid, Role::Ldap)]).unwrap(), uid);
        keyd_params.audit.socket = dir.join("ka.sock");
        let keyd_socket = keyd_params.keyd_socket.clone();
        let admind_role = match options.keyd {
            KeydMode::Directory => Some(Role::Directory),
            KeydMode::Admin => Some(Role::Admin),
            KeydMode::Silent => None,
        };
        if let Some(role) = admind_role {
            keyd_params.extra_listeners = vec![ExtraListener {
                socket: keyd_dir_socket.clone(),
                callers: CallerMap::new(&[(uid, role)]).unwrap(),
            }];
        }
        // The KDC's role on the same engine (A-102, docs/52 R4: no role
        // holds `verify_secret` any more, so the tests check a password the
        // way the KDC does — PA-ENC-TIMESTAMP, `verify_preauth`).
        let keyd_kdc_socket = dir.join("kq.sock");
        keyd_params.extra_listeners.push(ExtraListener {
            socket: keyd_kdc_socket.clone(),
            callers: CallerMap::new(&[(uid, Role::Kdc)]).unwrap(),
        });
        // keyadm's role on the same engine (A-102: keyadm executes the
        // decisions dird registers in this keyd).
        let keyadm_keyd_socket = dir.join("kk.sock");
        let keyadm_keys = options.keyadm_keyd;
        if keyadm_keys {
            keyd_params.extra_listeners.push(ExtraListener {
                socket: keyadm_keyd_socket.clone(),
                callers: CallerMap::new(&[(uid, Role::Admin)]).unwrap(),
            });
        }
        let keyd_auditd = FakeAuditd::start(&keyd_params.audit.socket);
        let keyd_clock = TestClock::at(common::keyd_started());
        let keyd_run = dird::keyd::Daemon::start(keyd_params, keyd_clock.clone(), move |started| {
            admin_keyd(started, keyadm_keys)
        })
        .unwrap();
        keyd_clock.set(common::now());
        let silent_keyd = match options.keyd {
            KeydMode::Silent => Some(SilentServer::start(&keyd_dir_socket, keyd::Role::Directory)),
            KeydMode::Directory | KeydMode::Admin => None,
        };

        // The dird side.
        let mut store = None;
        let (mut dird_auditd, mut dird_run, mut recording) = (None, None, None);
        let dird_socket = dir.join("m.sock");
        match &options.dird {
            DirdMode::Real => {
                let provisioned = provision(&dir.join("s.redb"));
                let keyd_socket = keyd_socket.clone();
                let mut params = dird::params(&dir, uid, uid, Duration::from_secs(5), 4);
                params.clock = SharedClock::new(FixedNow);
                dird_auditd = Some(FakeAuditd::start_recording_as(
                    &params.audit.socket,
                    ipc_audit::EventSource::Dird,
                ));
                let realm = common::realm();
                let factory: VerifierFactory = Arc::new(move || {
                    let verifier: Box<dyn TicketVerifier> = Box::new(
                        KeydTicketVerifier::new(
                            dird::connector::keyd(&keyd_socket),
                            uid,
                            realm.clone(),
                            ipc_keyd::DEFAULT_DEADLINE,
                        )
                        .ok()?,
                    );
                    Some(verifier)
                });
                let admin = AdminParams {
                    socket: dird_socket.clone(),
                    admind_uid: uid,
                    keyd: Some(factory),
                    ticket_age_max: Duration::from_secs(600),
                    quorum: 2,
                    node_id: NODE_ID,
                    manifest: manifest(),
                    max_connections: directory_daemon::MAX_ADMIN_CONNECTIONS,
                    queue_capacity: directory_daemon::ADMIN_QUEUE_CAPACITY,
                    ack_deadline: DecisionAckDeadline::PRODUCTION,
                    key_request_lifetime: options.key_request_lifetime,
                    destroy_reconcile_interval: directory_daemon::DESTROY_RECONCILE_INTERVAL,
                };
                dird_run = Some(DirdRun::start(params, admin, Arc::clone(&provisioned)));
                store = Some(provisioned);
            }
            DirdMode::Recording { reply, key_targets } => {
                recording = Some(RecordingDird::start(
                    &dird_socket,
                    reply.clone(),
                    *key_targets,
                    Some((keyd_socket.clone(), uid)),
                ));
            }
        }

        // admind.
        let admin_socket = dir.join("am.sock");
        let params = DaemonParams {
            admin_socket: admin_socket.clone(),
            audit: AuditEndpoint {
                socket: auditd_dir.socket(),
                uid,
            },
            frame_timeout: options.frame_timeout,
            min_password_length: options.min_password_length,
            dird: dird_link(&dird_socket, uid),
            keyd: keyd_link(&keyd_dir_socket, uid, options.keyd_deadline),
            limits: options.limits,
            queue_capacity: WORKER_QUEUE_CAPACITY,
            audit_window: ipc_audit::WindowConfig::DEFAULT,
        };
        let admind = AdmindRun::start(params).unwrap();
        Some(World {
            dir,
            uid,
            store,
            auditd_dir,
            auditd: Some(auditd_server),
            dird_auditd,
            keyd_auditd: Some(keyd_auditd),
            keyd: Some(keyd_run),
            keyd_clock: Some(keyd_clock),
            silent_keyd,
            recording,
            dird: dird_run,
            admind: Some(admind),
            admin_socket,
            keyd_ldap_socket: keyd_socket,
            keyd_dir_socket,
            dird_socket,
            keyadm_keyd_socket,
            keyd_kdc_socket,
        })
    }

    /// The one keyd's records of keyadm's calls (Role::Admin) so far (task
    /// A10; A-102) — without the `Ping` with which the keyd client verifies
    /// its role on each new connection (task R9).
    pub fn keyadm_records(&self) -> Vec<KeydRecord> {
        self.keyd_auditd
            .as_ref()
            .map(|a| {
                a.events()
                    .into_iter()
                    .filter_map(|e| match e {
                        EventBody::Keyd(record)
                            if record.caller_role == ipc_audit::KeydRole::Admin
                                && record.op != ipc_audit::KeydOperation::Ping =>
                        {
                            Some(*record)
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A new connection to admind.
    pub fn connect(&self) -> AdminConn {
        AdminConn::connect(&self.admin_socket)
    }

    /// dird's `DirAdmin` events so far.
    pub fn dir_admin_events(&self) -> Vec<DirAdminEvent> {
        self.dird_auditd
            .as_ref()
            .map(|a| {
                a.events()
                    .into_iter()
                    .filter_map(|e| match e {
                        EventBody::DirAdmin(event) => Some(*event),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// keyd's records so far (both of its sockets: dird's verifications and
    /// grants under Ldap, admind's set_secret calls under its role).
    pub fn keyd_records(&self) -> Vec<KeydRecord> {
        self.keyd_auditd
            .as_ref()
            .map(|a| {
                a.events()
                    .into_iter()
                    .filter_map(|e| match e {
                        EventBody::Keyd(record) => Some(*record),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Stop admind (it flushes its audit window), then auditd, and read
    /// admind's events back from the verified log.
    pub fn finish(&mut self) -> Vec<AdmindEvent> {
        if let Some(admind) = self.admind.take() {
            assert_eq!(admind.stop(), Ok(0), "admind delivered every event");
        }
        if let Some(server) = self.auditd.take() {
            let _ = server.stop();
        }
        let (records, _) = auditd::read_segment(&self.auditd_dir.base(), 1, Anchor::Genesis);
        records
            .into_iter()
            .filter_map(|record| match ipc_audit::decode_event(&record.payload) {
                Ok(EventBody::Admind(event)) => {
                    assert_eq!(record.source, audit_log::Source::Admind);
                    assert_eq!(record.source_uid, self.uid);
                    Some(*event)
                }
                _ => None,
            })
            .collect()
    }

    /// Every octet of every file under the world's directories.
    pub fn all_file_octets(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = Vec::new();
        for root in [self.dir.path(), self.auditd_dir.path()] {
            collect_files(root, &mut files);
        }
        files
    }
}

fn collect_files(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            collect_files(&path, out);
        } else if kind.is_file() {
            if let Ok(octets) = std::fs::read(&path) {
                out.push((path, octets));
            }
        }
    }
}

impl Drop for World {
    fn drop(&mut self) {
        if let Some(admind) = self.admind.take() {
            let _ = admind.stop();
        }
        if let Some(dird) = self.dird.take() {
            let _ = dird.stop();
        }
        if let Some(keyd) = self.keyd.take() {
            let _ = keyd.stop();
        }
        if let Some(server) = self.auditd.take() {
            let _ = server.stop();
        }
    }
}

// ---------------------------------------------------------------------------
// A raw client of admin.sock.
// ---------------------------------------------------------------------------

/// What one exchange got.
#[derive(Debug, PartialEq, Eq)]
pub enum Got {
    /// One of the channel's replies.
    Reply(ipc_admin::Reply),
    /// The shared refusal.
    Refused(Refused),
    /// admind closed the connection without a reply.
    Closed,
    /// No reply within the read timeout.
    Nothing,
}

/// A blocking client of admin.sock built from crate ipc-admin's codec.
pub struct AdminConn {
    pub stream: UnixStream,
}

impl AdminConn {
    pub fn connect(path: &Path) -> AdminConn {
        let stream = UnixStream::connect(path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        AdminConn { stream }
    }

    pub fn send_raw(&mut self, octets: &[u8]) {
        let _ = self.stream.write_all(octets);
    }

    pub fn send(&mut self, request: &ipc_admin::Request) {
        let frame = ipc_admin::encode_request(request).unwrap();
        self.send_raw(frame.as_bytes());
    }

    pub fn receive(&mut self) -> Got {
        let mut reader = FrameReader::new(ipc_admin::REPLY_LIMIT);
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(body) = reader.body() {
                return match ipc_admin::decode_reply(body).unwrap() {
                    ipc::Reply::Message(reply) => Got::Reply(reply),
                    ipc::Reply::Refused(refused) => Got::Refused(refused),
                };
            }
            let wanted = reader.wanted().min(chunk.len());
            match self.stream.read(&mut chunk[..wanted]) {
                Ok(0) => return Got::Closed,
                Ok(n) => {
                    reader.push(&chunk[..n]).unwrap();
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == ErrorKind::ConnectionReset => return Got::Closed,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Got::Nothing
                }
                Err(e) => panic!("read failed: {e}"),
            }
        }
    }

    pub fn call(&mut self, request: &ipc_admin::Request) -> Got {
        self.send(request);
        self.receive()
    }
}
