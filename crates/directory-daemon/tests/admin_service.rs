//! Tier 2, dird's admin service (docs/51 §7, task A8): dird in-process
//! (`directory_daemon::serve_with_admin` on its own thread and runtime) with
//! a **real keyd daemon** (`keyd_daemon::serve`, the test's own uid mapped to
//! Role::Ldap — the single-uid pattern of docs/50 §9 tier 2) and a fake
//! auditd built from the audit channel's message set, reached by admind's
//! client (`ipc_dird_admin::AdminClient`) over the real `dird-admin.sock`.
//!
//! # The AP-REQs
//!
//! keyd holds the admin service's key set — `(admind-svc$ objectGUID,
//! AdminService)` (R2: its own purpose), bound to `NT-SRV-HST
//! admind/dc1.example.org` (A-73) — created with `create_key` from scripted
//! test entropy, so the test, playing the Kerberos side, knows the key. The
//! test seals each administrator's service ticket under it (RFC 4120 §5.3:
//! EncTicketPart, key usage 2) and builds the AP-REQ with an authenticator
//! under the ticket's session key (§5.5.1, key usage 11) whose `cksum` is
//! the session key's MIC (key usage 10, §7.5.1) over the operation digest of
//! the request it accompanies (`ipc_dird_admin::operation_digest`; docs/52
//! §5), with krb-crypto and the kdc integration fixtures
//! (crates/kdc/tests/common: `usage`, `aes256`, the scripted entropy, the
//! names and times) — the construction keyd's own service-ticket tests use.
//! keyd then runs the whole of RFC 4120 §3.2.3 on it (the binding check,
//! the decryption, the authenticator, the replay cache).
//!
//! # What is checked
//!
//! Every operation end to end with its reply; the decision event
//! acknowledged **before** the commit and the outcome event after it; an
//! auditd that withholds acknowledgements ⇒ `Unavailable`, store unchanged,
//! the outcome `AuditUnacknowledged`; the `RateLimit` obligation past its
//! limit ⇒ `Denied`, the decision `ObligationRefused` (A-91, Q-397 — the
//! third F4 code, `ViewUnavailable`, has no injection point here: the store
//! dird holds cannot be made to fail to begin a transaction or a snapshot);
//! a bad or expired AP-REQ ⇒ `Denied` and keyd down ⇒ `Unavailable`, store
//! unchanged; dual control (a second Tier-0 administrator's approval
//! satisfies it, the same principal twice does not); a wrong peer uid ⇒
//! closed; a full queue ⇒ `Busy`; an oversize frame ⇒ closed before the
//! body; the admin service object absent ⇒ no admin service, dird's other
//! services run; **R2** — an administrator's valid AP-REQ made for one
//! operation and attached to another (the Q-292 attack), an approval made
//! for another operation, and an AP-REQ without its `cksum` are all
//! `Denied`, the store unchanged; **task A16** — a dual-controlled tier-map
//! change written as `policy.next` (version + 1) with its decision and
//! outcome events, and its refusals (one administrator, a self-approval, a
//! non-Tier-0 requester, an approval for another change, a second pending
//! change, no `policy_next_path`).
//!
//! Sources: docs/51 §5.2, §5.3, §5.6, §5.7, §5.10, §7.1-§7.5; docs/52 §3.2, §5;
//! docs/50 §3.3, §3.6,
//! §9; docs/10 §5ב; RFC 4120 §3.2.3, §5.3, §5.5.1, §6.2.1, §7.5.1; [MS-SAMR]
//! 2.2.1.14 (RID 502); [MS-DTYP] 2.4.2.4 (SID layout); docs/11 §2, §8;
//! A-26, A-56, A-73, A-85, A-89, A-91, P-22. Every value is constructed by
//! hand for these tests (the
//! times are those of the kdc fixtures); no vector comes from any other
//! implementation.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use ad_schema::flags::user_account_control as uac;
use ad_schema::{phase1, Phase1Schema};
use core::time::Duration;
use directory_admin::{wall_clock, CHANGE_SEQ_COUNTER, RID_COUNTER, RID_END_EXCLUSIVE, RID_FIRST};
use directory_daemon::policy::{DevelopmentPolicy, MandatoryFast};
use directory_daemon::policy_next::PolicyNextFile;
// The full parameters, the generic serve and any keyd verifier are dird's
// test seams (docs/52 C18, task R15; feature `test-seams`).
use directory_daemon::test_seams::{serve_with_admin, AdminParams, DaemonParams, VerifierFactory};
use directory_daemon::{
    admin_refused_peer_count, destroy_decision_id, Clock, DaemonControl, DecisionAckDeadline,
    DecisionAckDeadlineOutOfRange, KeydTicketVerifier, SharedClock, TicketVerifier,
    DECISION_ACK_DEADLINE, MAX_DECISION_ACK_DEADLINE,
};
use dirstore::{AttrId, IntegrityKey, NewObject, NodeId, Origin, Store, WriteTxn};
use dtyp::{
    ace_flags, create_security_descriptor, AccessMask, Ace, Acl, AutoInheritFlags, Control,
    GenericMapping, Guid, MaskSidAce, SecurityDescriptor, Sid, Token, ACL_REVISION_DS,
    SECURITY_NT_AUTHORITY,
};
use ipc::{Direction, FrameReader, Refused};
use ipc_audit::{
    decode_event, decode_request, encode_reply, Ack, AuditReply, AuditRequest, DecisionResult,
    DirAdminEvent, DirAdminOperation, DirAdminStage, EventBody, OutcomeResult, AUDIT_CHANNEL,
};
use ipc_dird_admin::{
    operation_digest, AccountExpires, AccountKind, AdminClient, Auth, LookupKey, Operation,
    PasswordSetOutcome, RefusalStatus, Reply, Request, Unserved, MAX_REQUEST_BODY,
};
use keyd::{DecisionId, InMemoryKeyStore, KeyHandle, KeyPurpose, Keyd, Kvno, Role};
use keyd_daemon::test_seams::ExtraListener;
use keyd_daemon::{CallerMap, RecordBuffer};
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

// ---------------------------------------------------------------------------
// The domain (test data).
// ---------------------------------------------------------------------------

/// The DC's host name (dird's `dns_host_name` in support `params`).
const DC_FQDN: &str = "dc1.example.org";

/// The admin service's key (scripted into keyd's `create_key`).
const ADMIN_SERVICE_KEY: [u8; 32] = [0xAD; 32];

/// The session key of the test tickets.
const SESSION_KEY: [u8; 32] = [0x5E; 32];

/// The dual-control quorum (P-22: 2).
const QUORUM: usize = 2;

/// The ticket-age threshold of these tests (R51-10; within 60 s ..= 3600 s).
const TICKET_AGE_MAX: Duration = Duration::from_secs(600);

/// dird's node-id (test data).
const NODE_ID: NodeId = NodeId([0xA8; 16]);

const ROOT: u32 = 1;
const TIER0_OU: u32 = 2;
const STAFF_OU: u32 = 3;
const KRBTGT: u32 = 10;
const LDAP_SVC: u32 = 11;
const ADMIND_SVC: u32 = 12;
const ADMIN1: u32 = 13;
const ADMIN2: u32 = 14;
const TIER0_GROUP: u32 = 20;
const BOOTSTRAP: u32 = 21;
const BOB: u32 = 30;
const STAFF_GROUP: u32 = 31;

/// The principals in the order provisioning takes their RIDs (krbtgt is
/// RID 502 and takes none).
const RID_ORDER: [u32; 8] = [
    TIER0_GROUP,
    BOOTSTRAP,
    ADMIN1,
    ADMIN2,
    BOB,
    STAFF_GROUP,
    LDAP_SVC,
    ADMIND_SVC,
];

/// whenCreated / pwdLastSet: 2026-11-01T00:00:00Z as DSTIME (derivation in
/// crates/directory-admin tests/common `PROVISIONED_DSTIME`).
const PROVISIONED_DSTIME: i64 = 13_437_964_800;

fn g(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0xA8,
        data3: 0x00D1,
        data4: [0xA, 8, 0xA, 8, 0xA, 8, 0xA, 8],
    }
}

/// S-1-5-21-7-8-9 ([MS-DTYP] 2.4.2.4 layout).
fn domain_sid() -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 7, 8, 9]).unwrap()
}

fn rid(id: u32) -> u32 {
    if id == KRBTGT {
        return 502;
    }
    let position = RID_ORDER.iter().position(|p| *p == id).unwrap();
    1101 + u32::try_from(position).unwrap()
}

fn sid_with_rid(rid: u32) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 7, 8, 9, rid]).unwrap()
}

fn sid_of(id: u32) -> Sid {
    sid_with_rid(rid(id))
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

/// One object of the provisioning plan.
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
/// (parents first, members before groups). `with_admin_service` = false
/// leaves the admin service object out.
fn plan(with_admin_service: bool) -> Vec<Planned> {
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
    let service = |id: u32, sam: &str, spn: &str| {
        let mut attrs = account(id, sam, uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT, false);
        attrs.push(("dNSHostName", text(DC_FQDN)));
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
    let planned = |id, parent, class, attrs| Planned {
        id,
        parent,
        class,
        attrs,
    };
    let mut plan = vec![
        planned(
            ROOT,
            None,
            "domainDNS",
            vec![
                ("dc", text("example")),
                ("objectSid", vec![domain_sid().encode()]),
            ],
        ),
        planned(
            TIER0_OU,
            Some(ROOT),
            "organizationalUnit",
            vec![("ou", text("Tier0"))],
        ),
        planned(
            STAFF_OU,
            Some(ROOT),
            "organizationalUnit",
            vec![("ou", text("Staff"))],
        ),
        planned(
            KRBTGT,
            Some(TIER0_OU),
            "user",
            account(KRBTGT, "krbtgt", n, false),
        ),
        planned(
            LDAP_SVC,
            Some(TIER0_OU),
            "computer",
            service(LDAP_SVC, "ldap-svc$", "ldap/dc1.example.org"),
        ),
    ];
    if with_admin_service {
        plan.push(planned(
            ADMIND_SVC,
            Some(TIER0_OU),
            "computer",
            service(ADMIND_SVC, "admind-svc$", "admind/dc1.example.org"),
        ));
    }
    plan.extend([
        planned(
            ADMIN1,
            Some(TIER0_OU),
            "user",
            account(ADMIN1, "admin1", n, true),
        ),
        planned(
            ADMIN2,
            Some(TIER0_OU),
            "user",
            account(ADMIN2, "admin2", n, true),
        ),
        planned(BOB, Some(STAFF_OU), "user", account(BOB, "bob", n, true)),
        planned(
            TIER0_GROUP,
            Some(TIER0_OU),
            "group",
            group(TIER0_GROUP, "tier0", &[ADMIN1, ADMIN2]),
        ),
        planned(
            BOOTSTRAP,
            Some(STAFF_OU),
            "group",
            group(BOOTSTRAP, "bootstrap", &[]),
        ),
        planned(
            STAFF_GROUP,
            Some(STAFF_OU),
            "group",
            group(STAFF_GROUP, "staff", &[]),
        ),
    ]);
    plan
}

fn provisioned_at() -> KerberosTime {
    common::kt("20261101000000Z")
}

/// Provision the directory in ONE transaction, with the two counters
/// (docs/51 §4.3 step 5, §8.3; A-83; Q-358 item 1: every write takes a
/// change-seq).
fn provision(path: &Path, with_admin_service: bool) -> Arc<Store> {
    let p1: Phase1Schema = phase1().unwrap();
    let store = Store::open(
        path,
        IntegrityKey::from_bytes(&support::TEST_KEY),
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
    for planned in plan(with_admin_service) {
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

fn origin(txn: &mut WriteTxn<'_>) -> Origin {
    Origin {
        wall_clock: wall_clock(&provisioned_at()).unwrap(),
        origin_node: NODE_ID,
        origin_seq: txn.take_counter_value(CHANGE_SEQ_COUNTER).unwrap(),
    }
}

/// The policy: tier map {tier0 group → Tier0}, {ou=Tier0 → Tier0}; the
/// Tier-0 group may run every Directory action under the NC root, and
/// `PolicyAdmin` on every policy scope (the rule `provision domain` writes
/// — the key operations' `keys` scope included, task A10, Q-420); the
/// bootstrap group is the FAST bootstrap set (docs/51 §4.3 step 6).
fn policy() -> DevelopmentPolicy {
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
fn manifest() -> Manifest {
    Manifest::new(&ManifestFields {
        realm: String::from(support::REALM),
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

fn principal(sam: &str) -> PrincipalName {
    common::name(KRB_NT_PRINCIPAL, &[sam])
}

/// An AP-REQ of `sam` for the admin service bound to `operation`: the
/// ticket sealed under the admin service key (usage 2), ending at
/// `endtime`; the authenticator at `now` with `cusec`, under the session key
/// (usage 11), its `cksum` the session key's MIC over the operation's digest
/// (key usage 10, the session key's required checksum type — R2).
/// Spec: RFC 4120 §4, §5.3, §5.5.1, §7.5.1; RFC 3961 §3; docs/52 §5.
fn ap_req(sam: &str, cusec: u32, endtime: KerberosTime, operation: &Operation) -> Vec<u8> {
    let digest = operation_digest(operation).unwrap();
    ap_req_with(sam, cusec, endtime, Some(digest.as_bytes()))
}

/// [`ap_req`] with `bound` (if any) as the application data the `cksum`
/// covers — `None`: no `cksum` at all.
fn ap_req_with(sam: &str, cusec: u32, endtime: KerberosTime, bound: Option<&[u8]>) -> Vec<u8> {
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
        endtime,
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

/// A fresh AP-REQ of `sam` bound to `operation` (R2).
fn fresh(sam: &str, operation: &Operation) -> Vec<u8> {
    ap_req(
        sam,
        CUSEC.fetch_add(1, Ordering::SeqCst),
        common::kt("20261113170000Z"),
        operation,
    )
}

/// `operation` by `requester` with `approvers`, every AP-REQ bound to it.
fn by(requester: &str, approvers: &[&str], operation: Operation) -> Request {
    Request::Operation {
        auth: Auth {
            requester: fresh(requester, &operation),
            approvals: approvers.iter().map(|a| fresh(a, &operation)).collect(),
        },
        operation,
    }
}

// ---------------------------------------------------------------------------
// keyd: the admin service key set, Role::Ldap for the test's uid.
// ---------------------------------------------------------------------------

/// keyd with the admin service's key set (`create_key`, docs/51 §4.3 step
/// 11) — the scripted entropy gives it [`ADMIN_SERVICE_KEY`] for each of
/// keyd's enctypes — and, as the ceremony makes them, the krbtgt and LDAP
/// service key sets (counter-drawn keys: the key-operation decisions of
/// A-102 run on them). The store holds krbtgt: tests only (D178).
fn admin_keyd(
    started: &KerberosTime,
) -> Result<Keyd<InMemoryKeyStore, RecordBuffer, common::TestEntropy>, keyd::ConfigError> {
    let entropy = common::TestEntropy::default();
    let mut keyd = Keyd::with_entropy(
        support::keyd_config(),
        InMemoryKeyStore::new_insecure_development_allowing_krbtgt(64),
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
    for target in [
        manifest().krbtgt().clone(),
        manifest().ldap_service().clone(),
    ] {
        keyd.create_key(
            &common::ADMIN,
            &target.handle,
            &target.binding,
            &common::now(),
        )
        .unwrap();
    }
    let _ = keyd.audit_sink_mut().take();
    Ok(keyd)
}

// ---------------------------------------------------------------------------
// A fake auditd that can withhold its acknowledgements and look at the
// store when a decision event arrives.
// ---------------------------------------------------------------------------

type Hook = Arc<dyn Fn(&EventBody) + Send + Sync>;

struct AdminAuditd {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    withhold: Arc<AtomicBool>,
    events: Arc<Mutex<Vec<EventBody>>>,
    connections: Arc<Mutex<Vec<UnixStream>>>,
    thread: Option<JoinHandle<()>>,
}

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

impl AdminAuditd {
    fn start(path: &Path, hook: Option<Hook>) -> AdminAuditd {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let withhold = Arc::new(AtomicBool::new(false));
        let events = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (stop, withhold, events, connections) = (
                Arc::clone(&stop),
                Arc::clone(&withhold),
                Arc::clone(&events),
                Arc::clone(&connections),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            connections
                                .lock()
                                .unwrap()
                                .push(stream.try_clone().unwrap());
                            let (withhold, events, hook) =
                                (Arc::clone(&withhold), Arc::clone(&events), hook.clone());
                            std::thread::spawn(move || {
                                serve_audit(stream, &withhold, &events, hook)
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
        AdminAuditd {
            path: path.to_path_buf(),
            stop,
            withhold,
            events,
            connections,
            thread: Some(thread),
        }
    }

    fn withhold(&self, on: bool) {
        self.withhold.store(on, Ordering::SeqCst);
    }

    /// The DirAdmin events received (acknowledged) so far, in order.
    fn admin_events(&self) -> Vec<DirAdminEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                EventBody::DirAdmin(event) => Some((**event).clone()),
                _ => None,
            })
            .collect()
    }
}

impl Drop for AdminAuditd {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop.store(true, Ordering::SeqCst);
            let _ = thread.join();
            for stream in self.connections.lock().unwrap().drain(..) {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// One audit connection: `Ping` → `Pong`; `Append` → the hook on each event,
/// then `Ack` — or, while withholding, nothing (the batch is not persisted
/// and never acknowledged).
fn serve_audit(
    mut stream: UnixStream,
    withhold: &AtomicBool,
    events: &Mutex<Vec<EventBody>>,
    hook: Option<Hook>,
) {
    while let Some(body) = read_frame(&mut stream, AUDIT_CHANNEL.limit(Direction::Request)) {
        let reply = match decode_request(&body) {
            Ok(AuditRequest::Ping) => AuditReply::Pong(ipc_audit::EventSource::Dird),
            Ok(AuditRequest::Append(append)) => {
                if withhold.load(Ordering::SeqCst) {
                    continue;
                }
                for event in append.events() {
                    let decoded = decode_event(event.as_bytes()).unwrap();
                    if let Some(hook) = &hook {
                        hook(&decoded);
                    }
                    events.lock().unwrap().push(decoded);
                }
                AuditReply::Ack(Ack {
                    through_seq: append.last_seq(),
                    head_hash: [0; 32],
                })
            }
            Err(_) => return,
        };
        let frame = encode_reply(&ipc::Reply::Message(reply)).unwrap();
        if stream.write_all(frame.as_bytes()).is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// dird with its admin service.
// ---------------------------------------------------------------------------

/// dird's clock: the kdc fixtures' `now` (the tickets' time base), moved
/// by the test's offset in seconds (0 unless a test moves it — task A10's
/// expiry test).
struct FixedNow(Arc<std::sync::atomic::AtomicI64>);

impl Clock for FixedNow {
    fn now(&self) -> Option<KerberosTime> {
        Some(common::at(self.0.load(Ordering::SeqCst)))
    }
}

struct DirdRun {
    control: DaemonControl,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl DirdRun {
    fn start(
        params: DaemonParams,
        admin: AdminParams,
        store: Arc<Store>,
        policy: DevelopmentPolicy,
    ) -> DirdRun {
        let control = DaemonControl::new();
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
                    directory_daemon::test_seams::opened(store),
                    policy,
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

    fn stop(mut self) -> Result<(), String> {
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

#[cfg(target_os = "linux")]
mod admin_connector {
    //! Linux: admind's own connector (rustix peer credentials).
    pub type AdminConnector = ipc_dird_admin::UnixConnector;

    pub fn admin(path: &std::path::Path) -> AdminConnector {
        ipc_dird_admin::UnixConnector::new(path.to_path_buf())
    }
}

#[cfg(not(target_os = "linux"))]
mod admin_connector {
    //! Other hosts: the server's uid through tokio `UnixStream::peer_cred`
    //! (support `connector::connect_checked`), then the blocking connection.
    use super::support::connector::{connect_checked, runtime};
    use ipc::FrameLimit;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use zeroize::Zeroizing;

    pub struct AdminConnector {
        path: PathBuf,
        runtime: tokio::runtime::Runtime,
    }

    pub struct AdminChecked {
        uid: u32,
        inner: ipc_dird_admin::UnixConnection,
    }

    pub fn admin(path: &Path) -> AdminConnector {
        AdminConnector {
            path: path.to_path_buf(),
            runtime: runtime(),
        }
    }

    impl ipc_dird_admin::Connector for AdminConnector {
        type Connection = AdminChecked;
        fn connect(&mut self) -> Result<AdminChecked, ipc_dird_admin::TransportError> {
            let (uid, stream) = connect_checked(&self.path, &self.runtime)
                .ok_or(ipc_dird_admin::TransportError::Connect)?;
            Ok(AdminChecked {
                uid,
                inner: ipc_dird_admin::UnixConnection::from_stream(stream),
            })
        }
    }

    impl ipc_dird_admin::Connection for AdminChecked {
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

use admin_connector::AdminConnector;

/// What a world is built with.
#[derive(Clone)]
struct Options {
    with_admin_service: bool,
    admind_uid_offset: u32,
    max_connections: usize,
    queue_capacity: usize,
    hook: bool,
    /// The pending key-operation request lifetime (task A10).
    key_request_lifetime: Duration,
    /// dird's decision-acknowledgement wait (A-95 follow-up, Q-441).
    ack_deadline: DecisionAckDeadline,
    /// dird's keyd client registers no decision (task A15a, A-102: the
    /// fail-closed paths of `BeginPasswordSet` and of the quorum-completing
    /// `Approve`).
    refuse_decisions: bool,
    /// How often dird re-registers lost destroy decisions (A-105).
    reconcile_interval: Duration,
    /// Whether dird is given a `policy_next_path` (task A16).
    policy_next: bool,
}

/// The decision-acknowledgement wait of the tests that expect auditd to
/// acknowledge: the ceiling, so a fake auditd slowed by a loaded machine
/// still answers in time (A-95 follow-up; docs/questions/Q-417 item 3,
/// Q-441). The production wait stays [`DecisionAckDeadline::PRODUCTION`];
/// the expiry test uses it.
fn generous() -> DecisionAckDeadline {
    DecisionAckDeadline::new(MAX_DECISION_ACK_DEADLINE).unwrap()
}

impl Default for Options {
    fn default() -> Options {
        Options {
            with_admin_service: true,
            admind_uid_offset: 0,
            max_connections: directory_daemon::MAX_ADMIN_CONNECTIONS,
            queue_capacity: directory_daemon::ADMIN_QUEUE_CAPACITY,
            hook: false,
            key_request_lifetime: directory_admin::KEY_REQUEST_LIFETIME,
            ack_deadline: generous(),
            refuse_decisions: false,
            reconcile_interval: directory_daemon::DESTROY_RECONCILE_INTERVAL,
            policy_next: true,
        }
    }
}

/// dird's `policy.next` in a world (task A16): `pn/policy.next` in a
/// scratch directory inside the workspace (crates/test-scratch, Q-480: the
/// protected-file walk from `/` accepts it with the test's account — which
/// stands in for dird's — as the owner; the system's temporary directory,
/// where the sockets live, it would not); `pn` is created mode 0700, as
/// dird's start prepares it.
fn policy_next_path(scratch: &test_scratch::ScratchDir) -> PathBuf {
    scratch.join("pn").join("policy.next")
}

/// dird's keyd client with every decision's registration refused as "not
/// performed" — the real verifier otherwise (task A15a, A-102; a keyd that
/// cannot register it).
struct RefusingDecisions(Box<dyn TicketVerifier>);

impl TicketVerifier for RefusingDecisions {
    fn verify(
        &mut self,
        service: &keyd::PrincipalId,
        operation: &keyd::OperationDigest,
        ap_req: &[u8],
    ) -> Result<keyd::OperationTicket, keyd::AuthnError> {
        self.0.verify(service, operation, ap_req)
    }

    fn register_decision(
        &mut self,
        _decision: directory_daemon::DecisionRegistration,
    ) -> Result<(), directory_daemon::RegistrationFailure> {
        Err(directory_daemon::RegistrationFailure::NotPerformed)
    }

    fn list_destroy_decisions(
        &mut self,
        after: Option<DecisionId>,
    ) -> Option<keyd_types::DestructionPage> {
        self.0.list_destroy_decisions(after)
    }
}

/// keyd's parameters in a world: the test's uid as Role::Ldap (A-73) on
/// `keyd_socket`, its own fake auditd at `ka.sock`, and — A-102 — keyadm's
/// (Admin, `kk.sock`) and admind's (Directory, `kd.sock`) roles on the same
/// engine, so the decisions dird registers can be executed (the single-uid
/// test seam of docs/questions/Q-453 item 3).
fn keyd_params(dir: &support::TempDir, uid: u32) -> keyd_daemon::test_seams::DaemonParams {
    let mut params = support::keyd::params(dir, CallerMap::new(&[(uid, Role::Ldap)]).unwrap(), uid);
    params.audit.socket = dir.join("ka.sock");
    params.extra_listeners = vec![
        ExtraListener {
            socket: dir.join("kk.sock"),
            callers: CallerMap::new(&[(uid, Role::Admin)]).unwrap(),
        },
        ExtraListener {
            socket: dir.join("kd.sock"),
            callers: CallerMap::new(&[(uid, Role::Directory)]).unwrap(),
        },
    ];
    params
}

/// keyd, both auditds, dird with its admin service, and admind's client.
struct World {
    /// Where `policy.next` lives (task A16; [`policy_next_path`]).
    scratch: test_scratch::ScratchDir,
    dir: support::TempDir,
    uid: u32,
    store: Arc<Store>,
    auditd: AdminAuditd,
    _keyd_auditd: support::FakeAuditd,
    keyd: Option<support::keyd::Daemon>,
    dird: Option<DirdRun>,
    admin_socket: PathBuf,
    kdc_socket: PathBuf,
    /// (change-seq next value when each Decision(Proceed) arrived, op id).
    seen_at_decision: Arc<Mutex<Vec<(u64, u64)>>>,
    /// dird's clock offset in seconds (task A10).
    clock_offset: Arc<std::sync::atomic::AtomicI64>,
    keyd_socket: PathBuf,
    /// The same keyd, the test's uid as Role::Admin (keyadm's — A-102).
    keyd_admin_socket: PathBuf,
    /// The same keyd, the test's uid as Role::Directory (admind's).
    keyd_directory_socket: PathBuf,
    options: Options,
}

/// dird with its admin service (the world's parameters).
#[allow(clippy::too_many_arguments)]
fn start_dird(
    dir: &support::TempDir,
    uid: u32,
    store: &Arc<Store>,
    admin_socket: &Path,
    keyd_socket: &Path,
    options: &Options,
    clock_offset: &Arc<std::sync::atomic::AtomicI64>,
    policy_next: &Path,
) -> DirdRun {
    let mut params = support::params(dir, uid, uid, Duration::from_secs(5), 4);
    params.clock = SharedClock::new(FixedNow(Arc::clone(clock_offset)));
    let realm = common::realm();
    let keyd_socket = keyd_socket.to_path_buf();
    let refuse_decisions = options.refuse_decisions;
    let factory: VerifierFactory = Arc::new(move || {
        let verifier: Box<dyn TicketVerifier> = Box::new(
            KeydTicketVerifier::new(
                support::connector::keyd(&keyd_socket),
                uid,
                realm.clone(),
                ipc_keyd::DEFAULT_DEADLINE,
            )
            .ok()?,
        );
        if refuse_decisions {
            let refusing: Box<dyn TicketVerifier> = Box::new(RefusingDecisions(verifier));
            return Some(refusing);
        }
        Some(verifier)
    });
    let admin = AdminParams {
        socket: admin_socket.to_path_buf(),
        admind_uid: uid + options.admind_uid_offset,
        keyd: Some(factory),
        ticket_age_max: TICKET_AGE_MAX,
        quorum: QUORUM,
        node_id: NODE_ID,
        manifest: manifest(),
        max_connections: options.max_connections,
        queue_capacity: options.queue_capacity,
        ack_deadline: options.ack_deadline,
        key_request_lifetime: options.key_request_lifetime,
        destroy_reconcile_interval: options.reconcile_interval,
        policy_next: options
            .policy_next
            .then(|| PolicyNextFile::new(policy_next.to_path_buf(), uid)),
    };
    DirdRun::start(params, admin, Arc::clone(store), policy())
}

fn change_seq_next(store: &Store) -> u64 {
    store
        .snapshot()
        .unwrap()
        .counter(CHANGE_SEQ_COUNTER)
        .unwrap()
        .unwrap()
        .next_value
}

fn rid_next(store: &Store) -> u64 {
    store
        .snapshot()
        .unwrap()
        .counter(RID_COUNTER)
        .unwrap()
        .unwrap()
        .next_value
}

impl World {
    fn new(options: Options) -> Option<World> {
        let dir = support::TempDir::new();
        let uid = support::my_uid(&dir);
        if support::skip_as_root(uid) {
            return None;
        }
        let store = provision(&dir.join("s.redb"), options.with_admin_service);
        // Task A16: dird's own `policy.next` directory.
        let scratch = test_scratch::ScratchDir::new("dd-pn").unwrap();
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(scratch.join("pn"))
                .unwrap();
        }

        // keyd: the test's uid is Role::Ldap (A-73); its own fake auditd.
        let keyd_params = keyd_params(&dir, uid);
        let keyd_socket = keyd_params.keyd_socket.clone();
        let keyd_admin_socket = dir.join("kk.sock");
        let keyd_directory_socket = dir.join("kd.sock");
        let keyd_auditd = support::FakeAuditd::start(&keyd_params.audit.socket);
        let clock = support::TestClock::at(common::keyd_started());
        let keyd = support::keyd::Daemon::start(keyd_params, clock.clone(), admin_keyd).unwrap();
        clock.set(common::now());

        // dird's auditd, with a hook recording the change-seq counter at
        // every Decision(Proceed) of a write.
        let seen_at_decision = Arc::new(Mutex::new(Vec::new()));
        let hook: Option<Hook> = if options.hook {
            let (store, seen) = (Arc::clone(&store), Arc::clone(&seen_at_decision));
            Some(Arc::new(move |event: &EventBody| {
                if let EventBody::DirAdmin(event) = event {
                    if event.stage == DirAdminStage::Decision(DecisionResult::Proceed) {
                        seen.lock()
                            .unwrap()
                            .push((change_seq_next(&store), event.operation_id));
                    }
                }
            }))
        } else {
            None
        };
        let auditd = AdminAuditd::start(&dir.join("a.sock"), hook);

        let clock_offset = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let admin_socket = dir.join("m.sock");
        let kdc_socket = dir.join("d.sock");
        let dird = start_dird(
            &dir,
            uid,
            &store,
            &admin_socket,
            &keyd_socket,
            &options,
            &clock_offset,
            &policy_next_path(&scratch),
        );
        Some(World {
            scratch,
            dir,
            uid,
            store,
            auditd,
            _keyd_auditd: keyd_auditd,
            keyd: Some(keyd),
            dird: Some(dird),
            admin_socket,
            kdc_socket,
            seen_at_decision,
            clock_offset,
            keyd_socket,
            keyd_admin_socket,
            keyd_directory_socket,
            options,
        })
    }

    /// A keyd client on `socket` (the test's uid, keyd's uid checked), that
    /// expects keyd to resolve it to `role` (task R9).
    fn keyd_client(
        &self,
        socket: &Path,
        role: keyd::Role,
    ) -> ipc_keyd::KeydClient<support::connector::KeydConnector> {
        ipc_keyd::KeydClient::new(
            support::connector::keyd(socket),
            ipc_keyd::ExpectedPeer::new(self.uid, role).unwrap(),
            ipc_keyd::DEFAULT_DEADLINE,
        )
    }

    /// keyadm's view of keyd (Role::Admin).
    fn keyadm(&self) -> ipc_keyd::KeydClient<support::connector::KeydConnector> {
        self.keyd_client(&self.keyd_admin_socket, keyd::Role::Admin)
    }

    /// admind's view of keyd (Role::Directory).
    fn admind_keyd(&self) -> ipc_keyd::KeydClient<support::connector::KeydConnector> {
        self.keyd_client(&self.keyd_directory_socket, keyd::Role::Directory)
    }

    /// Stop keyd and start it again on the same sockets and auditd, built by
    /// `build` — its decision table empty, as after every keyd start (A-102;
    /// the key sets are whatever `build` makes: a persistent store, P-17,
    /// would keep them).
    fn restart_keyd<F>(&mut self, build: F)
    where
        F: FnOnce(
                &KerberosTime,
            ) -> Result<
                Keyd<InMemoryKeyStore, RecordBuffer, common::TestEntropy>,
                keyd::ConfigError,
            > + Send
            + 'static,
    {
        if let Some(keyd) = self.keyd.take() {
            keyd.stop().unwrap();
        }
        let clock = support::TestClock::at(common::keyd_started());
        let keyd =
            support::keyd::Daemon::start(keyd_params(&self.dir, self.uid), clock.clone(), build)
                .unwrap();
        clock.set(common::now());
        self.keyd = Some(keyd);
    }

    /// Stop dird and start it again over the same store, keyd and auditd
    /// (task A10: a restart drops the pending key-operation requests).
    fn restart_dird(&mut self) {
        if let Some(dird) = self.dird.take() {
            dird.stop().unwrap();
        }
        self.dird = Some(start_dird(
            &self.dir,
            self.uid,
            &self.store,
            &self.admin_socket,
            &self.keyd_socket,
            &self.options,
            &self.clock_offset,
            &policy_next_path(&self.scratch),
        ));
    }

    fn client(&self) -> AdminClient<AdminConnector> {
        AdminClient::new(
            admin_connector::admin(&self.admin_socket),
            self.uid,
            ipc_dird_admin::DEFAULT_DEADLINE,
        )
        .unwrap()
    }

    fn object_named(&self, parent: Guid, rdn: &str) -> Option<Guid> {
        self.store
            .snapshot()
            .unwrap()
            .lookup_child(Some(parent), rdn.as_bytes())
            .unwrap()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        if let Some(dird) = self.dird.take() {
            let _ = dird.stop();
        }
        if let Some(keyd) = self.keyd.take() {
            let _ = keyd.stop();
        }
        let _ = &self.dir;
    }
}

fn created(reply: Reply) -> (Guid, Option<Sid>) {
    match reply {
        Reply::Created { guid, sid } => (guid, sid),
        other => panic!("expected Created, got {other:?}"),
    }
}

/// The operation's decision and outcome events, in arrival order.
fn events_of(world: &World, operation: DirAdminOperation) -> Vec<DirAdminEvent> {
    world
        .auditd
        .admin_events()
        .into_iter()
        .filter(|e| e.operation == operation)
        .collect()
}

/// Wait until auditd holds `count` events of `operation`.
fn await_events(world: &World, operation: DirAdminOperation, count: usize) -> Vec<DirAdminEvent> {
    assert!(
        support::eventually(Duration::from_secs(10), || events_of(world, operation)
            .len()
            >= count),
        "{operation:?}: {:?}",
        events_of(world, operation)
    );
    events_of(world, operation)
}

fn is_committed(event: &DirAdminEvent) -> bool {
    matches!(
        event.stage,
        DirAdminStage::Outcome(OutcomeResult::Committed { .. })
    )
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

/// docs/51 §7.3, §7.4, §5.7 (R51-12); A-85; A-89: every operation end to end
/// over the socket with its reply; for each write the decision event is
/// acknowledged by auditd before the commit (the store's change-seq counter
/// has not moved when auditd receives it) and the outcome event follows it
/// with the same operation number; `Lookup` and `CompletePasswordSet` have
/// their decision event only.
#[test]
fn every_operation_end_to_end() {
    let Some(world) = World::new(Options {
        hook: true,
        ..Options::default()
    }) else {
        return;
    };
    let mut client = world.client();
    client.ping().unwrap();

    // CreateUser.
    let first_rid = rid_next(&world.store);
    let seq_before = change_seq_next(&world.store);
    let (carol, carol_sid) = created(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::CreateUser {
                    parent: g(STAFF_OU),
                    sam: "carol".into(),
                    upn: Some("carol@example.org".into()),
                    description: Some("Staff account".into()),
                },
            ))
            .unwrap(),
    );
    assert_eq!(
        carol_sid,
        Some(sid_with_rid(u32::try_from(first_rid).unwrap()))
    );
    assert_eq!(world.object_named(g(STAFF_OU), "carol"), Some(carol));
    assert_eq!(rid_next(&world.store), first_rid + 1);
    assert_eq!(change_seq_next(&world.store), seq_before + 1);
    let events = await_events(&world, DirAdminOperation::CreateUser, 2);
    assert_eq!(
        events[0].stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    assert!(is_committed(&events[1]));
    assert_eq!(events[0].operation_id, events[1].operation_id);
    assert_eq!(
        world.seen_at_decision.lock().unwrap().first().copied(),
        Some((seq_before, events[0].operation_id)),
        "auditd saw the decision before anything was committed"
    );

    // CreateComputer (with its SPN).
    let (ws9, ws9_sid) = created(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::CreateComputer {
                    parent: g(STAFF_OU),
                    name: "ws9".into(),
                    dns_host_name: "ws9.example.org".into(),
                    spn: Some("host/ws9.example.org".into()),
                },
            ))
            .unwrap(),
    );
    assert_eq!(
        ws9_sid,
        Some(sid_with_rid(u32::try_from(first_rid + 1).unwrap()))
    );

    // CreateGroup (the default groupType).
    let (team, team_sid) = created(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::CreateGroup {
                    parent: g(STAFF_OU),
                    sam: "team".into(),
                    group_type: None,
                },
            ))
            .unwrap(),
    );
    assert!(team_sid.is_some());

    // CreateOu and CreateContainer: no SID.
    let (branch, branch_sid) = created(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::CreateOu {
                    parent: g(ROOT),
                    name: "Branch".into(),
                },
            ))
            .unwrap(),
    );
    assert_eq!(branch_sid, None);
    let (things, things_sid) = created(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::CreateContainer {
                    parent: branch,
                    name: "Things".into(),
                },
            ))
            .unwrap(),
    );
    assert_eq!(things_sid, None);
    assert_eq!(world.object_named(branch, "Things"), Some(things));

    // BeginPasswordSet: a user has one key target, a computer with its SPN
    // two; the salt is the account's ([MS-KILE] 3.1.1.2 via account_salt).
    match client
        .call(&by(
            "admin1",
            &[],
            Operation::BeginPasswordSet { target: carol },
        ))
        .unwrap()
    {
        Reply::PasswordSet(set) => {
            assert_eq!(set.kind, AccountKind::User);
            assert_eq!(set.keys.len(), 1);
            assert_eq!(
                set.keys[0].handle,
                KeyHandle::new(
                    keyd::PrincipalId::from_bytes(carol.to_packet()),
                    KeyPurpose::PrincipalLongterm
                )
            );
            assert_eq!(set.keys[0].binding.name, principal("carol"));
            assert_eq!(set.salt.as_str(), "EXAMPLE.ORGcarol");
        }
        other => panic!("{other:?}"),
    }
    match client
        .call(&by(
            "admin1",
            &[],
            Operation::BeginPasswordSet { target: ws9 },
        ))
        .unwrap()
    {
        Reply::PasswordSet(set) => {
            assert_eq!(set.kind, AccountKind::Computer);
            assert_eq!(set.keys.len(), 2);
            assert_eq!(set.keys[1].handle.purpose, KeyPurpose::Service);
        }
        other => panic!("{other:?}"),
    }

    // CompletePasswordSet: audit only.
    assert_eq!(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::CompletePasswordSet {
                    target: carol,
                    outcome: PasswordSetOutcome::Completed,
                    kvnos: vec![1],
                },
            ))
            .unwrap(),
        Reply::Done
    );
    let complete = await_events(&world, DirAdminOperation::CompletePasswordSet, 1);
    assert_eq!(complete.len(), 1, "decision only");

    // SetEnabled, SetAccountExpires.
    assert_eq!(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::SetEnabled {
                    target: carol,
                    enabled: true,
                },
            ))
            .unwrap(),
        Reply::Done
    );
    assert_eq!(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::SetAccountExpires {
                    target: carol,
                    value: AccountExpires::At(134_500_000_000_000_000),
                },
            ))
            .unwrap(),
        Reply::Done
    );

    // AddMember, RemoveMember.
    for operation in [
        Operation::AddMember {
            group: team,
            member: carol,
        },
        Operation::RemoveMember {
            group: team,
            member: carol,
        },
    ] {
        assert_eq!(
            client.call(&by("admin1", &[], operation)).unwrap(),
            Reply::Done
        );
    }

    // Lookup by sAMAccountName, SPN and DN; an absent name is NotFound.
    let expect_carol = |reply: Reply| match reply {
        Reply::Found(found) => {
            assert_eq!(found.guid, carol);
            assert_eq!(found.class, "user");
            assert_eq!(found.sid, carol_sid);
            assert_eq!(found.dn, ["cn=carol", "ou=Staff", "dc=example", "dc=org"]);
        }
        other => panic!("{other:?}"),
    };
    expect_carol(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::Lookup(LookupKey::SamAccountName("carol".into())),
            ))
            .unwrap(),
    );
    expect_carol(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::Lookup(LookupKey::Dn(vec![
                    "cn=carol".into(),
                    "ou=Staff".into(),
                    "dc=example".into(),
                    "dc=org".into(),
                ])),
            ))
            .unwrap(),
    );
    match client
        .call(&by(
            "admin1",
            &[],
            Operation::Lookup(LookupKey::ServicePrincipalName(
                "host/ws9.example.org".into(),
            )),
        ))
        .unwrap()
    {
        Reply::Found(found) => {
            assert_eq!(found.guid, ws9);
            assert_eq!(found.class, "computer");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::Lookup(LookupKey::SamAccountName("nobody".into())),
            ))
            .unwrap(),
        Reply::Refused(RefusalStatus::NotFound)
    );

    // Delete.
    assert_eq!(
        client
            .call(&by("admin1", &[], Operation::Delete { target: things }))
            .unwrap(),
        Reply::Done
    );
    assert_eq!(world.object_named(branch, "Things"), None);

    // Every write: a decision acknowledged before its commit, then its
    // outcome with the same number.
    let writes = [
        DirAdminOperation::CreateUser,
        DirAdminOperation::CreateComputer,
        DirAdminOperation::CreateGroup,
        DirAdminOperation::CreateOu,
        DirAdminOperation::CreateContainer,
        DirAdminOperation::BeginPasswordSet,
        DirAdminOperation::SetEnabled,
        DirAdminOperation::SetAccountExpires,
        DirAdminOperation::AddMember,
        DirAdminOperation::RemoveMember,
        DirAdminOperation::Delete,
    ];
    let all = await_events(&world, DirAdminOperation::Delete, 2);
    assert!(is_committed(&all[1]));
    let events = world.auditd.admin_events();
    let seen = world.seen_at_decision.lock().unwrap().clone();
    for operation in writes {
        let of: Vec<&DirAdminEvent> = events.iter().filter(|e| e.operation == operation).collect();
        assert!(of.len() >= 2, "{operation:?}");
        for pair in of.chunks(2) {
            assert_eq!(
                pair[0].stage,
                DirAdminStage::Decision(DecisionResult::Proceed)
            );
            assert!(is_committed(pair[1]), "{operation:?}");
            assert_eq!(pair[0].operation_id, pair[1].operation_id);
            let decision_index = events.iter().position(|e| e == pair[0]).unwrap();
            let outcome_index = events.iter().position(|e| e == pair[1]).unwrap();
            assert!(decision_index < outcome_index, "{operation:?}");
            // When auditd held the decision, nothing of the operation had
            // been committed: the counter moved only afterwards.
            let at_decision = seen
                .iter()
                .find(|(_, id)| *id == pair[0].operation_id)
                .map(|(seq, _)| *seq)
                .unwrap();
            assert!(at_decision < change_seq_next(&world.store), "{operation:?}");
        }
    }
    let lookups = events_of(&world, DirAdminOperation::Lookup);
    assert_eq!(lookups.len(), 4, "decision only, one per Lookup");
    // Each write's decision found the counter where the previous write had
    // left it: strictly increasing over the writes (writes are serialized).
    let write_ids: Vec<u64> = events
        .iter()
        .filter(|e| writes.contains(&e.operation))
        .map(|e| e.operation_id)
        .collect();
    let values: Vec<u64> = seen
        .iter()
        .filter(|(_, id)| write_ids.contains(id))
        .map(|(seq, _)| *seq)
        .collect();
    assert_eq!(values.len(), 12, "{values:?}");
    assert!(values.windows(2).all(|w| w[0] < w[1]), "{values:?}");
}

/// docs/51 §5.7 item 2; A-85: an auditd that withholds its
/// acknowledgements ⇒ the write is refused `Unavailable` and nothing is
/// committed; when auditd is back, the decision and a not-performed outcome
/// reach it. The wait is the production one (the expiry is what is tested,
/// and auditd never acknowledges while it lasts — A-95 follow-up, Q-441).
#[test]
fn no_acknowledgement_means_nothing_is_committed() {
    let Some(world) = World::new(Options {
        ack_deadline: DecisionAckDeadline::PRODUCTION,
        ..Options::default()
    }) else {
        return;
    };
    let mut client = world.client();
    client.ping().unwrap();
    let (rid_before, seq_before) = (rid_next(&world.store), change_seq_next(&world.store));
    world.auditd.withhold(true);
    let started = Instant::now();
    let reply = client
        .call(&by(
            "admin1",
            &[],
            Operation::CreateUser {
                parent: g(STAFF_OU),
                sam: "withheld".into(),
                upn: None,
                description: None,
            },
        ))
        .unwrap();
    assert_eq!(reply, Reply::Refused(RefusalStatus::Unavailable));
    assert!(started.elapsed() >= DECISION_ACK_DEADLINE);
    assert_eq!(world.object_named(g(STAFF_OU), "withheld"), None);
    assert_eq!(rid_next(&world.store), rid_before);
    assert_eq!(change_seq_next(&world.store), seq_before);
    world.auditd.withhold(false);
    let events = await_events(&world, DirAdminOperation::CreateUser, 2);
    assert_eq!(
        events[0].stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    // Its own code (A-91, Q-397): not performed because the decision was
    // not acknowledged — not an `InternalFailure`.
    assert_eq!(
        events[1].stage,
        DirAdminStage::Outcome(OutcomeResult::Failed(
            ipc_audit::AdminFailure::AuditUnacknowledged
        ))
    );
    assert_eq!(events[0].operation_id, events[1].operation_id);
    assert_eq!(world.object_named(g(STAFF_OU), "withheld"), None);
}

/// docs/11 §2 ("the PEP must honour obligations"), §8 (`RateLimit` with a
/// request-derived key); docs/questions/Q-358 item 7, Q-388 item 2; A-91
/// (Q-397: the refusal has its own code). Every Allow carries the PDP's
/// `RateLimit(requester, Directory)` obligation, which dird's admin thread
/// honours with its fixed-window limiter (`OBLIGATION_LIMIT` requests per
/// key per `OBLIGATION_WINDOW_SECS` of the request's `now`; dird's clock is
/// fixed in these tests, so every request falls in one window). An
/// administrator's `Lookup`s are served up to the limit; the next one is
/// answered `Denied`, and its decision event says
/// `Refused(ObligationRefused)` with the PDP reason still `Allowed` — not a
/// PDP deny. Another administrator (another key) is still served.
#[test]
fn an_obligation_dird_cannot_honour_is_refused_with_its_own_code() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    client.ping().unwrap();
    let lookup = || Operation::Lookup(LookupKey::SamAccountName("bob".into()));
    for i in 0..directory_daemon::rate::OBLIGATION_LIMIT {
        assert!(
            matches!(
                client.call(&by("admin1", &[], lookup())).unwrap(),
                Reply::Found(_)
            ),
            "lookup {i}"
        );
    }
    assert_eq!(
        client.call(&by("admin1", &[], lookup())).unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    // Another requester is another rate-limit key.
    assert!(matches!(
        client.call(&by("admin2", &[], lookup())).unwrap(),
        Reply::Found(_)
    ));
    let count = usize::try_from(directory_daemon::rate::OBLIGATION_LIMIT).unwrap() + 2;
    let events = await_events(&world, DirAdminOperation::Lookup, count);
    assert_eq!(events.len(), count, "one decision event per Lookup");
    let refused = &events[count - 2];
    assert_eq!(
        refused.stage,
        DirAdminStage::Decision(DecisionResult::Refused(
            ipc_audit::AdminRefusal::ObligationRefused
        ))
    );
    assert_eq!(
        refused.pdp.map(|reason| reason.code),
        Some(ipc_audit::PdpReasonCode::Allowed),
        "the PDP allowed it"
    );
    for (i, event) in events.iter().enumerate() {
        if i != count - 2 {
            assert_eq!(
                event.stage,
                DirAdminStage::Decision(DecisionResult::Proceed),
                "event {i}"
            );
        }
    }
    assert_ne!(events[count - 1].requester, refused.requester);
}

/// docs/51 §7.4 step 1; A-26; A-56: a bad AP-REQ and an expired one ⇒
/// `Denied`; keyd down ⇒ `Unavailable`; the store unchanged each time, and
/// each refusal recorded.
#[test]
fn bad_or_expired_tickets_and_keyd_down() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    let refused_ou = Operation::CreateOu {
        parent: g(ROOT),
        name: "Refused".into(),
    };
    let create = |requester: Vec<u8>| Request::Operation {
        auth: Auth {
            requester,
            approvals: Vec::new(),
        },
        operation: refused_ou.clone(),
    };
    let seq_before = change_seq_next(&world.store);
    // Not an AP-REQ at all.
    assert_eq!(
        client
            .call(&create(vec![0x30, 0x03, 0x02, 0x01, 0x05]))
            .unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    // Expired at 09:00 (keyd's skew is minutes; now is 10:00).
    let expired = ap_req(
        "admin1",
        CUSEC.fetch_add(1, Ordering::SeqCst),
        common::kt("20261113090000Z"),
        &refused_ou,
    );
    assert_eq!(
        client.call(&create(expired)).unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    // The same AP-REQ twice: keyd's replay cache (RFC 4120 §3.2.3) — the
    // second time for the same operation, the third for another (which R2
    // refuses before the replay cache: the binding does not match).
    let once = fresh("admin1", &refused_ou);
    assert!(matches!(
        client.call(&create(once.clone())).unwrap(),
        Reply::Created { .. }
    ));
    let seq_after_one = change_seq_next(&world.store);
    assert_eq!(seq_after_one, seq_before + 1);
    assert_eq!(
        client.call(&create(once.clone())).unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    assert_eq!(
        client
            .call(&Request::Operation {
                auth: Auth {
                    requester: once,
                    approvals: Vec::new(),
                },
                operation: Operation::CreateOu {
                    parent: g(ROOT),
                    name: "Replayed".into(),
                },
            })
            .unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    // keyd down.
    world.keyd.take().unwrap().stop().unwrap();
    assert_eq!(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::CreateOu {
                    parent: g(ROOT),
                    name: "KeydDown".into(),
                }
            ))
            .unwrap(),
        Reply::Refused(RefusalStatus::Unavailable)
    );
    assert_eq!(change_seq_next(&world.store), seq_after_one);
    assert_eq!(world.object_named(g(ROOT), "Replayed"), None);
    assert_eq!(world.object_named(g(ROOT), "KeydDown"), None);
    let events = await_events(&world, DirAdminOperation::CreateOu, 7);
    let decisions: Vec<&DirAdminStage> = events
        .iter()
        .filter(|e| matches!(e.stage, DirAdminStage::Decision(_)))
        .map(|e| &e.stage)
        .collect();
    use ipc_audit::{AdminFailure, AdminRefusal};
    assert_eq!(
        decisions,
        [
            &DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::Unauthenticated)),
            &DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::Unauthenticated)),
            &DirAdminStage::Decision(DecisionResult::Proceed),
            &DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::Unauthenticated)),
            &DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::Unauthenticated)),
            &DirAdminStage::Decision(DecisionResult::Failed(AdminFailure::KeydUnavailable)),
        ]
    );
}

/// docs/51 §5.6 (R51-11); P-22; Q-357: a change to the Tier-0 group's
/// membership needs an approver — without one ⇒ `ApprovalRequired`; a
/// second Tier-0 administrator's AP-REQ satisfies it; the same principal
/// twice (two distinct, valid AP-REQs of admin1) ⇒ `Denied`.
#[test]
fn dual_control() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    let add = || Operation::AddMember {
        group: g(TIER0_GROUP),
        member: g(BOB),
    };
    assert_eq!(
        client.call(&by("admin1", &[], add())).unwrap(),
        Reply::Refused(RefusalStatus::ApprovalRequired)
    );
    assert_eq!(
        client.call(&by("admin1", &["admin1"], add())).unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    let seq = change_seq_next(&world.store);
    assert_eq!(
        client.call(&by("admin1", &["admin2"], add())).unwrap(),
        Reply::Done
    );
    assert_eq!(change_seq_next(&world.store), seq + 1);
    let events = await_events(&world, DirAdminOperation::AddMember, 4);
    assert_eq!(
        events[1].stage,
        DirAdminStage::Decision(DecisionResult::Refused(
            ipc_audit::AdminRefusal::ApproverNotDistinct
        ))
    );
    let approved = &events[2];
    assert_eq!(
        approved.stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    assert_eq!(approved.approvers.len(), 1);
}

/// R2 — the Q-292 attack (docs/52 §3.2, class C2; §5): admind forwards
/// AP-REQs untouched, so a compromised admind could take an
/// administrator's valid AP-REQ made for one operation and attach it to
/// another. dird computes the digest of the operation it decoded and keyd
/// verifies the Authenticator's `cksum` against it: the attached AP-REQ is
/// `Denied` (`Unauthenticated`), the store unchanged — and the same AP-REQ
/// still serves, once, the operation it was made for. An AP-REQ without
/// any `cksum` (an admin ticket with no binding) cannot be used at all.
#[test]
fn an_ap_req_attached_to_another_operation_is_denied() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    let meant = Operation::CreateOu {
        parent: g(ROOT),
        name: "Meant".into(),
    };
    let hijacked = Operation::CreateOu {
        parent: g(ROOT),
        name: "Hijacked".into(),
    };
    let ap_req = fresh("admin1", &meant);
    let attach = |requester: Vec<u8>, operation: &Operation| Request::Operation {
        auth: Auth {
            requester,
            approvals: Vec::new(),
        },
        operation: operation.clone(),
    };
    let seq = change_seq_next(&world.store);
    assert_eq!(
        client.call(&attach(ap_req.clone(), &hijacked)).unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    // A delete of a user, from the same AP-REQ: refused too.
    assert_eq!(
        client
            .call(&attach(
                ap_req.clone(),
                &Operation::Delete { target: g(BOB) }
            ))
            .unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    // No cksum at all.
    let unbound = ap_req_with(
        "admin1",
        CUSEC.fetch_add(1, Ordering::SeqCst),
        common::kt("20261113170000Z"),
        None,
    );
    assert_eq!(
        client.call(&attach(unbound, &meant)).unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    assert_eq!(change_seq_next(&world.store), seq);
    assert_eq!(world.object_named(g(ROOT), "Hijacked"), None);
    assert_eq!(world.object_named(g(ROOT), "Meant"), None);
    // The operation it was made for: performed.
    assert!(matches!(
        client.call(&attach(ap_req, &meant)).unwrap(),
        Reply::Created { .. }
    ));
    assert_eq!(change_seq_next(&world.store), seq + 1);
    let events = await_events(&world, DirAdminOperation::CreateOu, 4);
    use ipc_audit::AdminRefusal;
    assert_eq!(
        events[0].stage,
        DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::Unauthenticated))
    );
    let deletes = await_events(&world, DirAdminOperation::Delete, 1);
    assert_eq!(
        deletes[0].stage,
        DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::Unauthenticated))
    );
}

/// R2 (docs/52 §5 items 1, 4): an approver's AP-REQ authorizes exactly the
/// request it was made for. admin2's valid AP-REQ made for another
/// operation does not approve this Tier-0 membership change (`Denied`,
/// recorded `ApproverUnauthenticated`), nor does one made for the same
/// change of another member; bound to this request it does.
#[test]
fn an_approval_bound_to_another_operation_is_refused() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    let add = |member| Operation::AddMember {
        group: g(TIER0_GROUP),
        member: g(member),
    };
    let seq = change_seq_next(&world.store);
    for elsewhere in [
        Operation::CreateOu {
            parent: g(ROOT),
            name: "Elsewhere".into(),
        },
        add(STAFF_GROUP),
    ] {
        let request = Request::Operation {
            auth: Auth {
                requester: fresh("admin1", &add(BOB)),
                approvals: vec![fresh("admin2", &elsewhere)],
            },
            operation: add(BOB),
        };
        assert_eq!(
            client.call(&request).unwrap(),
            Reply::Refused(RefusalStatus::Denied)
        );
    }
    assert_eq!(change_seq_next(&world.store), seq);
    assert_eq!(
        client.call(&by("admin1", &["admin2"], add(BOB))).unwrap(),
        Reply::Done
    );
    let events = await_events(&world, DirAdminOperation::AddMember, 3);
    for event in &events[..2] {
        assert_eq!(
            event.stage,
            DirAdminStage::Decision(DecisionResult::Refused(
                ipc_audit::AdminRefusal::ApproverUnauthenticated
            ))
        );
    }
}

/// docs/51 §7.1 ("the only peer = `admind_uid`; another uid ⇒ close +
/// count"): a client whose uid is not admind's is closed without a reply.
#[test]
fn a_wrong_peer_uid_is_closed() {
    let Some(world) = World::new(Options {
        admind_uid_offset: 7,
        ..Options::default()
    }) else {
        return;
    };
    let before = admin_refused_peer_count();
    let mut client = world.client();
    assert!(matches!(client.ping(), Err(Unserved::Transport(_))));
    assert!(admin_refused_peer_count() > before);
}

/// docs/50 §3.3 ("`length` checked against the MAX … before any body byte
/// is allocated or read"); docs/51 §7.5: a declared body over 256 KiB
/// closes the connection before any body octet is sent.
#[test]
fn an_oversize_frame_is_closed_before_its_body() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut stream = UnixStream::connect(&world.admin_socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(&(MAX_REQUEST_BODY + 1).to_be_bytes())
        .unwrap();
    let mut octet = [0u8; 1];
    assert_eq!(stream.read(&mut octet).unwrap(), 0, "closed, no reply");
    // dird serves on.
    world.client().ping().unwrap();
}

/// docs/51 §7.5 ("a bounded queue (full ⇒ `Busy`)"): with the admin thread
/// held (waiting for an acknowledgement auditd withholds) and its queue
/// full, a further request is answered `Busy`. (Three connections here so
/// the queue of one can fill; dird's bound for admind is two.)
#[test]
fn a_full_queue_answers_busy() {
    // The generous wait (the default, the ceiling): the held request must
    // still be waiting for its acknowledgement after the sleeps below and
    // two more connections (A-95 follow-up; docs/questions/Q-417 item 3).
    let Some(world) = World::new(Options {
        max_connections: 3,
        queue_capacity: 1,
        ack_deadline: generous(),
        ..Options::default()
    }) else {
        return;
    };
    {
        // dird answers; this connection is closed again, so the three
        // below are within the bound.
        let mut warm = world.client();
        warm.ping().unwrap();
    }
    world.auditd.withhold(true);
    let spawn = |name: &'static str| {
        let mut client = world.client();
        let request = by(
            "admin1",
            &[],
            Operation::CreateOu {
                parent: g(ROOT),
                name: name.into(),
            },
        );
        std::thread::spawn(move || client.call(&request))
    };
    let held = spawn("Held");
    std::thread::sleep(Duration::from_millis(500));
    let queued = spawn("Queued");
    std::thread::sleep(Duration::from_millis(300));
    let mut third = world.client();
    assert_eq!(
        third.call(&by(
            "admin1",
            &[],
            Operation::CreateOu {
                parent: g(ROOT),
                name: "Third".into(),
            },
        )),
        Err(Unserved::Refused(Refused::Busy))
    );
    assert_eq!(
        held.join().unwrap(),
        Ok(Reply::Refused(RefusalStatus::Unavailable))
    );
    assert_eq!(
        queued.join().unwrap(),
        Ok(Reply::Refused(RefusalStatus::Unavailable))
    );
    world.auditd.withhold(false);
    assert_eq!(world.object_named(g(ROOT), "Held"), None);
}

/// docs/51 §4.6; A-73 ("refuse to start the admin service if [the admin
/// service object] is absent"): without the admin service object the admin
/// socket is never bound, and dird's directory-view service still answers.
#[test]
fn without_the_admin_service_object_dird_serves_on() {
    let Some(world) = World::new(Options {
        with_admin_service: false,
        ..Options::default()
    }) else {
        return;
    };
    assert!(!world.admin_socket.exists());
    assert!(matches!(world.client().ping(), Err(Unserved::Transport(_))));
    let mut directory = ipc_directory::DirectoryClient::connect(
        support::connector::dird(&world.kdc_socket),
        world.uid,
        ipc_directory::DEFAULT_DEADLINE,
        PolicyVersion(1),
    )
    .unwrap();
    assert_eq!(directory.domain().realm, common::realm());
    let domain = directory.describe_domain().unwrap();
    assert_eq!(domain.realm, common::realm());
}

// ---------------------------------------------------------------------------
// Task A10: dual-controlled key operations (docs/51 §5.6, §6).
// ---------------------------------------------------------------------------

use ipc_dird_admin::{KeyOperation, KeyRef, KeyRequestState};

fn key_state(reply: Reply) -> KeyRequestState {
    match reply {
        Reply::KeyRequest(state) => state,
        other => panic!("expected KeyRequest, got {other:?}"),
    }
}

fn request_op(requester: &str, operation: KeyOperation) -> Request {
    by(requester, &[], Operation::RequestKeyOperation { operation })
}

fn approve_op(approver: &str, id: u64, operation: KeyOperation) -> Request {
    by(approver, &[], Operation::Approve { id, operation })
}

fn decision(event: &DirAdminEvent) -> DirAdminStage {
    event.stage
}

fn refused(refusal: ipc_audit::AdminRefusal) -> DirAdminStage {
    DirAdminStage::Decision(DecisionResult::Refused(refusal))
}

const PROCEED: DirAdminStage = DirAdminStage::Decision(DecisionResult::Proceed);

fn sid_value(sid: &Sid) -> ipc_audit::SidValue {
    ipc_audit::SidValue::new(sid.identifier_authority(), sid.sub_authority().to_vec()).unwrap()
}

/// docs/51 §5.6, §6 (R51-11, R51-14); P-22; A-85; docs/52 §4.2, §4.3, §4.5
/// (A-102): `rotate_krbtgt` from request to execution — admin1 requests
/// (PolicyAdmin on `keys`), an approval naming another operation is refused
/// (the digest binds), admin2's approval completes the quorum and **dird
/// registers the decision in keyd** (Role::Ldap, its decision event
/// acknowledged first, then an `Outcome` event of the registration); keyadm
/// (Role::Admin on the same keyd) executes it by the request's id — kvno 2
/// with the approvers keyd took from the decision — and a replay returns the
/// recorded result. Nothing of the directory is written.
#[test]
fn rotate_krbtgt_request_approve_registers_the_decision() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    let seq = change_seq_next(&world.store);
    let state = key_state(
        client
            .call(&request_op("admin1", KeyOperation::RotateKrbtgt))
            .unwrap(),
    );
    assert_eq!(state.operation, KeyOperation::RotateKrbtgt);
    assert_eq!((state.approvals, state.quorum), (0, 2));
    let id = state.id;
    // Not approved yet: keyd holds no decision.
    let mut keyadm = world.keyadm();
    assert_eq!(
        keyadm.rotate_krbtgt(DecisionId::new(id)),
        Ok(Err(keyd::Error::Denied))
    );
    // An approval naming another operation is refused (the digest binds).
    assert_eq!(
        client
            .call(&approve_op(
                "admin2",
                id,
                KeyOperation::RotateKey {
                    service: g(LDAP_SVC)
                }
            ))
            .unwrap(),
        Reply::Refused(RefusalStatus::Invalid)
    );
    // The approval: the digest and the operation are shown back.
    let approved = key_state(
        client
            .call(&approve_op("admin2", id, KeyOperation::RotateKrbtgt))
            .unwrap(),
    );
    assert_eq!(approved.id, id);
    assert_eq!(approved.digest, state.digest);
    assert!(approved.approved());
    // A further approval after the quorum ⇒ refused.
    assert_eq!(
        client
            .call(&approve_op("admin1", id, KeyOperation::RotateKrbtgt))
            .unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    // keyadm executes the decision by the request's id; a replay returns
    // the recorded kvno (docs/52 §3.10 (a)).
    assert_eq!(
        keyadm.rotate_krbtgt(DecisionId::new(id)),
        Ok(Ok(Kvno::new(2)))
    );
    assert_eq!(
        keyadm.rotate_krbtgt(DecisionId::new(id)),
        Ok(Ok(Kvno::new(2)))
    );
    assert_eq!(change_seq_next(&world.store), seq, "nothing written");

    // dird's trail: the completing approval's decision, then the
    // registration's outcome.
    let requested = await_events(&world, DirAdminOperation::RequestKeyOperation, 1);
    assert_eq!(decision(&requested[0]), PROCEED);
    assert_eq!(requested[0].key_request, Some(id));
    assert_eq!(requested[0].target, Some(g(KRBTGT).to_packet()));
    let approvals = await_events(&world, DirAdminOperation::Approve, 4);
    assert_eq!(
        decision(&approvals[0]),
        refused(ipc_audit::AdminRefusal::OperationMismatch)
    );
    assert_eq!(decision(&approvals[1]), PROCEED);
    assert_eq!(approvals[1].requester, Some(sid_value(&sid_of(ADMIN1))));
    assert_eq!(
        approvals[1].approvers.as_slice(),
        &[sid_value(&sid_of(ADMIN2))]
    );
    assert_eq!(
        approvals[2].stage,
        DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
    );
    assert_eq!(approvals[1].operation_id, approvals[2].operation_id);
    assert_eq!(approvals[2].key_request, Some(id));
    assert_eq!(
        decision(&approvals[3]),
        refused(ipc_audit::AdminRefusal::ApproverNotDistinct)
    );
    // keyd's trail: dird registered it (intent, then success) with the
    // requester and approver from the decision; keyadm's execution carries
    // the decision id and those approvers.
    let registered = keyd_records_for(
        &world,
        ipc_audit::KeydOperation::RegisterDecision,
        g(KRBTGT),
    );
    assert_eq!(registered.len(), 2);
    assert_eq!(registered[0].result, ipc_audit::KeydOutcome::Intent);
    assert_eq!(registered[1].result, ipc_audit::KeydOutcome::Success);
    assert_eq!(registered[1].caller_role, ipc_audit::KeydRole::Ldap);
    assert_eq!(registered[1].decision, Some(id));
    assert_eq!(
        registered[1].approvers,
        Some([g(ADMIN1).to_packet(), g(ADMIN2).to_packet()])
    );
    let rotations = keyd_records_for(&world, ipc_audit::KeydOperation::RotateKrbtgt, g(KRBTGT));
    let performed: Vec<_> = rotations
        .iter()
        .filter(|r| r.result == ipc_audit::KeydOutcome::Success && r.decision == Some(id))
        .collect();
    assert_eq!(performed.len(), 2, "the execution and its replay");
    assert_eq!(performed[0].kvno, Some(2));
    assert_eq!(performed[0].caller_role, ipc_audit::KeydRole::Admin);
    assert_eq!(
        performed[0].approvers,
        Some([g(ADMIN1).to_packet(), g(ADMIN2).to_packet()])
    );
    assert_eq!(performed[1].reason, ipc_audit::KeydReason::DecisionReplayed);
}

/// docs/51 §6 (`rotate-key` of a service object's randomized key set,
/// `retire-kvno` after it); docs/52 §4.3 (A-102): each approved request
/// becomes a decision keyadm executes in keyd by its id — the LDAP service
/// key set rotated to kvno 2, then its kvno 1 retired; a computer that is
/// not a service object, and a kvno 0 to retire, are refused at the
/// request; executing a decision with the wrong operation is refused and
/// does not consume it (keyd's rule, through dird's decision).
#[test]
fn rotate_key_and_retire_kvno_decisions_are_executed_by_id() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    let mut keyadm = world.keyadm();
    let rotate = KeyOperation::RotateKey {
        service: g(LDAP_SVC),
    };
    let state = key_state(client.call(&request_op("admin1", rotate)).unwrap());
    key_state(
        client
            .call(&approve_op("admin2", state.id, rotate))
            .unwrap(),
    );
    let id = DecisionId::new(state.id);
    assert_eq!(keyadm.retire_kvno(id), Ok(Err(keyd::Error::Denied)));
    assert_eq!(keyadm.rotate_key(id), Ok(Ok(Kvno::new(2))));
    // Not a service object (a user), and a kvno 0 to retire.
    for operation in [
        KeyOperation::RotateKey { service: g(BOB) },
        KeyOperation::RetireKvno {
            key: KeyRef::Krbtgt,
            kvno: 0,
        },
    ] {
        assert_eq!(
            client.call(&request_op("admin1", operation)).unwrap(),
            Reply::Refused(RefusalStatus::Invalid)
        );
    }
    // retire_kvno of the LDAP service key set's kvno 1, now previous.
    let retire = KeyOperation::RetireKvno {
        key: KeyRef::Service(g(LDAP_SVC)),
        kvno: 1,
    };
    let state = key_state(client.call(&request_op("admin1", retire)).unwrap());
    key_state(
        client
            .call(&approve_op("admin2", state.id, retire))
            .unwrap(),
    );
    assert_eq!(keyadm.retire_kvno(DecisionId::new(state.id)), Ok(Ok(())));
    let approvals = await_events(&world, DirAdminOperation::Approve, 4);
    assert_eq!(
        approvals[1].stage,
        DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
    );
    assert_eq!(approvals[1].target, Some(g(LDAP_SVC).to_packet()));
    assert_eq!(
        approvals[3].stage,
        DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
    );
}

/// docs/52 R2b; docs/questions/Q-493 item 1 (the follow-up of R2): the
/// admin service object's key set — `(GUID, AdminService)`, the purpose its
/// name `admind/<host>` derives (Q-491 item 1) — is rotated and its old kvno
/// retired through the admin plane: dird registers each decision on the
/// `AdminService` key set (keyd's records name that purpose, not
/// `Service`), and keyadm's execution in keyd succeeds — before R2b dird
/// named `(GUID, Service)` and keyd answered `KeyNotFound`. Every AP-REQ is
/// made before the rotation runs (they are sealed under the admin key's
/// kvno 1); keyadm runs both decisions afterwards.
#[test]
fn the_admin_service_key_is_rotated_and_retired_through_the_admin_plane() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    let mut keyadm = world.keyadm();
    let rotate = KeyOperation::RotateKey {
        service: g(ADMIND_SVC),
    };
    let retire = KeyOperation::RetireKvno {
        key: KeyRef::Service(g(ADMIND_SVC)),
        kvno: 1,
    };
    let mut ids = Vec::new();
    for operation in [rotate, retire] {
        let state = key_state(client.call(&request_op("admin1", operation)).unwrap());
        let approved = key_state(
            client
                .call(&approve_op("admin2", state.id, operation))
                .unwrap(),
        );
        assert!(approved.approved());
        ids.push(DecisionId::new(state.id));
    }
    assert_eq!(keyadm.rotate_key(ids[0]), Ok(Ok(Kvno::new(2))));
    assert_eq!(keyadm.retire_kvno(ids[1]), Ok(Ok(())));
    // keyd's trail: both registrations and both executions name the admin
    // service's own key set.
    for op in [
        ipc_audit::KeydOperation::RegisterDecision,
        ipc_audit::KeydOperation::RotateKey,
        ipc_audit::KeydOperation::RetireKvno,
    ] {
        let records = keyd_records_for(&world, op, g(ADMIND_SVC));
        let succeeded: Vec<_> = records
            .iter()
            .filter(|r| r.result == ipc_audit::KeydOutcome::Success)
            .collect();
        assert!(!succeeded.is_empty(), "{op:?}");
        assert!(
            succeeded
                .iter()
                .all(|r| r.purpose == Some(ipc_audit::KeyPurposeCode::AdminService)),
            "{op:?}: {succeeded:?}"
        );
    }
    // dird's trail: each completing approval's registration committed, on
    // the admin service object.
    let approvals = await_events(&world, DirAdminOperation::Approve, 4);
    for outcome in [&approvals[1], &approvals[3]] {
        assert_eq!(
            outcome.stage,
            DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
        );
        assert_eq!(outcome.target, Some(g(ADMIND_SVC).to_packet()));
    }
}

/// docs/52 §4.3 (A-102); docs/questions/Q-453 item 1 (fail closed): when
/// keyd does not register the decision of the quorum-completing `Approve`,
/// dird records the registration's failure (`Outcome(Failed(
/// KeyOperationNotPerformed))`), withdraws the approval and answers
/// `Unavailable` — keyd holds no decision, and the approver may approve
/// again (answered `Unavailable` again here, not `Conflict`).
#[test]
fn a_decision_keyd_does_not_register_withdraws_the_approval() {
    let Some(world) = World::new(Options {
        refuse_decisions: true,
        ..Options::default()
    }) else {
        return;
    };
    let mut client = world.client();
    let state = key_state(
        client
            .call(&request_op("admin1", KeyOperation::RotateKrbtgt))
            .unwrap(),
    );
    for _ in 0..2 {
        assert_eq!(
            client
                .call(&approve_op("admin2", state.id, KeyOperation::RotateKrbtgt))
                .unwrap(),
            Reply::Refused(RefusalStatus::Unavailable)
        );
    }
    assert_eq!(
        world.keyadm().rotate_krbtgt(DecisionId::new(state.id)),
        Ok(Err(keyd::Error::Denied))
    );
    let approvals = await_events(&world, DirAdminOperation::Approve, 4);
    assert_eq!(decision(&approvals[0]), PROCEED);
    assert_eq!(
        approvals[1].stage,
        DirAdminStage::Outcome(OutcomeResult::Failed(
            ipc_audit::AdminFailure::KeyOperationNotPerformed
        ))
    );
    assert_eq!(decision(&approvals[2]), PROCEED);
}

/// docs/51 §5.6 (distinct, `decide` = Allow for the same Action and
/// Resource); P-22: the requester cannot approve its own request; a usable
/// account the PDP does not allow `PolicyAdmin` (bob, not Tier-0) is
/// refused — as an approver and as a requester; an unverifiable approver
/// AP-REQ is refused; nothing was approved, so nothing can be fetched.
#[test]
fn approvals_must_be_distinct_and_allowed() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    let state = key_state(
        client
            .call(&request_op("admin1", KeyOperation::RotateKrbtgt))
            .unwrap(),
    );
    assert_eq!(
        client
            .call(&approve_op("admin1", state.id, KeyOperation::RotateKrbtgt))
            .unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    assert_eq!(
        client
            .call(&approve_op("bob", state.id, KeyOperation::RotateKrbtgt))
            .unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    assert_eq!(
        client
            .call(&request_op("bob", KeyOperation::RotateKrbtgt))
            .unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    // An approver's AP-REQ that does not verify (expired ticket).
    let expired = Request::Operation {
        auth: Auth {
            requester: ap_req(
                "admin2",
                999_001,
                common::kt("20261113090000Z"),
                &Operation::Approve {
                    id: state.id,
                    operation: KeyOperation::RotateKrbtgt,
                },
            ),
            approvals: Vec::new(),
        },
        operation: Operation::Approve {
            id: state.id,
            operation: KeyOperation::RotateKrbtgt,
        },
    };
    assert_eq!(
        client.call(&expired).unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    // One step, one AP-REQ: approvals inside a request are refused.
    assert_eq!(
        client
            .call(&by(
                "admin1",
                &["admin2"],
                Operation::RequestKeyOperation {
                    operation: KeyOperation::RotateKrbtgt
                }
            ))
            .unwrap(),
        Reply::Refused(RefusalStatus::Invalid)
    );
    // Nothing was approved: keyd holds no decision (A-102).
    assert_eq!(
        world.keyadm().rotate_krbtgt(DecisionId::new(state.id)),
        Ok(Err(keyd::Error::Denied))
    );
    let approvals = await_events(&world, DirAdminOperation::Approve, 3);
    assert_eq!(
        approvals.iter().map(decision).collect::<Vec<_>>(),
        vec![
            refused(ipc_audit::AdminRefusal::ApproverNotDistinct),
            refused(ipc_audit::AdminRefusal::ApproverDenied),
            refused(ipc_audit::AdminRefusal::ApproverUnauthenticated),
        ]
    );
    // The PDP reason of the denied approver is recorded.
    assert!(matches!(
        approvals[1].pdp,
        Some(ipc_audit::PdpReason {
            code: ipc_audit::PdpReasonCode::NoGrant,
            ..
        })
    ));
    let requested = await_events(&world, DirAdminOperation::RequestKeyOperation, 3);
    assert_eq!(
        decision(&requested[1]),
        refused(ipc_audit::AdminRefusal::PolicyDenied)
    );
    assert_eq!(
        decision(&requested[2]),
        refused(ipc_audit::AdminRefusal::ValueInvalid)
    );
}

/// docs/51 §5.6 ("bounded in number and in time"): a request expires after
/// its lifetime (dird's clock moved past it) — its approval is refused as
/// unknown; the table holds at most `MAX_PENDING_KEY_REQUESTS` requests,
/// one more is refused (`PendingLimit`, answered `Unavailable`) until one
/// expires.
#[test]
fn pending_requests_are_bounded_in_time_and_number() {
    let Some(world) = World::new(Options {
        key_request_lifetime: Duration::from_secs(60),
        ..Options::default()
    }) else {
        return;
    };
    let mut client = world.client();
    let state = key_state(
        client
            .call(&request_op("admin1", KeyOperation::RotateKrbtgt))
            .unwrap(),
    );
    world.clock_offset.store(61, Ordering::SeqCst);
    assert_eq!(
        client
            .call(&approve_op("admin2", state.id, KeyOperation::RotateKrbtgt))
            .unwrap(),
        Reply::Refused(RefusalStatus::NotFound)
    );
    // Fill the table (the expired request was dropped).
    for _ in 0..directory_admin::MAX_PENDING_KEY_REQUESTS {
        key_state(
            client
                .call(&request_op("admin1", KeyOperation::RotateKrbtgt))
                .unwrap(),
        );
    }
    assert_eq!(
        client
            .call(&request_op("admin1", KeyOperation::RotateKrbtgt))
            .unwrap(),
        Reply::Refused(RefusalStatus::Unavailable)
    );
    // Once they expire, a request is accepted again.
    world.clock_offset.store(122, Ordering::SeqCst);
    key_state(
        client
            .call(&request_op("admin1", KeyOperation::RotateKrbtgt))
            .unwrap(),
    );
    let approvals = await_events(&world, DirAdminOperation::Approve, 1);
    assert_eq!(
        decision(&approvals[0]),
        refused(ipc_audit::AdminRefusal::PendingUnknown)
    );
    let n = directory_admin::MAX_PENDING_KEY_REQUESTS;
    let requested = await_events(&world, DirAdminOperation::RequestKeyOperation, n + 3);
    assert_eq!(
        decision(&requested[n + 1]),
        refused(ipc_audit::AdminRefusal::PendingLimit)
    );
    assert_eq!(decision(&requested[n + 2]), PROCEED);
}

/// docs/51 §5.6 ("a restart of dird ⇒ the requests vanish (fail closed)"):
/// an approved request is gone after dird restarts — a further approval
/// does not find it (the decision its approval registered lives on in keyd
/// until it expires — keyd's table, A-102).
#[test]
fn a_dird_restart_drops_pending_requests() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    let id = {
        let mut client = world.client();
        let state = key_state(
            client
                .call(&request_op("admin1", KeyOperation::RotateKrbtgt))
                .unwrap(),
        );
        key_state(
            client
                .call(&approve_op("admin2", state.id, KeyOperation::RotateKrbtgt))
                .unwrap(),
        );
        state.id
    };
    // A restart happens at least a second later (the ids of a run start at
    // its start's DSTIME seconds x 2^20, docs/questions/Q-388 item 4).
    world.clock_offset.store(1, Ordering::SeqCst);
    world.restart_dird();
    let mut client = world.client();
    assert_eq!(
        client
            .call(&approve_op("admin2", id, KeyOperation::RotateKrbtgt))
            .unwrap(),
        Reply::Refused(RefusalStatus::NotFound)
    );
    // The ids of the new run do not reuse the old one.
    let state = key_state(
        client
            .call(&request_op("admin1", KeyOperation::RotateKrbtgt))
            .unwrap(),
    );
    assert_ne!(state.id, id);
    let approvals = await_events(&world, DirAdminOperation::Approve, 3);
    assert_eq!(
        decision(&approvals[2]),
        refused(ipc_audit::AdminRefusal::PendingUnknown)
    );
}

/// docs/51 §6, §9 (`destroy-sweep`: the tombstones of user / computer
/// objects, GUID + classes — A-18); docs/52 §4.3 row `destroy_key_set`
/// option (a) (A-102): after a committed `Delete` of bob, dird registers a
/// `DestroyKeySet` decision for his tombstone under its stable id (task R6,
/// A-105: `destroy_decision_id` of the GUID, so a re-registration names the
/// same decision) — keyadm's listing (Role::Admin) shows exactly it (the
/// deleted group, which has no key sets, gets none); executing it destroys
/// the key set admind set for bob earlier (on dird's `SetSecret` decision).
#[test]
fn a_delete_registers_a_destroy_decision_for_the_tombstone() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    let mut keyadm = world.keyadm();
    assert!(keyadm
        .list_destroy_decisions(None)
        .unwrap()
        .entries
        .is_empty());
    // bob gets a key set first: dird's SetSecret decision, admind's
    // set_secret with exactly its binding and salt.
    let Reply::PasswordSet(set) = client
        .call(&by(
            "admin1",
            &[],
            Operation::BeginPasswordSet { target: g(BOB) },
        ))
        .unwrap()
    else {
        panic!("a PasswordSet reply");
    };
    let target = &set.keys[0];
    assert_eq!(
        world.admind_keyd().set_secret(
            &target.handle,
            &target.binding,
            zeroize::Zeroizing::new(String::from("bob's first password")),
            set.salt.as_str(),
        ),
        Ok(Ok(Kvno::new(1)))
    );
    assert_eq!(
        client
            .call(&by("admin1", &[], Operation::Delete { target: g(BOB) }))
            .unwrap(),
        Reply::Done
    );
    assert_eq!(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::Delete {
                    target: g(STAFF_GROUP)
                }
            ))
            .unwrap(),
        Reply::Done
    );
    let _deletes = await_events(&world, DirAdminOperation::Delete, 4);
    let listed = keyadm.list_destroy_decisions(None).unwrap();
    assert_eq!(listed.entries.len(), 1);
    assert_eq!(
        listed.entries[0].principal,
        keyd::PrincipalId::from_bytes(g(BOB).to_packet())
    );
    assert_eq!(listed.entries[0].decision, destroy_decision_id(g(BOB)));
    assert_eq!(listed.next, None);
    assert_eq!(
        keyadm.destroy_key_set(listed.entries[0].decision),
        Ok(Ok(()))
    );
    assert!(keyadm
        .list_destroy_decisions(None)
        .unwrap()
        .entries
        .is_empty());
    let destroyed = keyd_records_for(&world, ipc_audit::KeydOperation::DestroyKeySet, g(BOB));
    let done = destroyed
        .iter()
        .find(|r| r.result == ipc_audit::KeydOutcome::Success)
        .unwrap();
    assert_eq!(done.kvno, Some(1));
    assert_eq!(done.decision, Some(destroy_decision_id(g(BOB)).get()));
}

/// A-95 follow-up (docs/questions/Q-417 item 3, Q-441): dird's
/// decision-acknowledgement wait is a bounded parameter — production is
/// `DECISION_ACK_DEADLINE` (2 s, Q-388 item 3), zero and anything above the
/// 4 s ceiling cannot be built, and the ceiling keeps admind's 20 s client
/// deadline (A-91) above dird's worst case for a request queued behind
/// another (2 × (3 AP-REQs × keyd's 2 s + the wait)).
#[test]
fn the_decision_ack_deadline_is_bounded() {
    assert_eq!(DecisionAckDeadline::PRODUCTION.get(), DECISION_ACK_DEADLINE);
    assert_eq!(DECISION_ACK_DEADLINE, Duration::from_secs(2));
    assert_eq!(MAX_DECISION_ACK_DEADLINE, Duration::from_secs(4));
    assert_eq!(
        DecisionAckDeadline::new(DECISION_ACK_DEADLINE),
        Ok(DecisionAckDeadline::PRODUCTION)
    );
    for accepted in [
        Duration::from_nanos(1),
        Duration::from_millis(500),
        DECISION_ACK_DEADLINE,
        MAX_DECISION_ACK_DEADLINE,
    ] {
        assert_eq!(
            DecisionAckDeadline::new(accepted).map(DecisionAckDeadline::get),
            Ok(accepted)
        );
    }
    for refused in [
        Duration::ZERO,
        MAX_DECISION_ACK_DEADLINE + Duration::from_nanos(1),
        ipc_dird_admin::DEFAULT_DEADLINE,
    ] {
        assert_eq!(
            DecisionAckDeadline::new(refused),
            Err(DecisionAckDeadlineOutOfRange)
        );
    }
    // Three AP-REQ verifications and one decision's registration (A15a,
    // A-102).
    let worst = 2 * (4 * ipc_keyd::DEFAULT_DEADLINE + MAX_DECISION_ACK_DEADLINE);
    assert!(worst <= ipc_dird_admin::DEFAULT_DEADLINE);
}

// ---------------------------------------------------------------------------
// The SetSecret decision (task A15a; docs/51 §5.8 option (b); docs/questions/
// Q-450, Q-453; A-102: a decision of keyd's table, the salt bound — N4).
// ---------------------------------------------------------------------------

/// keyd's records (every role of the one keyd) of `op` for `target`.
fn keyd_records_for(
    world: &World,
    op: ipc_audit::KeydOperation,
    target: Guid,
) -> Vec<ipc_audit::KeydRecord> {
    world
        ._keyd_auditd
        .events()
        .into_iter()
        .filter_map(|e| match e {
            EventBody::Keyd(r) if r.op == op && r.principal == Some(target.to_packet()) => Some(*r),
            _ => None,
        })
        .collect()
}

/// Q-453 item 1; docs/52 §4.2, §4.3 (A-102, N4): a committed
/// `BeginPasswordSet` registers keyd's `SetSecret` decision for exactly the
/// key targets and salt of the reply — under Role::Ldap, an intent first (a
/// loosening, Q-452), the decision id = the operation's id — after dird's
/// decision and outcome events (`Proceed`, then `Committed`). admind's
/// `set_secret` with another salt is refused and consumes it; a new
/// `BeginPasswordSet` and the right salt then succeed.
#[test]
fn begin_password_set_registers_the_decision_for_its_key_targets() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    let Reply::PasswordSet(set) = client
        .call(&by(
            "admin1",
            &[],
            Operation::BeginPasswordSet { target: g(BOB) },
        ))
        .unwrap()
    else {
        panic!("a PasswordSet reply");
    };
    assert_eq!(set.keys.len(), 1);
    assert!(support::eventually(Duration::from_secs(10), || {
        keyd_records_for(&world, ipc_audit::KeydOperation::RegisterDecision, g(BOB)).len() >= 2
    }));
    let grants = keyd_records_for(&world, ipc_audit::KeydOperation::RegisterDecision, g(BOB));
    assert_eq!(grants[0].result, ipc_audit::KeydOutcome::Intent);
    assert_eq!(grants[1].result, ipc_audit::KeydOutcome::Success);
    assert_eq!(grants[1].caller_role, ipc_audit::KeydRole::Ldap);
    assert_eq!(
        grants[1].purpose,
        Some(ipc_audit::KeyPurposeCode::PrincipalLongterm)
    );
    let events = await_events(&world, DirAdminOperation::BeginPasswordSet, 2);
    assert_eq!(
        events[0].stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    assert!(is_committed(&events[1]));
    assert_eq!(grants[1].decision, Some(events[0].operation_id));
    // N4: another salt is refused, and consumes the decision.
    let target = &set.keys[0];
    let mut admind = world.admind_keyd();
    let password = || zeroize::Zeroizing::new(String::from("bob's next password"));
    assert_eq!(
        admind.set_secret(
            &target.handle,
            &target.binding,
            password(),
            "EXAMPLE.ORGother"
        ),
        Ok(Err(keyd::Error::Denied))
    );
    assert_eq!(
        admind.set_secret(
            &target.handle,
            &target.binding,
            password(),
            set.salt.as_str()
        ),
        Ok(Err(keyd::Error::Denied))
    );
    let Reply::PasswordSet(set) = client
        .call(&by(
            "admin1",
            &[],
            Operation::BeginPasswordSet { target: g(BOB) },
        ))
        .unwrap()
    else {
        panic!("a PasswordSet reply");
    };
    assert_eq!(
        admind.set_secret(
            &target.handle,
            &target.binding,
            password(),
            set.salt.as_str()
        ),
        Ok(Ok(Kvno::new(1)))
    );
}

/// Q-453 item 1 (fail closed; A-102): when keyd does not register the
/// `SetSecret` decision, the `BeginPasswordSet` is answered `Unavailable` —
/// admind then sets no password. The write did commit (`pwdLastSet` moved;
/// dird's outcome event says `Committed`): the begun-but-not-set state
/// docs/51 §9 names as safe.
#[test]
fn a_secret_decision_keyd_does_not_register_answers_unavailable() {
    let Some(world) = World::new(Options {
        refuse_decisions: true,
        ..Options::default()
    }) else {
        return;
    };
    let mut client = world.client();
    let seq_before = change_seq_next(&world.store);
    assert_eq!(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::BeginPasswordSet { target: g(BOB) },
            ))
            .unwrap(),
        Reply::Refused(RefusalStatus::Unavailable)
    );
    assert_eq!(change_seq_next(&world.store), seq_before + 1, "committed");
    let events = await_events(&world, DirAdminOperation::BeginPasswordSet, 2);
    assert_eq!(
        events[0].stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    assert!(is_committed(&events[1]));
    // keyd holds no decision: dird's client never sent one.
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        keyd_records_for(&world, ipc_audit::KeydOperation::RegisterDecision, g(BOB)).is_empty()
    );
}

// ---------------------------------------------------------------------------
// The re-registration of lost destroy decisions (A-105; docs/questions/Q-470
// item 4, Q-501; task R6).
// ---------------------------------------------------------------------------

/// How long the re-registration tests wait for a run and for keyd's records
/// to reach its auditd (a loaded machine).
const RECONCILE_WAIT: Duration = Duration::from_secs(20);

/// keyd's successful `register_decision` records of `target`'s destroy
/// decision (its stable id; the set-secret decision of the same account is
/// not counted, nor the intent record every registration also has, A-88).
fn registrations_for(world: &World, target: Guid) -> usize {
    let id = destroy_decision_id(target).get();
    keyd_records_for(world, ipc_audit::KeydOperation::RegisterDecision, target)
        .iter()
        .filter(|r| r.result == ipc_audit::KeydOutcome::Success && r.decision == Some(id))
        .count()
}

/// keyd's refusals of `target`'s destroy decision because the account has
/// no key set left (R6b: `KeyNotFound` — the "destruction complete" answer,
/// docs/questions/Q-501, Q-520).
fn refused_for_no_key_set(world: &World, target: Guid) -> usize {
    let id = destroy_decision_id(target).get();
    keyd_records_for(world, ipc_audit::KeydOperation::RegisterDecision, target)
        .iter()
        .filter(|r| {
            r.result == ipc_audit::KeydOutcome::Denied
                && r.reason == ipc_audit::KeydReason::KeyNotFound
                && r.decision == Some(id)
        })
        .count()
}

/// The pending destroy decisions keyadm sees (Role::Admin), as principals.
fn pending_destructions(world: &World) -> Vec<keyd::PrincipalId> {
    world
        .keyadm()
        .list_destroy_decisions(None)
        .map(|page| page.entries.iter().map(|e| e.principal).collect())
        .unwrap_or_default()
}

/// A-105 (docs/questions/Q-470 item 4; docs/52 §4.3, §3.10 (a); docs/51 §6,
/// §9): a computer with both key sets is deleted — dird registers its
/// destroy decision — then keyd restarts and loses its decision table while
/// the key sets remain (as a persistent store, P-17, would keep them). dird's
/// periodic re-registration registers the decision again under the same id;
/// keyadm's `destroy-sweep` then destroys **both** key sets (keyd's record
/// names the two destroyed kvnos). The next run's registration is refused
/// by keyd — ws7 has no key set left (R6b: `KeyNotFound`, though keyd still
/// holds the executed decision) — so nothing is pending, nothing is left
/// to sweep, and dird settles it; the runs after that ask keyd nothing more
/// for it.
#[test]
fn lost_destroy_decisions_are_registered_again_until_keyd_ran_them() {
    let Some(mut world) = World::new(Options {
        reconcile_interval: Duration::from_millis(300),
        ..Options::default()
    }) else {
        return;
    };
    let mut client = world.client();
    // ws7: a computer with its SPN — two key sets, set by admind on dird's
    // SetSecret decision.
    let (ws7, _) = created(
        client
            .call(&by(
                "admin1",
                &[],
                Operation::CreateComputer {
                    parent: g(STAFF_OU),
                    name: "ws7".into(),
                    dns_host_name: "ws7.example.org".into(),
                    spn: Some("host/ws7.example.org".into()),
                },
            ))
            .unwrap(),
    );
    let Reply::PasswordSet(set) = client
        .call(&by(
            "admin1",
            &[],
            Operation::BeginPasswordSet { target: ws7 },
        ))
        .unwrap()
    else {
        panic!("a PasswordSet reply");
    };
    assert_eq!(set.keys.len(), 2);
    for target in &set.keys {
        assert_eq!(
            world.admind_keyd().set_secret(
                &target.handle,
                &target.binding,
                zeroize::Zeroizing::new(String::from("ws7's machine password")),
                set.salt.as_str(),
            ),
            Ok(Ok(Kvno::new(1)))
        );
    }
    let ws7_principal = keyd::PrincipalId::from_bytes(ws7.to_packet());
    let key_sets: Vec<(KeyHandle, keyd::PrincipalBinding)> = set
        .keys
        .iter()
        .map(|k| (k.handle, k.binding.clone()))
        .collect();

    // The Delete registers the destroy decision under the tombstone's id.
    assert_eq!(
        client
            .call(&by("admin1", &[], Operation::Delete { target: ws7 }))
            .unwrap(),
        Reply::Done
    );
    assert_eq!(pending_destructions(&world), vec![ws7_principal]);
    assert!(support::eventually(RECONCILE_WAIT, || registrations_for(
        &world, ws7
    ) == 1));

    // keyd restarts: its decisions are gone, ws7's two key sets are not.
    world.restart_keyd(move |started| {
        let mut keyd = admin_keyd(started)?;
        for (handle, binding) in &key_sets {
            keyd.create_key(&common::ADMIN, handle, binding, &common::now())
                .unwrap();
        }
        let _ = keyd.audit_sink_mut().take();
        Ok(keyd)
    });

    // dird registers it again (the same id), and only once.
    assert!(support::eventually(RECONCILE_WAIT, || {
        pending_destructions(&world) == vec![ws7_principal]
    }));
    assert!(support::eventually(RECONCILE_WAIT, || registrations_for(
        &world, ws7
    ) == 2));
    let listed = world.keyadm().list_destroy_decisions(None).unwrap();
    assert_eq!(listed.entries[0].decision, destroy_decision_id(ws7));

    // keyadm's destroy-sweep destroys both key sets.
    let report = keyadm::sweep::run(&mut world.keyadm());
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.destroyed.len(), 1);
    assert_eq!(report.destroyed[0].principal, ws7_principal);
    let destroyed_record = || {
        keyd_records_for(&world, ipc_audit::KeydOperation::DestroyKeySet, ws7)
            .into_iter()
            .find(|r| r.result == ipc_audit::KeydOutcome::Success)
    };
    assert!(support::eventually(RECONCILE_WAIT, || destroyed_record().is_some()));
    let done = destroyed_record().unwrap();
    assert_eq!(done.kvno, Some(1), "the account key set");
    assert_eq!(
        done.secondary.map(|k| (k.purpose, k.kvno)),
        Some((ipc_audit::KeyPurposeCode::Service, Some(1))),
        "the Service key set"
    );
    assert_eq!(done.decision, Some(destroy_decision_id(ws7).get()));

    // The next run: ws7 has no key set left, so keyd refuses the
    // registration from its key store (R6b) — nothing pending, nothing for
    // keyadm to sweep — and dird settles it.
    assert!(support::eventually(
        RECONCILE_WAIT,
        || refused_for_no_key_set(&world, ws7) == 1
    ));
    assert_eq!(registrations_for(&world, ws7), 2);
    assert!(pending_destructions(&world).is_empty());
    let report = keyadm::sweep::run(&mut world.keyadm());
    assert!(report.is_complete());
    assert_eq!(report.listed, 0);
    // The runs after it ask keyd nothing more for ws7.
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(registrations_for(&world, ws7), 2);
    assert_eq!(refused_for_no_key_set(&world, ws7), 1);
    assert_eq!(
        keyd_records_for(&world, ipc_audit::KeydOperation::DestroyKeySet, ws7)
            .iter()
            .filter(|r| r.result == ipc_audit::KeydOutcome::Success)
            .count(),
        1
    );
}

/// bob gets a key set: dird's `SetSecret` decision for the `BeginPasswordSet`,
/// admind's `set_secret` with exactly its binding and salt.
fn give_bob_a_key_set(world: &World) {
    let Reply::PasswordSet(set) = world
        .client()
        .call(&by(
            "admin1",
            &[],
            Operation::BeginPasswordSet { target: g(BOB) },
        ))
        .unwrap()
    else {
        panic!("a PasswordSet reply");
    };
    let target = &set.keys[0];
    assert_eq!(
        world.admind_keyd().set_secret(
            &target.handle,
            &target.binding,
            zeroize::Zeroizing::new(String::from("bob's first password")),
            set.salt.as_str(),
        ),
        Ok(Ok(Kvno::new(1)))
    );
}

/// A-105 at the admin service's start (docs/questions/Q-470 item 4): a
/// destroy decision whose registration failed at the `Delete` (keyd did not
/// register it — the fail-closed path of A-102: the `Delete` still answers
/// `Done`) is registered when dird starts again with a keyd that registers
/// decisions — bob still has his key set (R6b: keyd registers a destroy
/// decision only then); a dird with no tombstone to settle asks keyd
/// nothing (no listing in keyd's records).
#[test]
fn a_destroy_decision_not_registered_at_the_delete_is_registered_at_start() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    let listings = |world: &World| {
        world
            ._keyd_auditd
            .events()
            .iter()
            .filter(|e| {
                matches!(e, EventBody::Keyd(r)
                    if r.op == ipc_audit::KeydOperation::ListDestroyDecisions)
            })
            .count()
    };
    // No tombstone yet: the start-time run asked keyd nothing.
    assert_eq!(listings(&world), 0);
    give_bob_a_key_set(&world);
    // dird's keyd client now registers nothing (A-102's fail-closed path).
    world.options.refuse_decisions = true;
    world.restart_dird();
    assert_eq!(listings(&world), 0);
    assert_eq!(
        world
            .client()
            .call(&by("admin1", &[], Operation::Delete { target: g(BOB) }))
            .unwrap(),
        Reply::Done
    );
    assert!(pending_destructions(&world).is_empty());
    world.options.refuse_decisions = false;
    world.restart_dird();
    assert!(support::eventually(RECONCILE_WAIT, || {
        pending_destructions(&world) == vec![keyd::PrincipalId::from_bytes(g(BOB).to_packet())]
    }));
    let listed = world.keyadm().list_destroy_decisions(None).unwrap();
    assert_eq!(listed.entries[0].decision, destroy_decision_id(g(BOB)));
}

/// R6b (docs/questions/Q-501 decision; Q-520): "destruction complete" is
/// read from keyd's key store, not from dird's memory. bob is deleted (his
/// destroy decision registered at the `Delete`) and keyadm's sweep destroys
/// his key set; then dird restarts — its settled cache empty, as after any
/// dird start — and its start-time run registers bob's decision once more:
/// keyd refuses it (no key set left: `KeyNotFound`), dird settles it, no
/// destroy decision is scheduled, and keyadm's next sweep has nothing to
/// run. (Before R6b keyd accepted it — unchanged while it held the executed
/// decision, as a new pending one after that — and the sweep then ran a
/// destroy of nothing.)
#[test]
fn after_the_sweep_a_dird_restart_schedules_no_destroy() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    let bob = keyd::PrincipalId::from_bytes(g(BOB).to_packet());
    give_bob_a_key_set(&world);
    assert_eq!(
        world
            .client()
            .call(&by("admin1", &[], Operation::Delete { target: g(BOB) }))
            .unwrap(),
        Reply::Done
    );
    assert_eq!(pending_destructions(&world), vec![bob]);
    let report = keyadm::sweep::run(&mut world.keyadm());
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.destroyed.len(), 1);
    assert!(pending_destructions(&world).is_empty());

    // dird restarts: its start-time run presents bob's tombstone again.
    world.restart_dird();
    assert!(support::eventually(
        RECONCILE_WAIT,
        || refused_for_no_key_set(&world, g(BOB)) == 1
    ));
    assert!(pending_destructions(&world).is_empty());
    let report = keyadm::sweep::run(&mut world.keyadm());
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.listed, 0);
    assert!(report.destroyed.is_empty());
    // One destruction in keyd's records, ever; one successful registration
    // (the Delete's).
    let destroyed = keyd_records_for(&world, ipc_audit::KeydOperation::DestroyKeySet, g(BOB))
        .iter()
        .filter(|r| r.result == ipc_audit::KeydOutcome::Success)
        .count();
    assert_eq!(destroyed, 1);
    assert_eq!(registrations_for(&world, g(BOB)), 1);
}

/// Attack test (R6b follow-up; docs/questions/Q-520): the window between a
/// password set and a `Delete`. bob has no key set; admin1's
/// `BeginPasswordSet` commits — dird registers bob's `SetSecret` decision —
/// and before admind's `set_secret` arrives, admin1 deletes bob. The
/// `Delete`'s destroy registration is refused (no key set) and discards the
/// live decision (keyd's `SecretDecisionDiscarded` record for bob's handle);
/// admind's `set_secret` with exactly the decided binding and salt is then
/// refused (`NoGrant`) and creates no key set. So the tombstone is truly
/// settled: a dird restart's run is refused again (`KeyNotFound`), nothing
/// is pending, keyadm's sweep has nothing to run, nothing was destroyed.
#[test]
fn a_password_set_begun_before_the_delete_creates_no_key_set() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    let Reply::PasswordSet(set) = world
        .client()
        .call(&by(
            "admin1",
            &[],
            Operation::BeginPasswordSet { target: g(BOB) },
        ))
        .unwrap()
    else {
        panic!("a PasswordSet reply");
    };
    assert_eq!(
        world
            .client()
            .call(&by("admin1", &[], Operation::Delete { target: g(BOB) }))
            .unwrap(),
        Reply::Done
    );
    // keyd discarded bob's set-secret decision at the destroy registration
    // (refused: no key set yet).
    let discarded = || {
        keyd_records_for(&world, ipc_audit::KeydOperation::RegisterDecision, g(BOB))
            .into_iter()
            .filter(|r| {
                r.result == ipc_audit::KeydOutcome::Success
                    && r.reason == ipc_audit::KeydReason::SecretDecisionDiscarded
                    && r.purpose == Some(ipc_audit::KeyPurposeCode::PrincipalLongterm)
            })
            .count()
    };
    assert!(support::eventually(RECONCILE_WAIT, || discarded() == 1));
    assert!(support::eventually(
        RECONCILE_WAIT,
        || refused_for_no_key_set(&world, g(BOB)) == 1
    ));
    // admind's set_secret, exactly as dird decided it: refused, no key set.
    let target = &set.keys[0];
    assert_eq!(
        world.admind_keyd().set_secret(
            &target.handle,
            &target.binding,
            zeroize::Zeroizing::new(String::from("bob's first password")),
            set.salt.as_str(),
        ),
        Ok(Err(keyd::Error::Denied))
    );
    let set_secret_refused = || {
        world
            ._keyd_auditd
            .events()
            .iter()
            .filter(|e| {
                matches!(e, EventBody::Keyd(r)
                    if r.op == ipc_audit::KeydOperation::SetSecret
                        && r.principal == Some(g(BOB).to_packet())
                        && r.reason == ipc_audit::KeydReason::NoGrant)
            })
            .count()
    };
    assert!(support::eventually(RECONCILE_WAIT, || set_secret_refused() == 1));

    // Truly settled: a dird restart presents the tombstone again — refused,
    // nothing pending, nothing to sweep, nothing destroyed.
    world.restart_dird();
    assert!(support::eventually(
        RECONCILE_WAIT,
        || refused_for_no_key_set(&world, g(BOB)) == 2
    ));
    assert!(pending_destructions(&world).is_empty());
    let report = keyadm::sweep::run(&mut world.keyadm());
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.listed, 0);
    assert!(keyd_records_for(&world, ipc_audit::KeydOperation::DestroyKeySet, g(BOB)).is_empty());
    assert_eq!(registrations_for(&world, g(BOB)), 0);
}

// ---------------------------------------------------------------------------
// Task A16: `PolicyAdmin` online — `policy.next`.
// ---------------------------------------------------------------------------

use ipc_dird_admin::{PolicyChange, PolicyTier};

/// One tier-map change: the staff group's SID as a Tier1 principal.
fn staff_group_tier1() -> Operation {
    Operation::ChangePolicy {
        changes: vec![PolicyChange::AddPrincipal(
            sid_of(STAFF_GROUP),
            PolicyTier::Tier1,
        )],
    }
}

/// docs/51 §5.10 (R51-21), §5.6 (P-22), §5.7: a Tier-0 administrator asks
/// for a tier-map change with a second Tier-0 administrator's approval in
/// the same request (every AP-REQ bound to it, R2) — dird answers the
/// version it wrote, `policy.next` holds the loaded policy edited by the
/// one tier-map edit (version 1 → 2; mode 0600, dird's), and auditd holds
/// the decision (requester, approver, the change in the edit's spelling)
/// before the outcome `Committed`.
#[test]
fn a_dual_controlled_policy_change_is_written_as_policy_next() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    assert_eq!(
        client
            .call(&by("admin1", &["admin2"], staff_group_tier1()))
            .unwrap(),
        Reply::PolicyNext { version: 2 }
    );
    let next = policy_next_path(&world.scratch);
    let written = DevelopmentPolicy::decode(&std::fs::read(&next).unwrap()).unwrap();
    let (expected, _) = policy_store::edit_tier_map(
        &policy(),
        &[policy_store::TierChange::AddPrincipal(
            sid_of(STAFF_GROUP),
            Tier::Tier1,
        )],
    )
    .unwrap();
    assert_eq!(written, expected);
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(&next).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.mode() & 0o7777, 0o600);
        assert_eq!(meta.uid(), world.uid);
    }
    assert!(!next.with_file_name("policy.next.partial").exists());
    let events = await_events(&world, DirAdminOperation::ChangePolicy, 2);
    assert_eq!(
        events[0].stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    assert_eq!(events[0].requester, Some(sid_value(&sid_of(ADMIN1))));
    assert_eq!(
        events[0].approvers.as_slice(),
        &[sid_value(&sid_of(ADMIN2))]
    );
    let change = format!(
        "--add-principal {} Tier1",
        sid_of(STAFF_GROUP).to_sid_string()
    );
    assert_eq!(
        events[0]
            .names
            .as_slice()
            .iter()
            .map(|n| (n.kind, n.text.as_text().map(str::to_owned)))
            .collect::<Vec<_>>(),
        vec![(ipc_audit::AdminNameKind::PolicyChange, Some(change))]
    );
    assert!(is_committed(&events[1]));
    assert_eq!(events[1].operation_id, events[0].operation_id);
}

/// The attacks (docs/51 §5.2 row 13, §5.6, §5.10; docs/06 §9; P-22; R2;
/// docs/questions/Q-591): one administrator alone, or approving himself;
/// a non-Tier-0 account (bob) even with a Tier-0 approver; an approval made
/// for another operation — each refused, no `policy.next` written; then,
/// with one change pending, a second is refused (`Unavailable`, recorded
/// `PendingLimit`) and `policy.next` is left exactly as it was.
#[test]
fn a_policy_change_needs_two_tier0_administrators_and_one_at_a_time() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut client = world.client();
    let next = policy_next_path(&world.scratch);
    assert_eq!(
        client
            .call(&by("admin1", &[], staff_group_tier1()))
            .unwrap(),
        Reply::Refused(RefusalStatus::ApprovalRequired)
    );
    assert_eq!(
        client
            .call(&by("admin1", &["admin1"], staff_group_tier1()))
            .unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    assert_eq!(
        client
            .call(&by("bob", &["admin2"], staff_group_tier1()))
            .unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    // admin2's approval made for another change (R2): keyd refuses it.
    let other = Operation::ChangePolicy {
        changes: vec![PolicyChange::AddPrincipal(
            sid_of(STAFF_GROUP),
            PolicyTier::Tier2,
        )],
    };
    let mismatched = Request::Operation {
        auth: Auth {
            requester: fresh("admin1", &staff_group_tier1()),
            approvals: vec![fresh("admin2", &other)],
        },
        operation: staff_group_tier1(),
    };
    assert_eq!(
        client.call(&mismatched).unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    assert!(!next.exists(), "nothing written");

    // One pending change at a time.
    assert_eq!(
        client.call(&by("admin1", &["admin2"], other)).unwrap(),
        Reply::PolicyNext { version: 2 }
    );
    let pending = std::fs::read(&next).unwrap();
    assert_eq!(
        client
            .call(&by("admin2", &["admin1"], staff_group_tier1()))
            .unwrap(),
        Reply::Refused(RefusalStatus::Unavailable)
    );
    assert_eq!(std::fs::read(&next).unwrap(), pending, "left as it was");

    let events = await_events(&world, DirAdminOperation::ChangePolicy, 7);
    let stages: Vec<DirAdminStage> = events.iter().map(|e| e.stage).collect();
    assert_eq!(
        stages,
        vec![
            refused(ipc_audit::AdminRefusal::ApprovalRequired),
            refused(ipc_audit::AdminRefusal::ApproverNotDistinct),
            refused(ipc_audit::AdminRefusal::PolicyDenied),
            refused(ipc_audit::AdminRefusal::ApproverUnauthenticated),
            DirAdminStage::Decision(DecisionResult::Proceed),
            stages[5],
            refused(ipc_audit::AdminRefusal::PendingLimit),
        ]
    );
    assert!(is_committed(&events[5]));
}

/// Without a `policy_next_path` the online path does not exist: a change —
/// even fully approved — is refused `Unavailable`, recorded as a failure.
/// Spec: docs/51 §5.10; crates/config `policy_next_path` (optional).
#[test]
fn without_policy_next_path_a_policy_change_is_unavailable() {
    let Some(world) = World::new(Options {
        policy_next: false,
        ..Options::default()
    }) else {
        return;
    };
    let mut client = world.client();
    assert_eq!(
        client
            .call(&by("admin1", &["admin2"], staff_group_tier1()))
            .unwrap(),
        Reply::Refused(RefusalStatus::Unavailable)
    );
    let events = await_events(&world, DirAdminOperation::ChangePolicy, 1);
    assert_eq!(
        events[0].stage,
        DirAdminStage::Decision(DecisionResult::Failed(
            ipc_audit::AdminFailure::InternalFailure
        ))
    );
    assert!(!policy_next_path(&world.scratch).exists());
}
