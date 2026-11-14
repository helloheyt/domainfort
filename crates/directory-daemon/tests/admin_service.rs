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
//! Service)`, bound to `NT-SRV-HST admind/dc1.example.org` (A-73) — created
//! with `create_key` from scripted test entropy, so the test, playing the
//! Kerberos side, knows the key. The test seals each administrator's service
//! ticket under it (RFC 4120 §5.3: EncTicketPart, key usage 2) and builds the
//! AP-REQ with an authenticator under the ticket's session key (§5.5.1, key
//! usage 11), with krb-crypto and the kdc integration fixtures
//! (crates/kdc/tests/common: `usage`, `aes256`, the scripted entropy, the
//! names and times) — the construction keyd's own service-ticket tests use.
//! keyd then runs the whole of RFC 4120 §3.2.3 on it (the binding check,
//! the decryption, the authenticator, the replay cache).
//!
//! # What is checked
//!
//! Every operation end to end with its reply; the decision event
//! acknowledged **before** the commit and the outcome event after it; an
//! auditd that withholds acknowledgements ⇒ `Unavailable`, store unchanged;
//! a bad or expired AP-REQ ⇒ `Denied` and keyd down ⇒ `Unavailable`, store
//! unchanged; dual control (a second Tier-0 administrator's approval
//! satisfies it, the same principal twice does not); a wrong peer uid ⇒
//! closed; a full queue ⇒ `Busy`; an oversize frame ⇒ closed before the
//! body; the admin service object absent ⇒ no admin service, dird's other
//! services run.
//!
//! Sources: docs/51 §5.2, §5.3, §5.6, §5.7, §7.1-§7.5; docs/50 §3.3, §3.6,
//! §9; docs/10 §5ב; RFC 4120 §3.2.3, §5.3, §5.5.1, §6.2.1, §7.5.1; [MS-SAMR]
//! 2.2.1.14 (RID 502); [MS-DTYP] 2.4.2.4 (SID layout); A-26, A-56, A-73,
//! A-85, A-89, P-22. Every value is constructed by hand for these tests (the
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
use directory_daemon::{
    admin_refused_peer_count, serve_with_admin, AdminParams, Clock, DaemonControl, DaemonParams,
    KeydTicketVerifier, SharedClock, StoreSource, TicketVerifier, VerifierFactory,
    DECISION_ACK_DEADLINE,
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
    AccountExpires, AccountKind, AdminClient, Auth, LookupKey, Operation, PasswordSetOutcome,
    RefusalStatus, Reply, Request, Unserved, MAX_REQUEST_BODY,
};
use keyd::{InMemoryKeyStore, KeyHandle, KeyPurpose, Keyd, Role};
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
/// Tier-0 group may run every Directory action under the NC root; the
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
        rules: vec![Rule {
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
        }],
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

/// An AP-REQ of `sam` for the admin service: the ticket sealed under the
/// admin service key (usage 2), ending at `endtime`; the authenticator at
/// `now` with `cusec`, under the session key (usage 11).
/// Spec: RFC 4120 §5.3, §5.5.1, §7.5.1.
fn ap_req(sam: &str, cusec: u32, endtime: KerberosTime) -> Vec<u8> {
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
    let authenticator = Authenticator {
        crealm: common::realm(),
        cname: principal(sam),
        cksum: None,
        cusec: Microseconds::new(cusec).unwrap(),
        ctime: common::now(),
        subkey: None,
        seq_number: None,
        authorization_data: None,
    }
    .encode()
    .unwrap();
    let session = common::aes256(&SESSION_KEY);
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

fn fresh(sam: &str) -> Vec<u8> {
    ap_req(
        sam,
        CUSEC.fetch_add(1, Ordering::SeqCst),
        common::kt("20261113170000Z"),
    )
}

fn by(requester: &str, approvers: &[&str], operation: Operation) -> Request {
    Request::Operation {
        auth: Auth {
            requester: fresh(requester),
            approvals: approvers.iter().map(|a| fresh(a)).collect(),
        },
        operation,
    }
}

// ---------------------------------------------------------------------------
// keyd: the admin service key set, Role::Ldap for the test's uid.
// ---------------------------------------------------------------------------

/// keyd with the admin service's key set (`create_key`, docs/51 §4.3 step
/// 11) — the scripted entropy gives it [`ADMIN_SERVICE_KEY`] for each of
/// keyd's enctypes.
fn admin_keyd(
    started: &KerberosTime,
) -> Result<Keyd<InMemoryKeyStore, RecordBuffer, common::TestEntropy>, keyd::ConfigError> {
    let entropy = common::TestEntropy::default();
    let mut keyd = Keyd::with_entropy(
        support::keyd_config(),
        InMemoryKeyStore::new(64),
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
            Ok(AuditRequest::Ping) => AuditReply::Pong,
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

/// dird's clock: the kdc fixtures' `now` (the tickets' time base).
struct FixedNow;

impl Clock for FixedNow {
    fn now(&self) -> Option<KerberosTime> {
        Some(common::now())
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
                    StoreSource::Opened(store),
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
struct Options {
    with_admin_service: bool,
    admind_uid_offset: u32,
    max_connections: usize,
    queue_capacity: usize,
    hook: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            with_admin_service: true,
            admind_uid_offset: 0,
            max_connections: directory_daemon::MAX_ADMIN_CONNECTIONS,
            queue_capacity: directory_daemon::ADMIN_QUEUE_CAPACITY,
            hook: false,
        }
    }
}

/// keyd, both auditds, dird with its admin service, and admind's client.
struct World {
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

        // keyd: the test's uid is Role::Ldap (A-73); its own fake auditd.
        let mut keyd_params =
            support::keyd::params(&dir, CallerMap::new(&[(uid, Role::Ldap)]).unwrap(), uid);
        keyd_params.audit.socket = dir.join("ka.sock");
        let keyd_socket = keyd_params.keyd_socket.clone();
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

        let mut params = support::params(&dir, uid, uid, Duration::from_secs(5), 4);
        params.clock = SharedClock::new(FixedNow);
        let kdc_socket = params.kdc_socket.clone();
        let admin_socket = dir.join("m.sock");
        let realm = common::realm();
        let factory: VerifierFactory = Arc::new(move || {
            let client = ipc_keyd::KeydClient::new(
                support::connector::keyd(&keyd_socket),
                uid,
                ipc_keyd::DEFAULT_DEADLINE,
            )
            .ok()?;
            let verifier: Box<dyn TicketVerifier> =
                Box::new(KeydTicketVerifier::new(client, realm.clone()));
            Some(verifier)
        });
        let admin = AdminParams {
            socket: admin_socket.clone(),
            admind_uid: uid + options.admind_uid_offset,
            keyd: Some(factory),
            ticket_age_max: TICKET_AGE_MAX,
            quorum: QUORUM,
            node_id: NODE_ID,
            manifest: manifest(),
            max_connections: options.max_connections,
            queue_capacity: options.queue_capacity,
            ack_deadline: DECISION_ACK_DEADLINE,
        };
        let dird = DirdRun::start(params, admin, Arc::clone(&store), policy());
        Some(World {
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
        })
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
/// reach it.
#[test]
fn no_acknowledgement_means_nothing_is_committed() {
    let Some(world) = World::new(Options::default()) else {
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
    assert_eq!(
        events[1].stage,
        DirAdminStage::Outcome(OutcomeResult::Failed(
            ipc_audit::AdminFailure::InternalFailure
        ))
    );
    assert_eq!(events[0].operation_id, events[1].operation_id);
    assert_eq!(world.object_named(g(STAFF_OU), "withheld"), None);
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
    let create = |requester: Vec<u8>| Request::Operation {
        auth: Auth {
            requester,
            approvals: Vec::new(),
        },
        operation: Operation::CreateOu {
            parent: g(ROOT),
            name: "Refused".into(),
        },
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
    );
    assert_eq!(
        client.call(&create(expired)).unwrap(),
        Reply::Refused(RefusalStatus::Denied)
    );
    // The same AP-REQ twice: keyd's replay cache (RFC 4120 §3.2.3).
    let once = fresh("admin1");
    assert!(matches!(
        client.call(&create(once.clone())).unwrap(),
        Reply::Created { .. }
    ));
    let seq_after_one = change_seq_next(&world.store);
    assert_eq!(seq_after_one, seq_before + 1);
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
    let events = await_events(&world, DirAdminOperation::CreateOu, 6);
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
    let Some(world) = World::new(Options {
        max_connections: 3,
        queue_capacity: 1,
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
    let mut directory = ipc_directory::DirectoryClient::new(
        support::connector::dird(&world.kdc_socket),
        world.uid,
        ipc_directory::DEFAULT_DEADLINE,
        PolicyVersion(1),
    )
    .unwrap();
    let domain = directory.describe_domain().unwrap();
    assert_eq!(domain.realm, common::realm());
}
