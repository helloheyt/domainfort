//! Tier 2, dird's kpasswd service (task K7, dird side; docs/53 §5.6): dird
//! in-process (`directory_daemon::test_seams::serve_with_kpasswd` on its own
//! thread and runtime) with a **real keyd daemon** (`keyd_daemon::serve`, the
//! test's own uid mapped to Role::Ldap — the single-uid pattern of docs/50
//! §9 tier 2) and a fake auditd, reached by **a fake front** — the front's
//! own client, `ipc_kpasswd::KpasswdClient`, over the real
//! `dird-kpasswd.sock`.
//!
//! # The tickets
//!
//! alice's `kadmin/changepw` ticket comes from **the KDC's armored AS**
//! (crates/kdc tests/common `Fixture`: the in-process KDC and keyd of the
//! kdc fixtures — FAST, the encrypted challenge, keyd's change-password
//! profile with INITIAL, task K3b), whose change-password service key and
//! alice's password are the same scripted values this test's keyd daemon
//! holds (`CHANGEPW_KEY`, `ALICE_PASSWORD` — docs/53 §5.2). The KDC never
//! issues one to a computer (R53-1) or to an account it does not hold, so
//! the tickets of the refusal cases (ws1$, admin1) are sealed here under the
//! same service key, as keyd's own change-password tests seal theirs. The
//! client side — the AP-REQ with a subkey and a sequence number, the
//! KRB-PRIV under the subkey (usage 13), the opening of keyd's AP-REP
//! (usage 12) and reply KRB-PRIV — is RFC 3244 §2 / RFC 4120 §5.5.1, §5.5.2,
//! §5.7.1 with krb-crypto, written here from those sections; the
//! cryptography itself is verified against the RFC 3962 / RFC 8009 vectors
//! in crates/krb-crypto. No RFC gives an example RFC 3244 exchange.
//!
//! # What is checked
//!
//! An armored changepw ticket ⇒ the password changed (sealed SUCCESS, the
//! `ChangePassword` decision and outcome events, `pwdLastSet` = dird's now)
//! ⇒ the new password verifies in keyd and the old one does not; the same
//! ticket again (a fresh Authenticator) ⇒ sealed AUTHERROR (the change
//! revoked it — docs/53 R53-9), also when dird's clock is in the AS's own
//! second (Q-965 (a), A-161), and the same request octets again ⇒ keyd's
//! replay cache ⇒ unsealed AUTHERROR; a computer ⇒ sealed ACCESSDENIED; a
//! Tier0 account ⇒ sealed ACCESSDENIED (Q-608 item 1, strict default); a
//! policy-violating new password ⇒ sealed SOFTERROR with no result string,
//! nothing written, no dird event; a request keyd cannot open ⇒ unsealed
//! AUTHERROR; a wrong peer uid ⇒ closed without a reply, nothing done; the
//! decision event acknowledged **before** the commit (the store untouched
//! when auditd receives it); auditd withholding its acknowledgement ⇒
//! sealed HARDERROR, nothing written, the old password still valid.
//!
//! Sources: docs/53 §2.4, §4.3, §5.4–§5.7, §6.3, §8, §9, §10 item 3; RFC
//! 3244 §2 (pinned); RFC 4120 §2.1, §3.2.3, §3.2.4, §3.5.1, §5.5.1, §5.5.2,
//! §5.7.1, §7.1, §7.5.1 (pinned); [MS-ADTS] v20261026 3.1.1.3.1.5.1,
//! 6.1.1.2.7.52 (pinned); docs/50 §3.2, §9; docs/51 §5.7 item 2; A-85;
//! A-117; A-126; docs/questions/Q-603, Q-604, Q-608, Q-660, Q-662, Q-663,
//! Q-955. Every value is constructed by hand for these tests (the times are
//! those of the kdc fixtures; addresses from RFC 5737's documentation
//! range); no vector comes from any other implementation.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use ad_schema::flags::user_account_control as uac;
use ad_schema::{phase1, Phase1Schema};
use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;
use directory_admin::{wall_clock, CHANGE_SEQ_COUNTER, RID_COUNTER, RID_END_EXCLUSIVE, RID_FIRST};
use directory_daemon::policy::{DevelopmentPolicy, MandatoryFast};
use directory_daemon::test_seams::{
    serve_with_kpasswd, AdminParams, KpasswdKeydFactory, KpasswdParams, VerifierFactory,
};
use directory_daemon::{
    kpasswd_refused_peer_count, Clock, DaemonControl, DecisionAckDeadline, KeydKpasswdClient,
    KeydTicketVerifier, KpasswdKeyd, SharedClock, TicketVerifier, MAX_DECISION_ACK_DEADLINE,
};
use dirstore::{AttrId, IntegrityKey, NewObject, NodeId, Origin, Store, WriteTxn};
use dtyp::{
    ace_flags, create_security_descriptor, AccessMask, Ace, Acl, AutoInheritFlags, Control,
    GenericMapping, Guid, MaskSidAce, ObjectAce, SecurityDescriptor, Sid, Token, ACL_REVISION_DS,
    SECURITY_NT_AUTHORITY,
};
use ipc::{Direction, FrameReader};
use ipc_audit::{
    decode_event, decode_request, encode_reply, Ack, AuditReply, AuditRequest, DecisionResult,
    DirAdminEvent, DirAdminOperation, DirAdminStage, EventBody, OutcomeResult, AUDIT_CHANNEL,
};
use ipc_kpasswd::{
    ApReqOctets, ChangePasswordRequest, ExpectedDird, FrontZone, KpasswdAnswer, KpasswdClient,
    KrbPrivOctets, ObservedAddress, SealedReply, UnsealedCode,
};
use keyd::{
    InMemoryKeyStore, KeyHandle, KeyPurpose, Keyd, PrincipalBinding, PrincipalId, Role,
    ADDRESS_TYPE_DIRECTIONAL,
};
use keyd_daemon::test_seams::ExtraListener;
use keyd_daemon::{CallerMap, RecordBuffer};
use krb_crypto::ProtocolKey;
use krb_proto::constants::{DOMAIN_X500_COMPRESS, KRB_NT_PRINCIPAL, PA_ENC_TIMESTAMP};
use krb_proto::{
    ApOptions, ApRep, ApReq, Authenticator, ChangePasswdData, EncApRepPart, EncKrbPrivPart,
    EncTicketPart, EncryptedData, EncryptionKey, HostAddress, KerberosTime, KeyValue, KrbPriv,
    Microseconds, NewPasswd, PaData, PaEncTsEnc, PrincipalName, ResultCode, Ticket, TicketFlags,
    TransitedEncoding, UserData,
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
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

// ---------------------------------------------------------------------------
// The domain (test data).
// ---------------------------------------------------------------------------

const DC_FQDN: &str = "dc1.example.org";
const TICKET_AGE_MAX: Duration = Duration::from_secs(600);
const QUORUM: usize = 2;
const NODE_ID: NodeId = NodeId([0xB7; 16]);

const ROOT: u32 = 1;
const TIER0_OU: u32 = 2;
const STAFF_OU: u32 = 3;
const KRBTGT: u32 = 10;
const LDAP_SVC: u32 = 11;
const ADMIND_SVC: u32 = 12;
const CHANGEPW_SVC: u32 = 13;
const ADMIN1: u32 = 14;
const TIER0_GROUP: u32 = 20;
const BOOTSTRAP: u32 = 21;
const ALICE: u32 = 30;
const WS1: u32 = 31;

/// The principals in RID order (krbtgt is RID 502).
const RID_ORDER: [u32; 9] = [
    LDAP_SVC,
    ADMIND_SVC,
    CHANGEPW_SVC,
    ADMIN1,
    TIER0_GROUP,
    BOOTSTRAP,
    ALICE,
    WS1,
    ROOT,
];

/// whenCreated / pwdLastSet: 2026-11-01T00:00:00Z as DSTIME (derivation in
/// crates/directory-admin tests/common `PROVISIONED_DSTIME`).
const PROVISIONED_DSTIME: i64 = 13_437_964_800;

/// The client's subkey (RFC 3244 §2: "must be pseudo-randomly generated" —
/// a fixed value is enough for a test) and initial sequence number (RFC
/// 4120 §5.5.1: "SHOULD be random").
const SUBKEY: [u8; 32] = [0x6B; 32];
const SEQ: u32 = 0x8A21_3C47;

/// The new passwords (made up; they meet the owner's policy, A-153).
const NEW_PASSWORD: &str = "Garland-Owl-24-Fir";

fn g(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0xB7,
        data3: 0x00E2,
        data4: [0xE, 2, 0xE, 2, 0xE, 2, 0xE, 2],
    }
}

fn domain_sid() -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 7, 8, 9]).unwrap()
}

fn sid_of(id: u32) -> Sid {
    let rid = if id == KRBTGT {
        502
    } else {
        1101 + u32::try_from(RID_ORDER.iter().position(|p| *p == id).unwrap()).unwrap()
    };
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 7, 8, 9, rid]).unwrap()
}

fn dn(rdns: &[&str]) -> Dn {
    Dn::new(rdns.iter().map(|s| (*s).to_owned()).collect())
}

fn nc_dn() -> Dn {
    dn(&["dc=example", "dc=org"])
}

/// The rights the root SD grants the Tier-0 group (docs/51 §10).
const ADMIN_RIGHTS: u32 = RIGHT_DS_CREATE_CHILD
    | RIGHT_DS_DELETE_CHILD
    | RIGHT_DS_READ_PROPERTY
    | RIGHT_DS_WRITE_PROPERTY
    | RIGHT_DELETE
    | RIGHT_DS_CONTROL_ACCESS
    | RIGHT_DS_LIST_CONTENTS
    | RIGHT_READ_CONTROL;

/// The root SD: the Tier-0 group's rights, and — the ACE task K9 adds
/// (docs/53 §5.6 step 4) — User-Change-Password for PRINCIPAL_SELF
/// (S-1-5-10, [MS-DTYP] 2.4.2.4 as crates/pdp substitutes it), inherited by
/// every account ([MS-ADTS] 3.1.1.3.1.5.1: "on itself"; 6.1.1.2.7.52).
fn root_sd() -> SecurityDescriptor {
    SecurityDescriptor {
        sbz1: 0,
        control: Control(Control::SELF_RELATIVE | Control::DACL_PRESENT),
        owner_sid: Some(sid_of(TIER0_GROUP)),
        group_sid: Some(sid_of(TIER0_GROUP)),
        sacl: None,
        dacl: Some(Acl {
            acl_revision: ACL_REVISION_DS,
            aces: vec![
                Ace::AccessAllowed(MaskSidAce {
                    ace_flags: ace_flags::CONTAINER_INHERIT_ACE,
                    mask: AccessMask(ADMIN_RIGHTS),
                    sid: sid_of(TIER0_GROUP),
                }),
                Ace::AccessAllowedObject(ObjectAce {
                    ace_flags: ace_flags::CONTAINER_INHERIT_ACE,
                    mask: AccessMask(RIGHT_DS_CONTROL_ACCESS),
                    object_type: Some(directory_admin::USER_CHANGE_PASSWORD),
                    inherited_object_type: None,
                    sid: Sid::new(SECURITY_NT_AUTHORITY, &[10]).unwrap(),
                }),
            ],
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

fn text(s: &str) -> Vec<Vec<u8>> {
    vec![s.as_bytes().to_vec()]
}

fn int64(v: i64) -> Vec<Vec<u8>> {
    vec![v.to_be_bytes().to_vec()]
}

fn flags(v: u32) -> Vec<Vec<u8>> {
    vec![v.to_be_bytes().to_vec()]
}

struct Planned {
    id: u32,
    parent: Option<u32>,
    class: &'static str,
    attrs: Vec<(&'static str, Vec<Vec<u8>>)>,
}

/// The plan (docs/51 §4.3 step 5's shape): ou=Tier0 (krbtgt, the three
/// service objects — the third, `changepw-svc$`, holds `kadmin/changepw`,
/// RFC 3244 §2, as task K9 will provision it —, admin1 and the Tier-0
/// group) and ou=Staff (alice, the computer ws1$, the bootstrap group).
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
    let mut ws1 = account(WS1, "ws1$", uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT, true);
    ws1[0] = ("cn", text("ws1"));
    ws1.push(("dNSHostName", text("ws1.example.org")));
    let planned = |id, parent, class, attrs| Planned {
        id,
        parent,
        class,
        attrs,
    };
    vec![
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
        planned(
            ADMIND_SVC,
            Some(TIER0_OU),
            "computer",
            service(ADMIND_SVC, "admind-svc$", "admind/dc1.example.org"),
        ),
        planned(
            CHANGEPW_SVC,
            Some(TIER0_OU),
            "computer",
            service(CHANGEPW_SVC, "changepw-svc$", "kadmin/changepw"),
        ),
        planned(
            ADMIN1,
            Some(TIER0_OU),
            "user",
            account(ADMIN1, "admin1", n, true),
        ),
        planned(
            ALICE,
            Some(STAFF_OU),
            "user",
            account(ALICE, "alice", n, true),
        ),
        planned(WS1, Some(STAFF_OU), "computer", ws1),
        planned(
            TIER0_GROUP,
            Some(TIER0_OU),
            "group",
            group(TIER0_GROUP, "tier0", &[ADMIN1]),
        ),
        planned(
            BOOTSTRAP,
            Some(STAFF_OU),
            "group",
            group(BOOTSTRAP, "bootstrap", &[]),
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
/// (docs/51 §4.3 step 5, §8.3; A-83). The fixture writes beneath the one
/// checker, so it writes what the checker would have (task PN4b; docs/59
/// §4.3, §5.1, §5.5): every principal's namespace keys — derived by
/// tests/support `namespace`, the three service objects listed (they carry
/// the DC's host name without its key — Q-1010 item 3) — which the one
/// lookup path probes for the kpasswd service, the ticket's client and the
/// target; and the `principal-namespace` marker.
fn provision(path: &Path) -> Arc<Store> {
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
    for _ in RID_ORDER {
        txn.take_counter_value(RID_COUNTER).unwrap();
    }
    support::namespace::create_namespace_marker(&mut txn);
    let mut sds: BTreeMap<u32, SecurityDescriptor> = BTreeMap::new();
    let mut created = Vec::new();
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
        created.push((g(planned.id), origin));
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
    let ctx = directory_pip::DirectoryContext::new(
        p1.clone(),
        &support::keyd_config(),
        support::naming_context(),
    )
    .unwrap()
    .with_service_objects([LDAP_SVC, ADMIND_SVC, CHANGEPW_SVC].map(g).into());
    support::namespace::write_namespace_keys(&store, &mut txn, &ctx, &created);
    txn.commit().unwrap();
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    Arc::new(store)
}

/// The policy: tier map {tier0 group → Tier0}, {ou=Tier0 → Tier0, ou=Staff
/// → Tier2}; the Tier-0 group may run every Directory action under the NC
/// root; and — the rule task K9 adds (docs/53 §5.6 step 4) —
/// `DirControlRight(User-Change-Password)` for any subject under the NC
/// root: the coarse layer lets it through, the object's ACL (PRINCIPAL_SELF)
/// decides.
fn policy() -> DevelopmentPolicy {
    let rule = |id: u32, action: ActionMatch, subject: SubjectMatch| Rule {
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
    DevelopmentPolicy {
        version: PolicyVersion(1),
        principals: BTreeMap::from([(sid_of(TIER0_GROUP), Tier::Tier0)]),
        subtrees: vec![
            (dn(&["ou=Tier0", "dc=example", "dc=org"]), Tier::Tier0),
            (dn(&["ou=Staff", "dc=example", "dc=org"]), Tier::Tier2),
        ],
        mandatory_fast: MandatoryFast {
            bootstrap_group: sid_of(BOOTSTRAP),
            first_rule_id: RuleId(100),
        },
        rules: vec![
            rule(
                1,
                ActionMatch::Class(pdp::ActionClass::Directory),
                SubjectMatch::MemberOf(sid_of(TIER0_GROUP)),
            ),
            rule(
                2,
                ActionMatch::Exact(pdp::Action::DirControlRight(pdp::ControlRightId(
                    directory_admin::USER_CHANGE_PASSWORD,
                ))),
                SubjectMatch::Any,
            ),
        ],
        anonymous: Vec::new(),
    }
}

/// The provisioning manifest (docs/51 §4.3 step 8).
fn manifest() -> Manifest {
    Manifest::new(&ManifestFields {
        realm: String::from(support::REALM),
        domain_sid: domain_sid(),
        naming_context: vec![String::from("example"), String::from("org")],
        dc_fqdn: String::from(DC_FQDN),
        krbtgt: g(KRBTGT),
        ldap_service: g(LDAP_SVC),
        admin_service: g(ADMIND_SVC),
        // Required since task K9: the object that holds `kadmin/changepw`
        // in this directory (docs/53 §5.2; docs/questions/Q-964 item 4).
        change_password_service: g(CHANGEPW_SVC),
        // The manifest's quorum of first administrators (the second is not
        // in this directory: these tests read the manifest's service
        // objects only).
        first_admins: vec![
            (g(ADMIN1), String::from("admin1")),
            (g(99), String::from("admin2")),
        ],
        // Required since A-105 (Q-473); obviously fake.
        first_admin_salts: vec![
            String::from("test-salt-admin1"),
            String::from("test-salt-admin2"),
        ],
    })
    .unwrap()
}

// ---------------------------------------------------------------------------
// keyd: the change-password service's key set and alice's password.
// ---------------------------------------------------------------------------

/// The change-password service's key set in this directory: `(objectGUID of
/// changepw-svc$, ChangePasswordService)` — the purpose the one derivation
/// gives `kadmin/changepw` (docs/53 §5.2; docs/52 R2b).
fn changepw_handle() -> KeyHandle {
    KeyHandle::new(
        PrincipalId::from_bytes(g(CHANGEPW_SVC).to_packet()),
        KeyPurpose::of_service_name(&common::change_password_name()),
    )
}

/// alice's password key set (docs/47 §9.1: `(objectGUID, PrincipalLongterm)`).
fn alice_handle() -> KeyHandle {
    KeyHandle::new(
        PrincipalId::from_bytes(g(ALICE).to_packet()),
        KeyPurpose::PrincipalLongterm,
    )
}

/// keyd with the change-password service's key set (`create_key`, docs/53
/// §5.2 — the scripted entropy gives it `CHANGEPW_KEY`, the kdc fixtures'
/// value) and alice's password (`ALICE_PASSWORD` with the user salt of
/// docs/47 §3.3, through a set-secret decision and `set_secret`, as the kdc
/// fixtures set it).
fn kpasswd_keyd(
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
        entropy.push(&common::CHANGEPW_KEY[..length]);
    }
    let now = common::now();
    keyd.create_key(
        &common::ADMIN,
        &changepw_handle(),
        &PrincipalBinding::new(common::realm(), common::change_password_name()),
        &now,
    )
    .unwrap();
    let alice = PrincipalBinding::new(common::realm(), common::alice_name());
    common::grant_user(&mut keyd, &alice_handle(), &alice, &now);
    keyd.set_secret(
        &common::DIRECTORY,
        &alice_handle(),
        &alice,
        String::from(common::ALICE_PASSWORD).into(),
        common::ALICE_SALT,
        &now,
    )
    .unwrap();
    let _ = keyd.audit_sink_mut().take();
    Ok(keyd)
}

// ---------------------------------------------------------------------------
// A fake auditd that can withhold its acknowledgements and look at the
// store when an event arrives.
// ---------------------------------------------------------------------------

type Hook = Arc<dyn Fn(&EventBody) + Send + Sync>;

struct Auditd {
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

impl Auditd {
    fn start(path: &Path, hook: Option<Hook>) -> Auditd {
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
        Auditd {
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

    /// The `ChangePassword` events received (acknowledged) so far, in order.
    fn change_events(&self) -> Vec<DirAdminEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                EventBody::DirAdmin(event)
                    if event.operation == DirAdminOperation::ChangePassword =>
                {
                    Some((**event).clone())
                }
                _ => None,
            })
            .collect()
    }
}

impl Drop for Auditd {
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
/// then `Ack` — or, while withholding, nothing.
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
// dird with its admin service and its kpasswd service.
// ---------------------------------------------------------------------------

/// dird's clock: the kdc fixtures' `now` plus the test's offset in seconds
/// (`Options::dird_offset`: 1 by default, so the change's `pwdLastSet`
/// lies a second after the ticket's authtime; 0 puts it in the AS's own
/// second — docs/47 §4.5, Q-965).
struct FixedNow(Arc<AtomicI64>);

impl Clock for FixedNow {
    fn now(&self) -> Option<KerberosTime> {
        Some(common::at(self.0.load(Ordering::SeqCst)))
    }
}

struct DirdRun {
    control: DaemonControl,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl Drop for DirdRun {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

/// What a world is built with.
#[derive(Clone)]
struct Options {
    /// The configured front uid is the test's uid plus this.
    front_uid_offset: u32,
    /// dird's decision-acknowledgement wait.
    ack_deadline: DecisionAckDeadline,
    /// A hook recording alice's `pwdLastSet` and the change-seq counter at
    /// every `Decision(Proceed)` of a `ChangePassword`.
    hook: bool,
    /// dird's clock, in seconds after the kdc fixtures' `now` (the AS's
    /// authtime).
    dird_offset: i64,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            front_uid_offset: 0,
            // The ceiling, so a fake auditd slowed by a loaded machine still
            // answers in time (A-95 follow-up, Q-441).
            ack_deadline: DecisionAckDeadline::new(MAX_DECISION_ACK_DEADLINE).unwrap(),
            hook: false,
            dird_offset: 1,
        }
    }
}

/// What the hook saw: (alice's pwdLastSet, the change-seq counter's next
/// value) at each `ChangePassword` decision event.
type Seen = Arc<Mutex<Vec<(Vec<u8>, u64)>>>;

/// keyd, both auditds, dird with its admin and kpasswd services.
struct World {
    dir: support::TempDir,
    uid: u32,
    store: Arc<Store>,
    auditd: Auditd,
    _keyd_auditd: support::FakeAuditd,
    keyd: Option<support::keyd::Daemon>,
    dird: Option<DirdRun>,
    kpasswd_socket: PathBuf,
    /// The same keyd, the test's uid as Role::Kdc — to see whether a
    /// password verifies (keyd `verify_preauth`, docs/10 §4).
    keyd_kdc_socket: PathBuf,
    /// (alice's pwdLastSet, change-seq next value) at every
    /// `Decision(Proceed)` of a `ChangePassword` (the hook).
    seen_at_decision: Seen,
}

fn alice_pwd_last_set(store: &Store) -> Vec<u8> {
    let p1 = phase1().unwrap();
    let obj = store
        .snapshot()
        .unwrap()
        .get_object(g(ALICE))
        .unwrap()
        .unwrap();
    obj.attribute(p1.attribute_by_name("pwdLastSet").unwrap())
        .unwrap()
        .values[0]
        .value
        .clone()
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

impl World {
    fn new(options: Options) -> Option<World> {
        let dir = support::TempDir::new();
        let uid = support::my_uid(&dir);
        if support::skip_as_root(uid) {
            return None;
        }
        let store = provision(&dir.join("s.redb"));

        // keyd: the test's uid is Role::Ldap (dird's, A-73) on its socket and
        // Role::Kdc on a second one; its own fake auditd.
        let mut keyd_params =
            support::keyd::params(&dir, CallerMap::new(&[(uid, Role::Ldap)]).unwrap(), uid);
        keyd_params.audit.socket = dir.join("ka.sock");
        let keyd_kdc_socket = dir.join("kc.sock");
        keyd_params.extra_listeners = vec![ExtraListener {
            socket: keyd_kdc_socket.clone(),
            callers: CallerMap::new(&[(uid, Role::Kdc)]).unwrap(),
        }];
        let keyd_socket = keyd_params.keyd_socket.clone();
        let keyd_auditd = support::FakeAuditd::start(&keyd_params.audit.socket);
        let clock = support::TestClock::at(common::keyd_started());
        let keyd = support::keyd::Daemon::start(keyd_params, clock.clone(), kpasswd_keyd).unwrap();
        clock.set(common::now());

        // dird's auditd.
        let seen_at_decision: Seen = Arc::new(Mutex::new(Vec::new()));
        let hook: Option<Hook> = if options.hook {
            let (store, seen) = (Arc::clone(&store), Arc::clone(&seen_at_decision));
            Some(Arc::new(move |event: &EventBody| {
                if let EventBody::DirAdmin(event) = event {
                    if event.operation == DirAdminOperation::ChangePassword
                        && event.stage == DirAdminStage::Decision(DecisionResult::Proceed)
                    {
                        seen.lock()
                            .unwrap()
                            .push((alice_pwd_last_set(&store), change_seq_next(&store)));
                    }
                }
            }))
        } else {
            None
        };
        let auditd = Auditd::start(&dir.join("a.sock"), hook);

        // dird.
        let mut params = support::params(&dir, uid, uid, Duration::from_secs(5), 4);
        params.clock = SharedClock::new(FixedNow(Arc::new(AtomicI64::new(options.dird_offset))));
        let realm = common::realm();
        let verifier: VerifierFactory = {
            let (socket, realm) = (keyd_socket.clone(), realm.clone());
            Arc::new(move || {
                let verifier: Box<dyn TicketVerifier> = Box::new(
                    KeydTicketVerifier::new(
                        support::connector::keyd(&socket),
                        uid,
                        realm.clone(),
                        ipc_keyd::DEFAULT_DEADLINE,
                    )
                    .ok()?,
                );
                Some(verifier)
            })
        };
        let kpasswd_keyd: KpasswdKeydFactory = {
            let (socket, realm) = (keyd_socket.clone(), realm.clone());
            Arc::new(move || {
                let client: Box<dyn KpasswdKeyd> = Box::new(
                    KeydKpasswdClient::new(
                        support::connector::keyd(&socket),
                        uid,
                        realm.clone(),
                        ipc_keyd::DEFAULT_DEADLINE,
                    )
                    .ok()?,
                );
                Some(client)
            })
        };
        let admin = AdminParams {
            socket: dir.join("m.sock"),
            admind_uid: uid,
            keyd: Some(verifier),
            ticket_age_max: TICKET_AGE_MAX,
            quorum: QUORUM,
            node_id: NODE_ID,
            manifest: manifest(),
            max_connections: directory_daemon::MAX_ADMIN_CONNECTIONS,
            queue_capacity: directory_daemon::ADMIN_QUEUE_CAPACITY,
            ack_deadline: options.ack_deadline,
            request_lifetime: directory_admin::REQUEST_LIFETIME,
            requests_per_requester: directory_admin::REQUESTS_PER_REQUESTER,
            destroy_reconcile_interval: directory_daemon::DESTROY_RECONCILE_INTERVAL,
            policy_next: None,
        };
        let kpasswd_socket = dir.join("kp.sock");
        let kpasswd = KpasswdParams {
            socket: kpasswd_socket.clone(),
            front_uid: uid + options.front_uid_offset,
            keyd: Some(kpasswd_keyd),
            max_connections: directory_daemon::MAX_KPASSWD_CONNECTIONS,
            queue_capacity: directory_daemon::KPASSWD_QUEUE_CAPACITY,
        };
        let control = DaemonControl::new();
        let thread = {
            let (control, store) = (control.clone(), Arc::clone(&store));
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result = runtime.block_on(serve_with_kpasswd(
                    params,
                    Some(admin),
                    Some(kpasswd),
                    directory_daemon::test_seams::opened(store),
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
        while !(control.is_serving() && kpasswd_socket.exists()) {
            assert!(!thread.is_finished(), "dird did not start");
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "dird's kpasswd service did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        Some(World {
            dir,
            uid,
            store,
            auditd,
            _keyd_auditd: keyd_auditd,
            keyd: Some(keyd),
            dird: Some(DirdRun {
                control,
                thread: Some(thread),
            }),
            kpasswd_socket,
            keyd_kdc_socket,
            seen_at_decision,
        })
    }

    /// The fake front: the front's own client, expecting dird's uid (the
    /// test's) and the internal zone (docs/53 §5.6 step 1).
    fn front(&self) -> KpasswdClient {
        KpasswdClient::new(
            self.kpasswd_socket.clone(),
            ExpectedDird::new(self.uid, FrontZone::Internal).unwrap(),
            ipc_kpasswd::DEFAULT_DEADLINE,
        )
    }

    /// Hand one request to dird as the front does.
    fn send(&self, ap_req: &[u8], krb_priv: &[u8]) -> Result<KpasswdAnswer, ipc_kpasswd::Unserved> {
        let request = ChangePasswordRequest::new(
            ApReqOctets::new(ap_req).unwrap(),
            KrbPrivOctets::new(krb_priv).unwrap(),
            ObservedAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            ObservedAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(self.front().change_password(&request))
    }

    /// Whether `password` is alice's in keyd: keyd's `verify_preauth`
    /// (Role::Kdc) of a PA-ENC-TIMESTAMP under its key (RFC 4120 §5.2.7.2;
    /// docs/10 §4).
    fn alice_password_is(&self, password: &str) -> bool {
        let key = common::password_key(common::AES256, password, common::ALICE_SALT);
        let plain = PaEncTsEnc {
            patimestamp: common::now(),
            pausec: Some(Microseconds::new(4321).unwrap()),
        }
        .encode()
        .unwrap();
        let padata = PaData {
            padata_type: PA_ENC_TIMESTAMP,
            padata_value: EncryptedData {
                etype: key.enc_type().number(),
                kvno: None,
                cipher: krb_crypto::encrypt(&key, common::usage(1), &[0x31; 16], &plain).unwrap(),
            }
            .encode()
            .unwrap(),
        };
        let mut client = ipc_keyd::KeydClient::new(
            support::connector::keyd(&self.keyd_kdc_socket),
            ipc_keyd::ExpectedPeer::new(self.uid, Role::Kdc).unwrap(),
            ipc_keyd::DEFAULT_DEADLINE,
        );
        client
            .verify_preauth(&alice_handle(), &padata, None)
            .is_ok()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        drop(self.dird.take());
        if let Some(keyd) = self.keyd.take() {
            let _ = keyd.stop();
        }
        let _ = &self.dir;
    }
}

// ---------------------------------------------------------------------------
// The Kerberos client (RFC 3244 §2; RFC 4120 §5.5.1, §5.5.2, §5.7.1).
// ---------------------------------------------------------------------------

/// A `kadmin/changepw` ticket and its session key, as the client holds them.
struct ChangeTicket {
    ticket: Ticket,
    session: ProtocolKey,
    cname: PrincipalName,
}

/// alice's change-password ticket through the KDC's **armored** AS (RFC 6113
/// 5.4.2; docs/53 §5.2: only from an armored AS, INITIAL set by keyd), from
/// the kdc fixtures' KDC (its keyd holds the same scripted keys as this
/// test's keyd daemon).
fn alice_ticket() -> ChangeTicket {
    let mut f = common::Fixture::new();
    let key = common::alice_key(common::AES256);
    let spec = common::AsReqSpec {
        sname: Some(common::change_password_name()),
        ..common::AsReqSpec::alice()
    };
    let fast = f.send_fast(&spec.with_challenge(&key));
    let tgt = common::open_fast_as_rep(&common::sent(fast.reply), &fast.armor_key, &key);
    assert!(
        tgt.part.0.flags.contains(TicketFlags::INITIAL),
        "RFC 4120 2.1: an AS ticket is INITIAL"
    );
    ChangeTicket {
        ticket: tgt.rep.0.ticket.clone(),
        session: tgt.session,
        cname: common::alice_name(),
    }
}

/// A `kadmin/changepw` ticket of `sam` sealed here under the change-password
/// service key (usage 2; INITIAL | PRE-AUTHENT, authtime the kdc fixtures'
/// `now`, 300 s) — for the accounts the KDC never issues one to.
fn sealed_ticket(sam: &str) -> ChangeTicket {
    let session = common::aes256(&[0x5E; 32]);
    let cname = common::name(KRB_NT_PRINCIPAL, &[sam]);
    let part = EncTicketPart {
        flags: TicketFlags::INITIAL.union(TicketFlags::PRE_AUTHENT),
        key: EncryptionKey {
            keytype: common::AES256,
            keyvalue: KeyValue::from_slice(&[0x5E; 32]),
        },
        crealm: common::realm(),
        cname: cname.clone(),
        transited: TransitedEncoding {
            tr_type: DOMAIN_X500_COMPRESS,
            contents: Vec::new(),
        },
        authtime: common::now(),
        starttime: None,
        endtime: common::at(300),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let plain = part.encode().unwrap();
    let service = common::aes256(&common::CHANGEPW_KEY);
    ChangeTicket {
        ticket: Ticket {
            realm: common::realm(),
            sname: common::change_password_name(),
            enc_part: EncryptedData {
                etype: service.enc_type().number(),
                kvno: Some(1),
                cipher: krb_crypto::encrypt(&service, common::usage(2), &[0x31; 16], &plain)
                    .unwrap(),
            },
        },
        session,
        cname,
    }
}

/// A fresh cusec for every Authenticator (keyd's replay cache, RFC 4120
/// §3.2.3).
static CUSEC: AtomicU32 = AtomicU32::new(10);

/// The RFC 3244 request of `held` for `password`: the AP-REQ (Authenticator
/// under the session key, usage 11, with the subkey and the sequence
/// number) and the KRB-PRIV (EncKrbPrivPart under the subkey, usage 13: the
/// ChangePasswdData, the sequence number, the Directional address 0 —
/// RFC 4120 §7.1). Returns the two messages and the cusec.
fn request(held: &ChangeTicket, password: &str) -> (Vec<u8>, Vec<u8>, u32) {
    let cusec = CUSEC.fetch_add(1, Ordering::SeqCst);
    let authenticator = Authenticator {
        crealm: common::realm(),
        cname: held.cname.clone(),
        cksum: None,
        cusec: Microseconds::new(cusec).unwrap(),
        ctime: common::now(),
        subkey: Some(EncryptionKey {
            keytype: common::AES256,
            keyvalue: KeyValue::from_slice(&SUBKEY),
        }),
        seq_number: Some(SEQ),
        authorization_data: None,
    }
    .encode()
    .unwrap();
    let ap_req = ApReq {
        ap_options: ApOptions::empty(),
        ticket: held.ticket.clone(),
        authenticator: EncryptedData {
            etype: held.session.enc_type().number(),
            kvno: None,
            cipher: krb_crypto::encrypt(
                &held.session,
                common::usage(11),
                &[0x42; 16],
                &authenticator,
            )
            .unwrap(),
        },
    }
    .encode()
    .unwrap();
    let user_data = ChangePasswdData::change(NewPasswd::from_slice(password.as_bytes()))
        .encode()
        .unwrap();
    let part = EncKrbPrivPart {
        user_data: UserData::from_slice(&user_data),
        timestamp: Some(common::now()),
        usec: Some(Microseconds::new(cusec).unwrap()),
        seq_number: Some(SEQ),
        s_address: HostAddress {
            addr_type: ADDRESS_TYPE_DIRECTIONAL,
            address: vec![0, 0, 0, 0],
        },
        r_address: None,
    }
    .encode()
    .unwrap();
    let subkey = common::aes256(&SUBKEY);
    let krb_priv = KrbPriv {
        enc_part: EncryptedData {
            etype: subkey.enc_type().number(),
            kvno: None,
            cipher: krb_crypto::encrypt(&subkey, common::usage(13), &[0x43; 16], &part).unwrap(),
        },
    }
    .encode()
    .unwrap();
    (ap_req, krb_priv, cusec)
}

/// The client opens keyd's sealed reply: the AP-REP under the session key
/// (usage 12) with its own ctime / cusec (RFC 4120 §3.2.4), the KRB-PRIV
/// under the subkey (usage 13) whose user-data is exactly the two-octet
/// result code — no result string (Q-604 item 5).
fn result_of(held: &ChangeTicket, sealed: &SealedReply, cusec: u32) -> ResultCode {
    let ap_rep = ApRep::decode(sealed.ap_rep().as_bytes()).unwrap();
    let rep = EncApRepPart::decode(&common::open(&held.session, 12, &ap_rep.enc_part)).unwrap();
    assert_eq!(
        rep.ctime,
        common::now(),
        "RFC 4120 3.2.4: the client's ctime"
    );
    assert_eq!(rep.cusec.get(), cusec, "RFC 4120 3.2.4: the client's cusec");
    let krb_priv = KrbPriv::decode(sealed.krb_priv().as_bytes()).unwrap();
    let part = EncKrbPrivPart::decode(&common::open(
        &common::aes256(&SUBKEY),
        13,
        &krb_priv.enc_part,
    ))
    .unwrap();
    assert_eq!(
        part.user_data.as_bytes().len(),
        2,
        "RFC 3244 §2: no result string"
    );
    ResultCode::from_result_data(part.user_data.as_bytes()).unwrap()
}

/// The sealed reply of `answer`.
fn sealed(answer: KpasswdAnswer) -> SealedReply {
    match answer {
        KpasswdAnswer::Sealed(sealed) => sealed,
        KpasswdAnswer::Unsealed(code) => panic!("expected a sealed reply, got {code:?}"),
    }
}

fn is_committed(event: &DirAdminEvent) -> bool {
    matches!(
        event.stage,
        DirAdminStage::Outcome(OutcomeResult::Committed { .. })
    )
}

/// Wait until auditd holds `count` `ChangePassword` events.
fn await_change_events(world: &World, count: usize) -> Vec<DirAdminEvent> {
    assert!(
        support::eventually(Duration::from_secs(10), || world
            .auditd
            .change_events()
            .len()
            >= count),
        "{:?}",
        world.auditd.change_events()
    );
    world.auditd.change_events()
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

/// docs/53 §5.6, §10 K10 (as far as dird's tier-2 world goes): alice's
/// armored `kadmin/changepw` ticket ⇒ the front hands dird her request ⇒
/// keyd opens it, dird decides `ChangePassword` (User-Change-Password on
/// herself, [MS-ADTS] 3.1.1.3.1.5.1), its decision event is acknowledged,
/// `pwdLastSet` = dird's now, the `ChangePassword` decision registered, keyd
/// completes ⇒ a sealed SUCCESS her client opens (RFC 3244 §2; RFC 4120
/// §3.2.4). The new password verifies in keyd and the old one does not. The
/// same ticket with a fresh Authenticator ⇒ sealed AUTHERROR (the change
/// revoked it, R53-9; docs/47 §4.5); the same request octets ⇒ keyd's replay
/// cache (RFC 4120 §3.2.3) ⇒ unsealed AUTHERROR (A-26).
#[test]
fn an_armored_change_password_ticket_changes_the_password() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    assert!(world.alice_password_is(common::ALICE_PASSWORD));
    let held = alice_ticket();
    let (ap_req, krb_priv, cusec) = request(&held, NEW_PASSWORD);
    let answer = world.send(&ap_req, &krb_priv).unwrap();
    assert_eq!(
        result_of(&held, &sealed(answer), cusec),
        ResultCode::Success
    );

    // The decision event before the commit, the outcome after it (docs/51
    // §5.7 item 2; docs/53 §9: target = alice's own account).
    let events = await_change_events(&world, 2);
    assert_eq!(
        events[0].stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    assert!(is_committed(&events[1]));
    assert_eq!(events[0].operation_id, events[1].operation_id);
    assert_eq!(events[0].target, Some(g(ALICE).to_packet()));
    // pwdLastSet = dird's now (the kdc fixtures' now + 1 s) as FILETIME
    // ([MS-DTYP] 2.3.3 via directory-admin `filetime`).
    let filetime = directory_admin::filetime(&common::at(1)).unwrap();
    assert_eq!(
        alice_pwd_last_set(&world.store),
        filetime.to_be_bytes().to_vec()
    );
    // keyd installed it (docs/53 §5.5): the new password verifies, the old
    // one does not.
    assert!(world.alice_password_is(NEW_PASSWORD));
    assert!(!world.alice_password_is(common::ALICE_PASSWORD));

    // The same ticket, a fresh Authenticator: revoked by the change.
    let (ap_req2, krb_priv2, cusec2) = request(&held, "Quill-Marsh-31-Pebble");
    let answer = world.send(&ap_req2, &krb_priv2).unwrap();
    assert_eq!(
        result_of(&held, &sealed(answer), cusec2),
        ResultCode::Failure(krb_proto::NonZeroResultCode::AuthError)
    );
    assert!(world.alice_password_is(NEW_PASSWORD));

    // The same request octets again: keyd's replay cache.
    assert_eq!(
        world.send(&ap_req, &krb_priv).unwrap(),
        KpasswdAnswer::Unsealed(UnsealedCode::AuthError)
    );
}

/// Q-965 (a) / A-161; docs/53 R53-9 exact ("one INITIAL ticket ⇒ at most
/// one change"); docs/47 §4.5 (R47-7); RFC 4120 §3.3.3.1, §5.2.3 (authtime
/// in whole seconds): dird's clock in the AS's own second (offset 0) — the
/// change's `pwdLastSet` is the authtime's whole second — and the same
/// ticket with a fresh Authenticator (keyd's verdict again `Acceptable`) ⇒
/// sealed AUTHERROR, its decision event `Unauthenticated`: the change
/// revoked the ticket of its own second. Under the former
/// `ceil_s(pwdLastSet)` cut this second change passed (Q-965).
#[test]
fn a_change_in_the_tickets_own_second_revokes_it() {
    let Some(world) = World::new(Options {
        dird_offset: 0,
        ..Options::default()
    }) else {
        return;
    };
    let held = alice_ticket();
    let (ap_req, krb_priv, cusec) = request(&held, NEW_PASSWORD);
    let answer = world.send(&ap_req, &krb_priv).unwrap();
    assert_eq!(
        result_of(&held, &sealed(answer), cusec),
        ResultCode::Success
    );
    // pwdLastSet = dird's now = the AS's second ([MS-DTYP] 2.3.3 via
    // directory-admin `filetime`).
    let filetime = directory_admin::filetime(&common::now()).unwrap();
    assert_eq!(
        alice_pwd_last_set(&world.store),
        filetime.to_be_bytes().to_vec()
    );
    assert!(world.alice_password_is(NEW_PASSWORD));

    // The same ticket, a fresh Authenticator, in the same second: revoked.
    let other = "Quill-Marsh-31-Pebble";
    let (ap_req2, krb_priv2, cusec2) = request(&held, other);
    let answer = world.send(&ap_req2, &krb_priv2).unwrap();
    assert_eq!(
        result_of(&held, &sealed(answer), cusec2),
        ResultCode::Failure(krb_proto::NonZeroResultCode::AuthError)
    );
    let events = await_change_events(&world, 3);
    assert_eq!(
        events[2].stage,
        DirAdminStage::Decision(DecisionResult::Refused(
            ipc_audit::AdminRefusal::Unauthenticated
        ))
    );
    assert!(world.alice_password_is(NEW_PASSWORD));
    assert!(!world.alice_password_is(other));
}

/// docs/53 R53-1, §5.6 step 4, §5.7: a computer's request (its ticket sealed
/// here — the KDC refuses it, K5) is opened by keyd and refused by dird —
/// sealed ACCESSDENIED; its decision event says `TargetProtected`; nothing
/// is written.
#[test]
fn a_computer_is_refused() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let seq = change_seq_next(&world.store);
    let held = sealed_ticket("ws1$");
    let (ap_req, krb_priv, cusec) = request(&held, NEW_PASSWORD);
    let answer = world.send(&ap_req, &krb_priv).unwrap();
    assert_eq!(
        result_of(&held, &sealed(answer), cusec),
        ResultCode::Failure(krb_proto::NonZeroResultCode::AccessDenied)
    );
    let events = await_change_events(&world, 1);
    assert_eq!(
        events[0].stage,
        DirAdminStage::Decision(DecisionResult::Refused(
            ipc_audit::AdminRefusal::TargetProtected
        ))
    );
    assert_eq!(change_seq_next(&world.store), seq);
}

/// P-22; docs/questions/Q-608 item 1 (owner-open — the strict default):
/// admin1, a Tier0 account, may not change its own password through
/// kpasswd: sealed ACCESSDENIED, its decision event `ApprovalRequired`,
/// nothing written.
#[test]
fn a_tier0_account_is_refused() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let seq = change_seq_next(&world.store);
    let held = sealed_ticket("admin1");
    let (ap_req, krb_priv, cusec) = request(&held, NEW_PASSWORD);
    let answer = world.send(&ap_req, &krb_priv).unwrap();
    assert_eq!(
        result_of(&held, &sealed(answer), cusec),
        ResultCode::Failure(krb_proto::NonZeroResultCode::AccessDenied)
    );
    let events = await_change_events(&world, 1);
    assert_eq!(
        events[0].stage,
        DirAdminStage::Decision(DecisionResult::Refused(
            ipc_audit::AdminRefusal::ApprovalRequired
        ))
    );
    assert_eq!(change_seq_next(&world.store), seq);
}

/// docs/53 §5.4 item 6, §5.6 step 3, §6.2-§6.3; A-153: a new password that
/// breaks the policy (it contains the account's name, [MS-SAMR] 3.1.1.7.2
/// item 3.2.2 as applied by admin-password-policy) is keyd's verdict —
/// sealed SOFTERROR with no result string (which rule is never said), before
/// any directory work: no dird event, `pwdLastSet` unchanged, the old
/// password valid.
#[test]
fn a_password_against_the_policy_is_softerror_and_nothing_is_written() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let before = alice_pwd_last_set(&world.store);
    let held = alice_ticket();
    let (ap_req, krb_priv, cusec) = request(&held, "Alice-Lark-39-Marten");
    let answer = world.send(&ap_req, &krb_priv).unwrap();
    assert_eq!(
        result_of(&held, &sealed(answer), cusec),
        ResultCode::Failure(krb_proto::NonZeroResultCode::SoftError)
    );
    assert_eq!(alice_pwd_last_set(&world.store), before);
    assert!(world.alice_password_is(common::ALICE_PASSWORD));
    std::thread::sleep(Duration::from_millis(200));
    assert!(world.auditd.change_events().is_empty());
}

/// docs/53 §5.7 (an AP-REQ keyd cannot open ⇒ AUTHERROR, uniform — A-26;
/// A-126 on docs/questions/Q-660 item 3): octets that carry the AP-REQ and
/// KRB-PRIV identifiers but are no messages are refused by keyd; dird has no
/// context to seal in and answers the front's KRB-ERROR code AUTHERROR.
#[test]
fn a_request_keyd_cannot_open_is_an_unsealed_autherror() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    assert_eq!(
        world.send(&[0x6E, 0x00], &[0x75, 0x00]).unwrap(),
        KpasswdAnswer::Unsealed(UnsealedCode::AuthError)
    );
}

/// docs/53 §5.6 step 1; docs/50 R50-3, §3.2: dird admits only the configured
/// front's uid — a connection from another uid is closed without a reply
/// (the front's client cannot even ping) and counted; keyd is never asked,
/// nothing changes.
#[test]
fn a_wrong_peer_uid_is_closed() {
    let Some(world) = World::new(Options {
        front_uid_offset: 1,
        ..Options::default()
    }) else {
        return;
    };
    let refused = kpasswd_refused_peer_count();
    let held = alice_ticket();
    let (ap_req, krb_priv, _) = request(&held, NEW_PASSWORD);
    assert!(world.send(&ap_req, &krb_priv).is_err());
    assert!(kpasswd_refused_peer_count() > refused);
    assert!(world.alice_password_is(common::ALICE_PASSWORD));
    assert!(world.auditd.change_events().is_empty());
}

/// docs/51 §5.7 item 2; A-85; docs/52 R6; docs/53 §5.6 step 5: auditd
/// receives the `ChangePassword` decision event while alice's `pwdLastSet`
/// and the change-seq counter are still those of before the change — the
/// event is acknowledged before anything commits.
#[test]
fn the_decision_is_acknowledged_before_the_commit() {
    let Some(world) = World::new(Options {
        hook: true,
        ..Options::default()
    }) else {
        return;
    };
    let before = (
        alice_pwd_last_set(&world.store),
        change_seq_next(&world.store),
    );
    let held = alice_ticket();
    let (ap_req, krb_priv, cusec) = request(&held, NEW_PASSWORD);
    let answer = world.send(&ap_req, &krb_priv).unwrap();
    assert_eq!(
        result_of(&held, &sealed(answer), cusec),
        ResultCode::Success
    );
    let seen = world.seen_at_decision.lock().unwrap().clone();
    assert_eq!(seen, vec![before]);
    assert_ne!(alice_pwd_last_set(&world.store), seen[0].0);
}

/// A-85 ("auditd unavailable ⇒ refused before any commit"); docs/53 §5.6
/// step 5 ("a failure in one of them ⇒ seal 2"): auditd withholds its
/// acknowledgements ⇒ sealed HARDERROR after the bounded wait; nothing is
/// written and the old password stays valid.
#[test]
fn no_acknowledgement_means_nothing_changes() {
    let Some(world) = World::new(Options {
        ack_deadline: DecisionAckDeadline::new(Duration::from_millis(500)).unwrap(),
        ..Options::default()
    }) else {
        return;
    };
    let before = (
        alice_pwd_last_set(&world.store),
        change_seq_next(&world.store),
    );
    world.auditd.withhold(true);
    let held = alice_ticket();
    let (ap_req, krb_priv, cusec) = request(&held, NEW_PASSWORD);
    let answer = world.send(&ap_req, &krb_priv).unwrap();
    assert_eq!(
        result_of(&held, &sealed(answer), cusec),
        ResultCode::Failure(krb_proto::NonZeroResultCode::HardError)
    );
    assert_eq!(
        (
            alice_pwd_last_set(&world.store),
            change_seq_next(&world.store)
        ),
        before
    );
    world.auditd.withhold(false);
    assert!(world.alice_password_is(common::ALICE_PASSWORD));
    assert!(!world.alice_password_is(NEW_PASSWORD));
}
