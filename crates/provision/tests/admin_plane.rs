//! After provisioning, the admin plane works on the produced directory and
//! policy exactly as docs/51 §5.2 requires, and for nobody else:
//!
//! - directory-admin's `prepare` / `apply` in-process (with injected
//!   verified-ticket facts, as dird's admin service passes them after keyd
//!   verified the AP-REQ — docs/51 §5.3, §7.4): the first administrator
//!   alice (a Tier-0 group member), approved by the second first
//!   administrator bob (P-22: an explicit Tier-0 subtree needs dual
//!   control), performs every operation of docs/51 §5.2 on objects under
//!   the Tier-0 OU — a user at depth 2 (NC root → OU → user);
//! - `pdp::decide` directly, with the produced policy (loaded by
//!   policy-store) and the produced directory as PIP: every A3 action is
//!   allowed for alice on the depth-2 user, nothing beyond it (no other
//!   child class, no other attribute, no other control right), and
//!   nothing at all for an ordinary account.
//!
//! Sources: docs/51 §4.3 step 6, §5.2 (each operation's Action and
//! Resource), §5.3, §5.6 (dual control; P-22), §7.4, §10 (the root SD and
//! inheritance; A-76, A-84); docs/11 §4 (the five layers); crates/pdp
//! `desired_right`; [MS-ADTS] v20261026 5.1.3.2, 6.1.1.2.7.53.
//! Fixtures: tests/common (obviously fake names).

mod common;

use common::*;

use std::collections::BTreeSet;

use directory_admin::{
    AdminConfig, AdminSubject, CompletePasswordSet, CreateComputer, CreateContainerLike,
    CreateGroup, CreateUser, DirectoryAdmin, LookupKey, Membership, Operation, PasswordSetOutcome,
    ProtectedObjects, RandomError, RandomSource, Reply, Request, SetAccountExpires, SetEnabled,
    VerifiedTicket, USER_FORCE_CHANGE_PASSWORD,
};
use directory_daemon::startup::{read_integrity_key, read_policy};
use directory_pip::{DirectoryContext, NamingContext, TierMap};
use dirstore::Store;
use dtyp::{Guid, Sid};
use ipc_audit::{AccountExpiresValue, AdminRefusal, DecisionResult, DirAdminStage};
use keyd_types::KeydConfig;
use krb_proto::constants::KRB_NT_PRINCIPAL;
use krb_proto::{KerberosString, KerberosTime, PrincipalName, Realm};
use pdp::{
    decide, AccessRequest, Action, AttrId, Context, ControlRightId, Effect, Instant, IpScope,
    ObjClass, PolicyScope, PolicySnapshot, Resource, Subject, Transport, TransportSec,
};
use provision::{provision_domain, ObjectRole, Plan};

/// objectGUIDs for the admin plane's creates, distinct from the plan's
/// (tests only — A-15).
#[derive(Debug, Default)]
struct AdminRandom(u64);

impl RandomSource for AdminRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        self.0 += 1;
        let mut pattern = [0xC3u8; 16];
        pattern[8..].copy_from_slice(&self.0.to_be_bytes());
        for (i, o) in out.iter_mut().enumerate() {
            *o = pattern[i % 16];
        }
        Ok(())
    }
}

/// The time of every request: one minute after provisioning; tickets
/// authenticated 10 s after it (after whenCreated + 1 s and pwdLastSet,
/// docs/47 §4.5).
fn request_time() -> KerberosTime {
    at(10, 1, 0)
}

/// The operation binding every request here carries (R2, docs/52 §5 item
/// 4): these tests run the write PEP without dird or keyd, so the digest is
/// a made-up value standing for the one keyd would have verified.
const BOUND: keyd_types::OperationDigest = keyd_types::OperationDigest::new([0xB7; 32]);

fn ticket(name: &str, authtime: KerberosTime) -> VerifiedTicket {
    VerifiedTicket {
        crealm: Realm::new("EXAMPLE.TEST").unwrap(),
        cname: PrincipalName {
            name_type: KRB_NT_PRINCIPAL,
            name_string: vec![KerberosString::new(name).unwrap()],
        },
        authtime,
        bound_operation: Some(BOUND),
    }
}

/// A provisioned domain, opened as dird opens it.
struct Domain {
    _dir: TempDir,
    plan: Plan,
    store: Store,
    ctx: DirectoryContext,
    tiers: TierMap,
    policy: PolicySnapshot,
    admin: DirectoryAdmin<AdminRandom>,
    next_id: u64,
    authtime: KerberosTime,
    now: KerberosTime,
}

enum Ran {
    Applied(Reply),
    Read(Reply),
    Refused(AdminRefusal),
}

impl Ran {
    fn reply(self) -> Reply {
        match self {
            Ran::Applied(r) | Ran::Read(r) => r,
            Ran::Refused(code) => panic!("refused: {code:?}"),
        }
    }

    fn refusal(self) -> AdminRefusal {
        match self {
            Ran::Refused(code) => code,
            _ => panic!("not refused"),
        }
    }
}

impl Domain {
    fn new() -> Option<Domain> {
        let dir = TempDir::new();
        let uid = my_uid(&dir);
        if skip_as_root(uid) {
            return None;
        }
        let input = input(&dir, uid, 61007);
        let (plan, _) = provision_domain(
            &input,
            now(),
            &mut CountingRandom::default(),
            &mut Recorder::new(uid),
            &mut HaltAt::never(),
        )
        .unwrap();
        let p = &input.paths;
        let key = read_integrity_key(p.integrity_key.as_path(), uid).unwrap();
        let schema = ad_schema::phase1().unwrap();
        let store = Store::open(p.database.as_path(), key, schema.schema().clone()).unwrap();
        let policy_file = read_policy(p.policy.as_path(), uid).unwrap();
        let tiers = directory_daemon::policy::tier_map(&policy_file).unwrap();
        let policy = policy_file.snapshot().unwrap();
        let realm = Realm::new("EXAMPLE.TEST").unwrap();
        let nc = NamingContext::new(&["example", "test"]).unwrap();
        let ctx = DirectoryContext::new(
            ad_schema::phase1().unwrap(),
            &KeydConfig::new(realm.clone()),
            nc.clone(),
        )
        .unwrap();
        let protected = ProtectedObjects {
            service_objects: BTreeSet::from([
                plan.object(ObjectRole::LdapService).unwrap().guid,
                plan.object(ObjectRole::AdminService).unwrap().guid,
            ]),
            policy_principals: BTreeSet::from([plan
                .object(ObjectRole::BootstrapGroup)
                .unwrap()
                .sid
                .unwrap()]),
        };
        let config = AdminConfig::new(
            core::time::Duration::from_secs(300),
            2,
            realm,
            nc,
            plan.node_id,
            protected,
        )
        .unwrap();
        let admin = DirectoryAdmin::new(config, &schema, AdminRandom::default()).unwrap();
        Some(Domain {
            _dir: dir,
            plan,
            store,
            ctx,
            tiers,
            policy,
            admin,
            next_id: 1,
            authtime: at(10, 0, 10),
            now: request_time(),
        })
    }

    fn guid(&self, role: ObjectRole) -> Guid {
        self.plan.object(role).unwrap().guid
    }

    fn sid(&self, role: ObjectRole) -> Sid {
        self.plan.object(role).unwrap().sid.unwrap()
    }

    /// One request through prepare ⇒ apply ⇒ commit, as dird's admin
    /// service runs it (the WriteTxn begun before the view, Q-358 item 1).
    fn run(&mut self, operation: Operation, requester: &str, approvers: &[&str]) -> Ran {
        let request = Request {
            operation_id: self.next_id,
            operation,
            operation_digest: BOUND,
            requester: ticket(requester, self.authtime),
            approvals: approvers.iter().map(|a| ticket(a, self.authtime)).collect(),
        };
        self.next_id += 1;
        let mut txn = self.store.begin_write().unwrap();
        let view = self.ctx.view(&self.store, &self.tiers).unwrap();
        let prepared = match self.admin.prepare(&request, &view, &self.policy, &self.now) {
            Ok(p) => p,
            Err(refusal) => {
                return Ran::Refused(match refusal.event().stage {
                    DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
                    other => panic!("{other:?}"),
                })
            }
        };
        drop(view);
        if !prepared.writes() {
            return Ran::Read(prepared.reply().unwrap().clone());
        }
        let applied = self
            .admin
            .apply(acknowledged(prepared), &mut txn, &self.now)
            .unwrap_or_else(|r| panic!("apply refused: {:?}", r.event()));
        txn.commit().unwrap();
        Ran::Applied(applied.reply().clone())
    }

    fn created(
        &mut self,
        operation: Operation,
        requester: &str,
        approvers: &[&str],
    ) -> (Guid, Option<Sid>) {
        match self.run(operation, requester, approvers).reply() {
            Reply::Created { guid, sid } => (guid, sid),
            other => panic!("{other:?}"),
        }
    }

    /// The Subject of `name`, from the directory (docs/51 §5.3).
    fn subject(&self, name: &str) -> Subject {
        let view = self.ctx.view(&self.store, &self.tiers).unwrap();
        let t = ticket(name, self.authtime);
        AdminSubject::from_verified_ticket(&view, &t.crealm, &t.cname, &t.authtime, &self.now)
            .unwrap()
            .subject()
            .clone()
    }

    /// `decide` with the produced policy and directory, on the local admin
    /// channel's context (docs/51 §5.4; Q-358 item 11).
    fn decide(&self, subject: &Subject, action: Action, resource: Resource) -> Effect {
        let view = self.ctx.view(&self.store, &self.tiers).unwrap();
        let request = AccessRequest {
            subject: subject.clone(),
            resource,
            action,
            context: Context {
                src_net: IpScope::Internal,
                time: Instant(1_794_650_460),
                transport: Transport::LocalIpc,
                // What the admin PEP reports once keyd verified the
                // AP-REQs' operation binding (R2, docs/52 §5 item 4).
                transport_sec: TransportSec {
                    encrypted: true,
                    sealed: true,
                    channel_bound: true,
                },
            },
        };
        decide(&request, &self.policy, &view).effect
    }

    /// `decide` for a Kerberos question as the KDC asks it (docs/11 §1:
    /// transport Kerberos, no transport floor for `Kdc*` — A-22), with the
    /// Subject's `armored` set as the KDC reports it after keyd verified
    /// the armor (docs/48 §4.2).
    fn decide_kerberos(
        &self,
        subject: &Subject,
        armored: bool,
        action: Action,
        resource: Resource,
    ) -> Effect {
        let view = self.ctx.view(&self.store, &self.tiers).unwrap();
        let mut subject = subject.clone();
        subject.auth.armored = armored;
        let request = AccessRequest {
            subject,
            resource,
            action,
            context: Context {
                src_net: IpScope::Internal,
                time: Instant(1_794_650_460),
                transport: Transport::Kerberos,
                transport_sec: TransportSec::NONE,
            },
        };
        decide(&request, &self.policy, &view).effect
    }

    fn dn_of(&self, guid: Guid) -> pdp::Dn {
        let view = self.ctx.view(&self.store, &self.tiers).unwrap();
        view.dn_of(guid).unwrap().unwrap()
    }
}

/// docs/51 §5.2 rows 1-10 (and CompletePasswordSet, §7.3), on objects
/// under the Tier-0 OU, by alice approved by bob (P-22 dual control for an
/// explicit Tier-0 subtree): every operation is allowed and applied.
#[test]
fn the_first_administrator_can_run_every_admin_operation_under_the_tier0_ou() {
    let Some(mut d) = Domain::new() else { return };
    let ou = d.guid(ObjectRole::Tier0Ou);
    let approvers = ["bob"];
    // Row 1: a user at depth 2 (NC root → Tier-0 OU → user).
    let (carol, carol_sid) = d.created(
        Operation::CreateUser(CreateUser {
            parent: ou,
            sam: "carol".into(),
            upn: None,
            description: None,
        }),
        "alice",
        &approvers,
    );
    assert!(carol_sid.is_some());
    assert_eq!(
        d.dn_of(carol).rdns(),
        ["cn=carol", "ou=Tier0", "dc=example", "dc=test"]
    );
    // Rows 2-4.
    let (pc, _) = d.created(
        Operation::CreateComputer(CreateComputer {
            parent: ou,
            name: "ws9".into(),
            dns_host_name: "ws9.example.test".into(),
            spn: Some("host/ws9.example.test".into()),
        }),
        "alice",
        &approvers,
    );
    let (ops, _) = d.created(
        Operation::CreateGroup(CreateGroup {
            parent: ou,
            sam: "ops".into(),
            group_type: None,
        }),
        "alice",
        &approvers,
    );
    let (sub_ou, _) = d.created(
        Operation::CreateOu(CreateContainerLike {
            parent: ou,
            name: "Servers".into(),
        }),
        "alice",
        &approvers,
    );
    d.created(
        Operation::CreateContainer(CreateContainerLike {
            parent: ou,
            name: "Holding".into(),
        }),
        "alice",
        &approvers,
    );
    // Depth 3: under the new OU (the root's grants inherit at every depth,
    // A-84).
    d.created(
        Operation::CreateUser(CreateUser {
            parent: sub_ou,
            sam: "dave".into(),
            upn: None,
            description: None,
        }),
        "alice",
        &approvers,
    );
    // Row 5 (and its completion).
    match d
        .run(
            Operation::BeginPasswordSet { target: carol },
            "alice",
            &approvers,
        )
        .reply()
    {
        Reply::PasswordSet(r) => assert_eq!(r.keys.len(), 1),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        d.run(
            Operation::CompletePasswordSet(CompletePasswordSet {
                target: carol,
                outcome: PasswordSetOutcome::Completed,
                kvnos: vec![1],
            }),
            "alice",
            &approvers,
        ),
        Ran::Read(Reply::Done)
    ));
    match d
        .run(
            Operation::BeginPasswordSet { target: pc },
            "alice",
            &approvers,
        )
        .reply()
    {
        Reply::PasswordSet(r) => assert_eq!(r.keys.len(), 2),
        other => panic!("{other:?}"),
    }
    // Rows 6-7.
    assert!(matches!(
        d.run(
            Operation::SetEnabled(SetEnabled {
                target: carol,
                enabled: true,
            }),
            "alice",
            &approvers,
        ),
        Ran::Applied(Reply::Done)
    ));
    assert!(matches!(
        d.run(
            Operation::SetAccountExpires(SetAccountExpires {
                target: carol,
                value: AccountExpiresValue::NEVER,
            }),
            "alice",
            &approvers,
        ),
        Ran::Applied(Reply::Done)
    ));
    // Row 8: into a group under the Tier-0 OU and into the Tier-0 group.
    for group in [ops, d.guid(ObjectRole::Tier0Group)] {
        let m = Membership {
            group,
            member: carol,
        };
        assert!(matches!(
            d.run(Operation::AddMember(m), "alice", &approvers),
            Ran::Applied(Reply::Done)
        ));
        assert!(matches!(
            d.run(Operation::RemoveMember(m), "alice", &approvers),
            Ran::Applied(Reply::Done)
        ));
    }
    // Row 10.
    match d
        .run(
            Operation::Lookup(LookupKey::SamAccountName("carol".into())),
            "alice",
            &[],
        )
        .reply()
    {
        Reply::Found(r) => assert_eq!(r.guid, carol),
        other => panic!("{other:?}"),
    }
    // Row 9.
    assert!(matches!(
        d.run(Operation::Delete { target: carol }, "alice", &approvers),
        Ran::Applied(Reply::Done)
    ));
}

/// P-22 item 1 (docs/51 §5.6): a create inside the explicitly Tier0
/// subtree of the tier map needs an approver; under the unclassified
/// workstations OU one administrator suffices (A-36: Tier0 for writes, but
/// not explicitly).
#[test]
fn dual_control_applies_inside_the_tier0_subtree_only() {
    let Some(mut d) = Domain::new() else { return };
    let create = |parent, sam: &str| {
        Operation::CreateUser(CreateUser {
            parent,
            sam: sam.into(),
            upn: None,
            description: None,
        })
    };
    let ou = d.guid(ObjectRole::Tier0Ou);
    assert_eq!(
        d.run(create(ou, "erin"), "alice", &[]).refusal(),
        AdminRefusal::ApprovalRequired
    );
    let ws = d.guid(ObjectRole::WorkstationsOu);
    d.created(create(ws, "erin"), "alice", &[]);
}

/// docs/11 §4 layer 3: an ordinary account (not a Tier-0 group member —
/// created, given a password set and enabled by alice) is granted nothing:
/// every admin operation is refused.
#[test]
fn an_ordinary_account_is_granted_nothing() {
    let Some(mut d) = Domain::new() else { return };
    let ws = d.guid(ObjectRole::WorkstationsOu);
    let (eve, _) = d.created(
        Operation::CreateUser(CreateUser {
            parent: ws,
            sam: "eve".into(),
            upn: None,
            description: None,
        }),
        "alice",
        &[],
    );
    d.run(Operation::BeginPasswordSet { target: eve }, "alice", &[])
        .reply();
    d.run(
        Operation::SetEnabled(SetEnabled {
            target: eve,
            enabled: true,
        }),
        "alice",
        &[],
    )
    .reply();
    // eve's ticket must postdate her creation and password set (docs/47
    // §4.5: revoked_before).
    d.authtime = at(10, 1, 30);
    d.now = at(10, 2, 0);
    let ou = d.guid(ObjectRole::Tier0Ou);
    let alice = d.plan.object(ObjectRole::FirstAdmin(0)).unwrap().guid;
    let operations = vec![
        Operation::CreateUser(CreateUser {
            parent: ws,
            sam: "mallory".into(),
            upn: None,
            description: None,
        }),
        Operation::CreateUser(CreateUser {
            parent: ou,
            sam: "mallory".into(),
            upn: None,
            description: None,
        }),
        Operation::BeginPasswordSet { target: alice },
        Operation::SetEnabled(SetEnabled {
            target: alice,
            enabled: false,
        }),
        Operation::AddMember(Membership {
            group: d.guid(ObjectRole::Tier0Group),
            member: eve,
        }),
        Operation::Delete { target: alice },
    ];
    for op in operations {
        let code = d.run(op.clone(), "eve", &[]).refusal();
        assert!(
            matches!(code, AdminRefusal::PolicyDenied | AdminRefusal::NotVisible),
            "{op:?}: {code:?}"
        );
    }
    assert_eq!(
        d.run(
            Operation::Lookup(LookupKey::SamAccountName("alice".into())),
            "eve",
            &[]
        )
        .refusal(),
        AdminRefusal::NotVisible
    );
}

/// docs/51 §4.3 step 6 with docs/11 §4 and the root SD (module
/// `descriptor`): `decide` allows every A3 action for the Tier-0
/// administrator on the depth-2 user (and `PolicyAdmin`), refuses every
/// action outside the closed set, and allows nothing for an ordinary
/// account.
#[test]
fn the_policy_allows_exactly_the_a3_actions_for_tier0_and_nothing_for_others() {
    let Some(mut d) = Domain::new() else { return };
    let ou = d.guid(ObjectRole::Tier0Ou);
    let (carol, _) = d.created(
        Operation::CreateUser(CreateUser {
            parent: ou,
            sam: "carol".into(),
            upn: None,
            description: None,
        }),
        "alice",
        &["bob"],
    );
    let ws = d.guid(ObjectRole::WorkstationsOu);
    let (eve, _) = d.created(
        Operation::CreateUser(CreateUser {
            parent: ws,
            sam: "eve".into(),
            upn: None,
            description: None,
        }),
        "alice",
        &[],
    );
    d.run(Operation::BeginPasswordSet { target: eve }, "alice", &[])
        .reply();
    d.run(
        Operation::SetEnabled(SetEnabled {
            target: eve,
            enabled: true,
        }),
        "alice",
        &[],
    )
    .reply();
    d.authtime = at(10, 1, 30);
    d.now = at(10, 2, 0);
    let alice = d.subject("alice");
    let eve_subject = d.subject("eve");
    assert_eq!(alice.tier, pdp::Tier::Tier0);
    assert!(alice.groups.contains(&d.sid(ObjectRole::Tier0Group)));
    assert!(!eve_subject.groups.contains(&d.sid(ObjectRole::Tier0Group)));

    let p1 = ad_schema::phase1().unwrap();
    let class = |n: &str| {
        ObjClass(
            p1.class(p1.class_by_name(n).unwrap())
                .unwrap()
                .schema_id_guid,
        )
    };
    let attr = |n: &str| {
        AttrId(
            p1.attribute_schema_id_guid(p1.attribute_by_name(n).unwrap())
                .unwrap(),
        )
    };
    let carol_dn = d.dn_of(carol);
    let ou_dn = d.dn_of(ou);
    let group_dn = d.dn_of(d.guid(ObjectRole::Tier0Group));
    let obj = |dn: &pdp::Dn, attr: Option<AttrId>| Resource::DirObject {
        dn: dn.clone(),
        attr,
    };
    // Every A3 action on its resource (docs/51 §5.2).
    let allowed: Vec<(Action, Resource)> = vec![
        (Action::DirRead, obj(&carol_dn, None)),
        (Action::DirList, obj(&ou_dn, None)),
        (
            Action::DirWrite,
            obj(&carol_dn, Some(attr("userAccountControl"))),
        ),
        (
            Action::DirWrite,
            obj(&carol_dn, Some(attr("accountExpires"))),
        ),
        (Action::DirWrite, obj(&group_dn, Some(attr("member")))),
        (Action::DirDelete, obj(&carol_dn, None)),
        (
            Action::DirControlRight(ControlRightId(USER_FORCE_CHANGE_PASSWORD)),
            obj(&carol_dn, None),
        ),
        (Action::DirAddChild(class("user")), obj(&ou_dn, None)),
        (Action::DirAddChild(class("computer")), obj(&ou_dn, None)),
        (Action::DirAddChild(class("group")), obj(&ou_dn, None)),
        (
            Action::DirAddChild(class("organizationalUnit")),
            obj(&ou_dn, None),
        ),
        (Action::DirAddChild(class("container")), obj(&ou_dn, None)),
        (
            Action::PolicyAdmin,
            Resource::Policy {
                scope: PolicyScope("tier-map".into()),
            },
        ),
    ];
    for (action, resource) in &allowed {
        assert_eq!(
            d.decide(&alice, action.clone(), resource.clone()),
            Effect::Allow,
            "alice {action:?} {resource:?}"
        );
        assert_eq!(
            d.decide(&eve_subject, action.clone(), resource.clone()),
            Effect::Deny,
            "eve {action:?} {resource:?}"
        );
    }
    // Outside the closed set: denied for the Tier-0 administrator too.
    let other_right = Guid {
        data1: 0x1234_5678,
        data2: 0x9abc,
        data3: 0xdef0,
        data4: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    let denied: Vec<(Action, Resource)> = vec![
        (Action::DirAddChild(class("domainDNS")), obj(&ou_dn, None)),
        (
            Action::DirWrite,
            obj(&carol_dn, Some(attr("nTSecurityDescriptor"))),
        ),
        (Action::DirWrite, obj(&carol_dn, Some(attr("description")))),
        (
            Action::DirWrite,
            obj(&carol_dn, Some(attr("sAMAccountName"))),
        ),
        (Action::DirWrite, obj(&carol_dn, None)),
        (
            Action::DirControlRight(ControlRightId(other_right)),
            obj(&carol_dn, None),
        ),
        (
            Action::DirRead,
            obj(&carol_dn, Some(attr("nTSecurityDescriptor"))),
        ),
    ];
    for (action, resource) in denied {
        assert_eq!(
            d.decide(&alice, action.clone(), resource.clone()),
            Effect::Deny,
            "alice {action:?} {resource:?}"
        );
    }
    // The domain root itself (Tier0, structural) is administered by Tier-0
    // only: listing it is allowed for alice, not for eve.
    let root_dn = d.dn_of(d.guid(ObjectRole::NamingContextRoot));
    assert_eq!(
        d.decide(&alice, Action::DirList, obj(&root_dn, None)),
        Effect::Allow
    );
    assert_eq!(
        d.decide(&eve_subject, Action::DirList, obj(&root_dn, None)),
        Effect::Deny
    );
}

/// Q-377 (main-session decision): the generated policy grants exactly the
/// Kerberos actions the phase-1 KDC asks the PDP for — `KdcAs` on a TGT
/// (crates/kdc as_exchange.rs) and `KdcTgs` on a service, the admin
/// service's `admind/<fqdn>` included (tgs_exchange.rs step 10) — and
/// nothing else of the Kerberos class: `KdcS4u2Self` / `KdcS4u2Proxy` are
/// denied for every subject, the Tier-0 administrator included, even
/// armored (docs/11 §3: no matching Allow ⇒ Deny). Mandatory FAST still
/// denies the unarmored AS of a non-bootstrap account (docs/48 §7.2).
#[test]
fn the_policy_grants_only_the_phase1_kerberos_actions() {
    let Some(d) = Domain::new() else { return };
    let alice = d.subject("alice");
    let tgt = Resource::Kerberos {
        kind: pdp::KerbResKind::Tgt,
    };
    let service = |spn: &str| Resource::Kerberos {
        kind: pdp::KerbResKind::Service(pdp::Spn(spn.into())),
    };
    assert_eq!(
        d.decide_kerberos(&alice, true, Action::KdcAs, tgt.clone()),
        Effect::Allow
    );
    for spn in [
        "admind/dc1.example.test",
        "ldap/dc1.example.test",
        "host/ws9.example.test",
    ] {
        assert_eq!(
            d.decide_kerberos(&alice, true, Action::KdcTgs, service(spn)),
            Effect::Allow,
            "{spn}"
        );
    }
    for s4u in [Action::KdcS4u2Self, Action::KdcS4u2Proxy] {
        for armored in [true, false] {
            for resource in [tgt.clone(), service("admind/dc1.example.test")] {
                assert_eq!(
                    d.decide_kerberos(&alice, armored, s4u.clone(), resource.clone()),
                    Effect::Deny,
                    "{s4u:?} armored={armored} {resource:?}"
                );
            }
        }
    }
    // Mandatory FAST on top: the unarmored AS of a non-bootstrap account.
    assert_eq!(
        d.decide_kerberos(&alice, false, Action::KdcAs, tgt),
        Effect::Deny
    );
}

/// Play auditd for one prepared write (docs/51 §5.7 item 2, A-85; docs/52
/// §3.11 R6): commit its decision event into an `ipc_audit::AuditGate`,
/// acknowledge it as auditd does once it synced it (docs/50 §8.1), and take
/// the proof `apply` requires — the only way to obtain one.
fn acknowledged(
    prepared: directory_admin::Prepared,
) -> ipc_audit::AckedIntent<directory_admin::Prepared> {
    let gate = ipc_audit::AuditGate::new(ipc_audit::WindowConfig::DEFAULT);
    gate.set_reachable(true);
    let slot = gate.reserve().expect("a slot");
    let pending = gate.begin_intent(slot, prepared).expect("committed");
    let batch = gate.next_batch().expect("the decision event is sent");
    gate.acknowledge(&ipc_audit::Ack {
        through_seq: batch.last_seq(),
        head_hash: [0; 32],
    })
    .expect("auditd acknowledges");
    gate.wait_acknowledged(pending, std::time::Instant::now())
        .expect("acknowledged")
}
