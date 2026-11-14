//! The whole kdc AS → TGS flow, FAST included, with keyd behind `IpcKeyd`
//! and the in-process loopback (`dispatch` on a development keyd), against
//! the same flow with the in-process `LocalKeyd`: the replies, the KDC's
//! audit events and keyd's audit records are identical. Then the P4 path
//! through IPC: every transport failure and refusal — and keyd's own
//! startup hold-down, decided on keyd's clock, not the kdc's — reaches the
//! Kerberos client as KDC_ERR_SVC_UNAVAILABLE (29) over TCP and silence over
//! UDP.
//!
//! The kdc crate's integration fixtures (crates/kdc/tests/common) are reused
//! as they are: the Kerberos client side (RFC 4120 / RFC 6113, krb-crypto),
//! the identities, keys, accounts and policy. Only the custody differs.
//!
//! Sources: docs/50 §3.4, §3.5 (R50-5), §3.6, §3.7 (R50-8), §9 tier 1, §10
//! (P5); docs/10 §2, §9, §11; RFC 4120 §3.2.3, §7.5.9 (code 29); docs/48;
//! docs/questions/Q-217, Q-222 (A-56), Q-240 (A-62). Every value is
//! constructed by hand for these tests (by the kdc fixtures); no vector
//! comes from any other implementation.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use common::*;
use ipc::Refused;
use ipc_keyd::channel::request_kind;
use ipc_keyd::{IpcKeyd, KeydClient, DEFAULT_DEADLINE};
use kdc::{
    AuditOutcome, AuditReason, InMemoryAccounts, Kdc, KdcConfig, KdcReply, Peer, PolicyInputs,
    Transport,
};
use keyd::{InMemoryKeyStore, Keyd, PrincipalBinding};
use krb_proto::constants::KDC_ERR_SVC_UNAVAILABLE;
use krb_proto::KerberosTime;
use pdp::{IpScope, PolicySnapshot};
use support::{share, Faults, Loopback, Shared, KEYD_UID};

type Server = Shared<InMemoryKeyStore, KeydAudit, TestEntropy>;
type Custody = IpcKeyd<Loopback<InMemoryKeyStore, KeydAudit, TestEntropy>>;

/// The kdc fixture's world, with keyd reached over the keyd channel.
struct IpcWorld {
    kdc: Kdc<Custody, KdcAudit, TestRateLimiter>,
    server: Server,
    snapshot: PolicySnapshot,
    pip: TestPip,
    accounts: InMemoryAccounts,
    machine_tgt: Tgt,
    armor_counter: u32,
}

/// The accounts of the kdc fixture (crates/kdc/tests/common, `Fixture`).
fn accounts() -> InMemoryAccounts {
    let mut accounts = InMemoryAccounts::new();
    accounts
        .insert_client(&realm(), &alice_name(), alice_account())
        .unwrap();
    let mut bob = alice_account();
    bob.key = BOB;
    bob.sid = bob_sid();
    bob.groups = Default::default();
    bob.etype_info = etype_info(BOB_SALT);
    accounts.insert_client(&realm(), &bob_name(), bob).unwrap();
    accounts
        .insert_client(&realm(), &machine_name(), machine_account())
        .unwrap();
    accounts
        .insert_service(
            &realm(),
            &service_name(),
            kdc::ServiceAccount {
                key: SERVICE,
                state: kdc::AccountState::ACTIVE,
                enctypes: vec![AES256, AES128],
            },
        )
        .unwrap();
    accounts
}

impl IpcWorld {
    /// The fixture's world over IPC: the same keyd configuration, the same
    /// scripted keys, created through the keyd channel by the Admin and
    /// Directory callers, the same accounts and policy, and — unless the
    /// test brings one — the computer account's TGT through the unarmored
    /// bootstrap, exactly as `Fixture::new` does.
    fn new(keyd_started: KerberosTime, keyd_clock: KerberosTime, machine_tgt: Option<Tgt>) -> Self {
        let setup = Setup::new();
        let entropy = TestEntropy::default();
        let store = InMemoryKeyStore::new_insecure_development_allowing_krbtgt(64);
        let keyd = Keyd::with_entropy(
            setup.keyd,
            store,
            KeydAudit::default(),
            entropy.clone(),
            &keyd_started,
        )
        .unwrap();
        let server = share(keyd, keyd_clock);
        let mut admin =
            KeydClient::new(Loopback::new(&server, ADMIN), KEYD_UID, DEFAULT_DEADLINE).unwrap();
        let enctypes: Vec<krb_crypto::EncType> = server
            .borrow()
            .keyd
            .config()
            .enctypes
            .iter()
            .map(|e| krb_crypto::EncType::from_number(e.number()).unwrap())
            .collect();
        for (handle, binding, key) in [
            (KRBTGT, krbtgt_name(), KRBTGT_KEY),
            (SERVICE, service_name(), SERVICE_KEY),
            (MACHINE, machine_name(), MACHINE_KEY),
        ] {
            for e in &enctypes {
                entropy.push(&key[..e.key_length()]);
            }
            admin
                .create_key(&handle, &PrincipalBinding::new(realm(), binding))
                .unwrap();
        }
        let mut directory = KeydClient::new(
            Loopback::new(&server, DIRECTORY),
            KEYD_UID,
            DEFAULT_DEADLINE,
        )
        .unwrap();
        // dird's set-secret decisions (Role::Ldap, after its PDP; task A15a,
        // A-102) over the channel too.
        let mut ldap = KeydClient::new(
            Loopback::new(&server, LDAP_CALLER),
            KEYD_UID,
            DEFAULT_DEADLINE,
        )
        .unwrap();
        for (id, handle, who, password, salt) in [
            (1, ALICE, alice_name(), ALICE_PASSWORD, ALICE_SALT),
            (2, BOB, bob_name(), BOB_PASSWORD, BOB_SALT),
        ] {
            ldap.register_decision(
                keyd::DecisionId::new(id),
                &keyd::DecidedOperation::SetSecret {
                    kind: keyd::AccountKind::User,
                    targets: vec![keyd::SetSecretTarget {
                        handle,
                        binding: PrincipalBinding::new(realm(), who.clone()),
                        salt: String::from(salt),
                    }],
                },
                &[],
                keyd::MAX_SET_SECRET_GRANT_SECS,
            )
            .unwrap();
            directory
                .set_secret(
                    &handle,
                    &PrincipalBinding::new(realm(), who),
                    String::from(password).into(),
                    salt,
                )
                .unwrap();
        }
        let custody = IpcKeyd::connect(
            KeydClient::new(
                Loopback::new(&server, KDC_CALLER),
                KEYD_UID,
                DEFAULT_DEADLINE,
            )
            .unwrap(),
        )
        .unwrap();
        let mut kdc = Kdc::new(
            KdcConfig::new(realm(), KRBTGT),
            custody,
            KdcAudit::default(),
            TestRateLimiter::default(),
        )
        .unwrap();
        let pip = TestPip {
            tiers: [
                (alice_sid(), pdp::Tier::Tier2),
                (bob_sid(), pdp::Tier::Tier2),
                (machine_sid(), pdp::Tier::Tier2),
            ]
            .into_iter()
            .collect(),
        };
        let accounts = accounts();
        let machine_tgt = match machine_tgt {
            Some(tgt) => tgt,
            None => {
                let allow = snapshot(vec![allow_kerberos()]);
                let bootstrap = AsReqSpec::machine()
                    .with_timestamp(&machine_key(AES256))
                    .encode();
                let reply = kdc.handle(
                    &bootstrap,
                    Peer {
                        transport: Transport::Tcp,
                        src_net: IpScope::Internal,
                    },
                    now(),
                    &PolicyInputs {
                        snapshot: &allow,
                        pip: &pip,
                    },
                    &accounts,
                );
                open_as_rep(&sent(reply), &machine_key(AES256))
            }
        };
        kdc.audit_sink_mut().events.clear();
        kdc.rate_limiter_mut().seen.clear();
        server.borrow_mut().keyd.audit_sink_mut().records.clear();
        IpcWorld {
            kdc,
            server,
            snapshot: snapshot(setup.rules),
            pip,
            accounts,
            machine_tgt,
            armor_counter: 0,
        }
    }

    fn send_at(&mut self, request: &[u8], transport: Transport, when: KerberosTime) -> KdcReply {
        let inputs = PolicyInputs {
            snapshot: &self.snapshot,
            pip: &self.pip,
        };
        self.kdc.handle(
            request,
            Peer {
                transport,
                src_net: IpScope::Internal,
            },
            when,
            &inputs,
            &self.accounts,
        )
    }

    /// The armored AS-REQ of `spec` under a fresh armor on the computer
    /// account's TGT — the fixture's `fast_as_request`.
    fn fast_as_request(&mut self, spec: &AsReqSpec, when: KerberosTime) -> (Vec<u8>, Armor) {
        self.armor_counter += 1;
        let armor = Armor::new(&self.machine_tgt, when, self.armor_counter);
        (spec.encode_armored(&armor, when), armor)
    }

    fn keyd_records(&self) -> Vec<keyd::AuditRecord> {
        self.server.borrow().keyd.audit_sink().records.clone()
    }

    fn set_faults(&self, faults: Faults) {
        self.server.borrow_mut().faults = faults;
    }
}

/// docs/50 §3.4, §9 tier 1, §10 (P5: "a synchronous client that implements
/// `kdc::KeyCustody`"): the armored AS exchange (RFC 6113 encrypted
/// challenge), the armored TGS exchange (implicit armor), an armored AS
/// error sealed by keyd and an armored TGS error, through `IpcKeyd` — every
/// reply, KDC audit event and keyd audit record equals the in-process path.
#[test]
fn full_fast_flow_through_ipc_equals_the_direct_path() {
    let mut direct = Fixture::new();
    let mut ipc = IpcWorld::new(keyd_started(), now(), None);
    assert_eq!(direct.machine_tgt.rep, ipc.machine_tgt.rep, "bootstrap");

    // Armored AS (alice, encrypted challenge).
    let alice = AsReqSpec::alice().with_challenge(&alice_key(AES256));
    let (request, armor) = direct.fast_as_request(&alice, now());
    let (ipc_request, _) = ipc.fast_as_request(&alice, now());
    assert_eq!(request, ipc_request);
    let reply = direct.send_at(&request, Transport::Tcp, now());
    let ipc_reply = ipc.send_at(&ipc_request, Transport::Tcp, now());
    assert_eq!(reply, ipc_reply, "armored AS-REP");
    let tgt = open_fast_as_rep(&sent(ipc_reply), &armor.key, &alice_key(AES256));

    // Armored TGS (implicit armor) for host/files.example.org.
    let spec = TgsReqSpec::service();
    let (tgs, _) = spec.encode(&tgt);
    let reply = direct.send_at(&tgs, Transport::Tcp, now());
    let ipc_reply = ipc.send_at(&tgs, Transport::Tcp, now());
    assert_eq!(reply, ipc_reply, "armored TGS-REP");
    let (rep, part) = open_tgs_rep(&sent(ipc_reply), &tgt, &spec);
    assert_eq!(rep.0.cname, alice_name());
    assert_eq!(part.0.sname, service_name());
    let service_part = open_ticket(&rep.0.ticket, &service_key());
    assert_eq!(service_part.cname, alice_name());

    // Armored AS error: the challenge made with the wrong key (keyd seals
    // the KRB-ERROR, seal_fast_error over IPC).
    let wrong = AsReqSpec::alice().with_challenge(&password_key(AES256, BOB_PASSWORD, BOB_SALT));
    let (request, armor) = direct.fast_as_request(&wrong, now());
    let (ipc_request, _) = ipc.fast_as_request(&wrong, now());
    let reply = direct.send_at(&request, Transport::Tcp, now());
    let ipc_reply = ipc.send_at(&ipc_request, Transport::Tcp, now());
    assert_eq!(reply, ipc_reply, "armored AS error");
    let error = open_fast_error(ipc_reply, &armor.key);
    assert_eq!(
        error.outer.error_code,
        krb_proto::constants::KDC_ERR_PREAUTH_FAILED
    );

    // Armored TGS error: an unknown service (sealed under the implicit
    // armor of the TGS context).
    let mut unknown = TgsReqSpec::service();
    unknown.sname = Some(name(3, &["host", "nowhere.example.org"]));
    unknown.nonce = 0x1111_2222;
    unknown.cusec = 2; // a fresh authenticator (not a replay of the first)
    let (tgs, _) = unknown.encode(&tgt);
    let reply = direct.send_at(&tgs, Transport::Tcp, now());
    let ipc_reply = ipc.send_at(&tgs, Transport::Tcp, now());
    assert_eq!(reply, ipc_reply, "armored TGS error");
    let error = open_fast_error(ipc_reply, &unknown.armor_key(&tgt.session));
    assert_eq!(
        error.outer.error_code,
        krb_proto::constants::KDC_ERR_S_PRINCIPAL_UNKNOWN
    );

    // The same keyd operations, in the same order, with the same records.
    let ops: Vec<keyd::Operation> = ipc.keyd_records().iter().map(|r| r.op).collect();
    assert!(ops.contains(&keyd::Operation::OpenFastArmor));
    assert!(ops.contains(&keyd::Operation::SealFastError));
    assert!(ops.contains(&keyd::Operation::IssueTgsRep));
    assert_eq!(direct.keyd_records(), ipc.keyd_records().as_slice());
    assert_eq!(direct.events(), ipc.kdc.audit_sink().events.as_slice());
}

/// One request of each exchange path, fresh at `when` (as in the kdc's
/// tests/unavailable.rs).
fn path_request(world: &mut IpcWorld, path: u8, tgt: &Tgt, when: KerberosTime) -> Vec<u8> {
    match path {
        0 => {
            let mut spec = AsReqSpec::machine();
            spec.nonce = 0x0B0B_0B0B ^ world.armor_counter;
            world.armor_counter += 1;
            spec.padata = Some(vec![pa_enc_timestamp(&machine_key(AES256), when)]);
            spec.encode()
        }
        1 => {
            let spec = AsReqSpec::alice().with_challenge(&alice_key(AES256));
            world.fast_as_request(&spec, when).0
        }
        _ => {
            let mut spec = TgsReqSpec::service();
            spec.ctime = when;
            spec.cusec = 1 + world.armor_counter;
            world.armor_counter += 1;
            spec.encode(tgt).0
        }
    }
}

/// The reply must be a plain KDC_ERR_SVC_UNAVAILABLE (TCP) or nothing
/// (UDP), audited `CustodyUnavailable` (Q-240 item 5).
fn assert_unavailable(world: &IpcWorld, reply: KdcReply, transport: Transport, what: &str) {
    match transport {
        Transport::Tcp => {
            let error = error_of(reply);
            assert_eq!(error.error_code, KDC_ERR_SVC_UNAVAILABLE, "{what}");
            assert!(error.e_data.is_none(), "{what}: unarmored");
        }
        Transport::Udp => assert_eq!(reply, KdcReply::Silent, "{what}"),
    }
    let event = world.kdc.audit_sink().events.last().unwrap();
    assert_eq!(event.reason, AuditReason::CustodyUnavailable, "{what}");
    if transport == Transport::Tcp {
        assert_eq!(
            event.outcome,
            AuditOutcome::Refused {
                error_code: KDC_ERR_SVC_UNAVAILABLE
            },
            "{what}"
        );
    }
}

/// docs/50 §3.6, §3.7 (R50-8); Q-217 (A-56); Q-240 items 5, 8: keyd down,
/// a deadline, `Busy`, `Unavailable`, `Malformed`, `VersionMismatch` and an
/// unusable reply — on whichever keyd step of whichever path — make the KDC
/// answer 29 over TCP and nothing over UDP; never KDC_ERR_PREAUTH_FAILED or
/// KRB_AP_ERR_BAD_INTEGRITY.
#[test]
fn transport_failures_through_ipc_answer_29() {
    let faults = [
        Faults {
            deadline: true,
            ..Faults::default()
        },
        Faults {
            refuse: Some(Refused::Busy),
            ..Faults::default()
        },
        Faults {
            refuse: Some(Refused::Unavailable),
            ..Faults::default()
        },
        Faults {
            refuse: Some(Refused::Malformed),
            ..Faults::default()
        },
        Faults {
            refuse: Some(Refused::VersionMismatch),
            ..Faults::default()
        },
        Faults {
            trailing_reply_octet: true,
            ..Faults::default()
        },
    ];
    // (path, keyd step) as in the kdc's custody_unavailable test.
    let steps = [
        (0, request_kind::VERIFY_PREAUTH),
        (0, request_kind::ISSUE_AS_REP),
        (1, request_kind::OPEN_FAST_ARMOR),
        (1, request_kind::VERIFY_PREAUTH),
        (1, request_kind::ISSUE_AS_REP),
        (2, request_kind::OPEN_AND_VERIFY_TGT),
        (2, request_kind::ISSUE_TGS_REP),
    ];
    let base = Fixture::new().machine_tgt;
    for fault in faults {
        let mut world = IpcWorld::new(keyd_started(), now(), Some(clone_tgt(&base)));
        let alice = AsReqSpec::alice().with_challenge(&alice_key(AES256));
        let (request, armor) = world.fast_as_request(&alice, now());
        let tgt = open_fast_as_rep(
            &sent(world.send_at(&request, Transport::Tcp, now())),
            &armor.key,
            &alice_key(AES256),
        );
        for (path, kind) in steps {
            for transport in [Transport::Tcp, Transport::Udp] {
                world.set_faults(Faults {
                    only_kind: Some(kind),
                    ..fault
                });
                let request = path_request(&mut world, path, &tgt, now());
                let reply = world.send_at(&request, transport, now());
                assert_unavailable(
                    &world,
                    reply,
                    transport,
                    &format!("{fault:?} path {path} kind {kind:#04x}"),
                );
                world.set_faults(Faults::default());
            }
        }
    }
    // keyd goes down altogether: the open connection times out (and is
    // dropped), and reconnecting is refused — 29 both times.
    let mut world = IpcWorld::new(keyd_started(), now(), Some(clone_tgt(&base)));
    world.set_faults(Faults {
        refuse_connect: true,
        deadline: true,
        ..Faults::default()
    });
    let tgt = clone_tgt(&base);
    let request = path_request(&mut world, 1, &tgt, now());
    let reply = world.send_at(&request, Transport::Tcp, now());
    assert_unavailable(&world, reply, Transport::Tcp, "keyd down");
    let request = path_request(&mut world, 1, &tgt, now());
    let reply = world.send_at(&request, Transport::Tcp, now());
    assert_unavailable(&world, reply, Transport::Tcp, "keyd still down");
}

/// The fixture's `Tgt` has no `Clone`; rebuild one from its parts.
fn clone_tgt(tgt: &Tgt) -> Tgt {
    Tgt {
        rep: tgt.rep.clone(),
        part: tgt.part.clone(),
        session: key_from(&tgt.part.0.key),
        fast: tgt.fast.clone(),
    }
}

/// RFC 4120 §3.2.3; docs/50 R50-5, R50-6, §3.5; A-56; A-62: a freshly
/// started keyd refuses the Kerberos exchanges for two skew intervals, and
/// the client gets 29 through IPC — decided on **keyd's** clock: a kdc
/// whose clock says the hold-down is long over (it passes `now` an hour
/// later) still gets 29, because `now` never crosses the wire. Once keyd's
/// own clock passes the hold-down, the exchange is served.
#[test]
fn startup_hold_down_through_ipc_answers_29_on_keyds_clock() {
    let tgt = Fixture::new().machine_tgt;
    // keyd starts at `now()` (10:00:00) and its clock reads 10:01:00.
    let machine = clone_tgt(&tgt);
    let mut world = IpcWorld::new(now(), at(60), Some(tgt));
    for transport in [Transport::Tcp, Transport::Udp] {
        let request = path_request(&mut world, 0, &machine, at(60));
        let reply = world.send_at(&request, transport, at(60));
        assert_unavailable(&world, reply, transport, "held, bootstrap");
        let request = path_request(&mut world, 1, &machine, at(60));
        let reply = world.send_at(&request, transport, at(60));
        assert_unavailable(&world, reply, transport, "held, armored AS");
    }
    // The kdc believes it is 11:00 (hold-down over since 10:10 by its
    // clock); keyd's clock still reads 10:01 — held.
    let request = path_request(&mut world, 1, &machine, at(3600));
    let reply = world.send_at(&request, Transport::Tcp, at(3600));
    assert_unavailable(&world, reply, Transport::Tcp, "kdc clock ahead");
    let held: Vec<keyd::AuditRecord> = world.keyd_records();
    assert!(held
        .iter()
        .all(|r| r.result == keyd::AuditOutcome::Unavailable && r.ts == at(60)));

    // keyd's clock passes the hold-down (started + 2 × 300 s + 1, A-62).
    world.server.borrow_mut().clock = at(601);
    let alice = AsReqSpec::alice().with_challenge(&alice_key(AES256));
    let (request, armor) = world.fast_as_request(&alice, at(601));
    let reply = world.send_at(&request, Transport::Tcp, at(601));
    let tgt = open_fast_as_rep(&sent(reply), &armor.key, &alice_key(AES256));
    assert_eq!(tgt.rep.0.cname, alice_name());
}

/// docs/50 §7.5 step 4: the kdc's custody takes keyd's non-secret
/// configuration over the channel (`describe_config`) before the KDC is
/// built; it equals keyd's own description. And a keyd that cannot be
/// reached at that point stops the kdc from starting (fail closed).
#[test]
fn ipc_custody_describes_keyds_configuration() {
    let world = IpcWorld::new(keyd_started(), now(), None);
    use kdc::KeyCustody;
    assert_eq!(
        world.kdc.custody().config(),
        &world.server.borrow().keyd.config().description()
    );
    let server = support::share(
        Keyd::with_entropy(
            Setup::new().keyd,
            InMemoryKeyStore::new_insecure_development_allowing_krbtgt(4),
            KeydAudit::default(),
            TestEntropy::default(),
            &keyd_started(),
        )
        .unwrap(),
        now(),
    );
    server.borrow_mut().faults.refuse_connect = true;
    let client = KeydClient::new(
        Loopback::new(&server, KDC_CALLER),
        KEYD_UID,
        DEFAULT_DEADLINE,
    )
    .unwrap();
    assert_eq!(
        IpcKeyd::connect(client).map(|_| ()),
        Err(keyd::Error::Unavailable)
    );
}
