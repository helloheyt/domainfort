//! Tier 2 (docs/50 §9: "a full login … over sockets"): the kdc's whole
//! AS → TGS flow, FAST included, with keyd reached through `ipc_keyd::IpcKeyd`
//! over a REAL Unix socket into this daemon (`keyd_daemon::serve`: listener,
//! peer credentials, uid map, bounded queue, engine thread, audit gate). The
//! replies equal those of the kdc fixture's in-process keyd, byte for byte.
//! Then keyd's own startup hold-down, decided on keyd's clock and not the
//! kdc's (R50-5), reaches the client as KDC_ERR_SVC_UNAVAILABLE (29).
//!
//! The kdc crate's integration fixtures (crates/kdc/tests/common) are reused
//! as they are, as crates/ipc-keyd-server does: the Kerberos client side
//! (RFC 4120 / RFC 6113 with krb-crypto), the identities, scripted keys,
//! accounts and policy.
//!
//! The kdc side of the socket:
//! * on Linux, `ipc_keyd::UnixConnector` itself — the kdc client verifies
//!   keyd's uid through rustix `socket_peercred` (R50-3);
//! * elsewhere (rustix `socket_peercred` is Linux-only, docs/questions/Q-245
//!   item 11), a test connector that reads keyd's uid through tokio
//!   `UnixStream::peer_cred` and then hands the stream to
//!   `ipc_keyd::UnixConnection` for the exchanges — so the same server-uid
//!   check is made on every host.
//!
//! The keys keyd holds are created inside the test's keyd constructor (as
//! the fixture creates them), because one test process has one uid and the
//! map gives a uid one role (R50-3): over the socket the test is the Kdc.
//!
//! Sources: docs/50 R50-3, R50-5, R50-6, R50-7, §3.4, §3.7 (R50-8), §9 tier 2,
//! §10 (P7); docs/10 §2, §9, §11; RFC 4120 §3.2.3, §7.5.9 (code 29);
//! docs/48; docs/questions/Q-222 (A-56), Q-240 (A-62). Every value is
//! constructed by hand (by the kdc fixtures); no vector comes from any other
//! implementation.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use common::*;
use ipc_keyd::{IpcKeyd, KeydClient, DEFAULT_DEADLINE};
use kdc::{InMemoryAccounts, Kdc, KdcConfig, KdcReply, Peer, PolicyInputs, Transport};
use keyd::{InMemoryKeyStore, Keyd, PrincipalBinding, Role};
use keyd_daemon::{CallerMap, RecordBuffer};
use krb_proto::constants::KDC_ERR_SVC_UNAVAILABLE;
use krb_proto::KerberosTime;
use pdp::{IpScope, PolicySnapshot};
use std::path::{Path, PathBuf};
use support::{my_uid, params, skip_as_root, Daemon, FakeAuditd, TempDir, TestClock};

#[cfg(target_os = "linux")]
mod connector {
    //! Linux: the kdc daemon's own connector (rustix peer credentials).
    pub type KdcConnector = ipc_keyd::UnixConnector;

    pub fn new(path: &std::path::Path) -> KdcConnector {
        ipc_keyd::UnixConnector::new(path.to_path_buf())
    }
}

#[cfg(not(target_os = "linux"))]
mod connector {
    //! Other hosts: keyd's uid through tokio `UnixStream::peer_cred`, then
    //! `ipc_keyd::UnixConnection` for the exchanges (tokio 1.54.1 docs.rs:
    //! `from_std` needs a runtime context and a non-blocking stream;
    //! `into_std` returns it non-blocking).
    use ipc::FrameLimit;
    use ipc_keyd::{Connection, Connector, TransportError, UnixConnection};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use zeroize::Zeroizing;

    pub struct KdcConnector {
        path: PathBuf,
        runtime: tokio::runtime::Runtime,
    }

    pub fn new(path: &Path) -> KdcConnector {
        KdcConnector {
            path: path.to_path_buf(),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap(),
        }
    }

    pub struct PeerChecked {
        uid: u32,
        inner: UnixConnection,
    }

    impl Connector for KdcConnector {
        type Connection = PeerChecked;

        fn connect(&mut self) -> Result<PeerChecked, TransportError> {
            let stream = UnixStream::connect(&self.path).map_err(|_| TransportError::Connect)?;
            stream
                .set_nonblocking(true)
                .map_err(|_| TransportError::Connect)?;
            let (uid, stream) = {
                let _context = self.runtime.enter();
                let stream = tokio::net::UnixStream::from_std(stream)
                    .map_err(|_| TransportError::PeerCredentials)?;
                let uid = stream
                    .peer_cred()
                    .map_err(|_| TransportError::PeerCredentials)?
                    .uid();
                (
                    uid,
                    stream
                        .into_std()
                        .map_err(|_| TransportError::PeerCredentials)?,
                )
            };
            stream
                .set_nonblocking(false)
                .map_err(|_| TransportError::Connect)?;
            Ok(PeerChecked {
                uid,
                inner: UnixConnection::from_stream(stream),
            })
        }
    }

    impl Connection for PeerChecked {
        fn peer_uid(&self) -> Result<u32, TransportError> {
            Ok(self.uid)
        }

        fn exchange(
            &mut self,
            frame: &[u8],
            reply_limit: FrameLimit,
            deadline: Duration,
        ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
            self.inner.exchange(frame, reply_limit, deadline)
        }
    }
}

type Custody = IpcKeyd<connector::KdcConnector>;

/// The fixture's keyd (crates/kdc/tests/common `Fixture::from_setup`): the
/// same configuration, scripted keys created by the Admin caller and
/// passwords set by the Directory caller — inside the daemon's keyd
/// constructor, with the hold-down start the engine read from its clock.
/// The set-up records are not part of the flow and are dropped.
fn fixture_keyd(
    started: &KerberosTime,
) -> Result<Keyd<InMemoryKeyStore, RecordBuffer, TestEntropy>, keyd::ConfigError> {
    let setup = Setup::new();
    let entropy = TestEntropy::default();
    let mut keyd = Keyd::with_entropy(
        setup.keyd,
        InMemoryKeyStore::new_insecure_development_allowing_krbtgt(64),
        RecordBuffer::new(),
        entropy.clone(),
        started,
    )?;
    let enctypes: Vec<krb_crypto::EncType> = keyd
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
        keyd.create_key(
            &ADMIN,
            &handle,
            &PrincipalBinding::new(realm(), binding),
            &now(),
        )
        .unwrap();
    }
    for (handle, who, password, salt) in [
        (ALICE, alice_name(), ALICE_PASSWORD, ALICE_SALT),
        (BOB, bob_name(), BOB_PASSWORD, BOB_SALT),
    ] {
        keyd.set_secret(
            &DIRECTORY,
            &handle,
            &PrincipalBinding::new(realm(), who),
            String::from(password).into(),
            salt,
            &now(),
        )
        .unwrap();
    }
    let _ = keyd.audit_sink_mut().take();
    Ok(keyd)
}

/// The accounts of the kdc fixture.
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

/// The kdc of the fixture with keyd behind the daemon's socket.
struct SocketWorld {
    kdc: Kdc<Custody, KdcAudit, TestRateLimiter>,
    snapshot: PolicySnapshot,
    pip: TestPip,
    accounts: InMemoryAccounts,
    armor_counter: u32,
}

impl SocketWorld {
    fn new(socket: &Path, keyd_uid: u32) -> SocketWorld {
        let client = KeydClient::new(connector::new(socket), keyd_uid, DEFAULT_DEADLINE).unwrap();
        let custody = IpcKeyd::connect(client).unwrap();
        let kdc = Kdc::new(
            KdcConfig::new(realm(), KRBTGT),
            custody,
            KdcAudit::default(),
            TestRateLimiter::default(),
        )
        .unwrap();
        SocketWorld {
            kdc,
            snapshot: snapshot(vec![allow_kerberos()]),
            pip: TestPip {
                tiers: [
                    (alice_sid(), pdp::Tier::Tier2),
                    (bob_sid(), pdp::Tier::Tier2),
                    (machine_sid(), pdp::Tier::Tier2),
                ]
                .into_iter()
                .collect(),
            },
            accounts: accounts(),
            armor_counter: 0,
        }
    }

    fn send(&mut self, request: &[u8]) -> KdcReply {
        let inputs = PolicyInputs {
            snapshot: &self.snapshot,
            pip: &self.pip,
        };
        self.kdc.handle(
            request,
            Peer {
                transport: Transport::Tcp,
                src_net: IpScope::Internal,
            },
            now(),
            &inputs,
            &self.accounts,
        )
    }

    /// The fixture's `fast_as_request`.
    fn fast_as_request(&mut self, machine_tgt: &Tgt, spec: &AsReqSpec) -> (Vec<u8>, Armor) {
        self.armor_counter += 1;
        let armor = Armor::new(machine_tgt, now(), self.armor_counter);
        (spec.encode_armored(&armor, now()), armor)
    }
}

/// A daemon (uid map: the test's uid → Kdc) whose keyd clock starts at
/// `started`.
fn daemon(
    dir: &TempDir,
    uid: u32,
    started: KerberosTime,
) -> (Daemon, FakeAuditd, TestClock, PathBuf) {
    let params = params(dir, CallerMap::new(&[(uid, Role::Kdc)]).unwrap(), uid);
    let socket = params.keyd_socket.clone();
    let auditd = FakeAuditd::start(&params.audit.socket);
    let clock = TestClock::at(started);
    let daemon = Daemon::start(params, clock.clone(), fixture_keyd).unwrap();
    (daemon, auditd, clock, socket)
}

/// docs/50 §9 tier 2, §10 (P7); docs/48: the computer account's bootstrap,
/// the armored AS exchange (encrypted challenge), and the armored TGS
/// exchange for host/files.example.org, through the daemon's socket — every
/// reply equals the in-process fixture's, byte for byte; the service ticket
/// opens under the service key and names alice; keyd's records of the flow
/// reach auditd.
#[test]
fn the_full_kdc_flow_through_the_daemon_socket_equals_the_direct_path() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    // keyd starts at the fixture's start (a day before `now`); its clock
    // (not the kdc's) is then moved past the hold-down.
    let (daemon, auditd, clock, socket) = daemon(&dir, uid, keyd_started());
    clock.set(now());
    let mut direct = Fixture::new();
    let mut world = SocketWorld::new(&socket, uid);

    // Bootstrap (unarmored AS, computer account).
    let bootstrap = AsReqSpec::machine()
        .with_timestamp(&machine_key(AES256))
        .encode();
    let reply = world.send(&bootstrap);
    let machine_tgt = open_as_rep(&sent(reply), &machine_key(AES256));
    assert_eq!(direct.machine_tgt.rep, machine_tgt.rep, "bootstrap AS-REP");

    // Armored AS (alice, encrypted challenge).
    let alice = AsReqSpec::alice().with_challenge(&alice_key(AES256));
    let (request, armor) = direct.fast_as_request(&alice, now());
    let (socket_request, _) = world.fast_as_request(&machine_tgt, &alice);
    assert_eq!(request, socket_request);
    let direct_reply = direct.send_at(&request, Transport::Tcp, now());
    let socket_reply = world.send(&socket_request);
    assert_eq!(direct_reply, socket_reply, "armored AS-REP");
    let tgt = open_fast_as_rep(&sent(socket_reply), &armor.key, &alice_key(AES256));

    // Armored TGS (implicit armor) for host/files.example.org.
    let spec = TgsReqSpec::service();
    let (tgs, _) = spec.encode(&tgt);
    let direct_reply = direct.send_at(&tgs, Transport::Tcp, now());
    let socket_reply = world.send(&tgs);
    assert_eq!(direct_reply, socket_reply, "armored TGS-REP");
    let (rep, part) = open_tgs_rep(&sent(socket_reply), &tgt, &spec);
    assert_eq!(rep.0.cname, alice_name());
    assert_eq!(part.0.sname, service_name());
    assert_eq!(
        open_ticket(&rep.0.ticket, &service_key()).cname,
        alice_name()
    );

    // keyd's records of the flow reached auditd (A-57: every gating
    // operation's record is committed before its reply).
    drop(world);
    daemon.stop().unwrap();
    let ops: Vec<ipc_audit::KeydOperation> = auditd
        .events()
        .iter()
        .filter_map(|event| match event {
            ipc_audit::EventBody::Keyd(record) => Some(record.op),
            _ => None,
        })
        .collect();
    for op in [
        ipc_audit::KeydOperation::VerifyPreauth,
        ipc_audit::KeydOperation::IssueAsRep,
        ipc_audit::KeydOperation::OpenFastArmor,
        ipc_audit::KeydOperation::OpenAndVerifyTgt,
        ipc_audit::KeydOperation::IssueTgsRep,
    ] {
        assert!(ops.contains(&op), "{op:?} missing from {ops:?}");
    }
}

/// RFC 4120 §3.2.3; docs/50 R50-5, R50-6, R50-8; A-62: keyd starts at
/// S = `now` − 600 s on its own clock. While keyd's clock reads S and
/// S + 600 the bootstrap AS is answered KDC_ERR_SVC_UNAVAILABLE (29) over
/// TCP; at S + 601 it is served. The kdc's own clock reads `now` throughout:
/// it does not decide the hold-down.
#[test]
fn the_hold_down_on_keyds_clock_reaches_the_client_as_29() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let (daemon, _auditd, clock, socket) = daemon(&dir, uid, at(-600));
    let mut world = SocketWorld::new(&socket, uid);
    let bootstrap = |nonce: u32| {
        let mut spec = AsReqSpec::machine().with_timestamp(&machine_key(AES256));
        spec.nonce = nonce;
        spec.encode()
    };
    assert_eq!(code_of(world.send(&bootstrap(1))), KDC_ERR_SVC_UNAVAILABLE);
    clock.set(at(0));
    assert_eq!(code_of(world.send(&bootstrap(2))), KDC_ERR_SVC_UNAVAILABLE);
    clock.set(at(1));
    let reply = world.send(&bootstrap(3));
    let _ = open_as_rep(&sent(reply), &machine_key(AES256));
    drop(world);
    daemon.stop().unwrap();
}
