//! Tier 2, the end-to-end flow (docs/50 §9: "a full login (computer → armored
//! user → service ticket) over sockets"): the kdc with **both** remote
//! custody — `ipc_keyd::IpcKeyd` over a real Unix socket into the keyd
//! daemon (`keyd_daemon::serve`) — **and** the remote directory — this
//! channel over a real Unix socket into dird (`directory_daemon::serve`,
//! opening its own redb file with the integrity key) — runs the computer
//! account's bootstrap, the armored AS exchange and the armored TGS
//! exchange. Every reply equals, byte for byte, the in-process path: the
//! same kdc with keyd in process (`keyd::LocalKeyd`) and the directory-pip
//! `DirectoryView` in process over an identical directory.
//!
//! Then the unavailability path (docs/50 R50-8, §3.7; A-56): dird stopped
//! under a pinned view, dird gone, and a server that never answers (the
//! deadline) all reach the client as KDC_ERR_SVC_UNAVAILABLE (29) over TCP
//! and as silence over UDP.
//!
//! The Kerberos client side is the kdc crate's integration fixtures
//! (crates/kdc/tests/common, reused as crates/keyd-daemon does): RFC 4120 /
//! RFC 6113 with krb-crypto, the identities, the scripted keys. The
//! directory holds the same identities (tests/support `Directory`), and keyd
//! holds their keys under the directory's own handles (objectGUID, docs/47
//! R47-3), set up as docs/47 §9 describes.
//!
//! Sources: docs/50 R50-2, R50-3, R50-8, §3.4, §3.7, §7.5 step 4, §9 tier 2,
//! §10 (P8); docs/47 §1.4 (R47-2), §8.1 (R47-14), §9.1; docs/48 §7.3, §9.2;
//! RFC 4120 §7.5.9 (code 29); RFC 6113 5.4. Every value is constructed by
//! hand; no vector comes from any other implementation.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use common::*;
use core::time::Duration;
use directory_daemon::StoreSource;
use directory_pip::{DirectoryContext, TierMap};
use dirstore::{IntegrityKey, Store};
use ipc_directory::{
    Connector as _, DirectoryClient, RemoteView, TransportError, UnavailableDirectory, Unserved,
};
use ipc_keyd::{IpcKeyd, KeydClient, DEFAULT_DEADLINE};
use kdc::{AccountSource, Kdc, KdcConfig, KdcReply, Peer, PolicyInputs, Transport};
use keyd::{InMemoryKeyStore, KeyHandle, Keyd, LocalKeyd, PrincipalBinding, Role};
use keyd_daemon::{CallerMap, RecordBuffer};
use krb_proto::constants::KDC_ERR_SVC_UNAVAILABLE;
use krb_proto::KerberosTime;
use pdp::{IpScope, Pip, PolicySnapshot, PolicyVersion};
use std::os::unix::net::UnixListener;
use support::connector;

/// keyd's handles of the directory's key sets (docs/47 §9.1 table): the
/// krbtgt account's, alice's long-term, ws1$'s long-term (it is a client:
/// the bootstrap) and files$'s service key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Handles {
    krbtgt: KeyHandle,
    alice: KeyHandle,
    ws1: KeyHandle,
    files: KeyHandle,
}

/// The directory context of the identities (realm EXAMPLE.ORG).
fn context() -> DirectoryContext {
    DirectoryContext::new(
        ad_schema::phase1().unwrap(),
        &support::keyd_config(),
        support::naming_context(),
    )
    .unwrap()
}

impl Handles {
    /// Read from the directory, as the kdc and the management plane would
    /// (docs/47 R47-2, R47-3).
    fn read(store: &Store) -> Handles {
        let ctx = context();
        let tiers = TierMap::empty();
        let view = ctx.view(store, &tiers).unwrap();
        let alice = view.client(&realm(), &alice_name()).unwrap().unwrap();
        // The salt the client derives alice's key with is the directory's
        // [MS-KILE] 3.1.1.2 salt (docs/47 R47-4).
        assert_eq!(
            alice.etype_info[0].salt.as_ref().unwrap().as_str(),
            ALICE_SALT
        );
        Handles {
            krbtgt: view.krbtgt_handle(&support::domain_sid()).unwrap(),
            alice: alice.key,
            ws1: view.client(&realm(), &machine_name()).unwrap().unwrap().key,
            files: view
                .service(&realm(), &service_name())
                .unwrap()
                .unwrap()
                .key,
        }
    }
}

/// keyd with the directory's key sets (docs/47 §9.1, §9.2): the krbtgt,
/// files$ (service) and ws1$ (a computer client: a random key, docs/48 §7.3)
/// key sets from `create_key` with the fixtures' scripted key octets, and
/// alice's from `set_secret` with her password and the directory's salt —
/// all under the directory's handles; the set-up records are dropped. The
/// same function builds the in-process keyd and the daemon's (one
/// deterministic test entropy each, drawn in the same order).
fn directory_keyd(
    started: &KerberosTime,
    handles: Handles,
) -> Result<Keyd<InMemoryKeyStore, RecordBuffer, TestEntropy>, keyd::ConfigError> {
    let entropy = TestEntropy::default();
    let mut keyd = Keyd::with_entropy(
        support::keyd_config(),
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
        (handles.krbtgt, krbtgt_name(), KRBTGT_KEY),
        (handles.files, service_name(), SERVICE_KEY),
        (handles.ws1, machine_name(), MACHINE_KEY),
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
    crate::common::grant_user(
        &mut keyd,
        &handles.alice,
        &PrincipalBinding::new(realm(), alice_name()),
        &now(),
    );
    keyd.set_secret(
        &DIRECTORY,
        &handles.alice,
        &PrincipalBinding::new(realm(), alice_name()),
        String::from(ALICE_PASSWORD).into(),
        ALICE_SALT,
        &now(),
    )
    .unwrap();
    let _ = keyd.audit_sink_mut().take();
    Ok(keyd)
}

fn tcp() -> Peer {
    Peer {
        transport: Transport::Tcp,
        src_net: IpScope::Internal,
    }
}

fn policy() -> PolicySnapshot {
    snapshot(vec![allow_kerberos()])
}

/// One request through a kdc, with one view (account source and PIP of the
/// same snapshot, docs/47 R47-14).
fn send<K: kdc::KeyCustody, V: AccountSource + Pip>(
    kdc: &mut Kdc<K, KdcAudit, TestRateLimiter>,
    view: &V,
    request: &[u8],
    peer: Peer,
) -> KdcReply {
    let snapshot = policy();
    let inputs = PolicyInputs {
        snapshot: &snapshot,
        pip: view,
    };
    kdc.handle(request, peer, now(), &inputs, view)
}

/// One request through the remote kdc: a fresh view per request (docs/50
/// R50-2), ended afterwards.
fn send_remote<K: kdc::KeyCustody, C: ipc_directory::Connector>(
    kdc: &mut Kdc<K, KdcAudit, TestRateLimiter>,
    dird: &mut DirectoryClient<C>,
    request: &[u8],
) -> KdcReply {
    let view: RemoteView<'_, C> = dird.begin_view().unwrap();
    let reply = send(kdc, &view, request, tcp());
    assert!(view.is_open(), "every query of the request was served");
    view.end().unwrap();
    reply
}

/// docs/50 §9 tier 2, §10 (P8), R50-2, R50-3; docs/48 §9.2: bootstrap →
/// armored AS → armored TGS through both daemons equals the in-process
/// directory-pip path, byte for byte; the service ticket opens under the
/// service key and names alice.
#[test]
fn the_full_kdc_flow_through_keyd_and_dird_equals_the_in_process_path() {
    let dir = support::TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    // Two identical directories: dird's own file — inside the workspace
    // (crates/test-scratch), since dird reaches it through the
    // protected-file walk from `/` (task R11b, Q-530) — and the baseline's.
    let files = test_scratch::ScratchDir::new("dird-flow").unwrap();
    let remote_path = files.join("r.redb");
    drop(support::Directory::standard(&remote_path));
    let local = support::Directory::standard(&dir.join("l.redb"));
    let handles = Handles::read(&local.store);

    // auditd (a fake for each daemon, uid = the test's: each records its
    // peer under that daemon's own source — task R9b), keyd, dird.
    let keyd_params =
        support::keyd::params(&dir, CallerMap::new(&[(uid, Role::Kdc)]).unwrap(), uid);
    let keyd_socket = keyd_params.keyd_socket.clone();
    let _auditd = support::FakeAuditd::start(&keyd_params.audit.socket);
    let mut dird_params = support::params(&dir, uid, uid, Duration::from_secs(5), 4);
    dird_params.audit.socket = dir.join("da.sock");
    let _dird_auditd = support::FakeAuditd::start_recording_as(
        &dird_params.audit.socket,
        ipc_audit::EventSource::Dird,
    );
    let clock = support::TestClock::at(keyd_started());
    let keyd_daemon = support::keyd::Daemon::start(keyd_params, clock.clone(), move |started| {
        directory_keyd(started, handles)
    })
    .unwrap();
    clock.set(now());
    let dird = support::Dird::start(
        dird_params,
        StoreSource::File {
            path: remote_path,
            key: IntegrityKey::from_bytes(&support::TEST_KEY),
            owner_uid: uid,
        },
        support::policy(1),
    )
    .unwrap();

    // The remote kdc: custody and directory over the sockets; the krbtgt
    // handle and realm from DescribeDomain (docs/50 §7.5 step 4).
    let custody = IpcKeyd::connect(KeydClient::new(
        connector::keyd(&keyd_socket),
        ipc_keyd::ExpectedPeer::new(uid, Role::Kdc).unwrap(),
        DEFAULT_DEADLINE,
    ))
    .unwrap();
    let mut dird_client = DirectoryClient::connect(
        connector::dird(&dird.socket),
        uid,
        ipc_directory::DEFAULT_DEADLINE,
        policy().version(),
    )
    .unwrap();
    let domain = dird_client.domain().clone();
    assert_eq!(domain.krbtgt, handles.krbtgt);
    assert_eq!(domain.realm, realm());
    assert_eq!(domain.policy_version, PolicyVersion(1));
    let mut remote = Kdc::new(
        KdcConfig::new(domain.realm.clone(), domain.krbtgt),
        custody,
        KdcAudit::default(),
        TestRateLimiter::default(),
    )
    .unwrap();

    // The in-process baseline: the same keyd in process, the directory-pip
    // view in process.
    let mut direct = Kdc::new(
        KdcConfig::new(realm(), handles.krbtgt),
        LocalKeyd::new(
            directory_keyd(&keyd_started(), handles).unwrap(),
            KDC_CALLER,
        )
        .unwrap(),
        KdcAudit::default(),
        TestRateLimiter::default(),
    )
    .unwrap();
    let ctx = context();
    let tiers = TierMap::empty();
    let mut send_direct = |request: &[u8]| {
        let view = ctx.view(&local.store, &tiers).unwrap();
        send(&mut direct, &view, request, tcp())
    };

    // Bootstrap: ws1$, a computer account, unarmored PA-ENC-TIMESTAMP.
    let bootstrap = AsReqSpec::machine()
        .with_timestamp(&machine_key(AES256))
        .encode();
    let direct_reply = send_direct(&bootstrap);
    let remote_reply = send_remote(&mut remote, &mut dird_client, &bootstrap);
    assert_eq!(direct_reply, remote_reply, "bootstrap AS-REP");
    let machine_tgt = open_as_rep(&sent(remote_reply), &machine_key(AES256));

    // Armored AS: alice, encrypted challenge, armored by ws1$'s TGT.
    let armor = Armor::new(&machine_tgt, now(), 1);
    let alice = AsReqSpec::alice()
        .with_challenge(&alice_key(AES256))
        .encode_armored(&armor, now());
    let direct_reply = send_direct(&alice);
    let remote_reply = send_remote(&mut remote, &mut dird_client, &alice);
    assert_eq!(direct_reply, remote_reply, "armored AS-REP");
    let tgt = open_fast_as_rep(&sent(remote_reply), &armor.key, &alice_key(AES256));

    // Armored TGS (implicit armor) for host/files.example.org.
    let spec = TgsReqSpec::service();
    let (tgs, _) = spec.encode(&tgt);
    let direct_reply = send_direct(&tgs);
    let remote_reply = send_remote(&mut remote, &mut dird_client, &tgs);
    assert_eq!(direct_reply, remote_reply, "armored TGS-REP");
    let (rep, part) = open_tgs_rep(&sent(remote_reply), &tgt, &spec);
    assert_eq!(rep.0.cname, alice_name());
    assert_eq!(part.0.sname, service_name());
    assert_eq!(
        open_ticket(&rep.0.ticket, &service_key()).cname,
        alice_name()
    );

    drop(remote);
    drop(dird_client);
    dird.stop().unwrap();
    keyd_daemon.stop().unwrap();
}

/// docs/50 R50-8, §3.6, §3.7; A-56; RFC 4120 §7.5.9 (29): dird stopped under
/// a pinned view, dird gone, and a server that never answers (the deadline)
/// each make the kdc answer KDC_ERR_SVC_UNAVAILABLE over TCP and nothing over
/// UDP — never "no such principal", never KRB_ERR_GENERIC.
#[test]
fn dird_down_or_past_its_deadline_reaches_the_client_as_29() {
    let dir = support::TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    let directory = support::Directory::standard(&dir.join("s.redb"));
    let handles = Handles::read(&directory.store);
    let mut kdc = Kdc::new(
        KdcConfig::new(realm(), handles.krbtgt),
        LocalKeyd::new(
            directory_keyd(&keyd_started(), handles).unwrap(),
            KDC_CALLER,
        )
        .unwrap(),
        KdcAudit::default(),
        TestRateLimiter::default(),
    )
    .unwrap();
    let bootstrap = |nonce: u32| {
        let mut spec = AsReqSpec::machine().with_timestamp(&machine_key(AES256));
        spec.nonce = nonce;
        spec.encode()
    };
    let _auditd =
        support::FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Dird);
    let dird = support::Dird::start(
        support::params(&dir, uid, uid, Duration::from_secs(5), 4),
        directory_daemon::test_seams::opened(std::sync::Arc::clone(&directory.store)),
        support::policy(1),
    )
    .unwrap();
    let mut client = DirectoryClient::connect(
        connector::dird(&dird.socket),
        uid,
        ipc_directory::DEFAULT_DEADLINE,
        policy().version(),
    )
    .unwrap();

    // Served while dird is up.
    let reply = send_remote(&mut kdc, &mut client, &bootstrap(1));
    let _ = open_as_rep(&sent(reply), &machine_key(AES256));

    // dird stops under a pinned view: the view's lookups are not served.
    {
        let view = client.begin_view().unwrap();
        dird.stop().unwrap();
        assert_eq!(
            code_of(send(&mut kdc, &view, &bootstrap(2), tcp())),
            KDC_ERR_SVC_UNAVAILABLE
        );
        assert!(!view.is_open());
    }

    // dird gone: no view; the kdc answers through UnavailableDirectory.
    assert!(matches!(client.begin_view(), Err(Unserved::Transport(_))));
    let none = UnavailableDirectory;
    assert_eq!(
        code_of(send(&mut kdc, &none, &bootstrap(3), tcp())),
        KDC_ERR_SVC_UNAVAILABLE
    );
    let udp = Peer {
        transport: Transport::Udp,
        src_net: IpScope::Internal,
    };
    assert_eq!(send(&mut kdc, &none, &bootstrap(4), udp), KdcReply::Silent);

    // A server (of the right uid) that accepts and never answers: the
    // client's deadline passes at its start-time DescribeDomain — no client
    // (task R9: the domain is pinned at construction).
    let silent_path = dir.join("q.sock");
    let listener = UnixListener::bind(&silent_path).unwrap();
    let holder = std::thread::spawn(move || {
        let held = listener.accept().map(|(stream, _)| stream);
        std::thread::sleep(Duration::from_secs(2));
        drop(held);
    });
    let slow = DirectoryClient::connect(
        connector::dird(&silent_path),
        uid,
        Duration::from_millis(300),
        policy().version(),
    );
    assert_eq!(
        slow.err(),
        Some(ipc_directory::ConnectError::Unserved(Unserved::Transport(
            TransportError::DeadlineExceeded
        )))
    );
    assert_eq!(
        code_of(send(&mut kdc, &none, &bootstrap(5), tcp())),
        KDC_ERR_SVC_UNAVAILABLE
    );
    holder.join().unwrap();
    // The connector type is used through the client only.
    let _ = connector::dird(&silent_path).connect();
}
