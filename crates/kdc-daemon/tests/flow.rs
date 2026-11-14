//! Tier 1 of task P9 (docs/50 §9 "a full login (computer → armored user →
//! service ticket)", §10 P9): the kdc daemon — `kdc_daemon::serve` with its
//! real UDP and TCP listeners on loopback ports the system picked — in
//! front of the real keyd daemon (`keyd_daemon::serve`, over `keyd.sock`)
//! and the real dird (`directory_daemon::serve`, over `dird-kdc.sock`, its
//! own redb file), all loading **the same policy file** (crates/
//! policy-store, A-68). The computer account's bootstrap, the armored AS
//! exchange and the armored TGS exchange run through both listeners: every
//! reply equals, octet for octet, the in-process path — the same `Kdc` with
//! keyd in process (`keyd::LocalKeyd`) and the directory-pip view in
//! process over an identical directory, deciding with the snapshot of the
//! same policy file — and is decrypted client-side.
//!
//! Each request goes first over UDP (RFC 4120 §7.2.1), then, unchanged,
//! over TCP (§7.2.2): the second is the identical request the KDC answers
//! from its retransmit cache (§3.1.2) — so a reply too large for UDP
//! (KRB_ERR_RESPONSE_TOO_BIG, §7.2.1) is followed by the TCP retry the RFC
//! prescribes, exactly as in process.
//!
//! The Kerberos client side is the kdc crate's integration fixtures
//! (crates/kdc/tests/common: RFC 4120 / RFC 6113 with krb-crypto). The
//! kdc's events reach its auditd (A-57).
//!
//! Sources: docs/50 R50-2, R50-9, §4.1, §7.2, §7.5, §9, §10 (P9); docs/47
//! §8.1 (R47-14), §9.1; docs/48 §7.3, §9.2; RFC 4120 §3.1.2, §7.2.1,
//! §7.2.2; RFC 6113 §5.4. Every value is hand-made.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use common::*;
use directory_daemon::StoreSource;
use directory_pip::TierMap;
use dirstore::IntegrityKey;
use ipc_audit::EventBody;
use kdc::{AccountSource, Kdc, KdcConfig, KdcReply, Peer, PolicyInputs, Transport};
use keyd::{LocalKeyd, Role};
use keyd_daemon::CallerMap;
use pdp::{IpScope, Pip};
use std::time::Duration;
use support::*;

/// One request through the in-process kdc with one view.
fn send_direct<K: kdc::KeyCustody, V: AccountSource + Pip>(
    kdc: &mut Kdc<K, KdcAudit, TestRateLimiter>,
    snapshot: &pdp::PolicySnapshot,
    view: &V,
    request: &[u8],
    transport: Transport,
) -> KdcReply {
    let inputs = PolicyInputs {
        snapshot,
        pip: view,
    };
    let peer = Peer {
        transport,
        src_net: IpScope::Internal,
    };
    kdc.handle(request, peer, now(), &inputs, view)
}

/// What a UDP reply must be, given the in-process `KdcReply`.
fn expected(reply: KdcReply) -> Option<Vec<u8>> {
    match reply {
        KdcReply::Send(bytes) | KdcReply::SendAndClose(bytes) => Some(bytes),
        KdcReply::Silent => None,
    }
}

/// docs/50 §9 tier 1, §10 (P9), R50-2; docs/48 §9.2; RFC 4120 §7.2: the
/// bootstrap → armored AS → armored TGS through the daemon's UDP and TCP
/// listeners equals the in-process path octet for octet; the tickets open
/// under the right keys; the kdc audited every request.
#[test]
fn the_full_flow_through_the_kdc_daemon_equals_the_in_process_path() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    // Two identical directories: dird's own file — inside the workspace
    // (crates/test-scratch), since dird reaches it through the
    // protected-file walk from `/` (task R11b, Q-530) — and the baseline's.
    let files = test_scratch::ScratchDir::new("kdc-flow").unwrap();
    let remote_path = files.join("r.redb");
    drop(dird::Directory::standard(&remote_path));
    let local = dird::Directory::standard(&dir.join("l.redb"));
    let handles = Handles::read(&local.store);

    // The policy file both daemons load (A-68), and its snapshot.
    let policy = shared_policy(7, vec![allow_kerberos()]);
    let file = policy.encode().unwrap();
    let loaded = policy_store::DevelopmentPolicy::decode(&file).unwrap();
    let snapshot = loaded.snapshot().unwrap();

    // An auditd for each of keyd, dird and the kdc (each records its peer
    // under that daemon's own source — task R9b); keyd; dird.
    let keyd_params = keyd_support::params(&dir, CallerMap::new(&[(uid, Role::Kdc)]).unwrap(), uid);
    let keyd_socket = keyd_params.keyd_socket.clone();
    let _auditd = FakeAuditd::start(&keyd_params.audit.socket);
    let mut dird_params = dird::params(&dir, uid, uid, Duration::from_secs(5), 4);
    dird_params.audit.socket = dir.join("da.sock");
    let _dird_auditd =
        FakeAuditd::start_recording_as(&dird_params.audit.socket, ipc_audit::EventSource::Dird);
    let kdc_auditd =
        FakeAuditd::start_recording_as(&dir.join("ka.sock"), ipc_audit::EventSource::Kdc);
    let clock = TestClock::at(keyd_started());
    let keyd_daemon = keyd_support::Daemon::start(keyd_params, clock.clone(), move |started| {
        directory_keyd(started, handles)
    })
    .unwrap();
    clock.set(now());
    let dird_daemon = dird::Dird::start(
        dird_params,
        StoreSource::File {
            path: remote_path,
            key: IntegrityKey::from_bytes(&dird::TEST_KEY),
            owner_uid: uid,
        },
        loaded.clone(),
    )
    .unwrap();

    // The kdc daemon: its own clock at the fixtures' `now`.
    let kdcd = Kdcd::start(
        kdc_params(&dir.join("ka.sock"), uid),
        loaded,
        &keyd_socket,
        &dird_daemon.socket,
        HeldClock::at(now()),
    )
    .unwrap();

    // The in-process baseline.
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
    let mut both = |request: &[u8]| -> Vec<u8> {
        let view = ctx.view(&local.store, &tiers).unwrap();
        let udp_expected = expected(send_direct(
            &mut direct,
            &snapshot,
            &view,
            request,
            Transport::Udp,
        ));
        let tcp_expected = sent(send_direct(
            &mut direct,
            &snapshot,
            &view,
            request,
            Transport::Tcp,
        ));
        let udp_reply = udp_send(kdcd.udp, request, Duration::from_secs(5));
        assert_eq!(udp_reply, udp_expected, "UDP reply");
        let tcp_reply = message(tcp_send(kdcd.tcp, request));
        assert_eq!(tcp_reply, tcp_expected, "TCP reply");
        tcp_reply
    };

    // Bootstrap: ws1$, a computer account, unarmored PA-ENC-TIMESTAMP.
    let bootstrap = AsReqSpec::machine()
        .with_timestamp(&machine_key(AES256))
        .encode();
    let machine_tgt = open_as_rep(&both(&bootstrap), &machine_key(AES256));

    // Armored AS: alice, encrypted challenge, armored by ws1$'s TGT.
    let armor = Armor::new(&machine_tgt, now(), 1);
    let alice = AsReqSpec::alice()
        .with_challenge(&alice_key(AES256))
        .encode_armored(&armor, now());
    let tgt = open_fast_as_rep(&both(&alice), &armor.key, &alice_key(AES256));

    // Armored TGS (implicit armor) for host/files.example.org.
    let spec = TgsReqSpec::service();
    let (tgs, _) = spec.encode(&tgt);
    let (rep, part) = open_tgs_rep(&both(&tgs), &tgt, &spec);
    assert_eq!(rep.0.cname, alice_name());
    assert_eq!(part.0.sname, service_name());
    assert_eq!(
        open_ticket(&rep.0.ticket, &service_key()).cname,
        alice_name()
    );

    // A-57: the kdc's events reached its auditd (six requests at least).
    assert!(
        eventually(Duration::from_secs(5), || {
            kdc_auditd
                .events()
                .iter()
                .filter(|e| matches!(e, EventBody::Kdc(_)))
                .count()
                >= 6
        }),
        "the kdc's events were delivered"
    );

    kdcd.stop().unwrap();
    dird_daemon.stop().unwrap();
    keyd_daemon.stop().unwrap();
}
