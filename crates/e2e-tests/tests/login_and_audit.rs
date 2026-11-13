//! Task P12 scenarios 1 and 2 (docs/50 §9 tier 2 across all daemons; §10
//! P12): auditd, keyd, dird, the kdc and ldap-front all running at once,
//! wired only through their real Unix sockets and loopback listeners
//! (tests/support/harness.rs).
//!
//! 1. **Full login over the wire** — the computer account's AS exchange
//!    (the bootstrap, P-10), alice's armored AS exchange (FAST with the
//!    encrypted challenge, RFC 6113 §5.4.1.1, §5.4.2, §5.4.6), and the
//!    armored TGS exchange for host/files.example.org (implicit armor,
//!    §5.4.2), each request sent over the kdc's **UDP** listener (RFC 4120
//!    §7.2.1) and then, unchanged, over its **TCP** listener (§7.2.2). Every
//!    reply decodes (RFC 4120 §5.4.2), every enc-part opens with the key the
//!    client knows (§3.1.5, §3.3.4), every ticket opens with the key of the
//!    service it is for (the krbtgt key, the service key — fixture keys,
//!    §5.3), and every reply equals the in-process path octet for octet
//!    (crates/kdc-daemon tests/flow.rs: the same `Kdc` with keyd in process
//!    and the directory view in process over an identical directory and the
//!    same policy file).
//! 2. **Audit end to end** — after the login and an LDAP operation, every
//!    daemon stopped (each flushes its window, bounded) and then auditd:
//!    auditd's on-disk log verifies with crates/audit-log's own verifier
//!    (the hash chain from genesis, every segment); it holds the kdc's, keyd's
//!    and dird's events, each with its transport identity (the connection's
//!    peer uid, set by auditd — docs/50 §3.2; keyd's records carry the caller
//!    uid and role keyd took from its own transport); and no issuance
//!    happened without its record persisted (A-57, A-64).
//!
//! The Kerberos client side is the kdc crate's integration fixtures
//! (crates/kdc/tests/common: written from RFC 4120 / RFC 6113 with this
//! project's krb-crypto), reused as crates/kdc-daemon's tests reuse them.
//!
//! Sources: docs/50 R50-2, R50-9, R50-17, §3.2, §4.1, §7.2, §7.5, §8.1, §9;
//! docs/47 §8.1, §9.1; docs/48 §7, §9.2; RFC 4120 §3.1.2, §3.1.5, §3.3.4,
//! §5.4.1, §5.4.2, §7.2.1, §7.2.2; RFC 6113 §5.4.1.1, §5.4.2, §5.4.3,
//! §5.4.6; A-57, A-64, A-66..A-71. Every value is hand-made.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use audit_log::Source;
use common::*;
use ipc_audit::{
    decode_event, EventBody, KdcExchange, KdcOutcome, KdcTransport, KeydOperation, KeydOutcome,
    KeydRole, LdapOperation, LdapTransport,
};
use kdc::{AccountSource, Kdc, KdcConfig, KdcReply, Peer, PolicyInputs, Transport};
use keyd::LocalKeyd;
use krb_proto::{AsRep, TgsRep};
use pdp::{IpScope, Pip};
use std::io::Write;
use std::time::Duration;
use support::kdcd::{message, tcp_send, udp_send};
use support::ldap_client::{direct, root_dse, tcp, tls_over, LdapReader};
use support::*;

/// How long a UDP client waits for the reply datagram (RFC 4120 §7.2.1).
const UDP_WAIT: Duration = Duration::from_secs(5);

/// One request through the in-process kdc with one view (crates/kdc-daemon
/// tests/flow.rs).
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

/// Whether `reply` is a KDC-REP — AS-REP [APPLICATION 11] or TGS-REP
/// [APPLICATION 13] (RFC 4120 §5.4.2) — i.e. an issuance.
fn is_kdc_rep(reply: &[u8]) -> bool {
    AsRep::decode(reply).is_ok() || TgsRep::decode(reply).is_ok()
}

/// What the login saw.
struct Login {
    /// KDC-REPs (issuances) the client received, UDP and TCP together.
    kdc_reps: usize,
}

/// The login of scenario 1 (module documentation). `send` sends one
/// request over UDP, then over TCP, and returns both replies.
/// Spec: RFC 4120 §3.1, §3.3, §7.2; RFC 6113 §5.4; docs/48 §7, §9.2.
fn login(mut send: impl FnMut(&[u8]) -> (Option<Vec<u8>>, Vec<u8>)) -> Login {
    let mut kdc_reps = 0usize;
    let mut exchange = |request: &[u8]| -> Vec<u8> {
        let (udp, tcp) = send(request);
        kdc_reps += usize::from(udp.as_deref().is_some_and(is_kdc_rep));
        kdc_reps += usize::from(is_kdc_rep(&tcp));
        tcp
    };

    // The computer account's bootstrap: unarmored PA-ENC-TIMESTAMP (P-10).
    let bootstrap = AsReqSpec::machine()
        .with_timestamp(&machine_key(AES256))
        .encode();
    let machine_tgt = open_as_rep(&exchange(&bootstrap), &machine_key(AES256));
    assert_eq!(machine_tgt.rep.0.cname, machine_name(), "RFC 4120 §3.1.5");
    assert_eq!(machine_tgt.part.0.sname, krbtgt_name(), "RFC 4120 §3.1.5");
    let machine_ticket = open_ticket(&machine_tgt.rep.0.ticket, &krbtgt_key());
    assert_eq!(machine_ticket.cname, machine_name());
    assert_eq!(machine_ticket.key, machine_tgt.part.0.key, "RFC 4120 §5.3");

    // alice, armored by ws1$'s TGT, encrypted challenge (RFC 6113 §5.4.6).
    let armor = Armor::new(&machine_tgt, now(), 1);
    let alice = AsReqSpec::alice()
        .with_challenge(&alice_key(AES256))
        .encode_armored(&armor, now());
    let tgt = open_fast_as_rep(&exchange(&alice), &armor.key, &alice_key(AES256));
    assert_eq!(tgt.rep.0.cname, alice_name());
    let alice_ticket = open_ticket(&tgt.rep.0.ticket, &krbtgt_key());
    assert_eq!(alice_ticket.cname, alice_name());
    assert_eq!(alice_ticket.key, tgt.part.0.key, "RFC 4120 §5.3");

    // The armored TGS (implicit armor, RFC 6113 §5.4.2) for host/files.
    let spec = TgsReqSpec::service();
    let (tgs, _) = spec.encode(&tgt);
    let (rep, part) = open_tgs_rep(&exchange(&tgs), &tgt, &spec);
    assert_eq!(rep.0.cname, alice_name());
    assert_eq!(part.0.sname, service_name(), "RFC 4120 §3.3.4");
    let service_ticket = open_ticket(&rep.0.ticket, &service_key());
    assert_eq!(service_ticket.cname, alice_name());
    assert_eq!(service_ticket.key, part.0.key, "RFC 4120 §5.3");

    Login { kdc_reps }
}

/// Scenario 1. docs/50 §9 tier 2, §10 (P12), R50-2, R50-9, §7.5; docs/48
/// §9.2; RFC 4120 §3.1, §3.3, §7.2.1, §7.2.2; RFC 6113 §5.4: the computer
/// AS, the armored user AS and the armored TGS through the kdc's UDP and
/// TCP listeners, with keyd, dird, auditd and ldap-front all running and
/// reached only over their sockets — every reply decodes, opens with the
/// fixture's keys, and equals the in-process path octet for octet.
#[test]
fn full_login_over_udp_and_tcp_with_all_five_daemons() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        let kdc = (h.kdcd().udp, h.kdcd().tcp);

        // The in-process baseline (crates/kdc-daemon tests/flow.rs): keyd in
        // process with the same keys, the view of the reference copy, the
        // snapshot of the same policy file.
        let mut reference = Kdc::new(
            KdcConfig::new(realm(), h.handles.krbtgt),
            LocalKeyd::new(
                support::kdcd::directory_keyd(&keyd_started(), h.handles).unwrap(),
                KDC_CALLER,
            )
            .unwrap(),
            KdcAudit::default(),
            TestRateLimiter::default(),
        )
        .unwrap();
        let snapshot = h.policy.snapshot().unwrap();
        let tiers = directory_daemon::policy::tier_map(&h.policy).unwrap();
        let ctx = directory_context();
        let local = &h.local;

        let outcome = login(|request| {
            let view = ctx.view(&local.store, &tiers).unwrap();
            let udp_expected = expected(send_direct(
                &mut reference,
                &snapshot,
                &view,
                request,
                Transport::Udp,
            ));
            let tcp_expected = sent(send_direct(
                &mut reference,
                &snapshot,
                &view,
                request,
                Transport::Tcp,
            ));
            let udp = udp_send(kdc.0, request, UDP_WAIT);
            assert_eq!(udp, udp_expected, "UDP reply (RFC 4120 §7.2.1)");
            let tcp = message(tcp_send(kdc.1, request));
            assert_eq!(tcp, tcp_expected, "TCP reply (RFC 4120 §7.2.2)");
            (udp, tcp)
        });
        assert!(outcome.kdc_reps >= 3, "three issuances at least");
        h.stop_all();
    });
}

/// Scenario 2. docs/50 R50-17, §3.2 ("the source is set from the uid, not
/// from the event body"), §8.1; docs/37 §2; A-57, A-64, A-66: after the
/// login and an LDAP operation, with every daemon stopped (their windows
/// flushed) and then auditd — the on-disk log verifies from genesis through
/// crates/audit-log's verifier; it holds kdc, keyd and dird events, each
/// record carrying its connection's peer uid (the one test uid) and the
/// source auditd's map gives that uid, keyd's records carrying the caller
/// uid and role keyd derived from its own transport; and every issuance the
/// client received has its kdc event and keyd's issuing records persisted.
#[test]
fn the_audit_log_verifies_and_holds_every_daemons_events() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        let kdc = (h.kdcd().udp, h.kdcd().tcp);
        let outcome = login(|request| {
            let udp = udp_send(kdc.0, request, UDP_WAIT);
            let tcp = message(tcp_send(kdc.1, request));
            (udp, tcp)
        });

        // An LDAP operation: the anonymous rootDSE over LDAPS, the engine's
        // answer octet for octet (dird's event comes from it, R49-14).
        let mut stream = tls_over(tcp(h.front().ldaps), &h.tls_client).unwrap();
        stream.write_all(&root_dse(1)).unwrap();
        let mut reader = LdapReader::default();
        let entry = reader.next(&mut stream).unwrap();
        let done = reader.next(&mut stream).unwrap();
        let mut session = ldap::Session::new(1, ldap::Listener::Ldaps);
        let reference = direct(
            &h.local.store,
            &h.policy,
            now(),
            &mut session,
            &root_dse(1),
            true,
            false,
        );
        assert_eq!(vec![entry, done], reference.responses);
        drop(stream);

        // dird's event is persisted before dird stops (dird's stop does not
        // wait for its window — tests/support harness.rs
        // `wait_until_persisted`, docs/questions/Q-313); then every sender
        // stops (keyd and the kdc each wait, bounded, for auditd to
        // acknowledge their windows), then auditd.
        assert!(h.wait_until_persisted(|events| {
            events.iter().any(|event| {
                matches!(event, EventBody::Ldap(e)
                    if e.operation == LdapOperation::Search && e.transport == LdapTransport::Ldaps)
            })
        }));
        h.stop_all();
        let (head, records) = h.verified_audit_log().expect("the log verifies");
        assert_eq!(head.seq, records.len() as u64, "one chain from genesis");
        assert_eq!(records.last().map(|r| r.seq), Some(head.seq));

        let mut kdc_events = Vec::new();
        let mut keyd_records = Vec::new();
        let mut ldap_events = Vec::new();
        for record in &records {
            if record.source == Source::Auditd {
                continue;
            }
            // The transport identity (docs/50 §3.2): the peer uid auditd
            // read, and the one source its map gives that uid.
            assert_eq!(record.source_uid, h.uid, "the sender's peer uid");
            assert_eq!(record.source, Source::Kdc, "the label of the one uid");
            match decode_event(&record.payload).expect("every payload decodes") {
                EventBody::Kdc(event) => kdc_events.push(*event),
                EventBody::Keyd(record) => keyd_records.push(*record),
                EventBody::Ldap(event) => ldap_events.push(*event),
                EventBody::WindowSummary(_) => {}
            }
        }

        // The kdc's events: both exchanges, both transports.
        assert!(kdc_events
            .iter()
            .any(|e| e.exchange == Some(KdcExchange::As)));
        assert!(kdc_events
            .iter()
            .any(|e| e.exchange == Some(KdcExchange::Tgs)));
        assert!(kdc_events.iter().any(|e| e.transport == KdcTransport::Udp));
        assert!(kdc_events.iter().any(|e| e.transport == KdcTransport::Tcp));

        // keyd's records: the whole flow, each made for the caller keyd
        // identified by its transport — the test's uid as the Kdc role.
        for op in [
            KeydOperation::VerifyPreauth,
            KeydOperation::IssueAsRep,
            KeydOperation::OpenFastArmor,
            KeydOperation::OpenAndVerifyTgt,
            KeydOperation::IssueTgsRep,
        ] {
            assert!(
                keyd_records.iter().any(|r| r.op == op),
                "{op:?} missing from keyd's records"
            );
        }
        for record in &keyd_records {
            assert_eq!(record.caller_uid, h.uid);
            assert_eq!(record.caller_role, KeydRole::Kdc);
        }

        // dird's LDAP event for the rootDSE over LDAPS.
        assert!(
            ldap_events.iter().any(
                |e| e.operation == LdapOperation::Search && e.transport == LdapTransport::Ldaps
            ),
            "dird's event of the LDAPS search"
        );

        // A-57 / A-64: no issuance without its record persisted — every
        // KDC-REP the client received has an `Issued` kdc event in the log,
        // and keyd's successful issuing records cover the two AS issuances
        // (ws1$, alice) and the TGS issuance.
        let issued = kdc_events
            .iter()
            .filter(|e| e.outcome == KdcOutcome::Issued)
            .count();
        assert!(
            issued >= outcome.kdc_reps,
            "{issued} issued events for {} KDC-REPs received",
            outcome.kdc_reps
        );
        let succeeded = |op: KeydOperation| {
            keyd_records
                .iter()
                .filter(|r| r.op == op && r.result == KeydOutcome::Success)
                .count()
        };
        assert!(succeeded(KeydOperation::IssueAsRep) >= 2);
        assert!(succeeded(KeydOperation::IssueTgsRep) >= 1);
    });
}
