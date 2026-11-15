//! The one audit client (crate `ipc_audit_client`, task R9b) over real Unix
//! sockets: the peer uid and the source auditd reports are verified on every
//! new connection before any batch, and an auditd that would record this
//! process under another source receives nothing — the gate keeps auditd
//! unreachable meanwhile, so gating operations are refused. Task R15b: the
//! client is the only source of the gate's evidence — attaching a verified
//! connection opens the gate, ending the link closes it, and a proof of an
//! acknowledged intent comes only from an auditd's `Ack` delivered through
//! the client.
//!
//! The auditd here is a minimal server written from the audit channel's own
//! message set (this crate): `Ping` → `Pong` naming the source it was told
//! to report, `Append` → `Ack` of its last number (or no reply, in its
//! silent mode); it counts what it received (tests/linked, shared with the
//! other crates' tests). Real peer credentials on both sides (the test's own
//! uid); as root the tests are skipped (uid 0 is never an expected auditd
//! uid — docs/50 R50-3).
//!
//! Source: docs/50 R50-3 ("the client verifies the server's uid too"),
//! §3.2 ("the source is set from the uid"), §3.6, §3.7, §7.5, §8.1; docs/52
//! §3.11 R6 (a), §3.12 (C12); PENDING-OWNER A-57, A-67 item 2 (auditd
//! unreachable ⇒ gating refused), A-115; docs/questions/Q-512 (A-112),
//! Q-560, Q-630; the summary pace (task H1): A-57, docs/questions/Q-961
//! item 5, Q-989 (A-165). Every value is made up here.
// The fake auditd, the test gate and the link's runner — shared with the
// other crates whose tests need an acknowledged intent (task R15b).
mod linked;

use ipc_audit::{EventBody, EventSource, WindowSummary};
use ipc_audit_client::{AuditLinkError, ExpectedAuditd, IntentRecord, HEARTBEAT};
use linked::{
    acknowledged, block_on, eventually, link, not_acknowledged, FakeAuditd, LinkRun, TempDir,
    TestGate,
};
use std::sync::Arc;
use std::time::Instant;

/// Attack (docs/questions/Q-512 item 2): an auditd whose map gives this
/// process's uid another source — for each source a sender can expect, the
/// cross-wired auditd reports some other one — is refused at the first
/// `Pong`: one `Ping` and nothing else reaches it, no batch.
#[test]
fn a_cross_wired_auditd_receives_no_batch() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    for expected in EventSource::ALL {
        for reported in EventSource::ALL.into_iter().filter(|s| *s != expected) {
            let path = dir.join("a.sock");
            let auditd = FakeAuditd::start(&path, reported);
            let gate = TestGate::new();
            gate.commit_pending();
            let got = LinkRun::start(link(&path, uid, expected), Arc::clone(&gate));
            assert_eq!(got.err(), Some(AuditLinkError::SourceMismatch));
            assert_eq!(auditd.pings(), 1, "{expected:?} / {reported:?}");
            assert_eq!(auditd.appends(), 0, "no batch: {expected:?} / {reported:?}");
            assert!(!gate.core.is_reachable(), "the gate never saw auditd");
            assert!(gate.core.reserve().is_none(), "gating refused");
        }
    }
}

/// Attack (docs/50 R50-3): a peer of another uid than auditd's receives no
/// request at all — not even the `Ping`.
#[test]
fn a_peer_of_another_uid_receives_nothing() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    let path = dir.join("a.sock");
    let auditd = FakeAuditd::start(&path, EventSource::Keyd);
    let other = uid.wrapping_add(1).max(1);
    let got = block_on(link(&path, other, EventSource::Keyd).connect());
    assert_eq!(got.err(), Some(AuditLinkError::PeerMismatch));
    assert!(eventually(|| auditd.connections() == 1));
    assert_eq!(auditd.pings(), 0);
    assert_eq!(auditd.appends(), 0);
}

/// docs/50 §3.2 ("uid 0 is never mapped"); docs/questions/Q-510 item 1 (the
/// pattern): no expectation names auditd as uid 0.
#[test]
fn auditd_as_root_is_never_expected() {
    for source in EventSource::ALL {
        assert_eq!(
            ExpectedAuditd::new(0, source),
            Err(AuditLinkError::RootServerUid)
        );
    }
    let expected = ExpectedAuditd::new(7, EventSource::Dird).unwrap();
    assert_eq!((expected.uid(), expected.source()), (7, EventSource::Dird));
}

/// Positive (docs/50 §8.1): the expected auditd is verified, then every
/// committed event is delivered and acknowledged; the one-shot `verify`
/// (ldap-front's start-up check) passes too.
#[test]
fn the_expected_auditd_is_served() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    let path = dir.join("a.sock");
    let auditd = FakeAuditd::start(&path, EventSource::Kdc);
    assert_eq!(
        block_on(link(&path, uid, EventSource::Kdc).verify()),
        Ok(())
    );
    let gate = TestGate::new();
    let run = LinkRun::start(link(&path, uid, EventSource::Kdc), Arc::clone(&gate)).unwrap();
    assert!(
        gate.core.is_reachable(),
        "attached: the gate is open at once"
    );
    gate.commit_pending();
    gate.commit_pending();
    assert!(eventually(|| gate.core.outstanding() == 0), "acknowledged");
    assert!(auditd.appends() >= 1);
    drop(run);
}

/// Attack on the reconnection path (docs/questions/Q-512, Q-560; A-57,
/// A-67 item 2): after the verified auditd goes away, a cross-wired one at
/// the same path receives `Ping`s and never a batch; the gate counts auditd
/// as unreachable all along (gating refused) and the pending event stays in
/// the window — until an auditd that reports the right source is back, which
/// then receives it.
#[test]
fn reconnecting_to_a_cross_wired_auditd_sends_nothing() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    let path = dir.join("a.sock");
    let mut first = FakeAuditd::start(&path, EventSource::Admind);
    let gate = TestGate::new();
    let run = LinkRun::start(link(&path, uid, EventSource::Admind), Arc::clone(&gate)).unwrap();
    gate.commit_pending();
    assert!(eventually(|| gate.core.outstanding() == 0));
    assert!(first.appends() >= 1);

    first.stop();
    assert!(eventually(|| !gate.core.is_reachable()), "the loss is seen");
    let cross_wired = FakeAuditd::start(&path, EventSource::Dird);
    gate.commit_pending();
    assert!(
        eventually(|| cross_wired.pings() >= 2),
        "the link keeps trying, verifying each new connection"
    );
    assert_eq!(
        cross_wired.appends(),
        0,
        "no batch to the cross-wired auditd"
    );
    assert!(!gate.core.is_reachable());
    assert!(gate.core.reserve().is_none(), "gating refused meanwhile");
    assert_eq!(gate.core.outstanding(), 1, "the event waits");
    drop(cross_wired);

    let back = FakeAuditd::start(&path, EventSource::Admind);
    assert!(eventually(|| gate.core.outstanding() == 0), "delivered");
    assert!(back.appends() >= 1);
    assert!(gate.core.is_reachable());
    drop(run);
}

/// Task R15b (docs/questions/Q-630): the gate's reachability is the
/// client's alone — a new gate is closed (no slot); attaching the verified
/// start-up connection opens it at once (before the delivery task runs: a
/// daemon serves right after its start); dropping the attached link — the
/// daemon's stop aborting the task, or a start that failed before spawning
/// it — closes it again (A-57: no link, no reachability).
#[test]
fn attaching_a_verified_connection_opens_the_gate_and_its_end_closes_it() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    let path = dir.join("a.sock");
    let _auditd = FakeAuditd::start(&path, EventSource::Keyd);
    let gate = TestGate::new();
    assert!(!gate.core.is_reachable());
    assert!(gate.core.reserve().is_none(), "closed until attached");
    block_on(async {
        let link = link(&path, uid, EventSource::Keyd);
        let first = link.connect().await.unwrap();
        let attached = link.attach(Arc::clone(&gate), first);
        assert!(gate.core.is_reachable(), "open on the verified connection");
        let slot = gate.core.reserve().expect("a gating slot");
        gate.core.release(slot);
        drop(attached);
        assert!(!gate.core.is_reachable(), "the link ended: closed");
        assert!(gate.core.reserve().is_none());
    });
    // A delivery task aborted at stop closes the gate too.
    let run = LinkRun::start(link(&path, uid, EventSource::Keyd), Arc::clone(&gate)).unwrap();
    assert!(gate.core.is_reachable());
    drop(run);
    assert!(
        !gate.core.is_reachable(),
        "the aborted link closed the gate"
    );
}

/// Task R15b: a connection verified against another expectation (another
/// source) does not open a gate when attached to a link that expects
/// something else — the link verifies its own auditd again (here a
/// cross-wired one: never), and nothing is sent.
#[test]
fn a_connection_verified_for_another_expectation_opens_nothing() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    let path = dir.join("a.sock");
    let auditd = FakeAuditd::start(&path, EventSource::Kdc);
    let gate = TestGate::new();
    gate.commit_pending();
    block_on(async {
        let as_kdc = link(&path, uid, EventSource::Kdc).connect().await.unwrap();
        let attached = link(&path, uid, EventSource::Dird).attach(Arc::clone(&gate), as_kdc);
        assert!(!gate.core.is_reachable(), "not this link's verified auditd");
        let task = tokio::spawn(attached.run());
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!gate.core.is_reachable());
        task.abort();
        let _ = task.await;
    });
    assert_eq!(
        auditd.appends(),
        0,
        "no batch to an auditd it did not verify"
    );
    assert_eq!(gate.core.outstanding(), 1, "the event waits");
}

/// A value whose intent record is a summary carrying `n` (any event built
/// from this crate's types serves).
#[derive(Debug, PartialEq, Eq)]
struct Change(u64);

impl IntentRecord for Change {
    fn intent_event(&self) -> EventBody {
        EventBody::WindowSummary(WindowSummary {
            suppressed_noise: self.0,
            refused_gating: 0,
            unrecorded_outcomes: 0,
        })
    }
}

/// Task R15b / docs/52 §3.11 R6 (a): code outside ipc-audit-client obtains an
/// `AckedIntent` only through the client — the intent record delivered to
/// an auditd that acknowledges it ⇒ the proof, for the same value; the
/// record delivered to an auditd that never acknowledges ⇒ the value back,
/// no proof. (That nothing outside the crate can mark auditd reachable or
/// acknowledge is shown by the `compile_fail` examples on `AuditGate`.)
#[test]
fn a_proof_comes_only_from_an_ack_delivered_through_the_client() {
    if TempDir::new().uid().is_none() {
        return;
    }
    let acked = acknowledged(Change(5));
    assert_eq!(acked.into_inner(), Change(5));
    assert_eq!(not_acknowledged(Change(6)), Change(6));
}

/// docs/questions/Q-989 (A-165; class "a counter-only report is paced by the
/// transport's acknowledgements instead of by its own clock"), Q-961 item 5
/// ("at most one summary per heartbeat"); A-57 (noise "summarised in counters
/// and rate-limited"); docs/50 §8.1: noise counted continuously — one at a
/// time and in bulk, in a tight loop for 3.5 heartbeats, so that every round
/// trip to auditd finds new counts — into the gate of a counters-only sender
/// (no event, no wake-up: dnsd's and kpasswd-front's arrangement),
/// delivered by the real client to an auditd that acknowledges **at once**,
/// reaches auditd only as `WindowSummary` events, each alone in its batch,
/// at most one per heartbeat and about a heartbeat apart, whose counts add
/// up to exactly what was counted. (Positive control, run for task H1: with
/// the pace bypassed the client summarised after every acknowledgement —
/// thousands of summaries here.)
#[test]
fn continuous_noise_is_summarised_at_most_once_per_heartbeat() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    let path = dir.join("a.sock");
    let auditd = FakeAuditd::start(&path, EventSource::Dnsd);
    let gate = TestGate::new();
    let started = Instant::now();
    let run = LinkRun::start(link(&path, uid, EventSource::Dnsd), Arc::clone(&gate)).unwrap();
    let flood = HEARTBEAT * 7 / 2;
    let mut counted = 0u64;
    while started.elapsed() < flood {
        for _ in 0..64 {
            gate.core.count_noise();
        }
        gate.core.count_noise_n(3);
        counted += 64 + 3;
        std::thread::yield_now();
    }
    assert!(
        eventually(|| auditd.counted_noise() == counted),
        "{} of {counted} counted",
        auditd.counted_noise()
    );
    let elapsed = started.elapsed();
    let events = auditd.events();
    assert!(
        events
            .iter()
            .all(|(_, event)| matches!(event, EventBody::WindowSummary(_))),
        "{events:?}"
    );
    let summaries = auditd.summaries();
    let heartbeats = elapsed.as_millis() / HEARTBEAT.as_millis() + 1;
    assert!(
        summaries.len() as u128 <= heartbeats,
        "{} summaries in {heartbeats} heartbeats for {counted} counts",
        summaries.len()
    );
    assert!(summaries.len() >= 2, "continuous noise is summarised again");
    assert_eq!(auditd.appends(), summaries.len(), "each summary alone");
    for pair in summaries.windows(2) {
        let gap = pair[1].0.duration_since(pair[0].0);
        assert!(gap >= HEARTBEAT / 2, "two summaries {gap:?} apart");
    }
    for (_, summary) in &summaries {
        assert_eq!(
            (summary.refused_gating, summary.unrecorded_outcomes),
            (0, 0)
        );
    }
    drop(run);
}

/// A value whose intent record is marked by `n` in a field the counted
/// noise never fills (so the noise in auditd's summaries adds up apart).
#[derive(Debug, PartialEq, Eq)]
struct Marked(u64);

impl IntentRecord for Marked {
    fn intent_event(&self) -> EventBody {
        EventBody::WindowSummary(WindowSummary {
            suppressed_noise: 0,
            refused_gating: 0,
            unrecorded_outcomes: 1_000 + self.0,
        })
    }
}

/// docs/52 §3.11 R6 (an intent acknowledged before the change — not
/// delayed); docs/questions/Q-989 item 3 ("gating events are untouched: they
/// never wait"): while the summary pace holds counted noise (a summary was
/// just sent, more noise counted since), an intent committed into the gate
/// and signalled to the client is sent and acknowledged at once — well
/// within a quarter heartbeat, every time — and the held noise still adds up
/// exactly at auditd.
#[test]
fn an_intent_is_acknowledged_at_once_while_the_pace_holds_noise() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    let path = dir.join("a.sock");
    let auditd = FakeAuditd::start(&path, EventSource::Dird);
    let gate = TestGate::new();
    let run = LinkRun::start(link(&path, uid, EventSource::Dird), Arc::clone(&gate)).unwrap();
    gate.core.count_noise();
    assert!(
        eventually(|| auditd.counted_noise() == 1),
        "the first summary"
    );
    for n in 0..5 {
        gate.core.count_noise_n(10);
        let slot = gate.core.reserve().expect("the gate is open");
        let pending = gate
            .core
            .begin_intent(slot, Marked(n))
            .expect("the intent commits");
        gate.wake.notify_one();
        let sent = Instant::now();
        let acked = gate.core.wait_acknowledged(pending, sent + HEARTBEAT / 4);
        let took = sent.elapsed();
        assert_eq!(
            acked.map(|proof| proof.into_inner()).ok(),
            Some(Marked(n)),
            "intent {n} not acknowledged within a quarter heartbeat ({took:?})"
        );
        std::thread::sleep(HEARTBEAT / 5);
    }
    assert!(
        eventually(|| auditd.counted_noise() == 51),
        "{} of 51 counted",
        auditd.counted_noise()
    );
    let intents: Vec<u64> = auditd
        .summaries()
        .iter()
        .filter(|(_, summary)| summary.unrecorded_outcomes >= 1_000)
        .map(|(_, summary)| summary.unrecorded_outcomes - 1_000)
        .collect();
    assert_eq!(intents, [0, 1, 2, 3, 4], "every intent, once, in order");
    drop(run);
}
