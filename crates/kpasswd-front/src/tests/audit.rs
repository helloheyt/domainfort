//! The front's noise counts on the audit channel (docs/questions/Q-961
//! item 7, accepted under A-160; Q-988):
//!
//! * against the **real** auditd (crates/audit-daemon's listener and writer,
//!   reused through `#[path]`): every noise occurrence at the front's layer
//!   reaches the audit log as `WindowSummary` counts recorded under the
//!   source `kpasswd-front`, the counts add up to the counted noise, and a
//!   forwarded request or dird not serving adds nothing;
//! * a sustained flood of noise — against an auditd that acknowledges fast,
//!   and one that takes time to (its persistence, docs/50 §8.1) — is
//!   summarised at most once per heartbeat, never one record per connection
//!   and never one summary per acknowledgement (the shared gate's summary
//!   pace, docs/questions/Q-989);
//! * requests are not gated on auditd: lost while the front serves, the
//!   front still serves, and the noise is still counted.
//!
//! Sources: docs/53 §9 ("kpasswd-front: connection closed (source outside
//! `internal_networks`, malformed framing, version) — with the A-57 noise
//! rule (a count, not a record per datagram)"); docs/50 R50-16, §3.2 ("the
//! source is set from the uid"), §8.1 (`WindowSummary` = `suppressed_noise ‖
//! refused_gating ‖ unrecorded_outcomes`; a mapped source may send
//! `WindowSummary` only); A-57 (noise "summarised in counters and
//! rate-limited"); docs/questions/Q-960, Q-961 items 3, 5, 6, 7 (A-160),
//! Q-988, Q-989 (A-165); RFC 3244 §2 (the requests, built by hand as in crate::tests::
//! world). Uids, paths and octets are hand-made test values; no fixture
//! comes from any other implementation.

#![cfg(unix)]

use super::startup::real_auditd;
use super::world::*;
use crate::audit::FRONT_AUDIT_SOURCE;
use audit_log::{Anchor, Record, SegmentLimit, SegmentReader, Source};
use core::time::Duration;
use ipc_audit::{EventBody, WindowSummary};
use ipc_audit_client::HEARTBEAT;
use ipc_kpasswd::HostUnserved;
use parse_kpasswd::ReplyMessage;
use std::io::Write;
use std::time::Instant;

fn good_request() -> Vec<u8> {
    request_frame(&octets(AP_REQ, 48, 0x11), &octets(KRB_PRIV, 30, 0x22))
}

/// A TCP header announcing fewer octets than RFC 3244 §2's 6-octet message
/// header: answered MALFORMED at once (docs/53 §5.1).
const SHORT_HEADER: [u8; 4] = [0, 0, 0, 5];

/// The records of the first segment of the log at `base` that verify so far
/// (the writer may be appending: a torn last record ends the read).
fn records_so_far(base: &std::path::Path) -> Vec<Record> {
    let Ok(bytes) = std::fs::read(audit_daemon::segments::segment_path(base, 1)) else {
        return Vec::new();
    };
    let Ok(mut reader) =
        SegmentReader::open(&bytes[..], Anchor::Genesis, SegmentLimit::DEFAULT, None)
    else {
        return Vec::new();
    };
    let mut records = Vec::new();
    while let Ok(Some(record)) = reader.next_record() {
        records.push(record);
    }
    records
}

/// The events among `records` from a peer of uid `uid` — every one must be
/// a `WindowSummary` — with each record's source. (In this harness auditd's
/// own records carry the test's uid too, under the source `Auditd`.)
fn summaries_of(records: &[Record], uid: u32) -> Vec<(Source, WindowSummary)> {
    records
        .iter()
        .filter(|record| record.source_uid == uid && record.source != Source::Auditd)
        .map(|record| match ipc_audit::decode_event(&record.payload) {
            Ok(EventBody::WindowSummary(summary)) => (record.source, summary),
            other => panic!("the front recorded something else than a summary: {other:?}"),
        })
        .collect()
}

/// docs/53 §9; docs/50 §3.2, §8.1; A-57; docs/questions/Q-961 item 7,
/// Q-988: with the real auditd mapping the front's uid to `kpasswd-front`,
/// the front's noise — two requests answered MALFORMED, two of other
/// versions answered BAD_VERSION, one incomplete request closed on its
/// timeout — reaches the log as `WindowSummary` counts recorded under the
/// source `kpasswd-front` that add up to exactly the five counted; a request
/// relayed to dird and one dird did not serve (the front's dependency
/// failing — not noise) add nothing.
#[test]
fn noise_reaches_the_audit_log_as_summaries_under_kpasswd_front() {
    let Some(uid) = own_uid() else {
        return;
    };
    let (logs, server) = real_auditd(uid, "kpasswd-front");
    let audit_socket = server.socket.clone();
    let Some(w) = world(move |p| p.audit.socket = audit_socket) else {
        return;
    };

    // Not noise.
    assert!(ReplyMessage::parse_tcp(&exchange(w.front, &good_request())).is_ok());
    *w.dird.answer.lock().unwrap() = Err(HostUnserved::Unavailable);
    assert_eq!(result_code_of(&exchange(w.front, &good_request())), 2);

    // Noise.
    assert_eq!(result_code_of(&exchange(w.front, &SHORT_HEADER)), 1);
    let mut broken_length = good_request();
    broken_length[5] ^= 0x01;
    assert_eq!(result_code_of(&exchange(w.front, &broken_length)), 1);
    let (ap_req, krb_priv) = (octets(AP_REQ, 48, 0x11), octets(KRB_PRIV, 30, 0x22));
    for version in [0x0001u16, 0xff81] {
        let request = request_with_version(version, &ap_req, &krb_priv);
        assert_eq!(result_code_of(&exchange(w.front, &request)), 6);
    }
    let mut incomplete = std::net::TcpStream::connect(w.front).unwrap();
    incomplete.write_all(&good_request()[..2]).unwrap();
    assert!(closed_without_a_byte(&mut incomplete));
    assert!(eventually(LONG, || w.control.counts().timed_out == 1));

    let counts = w.control.counts();
    assert_eq!(counts.noise(), 5);
    assert_eq!((counts.malformed, counts.bad_version), (2, 2));
    assert_eq!(counts.dird_not_serving, 1);
    let base = logs.base();
    let logged = || {
        summaries_of(&records_so_far(&base), uid)
            .iter()
            .map(|(_, summary)| summary.suppressed_noise)
            .sum::<u64>()
    };
    assert!(
        eventually(Duration::from_secs(20), || logged() >= 5),
        "the counts reach the log"
    );
    drop(w);
    assert_eq!(server.stop(), Some(Ok(())));

    let summaries = summaries_of(&records_so_far(&logs.base()), uid);
    assert!(!summaries.is_empty());
    for (source, summary) in &summaries {
        assert_eq!(
            *source,
            Source::KpasswdFront,
            "recorded under kpasswd-front"
        );
        assert_eq!(summary.refused_gating, 0, "the front reserves no slot");
        assert_eq!(summary.unrecorded_outcomes, 0);
    }
    assert_eq!(
        summaries
            .iter()
            .map(|(_, summary)| summary.suppressed_noise)
            .sum::<u64>(),
        5,
        "exactly the noise counted; the relayed request and dird's failure \
         left no record"
    );
}

/// A sustained flood of noise for 3.5 heartbeats — `flooders` clients at
/// once, each sending a request answered MALFORMED, then pausing `pause` —
/// against an auditd that acknowledges each batch after `ack_delay`: only
/// `WindowSummary` events reach auditd, at most one per heartbeat and about
/// a heartbeat apart, whose counts add up to every request sent.
fn flood_is_summarised_at_most_once_per_heartbeat(
    tag: &str,
    ack_delay: Duration,
    flooders: usize,
    pause: Duration,
) {
    let audit_path = socket_path(tag);
    let auditd = start_auditd_with(
        &audit_path,
        FRONT_AUDIT_SOURCE,
        AuditdBehaviour::Acknowledge(ack_delay),
    );
    let started = Instant::now();
    let socket = audit_path.clone();
    let Some(w) = world(move |p| p.audit.socket = socket) else {
        let _ = std::fs::remove_file(&audit_path);
        return;
    };
    let flood = HEARTBEAT * 7 / 2;
    let front = w.front;
    let sent: u64 = (0..flooders)
        .map(|_| {
            std::thread::spawn(move || {
                let mut sent = 0u64;
                while started.elapsed() < flood {
                    assert_eq!(result_code_of(&exchange(front, &SHORT_HEADER)), 1);
                    sent += 1;
                    std::thread::sleep(pause);
                }
                sent
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|flooder| flooder.join().unwrap())
        .sum();
    assert!(
        eventually(LONG, || auditd.counted_noise() == sent),
        "{} of {sent} counted",
        auditd.counted_noise()
    );
    let elapsed = started.elapsed();
    assert_eq!(w.control.counts().noise(), sent);
    let events = auditd.events();
    assert!(
        events
            .iter()
            .all(|event| matches!(event, EventBody::WindowSummary(_))),
        "{events:?}"
    );
    let summaries = auditd.summaries();
    let heartbeats = elapsed.as_millis() / HEARTBEAT.as_millis() + 1;
    assert!(
        summaries.len() as u128 <= heartbeats,
        "{} summaries in {heartbeats} heartbeats for {sent} requests",
        summaries.len()
    );
    assert!(
        summaries.len() >= 2,
        "a sustained flood is summarised again"
    );
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
    drop(w);
    let _ = std::fs::remove_file(&audit_path);
}

/// A-57 ("summarised in counters and rate-limited"); docs/53 §9 ("a count,
/// not a record per datagram"); docs/50 §8.1; docs/questions/Q-989 (A-165;
/// class "a counter-only report is paced by the transport's
/// acknowledgements instead of by its own clock"): an auditd that
/// acknowledges fast (1 ms) and noise denser than that round trip (two
/// clients at once) — the case where a summary after every acknowledgement
/// would be thousands of summaries (positive control, run for task H1 with
/// the pace bypassed) — the front's flood is still summarised at most once
/// per heartbeat, with no pace of the front's own (the shared gate's).
#[test]
fn a_flood_of_noise_is_summarised_at_most_once_per_heartbeat_with_a_fast_auditd() {
    flood_is_summarised_at_most_once_per_heartbeat(
        "audit-fast",
        Duration::from_millis(1),
        2,
        Duration::from_millis(1),
    );
}

/// A-57; docs/53 §9; docs/50 §8.1 (auditd acknowledges after it
/// persisted); docs/questions/Q-988, Q-989: the same with an auditd that
/// takes 20 ms to acknowledge each batch and one client sending a request
/// every few milliseconds.
#[test]
fn a_flood_of_noise_is_summarised_at_most_once_per_heartbeat_with_a_slow_auditd() {
    flood_is_summarised_at_most_once_per_heartbeat(
        "audit-slow",
        Duration::from_millis(20),
        1,
        Duration::from_millis(3),
    );
}

/// docs/53 §9 (no gating event for the front); docs/questions/Q-961 item 6
/// (A-160: "auditd lost at run time ⇒ queries unaffected, counts kept"),
/// Q-988: auditd verified at start and then lost — it closes the verified
/// connection and refuses every new one — does not stop the front: a
/// request is still relayed, a malformed one still answered MALFORMED and
/// counted as noise, and nothing reached auditd.
#[test]
fn requests_are_not_gated_on_auditd() {
    let audit_path = socket_path("audit-lost");
    let auditd = start_auditd_with(
        &audit_path,
        FRONT_AUDIT_SOURCE,
        AuditdBehaviour::LostAfterStart,
    );
    let socket = audit_path.clone();
    let Some(w) = world(move |p| p.audit.socket = socket) else {
        let _ = std::fs::remove_file(&audit_path);
        return;
    };
    // The link notices the loss at its next look (one heartbeat at most).
    std::thread::sleep(HEARTBEAT + HEARTBEAT / 2);
    assert!(ReplyMessage::parse_tcp(&exchange(w.front, &good_request())).is_ok());
    assert_eq!(result_code_of(&exchange(w.front, &SHORT_HEADER)), 1);
    assert_eq!(w.control.counts().noise(), 1);
    assert_eq!(w.dird.requests.lock().unwrap().len(), 1);
    std::thread::sleep(HEARTBEAT + HEARTBEAT / 2);
    assert!(auditd.events().is_empty());
    drop(w);
    let _ = std::fs::remove_file(&audit_path);
}
