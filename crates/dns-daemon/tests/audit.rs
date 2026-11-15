//! dnsd's audit source and its noise counters (task DN12).
//!
//! * The product start against the **real** auditd (crates/audit-daemon's
//!   listener and writer, reused through `#[path]` as crates/ldap-front's
//!   tests do): an auditd whose `uid_sources` maps dnsd's uid to `dnsd`
//!   passes dnsd's audit check, and the start goes on to the next real
//!   dependency — dird; an auditd that maps the uid to another source, or
//!   does not map it, stops the start at the audit check (fail closed).
//! * The noise counters: every peer-driven noise occurrence reaches the
//!   audit log as `WindowSummary` counts, recorded under the source `dnsd`;
//!   answered queries leave no record; continuous noise is summarised at
//!   most once per heartbeat even against an auditd that acknowledges at
//!   once (the shared gate's summary pace — docs/questions/Q-989).
//!
//! Sources: docs/54 §4.8 ("auditd verified (the one audit client, source
//! `dnsd` — R9b)"), §9 ("dnsd — a new source (`dnsd`, source code 7): only
//! counters (`WindowSummary` — noise: dropped / limited / malformed /
//! refused) … no record per query"), R54-11; docs/50 R50-16, §3.2 ("the
//! source is set from the uid"), §7.5 (fail closed), §8.1; A-57;
//! docs/questions/Q-619 items 2, 3, Q-950 (A-157), Q-960, Q-961, Q-989
//! (A-165). Values: the
//! RFC 2782 "Fictional example" zone (crate tests/common), hand-made uids,
//! octets and paths. No fixture comes from any other implementation.

mod common;

#[path = "../../audit-daemon/tests/common/mod.rs"]
mod auditd_support;

use audit_daemon::listener::ListenerConfig;
use audit_log::{Anchor, Record, SegmentLimit, SegmentReader, Source};
use common::{eventually, parts, query, transfer, udp_client, udp_exchange, World, SERIAL};
use core::time::Duration;
use dns_daemon::{DaemonControl, DaemonError, DaemonParams, DirdEndpoint, Listeners, TcpLimits};
use ipc_audit::{EventBody, WindowSummary};
use ipc_audit_client::{AuditEndpoint, AuditLinkError, HEARTBEAT};
use ipc_dns::{TransportError, Unserved};
use parse_dns::RrType;
use rate_limit::SourceLimits;
use std::time::Instant;

/// Datagrams dns-zone answers with silence: not DNS messages (shorter than
/// the 12-octet header of RFC 1035 §4.1.1). Hand-made octets.
const NOT_A_MESSAGE: [u8; 3] = [0x01, 0x02, 0x03];

/// The real auditd, its log in a scratch directory, mapping `mapped_uid` to
/// the source named `source` (docs/50 §3.2, §7.1).
fn real_auditd(mapped_uid: u32, source: &str) -> (auditd_support::TempDir, auditd_support::Server) {
    let logs = auditd_support::TempDir::new();
    let settings = auditd_support::settings_for(&logs, mapped_uid, source, 5);
    let server = auditd_support::Server::start(
        &settings,
        ListenerConfig::from_settings(&settings),
        64,
        true,
    );
    (logs, server)
}

/// The test's uid, or `None` (skipped) as root — uid 0 is never mapped
/// (docs/50 R50-3).
fn test_uid() -> Option<u32> {
    let uid = auditd_support::own_uid();
    if uid == 0 {
        eprintln!("skipped: running as root (docs/50 R50-3: uid 0 is never mapped)");
        None
    } else {
        Some(uid)
    }
}

/// The product parameters of a dnsd whose auditd is `audit` (uid `uid`) and
/// whose dird socket does not exist (docs/54 §4.3; crates/config
/// `DnsdSettings` — test values).
fn product_params(
    audit: &auditd_support::Server,
    uid: u32,
    dird: &std::path::Path,
) -> DaemonParams {
    DaemonParams {
        dird: DirdEndpoint {
            socket: dird.to_path_buf(),
            uid: common::DIRD_UID,
        },
        audit: AuditEndpoint {
            socket: audit.socket.clone(),
            uid,
        },
        internal_networks: vec![common::loopback_network()],
        tcp: TcpLimits {
            max_connections: 8,
            max_per_source: 4,
            first_octet_timeout: Duration::from_secs(2),
            frame_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(5),
            max_requests: 8,
        },
        zone_image_max_age: Duration::from_secs(60),
    }
}

/// Run the **product** `dns_daemon::serve` (the product constants, the
/// product audit source, the product Unix connector to dird) to its end.
fn product_start(params: DaemonParams) -> Result<(), DaemonError> {
    let listeners = Listeners {
        udp: vec![std::net::UdpSocket::bind("127.0.0.1:0").expect("udp")],
        tcp: vec![std::net::TcpListener::bind("127.0.0.1:0").expect("tcp")],
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let control = DaemonControl::new();
    let result = runtime.block_on(dns_daemon::serve(params, listeners, control.clone()));
    assert!(!control.is_serving(), "nothing was served");
    result.map(drop)
}

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

/// The events among `records` from a peer of uid `uid` — every one must be a
/// `WindowSummary` — with each record's source. (In this harness auditd's
/// own records carry the test's uid too, under the source `Auditd`.)
fn summaries_of(records: &[Record], uid: u32) -> Vec<(Source, WindowSummary)> {
    records
        .iter()
        .filter(|record| record.source_uid == uid && record.source != Source::Auditd)
        .map(|record| match ipc_audit::decode_event(&record.payload) {
            Ok(EventBody::WindowSummary(summary)) => (record.source, summary),
            other => panic!("dnsd recorded something else than a summary: {other:?}"),
        })
        .collect()
}

/// docs/54 §4.8, §9; docs/50 R50-16, §3.2: the product dnsd, against a real
/// auditd that maps its uid to `dnsd`, passes the audit check — and goes on
/// to the next real dependency, dird, which is absent here: the start ends
/// there (docs/54 §4.8: "dird down at start ⇒ dnsd does not come up"), not
/// at the audit check.
#[test]
fn the_product_start_passes_an_auditd_that_maps_dnsd() {
    let Some(uid) = test_uid() else { return };
    let (logs, server) = real_auditd(uid, "dnsd");
    let dird = logs.path().join("absent-dird.sock");
    assert_eq!(
        product_start(product_params(&server, uid, &dird)),
        Err(DaemonError::Dird(Unserved::Transport(
            TransportError::Connect
        )))
    );
    assert_eq!(server.stop(), Some(Ok(())));
    // dnsd sent no batch: nothing of it was recorded.
    assert!(records_so_far(&logs.base())
        .iter()
        .all(|record| record.source_uid != uid || record.source == Source::Auditd));
}

/// docs/50 R50-16, §3.2, §7.5; docs/52 §3.12 (C12); docs/questions/Q-950:
/// an auditd whose `uid_sources` maps dnsd's uid to another source names
/// that source in its `Pong` — dnsd does not start, dird is never reached;
/// an auditd that does not map the uid at all closes the connection without
/// a reply — dnsd does not start either.
#[test]
fn the_product_start_fails_closed_without_the_dnsd_mapping() {
    let Some(uid) = test_uid() else { return };
    for other in ["kdc", "ldap-front", "kpasswd-front"] {
        let (logs, server) = real_auditd(uid, other);
        let dird = logs.path().join("absent-dird.sock");
        assert_eq!(
            product_start(product_params(&server, uid, &dird)),
            Err(DaemonError::Audit(AuditLinkError::SourceMismatch)),
            "{other}"
        );
        drop(server);
    }
    let unmapped = auditd_support::other_uid(&[uid]);
    let (logs, server) = real_auditd(unmapped, "dnsd");
    let dird = logs.path().join("absent-dird.sock");
    let result = product_start(product_params(&server, uid, &dird));
    assert!(
        matches!(
            result,
            Err(DaemonError::Audit(
                AuditLinkError::Closed | AuditLinkError::Io
            ))
        ),
        "{result:?}"
    );
}

/// docs/54 §9 ("only counters (`WindowSummary` — noise …)", "no record per
/// query"), R54-11; A-57: with the real auditd mapping the uid to `dnsd`,
/// datagrams dns-zone silences reach the log as `WindowSummary` counts
/// recorded under the source `dnsd` — the counts add up to the datagrams
/// sent — and an answered query adds no record.
#[test]
fn noise_reaches_the_audit_log_as_summaries_under_dnsd() {
    let Some(world) = World::new(transfer(&parts(SERIAL, &[]))) else {
        return;
    };
    let (logs, server) = real_auditd(world.uid, "dnsd");
    let mut params = world.params();
    params.audit.socket = server.socket.clone();
    let dnsd = world.start(params);
    assert!(dnsd.serving());

    let client = udp_client();
    let answered = udp_exchange(
        &client,
        dnsd.udp,
        &query(0x0D12, "server.example.com", RrType::A),
    );
    assert!(answered.is_some(), "a query is answered");
    for _ in 0..5 {
        client.send_to(&NOT_A_MESSAGE, dnsd.udp).expect("send");
    }
    let counted = || {
        summaries_of(&records_so_far(&logs.base()), world.uid)
            .iter()
            .map(|(_, summary)| summary.suppressed_noise)
            .sum::<u64>()
    };
    assert!(
        eventually(Duration::from_secs(20), || counted() >= 5),
        "the counts reach the log"
    );
    assert_eq!(dnsd.stop(), Ok(()));
    assert_eq!(server.stop(), Some(Ok(())));

    let summaries = summaries_of(&records_so_far(&logs.base()), world.uid);
    assert!(!summaries.is_empty());
    for (source, summary) in &summaries {
        assert_eq!(*source, Source::Dnsd, "recorded under dnsd");
        assert_eq!(summary.refused_gating, 0, "dnsd reserves no slot");
        assert_eq!(summary.unrecorded_outcomes, 0);
    }
    assert_eq!(
        summaries
            .iter()
            .map(|(_, s)| s.suppressed_noise)
            .sum::<u64>(),
        5,
        "exactly the noise sent; the answered query left no record"
    );
}

/// docs/54 §9; A-57 (summarised in counters and rate-limited): a flood of
/// noise yields a few summaries — at most one per audit heartbeat — never a
/// record per datagram; the fake auditd sees only `WindowSummary` events.
#[test]
fn a_flood_of_noise_is_summarised_not_recorded_per_datagram() {
    let Some(world) = World::new(transfer(&parts(SERIAL, &[]))) else {
        return;
    };
    let dnsd = world.start(world.params());
    assert!(dnsd.serving());
    let client = udp_client();
    for _ in 0..200 {
        client.send_to(&NOT_A_MESSAGE, dnsd.udp).expect("send");
    }
    // UDP on loopback may drop under load: the count is what dnsd received.
    assert!(
        eventually(Duration::from_secs(20), || world.auditd.counted_noise() > 0),
        "the counts reach auditd"
    );
    std::thread::sleep(Duration::from_millis(1500));
    let events = world.auditd.events();
    assert!(
        events
            .iter()
            .all(|event| matches!(event, EventBody::WindowSummary(_))),
        "{events:?}"
    );
    let noise = world.auditd.counted_noise();
    assert!(noise <= 200);
    assert!(
        (events.len() as u64) < noise.max(2),
        "{} summaries for {noise} datagrams",
        events.len()
    );
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §9 ("only counters", "no record per query"); A-57 ("summarised in
/// counters and rate-limited"); docs/50 §8.1; docs/questions/Q-961 item 5
/// ("at most one summary per heartbeat"), Q-989 (A-165; class "a
/// counter-only report is paced by the transport's acknowledgements instead
/// of by its own clock"): continuous noise — datagrams dns-zone silences,
/// sent back to back for 3.5 heartbeats, every sixteen followed by a query
/// that is answered (one client socket, nothing queued behind them: the
/// sixteen were received; the UDP limits widened so that none is limited)
/// — against the test auditd, which acknowledges **at once**, reaches
/// auditd only as `WindowSummary` events, at most one per heartbeat and
/// about a heartbeat apart, whose counts add up to exactly the datagrams
/// sent; the answered queries add nothing. (Positive control, run for task
/// H1: with the pace bypassed the link summarised after every
/// acknowledgement that found new counts.)
#[test]
fn continuous_noise_is_summarised_at_most_once_per_heartbeat() {
    let Some(world) = World::new(transfer(&parts(SERIAL, &[]))) else {
        return;
    };
    let mut params = world.params();
    params.udp = SourceLimits {
        per_source: 10_000_000,
        global: 10_000_000,
        window: Duration::from_secs(1),
    };
    let started = Instant::now();
    let dnsd = world.start(params);
    assert!(dnsd.serving());
    let client = udp_client();
    let flood = HEARTBEAT * 7 / 2;
    let mut sent = 0u64;
    let mut id = 0u16;
    while started.elapsed() < flood {
        for _ in 0..16 {
            client.send_to(&NOT_A_MESSAGE, dnsd.udp).expect("send");
            sent += 1;
        }
        id = id.wrapping_add(1);
        let answered = udp_exchange(
            &client,
            dnsd.udp,
            &query(id, "server.example.com", RrType::A),
        );
        assert!(answered.is_some(), "the query after the noise is answered");
    }
    assert!(
        eventually(Duration::from_secs(20), || world.auditd.counted_noise()
            == sent),
        "{} of {sent} counted",
        world.auditd.counted_noise()
    );
    let elapsed = started.elapsed();
    let events = world.auditd.events();
    assert!(
        events
            .iter()
            .all(|event| matches!(event, EventBody::WindowSummary(_))),
        "{events:?}"
    );
    let summaries = world.auditd.summaries_with_arrival();
    let heartbeats = elapsed.as_millis() / HEARTBEAT.as_millis() + 1;
    assert!(
        summaries.len() as u128 <= heartbeats,
        "{} summaries in {heartbeats} heartbeats for {sent} datagrams",
        summaries.len()
    );
    assert!(summaries.len() >= 2, "continuous noise is summarised again");
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
    assert_eq!(dnsd.stop(), Ok(()));
}
