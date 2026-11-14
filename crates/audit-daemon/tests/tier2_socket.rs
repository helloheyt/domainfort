//! Tier 2 (docs/50 §9): the listener and the writer over real Unix sockets
//! in a temp directory. The uid map is configuration text naming this test
//! process's own uid (from tokio `peer_cred` on a socket pair) — the real
//! peer-credential path, no injected identity. If the tests run as uid 0,
//! which the map can never name (R50-3), the mapped cases are skipped.
//!
//! Each test names its source. Payloads are arbitrary test octets.

mod common;

use audit_daemon::listener::{self, BindError, ListenerConfig, MAX_CONNECTIONS_PER_SOURCE};
use audit_log::{Anchor, Source};
use common::*;
use ipc::{Refused, Reply};
use ipc_audit::{Ack, Append, AuditReply, AuditRequest, EventBody};
use std::io::Write;
use std::time::{Duration, Instant};

/// This process's uid, unless it is 0 (never mappable — docs/50 R50-3).
fn mappable_uid() -> Option<u32> {
    let uid = own_uid();
    if uid == 0 {
        eprintln!("skipped: running as uid 0, which the uid map never names (R50-3)");
        None
    } else {
        Some(uid)
    }
}

fn config(settings: &config::AuditdSettings) -> ListenerConfig {
    ListenerConfig::from_settings(settings)
}

fn append(first: u64, count: usize, tag: u8) -> AuditRequest {
    AuditRequest::Append(Append::new(first, events(count, 64, tag)).expect("append"))
}

fn expect_ack(got: Got) -> Ack {
    match got {
        Got::Reply(Reply::Message(AuditReply::Ack(ack))) => ack,
        other => panic!("expected an Ack, got {other:?}"),
    }
}

/// Source: docs/50 R50-17, §3.2 (source from the connection's uid), §8.1
/// (`Ack` after persistence: through_seq and the chain hash).
#[test]
fn mapped_source_appends_and_gets_ack() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings(&dir, uid, 5);
    let server = Server::start(&settings, config(&settings), 8, true);

    let mut client = connect(&server.socket);
    send(&mut client, &append(1, 3, 1));
    let ack = expect_ack(receive(&mut client));
    assert_eq!(ack.through_seq, 3);
    send(&mut client, &append(4, 2, 2));
    let ack = expect_ack(receive(&mut client));
    assert_eq!(ack.through_seq, 5);
    drop(client);
    assert_eq!(server.stop(), Some(Ok(())));

    let (records, head) = read_segment(&dir.base(), 1, Anchor::Genesis);
    assert_eq!(records.len(), 5);
    assert_eq!(head.hash.as_bytes(), &ack.head_hash);
    for (i, record) in records.iter().enumerate() {
        assert_eq!(record.source, Source::Kdc);
        assert_eq!(record.source_uid, uid);
        assert_eq!(record.source_seq, i as u64 + 1);
    }
    assert_eq!(records[0].payload, events(3, 64, 1)[0].as_bytes());
}

/// Source: docs/50 R50-3, §3.2 ("an unmapped uid ⇒ the connection is closed
/// + an audit record"); Q-265 item 8 (the record is a summary).
#[test]
fn unmapped_uid_is_closed_without_reply_and_counted() {
    let uid = own_uid();
    let dir = TempDir::new();
    let settings = settings(&dir, other_uid(&[uid]), 5);
    let server = Server::start(&settings, config(&settings), 8, true);

    let mut client = connect(&server.socket);
    // The server may already have closed; a failed write is fine.
    let frame = ipc_audit::encode_request(&AuditRequest::Ping).unwrap();
    let _ = client.write_all(frame.as_bytes());
    assert_eq!(receive(&mut client), Got::Closed);

    // The summary record is written within the summary interval.
    std::thread::sleep(Duration::from_millis(1600));
    assert_eq!(server.stop(), Some(Ok(())));
    let (records, _) = read_segment(&dir.base(), 1, Anchor::Genesis);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].source, Source::Auditd);
    assert_eq!(records[0].payload, expected_refused(1, 0, uid));
}

/// Source: docs/50 §3.2 ("an unmapped uid ⇒ the connection is closed + an
/// audit record"); docs/questions/Q-341 residual (A-85), decision A-88,
/// Q-396 (a last summary at a clean stop). A connection refused just before
/// the server stops — no summary interval has passed — is still in the log:
/// the stop writes the pending count before the log closes. The next start
/// (the daemon's start-up verification, `open_log`) verifies the log and
/// resumes after that record.
#[test]
fn a_refusal_just_before_a_stop_is_written() {
    let uid = own_uid();
    let dir = TempDir::new();
    let settings = settings(&dir, other_uid(&[uid]), 5);
    let server = Server::start(&settings, config(&settings), 8, true);

    let mut client = connect(&server.socket);
    let frame = ipc_audit::encode_request(&AuditRequest::Ping).unwrap();
    let _ = client.write_all(frame.as_bytes());
    assert_eq!(receive(&mut client), Got::Closed);
    // No wait for the summary interval: stop at once.
    assert_eq!(server.stop(), Some(Ok(())));

    let (records, head) = read_segment(&dir.base(), 1, Anchor::Genesis);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].source, Source::Auditd);
    assert_eq!(records[0].payload, expected_refused(1, 0, uid));
    let reopened = audit_daemon::recovery::open_log(
        &dir.base(),
        audit_log::SegmentLimit::DEFAULT,
        settings.run_as().uid(),
    )
    .expect("the log verifies at the next start");
    assert_eq!(reopened.start, audit_daemon::recovery::StartKind::Resumed);
    assert_eq!(reopened.sink.head(), head);
}

/// Source: docs/questions/Q-252 item 7 (contiguous numbering per
/// connection; a new connection sets a new baseline), Q-265 item 3
/// (`Refused::Malformed` + close).
#[test]
fn non_contiguous_first_seq_is_refused() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings(&dir, uid, 5);
    let server = Server::start(&settings, config(&settings), 8, true);

    let mut client = connect(&server.socket);
    send(&mut client, &append(1, 3, 1));
    assert_eq!(expect_ack(receive(&mut client)).through_seq, 3);
    send(&mut client, &append(7, 1, 2));
    assert_eq!(
        receive(&mut client),
        Got::Reply(Reply::Refused(Refused::Malformed))
    );
    assert_eq!(receive(&mut client), Got::Closed);

    // A sender that reconnects resends from its own numbers.
    let mut again = connect(&server.socket);
    send(&mut again, &append(4, 1, 3));
    assert_eq!(expect_ack(receive(&mut again)).through_seq, 4);
    drop(again);
    assert_eq!(server.stop(), Some(Ok(())));
}

/// Source: docs/50 §7.5 ("op `Ping` on every channel"); Q-252 item 2.
#[test]
fn ping_gets_pong() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings(&dir, uid, 5);
    let server = Server::start(&settings, config(&settings), 8, true);
    let mut client = connect(&server.socket);
    send(&mut client, &AuditRequest::Ping);
    assert_eq!(
        receive(&mut client),
        Got::Reply(Reply::Message(AuditReply::Pong))
    );
    send(&mut client, &AuditRequest::Ping);
    assert_eq!(
        receive(&mut client),
        Got::Reply(Reply::Message(AuditReply::Pong))
    );
    drop(client);
    assert_eq!(server.stop(), Some(Ok(())));
}

/// Source: docs/questions/Q-218 (A-57: a full queue answers `Busy`, the
/// sender's window keeps issuance gated); docs/50 §3.6 (immediate `Busy`),
/// R50-7.
#[test]
fn full_queue_answers_busy() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings(&dir, uid, 5);
    // One slot, never drained: of three Appends exactly one is queued.
    let server = Server::start(&settings, config(&settings), 1, false);

    let mut clients: Vec<_> = (0..3).map(|_| connect(&server.socket)).collect();
    for (i, client) in clients.iter_mut().enumerate() {
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        send(client, &append(1, 1, i as u8));
    }
    let results: Vec<Got> = std::thread::scope(|scope| {
        let readers: Vec<_> = clients
            .iter_mut()
            .map(|client| scope.spawn(move || receive(client)))
            .collect();
        readers.into_iter().map(|r| r.join().unwrap()).collect()
    });
    let busy: Vec<usize> = results
        .iter()
        .enumerate()
        .filter(|(_, got)| **got == Got::Reply(Reply::Refused(Refused::Busy)))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(busy.len(), 2, "{results:?}");
    assert_eq!(results.iter().filter(|g| **g == Got::Nothing).count(), 1);

    // A connection answered Busy stays open.
    let open = &mut clients[busy[0]];
    send(open, &AuditRequest::Ping);
    assert_eq!(receive(open), Got::Reply(Reply::Message(AuditReply::Pong)));
    drop(clients);
    assert_eq!(server.stop(), None);
}

/// Source: docs/50 §3.6 ("a frame that has started must finish within the
/// timeout … otherwise close; an idle connection is allowed").
#[test]
fn started_frame_must_finish_before_the_deadline() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings(&dir, uid, 1);
    let server = Server::start(&settings, config(&settings), 8, true);

    // Idle for longer than the timeout: still served.
    let mut idle = connect(&server.socket);
    std::thread::sleep(Duration::from_millis(1500));
    send(&mut idle, &AuditRequest::Ping);
    assert_eq!(
        receive(&mut idle),
        Got::Reply(Reply::Message(AuditReply::Pong))
    );

    // Three octets of a length prefix, then silence: closed.
    let mut slow = connect(&server.socket);
    slow.write_all(&[0, 0, 0]).unwrap();
    let started = Instant::now();
    assert_eq!(receive(&mut slow), Got::Closed);
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(900), "{waited:?}");
    assert!(waited < Duration::from_millis(4000), "{waited:?}");
    drop((idle, slow));
    assert_eq!(server.stop(), Some(Ok(())));
}

/// Source: docs/50 §3.3 (wrong version ⇒ `Refused{VersionMismatch}` +
/// close; wrong magic ⇒ close), A-59.
#[test]
fn version_and_magic_errors_follow_the_shared_rules() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings(&dir, uid, 5);
    let server = Server::start(&settings, config(&settings), 8, true);
    let ping = ipc_audit::encode_request(&AuditRequest::Ping).unwrap();

    // Frame = length:u32 ‖ magic:u16 ‖ version:u8 ‖ kind:u8 (docs/50 §3.3).
    let mut wrong_version = ping.as_bytes().to_vec();
    wrong_version[6] ^= 0xFF;
    let mut client = connect(&server.socket);
    client.write_all(&wrong_version).unwrap();
    assert_eq!(
        receive(&mut client),
        Got::Reply(Reply::Refused(Refused::VersionMismatch))
    );
    assert_eq!(receive(&mut client), Got::Closed);

    let mut wrong_magic = ping.as_bytes().to_vec();
    wrong_magic[4] ^= 0xFF;
    let mut client = connect(&server.socket);
    client.write_all(&wrong_magic).unwrap();
    assert_eq!(receive(&mut client), Got::Closed);
    assert_eq!(server.stop(), Some(Ok(())));
}

/// Source: AGENTS.md §6 (bounded resources); docs/50 §3.6; Q-265 item 5
/// (connection quota per source), item 8 (counted in the summary).
#[test]
fn connections_over_the_quota_are_closed() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings(&dir, uid, 5);
    let server = Server::start(&settings, config(&settings), 8, true);

    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS_PER_SOURCE {
        let mut client = connect(&server.socket);
        send(&mut client, &AuditRequest::Ping);
        assert_eq!(
            receive(&mut client),
            Got::Reply(Reply::Message(AuditReply::Pong))
        );
        held.push(client);
    }
    let mut extra = connect(&server.socket);
    let frame = ipc_audit::encode_request(&AuditRequest::Ping).unwrap();
    let _ = extra.write_all(frame.as_bytes());
    assert_eq!(receive(&mut extra), Got::Closed);

    // Closing one frees a slot.
    held.pop();
    std::thread::sleep(Duration::from_millis(200));
    let mut next = connect(&server.socket);
    send(&mut next, &AuditRequest::Ping);
    assert_eq!(
        receive(&mut next),
        Got::Reply(Reply::Message(AuditReply::Pong))
    );

    std::thread::sleep(Duration::from_millis(1600));
    drop((held, next));
    assert_eq!(server.stop(), Some(Ok(())));
    let (records, _) = read_segment(&dir.base(), 1, Anchor::Genesis);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].payload, expected_refused(0, 1, uid));
}

/// Source: docs/50 §3.1 ("deleting a stale socket file before bind … the
/// daemon manages this explicitly"); Q-265 item 9.
#[test]
fn bind_replaces_a_stale_socket_but_never_another_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    let _context = runtime.enter();

    // A stale socket file left by an earlier run.
    let stale = std::os::unix::net::UnixListener::bind(dir.socket()).unwrap();
    drop(stale);
    assert!(dir.socket().exists());
    let bound = listener::bind(&dir.socket()).expect("stale socket replaced");
    let mode = std::fs::metadata(dir.socket())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, listener::SOCKET_FILE_MODE);
    drop(bound);

    // A regular file is left alone.
    let other = dir.path().join("not-a-socket");
    std::fs::write(&other, b"keep").unwrap();
    assert_eq!(listener::bind(&other).err(), Some(BindError::NotASocket));
    assert_eq!(std::fs::read(&other).unwrap(), b"keep");
}

// ---- the admin-plane shapes (docs/51 §5.7) ------------------------------------

/// Source: docs/51 §5.7 item 2 (dird's decision event is acknowledged by
/// auditd before the commit, the outcome event follows); docs/50 §3.2,
/// §8.1. A dird-mapped connection appends a `DirAdmin` decision, gets the
/// `Ack` (only after the sync), then appends the outcome; the on-disk chain
/// verifies and the records decode back to the events, with the transport
/// identity.
#[test]
fn dird_admin_decision_is_acknowledged_then_outcome() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings_for(&dir, uid, "dird", 5);
    let server = Server::start(&settings, config(&settings), 8, true);
    let pair = dir_admin_pair();
    let octets = encoded(&pair);

    let mut client = connect(&server.socket);
    send(
        &mut client,
        &AuditRequest::Append(Append::new(1, vec![octets[0].clone()]).unwrap()),
    );
    let decision_ack = expect_ack(receive(&mut client));
    assert_eq!(decision_ack.through_seq, 1);
    // (dird commits only now; then the outcome.)
    send(
        &mut client,
        &AuditRequest::Append(Append::new(2, vec![octets[1].clone()]).unwrap()),
    );
    let outcome_ack = expect_ack(receive(&mut client));
    assert_eq!(outcome_ack.through_seq, 2);
    drop(client);
    assert_eq!(server.stop(), Some(Ok(())));

    let (records, head) = read_segment(&dir.base(), 1, Anchor::Genesis);
    assert_eq!(head.hash.as_bytes(), &outcome_ack.head_hash);
    assert_eq!(records.len(), 2);
    for (i, record) in records.iter().enumerate() {
        assert_eq!(record.source, Source::Dird);
        assert_eq!(record.source_uid, uid);
        assert_eq!(record.source_seq, i as u64 + 1);
        assert_eq!(ipc_audit::decode_event(&record.payload).unwrap(), pair[i]);
    }
}

/// Source: docs/51 §5.7 item 3 (admind sends its own events); docs/50 §3.2.
#[test]
fn admind_events_are_appended() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings_for(&dir, uid, "admind", 5);
    let server = Server::start(&settings, config(&settings), 8, true);
    let admind = admind_events();

    let mut client = connect(&server.socket);
    send(
        &mut client,
        &AuditRequest::Append(Append::new(1, encoded(&admind)).unwrap()),
    );
    let ack = expect_ack(receive(&mut client));
    assert_eq!(ack.through_seq, 2);
    drop(client);
    assert_eq!(server.stop(), Some(Ok(())));

    let (records, head) = read_segment(&dir.base(), 1, Anchor::Genesis);
    assert_eq!(head.hash.as_bytes(), &ack.head_hash);
    assert_eq!(records.len(), 2);
    for (record, event) in records.iter().zip(&admind) {
        assert_eq!(record.source, Source::Admind);
        assert_eq!(record.source_uid, uid);
        assert_eq!(&ipc_audit::decode_event(&record.payload).unwrap(), event);
    }
}

/// Source: docs/51 §5.7 (dird is the source of `DirAdmin`, admind of
/// `Admind`); docs/50 §3.2 ("closed + an audit record"); docs/questions/
/// Q-341. A batch holding a shape its source may not send is refused as a
/// whole — `Refused::Malformed`, then close, nothing of it persisted — and
/// counted into an `EventsMisbound` record. The service stays up for the
/// source's own events.
#[test]
fn misbound_shape_is_refused_and_recorded() {
    let Some(uid) = mappable_uid() else { return };
    for (source, foreign) in [
        ("kdc", dir_admin_pair()),
        ("dird", admind_events()),
        ("admind", dir_admin_pair()),
        ("keyd", admind_events()),
    ] {
        let dir = TempDir::new();
        let settings = settings_for(&dir, uid, source, 5);
        let server = Server::start(&settings, config(&settings), 8, true);

        // A legitimate batch first, then one with a foreign shape behind an
        // opaque event.
        let mut client = connect(&server.socket);
        send(&mut client, &append(1, 1, 1));
        assert_eq!(expect_ack(receive(&mut client)).through_seq, 1);
        let mut batch = events(1, 64, 2);
        batch.push(encoded(&foreign)[0].clone());
        send(
            &mut client,
            &AuditRequest::Append(Append::new(2, batch).unwrap()),
        );
        assert_eq!(
            receive(&mut client),
            Got::Reply(Reply::Refused(Refused::Malformed)),
            "{source}"
        );
        assert_eq!(receive(&mut client), Got::Closed, "{source}");

        // The service is still up for this source's own events.
        let mut again = connect(&server.socket);
        send(&mut again, &append(2, 1, 3));
        assert_eq!(expect_ack(receive(&mut again)).through_seq, 2);
        drop(again);

        // The summary record is written within the summary interval.
        std::thread::sleep(Duration::from_millis(1600));
        assert_eq!(server.stop(), Some(Ok(())), "{source}");
        let (records, _) = read_segment(&dir.base(), 1, Anchor::Genesis);
        let from_source: Vec<_> = records
            .iter()
            .filter(|r| r.source != Source::Auditd)
            .collect();
        assert_eq!(
            from_source.len(),
            2,
            "{source}: nothing of the refused batch"
        );
        assert_eq!(from_source[0].payload, events(1, 64, 1)[0].as_bytes());
        assert_eq!(from_source[1].payload, events(1, 64, 3)[0].as_bytes());
        let own: Vec<_> = records
            .iter()
            .filter(|r| r.source == Source::Auditd)
            .collect();
        assert_eq!(own.len(), 1, "{source}");
        assert_eq!(own[0].payload, expected_misbound(1, uid), "{source}");
    }
}

/// Source: docs/50 §3.2, §4.2 (dird writes the LDAP events), §8.1 ("a
/// compromised kdc can add false records"); docs/questions/Q-341 option (a)
/// (decided): `Kdc` ⇐ kdc, `Keyd` ⇐ keyd, `Ldap` ⇐ dird, `WindowSummary` ⇐
/// any mapped source — the older shapes are bound too. For a kdc- and a
/// dird-mapped connection (between them every older shape is both accepted
/// and refused; keyd's own `Keyd` is accepted in tier 1 `binding_permits`),
/// every shape is sent on its own connection: the sender's own shapes and
/// `WindowSummary` get an `Ack`; every other shape is refused (`Malformed`,
/// then close), nothing of it persisted, and the refusals are counted into
/// `EventsMisbound` records.
#[test]
fn older_shapes_are_bound_to_their_sender() {
    let Some(uid) = mappable_uid() else { return };
    let shapes: [(&str, EventBody); 6] = [
        ("Kdc", kdc_event()),
        ("Keyd", keyd_record()),
        ("Ldap", ldap_event()),
        ("DirAdmin", dir_admin_pair().remove(0)),
        ("Admind", admind_events().remove(1)),
        ("WindowSummary", window_summary()),
    ];
    for (source, own_shapes) in [("kdc", &["Kdc"][..]), ("dird", &["Ldap", "DirAdmin"][..])] {
        let dir = TempDir::new();
        let settings = settings_for(&dir, uid, source, 5);
        let server = Server::start(&settings, config(&settings), 8, true);
        let mut accepted = Vec::new();
        let mut refused = 0u64;
        for (name, event) in &shapes {
            let permitted = *name == "WindowSummary" || own_shapes.contains(name);
            let mut client = connect(&server.socket);
            // Each Ack waits for a sync; allow for a loaded machine.
            client
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            send(
                &mut client,
                &AuditRequest::Append(
                    Append::new(1, encoded(std::slice::from_ref(event))).unwrap(),
                ),
            );
            if permitted {
                assert_eq!(
                    expect_ack(receive(&mut client)).through_seq,
                    1,
                    "{source}: {name}"
                );
                accepted.push(event.clone());
            } else {
                assert_eq!(
                    receive(&mut client),
                    Got::Reply(Reply::Refused(Refused::Malformed)),
                    "{source}: {name}"
                );
                assert_eq!(receive(&mut client), Got::Closed, "{source}: {name}");
                refused += 1;
            }
        }
        std::thread::sleep(Duration::from_millis(1600));
        assert_eq!(server.stop(), Some(Ok(())), "{source}");

        let (records, _) = read_segment(&dir.base(), 1, Anchor::Genesis);
        let stored: Vec<EventBody> = records
            .iter()
            .filter(|r| r.source != Source::Auditd)
            .map(|r| {
                assert_eq!(r.source_uid, uid);
                ipc_audit::decode_event(&r.payload).unwrap()
            })
            .collect();
        assert_eq!(stored, accepted, "{source}: only its own shapes");
        // The refusals are summarised at most once per summary interval
        // while auditd serves, and what is still pending at the stop is
        // written then (Q-396): the records count every refused batch,
        // only refused batches, from this uid.
        let counted: u64 = records
            .iter()
            .filter(|r| r.source == Source::Auditd)
            .map(|r| {
                assert_eq!(&r.payload[..2], &[0xAD, 0x03], "{source}: EventsMisbound");
                assert_eq!(&r.payload[10..14], &uid.to_be_bytes());
                u64::from_be_bytes(r.payload[2..10].try_into().unwrap())
            })
            .sum();
        assert_eq!(counted, refused, "{source}");
        assert_eq!(refused, 5 - own_shapes.len() as u64, "{source}");
    }
}

// ---- resent batches (task F8) ----------------------------------------------------

/// Source: decision A-98 (follow-up F8), docs/questions/Q-432 item 5 (auditd
/// stopped after the sync, before the sender saw the `Ack`), Q-445; docs/50
/// §3.7 (reconnect), §7.5 (the log verified at start), §8.1;
/// ipc-audit `SendWindow::connection_lost` (resend with the same numbers),
/// `SendWindow::new` (a restarted sender numbers from 1). The test reads
/// the `Ack` only to know the batch was synced, then acts as the sender that
/// lost it: auditd stops and starts again (the real start-up, `open_log`),
/// the sender resends on a new connection and gets an `Ack` naming the
/// record that already holds its last event — one copy in the log; then a
/// restarted sender's numbering from 1 is accepted.
#[test]
fn a_batch_resent_after_auditd_restarts_is_acknowledged_once() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings(&dir, uid, 5);
    let server = Server::start(&settings, config(&settings), 8, true);
    let mut client = connect(&server.socket);
    send(&mut client, &append(1, 3, 1));
    assert_eq!(expect_ack(receive(&mut client)).through_seq, 3);
    send(&mut client, &append(4, 2, 2));
    let synced = expect_ack(receive(&mut client));
    assert_eq!(synced.through_seq, 5);
    // From here the sender behaves as if that Ack never arrived.
    drop(client);
    assert_eq!(server.stop(), Some(Ok(())));

    let server = Server::start(&settings, config(&settings), 8, true);
    let mut resend = connect(&server.socket);
    send(&mut resend, &append(4, 2, 2));
    let ack = expect_ack(receive(&mut resend));
    assert_eq!(
        ack, synced,
        "the same Ack: through 5, the record holding it"
    );
    drop(resend);
    // A restarted sender: a new numbering from 1, other events.
    let mut restarted = connect(&server.socket);
    send(&mut restarted, &append(1, 2, 7));
    assert_eq!(expect_ack(receive(&mut restarted)).through_seq, 2);
    drop(restarted);
    assert_eq!(server.stop(), Some(Ok(())));

    let (records, head) = read_segment(&dir.base(), 1, Anchor::Genesis);
    let numbers: Vec<u64> = records.iter().map(|r| r.source_seq).collect();
    assert_eq!(numbers, [1, 2, 3, 4, 5, 1, 2], "one copy of 4 and 5");
    assert_eq!(records[3].payload, events(2, 64, 2)[0].as_bytes());
    assert_eq!(records[5].payload, events(2, 64, 7)[0].as_bytes());
    let reopened = audit_daemon::recovery::open_log(
        &dir.base(),
        audit_log::SegmentLimit::DEFAULT,
        settings.run_as().uid(),
    )
    .expect("the log verifies at the next start");
    assert_eq!(reopened.sink.head(), head);
}

/// Source: crate `audit_daemon::resend` rule 2 (a partly persisted batch);
/// ipc-audit `SendWindow::next_batch` (the resent batch carries the events
/// committed since); docs/questions/Q-445 item 2. Over the socket: only the
/// events after the last persisted number are appended; the `Ack` names the
/// last event.
#[test]
fn a_partly_persisted_resend_is_completed() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings(&dir, uid, 5);
    let server = Server::start(&settings, config(&settings), 8, true);
    let mut client = connect(&server.socket);
    send(&mut client, &append(1, 2, 1));
    assert_eq!(expect_ack(receive(&mut client)).through_seq, 2);
    send(&mut client, &append(3, 2, 2));
    assert_eq!(expect_ack(receive(&mut client)).through_seq, 4);
    drop(client); // that Ack counts as lost

    let mut resend = connect(&server.socket);
    let mut batch = events(2, 64, 2);
    batch.extend(events(2, 64, 3));
    send(
        &mut resend,
        &AuditRequest::Append(Append::new(3, batch.clone()).unwrap()),
    );
    let ack = expect_ack(receive(&mut resend));
    assert_eq!(ack.through_seq, 6);
    drop(resend);
    assert_eq!(server.stop(), Some(Ok(())));

    let (records, head) = read_segment(&dir.base(), 1, Anchor::Genesis);
    assert_eq!(head.hash.as_bytes(), &ack.head_hash);
    let numbers: Vec<u64> = records.iter().map(|r| r.source_seq).collect();
    assert_eq!(numbers, [1, 2, 3, 4, 5, 6]);
    for (record, event) in records[2..].iter().zip(&batch) {
        assert_eq!(record.payload, event.as_bytes());
    }
}

/// Source: decision A-98 / the F8 brief (a resent event must be
/// byte-identical; a mismatch is refused and counted); docs/50 §3.2
/// ("closed + an audit record"); docs/questions/Q-265 item 3 (refusal of a
/// numbering error: `Refused::Malformed` + close), Q-445 items 3, 6. A
/// resend whose last event differs is refused and closed, nothing appended;
/// the true resend is acknowledged; a `ResendsRefused` record counts the
/// refusal.
#[test]
fn a_resend_that_differs_is_refused_and_recorded() {
    let Some(uid) = mappable_uid() else { return };
    let dir = TempDir::new();
    let settings = settings(&dir, uid, 5);
    let server = Server::start(&settings, config(&settings), 8, true);
    let mut client = connect(&server.socket);
    send(&mut client, &append(1, 3, 1));
    assert_eq!(expect_ack(receive(&mut client)).through_seq, 3);
    drop(client);

    let mut forged = events(3, 64, 1)[1..].to_vec();
    forged[1] = events(1, 64, 9).remove(0);
    let mut client = connect(&server.socket);
    send(
        &mut client,
        &AuditRequest::Append(Append::new(2, forged).unwrap()),
    );
    assert_eq!(
        receive(&mut client),
        Got::Reply(Reply::Refused(Refused::Malformed))
    );
    assert_eq!(receive(&mut client), Got::Closed);

    let mut client = connect(&server.socket);
    send(
        &mut client,
        &AuditRequest::Append(Append::new(2, events(3, 64, 1)[1..].to_vec()).unwrap()),
    );
    assert_eq!(expect_ack(receive(&mut client)).through_seq, 3);
    drop(client);
    assert_eq!(server.stop(), Some(Ok(())));

    let (records, _) = read_segment(&dir.base(), 1, Anchor::Genesis);
    assert_eq!(records.len(), 4);
    for (record, event) in records.iter().zip(&events(3, 64, 1)) {
        assert_eq!(record.source, Source::Kdc);
        assert_eq!(record.payload, event.as_bytes());
    }
    assert_eq!(records[3].source, Source::Auditd);
    assert_eq!(records[3].payload, expected_resends(1, 0, uid));
}
