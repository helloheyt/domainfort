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
use ipc_audit::{Ack, Append, AuditReply, AuditRequest};
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
