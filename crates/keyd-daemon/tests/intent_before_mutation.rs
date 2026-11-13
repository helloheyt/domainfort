//! Tier 2 (docs/50 §9) for decision A-86 (docs/questions/Q-346, Q-365):
//! a key-state change has the record of its intent **acknowledged by auditd
//! before keyd runs it**, so "unavailable" always means "not done".
//!
//! The real daemon (`keyd_daemon::serve`) on a real Unix socket, the real
//! auditd listener and writer (crates/audit-daemon tests/common, reused by
//! `#[path]`) and the log they write, read back and **verified** with
//! crates/audit-log. Real peer credentials on every socket; the test's own
//! uid is the keyd caller (one role per daemon), keyd's audit source and
//! auditd's expected uid.
//!
//! Every test names its source. Every value is constructed by hand for these
//! tests; no vector comes from any other implementation.

mod support;

#[path = "../../audit-daemon/tests/common/mod.rs"]
mod auditd_support;

use audit_daemon::listener::ListenerConfig;
use audit_daemon::segments::{list_segments, segment_path};
use audit_log::{verify_log, Anchor, Record, SegmentLimit, SegmentReader, Source};
use ipc::{Direction, FrameReader, Refused, Reply};
use ipc_audit::{
    decode_event, decode_request, encode_reply, Ack, AuditReply, AuditRequest, EventBody,
    KeyPurposeCode, KeydOperation, KeydOutcome, KeydReason, KeydRecord, AUDIT_CHANNEL,
};
use ipc_keyd::{Answer, Call, Password};
use keyd::{Error, KeyHandle, KeyPurpose, Kvno, PrincipalBinding, PrincipalId, Role};
use keyd_daemon::startup::development_keyd;
use keyd_daemon::{CallerMap, SystemClock, INTENT_ACK_BUDGET};
use krb_proto::{KerberosString, PrincipalName, Realm};
use std::fs::File;
use std::io::{BufReader, ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use support::{eventually, my_uid, params, skip_as_root, Daemon, RawClient, TempDir};
use zeroize::Zeroizing;

fn realm() -> Realm {
    Realm::new("EXAMPLE.ORG").unwrap()
}

fn binding(name: &str) -> PrincipalBinding {
    PrincipalBinding::new(
        realm(),
        PrincipalName {
            name_type: 1,
            name_string: vec![KerberosString::new(name).unwrap()],
        },
    )
}

fn handle(octet: u8) -> KeyHandle {
    KeyHandle::new(
        PrincipalId::from_bytes([octet; 16]),
        KeyPurpose::PrincipalLongterm,
    )
}

fn create_key(octet: u8) -> Call {
    Call::CreateKey {
        handle: handle(octet),
        binding: binding("alice"),
    }
}

fn set_secret(octet: u8) -> Call {
    Call::SetSecret {
        handle: handle(octet),
        binding: binding("bob"),
        password: Password::new(Zeroizing::new(String::from("tier-two-test-pass"))),
        salt: String::from("EXAMPLE.ORGbob"),
    }
}

/// The real auditd (listener + writer) in `dir` at `a.sock`, writing the log
/// based at `log`, mapping `uid` to keyd. With `acknowledging == false` the
/// writer never runs: auditd answers `Ping` but never acknowledges an
/// `Append` (an auditd that is reachable and stuck).
fn start_auditd(dir: &TempDir, uid: u32, log: &str, acknowledging: bool) -> auditd_support::Server {
    let run_as = auditd_support::other_uid(&[uid]);
    let text = format!(
        "run_as_uid = {run_as}\nrun_as_gid = {run_as}\naudit_socket = {}\n\
         audit_log_path = {}\nuid_sources = {uid}:keyd\nframe_timeout = 5s\n",
        dir.join("a.sock").display(),
        dir.join(log).display()
    );
    let settings = config::AuditdSettings::parse(text.as_bytes()).unwrap();
    auditd_support::Server::start(
        &settings,
        ListenerConfig::from_settings(&settings),
        64,
        acknowledging,
    )
}

/// keyd with the development store on the system clock (Admin and Directory
/// calls are not held, docs/10 §11), the test's uid holding `role`.
fn start_keyd(dir: &TempDir, uid: u32, role: Role) -> Daemon {
    let params = params(dir, CallerMap::new(&[(uid, role)]).unwrap(), uid);
    Daemon::start(params, SystemClock, development_keyd(realm())).unwrap()
}

/// The open segment files of the log based at `base`.
fn open_segment(base: &Path, index: u64) -> BufReader<File> {
    BufReader::new(File::open(segment_path(base, index)).unwrap())
}

/// The whole log based at `base`, verified from genesis with crates/audit-log
/// (`verify_log`, then every record re-read through `SegmentReader`), with
/// the writer stopped.
fn verified_log(base: &Path) -> Vec<Record> {
    let indexes = list_segments(base).unwrap();
    assert!(!indexes.is_empty(), "no segment");
    let files: Vec<_> = indexes.iter().map(|&i| open_segment(base, i)).collect();
    let head = verify_log(files, Anchor::Genesis, SegmentLimit::DEFAULT, None).unwrap();
    let mut records = Vec::new();
    let mut anchor = Anchor::Genesis;
    for &index in &indexes {
        let mut reader = SegmentReader::open(
            open_segment(base, index),
            anchor,
            SegmentLimit::DEFAULT,
            None,
        )
        .unwrap();
        while let Some(record) = reader.next_record().unwrap() {
            records.push(record);
        }
        anchor = Anchor::After(reader.head());
        reader.finish().unwrap();
    }
    assert_eq!(records.last().map(|r| r.seq), Some(head.seq));
    records
}

/// The records of the log based at `base` that verify so far, read while the
/// writer may still be appending (for waiting only).
fn persisted_records(base: &Path) -> Vec<Record> {
    let mut records = Vec::new();
    let Ok(indexes) = list_segments(base) else {
        return records;
    };
    let mut anchor = Anchor::Genesis;
    for index in indexes {
        let Ok(file) = File::open(segment_path(base, index)) else {
            break;
        };
        let Ok(mut reader) =
            SegmentReader::open(BufReader::new(file), anchor, SegmentLimit::DEFAULT, None)
        else {
            break;
        };
        loop {
            match reader.next_record() {
                Ok(Some(record)) => records.push(record),
                Ok(None) => break,
                Err(_) => return records,
            }
        }
        anchor = Anchor::After(reader.head());
    }
    records
}

/// The keyd records among `records`, in log order, each checked to carry the
/// transport identity auditd gave it (docs/50 §3.2: source keyd, the peer
/// uid). auditd's own records and window summaries are skipped.
fn keyd_records(records: &[Record], uid: u32) -> Vec<KeydRecord> {
    records
        .iter()
        .filter(|record| record.source != Source::Auditd)
        .filter_map(|record| {
            assert_eq!(record.source, Source::Keyd, "the one uid's source");
            assert_eq!(record.source_uid, uid, "the sender's peer uid");
            match decode_event(&record.payload).unwrap() {
                EventBody::Keyd(keyd) => Some(*keyd),
                EventBody::WindowSummary(_) => None,
                other => panic!("keyd sent a {:?} event", other.shape()),
            }
        })
        .collect()
}

/// (operation, outcome, kvno) of each record.
fn phases(records: &[KeydRecord]) -> Vec<(KeydOperation, KeydOutcome, Option<u32>)> {
    records.iter().map(|r| (r.op, r.result, r.kvno)).collect()
}

/// Call until the answer is not `Busy` (keyd's audit connection is coming
/// back; `Busy` means "not done", so retrying is safe), bounded.
fn call_until_served(client: &mut RawClient, call: &Call) -> Result<Answer, Refused> {
    let start = Instant::now();
    loop {
        match client.call(call).expect("a reply") {
            Err(Refused::Busy) if start.elapsed() < Duration::from_secs(20) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            other => return other,
        }
    }
}

use KeydOperation as Op;
use KeydOutcome as Out;

/// docs/questions/Q-346 (A-86: "auditd up ⇒ intent then outcome records,
/// both in the verified log, in order"), with every Admin key-state change
/// (docs/10 §7): each answered with its true result, and in the verified
/// log each intent (outcome `Intent`, reason `None`, the handle, the kvno a
/// `retire_kvno` names) directly followed by keyd's own outcome. A refused
/// authorization (Admin may not `set_secret`, docs/10 §2) is one record and
/// no intent.
#[test]
fn every_admin_change_is_intent_then_outcome_in_the_verified_log() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let auditd = start_auditd(&dir, uid, "audit.log", true);
    let keyd = start_keyd(&dir, uid, Role::Admin);
    let mut client = RawClient::connect(&keyd.socket);
    assert!(matches!(
        client.call(&create_key(0xA1)),
        Some(Ok(Answer::CreateKey(Ok(kvno)))) if kvno == Kvno::INITIAL
    ));
    assert!(matches!(
        client.call(&Call::RotateKey { handle: handle(0xA1) }),
        Some(Ok(Answer::RotateKey(Ok(kvno)))) if kvno == Kvno::new(2)
    ));
    assert!(matches!(
        client.call(&Call::RetireKvno {
            handle: handle(0xA1),
            kvno: Kvno::INITIAL
        }),
        Some(Ok(Answer::RetireKvno(Ok(()))))
    ));
    assert!(matches!(
        client.call(&Call::DestroyKeySet {
            handle: handle(0xA1)
        }),
        Some(Ok(Answer::DestroyKeySet(Ok(()))))
    ));
    assert!(matches!(
        client.call(&set_secret(0xA1)),
        Some(Ok(Answer::SetSecret(Err(Error::Denied))))
    ));
    // keyd waits (bounded) for auditd to acknowledge its window at stop.
    keyd.stop().unwrap();
    assert!(matches!(auditd.stop(), Some(Ok(()))));

    let records = keyd_records(&verified_log(&dir.join("audit.log")), uid);
    assert_eq!(
        phases(&records),
        [
            (Op::CreateKey, Out::Intent, None),
            (Op::CreateKey, Out::Success, Some(1)),
            (Op::RotateKey, Out::Intent, None),
            (Op::RotateKey, Out::Success, Some(2)),
            (Op::RetireKvno, Out::Intent, Some(1)),
            (Op::RetireKvno, Out::Success, Some(1)),
            (Op::DestroyKeySet, Out::Intent, None),
            (Op::DestroyKeySet, Out::Success, Some(2)),
            (Op::SetSecret, Out::Denied, None),
        ]
    );
    for intent in records.iter().filter(|r| r.result == Out::Intent) {
        assert_eq!(intent.reason, KeydReason::None);
        assert_eq!(intent.caller_uid, uid);
        assert_eq!(intent.principal, Some([0xA1; 16]));
        assert_eq!(intent.purpose, Some(KeyPurposeCode::PrincipalLongterm));
    }
    assert_eq!(records[8].reason, KeydReason::RoleNotPermitted);
}

/// The same for the Directory's `set_secret` (docs/10 §6): kvno 1, then
/// kvno 2, each preceded by its acknowledged intent in the verified log.
#[test]
fn set_secret_is_intent_then_outcome_in_the_verified_log() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let auditd = start_auditd(&dir, uid, "audit.log", true);
    let keyd = start_keyd(&dir, uid, Role::Directory);
    let mut client = RawClient::connect(&keyd.socket);
    for expected in [Kvno::INITIAL, Kvno::new(2)] {
        assert!(matches!(
            client.call(&set_secret(0xB0)),
            Some(Ok(Answer::SetSecret(Ok(kvno)))) if kvno == expected
        ));
    }
    keyd.stop().unwrap();
    assert!(matches!(auditd.stop(), Some(Ok(()))));
    let records = keyd_records(&verified_log(&dir.join("audit.log")), uid);
    assert_eq!(
        phases(&records),
        [
            (Op::SetSecret, Out::Intent, None),
            (Op::SetSecret, Out::Success, Some(1)),
            (Op::SetSecret, Out::Intent, None),
            (Op::SetSecret, Out::Success, Some(2)),
        ]
    );
}

/// docs/questions/Q-346 (A-86: "auditd down ⇒ `create_key` / `set_secret`
/// answer `Unavailable` and a later successful ceremony proves nothing was
/// created (kvno 1, not 2)"). auditd is reachable but never acknowledges
/// (its writer does not run): the change is answered `Refused::Unavailable`
/// after the budget, and keyd does not run it. Then a healthy auditd takes
/// over: the same change is served at the **initial** kvno — the first
/// attempt created / set nothing — and the verified log holds, in order,
/// the first intent, its `NotPerformed` outcome, the second intent and
/// keyd's outcome.
fn unacknowledged_intent_changes_nothing(role: Role, call: &Call, op: KeydOperation) {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let stuck = start_auditd(&dir, uid, "stuck.log", false);
    let keyd = start_keyd(&dir, uid, role);
    let started = Instant::now();
    assert_eq!(
        RawClient::connect(&keyd.socket).call(call),
        Some(Err(Refused::Unavailable))
    );
    assert!(started.elapsed() >= INTENT_ACK_BUDGET);

    let _ = stuck.stop();
    let auditd = start_auditd(&dir, uid, "audit.log", true);
    let answer = call_until_served(&mut RawClient::connect(&keyd.socket), call);
    match answer {
        Ok(Answer::CreateKey(Ok(kvno)) | Answer::SetSecret(Ok(kvno))) => {
            assert_eq!(kvno, Kvno::INITIAL, "the refused attempt changed nothing");
        }
        other => panic!("{other:?}"),
    }
    keyd.stop().unwrap();
    assert!(matches!(auditd.stop(), Some(Ok(()))));
    let records = keyd_records(&verified_log(&dir.join("audit.log")), uid);
    assert_eq!(
        phases(&records),
        [
            (op, Out::Intent, None),
            (op, Out::NotPerformed, None),
            (op, Out::Intent, None),
            (op, Out::Success, Some(1)),
        ]
    );
}

#[test]
fn an_unacknowledged_create_key_is_unavailable_and_creates_nothing() {
    unacknowledged_intent_changes_nothing(Role::Admin, &create_key(0xA1), Op::CreateKey);
}

#[test]
fn an_unacknowledged_set_secret_is_unavailable_and_sets_nothing() {
    unacknowledged_intent_changes_nothing(Role::Directory, &set_secret(0xB0), Op::SetSecret);
}

// ---- auditd that stops between the intent and the outcome -----------------

/// An auditd that acknowledges exactly one `Append` — the first, which is the
/// intent of the first key-state change — and vanishes at that moment: it
/// removes its socket file and stops accepting before it sends the `Ack`,
/// then closes the connection. So keyd's engine is released to run the
/// change, and its outcome finds no auditd. Written from the audit channel's
/// own message set (crates/ipc-audit; docs/50 §8.1).
struct VanishingAuditd {
    events: Arc<Mutex<Vec<EventBody>>>,
    thread: Option<JoinHandle<()>>,
}

impl VanishingAuditd {
    fn start(path: &Path) -> VanishingAuditd {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let gone = Arc::new(AtomicBool::new(false));
        let events = Arc::new(Mutex::new(Vec::new()));
        let path: PathBuf = path.to_path_buf();
        let thread = {
            let events = Arc::clone(&events);
            std::thread::spawn(move || {
                let mut served: Vec<JoinHandle<()>> = Vec::new();
                while !gone.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            let (events, gone, path) =
                                (Arc::clone(&events), Arc::clone(&gone), path.clone());
                            served.push(std::thread::spawn(move || {
                                serve_once(stream, &events, &gone, &path);
                            }));
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
                drop(listener);
                for thread in served {
                    let _ = thread.join();
                }
            })
        };
        VanishingAuditd {
            events,
            thread: Some(thread),
        }
    }

    fn events(&self) -> Vec<EventBody> {
        self.events.lock().unwrap().clone()
    }

    /// Wait until it has vanished (its threads ended).
    fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

/// One connection of [`VanishingAuditd`]: `Ping` → `Pong`; the first
/// `Append` is kept, auditd vanishes, then the `Ack` goes and the connection
/// closes.
fn serve_once(
    mut stream: UnixStream,
    events: &Mutex<Vec<EventBody>>,
    gone: &AtomicBool,
    path: &Path,
) {
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut reader = FrameReader::new(AUDIT_CHANNEL.limit(Direction::Request));
    let mut chunk = [0u8; 4096];
    loop {
        if gone.load(Ordering::SeqCst) {
            return;
        }
        if let Some(body) = reader.body() {
            let body = body.to_vec();
            reader = FrameReader::new(AUDIT_CHANNEL.limit(Direction::Request));
            let (reply, last) = match decode_request(&body).unwrap() {
                AuditRequest::Ping => (AuditReply::Pong, false),
                AuditRequest::Append(append) => {
                    let mut held = events.lock().unwrap();
                    for event in append.events() {
                        held.push(decode_event(event.as_bytes()).unwrap());
                    }
                    // Vanish before the Ack can release keyd's engine.
                    gone.store(true, Ordering::SeqCst);
                    let _ = std::fs::remove_file(path);
                    let ack = Ack {
                        through_seq: append.last_seq(),
                        head_hash: [0; 32],
                    };
                    (AuditReply::Ack(ack), true)
                }
            };
            let frame = encode_reply(&Reply::Message(reply)).unwrap();
            let _ = stream.write_all(frame.as_bytes());
            if last {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            }
            continue;
        }
        let wanted = reader.wanted().min(chunk.len());
        match stream.read(&mut chunk[..wanted]) {
            Ok(0) => return,
            Ok(n) => {
                reader.push(&chunk[..n]).unwrap();
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// docs/questions/Q-346 (A-86: "the outcome record cannot be sent ⇒ the
/// reply is the true result"). auditd acknowledges the intent of a
/// `create_key` and is gone before the outcome: the reply is still the true
/// result (kvno 1). The outcome is not dropped — it waits in keyd's window
/// — and when an auditd is back it is delivered and verified in its log.
/// (Lost it would be only if keyd ended first: the stop notes it on stderr,
/// Q-252 item 9. An outcome that cannot even enter the window is counted —
/// tier 1, `an_unrecorded_outcome_answers_the_true_result_and_is_counted`.)
#[test]
fn auditd_gone_between_intent_and_outcome_keeps_the_true_result() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let vanishing = VanishingAuditd::start(&dir.join("a.sock"));
    let keyd = start_keyd(&dir, uid, Role::Admin);
    assert!(matches!(
        RawClient::connect(&keyd.socket).call(&create_key(0xA1)),
        Some(Ok(Answer::CreateKey(Ok(kvno)))) if kvno == Kvno::INITIAL
    ));
    let seen: Vec<_> = vanishing
        .events()
        .into_iter()
        .map(|event| match event {
            EventBody::Keyd(record) => (record.op, record.result),
            other => panic!("{:?}", other.shape()),
        })
        .collect();
    assert_eq!(seen, [(Op::CreateKey, Out::Intent)]);
    vanishing.join();

    // An auditd again: keyd reconnects and delivers the held outcome.
    let auditd = start_auditd(&dir, uid, "audit.log", true);
    let base = dir.join("audit.log");
    assert!(eventually(Duration::from_secs(20), || {
        keyd_records(&persisted_records(&base), uid)
            .iter()
            .any(|r| r.op == Op::CreateKey && r.result == Out::Success)
    }));
    keyd.stop().unwrap();
    assert!(matches!(auditd.stop(), Some(Ok(()))));
    let records = keyd_records(&verified_log(&base), uid);
    assert_eq!(phases(&records), [(Op::CreateKey, Out::Success, Some(1))]);
}
