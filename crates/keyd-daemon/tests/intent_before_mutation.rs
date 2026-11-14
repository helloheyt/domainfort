//! Tier 2 (docs/50 §9) for decision A-86 (docs/questions/Q-346, Q-365):
//! a key-state change has the record of its intent **acknowledged by auditd
//! before keyd runs it**, so "unavailable" always means "not done" — and,
//! for decision A-88 (docs/questions/Q-366, Q-395), an outcome record that
//! could not be committed is counted into a window summary in the log.
//!
//! The real daemon (`keyd_daemon::serve`) on a real Unix socket, the real
//! auditd listener and writer (crates/audit-daemon tests/common, reused by
//! `#[path]`) and the log they write, read back and **verified** with
//! crates/audit-log. Real peer credentials on every socket; the test's own
//! uid is the keyd caller (one role per daemon), keyd's audit source and
//! auditd's expected uid.
//!
//! **The budget** (decision A-93's follow-up F5, docs/questions/Q-415): the
//! tests in which the real auditd is expected to acknowledge give the daemon
//! the ceiling, [`MAX_INTENT_ACK_BUDGET`], so that a loaded machine writing
//! auditd's log late rarely turns the wait into `Unavailable`. The A-88 rule
//! then holds against this test's own client: [`RawClient`] waits 10 s for a
//! reply, more than twice the ceiling. The ceiling is a hard bound, and a
//! heavily loaded machine was seen to need more (an acknowledgement later
//! than 2 s), so these tests also retry an `Unavailable` change (A-86: it was
//! not done) and require every refused attempt in the verified log as its
//! intent and a `NotPerformed` outcome, before the performed one's intent
//! and keyd's outcome. The test that times the expiry keeps the short
//! production budget with an auditd that never acknowledges (deterministic),
//! and retries the same way against the healthy auditd that follows.
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
    KeyPurposeCode, KeydOperation, KeydOutcome, KeydReason, KeydRecord, WindowSummary,
    AUDIT_CHANNEL,
};
use ipc_keyd::{Answer, Call, Password};
use keyd::{
    AccountKind, CallerId, DecidedOperation, DecisionId, Error, KeyHandle, KeyPurpose, Kvno,
    PrincipalBinding, PrincipalId, Role, SetSecretTarget, MAX_INITIAL_SECRET_GRANT_SECS,
    MAX_SET_SECRET_GRANT_SECS,
};
use keyd_daemon::audit::MAX_RECORDS_PER_OPERATION;
use keyd_daemon::startup::development_keyd;
use keyd_daemon::test_seams::ExtraListener;
use keyd_daemon::{
    CallerMap, IntentAckBudget, SystemClock, INTENT_ACK_BUDGET, MAX_INTENT_ACK_BUDGET,
};
use krb_proto::{KerberosString, KerberosTime, PrincipalName, Realm};
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

/// bob's key target with the salt [`set_secret`] presents (N4, A-102).
fn bob_target(octet: u8) -> SetSecretTarget {
    SetSecretTarget {
        handle: handle(octet),
        binding: binding("bob"),
        salt: String::from("EXAMPLE.ORGbob"),
    }
}

/// The set-secret decision dird registers for [`set_secret`]'s key set
/// (task A15a; A-102: keyd refuses Directory's `set_secret` without one),
/// sent by the test's uid as Role::Ldap on keyd's grant socket
/// ([`grant_socket`]).
fn grant(id: u64, octet: u8) -> Call {
    Call::RegisterDecision {
        id: DecisionId::new(id),
        operation: DecidedOperation::SetSecret {
            kind: AccountKind::User,
            targets: vec![bob_target(octet)],
        },
        approvers: Vec::new(),
        lifetime_secs: MAX_SET_SECRET_GRANT_SECS,
    }
}

/// A key-operation or destroy decision dird registers (A-102, docs/52
/// §4.3), with the requester and one approver (dual control), sent as
/// Role::Ldap on [`grant_socket`].
fn decide(id: u64, operation: DecidedOperation) -> Call {
    Call::RegisterDecision {
        id: DecisionId::new(id),
        operation,
        approvers: vec![
            PrincipalId::from_bytes([0x01; 16]),
            PrincipalId::from_bytes([0x02; 16]),
        ],
        lifetime_secs: 900,
    }
}

/// keyd's second socket in these tests, where the test's uid is Role::Ldap
/// (keyd-daemon `ExtraListener`, tests only — docs/questions/Q-453).
fn grant_socket(dir: &TempDir) -> PathBuf {
    dir.join("g.sock")
}

/// The real auditd (listener + writer) in `dir` at `a.sock`, writing the log
/// based at `log` (in a scratch directory the protected-file walk accepts:
/// crates/audit-daemon `segments`, task R11b), mapping `uid` to keyd. With `acknowledging == false` the
/// writer never runs: auditd answers `Ping` but never acknowledges an
/// `Append` (an auditd that is reachable and stuck).
fn start_auditd(
    dir: &TempDir,
    uid: u32,
    log: &Path,
    acknowledging: bool,
) -> auditd_support::Server {
    let run_as = auditd_support::other_uid(&[uid]);
    let text = format!(
        "run_as_uid = {run_as}\nrun_as_gid = {run_as}\naudit_socket = {}\n\
         audit_log_path = {}\nuid_sources = {uid}:keyd\nframe_timeout = 5s\n",
        dir.join("a.sock").display(),
        log.display()
    );
    let settings = config::AuditdSettings::parse(text.as_bytes()).unwrap();
    auditd_support::Server::start(
        &settings,
        ListenerConfig::from_settings(&settings),
        64,
        acknowledging,
    )
}

/// The budget of a daemon whose test expects auditd to acknowledge: the
/// ceiling (module documentation; docs/questions/Q-415).
fn generous() -> IntentAckBudget {
    IntentAckBudget::new(MAX_INTENT_ACK_BUDGET).unwrap()
}

/// keyd with the development store on the system clock (Admin and Directory
/// calls are not held, docs/10 §11), the test's uid holding `role`, with the
/// intent budget `budget`.
///
/// A second socket of the same keyd maps the test's uid to Role::Ldap, for
/// the grants a Directory `set_secret` needs (task A15a; [`grant_socket`]).
fn start_keyd(dir: &TempDir, uid: u32, role: Role, budget: IntentAckBudget) -> Daemon {
    let mut params = params(dir, CallerMap::new(&[(uid, role)]).unwrap(), uid);
    params.intent_ack_budget = budget;
    params.extra_listeners = vec![ExtraListener {
        socket: grant_socket(dir),
        callers: CallerMap::new(&[(uid, Role::Ldap)]).unwrap(),
    }];
    Daemon::start(params, SystemClock, development_keyd(realm())).unwrap()
}

/// As [`start_keyd`] (Role::Directory), with a grant for
/// [`set_secret`]'s key set already in keyd when it starts — registered
/// there by the keyadm role at keyd's start time (an initial secret, 15
/// minutes: this test's auditd never acknowledges a grant's intent), its
/// record drained before the engine runs, so the log holds only the
/// `set_secret` phases. Test setup only (task A15a).
fn start_keyd_granted(dir: &TempDir, uid: u32, budget: IntentAckBudget) -> Daemon {
    let mut params = params(dir, CallerMap::new(&[(uid, Role::Directory)]).unwrap(), uid);
    params.intent_ack_budget = budget;
    let build = development_keyd(realm());
    Daemon::start(params, SystemClock, move |started: &KerberosTime| {
        let mut keyd = build(started)?;
        let keyadm = CallerId {
            uid: uid.wrapping_add(1),
            role: Role::Admin,
        };
        keyd.grant_set_secret(
            &keyadm,
            AccountKind::User,
            &[bob_target(0xB0)],
            MAX_INITIAL_SECRET_GRANT_SECS,
            started,
        )
        .expect("the grant is registered");
        let _ = keyd.audit_sink_mut().take();
        Ok(keyd)
    })
    .unwrap()
}

/// The open segment files of the log based at `base`.
fn open_segment(base: &Path, index: u64) -> BufReader<File> {
    BufReader::new(File::open(segment_path(base, index)).unwrap())
}

/// The whole log based at `base`, verified from genesis with crates/audit-log
/// (`verify_log`, then every record re-read through `SegmentReader`), with
/// the writer stopped.
fn verified_log(base: &Path) -> Vec<Record> {
    let indexes = list_segments(base, auditd_support::log_uid()).unwrap();
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
    let Ok(indexes) = list_segments(base, auditd_support::log_uid()) else {
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

/// Call `call` on keyd at `socket` until it is performed, bounded: `Busy`
/// (keyd's audit connection is coming back) and `Unavailable` (an intent
/// not acknowledged within the short budget — a loaded machine) both mean
/// "not done" (A-86), so retrying is safe. `Unavailable` closes the
/// connection, so the next attempt opens another. Returns the last answer and
/// how many attempts were answered `Unavailable`.
fn call_until_performed(socket: &Path, call: &Call) -> (Result<Answer, Refused>, usize) {
    let start = Instant::now();
    let mut unacknowledged = 0;
    let mut client = RawClient::connect(socket);
    loop {
        let retry = start.elapsed() < Duration::from_secs(20);
        match client.call(call).expect("a reply") {
            Err(Refused::Busy) if retry => std::thread::sleep(Duration::from_millis(50)),
            Err(Refused::Unavailable) if retry => {
                unacknowledged += 1;
                client = RawClient::connect(socket);
            }
            other => return (other, unacknowledged),
        }
    }
}

use KeydOperation as Op;
use KeydOutcome as Out;

/// The log phases of one key-state change that took `unacknowledged`
/// refused attempts before it was performed with `outcome` (kvno
/// `kvno`): each refused attempt is its intent and a `NotPerformed`
/// outcome (A-86), then the performed one's intent and keyd's outcome.
/// `intent_kvno` is the kvno an intent names (`retire_kvno` only).
fn change_phases(
    op: KeydOperation,
    unacknowledged: usize,
    intent_kvno: Option<u32>,
    outcome: KeydOutcome,
    kvno: Option<u32>,
) -> Vec<(KeydOperation, KeydOutcome, Option<u32>)> {
    let mut phases = Vec::new();
    for _ in 0..unacknowledged {
        phases.push((op, Out::Intent, intent_kvno));
        phases.push((op, Out::NotPerformed, intent_kvno));
    }
    phases.push((op, Out::Intent, intent_kvno));
    phases.push((op, outcome, kvno));
    phases
}

/// docs/questions/Q-346 (A-86: "auditd up ⇒ intent then outcome records,
/// both in the verified log, in order"), with every Admin key-state change
/// (docs/10 §7): each answered with its true result, and in the verified
/// log each intent (outcome `Intent`, reason `None`, the handle, the kvno a
/// `retire_kvno` names) directly followed by keyd's own outcome. Since
/// A-102 (docs/52 §4.2, §4.5) each execution runs on a decision dird
/// (Role::Ldap, the grant socket) registered first — a loosening, so its
/// intent and outcome come first — and the execution's intent names the
/// decided handle and kvno from keyd's table. A refused
/// authorization (Admin may not `set_secret`, docs/10 §2) is one record and
/// no intent. On a loaded machine an acknowledgement may still miss the
/// budget: such an attempt is answered `Unavailable`, retried, and must be
/// in the log as its intent and a `NotPerformed` outcome — the true results
/// (kvno 2 after the rotation, …) show it changed nothing (Q-415).
#[test]
fn every_admin_change_is_intent_then_outcome_in_the_verified_log() {
    let dir = TempDir::new();
    let logs = auditd_support::TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let auditd = start_auditd(&dir, uid, &logs.path().join("audit.log"), true);
    let keyd = start_keyd(&dir, uid, Role::Admin, generous());
    let socket = keyd.socket.clone();
    let (answer, created) = call_until_performed(&socket, &create_key(0xA1));
    assert!(
        matches!(&answer, Ok(Answer::CreateKey(Ok(kvno))) if *kvno == Kvno::INITIAL),
        "{answer:?}"
    );
    let registered = |call: &Call| {
        let (answer, unacknowledged) = call_until_performed(&grant_socket(&dir), call);
        assert!(
            matches!(&answer, Ok(Answer::RegisterDecision(Ok(())))),
            "{answer:?}"
        );
        unacknowledged
    };
    let decided_rotate = registered(&decide(
        1,
        DecidedOperation::RotateKey {
            handle: handle(0xA1),
        },
    ));
    let rotate = Call::RotateKey {
        decision: DecisionId::new(1),
    };
    let (answer, rotated) = call_until_performed(&socket, &rotate);
    assert!(
        matches!(&answer, Ok(Answer::RotateKey(Ok(kvno))) if *kvno == Kvno::new(2)),
        "{answer:?}"
    );
    let decided_retire = registered(&decide(
        2,
        DecidedOperation::RetireKvno {
            handle: handle(0xA1),
            kvno: Kvno::INITIAL,
        },
    ));
    let retire = Call::RetireKvno {
        decision: DecisionId::new(2),
    };
    let (answer, retired) = call_until_performed(&socket, &retire);
    assert!(
        matches!(&answer, Ok(Answer::RetireKvno(Ok(())))),
        "{answer:?}"
    );
    let decided_destroy = registered(&decide(
        3,
        DecidedOperation::DestroyKeySet {
            principal: handle(0xA1).principal,
        },
    ));
    let destroy = Call::DestroyKeySet {
        decision: DecisionId::new(3),
    };
    let (answer, destroyed) = call_until_performed(&socket, &destroy);
    assert!(
        matches!(&answer, Ok(Answer::DestroyKeySet(Ok(())))),
        "{answer:?}"
    );
    // An authorization refusal takes no intent and never waits.
    let answer = RawClient::connect(&socket).call(&set_secret(0xA1));
    assert!(
        matches!(&answer, Some(Ok(Answer::SetSecret(Err(Error::Denied))))),
        "{answer:?}"
    );
    // keyd waits (bounded) for auditd to acknowledge its window at stop.
    keyd.stop().unwrap();
    assert!(matches!(auditd.stop(), Some(Ok(()))));

    let records = keyd_records(&verified_log(&logs.path().join("audit.log")), uid);
    let mut expected = change_phases(Op::CreateKey, created, None, Out::Success, Some(1));
    expected.extend(change_phases(
        Op::RegisterDecision,
        decided_rotate,
        None,
        Out::Success,
        None,
    ));
    expected.extend(change_phases(
        Op::RotateKey,
        rotated,
        None,
        Out::Success,
        Some(2),
    ));
    expected.extend(change_phases(
        Op::RegisterDecision,
        decided_retire,
        Some(1),
        Out::Success,
        Some(1),
    ));
    expected.extend(change_phases(
        Op::RetireKvno,
        retired,
        Some(1),
        Out::Success,
        Some(1),
    ));
    expected.extend(change_phases(
        Op::RegisterDecision,
        decided_destroy,
        None,
        Out::Success,
        None,
    ));
    expected.extend(change_phases(
        Op::DestroyKeySet,
        destroyed,
        None,
        Out::Success,
        Some(2),
    ));
    expected.push((Op::SetSecret, Out::Denied, None));
    assert_eq!(phases(&records), expected);
    for phase in records
        .iter()
        .filter(|r| matches!(r.result, Out::Intent | Out::NotPerformed))
    {
        assert_eq!(phase.reason, KeydReason::None);
        assert_eq!(phase.caller_uid, uid);
        assert_eq!(phase.principal, Some([0xA1; 16]));
        assert_eq!(phase.purpose, Some(KeyPurposeCode::PrincipalLongterm));
        // A-102 (docs/52 §4.5): every phase but create_key's names its
        // decision, and the decision's approvers.
        if phase.op != Op::CreateKey {
            assert!(phase.decision.is_some(), "{:?}", phase.op);
            assert_eq!(phase.approvers, Some([[0x01; 16], [0x02; 16]]));
        }
    }
    assert_eq!(
        records.last().map(|r| r.reason),
        Some(KeydReason::RoleNotPermitted)
    );
}

/// The same for the Directory's `set_secret` (docs/10 §6): kvno 1, then
/// kvno 2, each preceded by its acknowledged intent in the verified log
/// (and, on a loaded machine, by any attempt refused for a late
/// acknowledgement — its intent and `NotPerformed`; Q-415). Since task A15a
/// each `set_secret` follows the decision dird would register (Role::Ldap
/// on the same keyd; A-102: `register_decision`): a loosening, so its intent
/// too is acknowledged first and the log holds its intent, its outcome, then
/// the `set_secret` pair (docs/questions/Q-452).
#[test]
fn set_secret_is_intent_then_outcome_in_the_verified_log() {
    let dir = TempDir::new();
    let logs = auditd_support::TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let auditd = start_auditd(&dir, uid, &logs.path().join("audit.log"), true);
    let keyd = start_keyd(&dir, uid, Role::Directory, generous());
    let mut expected = Vec::new();
    for kvno in [1, 2] {
        let (answer, unacknowledged) =
            call_until_performed(&grant_socket(&dir), &grant(u64::from(kvno), 0xB0));
        assert!(
            matches!(&answer, Ok(Answer::RegisterDecision(Ok(())))),
            "{answer:?}"
        );
        expected.extend(change_phases(
            Op::RegisterDecision,
            unacknowledged,
            None,
            Out::Success,
            None,
        ));
        let (answer, unacknowledged) = call_until_performed(&keyd.socket, &set_secret(0xB0));
        assert!(
            matches!(&answer, Ok(Answer::SetSecret(Ok(set))) if *set == Kvno::new(kvno)),
            "{answer:?}"
        );
        expected.extend(change_phases(
            Op::SetSecret,
            unacknowledged,
            None,
            Out::Success,
            Some(kvno),
        ));
    }
    keyd.stop().unwrap();
    assert!(matches!(auditd.stop(), Some(Ok(()))));
    let records = keyd_records(&verified_log(&logs.path().join("audit.log")), uid);
    assert_eq!(phases(&records), expected);
}

/// docs/questions/Q-346 (A-86: "auditd down ⇒ `create_key` / `set_secret`
/// answer `Unavailable` and a later successful ceremony proves nothing was
/// created (kvno 1, not 2)"). auditd is reachable but never acknowledges
/// (its writer does not run): with the short production budget the change
/// is answered `Refused::Unavailable` after the budget, and keyd does not run
/// it. Then a healthy auditd takes over: the same change is served at the
/// **initial** kvno — no refused attempt created / set anything — and the
/// verified log holds, in order, the first intent and its `NotPerformed`
/// outcome, the same pair for every further attempt the short budget did
/// not see acknowledged (a loaded machine — module documentation), then the
/// last intent and keyd's outcome.
fn unacknowledged_intent_changes_nothing(role: Role, call: &Call, op: KeydOperation) {
    let dir = TempDir::new();
    let logs = auditd_support::TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let stuck = start_auditd(&dir, uid, &logs.path().join("stuck.log"), false);
    // A set_secret passes keyd's authorization step only with its grant
    // (task A15a) — already in keyd here, since this auditd acknowledges no
    // grant intent either.
    let keyd = if op == Op::SetSecret {
        start_keyd_granted(&dir, uid, IntentAckBudget::PRODUCTION)
    } else {
        start_keyd(&dir, uid, role, IntentAckBudget::PRODUCTION)
    };
    let started = Instant::now();
    assert_eq!(
        RawClient::connect(&keyd.socket).call(call),
        Some(Err(Refused::Unavailable))
    );
    assert!(started.elapsed() >= INTENT_ACK_BUDGET);

    let _ = stuck.stop();
    let auditd = start_auditd(&dir, uid, &logs.path().join("audit.log"), true);
    let (answer, unacknowledged) = call_until_performed(&keyd.socket, call);
    match answer {
        Ok(Answer::CreateKey(Ok(kvno)) | Answer::SetSecret(Ok(kvno))) => {
            assert_eq!(kvno, Kvno::INITIAL, "no refused attempt changed anything");
        }
        other => panic!("{other:?}"),
    }
    keyd.stop().unwrap();
    assert!(matches!(auditd.stop(), Some(Ok(()))));
    let records = keyd_records(&verified_log(&logs.path().join("audit.log")), uid);
    let expected = change_phases(op, 1 + unacknowledged, None, Out::Success, Some(1));
    assert_eq!(phases(&records), expected);
}

#[test]
fn an_unacknowledged_create_key_is_unavailable_and_creates_nothing() {
    unacknowledged_intent_changes_nothing(Role::Admin, &create_key(0xA1), Op::CreateKey);
}

#[test]
fn an_unacknowledged_set_secret_is_unavailable_and_sets_nothing() {
    unacknowledged_intent_changes_nothing(Role::Directory, &set_secret(0xB0), Op::SetSecret);
}

/// docs/questions/Q-415 (decision A-93's follow-up F5): the budget is the
/// daemon's parameter, end to end — with an auditd that never acknowledges,
/// a daemon given the ceiling waits at least the ceiling (longer than the
/// production budget) before it answers `Unavailable`.
#[test]
fn the_daemons_budget_parameter_bounds_the_wait() {
    let dir = TempDir::new();
    let logs = auditd_support::TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let stuck = start_auditd(&dir, uid, &logs.path().join("stuck.log"), false);
    let keyd = start_keyd(&dir, uid, Role::Admin, generous());
    let started = Instant::now();
    assert_eq!(
        RawClient::connect(&keyd.socket).call(&create_key(0xA1)),
        Some(Err(Refused::Unavailable))
    );
    assert!(started.elapsed() >= MAX_INTENT_ACK_BUDGET);
    assert!(MAX_INTENT_ACK_BUDGET > INTENT_ACK_BUDGET);
    // auditd first, so keyd's stop does not wait for acknowledgements.
    let _ = stuck.stop();
    keyd.stop().unwrap();
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
                AuditRequest::Ping => (AuditReply::Pong(ipc_audit::EventSource::Keyd), false),
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
    let logs = auditd_support::TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let vanishing = VanishingAuditd::start(&dir.join("a.sock"));
    let keyd = start_keyd(&dir, uid, Role::Admin, generous());
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
    let auditd = start_auditd(&dir, uid, &logs.path().join("audit.log"), true);
    let base = logs.path().join("audit.log");
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

// ---- a lost outcome, counted in the log (decision A-88) ----------------------

/// The window summaries among the sender records of `records`, each with its
/// position in the log (docs/50 §3.2: every one from the one peer uid).
fn window_summaries(records: &[Record], uid: u32) -> Vec<(usize, WindowSummary)> {
    records
        .iter()
        .enumerate()
        .filter(|(_, record)| record.source != Source::Auditd)
        .filter_map(|(at, record)| {
            assert_eq!(record.source_uid, uid, "the sender's peer uid");
            match decode_event(&record.payload).unwrap() {
                EventBody::WindowSummary(summary) => Some((at, summary)),
                _ => None,
            }
        })
        .collect()
}

/// Decision A-88 (docs/questions/Q-366 option (a), Q-395): the outcome
/// record of a key-state change keyd **performed** but whose record could not
/// be committed is counted into keyd's next `WindowSummary`, and that summary
/// reaches auditd's verified log. The lost outcome is forced as tier 1 does
/// (`an_unrecorded_outcome_answers_the_true_result_and_is_counted`): keyd's
/// sink already holds the most records it keeps when the change runs (four
/// `ping` records left by the builder — injected, no seam in the daemon), so
/// the change's own record overflows. The reply is the true result (kvno 1);
/// the verified log holds the acknowledged intent, the four left-over
/// records, no `CreateKey` outcome, and — after the intent — one window
/// summary counting exactly one unrecorded outcome, with nothing refused or
/// suppressed (a lost outcome is not a refusal). An attempt refused for a
/// late acknowledgement on a loaded machine (retried; Q-415) leaves its
/// intent and `NotPerformed` before all of this — keyd did not run it, so
/// the four records are still in its sink for the performed attempt.
#[test]
fn a_lost_outcome_is_counted_in_a_window_summary_of_the_verified_log() {
    let dir = TempDir::new();
    let logs = auditd_support::TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let auditd = start_auditd(&dir, uid, &logs.path().join("audit.log"), true);
    let caller = CallerId {
        uid,
        role: Role::Admin,
    };
    let mut params = params(&dir, CallerMap::new(&[(uid, Role::Admin)]).unwrap(), uid);
    params.intent_ack_budget = generous();
    let keyd = Daemon::start(params, SystemClock, move |started: &KerberosTime| {
        let mut keyd = development_keyd(realm())(started)?;
        for _ in 0..MAX_RECORDS_PER_OPERATION {
            let _ = keyd.ping(&caller, started);
        }
        Ok(keyd)
    })
    .unwrap();
    let (answer, unacknowledged) = call_until_performed(&keyd.socket, &create_key(0xA1));
    assert!(
        matches!(&answer, Ok(Answer::CreateKey(Ok(kvno))) if *kvno == Kvno::INITIAL),
        "{answer:?}"
    );
    // keyd waits (bounded) for auditd to acknowledge its window at stop.
    keyd.stop().unwrap();
    assert!(matches!(auditd.stop(), Some(Ok(()))));

    let log = verified_log(&logs.path().join("audit.log"));
    let records = keyd_records(&log, uid);
    let performed = 2 * unacknowledged;
    assert_eq!(records.len(), performed + 1 + MAX_RECORDS_PER_OPERATION);
    let mut expected = change_phases(Op::CreateKey, unacknowledged, None, Out::Success, None);
    expected.pop(); // the performed attempt's outcome is the lost one
    assert_eq!(phases(&records)[..=performed], expected[..]);
    assert!(records[performed + 1..].iter().all(|r| r.op == Op::Ping));
    assert!(
        !records
            .iter()
            .any(|r| r.op == Op::CreateKey && !matches!(r.result, Out::Intent | Out::NotPerformed)),
        "the change's own outcome is lost"
    );
    let intent_at = log
        .iter()
        .rposition(|record| {
            record.source != Source::Auditd
                && matches!(
                    decode_event(&record.payload),
                    Ok(EventBody::Keyd(r)) if r.result == Out::Intent
                )
        })
        .unwrap();
    let summaries = window_summaries(&log, uid);
    assert_eq!(summaries.len(), 1, "{summaries:?}");
    let (at, summary) = summaries[0];
    assert!(at > intent_at, "the summary follows the intent");
    assert_eq!(
        summary,
        WindowSummary {
            suppressed_noise: 0,
            refused_gating: 0,
            unrecorded_outcomes: 1,
        }
    );
}
