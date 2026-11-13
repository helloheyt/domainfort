//! Tier 1 (docs/50 §9: "in-process … without sockets"): the engine with the
//! real development keyd, the A-57 gate and the bounded queue, fed request
//! bodies built with the keyd channel's own codec (crates/ipc-keyd). The
//! socket side is tier 2 (tests/socket_server.rs, tests/kdc_flow.rs).
//!
//! Every test names its source. Every value is constructed by hand for these
//! tests; no vector comes from any other implementation.

use crate::audit::AuditGate;
use crate::clock::{kerberos_time_from_unix, Clock};
use crate::engine::{Engine, EngineError, SubmitError};
use crate::startup::development_keyd;
use ipc::{decode_reply, encode_frame, Direction, Refused, Reply};
use ipc_audit::{
    decode_event, Ack, EventBody, KeydOperation, KeydOutcome, KeydReason, WindowConfig,
};
use ipc_keyd::{Answer, Call, KeydReply, Password, KEYD_CHANNEL};
use ipc_keyd_server::Dispatch;
use keyd::{
    kerberos_time_seconds, AuthnError, CallerId, Error, InMemoryKeyStore, KeyHandle, KeyPurpose,
    Operation, OsEntropy, PrincipalBinding, PrincipalId, Role,
};
use krb_proto::{KerberosString, KerberosTime, PaData, PrincipalName, Realm};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const KDC: CallerId = CallerId {
    uid: 803,
    role: Role::Kdc,
};
const DIRECTORY: CallerId = CallerId {
    uid: 806,
    role: Role::Directory,
};
const ADMIN: CallerId = CallerId {
    uid: 807,
    role: Role::Admin,
};

const REALM: &str = "EXAMPLE.ORG";

fn realm() -> Realm {
    Realm::new(REALM).unwrap()
}

fn binding(component: &str) -> PrincipalBinding {
    PrincipalBinding::new(
        realm(),
        PrincipalName {
            name_type: 1,
            name_string: vec![KerberosString::new(component).unwrap()],
        },
    )
}

fn client(octet: u8) -> KeyHandle {
    KeyHandle::new(
        PrincipalId::from_bytes([octet; 16]),
        KeyPurpose::PrincipalLongterm,
    )
}

/// Unix seconds of a calendar time (the inverse of the clock's conversion).
fn unix(t: &KerberosTime) -> u64 {
    let epoch = kerberos_time_seconds(&KerberosTime::new(1970, 1, 1, 0, 0, 0).unwrap());
    u64::try_from(kerberos_time_seconds(t) - epoch).unwrap()
}

/// The start time of the engines below: 2026-11-13T10:00:00Z.
fn t0() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap()
}

fn at(offset_secs: u64) -> KerberosTime {
    kerberos_time_from_unix(unix(&t0()) + offset_secs).unwrap()
}

/// A clock the test sets; `None` plays an unreadable clock.
#[derive(Clone)]
struct TestClock(Arc<Mutex<Option<KerberosTime>>>);

impl TestClock {
    fn at(time: KerberosTime) -> TestClock {
        TestClock(Arc::new(Mutex::new(Some(time))))
    }
    fn set(&self, time: Option<KerberosTime>) {
        *self.0.lock().unwrap() = time;
    }
}

impl Clock for TestClock {
    fn now(&self) -> Option<KerberosTime> {
        *self.0.lock().unwrap()
    }
}

type TestEngine = Engine<InMemoryKeyStore, OsEntropy, TestClock>;

/// The daemon's engine (development keyd, kernel CSPRNG) on a test clock,
/// with a gate that counts auditd as reachable when `reachable`.
fn engine(
    clock: &TestClock,
    window: WindowConfig,
    reachable: bool,
) -> (TestEngine, Arc<AuditGate>) {
    let gate = Arc::new(AuditGate::new(window));
    gate.set_reachable(reachable);
    let engine =
        Engine::start(clock.clone(), Arc::clone(&gate), development_keyd(realm())).unwrap();
    (engine, gate)
}

/// A request body (envelope + payload, no length prefix) of `call`.
fn body(call: &Call) -> Vec<u8> {
    let wire = call.to_wire().unwrap();
    encode_frame(KEYD_CHANNEL, Direction::Request, &wire)
        .unwrap()
        .body()
        .to_vec()
}

/// The reply of `outcome` to an `operation` request: keyd's answer or the
/// shared refusal, and whether the connection stays open.
fn reply(operation: Operation, outcome: &Dispatch) -> (Result<Answer, Refused>, bool) {
    let (frame, stays_open) = match outcome {
        Dispatch::Reply(frame) => (frame, true),
        Dispatch::ReplyAndClose(frame) => (frame, false),
        Dispatch::Close => panic!("closed without a reply"),
    };
    let decoded = match decode_reply::<KeydReply>(KEYD_CHANNEL, frame.body()).unwrap() {
        Reply::Message(message) => Ok(Answer::from_wire(operation, message).unwrap()),
        Reply::Refused(refused) => Err(refused),
    };
    (decoded, stays_open)
}

fn serve(
    engine: &mut TestEngine,
    caller: CallerId,
    call: &Call,
) -> (Result<Answer, Refused>, bool) {
    let operation = call.operation();
    reply(operation, &engine.handle(caller, &body(call)))
}

fn verify_preauth() -> Call {
    Call::VerifyPreauth {
        client: client(0xA1),
        padata: PaData {
            padata_type: 2,
            padata_value: vec![0x30, 0x00],
        },
        armor: None,
    }
}

fn create_key(octet: u8, name: &str) -> Call {
    Call::CreateKey {
        handle: client(octet),
        binding: binding(name),
    }
}

fn set_secret() -> Call {
    Call::SetSecret {
        handle: client(0xB0),
        binding: binding("bob"),
        password: Password::new(Zeroizing::new(String::from("tier-one-test-pass"))),
        salt: String::from("EXAMPLE.ORGbob"),
    }
}

/// The keyd records in the window, in order (acknowledging nothing).
fn window_records(gate: &AuditGate) -> Vec<ipc_audit::KeydRecord> {
    let batch = gate.with_window(|window| window.next_batch()).unwrap();
    let records = batch
        .map(|append| {
            append
                .events()
                .iter()
                .filter_map(|event| match decode_event(event.as_bytes()).unwrap() {
                    EventBody::Keyd(record) => Some(*record),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    gate.with_window(|window| window.connection_lost());
    records
}

/// Acknowledge every event in the window, as auditd would.
fn acknowledge_all(gate: &AuditGate) {
    while let Some(append) = gate.with_window(|window| window.next_batch()).unwrap() {
        let ack = Ack {
            through_seq: append.last_seq(),
            head_hash: [0; 32],
        };
        gate.acknowledge(&ack).unwrap();
    }
}

/// docs/50 R50-3, §3.4 (`Ping`: every mapped role; `DescribeConfig`: Kdc,
/// Ldap); docs/10 §7א: a mapped Kdc caller is served both, with keyd's own
/// configuration (the realm of the daemon's keyd).
#[test]
fn a_mapped_kdc_caller_can_ping_and_describe_config() {
    let clock = TestClock::at(t0());
    let (mut engine, _gate) = engine(&clock, WindowConfig::DEFAULT, true);
    let (answer, open) = serve(&mut engine, KDC, &Call::Ping);
    assert!(matches!(answer, Ok(Answer::Ping(Ok(())))));
    assert!(open);
    match serve(&mut engine, KDC, &Call::DescribeConfig).0 {
        Ok(Answer::DescribeConfig(Ok(description))) => assert_eq!(description.realm, realm()),
        other => panic!("{other:?}"),
    }
}

/// docs/10 §2 (I2: the role check over the compile-time capability table is
/// keyd's) and docs/50 §3.2 (the role comes from the uid map, never the
/// request): a wrong-role call gets keyd's authorization result — the
/// uniform `Denied` — and keyd's record says why (`RoleNotPermitted`).
#[test]
fn a_wrong_role_gets_keyds_authorization_result() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &Call::DescribeConfig).0,
        Ok(Answer::DescribeConfig(Err(Error::Denied)))
    ));
    assert!(matches!(
        serve(&mut engine, KDC, &set_secret()).0,
        Ok(Answer::SetSecret(Err(Error::Denied)))
    ));
    let records = window_records(&gate);
    let set_secret_record = records
        .iter()
        .find(|r| r.op == KeydOperation::SetSecret)
        .unwrap();
    assert_eq!(set_secret_record.reason, KeydReason::RoleNotPermitted);
    assert_eq!(set_secret_record.caller_uid, KDC.uid);
}

/// RFC 4120 §3.2.3; docs/50 R50-5, R50-6; A-62: the hold-down runs on keyd's
/// OWN clock from the engine's construction — held while `now ≤ started +
/// 2 × 300 s` (the library default skew), served from `started + 601`.
/// Directory / Admin and `ping` are not held.
#[test]
fn the_hold_down_runs_on_keyds_clock_from_construction() {
    let clock = TestClock::at(t0());
    let (mut engine, _gate) = engine(&clock, WindowConfig::DEFAULT, true);
    clock.set(Some(at(600)));
    assert!(matches!(
        serve(&mut engine, KDC, &verify_preauth()).0,
        Ok(Answer::VerifyPreauth(Err(AuthnError::Unavailable)))
    ));
    assert!(matches!(
        serve(&mut engine, ADMIN, &create_key(0xA1, "alice")).0,
        Ok(Answer::CreateKey(Ok(_)))
    ));
    assert!(matches!(
        serve(&mut engine, KDC, &Call::Ping).0,
        Ok(Answer::Ping(Ok(())))
    ));
    clock.set(Some(at(601)));
    // Served: the hold-down is over; the bogus PA-DATA is keyd's uniform
    // refusal, not `Unavailable`.
    assert!(matches!(
        serve(&mut engine, KDC, &verify_preauth()).0,
        Ok(Answer::VerifyPreauth(Err(AuthnError::Denied)))
    ));
}

/// docs/50 R50-5 (keyd reads its own clock) and AGENTS.md §6 (fail closed):
/// an unreadable clock is `Refused::Unavailable`, then close; keyd is not
/// called (no record).
#[test]
fn an_unreadable_clock_refuses() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    clock.set(None);
    let (answer, open) = serve(&mut engine, KDC, &Call::Ping);
    assert_eq!(answer.err(), Some(Refused::Unavailable));
    assert!(!open);
    assert_eq!(gate.outstanding(), 0);
}

/// docs/50 R50-5 / R50-6: no hold-down start, no engine.
#[test]
fn an_unreadable_clock_at_start_is_an_error() {
    let clock = TestClock::at(t0());
    clock.set(None);
    let gate = Arc::new(AuditGate::new(WindowConfig::DEFAULT));
    let result = Engine::start(clock, gate, development_keyd(realm()));
    assert!(matches!(result.err(), Some(EngineError::Clock)));
}

/// docs/questions/Q-218 (A-57), Q-252 item 8 (A-64) and the task brief:
/// with auditd unreachable every gating operation is refused `Busy` and
/// keyd does not run it (no record, no key created); `ping` and
/// `describe_config` are still served.
#[test]
fn audit_unreachable_refuses_gating_operations_but_serves_ping_and_describe() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, false);
    clock.set(Some(at(601)));
    for (caller, call) in [
        (KDC, verify_preauth()),
        (DIRECTORY, set_secret()),
        (ADMIN, create_key(0xA1, "alice")),
    ] {
        let (answer, open) = serve(&mut engine, caller, &call);
        assert_eq!(answer.err(), Some(Refused::Busy), "{:?}", call.operation());
        assert!(open, "Busy keeps the connection");
    }
    assert!(matches!(
        serve(&mut engine, KDC, &Call::Ping).0,
        Ok(Answer::Ping(Ok(())))
    ));
    assert!(matches!(
        serve(&mut engine, KDC, &Call::DescribeConfig).0,
        Ok(Answer::DescribeConfig(Ok(_)))
    ));
    // keyd ran none of the refused operations: the window holds only the
    // (noise) records of ping and describe_config.
    let ops: Vec<_> = window_records(&gate).iter().map(|r| r.op).collect();
    assert_eq!(ops, [KeydOperation::Ping, KeydOperation::DescribeConfig]);
    // auditd back: the same create_key is served.
    gate.set_reachable(true);
    assert!(matches!(
        serve(&mut engine, ADMIN, &create_key(0xA1, "alice")).0,
        Ok(Answer::CreateKey(Ok(_)))
    ));
}

/// docs/questions/Q-218 (A-57), Q-252 item 8 (A-64: "full window → no
/// issuance, keyd answers Busy"): a full window of unacknowledged events
/// refuses gating operations; an acknowledgement frees the slots.
#[test]
fn a_full_window_refuses_gating_operations_until_acknowledged() {
    let clock = TestClock::at(t0());
    let window = WindowConfig::new(2, 1).unwrap();
    let (mut engine, gate) = engine(&clock, window, true);
    assert!(matches!(
        serve(&mut engine, ADMIN, &create_key(0xA1, "alice")).0,
        Ok(Answer::CreateKey(Ok(_)))
    ));
    assert!(matches!(
        serve(&mut engine, ADMIN, &create_key(0xA2, "carol")).0,
        Ok(Answer::CreateKey(Ok(_)))
    ));
    assert_eq!(
        serve(&mut engine, ADMIN, &create_key(0xA3, "dave")).0.err(),
        Some(Refused::Busy)
    );
    assert!(matches!(
        serve(&mut engine, ADMIN, &Call::Ping).0,
        Ok(Answer::Ping(Ok(())))
    ));
    acknowledge_all(&gate);
    assert!(matches!(
        serve(&mut engine, ADMIN, &create_key(0xA3, "dave")).0,
        Ok(Answer::CreateKey(Ok(_)))
    ));
}

/// docs/10 I8 (one record per operation) and docs/questions/Q-252 item 9
/// (commit, then reply): when a gating operation's reply leaves, its record
/// is already in the window — the converted keyd record, field for field.
#[test]
fn a_gating_operation_commits_its_record_before_the_reply() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    assert!(matches!(
        serve(&mut engine, ADMIN, &create_key(0xA1, "alice")).0,
        Ok(Answer::CreateKey(Ok(_)))
    ));
    assert_eq!(gate.outstanding(), 1);
    let records = window_records(&gate);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].op, KeydOperation::CreateKey);
    assert_eq!(records[0].caller_uid, ADMIN.uid);
    assert_eq!(records[0].result, KeydOutcome::Success);
    assert_eq!(records[0].principal, Some([0xA1; 16]));
}

/// docs/50 §3.3 (bad prefix / wrong magic / unknown kind ⇒ close without a
/// reply; malformed ⇒ `Malformed` + close) — the refusal rules of
/// `ipc_keyd_server::dispatch` — and keyd is not called (no record).
#[test]
fn rejected_bodies_follow_the_dispatch_rules() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    let mut wrong_magic = body(&Call::Ping);
    wrong_magic[0] ^= 0xFF;
    assert!(matches!(engine.handle(KDC, &wrong_magic), Dispatch::Close));
    let mut trailing = body(&Call::Ping);
    trailing.push(0x00);
    let (answer, open) = reply(Operation::Ping, &engine.handle(KDC, &trailing));
    assert_eq!(answer.err(), Some(Refused::Malformed));
    assert!(!open);
    assert_eq!(gate.outstanding(), 0);
}

/// The disposition and frame of `outcome`, for comparison.
fn shape(outcome: &Dispatch) -> (u8, Vec<u8>) {
    match outcome {
        Dispatch::Reply(frame) => (0, frame.as_bytes().to_vec()),
        Dispatch::ReplyAndClose(frame) => (1, frame.as_bytes().to_vec()),
        Dispatch::Close => (2, Vec::new()),
    }
}

/// docs/questions/Q-260 item 3: with the gate open, the engine answers
/// exactly as `ipc_keyd_server::dispatch` does on an equal keyd at the same
/// `now` — same disposition, same octets — for served calls, keyd's own
/// refusals and rejected bodies.
#[test]
fn the_engine_answers_as_dispatch_does() {
    let clock = TestClock::at(t0());
    let (mut engine, _gate) = engine(&clock, WindowConfig::DEFAULT, true);
    let mut keyd = development_keyd(realm())(&t0()).unwrap();
    clock.set(Some(at(601)));
    let mut wrong_magic = body(&Call::Ping);
    wrong_magic[0] ^= 0xFF;
    let mut trailing = body(&Call::Ping);
    trailing.push(0x00);
    let cases = [
        (KDC, body(&Call::Ping)),
        (KDC, body(&Call::DescribeConfig)),
        (DIRECTORY, body(&Call::DescribeConfig)),
        (KDC, body(&set_secret())),
        (KDC, body(&verify_preauth())),
        (ADMIN, body(&Call::Ping)),
        (KDC, wrong_magic),
        (KDC, trailing),
    ];
    for (caller, request) in cases {
        let expected = ipc_keyd_server::dispatch(&mut keyd, caller, at(601), &request);
        assert_eq!(shape(&engine.handle(caller, &request)), shape(&expected));
    }
}

/// A clock whose first reading is immediate and every later reading waits
/// for a permit, announcing that it is waiting.
struct GatedClock {
    time: KerberosTime,
    first: Mutex<bool>,
    permits: Mutex<std_mpsc::Receiver<()>>,
    waiting: Mutex<std_mpsc::Sender<()>>,
}

impl Clock for GatedClock {
    fn now(&self) -> Option<KerberosTime> {
        let mut first = self.first.lock().unwrap();
        if *first {
            *first = false;
            return Some(self.time);
        }
        drop(first);
        self.waiting.lock().unwrap().send(()).unwrap();
        self.permits.lock().unwrap().recv().unwrap();
        Some(self.time)
    }
}

/// docs/50 R50-7, §3.6 ("queue full ⇒ immediate `Busy` — not
/// `spawn_blocking`"): with the engine busy on one request and the queue
/// (capacity 1) holding another, the next submission is `Busy` at once; the
/// queued ones are still served.
#[test]
fn a_full_queue_answers_busy_at_once() {
    let (permit, permits) = std_mpsc::channel();
    let (waiting, engine_waits) = std_mpsc::channel();
    let clock = GatedClock {
        time: t0(),
        first: Mutex::new(true),
        permits: Mutex::new(permits),
        waiting: Mutex::new(waiting),
    };
    let gate = Arc::new(AuditGate::new(WindowConfig::DEFAULT));
    gate.set_reachable(true);
    let engine = Engine::start(clock, gate, development_keyd(realm())).unwrap();
    let (handle, thread) = engine.spawn(1, || {}).unwrap();
    let ping = || Zeroizing::new(body(&Call::Ping));

    let first = handle.submit(KDC, ping()).unwrap();
    engine_waits.recv().unwrap(); // the engine holds the first request
    let second = handle.submit(KDC, ping()).unwrap(); // fills the queue
    assert_eq!(handle.submit(KDC, ping()).err(), Some(SubmitError::Busy));

    permit.send(()).unwrap();
    engine_waits.recv().unwrap();
    permit.send(()).unwrap();
    for pending in [first, second] {
        let outcome = pending.blocking_recv().unwrap();
        assert!(matches!(
            reply(Operation::Ping, &outcome).0,
            Ok(Answer::Ping(Ok(())))
        ));
    }
    drop(handle);
    thread.join().unwrap();
}

/// docs/50 R50-7 and the task's "drain the queue and close": requests queued
/// when the last handle goes are still answered; then the thread ends and
/// runs its exit hook (which the daemon uses to stop itself).
#[test]
fn queued_requests_are_answered_before_the_engine_ends() {
    let clock = TestClock::at(t0());
    let (engine, _gate) = engine(&clock, WindowConfig::DEFAULT, true);
    let (exited, on_exit) = std_mpsc::channel();
    let (handle, thread) = engine
        .spawn(8, move || {
            let _ = exited.send(());
        })
        .unwrap();
    let pending: Vec<_> = (0..4)
        .map(|_| {
            handle
                .submit(KDC, Zeroizing::new(body(&Call::Ping)))
                .unwrap()
        })
        .collect();
    drop(handle);
    for receiver in pending {
        let outcome = receiver.blocking_recv().unwrap();
        assert!(matches!(
            reply(Operation::Ping, &outcome).0,
            Ok(Answer::Ping(Ok(())))
        ));
    }
    thread.join().unwrap();
    on_exit.recv().unwrap();
}

/// AGENTS.md §6 (bounded queues; tokio's `mpsc::channel` panics on 0):
/// a capacity of 0 or above the ceiling is refused.
#[test]
fn queue_capacity_is_bounded() {
    for capacity in [0, crate::engine::MAX_QUEUE_CAPACITY + 1] {
        let clock = TestClock::at(t0());
        let (engine, _gate) = engine(&clock, WindowConfig::DEFAULT, true);
        assert!(matches!(
            engine.spawn(capacity, || {}).err(),
            Some(EngineError::QueueCapacity)
        ));
    }
}
