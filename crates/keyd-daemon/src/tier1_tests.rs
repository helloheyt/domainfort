//! Tier 1 (docs/50 §9: "in-process … without sockets"): the engine with the
//! real development keyd, the A-57 gate and the bounded queue, fed request
//! bodies built with the keyd channel's own codec (crates/ipc-keyd). The
//! socket side is tier 2 (tests/socket_server.rs, tests/kdc_flow.rs).
//!
//! Every test names its source. Every value is constructed by hand for these
//! tests; no vector comes from any other implementation.
//!
//! Tier 1 plays the audit client itself at the window level — the gate
//! opened or closed, a batch taken and inspected without being delivered,
//! a connection lost, auditd's `Ack` fed at a chosen moment. The shared
//! gate's link side is crate-private to ipc-audit-client (a product reaches it only
//! through the one audit client, task R15b, docs/questions/Q-630), so these
//! tests reach it through ipc-audit's dev-only `test_seams` (feature
//! `test-seams`, enabled only by this crate's dev-dependency).

use crate::audit::AuditGate;
use crate::clock::Clock;
use crate::engine::{
    Engine, EngineError, IntentAckBudget, IntentAckBudgetOutOfRange, SubmitError,
    INTENT_ACK_BUDGET, MAX_INTENT_ACK_BUDGET,
};
use crate::startup::development_keyd;
use ipc::{decode_reply, encode_frame, Direction, Refused, Reply};
use ipc_audit::{
    decode_event, Ack, EventBody, KeyPurposeCode, KeydOperation, KeydOutcome, KeydReason,
    KeydRecord, KeydRole, WindowConfig,
};
use ipc_audit_client::test_seams;
use ipc_audit_client::LinkedGate;
use ipc_keyd::{Answer, Call, KeydReply, Password, KEYD_CHANNEL};
use ipc_keyd_server::{Dispatch, KeyStateIntent};
use keyd::{
    requires_acknowledged_intent, AccountKind, AuthnError, CallerId, DecidedOperation, DecisionId,
    Error, InMemoryKeyStore, KeyHandle, KeyPurpose, Kvno, Operation, OsEntropy, PrincipalBinding,
    PrincipalId, Role, SetSecretTarget, MAX_INITIAL_SECRET_GRANT_SECS, MAX_SET_SECRET_GRANT_SECS,
};
use krb_proto::{
    kerberos_time_from_unix, kerberos_time_to_unix, KerberosString, KerberosTime, PaData,
    PrincipalName, Realm,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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
const LDAP: CallerId = CallerId {
    uid: 808,
    role: Role::Ldap,
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

/// Unix seconds of a calendar time (the inverse of the clock's conversion,
/// krb-proto's one pair — Q-995).
fn unix(t: &KerberosTime) -> u64 {
    kerberos_time_to_unix(t).unwrap()
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

/// The budget of the tier-1 engines whose key-state calls wait for
/// [`AutoAck`]: the ceiling, so that a loaded machine scheduling the
/// acknowledging thread late does not turn the wait into `Unavailable`
/// (docs/questions/Q-415). The test that times the expiry uses
/// [`IntentAckBudget::PRODUCTION`].
fn generous() -> IntentAckBudget {
    IntentAckBudget::new(MAX_INTENT_ACK_BUDGET).unwrap()
}

/// The daemon's engine (development keyd, kernel CSPRNG) on a test clock,
/// with a gate that counts auditd as reachable when `reachable`, and the
/// [`generous`] budget.
fn engine(
    clock: &TestClock,
    window: WindowConfig,
    reachable: bool,
) -> (TestEngine, Arc<AuditGate>) {
    engine_with(clock, window, reachable, generous())
}

/// As [`engine`], with `budget`.
fn engine_with(
    clock: &TestClock,
    window: WindowConfig,
    reachable: bool,
    budget: IntentAckBudget,
) -> (TestEngine, Arc<AuditGate>) {
    let gate = Arc::new(AuditGate::new(window));
    test_seams::set_reachable(gate.audit_gate(), reachable);
    let engine = Engine::start(
        clock.clone(),
        Arc::clone(&gate),
        budget,
        development_keyd(realm()),
    )
    .unwrap();
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
    serve_queued(engine, caller, call, Instant::now())
}

/// As [`serve`], for a request queued at `queued`.
fn serve_queued(
    engine: &mut TestEngine,
    caller: CallerId,
    call: &Call,
    queued: Instant,
) -> (Result<Answer, Refused>, bool) {
    let operation = call.operation();
    reply(operation, &engine.handle(caller, &body(call), queued))
}

/// A queueing time whose budget has already run out — for any budget up to
/// the ceiling (now, if the monotonic clock cannot go back that far — the
/// test then waits the budget).
fn long_ago() -> Instant {
    let now = Instant::now();
    now.checked_sub(MAX_INTENT_ACK_BUDGET * 2).unwrap_or(now)
}

/// auditd for tier 1: a thread that acknowledges every batch of the window
/// as soon as it is committed — what the audit client does with a healthy
/// auditd (docs/50 §8.1) — and keeps the keyd records it acknowledged, in
/// order. Stopped on drop.
struct AutoAck {
    stop: Arc<AtomicBool>,
    acked: Arc<Mutex<Vec<KeydRecord>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl AutoAck {
    fn start(gate: &Arc<AuditGate>) -> AutoAck {
        let stop = Arc::new(AtomicBool::new(false));
        let acked = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (gate, stop, acked) = (Arc::clone(gate), Arc::clone(&stop), Arc::clone(&acked));
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let Some(append) = test_seams::next_batch(gate.audit_gate()) else {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    };
                    for event in append.events() {
                        if let EventBody::Keyd(record) = decode_event(event.as_bytes()).unwrap() {
                            acked.lock().unwrap().push(*record);
                        }
                    }
                    let ack = Ack {
                        through_seq: append.last_seq(),
                        head_hash: [0; 32],
                    };
                    test_seams::acknowledge(gate.audit_gate(), &ack).unwrap();
                }
            })
        };
        AutoAck {
            stop,
            acked,
            thread: Some(thread),
        }
    }

    /// The keyd records acknowledged so far, in order.
    fn records(&self) -> Vec<KeydRecord> {
        self.acked.lock().unwrap().clone()
    }

    /// The records once `count` were acknowledged (bounded wait).
    fn wait_for(&self, count: usize) -> Vec<KeydRecord> {
        let start = Instant::now();
        while self.records().len() < count && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(2));
        }
        self.records()
    }
}

impl Drop for AutoAck {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
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
        password: Password::new(Zeroizing::new(String::from("Ridge-Toucan-68-Umbel"))),
        salt: String::from("EXAMPLE.ORGbob"),
    }
}

/// A user's key target, with the salt its `set_secret` presents (N4,
/// A-102).
fn target(octet: u8, name: &str) -> SetSecretTarget {
    SetSecretTarget {
        handle: client(octet),
        binding: binding(name),
        salt: format!("{REALM}{name}"),
    }
}

/// The two approvers of these tests' key-operation decisions (dual control,
/// docs/51 §5.6).
fn approvers() -> Vec<PrincipalId> {
    vec![
        PrincipalId::from_bytes([0x01; 16]),
        PrincipalId::from_bytes([0x02; 16]),
    ]
}

/// The set-secret decision dird would register for [`set_secret`]'s key
/// set (task A15a; A-102: keyd refuses Directory's `set_secret` without
/// one), put straight into the engine's keyd as Role::Ldap at `now`, its
/// record drained — so each test's window holds only what the test serves.
fn grant_bob(engine: &mut TestEngine, now: &KerberosTime) {
    let keyd = engine.keyd_mut();
    keyd.register_decision(
        &LDAP,
        DecisionId::new(1),
        &DecidedOperation::SetSecret {
            kind: AccountKind::User,
            targets: vec![target(0xB0, "bob")],
        },
        &[],
        MAX_SET_SECRET_GRANT_SECS,
        now,
    )
    .unwrap();
    let _ = keyd.audit_sink_mut().take();
}

/// The ceremony's `grant_set_secret` for one user key target (Role::Admin,
/// before the seal; a loosening: intent first, task A15a, A-102).
fn grant(octet: u8, name: &str) -> Call {
    Call::GrantSetSecret {
        kind: AccountKind::User,
        targets: vec![target(octet, name)],
        lifetime_secs: MAX_INITIAL_SECRET_GRANT_SECS,
    }
}

/// dird's `register_decision` (Role::Ldap; a loosening — intent first,
/// A-102, docs/52 §4.5).
fn register(id: u64, operation: DecidedOperation, approvers: Vec<PrincipalId>) -> Call {
    Call::RegisterDecision {
        id: DecisionId::new(id),
        operation,
        approvers,
        lifetime_secs: 900,
    }
}

/// A randomized `Service` key set in the engine's keyd, created straight in
/// it as the ceremony would (Role::Admin, before the seal), its record
/// drained.
fn service_key(engine: &mut TestEngine, octet: u8, now: &KerberosTime) -> KeyHandle {
    let handle = KeyHandle::new(PrincipalId::from_bytes([octet; 16]), KeyPurpose::Service);
    let keyd = engine.keyd_mut();
    keyd.create_key(&ADMIN, &handle, &binding("svc"), now)
        .unwrap();
    let _ = keyd.audit_sink_mut().take();
    handle
}

/// A gating Directory call that changes no key state (docs/10 §6): a
/// candidate password for a handle with no key set — keyd's uniform
/// `Denied` (since A-102 at the capability table: no role holds
/// `verify_secret`, docs/52 R4).
fn verify_secret(octet: u8) -> Call {
    Call::VerifySecret {
        handle: client(octet),
        candidate: Password::new(Zeroizing::new(String::from("tier-one-candidate"))),
    }
}

/// The keyd records in the window, in order (acknowledging nothing).
fn window_records(gate: &AuditGate) -> Vec<ipc_audit::KeydRecord> {
    let batch = test_seams::next_batch(gate.audit_gate());
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
    test_seams::connection_lost(gate.audit_gate());
    records
}

/// Acknowledge every event in the window, as auditd would.
fn acknowledge_all(gate: &AuditGate) {
    while let Some(append) = test_seams::next_batch(gate.audit_gate()) {
        let ack = Ack {
            through_seq: append.last_seq(),
            head_hash: [0; 32],
        };
        test_seams::acknowledge(gate.audit_gate(), &ack).unwrap();
    }
}

/// docs/50 R50-3, §3.4 (`Ping`: every mapped role; `DescribeConfig`: Kdc,
/// Ldap); docs/10 §7a; docs/questions/Q-351 (A-87): a mapped Kdc caller is
/// served both, with keyd's own configuration (the realm of the daemon's
/// keyd) and the caller role the daemon resolved for it (Kdc).
#[test]
fn a_mapped_kdc_caller_can_ping_and_describe_config() {
    let clock = TestClock::at(t0());
    let (mut engine, _gate) = engine(&clock, WindowConfig::DEFAULT, true);
    let (answer, open) = serve(&mut engine, KDC, &Call::Ping);
    assert!(matches!(answer, Ok(Answer::Ping(Ok(keyd::Role::Kdc)))));
    assert!(open);
    match serve(&mut engine, KDC, &Call::DescribeConfig).0 {
        Ok(Answer::DescribeConfig(Ok(described))) => {
            assert_eq!(described.description.realm, realm());
            assert_eq!(described.caller_role, KDC.role);
        }
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
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    // create_key is a key-state change: auditd acknowledges its intent
    // (A-86).
    let _auditd = AutoAck::start(&gate);
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
        Ok(Answer::Ping(Ok(keyd::Role::Kdc)))
    ));
    clock.set(Some(at(601)));
    // Served: the hold-down is over; the bogus PA-DATA is keyd's uniform
    // refusal, not `Unavailable`.
    assert!(matches!(
        serve(&mut engine, KDC, &verify_preauth()).0,
        Ok(Answer::VerifyPreauth(Err(AuthnError::Denied)))
    ));
}

/// docs/50 R50-5 (keyd reads its own clock) and docs/CLEAN-ROOM.md (fail closed):
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
    let result = Engine::start(
        clock,
        gate,
        IntentAckBudget::PRODUCTION,
        development_keyd(realm()),
    );
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
        Ok(Answer::Ping(Ok(keyd::Role::Kdc)))
    ));
    assert!(matches!(
        serve(&mut engine, KDC, &Call::DescribeConfig).0,
        Ok(Answer::DescribeConfig(Ok(_)))
    ));
    // keyd ran none of the refused operations: the window holds only the
    // (noise) records of ping and describe_config — no intent either (A-86:
    // nothing is recorded for a change refused at the gate).
    let ops: Vec<_> = window_records(&gate).iter().map(|r| r.op).collect();
    assert_eq!(ops, [KeydOperation::Ping, KeydOperation::DescribeConfig]);
    // auditd back: the same create_key and set_secret are served, each at
    // the initial kvno — the refused attempts created nothing.
    test_seams::set_reachable(gate.audit_gate(), true);
    let _auditd = AutoAck::start(&gate);
    assert!(matches!(
        serve(&mut engine, ADMIN, &create_key(0xA1, "alice")).0,
        Ok(Answer::CreateKey(Ok(kvno))) if kvno == Kvno::INITIAL
    ));
    grant_bob(&mut engine, &at(601));
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &set_secret()).0,
        Ok(Answer::SetSecret(Ok(kvno))) if kvno == Kvno::INITIAL
    ));
}

/// docs/questions/Q-218 (A-57), Q-252 item 8 (A-64: "full window → no
/// issuance, keyd answers Busy"): a full window of unacknowledged events
/// refuses gating operations; an acknowledgement frees the slots. A
/// key-state change needs two free slots (intent and outcome, A-86): with
/// one left it is refused `Busy`, and nothing of it is recorded.
#[test]
fn a_full_window_refuses_gating_operations_until_acknowledged() {
    let clock = TestClock::at(t0());
    let window = WindowConfig::new(2, 1).unwrap();
    let (mut engine, gate) = engine(&clock, window, true);
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &verify_secret(0xA1)).0,
        Ok(Answer::VerifySecret(Err(Error::Denied)))
    ));
    // One slot left: a key-state change cannot have both of its records.
    assert_eq!(
        serve(&mut engine, ADMIN, &create_key(0xA3, "dave")).0.err(),
        Some(Refused::Busy)
    );
    assert_eq!(gate.outstanding(), 1);
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &verify_secret(0xA2)).0,
        Ok(Answer::VerifySecret(Err(Error::Denied)))
    ));
    assert_eq!(
        serve(&mut engine, DIRECTORY, &verify_secret(0xA3)).0.err(),
        Some(Refused::Busy)
    );
    assert!(matches!(
        serve(&mut engine, ADMIN, &Call::Ping).0,
        Ok(Answer::Ping(Ok(keyd::Role::Admin)))
    ));
    acknowledge_all(&gate);
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &verify_secret(0xA3)).0,
        Ok(Answer::VerifySecret(Err(Error::Denied)))
    ));
    acknowledge_all(&gate);
    let _auditd = AutoAck::start(&gate);
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
        serve(&mut engine, DIRECTORY, &verify_secret(0xA1)).0,
        Ok(Answer::VerifySecret(Err(Error::Denied)))
    ));
    assert_eq!(gate.outstanding(), 1);
    let records = window_records(&gate);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].op, KeydOperation::VerifySecret);
    assert_eq!(records[0].caller_uid, DIRECTORY.uid);
    assert_eq!(records[0].result, KeydOutcome::Denied);
    assert_eq!(records[0].principal, Some([0xA1; 16]));
    // docs/52 §7 R4, Q-465 (A-102): refused at the capability table — the
    // Directory role no longer holds `verify_secret`.
    assert_eq!(records[0].reason, KeydReason::RoleNotPermitted);
}

/// The intent record of a key-state change as keyd-daemon writes it
/// (A-86): keyd's layout, the caller and the handle, reason `None`.
fn assert_intent(record: &KeydRecord, op: KeydOperation, caller: CallerId, octet: u8) {
    assert_eq!(record.op, op);
    assert_eq!(record.result, KeydOutcome::Intent);
    assert_eq!(record.reason, KeydReason::None);
    assert_eq!(record.caller_uid, caller.uid);
    assert_eq!(record.principal, Some([octet; 16]));
    assert_eq!(record.purpose, Some(KeyPurposeCode::PrincipalLongterm));
    assert_eq!(record.secondary, None);
}

/// docs/questions/Q-346 (A-86): a key-state change keyd admits is written
/// to the window as its intent, acknowledged, and only then run; its outcome
/// is keyd's own record with the true result (here kvno 1, then kvno 2 for a
/// second password), committed before the reply leaves. Intent, outcome,
/// intent, outcome — in that order.
#[test]
fn a_key_state_change_is_intent_then_outcome() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    let auditd = AutoAck::start(&gate);
    grant_bob(&mut engine, &t0());
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &set_secret()).0,
        Ok(Answer::SetSecret(Ok(kvno))) if kvno == Kvno::INITIAL
    ));
    grant_bob(&mut engine, &t0());
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &set_secret()).0,
        Ok(Answer::SetSecret(Ok(kvno))) if kvno == Kvno::new(2)
    ));
    let records = auditd.wait_for(4);
    assert_eq!(records.len(), 4);
    assert_intent(&records[0], KeydOperation::SetSecret, DIRECTORY, 0xB0);
    assert_eq!(records[0].kvno, None, "keyd has not chosen a kvno yet");
    assert_eq!(records[0].caller_role, KeydRole::Directory);
    assert_eq!(records[1].op, KeydOperation::SetSecret);
    assert_eq!(records[1].result, KeydOutcome::Success);
    assert_eq!(records[1].kvno, Some(1));
    assert_intent(&records[2], KeydOperation::SetSecret, DIRECTORY, 0xB0);
    assert_eq!(records[3].result, KeydOutcome::Success);
    assert_eq!(records[3].kvno, Some(2));
    assert_eq!(gate.unrecorded_outcomes(), 0);
}

/// docs/questions/Q-346 (A-86: "intent not acknowledged ⇒ Unavailable, and
/// nothing changed"): auditd reachable but not acknowledging — the change is
/// answered `Refused::Unavailable` (then close) and keyd does not run it;
/// the window holds its intent and a `NotPerformed` outcome. Once auditd
/// acknowledges, the same calls are served at the initial kvno: nothing was
/// created or set before. The first refusal waits the real production
/// budget (the timed wait — nothing acknowledges, so it is deterministic);
/// the others were queued long ago.
#[test]
fn an_unacknowledged_intent_is_unavailable_and_changes_nothing() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine_with(
        &clock,
        WindowConfig::DEFAULT,
        true,
        IntentAckBudget::PRODUCTION,
    );
    let started = Instant::now();
    let (answer, open) = serve(&mut engine, ADMIN, &create_key(0xA1, "alice"));
    assert_eq!(answer.err(), Some(Refused::Unavailable));
    assert!(!open);
    assert!(
        started.elapsed() >= INTENT_ACK_BUDGET,
        "the wait is the budget"
    );
    // dird's grant (task A15a): the set_secret passes keyd's authorization
    // step, so it takes the intent path; not run, it does not consume it.
    grant_bob(&mut engine, &t0());
    let (answer, _) = serve_queued(&mut engine, DIRECTORY, &set_secret(), long_ago());
    assert_eq!(answer.err(), Some(Refused::Unavailable));
    let records = window_records(&gate);
    let phases: Vec<_> = records.iter().map(|r| (r.op, r.result)).collect();
    assert_eq!(
        phases,
        [
            (KeydOperation::CreateKey, KeydOutcome::Intent),
            (KeydOperation::CreateKey, KeydOutcome::NotPerformed),
            (KeydOperation::SetSecret, KeydOutcome::Intent),
            (KeydOperation::SetSecret, KeydOutcome::NotPerformed),
        ]
    );
    assert_intent(&records[0], KeydOperation::CreateKey, ADMIN, 0xA1);
    assert_eq!(records[1].reason, KeydReason::None);
    assert_eq!(records[1].principal, Some([0xA1; 16]));
    // auditd acknowledges now: the earlier records go first, then the calls
    // are served — at kvno 1, so neither earlier attempt ran.
    let auditd = AutoAck::start(&gate);
    assert!(matches!(
        serve(&mut engine, ADMIN, &create_key(0xA1, "alice")).0,
        Ok(Answer::CreateKey(Ok(kvno))) if kvno == Kvno::INITIAL
    ));
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &set_secret()).0,
        Ok(Answer::SetSecret(Ok(kvno))) if kvno == Kvno::INITIAL
    ));
    let acked: Vec<_> = auditd
        .wait_for(8)
        .iter()
        .map(|r| (r.op, r.result))
        .collect();
    assert_eq!(
        acked[4..],
        [
            (KeydOperation::CreateKey, KeydOutcome::Intent),
            (KeydOperation::CreateKey, KeydOutcome::Success),
            (KeydOperation::SetSecret, KeydOutcome::Intent),
            (KeydOperation::SetSecret, KeydOutcome::Success),
        ]
    );
    assert_eq!(gate.unrecorded_outcomes(), 0);
}

/// docs/10 §2 (an authorization refusal is `Denied`, recorded) and the A-86
/// brief ("keep them audited exactly as today, with no new waiting"): a
/// key-state call refused at keyd's authorization step gets one record —
/// keyd's `Denied` / `RoleNotPermitted` — and no intent, without waiting
/// for any acknowledgement (no auditd acknowledges here).
#[test]
fn an_authorization_refusal_is_one_record_without_intent() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    let started = Instant::now();
    assert!(matches!(
        serve(&mut engine, KDC, &create_key(0xA1, "alice")).0,
        Ok(Answer::CreateKey(Err(Error::Denied)))
    ));
    assert!(matches!(
        serve(&mut engine, ADMIN, &set_secret()).0,
        Ok(Answer::SetSecret(Err(Error::Denied)))
    ));
    assert!(started.elapsed() < generous().get(), "no wait");
    let records = window_records(&gate);
    let phases: Vec<_> = records.iter().map(|r| (r.op, r.result, r.reason)).collect();
    assert_eq!(
        phases,
        [
            (
                KeydOperation::CreateKey,
                KeydOutcome::Denied,
                KeydReason::RoleNotPermitted
            ),
            (
                KeydOperation::SetSecret,
                KeydOutcome::Denied,
                KeydReason::RoleNotPermitted
            ),
        ]
    );
}

/// docs/questions/Q-346 (A-86: "if the outcome cannot be recorded, the
/// intent record already documents the attempt, the caller gets the true
/// result, and the gap is surfaced"): keyd's sink already holds the most
/// records it keeps when a change runs (four records left in it by the
/// builder — injected, no seam in the daemon), so the change's own record
/// overflows. The reply is still the true result (kvno 1), the gap is
/// counted, and the intent was acknowledged before.
#[test]
fn an_unrecorded_outcome_answers_the_true_result_and_is_counted() {
    let clock = TestClock::at(t0());
    let gate = Arc::new(AuditGate::new(WindowConfig::DEFAULT));
    test_seams::set_reachable(gate.audit_gate(), true);
    let mut engine = Engine::start(
        clock.clone(),
        Arc::clone(&gate),
        generous(),
        |started: &KerberosTime| {
            let mut keyd = development_keyd(realm())(started)?;
            for _ in 0..crate::audit::MAX_RECORDS_PER_OPERATION {
                let _ = keyd.ping(&KDC, started);
            }
            Ok(keyd)
        },
    )
    .unwrap();
    let auditd = AutoAck::start(&gate);
    assert!(matches!(
        serve(&mut engine, ADMIN, &create_key(0xA1, "alice")).0,
        Ok(Answer::CreateKey(Ok(kvno))) if kvno == Kvno::INITIAL
    ));
    assert_eq!(gate.unrecorded_outcomes(), 1);
    let records = auditd.wait_for(5);
    assert_intent(&records[0], KeydOperation::CreateKey, ADMIN, 0xA1);
    // The four left-over records follow; the change's own outcome is lost.
    assert!(records[1..].iter().all(|r| r.op == KeydOperation::Ping));
    assert!(!records
        .iter()
        .any(|r| r.op == KeydOperation::CreateKey && r.result == KeydOutcome::Success));
    // The key set exists all the same (the change happened): a second
    // create_key is refused, KeyExists.
    assert!(matches!(
        serve(&mut engine, ADMIN, &create_key(0xA1, "alice")).0,
        Ok(Answer::CreateKey(Err(Error::Denied)))
    ));
}

/// The Kerberos path is unchanged by A-86: an issuance-side operation takes
/// no intent and does not wait (nothing acknowledges here), as before.
/// Spec: docs/questions/Q-346 (A-86: "issuance is not affected"); A-57.
#[test]
fn issuance_operations_take_no_intent_and_do_not_wait() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    clock.set(Some(at(601)));
    let started = Instant::now();
    assert!(matches!(
        serve(&mut engine, KDC, &verify_preauth()).0,
        Ok(Answer::VerifyPreauth(Err(AuthnError::Denied)))
    ));
    assert!(started.elapsed() < generous().get(), "no wait");
    let records = window_records(&gate);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].result, KeydOutcome::Denied);
}

/// The daemon's call classification agrees with keyd's
/// (`requires_acknowledged_intent`: the key-state calls and, since task
/// A15a, the grant; since A-102 the decision registration) for every such
/// call and a sample of the others, and an intent carries exactly what
/// keyd's own record carries before keyd resolves anything: the kvno and
/// approvers of a decision being registered, its id, nothing secret. An
/// **execution** of a decision names only its id: `KeyStateIntent::of` has
/// no intent for it — the engine builds it from keyd's table
/// ([`KeyStateIntent::decided`]). Spec: docs/10 §6, §7, §10; A-86; docs/52
/// §4.5.
#[test]
fn key_state_intents_match_keyd_and_carry_no_secret() {
    let id = DecisionId::new(0x55);
    let calls = [
        set_secret(),
        create_key(0xA1, "alice"),
        Call::RotateKey { decision: id },
        Call::RotateKrbtgt { decision: id },
        Call::RetireKvno { decision: id },
        Call::DestroyKeySet { decision: id },
        grant(0xA2, "carol"),
        register(
            0x55,
            DecidedOperation::RetireKvno {
                handle: client(0xA1),
                kvno: Kvno::new(4),
            },
            approvers(),
        ),
        verify_secret(0xA1),
        verify_preauth(),
        Call::DescribeConfig,
        Call::Ping,
        Call::SealCeremony,
        Call::ListDestroyDecisions { after: None },
    ];
    for call in &calls {
        let intent = KeyStateIntent::of(ADMIN, t0(), call);
        if call.decision().is_some() {
            assert!(requires_acknowledged_intent(call.operation()));
            assert!(intent.is_none(), "{:?}", call.operation());
            continue;
        }
        assert_eq!(
            intent.is_some(),
            requires_acknowledged_intent(call.operation()),
            "{:?}",
            call.operation()
        );
        let Some(intent) = intent else { continue };
        assert_eq!(intent.op(), call.operation());
        let EventBody::Keyd(record) = intent.event(KeydOutcome::Intent) else {
            panic!("a keyd record");
        };
        let registration = matches!(call, Call::RegisterDecision { .. });
        assert_eq!(record.result, KeydOutcome::Intent);
        assert_eq!(record.reason, KeydReason::None);
        assert_eq!(record.secondary, None);
        assert_eq!(record.kvno, registration.then_some(4));
        assert_eq!(
            record.approvers,
            registration.then_some([[0x01; 16], [0x02; 16]])
        );
        assert_eq!(record.decision, registration.then_some(0x55));
        let EventBody::Keyd(not_performed) = intent.event(KeydOutcome::NotPerformed) else {
            panic!("a keyd record");
        };
        assert_eq!(
            *not_performed,
            KeydRecord {
                result: KeydOutcome::NotPerformed,
                ..*record
            }
        );
    }
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
    assert!(matches!(
        engine.handle(KDC, &wrong_magic, Instant::now()),
        Dispatch::Close
    ));
    let mut trailing = body(&Call::Ping);
    trailing.push(0x00);
    let (answer, open) = reply(
        Operation::Ping,
        &engine.handle(KDC, &trailing, Instant::now()),
    );
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
        assert_eq!(
            shape(&engine.handle(caller, &request, Instant::now())),
            shape(&expected)
        );
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
    test_seams::set_reachable(gate.audit_gate(), true);
    let engine = Engine::start(
        clock,
        gate,
        IntentAckBudget::PRODUCTION,
        development_keyd(realm()),
    )
    .unwrap();
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
            Ok(Answer::Ping(Ok(_)))
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
            Ok(Answer::Ping(Ok(_)))
        ));
    }
    thread.join().unwrap();
    on_exit.recv().unwrap();
}

/// docs/CLEAN-ROOM.md (bounded queues; tokio's `mpsc::channel` panics on 0):
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

/// docs/questions/Q-415 (decision A-93's follow-up F5): the intent budget is
/// a daemon parameter whose range is checked when it is built — more than
/// zero, at most the ceiling. Production is exactly the A-88 constant (1 s,
/// half the keyd client's 2 s deadline, docs/50 §3.6, Q-365), and the
/// ceiling is that production client deadline itself.
#[test]
fn the_intent_budget_is_bounded_when_built() {
    assert_eq!(IntentAckBudget::PRODUCTION.get(), INTENT_ACK_BUDGET);
    assert_eq!(INTENT_ACK_BUDGET, Duration::from_secs(1));
    assert_eq!(MAX_INTENT_ACK_BUDGET, ipc_keyd::DEFAULT_DEADLINE);
    assert_eq!(
        IntentAckBudget::new(INTENT_ACK_BUDGET),
        Ok(IntentAckBudget::PRODUCTION)
    );
    for accepted in [Duration::from_nanos(1), MAX_INTENT_ACK_BUDGET] {
        assert_eq!(
            IntentAckBudget::new(accepted).map(IntentAckBudget::get),
            Ok(accepted)
        );
    }
    for refused in [
        Duration::ZERO,
        MAX_INTENT_ACK_BUDGET + Duration::from_nanos(1),
        Duration::MAX,
    ] {
        assert_eq!(
            IntentAckBudget::new(refused),
            Err(IntentAckBudgetOutOfRange)
        );
    }
}

/// Task A15a (docs/questions/Q-452 items 1, 3) as amended by A-102 (docs/52
/// §4.2, §4.4): the ceremony's grant (Role::Admin, before the seal) loosens
/// keyd, so the daemon has its intent acknowledged before keyd registers it
/// (intent, then keyd's own outcome); the `set_secret` it allows is intent
/// and outcome as before; a second `set_secret` finds no grant and is
/// refused at keyd's authorization step — one record (`Denied`, `NoGrant`),
/// no intent. A grant from Role::Directory or Role::Ldap (dird registers
/// decisions instead) is refused the same way.
#[test]
fn a_grant_takes_the_intent_path_and_a_set_secret_without_one_does_not() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    let auditd = AutoAck::start(&gate);
    assert!(matches!(
        serve(&mut engine, ADMIN, &grant(0xB0, "bob")).0,
        Ok(Answer::GrantSetSecret(Ok(())))
    ));
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &set_secret()).0,
        Ok(Answer::SetSecret(Ok(kvno))) if kvno == Kvno::INITIAL
    ));
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &set_secret()).0,
        Ok(Answer::SetSecret(Err(Error::Denied)))
    ));
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &grant(0xB0, "bob")).0,
        Ok(Answer::GrantSetSecret(Err(Error::Denied)))
    ));
    assert!(matches!(
        serve(&mut engine, LDAP, &grant(0xB0, "bob")).0,
        Ok(Answer::GrantSetSecret(Err(Error::Denied)))
    ));
    let records = auditd.wait_for(7);
    let phases: Vec<_> = records.iter().map(|r| (r.op, r.result, r.reason)).collect();
    assert_eq!(
        phases,
        [
            (
                KeydOperation::GrantSetSecret,
                KeydOutcome::Intent,
                KeydReason::None
            ),
            (
                KeydOperation::GrantSetSecret,
                KeydOutcome::Success,
                KeydReason::None
            ),
            (
                KeydOperation::SetSecret,
                KeydOutcome::Intent,
                KeydReason::None
            ),
            (
                KeydOperation::SetSecret,
                KeydOutcome::Success,
                KeydReason::None
            ),
            (
                KeydOperation::SetSecret,
                KeydOutcome::Denied,
                KeydReason::NoGrant
            ),
            (
                KeydOperation::GrantSetSecret,
                KeydOutcome::Denied,
                KeydReason::RoleNotPermitted
            ),
            (
                KeydOperation::GrantSetSecret,
                KeydOutcome::Denied,
                KeydReason::RoleNotPermitted
            ),
        ]
    );
    assert_eq!(records[0].caller_role, KeydRole::Admin);
    assert_eq!(records[0].principal, Some([0xB0; 16]));
    assert_eq!(records[4].caller_role, KeydRole::Directory);
    assert_eq!(records[6].caller_role, KeydRole::Ldap);
    assert_eq!(gate.unrecorded_outcomes(), 0);
}

/// Task A15a (docs/questions/Q-452 item 2), for dird's set-secret decision
/// (A-102, docs/52 §4.2): a computer decision's intent names its first key
/// target as the record's handle and its second (the Service key set) as
/// the secondary key — as keyd's own record of it — and no binding; an
/// unacknowledged registration intent is `NotPerformed` and registers
/// nothing.
#[test]
fn a_computer_decision_intent_carries_its_second_target() {
    let host = KeyHandle::new(PrincipalId::from_bytes([0xC7; 16]), KeyPurpose::Service);
    let call = register(
        7,
        DecidedOperation::SetSecret {
            kind: AccountKind::Computer,
            targets: vec![
                target(0xC7, "ws7$"),
                SetSecretTarget {
                    handle: host,
                    binding: binding("host-ws7"),
                    salt: String::from("EXAMPLE.ORGhostws7"),
                },
            ],
        },
        Vec::new(),
    );
    let intent = KeyStateIntent::of(LDAP, t0(), &call).unwrap();
    let EventBody::Keyd(record) = intent.event(KeydOutcome::Intent) else {
        panic!("a keyd record");
    };
    assert_eq!(record.op, KeydOperation::RegisterDecision);
    assert_eq!(record.principal, Some([0xC7; 16]));
    assert_eq!(record.purpose, Some(KeyPurposeCode::PrincipalLongterm));
    assert_eq!(record.decision, Some(7));
    let secondary = record.secondary.unwrap();
    assert_eq!(secondary.principal, [0xC7; 16]);
    assert_eq!(secondary.purpose, KeyPurposeCode::Service);
    assert_eq!(secondary.kvno, None);

    // Not acknowledged in time: Unavailable, NotPerformed, nothing decided.
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine_with(
        &clock,
        WindowConfig::DEFAULT,
        true,
        IntentAckBudget::PRODUCTION,
    );
    let (answer, _) = serve_queued(&mut engine, LDAP, &call, long_ago());
    assert_eq!(answer.err(), Some(Refused::Unavailable));
    let phases: Vec<_> = window_records(&gate)
        .iter()
        .map(|r| (r.op, r.result))
        .collect();
    assert_eq!(
        phases,
        [
            (KeydOperation::RegisterDecision, KeydOutcome::Intent),
            (KeydOperation::RegisterDecision, KeydOutcome::NotPerformed),
        ]
    );
    let _auditd = AutoAck::start(&gate);
    let ws7 = Call::SetSecret {
        handle: client(0xC7),
        binding: binding("ws7$"),
        password: Password::new(Zeroizing::new(String::from("Ridge-Toucan-68-Umbel"))),
        salt: String::from("EXAMPLE.ORGws7$"),
    };
    assert!(matches!(
        serve(&mut engine, DIRECTORY, &ws7).0,
        Ok(Answer::SetSecret(Err(Error::Denied)))
    ));
}

/// A-102 (docs/52 §4.2, §4.5; Q-460): dird's `register_decision` takes the
/// intent path — the intent names the decided key set, the decision id and
/// the approvers **from the request** (the registration is what is being
/// recorded) — then keyd's own outcome; an unacknowledged registration is
/// `Unavailable` and registers nothing: the execution it would allow is
/// then refused at keyd's authorization step (`NoDecision`, one record).
#[test]
fn a_decision_registration_takes_the_intent_path() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine_with(
        &clock,
        WindowConfig::DEFAULT,
        true,
        IntentAckBudget::PRODUCTION,
    );
    let service = service_key(&mut engine, 0x5E, &t0());
    let call = register(
        21,
        DecidedOperation::RotateKey { handle: service },
        approvers(),
    );
    let (answer, _) = serve_queued(&mut engine, LDAP, &call, long_ago());
    assert_eq!(answer.err(), Some(Refused::Unavailable));
    let records = window_records(&gate);
    let phases: Vec<_> = records.iter().map(|r| (r.op, r.result)).collect();
    assert_eq!(
        phases,
        [
            (KeydOperation::RegisterDecision, KeydOutcome::Intent),
            (KeydOperation::RegisterDecision, KeydOutcome::NotPerformed),
        ]
    );
    assert_eq!(records[0].decision, Some(21));
    assert_eq!(records[0].approvers, Some([[0x01; 16], [0x02; 16]]));
    assert_eq!(records[0].principal, Some([0x5E; 16]));
    assert_eq!(records[0].purpose, Some(KeyPurposeCode::Service));
    assert_eq!(records[0].caller_role, KeydRole::Ldap);

    let auditd = AutoAck::start(&gate);
    // Nothing was registered: the execution has no decision.
    assert!(matches!(
        serve(
            &mut engine,
            ADMIN,
            &Call::RotateKey {
                decision: DecisionId::new(21)
            }
        )
        .0,
        Ok(Answer::RotateKey(Err(Error::Denied)))
    ));
    // Registered now: intent, then keyd's outcome carrying the id.
    assert!(matches!(
        serve(&mut engine, LDAP, &call).0,
        Ok(Answer::RegisterDecision(Ok(())))
    ));
    let acked = auditd.wait_for(5);
    let phases: Vec<_> = acked[2..]
        .iter()
        .map(|r| (r.op, r.result, r.reason))
        .collect();
    assert_eq!(
        phases,
        [
            (
                KeydOperation::RotateKey,
                KeydOutcome::Denied,
                KeydReason::NoDecision
            ),
            (
                KeydOperation::RegisterDecision,
                KeydOutcome::Intent,
                KeydReason::None
            ),
            (
                KeydOperation::RegisterDecision,
                KeydOutcome::Success,
                KeydReason::None
            ),
        ]
    );
    assert_eq!(acked[4].decision, Some(21));
    assert_eq!(acked[4].approvers, Some([[0x01; 16], [0x02; 16]]));
    assert_eq!(gate.unrecorded_outcomes(), 0);
}

/// A-102 (docs/52 §3.10 (a), §4.2, §4.5): an execution names only its
/// decision id. For a pending decision the intent record carries the id,
/// the decided key set and the approvers **from keyd's table**, then keyd's
/// outcome (kvno 2); presented again, the recorded result is returned — one
/// record, reason `DecisionReplayed`, no intent and no second rotation; an
/// unknown id is refused at keyd's authorization step — one record
/// (`Denied`, `NoDecision`), no intent, no wait.
#[test]
fn an_execution_takes_its_intent_from_keyds_table() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    let service = service_key(&mut engine, 0x5E, &t0());
    {
        let keyd = engine.keyd_mut();
        keyd.register_decision(
            &LDAP,
            DecisionId::new(31),
            &DecidedOperation::RotateKey { handle: service },
            &approvers(),
            900,
            &t0(),
        )
        .unwrap();
        let _ = keyd.audit_sink_mut().take();
    }
    // An unknown id: one record, no intent, no wait (nothing acknowledges
    // yet).
    let started = Instant::now();
    assert!(matches!(
        serve(
            &mut engine,
            ADMIN,
            &Call::RotateKey {
                decision: DecisionId::new(999)
            }
        )
        .0,
        Ok(Answer::RotateKey(Err(Error::Denied)))
    ));
    assert!(started.elapsed() < generous().get(), "no wait");
    let refused = window_records(&gate);
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].result, KeydOutcome::Denied);
    assert_eq!(refused[0].reason, KeydReason::NoDecision);
    assert_eq!(refused[0].decision, Some(999));
    acknowledge_all(&gate);

    let auditd = AutoAck::start(&gate);
    let rotate = Call::RotateKey {
        decision: DecisionId::new(31),
    };
    assert!(matches!(
        serve(&mut engine, ADMIN, &rotate).0,
        Ok(Answer::RotateKey(Ok(kvno))) if kvno == Kvno::new(2)
    ));
    // Presented again: the recorded result, nothing run.
    assert!(matches!(
        serve(&mut engine, ADMIN, &rotate).0,
        Ok(Answer::RotateKey(Ok(kvno))) if kvno == Kvno::new(2)
    ));
    let records = auditd.wait_for(3);
    let phases: Vec<_> = records
        .iter()
        .map(|r| (r.op, r.result, r.reason, r.kvno))
        .collect();
    assert_eq!(
        phases,
        [
            (
                KeydOperation::RotateKey,
                KeydOutcome::Intent,
                KeydReason::None,
                None
            ),
            (
                KeydOperation::RotateKey,
                KeydOutcome::Success,
                KeydReason::None,
                Some(2)
            ),
            (
                KeydOperation::RotateKey,
                KeydOutcome::Success,
                KeydReason::DecisionReplayed,
                Some(2)
            ),
        ]
    );
    for record in &records {
        assert_eq!(record.decision, Some(31));
        assert_eq!(record.principal, Some([0x5E; 16]));
        assert_eq!(record.purpose, Some(KeyPurposeCode::Service));
        assert_eq!(record.approvers, Some([[0x01; 16], [0x02; 16]]));
        assert_eq!(record.caller_role, KeydRole::Admin);
    }
    assert_eq!(gate.unrecorded_outcomes(), 0);
}

/// A-102 (docs/52 §4.4, §7 R3; Q-462 item 1): `seal_ceremony` by Admin is
/// one record (it only makes keyd stricter: no intent); afterwards
/// `create_key` is refused at keyd's authorization step (`CeremonySealed`)
/// — one record, no intent, no wait. The seal is Admin's alone. Task PN11
/// (Q-1056 item 4, A-188): before the attestation key is installed the
/// seal is refused (`AttestationKeyNotInstalled`) — one record, no intent;
/// the install itself is intent then outcome (task PN9).
#[test]
fn the_seal_is_one_record_and_ends_create_key_without_an_intent() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    // auditd acknowledges the install's intent (task PN9); the seal and the
    // refusals need none.
    let auditd = AutoAck::start(&gate);
    assert!(matches!(
        serve(&mut engine, LDAP, &Call::SealCeremony).0,
        Ok(Answer::SealCeremony(Err(Error::Denied)))
    ));
    assert!(matches!(
        serve(&mut engine, ADMIN, &Call::SealCeremony).0,
        Ok(Answer::SealCeremony(Err(Error::Denied)))
    ));
    assert!(matches!(
        serve(&mut engine, ADMIN, &install_attestation_key()).0,
        Ok(Answer::InstallAttestationKey(Ok(())))
    ));
    let started = Instant::now();
    assert!(matches!(
        serve(&mut engine, ADMIN, &Call::SealCeremony).0,
        Ok(Answer::SealCeremony(Ok(())))
    ));
    assert!(matches!(
        serve(&mut engine, ADMIN, &create_key(0xA1, "alice")).0,
        Ok(Answer::CreateKey(Err(Error::Denied)))
    ));
    assert!(started.elapsed() < generous().get(), "no wait");
    let records = auditd.wait_for(6);
    let phases: Vec<_> = records.iter().map(|r| (r.op, r.result, r.reason)).collect();
    assert_eq!(
        phases,
        [
            (
                KeydOperation::SealCeremony,
                KeydOutcome::Denied,
                KeydReason::RoleNotPermitted
            ),
            (
                KeydOperation::SealCeremony,
                KeydOutcome::Denied,
                KeydReason::AttestationKeyNotInstalled
            ),
            (
                KeydOperation::InstallAttestationKey,
                KeydOutcome::Intent,
                KeydReason::None
            ),
            (
                KeydOperation::InstallAttestationKey,
                KeydOutcome::Success,
                KeydReason::None
            ),
            (
                KeydOperation::SealCeremony,
                KeydOutcome::Success,
                KeydReason::None
            ),
            (
                KeydOperation::CreateKey,
                KeydOutcome::Denied,
                KeydReason::CeremonySealed
            ),
        ]
    );
}

// ---- the attestation key's install (task PN9) ---------------------------------------

/// The attestation-key install of these tests: a made-up key.
fn install_attestation_key() -> Call {
    Call::InstallAttestationKey {
        key: ipc_keyd::AttestationKeyOctets::from_slice(&[0x4D; 32]).unwrap(),
    }
}

/// Task PN9 (docs/59 §7.4, §7.5; docs/questions/Q-1011 items 2, 8 — A-173;
/// Q-1033 items 2, 3 — A-177; A-86 / A-88): through the daemon's engine,
/// Admin's install in the ceremony is written to the window as its intent,
/// acknowledged, and only then run — its outcome keyd's own record
/// (`Success`); keyd then holds the key. A Kdc caller is refused at the
/// authorization step (one record, `RoleNotPermitted`, no intent); after the
/// seal Admin's install is refused the same way (`CeremonySealed`). No
/// record names a principal, a purpose or a kvno — nothing of the key.
#[test]
fn the_attestation_key_install_is_intent_then_outcome_in_the_ceremony_only() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    let auditd = AutoAck::start(&gate);
    assert!(matches!(
        serve(&mut engine, ADMIN, &install_attestation_key()).0,
        Ok(Answer::InstallAttestationKey(Ok(())))
    ));
    assert!(engine.keyd_mut().has_attestation_key());
    assert!(matches!(
        serve(&mut engine, KDC, &install_attestation_key()).0,
        Ok(Answer::InstallAttestationKey(Err(Error::Denied)))
    ));
    assert!(matches!(
        serve(&mut engine, ADMIN, &Call::SealCeremony).0,
        Ok(Answer::SealCeremony(Ok(())))
    ));
    assert!(matches!(
        serve(&mut engine, ADMIN, &install_attestation_key()).0,
        Ok(Answer::InstallAttestationKey(Err(Error::Denied)))
    ));
    let records = auditd.wait_for(5);
    let phases: Vec<_> = records.iter().map(|r| (r.op, r.result, r.reason)).collect();
    assert_eq!(
        phases,
        [
            (
                KeydOperation::InstallAttestationKey,
                KeydOutcome::Intent,
                KeydReason::None
            ),
            (
                KeydOperation::InstallAttestationKey,
                KeydOutcome::Success,
                KeydReason::None
            ),
            (
                KeydOperation::InstallAttestationKey,
                KeydOutcome::Denied,
                KeydReason::RoleNotPermitted
            ),
            (
                KeydOperation::SealCeremony,
                KeydOutcome::Success,
                KeydReason::None
            ),
            (
                KeydOperation::InstallAttestationKey,
                KeydOutcome::Denied,
                KeydReason::CeremonySealed
            ),
        ]
    );
    for record in &records {
        assert_eq!(record.principal, None);
        assert_eq!(record.purpose, None);
        assert_eq!(record.kvno, None);
    }
    assert_eq!(records[0].caller_role, KeydRole::Admin);
    assert_eq!(records[0].caller_uid, ADMIN.uid);
    assert_eq!(gate.unrecorded_outcomes(), 0);
}

/// Task PN9 (Q-1033 item 3, A-177) with A-86 / A-88 ("intent not
/// acknowledged ⇒ Unavailable, and nothing changed"): an install whose
/// intent auditd does not acknowledge in time is answered
/// `Refused::Unavailable` (then close) and keyd does not run it — keyd holds
/// no key; the window holds the intent and a `NotPerformed` outcome. Once
/// auditd acknowledges, the same install succeeds (so the first one
/// installed nothing).
#[test]
fn an_unacknowledged_install_is_unavailable_and_installs_nothing() {
    let clock = TestClock::at(t0());
    let (mut engine, gate) = engine(&clock, WindowConfig::DEFAULT, true);
    let (answer, open) = serve_queued(&mut engine, ADMIN, &install_attestation_key(), long_ago());
    assert_eq!(answer.err(), Some(Refused::Unavailable));
    assert!(!open);
    assert!(!engine.keyd_mut().has_attestation_key());
    let records = window_records(&gate);
    let phases: Vec<_> = records.iter().map(|r| (r.op, r.result)).collect();
    assert_eq!(
        phases,
        [
            (KeydOperation::InstallAttestationKey, KeydOutcome::Intent),
            (
                KeydOperation::InstallAttestationKey,
                KeydOutcome::NotPerformed
            ),
        ]
    );
    let _auditd = AutoAck::start(&gate);
    assert!(matches!(
        serve(&mut engine, ADMIN, &install_attestation_key()).0,
        Ok(Answer::InstallAttestationKey(Ok(())))
    ));
    assert!(engine.keyd_mut().has_attestation_key());
}
