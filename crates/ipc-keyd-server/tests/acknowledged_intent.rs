//! A key-state change runs only with the proof that auditd acknowledged its
//! intent (docs/52 §3.11 R6, decision A-102): `classify` decides from keyd's
//! own authorization step, an admitted change runs only through
//! `execute_acknowledged` with an `ipc_audit::AckedIntent`, and `execute`
//! refuses (`NotRun`, keyd not called) a plain call keyd would now admit.
//!
//! Sources: docs/52 §3.11 R6 (a); docs/questions/Q-365 (A-88: the six
//! key-state operations and the loosenings take the intent path; an
//! authorization refusal keeps one record and no intent); docs/52 §4.2
//! (A-102: `set_secret` only on a live decision dird registered); docs/50
//! §8.1 (an `Ack` after auditd's sync). Every value is constructed by hand
//! for these tests; no vector comes from any other implementation.

#[path = "../../ipc-keyd/tests/samples/mod.rs"]
mod samples;

use ipc_audit::{
    Ack, AckedIntent, AuditGate, EventBody, IntentRecord, KeydOutcome, KeydRecord, WindowConfig,
};
use ipc_keyd::{Answer, Call};
use ipc_keyd_server::{classify, execute, execute_acknowledged, Classified, KeyStateCall, NotRun};
use keyd::{
    AccountKind, AuditRecord, CallerId, DecidedOperation, DecisionId, Error, InMemoryKeyStore,
    KeyPurpose, Keyd, KeydConfig, Kvno, OsEntropy, Role,
};
use krb_proto::KerberosTime;
use std::time::{Duration, Instant};

#[derive(Default)]
struct Records(Vec<AuditRecord>);

impl keyd::AuditSink for Records {
    fn record(&mut self, record: &AuditRecord) {
        self.0.push(record.clone());
    }
}

type DevKeyd = Keyd<InMemoryKeyStore, Records, OsEntropy>;

const DIRECTORY: CallerId = CallerId {
    uid: 200,
    role: Role::Directory,
};
const ADMIN: CallerId = CallerId {
    uid: 300,
    role: Role::Admin,
};
const LDAP: CallerId = CallerId {
    uid: 400,
    role: Role::Ldap,
};

fn started() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 9, 0, 0).unwrap()
}

/// One hour after `started()`: past the start-up hold-down (A-62).
fn now() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap()
}

fn dev_keyd() -> DevKeyd {
    let store = InMemoryKeyStore::new_insecure_development_allowing_krbtgt(16);
    Keyd::new(
        KeydConfig::new(samples::realm()),
        store,
        Records::default(),
        &started(),
    )
    .unwrap()
}

/// Play auditd: commit `change`'s intent into a gate, acknowledge it as
/// auditd does after its sync, and take the proof.
fn acknowledged(change: KeyStateCall) -> AckedIntent<KeyStateCall> {
    let gate = AuditGate::new(WindowConfig::DEFAULT);
    gate.set_reachable(true);
    let pending = gate.begin_intent(gate.reserve().unwrap(), change).unwrap();
    let batch = gate.next_batch().unwrap();
    gate.acknowledge(&Ack {
        through_seq: batch.last_seq(),
        head_hash: [0; 32],
    })
    .unwrap();
    gate.wait_acknowledged(pending, Instant::now()).unwrap()
}

fn set_alice() -> Call {
    Call::SetSecret {
        handle: samples::alice_target().handle,
        binding: samples::binding(),
        password: samples::password(samples::PASSWORD),
        salt: String::from("EXAMPLE.ORGalice"),
    }
}

fn register_alice() -> Call {
    Call::RegisterDecision {
        id: DecisionId::new(7),
        operation: DecidedOperation::SetSecret {
            kind: AccountKind::User,
            targets: vec![samples::alice_target()],
        },
        approvers: Vec::new(),
        lifetime_secs: 30,
    }
}

/// Q-365 (A-88) / R6: an admitted `create_key` is a key-state change — its
/// intent record is the call's own (`Intent`, the handle, no secret) — and
/// keyd runs it only with the proof; without one (the intent sent but never
/// acknowledged) the gate hands the change back and keyd is never called.
#[test]
fn an_admitted_change_runs_only_with_its_proof() {
    let mut keyd = dev_keyd();
    let create = Call::CreateKey {
        handle: samples::handle(0x5E, KeyPurpose::Service),
        binding: samples::binding(),
    };
    let Classified::KeyStateChange(change) = classify(&keyd, ADMIN, now(), create) else {
        panic!("an admitted create_key needs an acknowledged intent");
    };
    let EventBody::Keyd(intent) = change.intent_event() else {
        panic!("a keyd record");
    };
    assert_eq!(intent.result, KeydOutcome::Intent);
    assert_eq!(intent.principal, Some([0x5E; 16]));
    assert_eq!(
        *intent,
        KeydRecord {
            result: KeydOutcome::Intent,
            ..match change.not_performed_event() {
                EventBody::Keyd(r) => *r,
                _ => panic!("a keyd record"),
            }
        }
    );

    // Sent, never acknowledged: no proof, the change back, keyd untouched.
    let gate = AuditGate::new(WindowConfig::DEFAULT);
    gate.set_reachable(true);
    let pending = gate.begin_intent(gate.reserve().unwrap(), change).unwrap();
    let _sent = gate.next_batch().unwrap();
    let deadline = Instant::now() + Duration::from_millis(20);
    let change = gate.wait_acknowledged(pending, deadline).unwrap_err();
    assert!(keyd.audit_sink().0.is_empty(), "keyd was not called");

    // Acknowledged: keyd runs it, once.
    let answer = execute_acknowledged(&mut keyd, acknowledged(change));
    assert!(matches!(answer, Answer::CreateKey(Ok(kvno)) if kvno == Kvno::INITIAL));
    assert_eq!(keyd.audit_sink().0.len(), 1);
}

/// Q-365 item 3 (A-88): a change keyd's authorization step refuses is a
/// plain call — `execute` runs it, keyd answers its uniform `Denied` with one
/// record (no intent). R6: when keyd's state changes so that the same call
/// would now be admitted (dird registered a live decision for it), that
/// classification is stale and `execute` refuses to run it (`NotRun`, keyd
/// not called); classified again it is a key-state change.
#[test]
fn a_stale_plain_call_is_not_run() {
    let mut keyd = dev_keyd();
    // No decision: refused at keyd's authorization step (NoGrant).
    let Classified::Plain(refused) = classify(&keyd, DIRECTORY, now(), set_alice()) else {
        panic!("a refused set_secret is plain");
    };
    assert!(matches!(
        execute(&mut keyd, refused),
        Ok(Answer::SetSecret(Err(Error::Denied)))
    ));
    assert_eq!(keyd.audit_sink().0.len(), 1, "one record, no intent");

    // Classified while refused, then dird registers the decision.
    let Classified::Plain(stale) = classify(&keyd, DIRECTORY, now(), set_alice()) else {
        panic!("still refused");
    };
    let Classified::KeyStateChange(registration) = classify(&keyd, LDAP, now(), register_alice())
    else {
        panic!("a registration loosens keyd: it needs its proof");
    };
    assert!(matches!(
        execute_acknowledged(&mut keyd, acknowledged(registration)),
        Answer::RegisterDecision(Ok(()))
    ));
    let records = keyd.audit_sink().0.len();
    assert_eq!(execute(&mut keyd, stale).map(|_| ()), Err(NotRun));
    assert_eq!(keyd.audit_sink().0.len(), records, "keyd was not called");
    assert!(matches!(
        classify(&keyd, DIRECTORY, now(), set_alice()),
        Classified::KeyStateChange(_)
    ));
}

/// Q-365 item 1: a call that changes no key state and loosens nothing is
/// plain whatever keyd's state (here `ping`, and the destroy listing — a
/// read).
#[test]
fn reads_are_plain() {
    let mut keyd = dev_keyd();
    for (caller, call) in [
        (ADMIN, Call::Ping),
        (LDAP, Call::ListDestroyDecisions { after: None }),
    ] {
        let Classified::Plain(plain) = classify(&keyd, caller, now(), call) else {
            panic!("a read is plain");
        };
        assert!(execute(&mut keyd, plain).is_ok());
    }
}
