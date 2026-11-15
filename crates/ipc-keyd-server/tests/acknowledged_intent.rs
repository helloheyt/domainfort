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
//! §8.1 (an `Ack` after auditd's sync). The proof comes only through the
//! real audit client from a (fake) auditd's `Ack` — the gate's link side is
//! crate-private to ipc-audit (task R15b, docs/questions/Q-630). Every value
//! is constructed by hand for these tests; no vector comes from any other
//! implementation.

#[path = "../../ipc-keyd/tests/samples/mod.rs"]
mod samples;

// A fake auditd and the real audit client linked to a gate (task R15b).
#[path = "../../ipc-audit/tests/linked/mod.rs"]
mod linked;

use ipc_audit::{AckedIntent, EventBody, IntentRecord, KeydOutcome, KeydRecord};
use ipc_keyd::{Answer, Call};
use ipc_keyd_server::{classify, execute, execute_acknowledged, Classified, KeyStateCall, NotRun};
use keyd::{
    AccountKind, AuditRecord, CallerId, DecidedOperation, DecisionId, Error, InMemoryKeyStore,
    KeyPurpose, Keyd, KeydConfig, Kvno, OsEntropy, Role,
};
use krb_proto::KerberosTime;

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

/// Play auditd: commit `change`'s intent into a gate the real audit client
/// is attached to, let a fake auditd acknowledge it as auditd does after
/// its sync, and take the proof.
fn acknowledged(change: KeyStateCall) -> AckedIntent<KeyStateCall> {
    linked::acknowledged(change)
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
    let change = linked::not_acknowledged(change);
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

/// docs/52 §3.10 (c), §7 R9; docs/questions/Q-466 item 3 (A-102: one
/// classification consistent with `classify` / `KeyStateIntent`, not a
/// second, divergent list): for every call of every operation
/// (crates/ipc-keyd tests/samples), the keyd client's split — a state call
/// has no fate-dropping path (`ipc_keyd::Call::is_state_call`) — is exactly
/// the set of calls this crate takes through the intent path: those
/// `keyd::requires_acknowledged_intent` names (the one table, in
/// keyd-types), which are those `KeyStateIntent::of` derives an intent from
/// or that execute a decision by id.
#[test]
fn the_clients_state_calls_are_the_calls_classified_for_an_intent() {
    for call in samples::calls() {
        let operation = call.operation();
        let server_side = keyd::requires_acknowledged_intent(operation);
        assert_eq!(call.is_state_call(), server_side, "{operation:?}");
        let derived = ipc_keyd_server::KeyStateIntent::of(ADMIN, now(), &call).is_some()
            || call.decision().is_some();
        assert_eq!(derived, server_side, "{operation:?}");
    }
}

/// Task K4 (docs/53 §5.5, §9; docs/52 §3.10 (c)): `complete_change_password`
/// is a key-state change. Without a live `ChangePassword` decision for its
/// target keyd's authorization step refuses it — a plain call, one record,
/// no intent; with dird's decision it is classified for an acknowledged
/// intent whose record names the target and the decision (from keyd's
/// table), never the context or a password. The request's opening and its
/// error seal change no key state: plain.
#[test]
fn a_change_password_completion_takes_the_intent_path() {
    let mut keyd = dev_keyd();
    let alice = samples::alice_target().handle;
    let complete = || Call::CompleteChangePassword {
        ctx: keyd::ChangePasswordCtxId::from_bytes([0xCC; 16]),
        target: alice,
    };
    let Classified::Plain(refused) = classify(&keyd, LDAP, now(), complete()) else {
        panic!("no decision: refused at keyd's authorization step");
    };
    assert!(matches!(
        execute(&mut keyd, refused),
        Ok(Answer::CompleteChangePassword(Err(Error::Denied)))
    ));

    let register = Call::RegisterDecision {
        id: DecisionId::new(21),
        operation: DecidedOperation::ChangePassword {
            target: samples::alice_target(),
        },
        approvers: Vec::new(),
        lifetime_secs: 30,
    };
    let Classified::KeyStateChange(registration) = classify(&keyd, LDAP, now(), register) else {
        panic!("a registration loosens keyd");
    };
    assert!(matches!(
        execute_acknowledged(&mut keyd, acknowledged(registration)),
        Answer::RegisterDecision(Ok(()))
    ));
    // admind's `set_secret` of the same handle is not admitted by it (Q-662).
    assert!(matches!(
        classify(&keyd, DIRECTORY, now(), set_alice()),
        Classified::Plain(_)
    ));
    let Classified::KeyStateChange(change) = classify(&keyd, LDAP, now(), complete()) else {
        panic!("with dird's decision the completion needs its intent");
    };
    let EventBody::Keyd(intent) = change.intent_event() else {
        panic!("a keyd record");
    };
    assert_eq!(intent.result, KeydOutcome::Intent);
    assert_eq!(intent.op, ipc_audit::KeydOperation::CompleteChangePassword);
    assert_eq!(intent.principal, Some(*alice.principal.as_bytes()));
    assert_eq!(intent.decision, Some(21));
    // Run with its proof: no such context — refused.
    assert!(matches!(
        execute_acknowledged(&mut keyd, acknowledged(change)),
        Answer::CompleteChangePassword(Err(Error::Denied))
    ));

    for call in [
        Call::OpenChangePasswordRequest {
            service: keyd::PrincipalId::from_bytes([0xCF; 16]),
            ap_req_octets: vec![0x30, 0x00],
            krb_priv_octets: vec![0x30, 0x00],
            peer: keyd::HostAddr::ipv4([192, 0, 2, 10]),
            local: keyd::HostAddr::ipv4([192, 0, 2, 1]),
        },
        Call::SealChangePasswordError {
            ctx: keyd::ChangePasswordCtxId::from_bytes([0xCC; 16]),
            code: krb_proto::NonZeroResultCode::HardError,
        },
    ] {
        let Classified::Plain(plain) = classify(&keyd, LDAP, now(), call) else {
            panic!("no key state: plain");
        };
        assert!(execute(&mut keyd, plain).is_ok());
    }
}
