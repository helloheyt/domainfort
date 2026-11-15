//! Key-set lifecycle of decision A-35 (docs/questions/Q-115): keyd chooses
//! the kvno of `set_secret` (initial for a new set, current + 1 otherwise)
//! and returns it; `destroy_key_set` (Admin, never krbtgt) removes and
//! zeroizes a deleted account's key sets, leaving the handles unknown to
//! every operation. Since A-102 (docs/52 §4.2, §4.3) every one of these
//! runs on a decision dird registered (the `decide` / `grant` helpers), and
//! `destroy_key_set` destroys a deleted principal's PrincipalLongterm and
//! Service key sets together. Sources: docs/questions/Q-115 (A-35); docs/10
//! §6, §7, §8, §9, §10, §12 I2, I3, I4, I8; docs/47 §9.1 (a computer's two
//! key sets share one id, password and salt); docs/52 §4.2, §4.3. The kvno ceiling is tested inside the
//! crate (src/directory.rs), since 2^32 changes are unreachable here. All
//! values are constructed for these tests.

mod common;

use common::*;
use keyd::{
    AccountKind, AuditOutcome, AuditReason, AuthnError, DecidedOperation, DecisionId, Error,
    IssueError, KeyHandle, KeyPurpose, Kvno, Operation, PrincipalId, SetSecretTarget,
};
use krb_crypto::EncType;
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};
use krb_proto::PrincipalName;
use zeroize::Zeroizing;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

const CAROL: KeyHandle = KeyHandle::new(
    PrincipalId::from_bytes([0xCA; 16]),
    KeyPurpose::PrincipalLongterm,
);
const CAROL_PASSWORD: &str = "her first passphrase";
const CAROL_SALT: &str = "EXAMPLE.ORGcarol";

fn carol_name() -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("carol")],
    }
}

/// The destroy decision dird registers after a `Delete` of `principal`
/// committed (A-102, docs/52 §4.3).
fn destroy_decision(f: &mut Fixture, principal: PrincipalId) -> DecisionId {
    f.decide(DecidedOperation::DestroyKeySet { principal }, &now())
        .unwrap()
}

fn pa_with(password: &str, salt: &str, kvno: u32) -> krb_proto::PaData {
    pa_enc_timestamp(
        &password_key(EncType::Aes256CtsHmacSha196, password, salt),
        Some(kvno),
        now(),
    )
}

/// A-35: creating a key set through set_secret installs `Kvno::INITIAL`
/// (1) and returns it; the audit record names it; the password
/// pre-authenticates under that kvno. Source: docs/questions/Q-115 (A-35);
/// docs/10 §6, §10.
#[test]
fn set_secret_on_a_new_set_returns_the_initial_kvno() {
    let mut f = Fixture::new();
    f.grant(&CAROL, &bound(carol_name()), CAROL_SALT, &now())
        .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &CAROL,
            &bound(carol_name()),
            z(CAROL_PASSWORD),
            CAROL_SALT,
            &now(),
        ),
        Ok(Kvno::INITIAL)
    );
    assert_eq!(Kvno::INITIAL, Kvno::new(1));
    let last = f.records().last().unwrap();
    assert_eq!(last.op, Operation::SetSecret);
    assert_eq!(last.result, AuditOutcome::Success);
    assert_eq!(last.kvno, Some(Kvno::new(1)));
    assert!(f
        .keyd
        .verify_preauth(
            &KDC,
            &CAROL,
            &pa_with(CAROL_PASSWORD, CAROL_SALT, 1),
            None,
            &now()
        )
        .is_ok());
}

/// A-35: on an existing set keyd installs current + 1 and returns it — the
/// same counter whichever operation produced the current version
/// (create_key, rotate_key, set_secret). Source: docs/questions/Q-115
/// (A-35); docs/10 §1 (current + previous), §6, §7.
#[test]
fn set_secret_on_an_existing_set_returns_current_plus_one() {
    let mut f = Fixture::new();
    // alice was created at kvno 1 by the fixture.
    for (password, expected) in [("a second passphrase", 2), ("a third passphrase", 3)] {
        f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
            .unwrap();
        assert_eq!(
            f.keyd.set_secret(
                &DIRECTORY,
                &ALICE,
                &alice_binding(),
                z(password),
                ALICE_SALT,
                &now(),
            ),
            Ok(Kvno::new(expected))
        );
        assert_eq!(f.records().last().unwrap().kvno, Some(Kvno::new(expected)));
    }
    assert!(f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_with("a third passphrase", ALICE_SALT, 3),
            None,
            &now()
        )
        .is_ok());
    // The superseded kvno is not the current one any more.
    assert_eq!(
        f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &pa_with("a second passphrase", ALICE_SALT, 2),
            None,
            &now()
        ),
        Err(AuthnError::Denied)
    );

    // Service key: create_key gave 1, rotate_key gives 2, set_secret 3.
    let rotation = f
        .decide(DecidedOperation::RotateKey { handle: SERVICE }, &now())
        .unwrap();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, rotation, &now()),
        Ok(Kvno::new(2))
    );
    f.grant(
        &SERVICE,
        &service_binding(),
        "EXAMPLE.ORGhostfiles.example.org",
        &now(),
    )
    .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &SERVICE,
            &service_binding(),
            z("service password"),
            "EXAMPLE.ORGhostfiles.example.org",
            &now(),
        ),
        Ok(Kvno::new(3))
    );
}

/// A-35: after destroy_key_set the handle is unknown to every operation —
/// verify_preauth, issue_as_rep, and a rotate_key / retire_kvno decision on
/// it all give the uniform Denied (KeyNotFound); a second destroy decision
/// is refused at its registration (R6b: no key set left, KeyNotFound) — and
/// set_secret on the same handle creates a
/// NEW set, from the initial kvno, only with a binding that passes the
/// creation rules. Other principals are untouched.
/// Source: docs/questions/Q-115 (A-35); docs/10 §7, §9 (uniform Denied);
/// docs/questions/Q-040 (A-19, creation-time binding rules); docs/52 §4.2
/// (A-102).
#[test]
fn destroyed_handle_is_unknown_to_every_operation() {
    let mut f = Fixture::new();
    // Give alice a previous version too: the whole set must go.
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
        .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            z("a second passphrase"),
            ALICE_SALT,
            &now(),
        ),
        Ok(Kvno::new(2))
    );
    let proof = f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_with("a second passphrase", ALICE_SALT, 2),
            None,
            &now(),
        )
        .unwrap();

    let destroy = destroy_decision(&mut f, ALICE_ID);
    assert_eq!(f.keyd.destroy_key_set(&ADMIN, destroy, &now()), Ok(()));
    let last = f.records().last().unwrap();
    assert_eq!(last.op, Operation::DestroyKeySet);
    assert_eq!(last.result, AuditOutcome::Success);
    assert_eq!(last.principal, Some(ALICE_ID));
    assert_eq!(last.purpose, Some(KeyPurpose::PrincipalLongterm));
    assert_eq!(last.kvno, Some(Kvno::new(2)));
    assert_eq!(last.decision, Some(destroy));

    for (password, kvno) in [("a second passphrase", 2), (ALICE_PASSWORD, 1)] {
        assert_eq!(
            f.keyd.verify_preauth(
                &KDC,
                &ALICE,
                &pa_with(password, ALICE_SALT, kvno),
                None,
                &now()
            ),
            Err(AuthnError::Denied)
        );
        assert_eq!(f.records().last().unwrap().reason, AuditReason::KeyNotFound);
    }
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &ALICE, &KRBTGT, &proof, None, &as_template(), &now()),
        Err(IssueError::Denied)
    );
    let rotation = f
        .decide(DecidedOperation::RotateKey { handle: ALICE }, &now())
        .unwrap();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, rotation, &now()),
        Err(Error::Denied)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::KeyNotFound);
    for kvno in [1, 2] {
        let retirement = f
            .decide(
                DecidedOperation::RetireKvno {
                    handle: ALICE,
                    kvno: Kvno::new(kvno),
                },
                &now(),
            )
            .unwrap();
        assert_eq!(
            f.keyd.retire_kvno(&ADMIN, retirement, &now()),
            Err(Error::Denied)
        );
        assert_eq!(f.records().last().unwrap().reason, AuditReason::KeyNotFound);
    }
    // A second destroy decision is not even registered: alice has no key
    // set left, so the destruction is complete as keyd's store says (R6b,
    // docs/questions/Q-501) — refused, KeyNotFound, nothing scheduled.
    assert_eq!(
        f.decide(
            DecidedOperation::DestroyKeySet {
                principal: ALICE_ID
            },
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::KeyNotFound);
    assert!(f
        .keyd
        .list_destroy_decisions(&ADMIN, None, &now())
        .unwrap()
        .entries
        .is_empty());

    // Recreating needs a creation-valid binding (a krbtgt name is refused,
    // and nothing is created) — even with a grant naming it (task A15a: the
    // grant does not judge bindings; set_secret does) ...
    f.grant(&ALICE, &krbtgt_binding(), ALICE_SALT, &now())
        .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &krbtgt_binding(),
            z("a new passphrase"),
            ALICE_SALT,
            &now(),
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::InvalidNameBinding
    );
    // ... and then starts again from the initial kvno (so the refused call
    // created nothing).
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
        .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            z("a new passphrase"),
            ALICE_SALT,
            &now(),
        ),
        Ok(Kvno::INITIAL)
    );
    assert!(f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_with("a new passphrase", ALICE_SALT, 1),
            None,
            &now()
        )
        .is_ok());
    // The destroyed versions' passwords do not come back.
    assert_eq!(
        f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &pa_with(ALICE_PASSWORD, ALICE_SALT, 1),
            None,
            &now()
        ),
        Err(AuthnError::Denied)
    );

    // Bob was never touched.
    assert!(f
        .keyd
        .verify_preauth(
            &KDC,
            &BOB,
            &pa_with(BOB_PASSWORD, BOB_SALT, 1),
            None,
            &now()
        )
        .is_ok());
}

/// A-35: a live AuthnProof dies with its key set. Even when the set is
/// recreated at once with the SAME password (same key, same kvno 1), the
/// proof issued before the destruction does not redeem. Source:
/// docs/questions/Q-115 (A-35); docs/10 §8, §12 I4 (issuance needs a valid
/// proof).
#[test]
fn destroy_discards_live_proofs_of_the_key_set() {
    let mut f = Fixture::new();
    let proof = f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_with(ALICE_PASSWORD, ALICE_SALT, 1),
            None,
            &now(),
        )
        .unwrap();
    let destroy = destroy_decision(&mut f, ALICE_ID);
    f.keyd.destroy_key_set(&ADMIN, destroy, &now()).unwrap();
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
        .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            z(ALICE_PASSWORD),
            ALICE_SALT,
            &now(),
        ),
        Ok(Kvno::INITIAL)
    );
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &ALICE, &KRBTGT, &proof, None, &as_template(), &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::TokenUnknown
    );
    // A fresh exchange against the recreated set works.
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    assert_eq!(tgt.parts.ticket.enc_part.kvno, Some(1));
}

/// A computer has two key sets under one id (PrincipalLongterm and Service,
/// docs/47 §9.1). A destroy decision names the deleted principal, and
/// `destroy_key_set` destroys both key sets (with the client set's live
/// proof); the record names the client set and, as its secondary key, the
/// Service set, each with its destroyed kvno. Another principal is
/// untouched. Source: docs/47 §9.1; docs/questions/Q-115 (A-35); docs/52
/// §4.2 (`DestroyKeySet { principal }` — both purposes), §4.3; docs/51 §6.
#[test]
fn destroy_takes_both_key_sets_of_the_principal() {
    let mut f = Fixture::new();
    let id = PrincipalId::from_bytes([0xC5; 16]);
    let client = KeyHandle::new(id, KeyPurpose::PrincipalLongterm);
    let service = KeyHandle::new(id, KeyPurpose::Service);
    let salt = "EXAMPLE.ORGhostws05.example.org";
    let client_name = PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("ws05$")],
    };
    let service_name = PrincipalName {
        name_type: KRB_NT_SRV_HST,
        name_string: vec![kstr("host"), kstr("ws05.example.org")],
    };
    // One computer decision for both key sets, as dird registers it after
    // BeginPasswordSet (task A15a; docs/47 §9.1; A-102).
    let computer = DecidedOperation::SetSecret {
        kind: AccountKind::Computer,
        targets: vec![
            SetSecretTarget {
                handle: client,
                binding: bound(client_name.clone()),
                salt: salt.to_owned(),
            },
            SetSecretTarget {
                handle: service,
                binding: bound(service_name.clone()),
                salt: salt.to_owned(),
            },
        ],
    };
    f.decide(computer.clone(), &now()).unwrap();
    for (handle, name) in [
        (client, client_name.clone()),
        (service, service_name.clone()),
    ] {
        assert_eq!(
            f.keyd.set_secret(
                &DIRECTORY,
                &handle,
                &bound(name),
                z("machine password"),
                salt,
                &now(),
            ),
            Ok(Kvno::INITIAL)
        );
    }
    let proof = f
        .keyd
        .verify_preauth(
            &KDC,
            &client,
            &pa_with("machine password", salt, 1),
            None,
            &now(),
        )
        .unwrap();
    let destroy = destroy_decision(&mut f, id);
    assert_eq!(f.keyd.destroy_key_set(&ADMIN, destroy, &now()), Ok(()));
    let last = f.records().last().unwrap();
    assert_eq!(last.principal, Some(id));
    assert_eq!(last.purpose, Some(KeyPurpose::PrincipalLongterm));
    assert_eq!(last.kvno, Some(Kvno::INITIAL));
    let secondary = last.secondary.unwrap();
    assert_eq!(secondary.principal, id);
    assert_eq!(secondary.purpose, KeyPurpose::Service);
    assert_eq!(secondary.kvno, Some(Kvno::INITIAL));
    // The client set and its live proof are gone.
    let mut template = as_template();
    template.client = id;
    template.cname = client_name.clone();
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &client, &KRBTGT, &proof, None, &template, &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.keyd.verify_preauth(
            &KDC,
            &client,
            &pa_with("machine password", salt, 1),
            None,
            &now()
        ),
        Err(AuthnError::Denied)
    );
    // Both sets are recreated from the initial kvno: neither survived.
    f.decide(computer, &now()).unwrap();
    for (handle, name) in [(client, client_name), (service, service_name)] {
        assert_eq!(
            f.keyd.set_secret(
                &DIRECTORY,
                &handle,
                &bound(name),
                z("another machine password"),
                salt,
                &now(),
            ),
            Ok(Kvno::INITIAL)
        );
    }
    // Bob was never touched.
    assert!(f.password_works(&BOB, BOB_PASSWORD, BOB_SALT));
}

/// A-35: a destroyed Service key set seals no more service tickets; the
/// krbtgt and the TGT path are unaffected. Source: docs/questions/Q-115
/// (A-35); docs/10 §5, §7.
#[test]
fn destroyed_service_key_issues_no_ticket() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let destroy = destroy_decision(&mut f, SERVICE_ID);
    assert_eq!(f.keyd.destroy_key_set(&ADMIN, destroy, &now()), Ok(()));
    let ctx = open_tgt(&mut f, &tgt, 31, 31);
    assert_eq!(
        f.keyd
            .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(31), &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::KeyNotFound);
    // The TGS path still works for the TGT itself (krbtgt untouched).
    open_tgt(&mut f, &tgt, 32, 32);
}

/// A-35 / A-102: only Admin may run a destroy decision (Directory and Kdc:
/// RoleNotPermitted, and the decision stays pending); a krbtgt key set is
/// never destroyed (a destroy decision names a principal's PrincipalLongterm
/// and Service handles only — the krbtgt principal has neither, so since
/// R6b its destroy decision is not even registered), nor is a decision
/// registered for a principal without key sets (KeyNotFound); an id no
/// decision has is the uniform Denied (NoDecision). Nothing is destroyed by
/// a refused call. Source: docs/questions/Q-115 (A-35: "never for
/// krbtgt"); docs/10 §2 (capability table), §7, §9, §12 I2; docs/52 §4.2;
/// docs/questions/Q-501 (R6b).
#[test]
fn destroy_key_set_role_krbtgt_and_unknown_decision() {
    let mut f = Fixture::new();
    let destroy_alice = destroy_decision(&mut f, ALICE_ID);
    for caller in [DIRECTORY, KDC] {
        assert_eq!(
            f.keyd.destroy_key_set(&caller, destroy_alice, &now()),
            Err(Error::Denied)
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.op, Operation::DestroyKeySet);
        assert_eq!(last.caller_role, caller.role);
        assert_eq!(last.reason, AuditReason::RoleNotPermitted);
    }
    // The refused calls consumed nothing: the decision is still pending.
    let page = f.keyd.list_destroy_decisions(&ADMIN, None, &now()).unwrap();
    assert!(page.entries.iter().any(|p| p.decision == destroy_alice));
    // R6b: the krbtgt principal (only a Krbtgt key set, which no
    // destruction touches) and a principal without key sets get no destroy
    // decision at all — refused at the registration, KeyNotFound.
    for principal in [KRBTGT_ID, PrincipalId::from_bytes([0xEE; 16])] {
        assert_eq!(
            f.decide(DecidedOperation::DestroyKeySet { principal }, &now()),
            Err(Error::Denied)
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.op, Operation::RegisterDecision);
        assert_eq!(last.reason, AuditReason::KeyNotFound);
    }
    assert_eq!(
        f.keyd
            .destroy_key_set(&ADMIN, DecisionId::new(0xDEAD_0001), &now()),
        Err(Error::Denied)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::NoDecision);
    // Everything still works: the krbtgt, alice and the service key.
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let ctx = open_tgt(&mut f, &tgt, 33, 33);
    assert!(f
        .keyd
        .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(33), &now())
        .is_ok());
}

/// Decimal and hex renderings of the first octets of `secret`, as they
/// would appear if a byte slice leaked into Debug output.
fn renderings(secret: &[u8]) -> Vec<String> {
    let head = &secret[..4];
    vec![
        format!("{}, {}, {}, {}", head[0], head[1], head[2], head[3]),
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            head[0], head[1], head[2], head[3]
        ),
        format!(
            "{:02X}{:02X}{:02X}{:02X}",
            head[0], head[1], head[2], head[3]
        ),
    ]
}

/// A-35 / I8: each destroy_key_set call — success or refusal — emits
/// exactly one audit record, and no record carries key bytes (in any
/// rendering) or password text. Source: docs/questions/Q-115 (A-35:
/// "zeroize + audit"); docs/10 §10 ("without any secret"), §12 I8;
/// AGENTS.md §6.
#[test]
fn destroy_key_set_audit_has_no_key_material() {
    let mut f = Fixture::new();
    let service = destroy_decision(&mut f, SERVICE_ID);
    let alice = destroy_decision(&mut f, ALICE_ID);
    let bob = destroy_decision(&mut f, BOB_ID);
    let calls: [(keyd::CallerId, DecisionId, bool); 5] = [
        (ADMIN, service, true),
        (ADMIN, alice, true),
        // The same decision again: its recorded result, nothing run.
        (ADMIN, alice, true),
        (ADMIN, DecisionId::new(0xDEAD_0002), false),
        (DIRECTORY, bob, false),
    ];
    for (caller, id, ok) in calls {
        let before = f.records().len();
        assert_eq!(f.keyd.destroy_key_set(&caller, id, &now()).is_ok(), ok);
        assert_eq!(f.records().len(), before + 1);
        let last = f.records().last().unwrap();
        assert_eq!(last.op, Operation::DestroyKeySet);
        assert_eq!(last.approvers, None);
        assert_eq!(last.decision, Some(id));
    }
    let text = format!("{:?}", f.records());
    for password in [ALICE_PASSWORD, BOB_PASSWORD] {
        assert!(!text.contains(password), "password text in audit");
    }
    let alice = alice_key();
    let bob = password_key(EncType::Aes256CtsHmacSha196, BOB_PASSWORD, BOB_SALT);
    for secret in [&SERVICE_KEY[..], alice.octets(), bob.octets()] {
        for r in renderings(secret) {
            assert!(!text.contains(&r), "key material in audit: {r}");
        }
    }
}
