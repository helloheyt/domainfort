//! The pending key-operation requests (task A10; A-102): the operation
//! digest binds every field of the request, the table's lifetime is
//! bounded, the operations' codes and purposes; and the steps against the
//! provisioned test domain (tests/common): the `Approve` that completes the
//! quorum yields the decision dird registers in keyd (docs/52 §4.3), one
//! that does not yields none, and an approval after the quorum is a
//! conflict. The registration itself runs against the real dird and keyd in
//! crates/directory-daemon tests/admin_service.rs.
//!
//! Sources: docs/51 §5.6 ("the operation digest", "bounded in time"), §6;
//! docs/24 §6 (principle: sign the exact operation); docs/10 §1, §7;
//! docs/questions/Q-420, Q-460; docs/52 §4.2, §4.3 (A-102). Every value is
//! constructed by hand for these tests; no vector comes from any other
//! implementation (SHA-256 itself is the approved `sha2`'s — only its use is
//! checked here).

mod common;

use core::time::Duration;
use directory_admin::{
    operation_digest, ConfigError, KeyAdminOperation, KeyOperation, KeyRef, KeyReply, KeyRequests,
    KeyStep, KeyTargets, RegistrationOutcome, KEY_REQUEST_LIFETIME, MAX_KEY_REQUEST_LIFETIME,
};
use dtyp::Guid;
use ipc_audit::{
    AdminFailure, AdminRefusal, DecisionResult, DirAdminOperation, DirAdminStage, KeydOperation,
    OutcomeResult,
};
use keyd_types::{DecidedOperation, DecisionId, KeyHandle, KeyPurpose, Kvno, PrincipalId};
use std::collections::BTreeSet;

fn guid(n: u8) -> Guid {
    let mut packet = [0u8; 16];
    packet[0] = 0xA1;
    packet[15] = n;
    Guid::from_packet(&packet)
}

/// docs/51 §5.6; docs/24 §6: the digest is a function of the request — the
/// same inputs give the same digest; changing the id, the operation, its
/// kvno, the key set, the requester or the expiry changes it.
#[test]
fn the_digest_binds_every_field() {
    let base = operation_digest(7, &KeyOperation::RotateKrbtgt, guid(1), guid(2), 1000);
    assert_eq!(
        base,
        operation_digest(7, &KeyOperation::RotateKrbtgt, guid(1), guid(2), 1000)
    );
    let retire = |kvno| KeyOperation::RetireKvno {
        key: KeyRef::Krbtgt,
        kvno,
    };
    let variants = [
        operation_digest(8, &KeyOperation::RotateKrbtgt, guid(1), guid(2), 1000),
        operation_digest(7, &retire(0), guid(1), guid(2), 1000),
        operation_digest(7, &retire(1), guid(1), guid(2), 1000),
        operation_digest(7, &retire(2), guid(1), guid(2), 1000),
        operation_digest(
            7,
            &KeyOperation::RotateKey { service: guid(1) },
            guid(1),
            guid(2),
            1000,
        ),
        operation_digest(7, &KeyOperation::RotateKrbtgt, guid(3), guid(2), 1000),
        operation_digest(7, &KeyOperation::RotateKrbtgt, guid(1), guid(4), 1000),
        operation_digest(7, &KeyOperation::RotateKrbtgt, guid(1), guid(2), 1001),
    ];
    let mut all: BTreeSet<[u8; 32]> = variants.iter().copied().collect();
    assert_eq!(all.len(), variants.len());
    assert!(all.insert(base), "every variant differs from the base");
}

/// docs/10 §1, §7: the keyd operation and the key purpose of each request.
#[test]
fn operations_name_their_keyd_operation_and_purpose() {
    let service = guid(5);
    for (operation, keyd, purpose, kvno) in [
        (
            KeyOperation::RotateKrbtgt,
            KeydOperation::RotateKrbtgt,
            KeyPurpose::Krbtgt,
            true,
        ),
        (
            KeyOperation::RotateKey { service },
            KeydOperation::RotateKey,
            KeyPurpose::Service,
            true,
        ),
        (
            KeyOperation::RetireKvno {
                key: KeyRef::Krbtgt,
                kvno: 1,
            },
            KeydOperation::RetireKvno,
            KeyPurpose::Krbtgt,
            false,
        ),
        (
            KeyOperation::RetireKvno {
                key: KeyRef::Service(service),
                kvno: 1,
            },
            KeydOperation::RetireKvno,
            KeyPurpose::Service,
            false,
        ),
    ] {
        assert_eq!(operation.keyd_operation(), keyd);
        assert_eq!(operation.purpose(), purpose);
        assert_eq!(operation.answers_kvno(), kvno);
    }
    // Both steps carry a ticket (keyadm's ticketless steps are retired —
    // A-102); `Approve` reserves two events (its decision and the outcome of
    // its decision's registration in keyd — docs/52 §4.3).
    let steps = [
        (
            KeyAdminOperation::RequestKeyOperation {
                operation: KeyOperation::RotateKrbtgt,
            },
            DirAdminOperation::RequestKeyOperation,
            true,
            1,
        ),
        (
            KeyAdminOperation::Approve {
                id: 1,
                operation: KeyOperation::RotateKrbtgt,
            },
            DirAdminOperation::Approve,
            true,
            2,
        ),
    ];
    for (step, code, ticket, events) in steps {
        assert_eq!(step.code(), code);
        assert_eq!(step.takes_ticket(), ticket);
        assert_eq!(step.audit_events(), events);
    }
}

/// docs/51 §5.6 ("bounded in time"): the lifetime is 1 s ..= one hour; a
/// new table is empty.
#[test]
fn the_lifetime_is_bounded() {
    let targets = || KeyTargets {
        krbtgt: guid(1),
        services: BTreeSet::from([guid(2), guid(3)]),
    };
    for lifetime in [
        Duration::ZERO,
        MAX_KEY_REQUEST_LIFETIME + Duration::from_secs(1),
    ] {
        assert_eq!(
            KeyRequests::new(targets(), lifetime, 0).unwrap_err(),
            ConfigError::KeyRequestLifetime
        );
    }
    for lifetime in [
        Duration::from_secs(1),
        KEY_REQUEST_LIFETIME,
        MAX_KEY_REQUEST_LIFETIME,
    ] {
        let table = KeyRequests::new(targets(), lifetime, 0).unwrap();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }
}

// ---------------------------------------------------------------------------
// The steps against the provisioned test domain (A-102).
// ---------------------------------------------------------------------------

/// The test domain's policy plus `PolicyAdmin` on every policy scope for the
/// Tier-0 group — provision's rule 4 (docs/questions/Q-420 item 1: the
/// key operations ask `PolicyAdmin` on `Policy { scope: "keys" }`).
fn with_policy_admin(d: &mut common::Domain) {
    let mut rules = d.policy.rules().to_vec();
    rules.push(pdp::Rule {
        id: pdp::RuleId(9),
        effect: pdp::Effect::Allow,
        when: pdp::Match {
            action: pdp::ActionMatch::Exact(pdp::Action::PolicyAdmin),
            resource: pdp::ResourceMatch::Policy { scope: None },
            subject: pdp::SubjectMatch::MemberOf(common::sid_of(common::TIER0_GROUP)),
            context: pdp::ContextMatch::ANY,
            auth: pdp::AuthMatch::ANY,
        },
        obligations: vec![],
    });
    d.policy = pdp::PolicySnapshot::new(d.policy.version(), rules, vec![]);
}

/// The domain's key sets: its krbtgt (RID 502) and its two service objects.
fn domain_targets() -> KeyTargets {
    KeyTargets {
        krbtgt: common::guid(common::KRBTGT),
        services: BTreeSet::from([
            common::guid(common::LDAP_SVC),
            common::guid(common::ADMIND_SVC),
        ]),
    }
}

/// One step by `sam` at `common::now()`.
fn step(
    d: &common::Domain,
    table: &mut KeyRequests,
    id: u64,
    request: &KeyAdminOperation,
    sam: &str,
) -> Result<KeyStep, directory_admin::Refusal> {
    let view = d.view();
    let ticket = common::ticket(sam);
    let mut honour = |_: &[pdp::Obligation]| true;
    d.admin.key_step(
        table,
        id,
        request,
        &common::TEST_DIGEST,
        Some(&ticket),
        0,
        &view,
        &d.policy,
        &common::now(),
        &mut honour,
    )
}

fn principal(g: Guid) -> PrincipalId {
    PrincipalId::from_bytes(g.to_packet())
}

/// docs/52 §4.3 (the key-operation rows), docs/51 §5.6 (R51-11: the
/// requester plus one other approver; `DualControlToken { approver_1: the
/// requester, approver_2: the approver }`), Q-460 (the decision lives no
/// longer than its request): with quorum 2, the requester's
/// `RequestKeyOperation` yields no decision; admin2's `Approve` completes the
/// quorum and yields the decision — id = the request's id, the krbtgt's
/// `RotateKrbtgt`, approvers [admin1, admin2], the request's remaining
/// lifetime; a further approval is a `Conflict` and yields nothing.
#[test]
fn the_quorum_completing_approve_yields_the_decision() {
    let mut d = common::Domain::new("kr-decision");
    with_policy_admin(&mut d);
    let mut table = KeyRequests::new(domain_targets(), KEY_REQUEST_LIFETIME, 1000).unwrap();
    let opened = step(
        &d,
        &mut table,
        1,
        &KeyAdminOperation::RequestKeyOperation {
            operation: KeyOperation::RotateKrbtgt,
        },
        "admin1",
    )
    .unwrap();
    assert!(opened.decision().is_none());
    let KeyReply::Request(view) = opened.reply();
    let id = view.id;
    let approved = step(
        &d,
        &mut table,
        2,
        &KeyAdminOperation::Approve {
            id,
            operation: KeyOperation::RotateKrbtgt,
        },
        "admin2",
    )
    .unwrap();
    let decision = approved.decision().unwrap();
    assert_eq!(decision.id, DecisionId::new(id));
    assert_eq!(
        decision.operation,
        DecidedOperation::RotateKrbtgt {
            krbtgt: KeyHandle::new(principal(common::guid(common::KRBTGT)), KeyPurpose::Krbtgt)
        }
    );
    assert_eq!(
        decision.approvers,
        vec![
            principal(common::guid(common::ADMIN1)),
            principal(common::guid(common::ADMIN2))
        ]
    );
    assert_eq!(
        u64::from(decision.lifetime_secs),
        KEY_REQUEST_LIFETIME.as_secs()
    );
    // Its decision event, then (built on demand) its registration's outcome.
    assert_eq!(approved.events().len(), 1);
    assert!(matches!(
        approved.events()[0].stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    ));
    assert_eq!(
        approved
            .registration_event(RegistrationOutcome::Registered)
            .stage,
        DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
    );
    assert_eq!(
        approved
            .registration_event(RegistrationOutcome::Refused)
            .stage,
        DirAdminStage::Outcome(OutcomeResult::Refused(AdminRefusal::KeyOperationRefused))
    );
    assert_eq!(
        approved
            .registration_event(RegistrationOutcome::OutcomeUnknown)
            .stage,
        DirAdminStage::Outcome(OutcomeResult::Failed(
            AdminFailure::KeyOperationOutcomeUnknown
        ))
    );
    // After the quorum: a conflict, no decision.
    let again = step(
        &d,
        &mut table,
        3,
        &KeyAdminOperation::Approve {
            id,
            operation: KeyOperation::RotateKrbtgt,
        },
        "admin2",
    );
    assert!(again.is_err());
}

/// docs/52 §4.3; Q-453 item 1 (fail closed): when the decision could not be
/// registered, dird withdraws the approval that completed the quorum — the
/// approver may approve again, and the same decision is yielded again (keyd
/// accepts an identical decision unchanged). A retire decision names the
/// key set and the kvno (Q-420 item 4).
#[test]
fn a_withdrawn_approval_can_be_given_again() {
    let mut d = common::Domain::with_quorum("kr-withdraw", 2);
    with_policy_admin(&mut d);
    let mut table = KeyRequests::new(domain_targets(), KEY_REQUEST_LIFETIME, 2000).unwrap();
    let operation = KeyOperation::RetireKvno {
        key: KeyRef::Service(common::guid(common::LDAP_SVC)),
        kvno: 4,
    };
    let opened = step(
        &d,
        &mut table,
        1,
        &KeyAdminOperation::RequestKeyOperation { operation },
        "admin1",
    )
    .unwrap();
    let KeyReply::Request(view) = opened.reply();
    let id = view.id;
    let approve = KeyAdminOperation::Approve { id, operation };
    let first = step(&d, &mut table, 2, &approve, "admin2").unwrap();
    let decision = first.decision().unwrap().clone();
    assert_eq!(
        decision.operation,
        DecidedOperation::RetireKvno {
            handle: KeyHandle::new(
                principal(common::guid(common::LDAP_SVC)),
                KeyPurpose::Service
            ),
            kvno: Kvno::new(4),
        }
    );
    assert!(table.withdraw(&decision));
    assert!(!table.withdraw(&decision), "only the completing approval");
    let second = step(&d, &mut table, 3, &approve, "admin2").unwrap();
    assert_eq!(second.decision(), Some(&decision));
}

/// docs/51 §5.6 (P-22: quorum 3 = the requester and two approvers);
/// docs/52 §4.3: an approval that does not complete the quorum yields no
/// decision (the test domain has two Tier-0 administrators, so the first
/// approval is the only one possible here).
#[test]
fn a_non_completing_approve_yields_no_decision() {
    let mut d = common::Domain::with_quorum("kr-quorum3", 3);
    with_policy_admin(&mut d);
    let mut table = KeyRequests::new(domain_targets(), KEY_REQUEST_LIFETIME, 3000).unwrap();
    let operation = KeyOperation::RotateKey {
        service: common::guid(common::ADMIND_SVC),
    };
    let opened = step(
        &d,
        &mut table,
        1,
        &KeyAdminOperation::RequestKeyOperation { operation },
        "admin1",
    )
    .unwrap();
    let KeyReply::Request(view) = opened.reply();
    let approved = step(
        &d,
        &mut table,
        2,
        &KeyAdminOperation::Approve {
            id: view.id,
            operation,
        },
        "admin2",
    )
    .unwrap();
    assert!(approved.decision().is_none());
    let KeyReply::Request(view) = approved.reply();
    assert_eq!((view.approvals, view.quorum), (1, 3));
}
