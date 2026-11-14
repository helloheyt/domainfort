//! The pending key-operation requests (task A10; A-102): the operation
//! digest binds every field of the request, the table's lifetime is
//! bounded, the operations' codes and purposes; and the steps against the
//! provisioned test domain (tests/common): the `Approve` that completes the
//! quorum yields the decision dird registers in keyd (docs/52 §4.3), one
//! that does not yields none, and an approval after the quorum is a
//! conflict. The key set of a service object carries the purpose its name
//! derives — `AdminService` for the admin service, `Service` for the LDAP
//! service (docs/52 R2b). The registration itself runs against the real
//! dird and keyd in crates/directory-daemon tests/admin_service.rs.
//!
//! Sources: docs/51 §5.6 ("the operation digest", "bounded in time"), §6;
//! docs/24 §6 (principle: sign the exact operation); docs/10 §1, §7;
//! docs/questions/Q-420, Q-460, Q-491 item 1, Q-493 item 1; docs/52 §4.2,
//! §4.3 (A-102), R2b. Every value is
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
use keyd_types::{
    DecidedOperation, DecisionId, KeyHandle, KeyPurpose, Kvno, PrincipalId, ServiceKeyHandle,
};
use krb_proto::constants::KRB_NT_SRV_HST;
use krb_proto::{KerberosString, PrincipalName};
use std::collections::BTreeSet;

fn guid(n: u8) -> Guid {
    let mut packet = [0u8; 16];
    packet[0] = 0xA1;
    packet[15] = n;
    Guid::from_packet(&packet)
}

/// The NT-SRV-HST name `class/host` (RFC 4120 §6.2.1).
fn spn(class: &str, host: &str) -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_SRV_HST,
        name_string: vec![
            KerberosString::new(class).unwrap(),
            KerberosString::new(host).unwrap(),
        ],
    }
}

/// The key set of the service object `g` named `class/host`, as the one
/// derivation names it (docs/52 R2b).
fn service_key(g: Guid, class: &str, host: &str) -> ServiceKeyHandle {
    ServiceKeyHandle::of_service(PrincipalId::from_bytes(g.to_packet()), &spn(class, host))
}

/// The krbtgt key set of the account `g`.
fn krbtgt_key(g: Guid) -> KeyHandle {
    KeyHandle::new(PrincipalId::from_bytes(g.to_packet()), KeyPurpose::Krbtgt)
}

/// docs/51 §5.6; docs/24 §6: the digest is a function of the request — the
/// same inputs give the same digest; changing the id, the operation, its
/// kvno, the key set, the requester or the expiry changes it.
#[test]
fn the_digest_binds_every_field() {
    let k = krbtgt_key;
    let base = operation_digest(7, &KeyOperation::RotateKrbtgt, k(guid(1)), guid(2), 1000);
    assert_eq!(
        base,
        operation_digest(7, &KeyOperation::RotateKrbtgt, k(guid(1)), guid(2), 1000)
    );
    let retire = |kvno| KeyOperation::RetireKvno {
        key: KeyRef::Krbtgt,
        kvno,
    };
    let rotate = KeyOperation::RotateKey { service: guid(1) };
    let variants = [
        operation_digest(8, &KeyOperation::RotateKrbtgt, k(guid(1)), guid(2), 1000),
        operation_digest(7, &retire(0), k(guid(1)), guid(2), 1000),
        operation_digest(7, &retire(1), k(guid(1)), guid(2), 1000),
        operation_digest(7, &retire(2), k(guid(1)), guid(2), 1000),
        operation_digest(
            7,
            &rotate,
            service_key(guid(1), "ldap", "dc01.example.test").handle(),
            guid(2),
            1000,
        ),
        // The same object and operation under the other service purpose
        // (docs/52 R2b): the digest binds the purpose too.
        operation_digest(
            7,
            &rotate,
            service_key(guid(1), "admind", "dc01.example.test").handle(),
            guid(2),
            1000,
        ),
        operation_digest(7, &KeyOperation::RotateKrbtgt, k(guid(3)), guid(2), 1000),
        operation_digest(7, &KeyOperation::RotateKrbtgt, k(guid(1)), guid(4), 1000),
        operation_digest(7, &KeyOperation::RotateKrbtgt, k(guid(1)), guid(2), 1001),
    ];
    let mut all: BTreeSet<[u8; 32]> = variants.iter().copied().collect();
    assert_eq!(all.len(), variants.len());
    assert!(all.insert(base), "every variant differs from the base");
}

/// docs/10 §1, §7: the keyd operation of each request, and the key set it
/// acts on — the krbtgt's `Krbtgt` key set, or the service object's key set
/// with the purpose its name derives (docs/52 R2b; Q-493 item 1): `Service`
/// for `ldap/<host>`, `AdminService` for `admind/<host>`; a service object
/// that is no target names no key set.
#[test]
fn operations_name_their_keyd_operation_and_purpose() {
    let (ldap, admin, other) = (guid(5), guid(6), guid(9));
    let targets = KeyTargets {
        krbtgt: guid(1),
        services: BTreeSet::from([
            service_key(ldap, "ldap", "dc01.example.test"),
            service_key(admin, "admind", "dc01.example.test"),
        ]),
    };
    for (operation, keyd, key, kvno) in [
        (
            KeyOperation::RotateKrbtgt,
            KeydOperation::RotateKrbtgt,
            Some((guid(1), KeyPurpose::Krbtgt)),
            true,
        ),
        (
            KeyOperation::RotateKey { service: ldap },
            KeydOperation::RotateKey,
            Some((ldap, KeyPurpose::Service)),
            true,
        ),
        (
            KeyOperation::RotateKey { service: admin },
            KeydOperation::RotateKey,
            Some((admin, KeyPurpose::AdminService)),
            true,
        ),
        (
            KeyOperation::RotateKey { service: other },
            KeydOperation::RotateKey,
            None,
            true,
        ),
        (
            KeyOperation::RetireKvno {
                key: KeyRef::Krbtgt,
                kvno: 1,
            },
            KeydOperation::RetireKvno,
            Some((guid(1), KeyPurpose::Krbtgt)),
            false,
        ),
        (
            KeyOperation::RetireKvno {
                key: KeyRef::Service(ldap),
                kvno: 1,
            },
            KeydOperation::RetireKvno,
            Some((ldap, KeyPurpose::Service)),
            false,
        ),
        (
            KeyOperation::RetireKvno {
                key: KeyRef::Service(admin),
                kvno: 1,
            },
            KeydOperation::RetireKvno,
            Some((admin, KeyPurpose::AdminService)),
            false,
        ),
    ] {
        assert_eq!(operation.keyd_operation(), keyd);
        assert_eq!(
            targets.handle_of(&operation),
            key.map(|(g, purpose)| KeyHandle::new(PrincipalId::from_bytes(g.to_packet()), purpose))
        );
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
        services: BTreeSet::from([
            service_key(guid(2), "ldap", "dc01.example.test"),
            service_key(guid(3), "admind", "dc01.example.test"),
        ]),
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

/// The domain's key sets: its krbtgt (RID 502) and its two service objects,
/// each named by the SPN tests/common gives it (`ldap/dc01.example.test`,
/// `admind/dc01.example.test`) through the one derivation (docs/52 R2b).
fn domain_targets() -> KeyTargets {
    KeyTargets {
        krbtgt: common::guid(common::KRBTGT),
        services: BTreeSet::from([
            service_key(common::guid(common::LDAP_SVC), "ldap", "dc01.example.test"),
            service_key(
                common::guid(common::ADMIND_SVC),
                "admind",
                "dc01.example.test",
            ),
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

/// The decision of a quorum-completing `Approve` of `operation`, requested
/// by admin1 and approved by admin2 against the test domain.
fn decided(table_seed: u64, operation: KeyOperation) -> DecidedOperation {
    let mut d = common::Domain::new("kr-r2b");
    with_policy_admin(&mut d);
    let mut table = KeyRequests::new(domain_targets(), KEY_REQUEST_LIFETIME, table_seed).unwrap();
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
    approved.decision().unwrap().operation.clone()
}

/// docs/52 R2b; docs/questions/Q-493 item 1 (the fix): `rotate_key` and
/// `retire_kvno` of the admin service object decide on its
/// `AdminService` key set — the key set keyd holds for `admind/<host>` and
/// the KDC seals admin tickets under (Q-491 item 1) — so keyd can run them
/// (the end-to-end run against keyd: crates/directory-daemon
/// tests/admin_service.rs); the LDAP service object's stay `Service`.
#[test]
fn the_admin_service_key_operations_name_its_admin_service_key_set() {
    let admin = KeyHandle::new(
        principal(common::guid(common::ADMIND_SVC)),
        KeyPurpose::AdminService,
    );
    let ldap = KeyHandle::new(
        principal(common::guid(common::LDAP_SVC)),
        KeyPurpose::Service,
    );
    assert_eq!(
        decided(
            4000,
            KeyOperation::RotateKey {
                service: common::guid(common::ADMIND_SVC)
            }
        ),
        DecidedOperation::RotateKey { handle: admin }
    );
    assert_eq!(
        decided(
            5000,
            KeyOperation::RetireKvno {
                key: KeyRef::Service(common::guid(common::ADMIND_SVC)),
                kvno: 1,
            }
        ),
        DecidedOperation::RetireKvno {
            handle: admin,
            kvno: Kvno::new(1),
        }
    );
    assert_eq!(
        decided(
            6000,
            KeyOperation::RotateKey {
                service: common::guid(common::LDAP_SVC)
            }
        ),
        DecidedOperation::RotateKey { handle: ldap }
    );
}

/// Attack (docs/52 R2b, class "one fact derived in two places"): a key
/// operation cannot name a purpose that contradicts the service's name.
/// The operation carries no purpose at all; the only purpose it gets is the
/// target's, which only the derivation from the name builds — so whatever
/// table a caller assembles, the admin service's object is `AdminService`
/// and nothing else is (the type has no other constructor: a hand-built
/// `(admind GUID, Service)` target does not compile). An approval naming a
/// service object outside the targets matches no request
/// (`OperationMismatch`), and a request for it is `ValueInvalid`.
#[test]
fn a_key_operation_cannot_name_a_purpose_against_the_name() {
    let admin = common::guid(common::ADMIND_SVC);
    // Whatever name a caller hands the derivation, the purpose follows it.
    for (class, purpose) in [
        ("admind", KeyPurpose::AdminService),
        ("ldap", KeyPurpose::Service),
    ] {
        let targets = KeyTargets {
            krbtgt: common::guid(common::KRBTGT),
            services: BTreeSet::from([service_key(admin, class, "dc01.example.test")]),
        };
        assert_eq!(
            targets
                .handle_of(&KeyOperation::RotateKey { service: admin })
                .map(|h| h.purpose),
            Some(purpose)
        );
    }
    // A service object that is not a target.
    let mut d = common::Domain::new("kr-r2b-attack");
    with_policy_admin(&mut d);
    let mut table = KeyRequests::new(domain_targets(), KEY_REQUEST_LIFETIME, 7000).unwrap();
    let outsider = KeyOperation::RotateKey {
        service: common::guid(common::BOB),
    };
    assert!(step(
        &d,
        &mut table,
        1,
        &KeyAdminOperation::RequestKeyOperation {
            operation: outsider
        },
        "admin1",
    )
    .is_err());
    let rotate = KeyOperation::RotateKey { service: admin };
    let opened = step(
        &d,
        &mut table,
        2,
        &KeyAdminOperation::RequestKeyOperation { operation: rotate },
        "admin1",
    )
    .unwrap();
    let KeyReply::Request(view) = opened.reply();
    let refused = step(
        &d,
        &mut table,
        3,
        &KeyAdminOperation::Approve {
            id: view.id,
            operation: outsider,
        },
        "admin2",
    )
    .unwrap_err();
    assert_eq!(
        refused.event().stage,
        DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::OperationMismatch))
    );
}
