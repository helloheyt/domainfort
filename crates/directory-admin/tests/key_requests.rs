//! Key operations through the one dual-control mechanism (task D2-c;
//! docs/questions/Q-882, A-148 — task A10's key-only table and steps are
//! retired): the operations' codes and the key sets they act on; and the
//! steps against the provisioned test domain (tests/common): a key
//! operation is proposed like every other dual-controlled operation, the
//! `Approve` that completes the quorum yields the decision dird registers
//! in keyd (docs/52 §4.3), one that does not yields none, an approval after
//! the quorum is a conflict, and a decision that could not be registered
//! reverts its approval; an approved key request is withdrawn or rejected
//! only once keyd revoked its decision (task F3). The key set of a service object carries the
//! purpose its name derives — `AdminService` for the admin service,
//! `Service` for the LDAP service (docs/52 R2b). The registration itself
//! runs against the real dird and keyd in crates/directory-daemon
//! tests/admin_service.rs.
//!
//! Sources: docs/51 §5.6, §6; docs/24 §6 (principle: sign the exact
//! operation); docs/10 §1, §7; docs/questions/Q-420, Q-460, Q-491 item 1,
//! Q-493 item 1, Q-882, Q-937 item 6, Q-977, Q-978 (task F3; A-126);
//! docs/52 §4.2, §4.3 (A-102), R2b. Every value is
//! constructed by hand for these tests; no vector comes from any other
//! implementation.

mod common;

use common::{request_view, with_policy_admin, Domain};
use directory_admin::{
    KeyOperation, KeyRef, KeyTargets, ProposedOperation, RefusalStatus, RegistrationOutcome,
    RequestState, RequestStep, RevocationFailure, StepReply,
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

fn principal(g: Guid) -> PrincipalId {
    PrincipalId::from_bytes(g.to_packet())
}

/// docs/10 §1, §7: the keyd operation of each key operation, and the key
/// set it acts on — the krbtgt's `Krbtgt` key set, or the service object's
/// key set with the purpose its name derives (docs/52 R2b; Q-493 item 1):
/// `Service` for `ldap/<host>`, `AdminService` for `admind/<host>`; a
/// service object that is no target names no key set.
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
}

/// admin1 proposes `operation`; returns the request's id and digest.
fn proposed(d: &mut Domain, operation: KeyOperation) -> (u64, keyd_types::OperationDigest) {
    let proposed = d
        .propose(ProposedOperation::Key(operation), "admin1", None)
        .unwrap();
    assert!(proposed.reply().state == RequestState::Pending);
    (proposed.reply().id, proposed.reply().digest)
}

/// docs/52 §4.3 (the key-operation rows), docs/51 §5.6 (R51-11: the
/// requester plus one other approver; `DualControlToken { approver_1: the
/// requester, approver_2: the approver }`), Q-460 (the decision lives no
/// longer than its request): with quorum 2, admin1's `Propose` yields no
/// decision; admin2's `Approve` completes the quorum and yields the decision
/// — id = the request's id, the krbtgt's `RotateKrbtgt`, approvers
/// [admin1, admin2], the request's remaining lifetime; a further approval is
/// a `Conflict` and yields nothing.
#[test]
fn the_quorum_completing_approve_yields_the_decision() {
    let mut d = Domain::new("kr-decision");
    with_policy_admin(&mut d);
    let (id, digest) = proposed(&mut d, KeyOperation::RotateKrbtgt);
    let approved = d.approve(id, digest, "admin2").unwrap();
    let decision = approved.decision().unwrap().clone();
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
        directory_admin::REQUEST_LIFETIME.as_secs()
    );
    assert_eq!(request_view(&approved).state, RequestState::Approved);
    // Its decision event names the step, the request, the key operation and
    // its fingerprint (Q-888); its registration's outcome is built on demand.
    let event = approved.event();
    assert_eq!(event.operation, DirAdminOperation::Approve);
    assert_eq!(
        event.stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    assert_eq!(event.pending_request, Some(id));
    assert_eq!(event.key_operation, Some(KeydOperation::RotateKrbtgt));
    assert_eq!(event.operation_digest, *digest.as_bytes());
    let quorum = approved.into_quorum().unwrap();
    assert_eq!(
        quorum
            .registration_event(RegistrationOutcome::Registered)
            .stage,
        DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
    );
    assert_eq!(
        quorum
            .registration_event(RegistrationOutcome::Refused)
            .stage,
        DirAdminStage::Outcome(OutcomeResult::Refused(AdminRefusal::KeyOperationRefused))
    );
    assert_eq!(
        quorum
            .registration_event(RegistrationOutcome::OutcomeUnknown)
            .stage,
        DirAdminStage::Outcome(OutcomeResult::Failed(
            AdminFailure::KeyOperationOutcomeUnknown
        ))
    );
    // After the quorum: a conflict, no decision.
    let again = d.approve(id, digest, "admin2").unwrap_err();
    assert_eq!(
        again.event().stage,
        DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::Conflict))
    );
}

/// docs/52 §4.3; Q-453 item 1 (fail closed): when the decision could not be
/// registered, dird reverts the approval that completed the quorum — the
/// request is pending again, the approver may approve again, and the same
/// decision is yielded again (keyd accepts an identical decision
/// unchanged). A retire decision names the key set and the kvno (Q-420
/// item 4).
#[test]
fn a_reverted_approval_can_be_given_again() {
    let mut d = Domain::new("kr-revert");
    with_policy_admin(&mut d);
    let operation = KeyOperation::RetireKvno {
        key: KeyRef::Service(common::guid(common::LDAP_SVC)),
        kvno: 4,
    };
    let (id, digest) = proposed(&mut d, operation);
    let decision = d
        .approve(id, digest, "admin2")
        .unwrap()
        .decision()
        .unwrap()
        .clone();
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
    assert!(d.requests.revert_approval(&decision));
    assert!(
        !d.requests.revert_approval(&decision),
        "only the completing approval"
    );
    let second = d.approve(id, digest, "admin2").unwrap();
    assert_eq!(second.decision(), Some(&decision));
}

/// docs/51 §5.6 (P-22: quorum 3 = the requester and two approvers);
/// docs/52 §4.3: an approval that does not complete the quorum yields no
/// decision (the test domain has two Tier-0 administrators, so the first
/// approval is the only one possible here).
#[test]
fn a_non_completing_approve_yields_no_decision() {
    let mut d = Domain::with_quorum("kr-quorum3", 3);
    with_policy_admin(&mut d);
    let (id, digest) = proposed(
        &mut d,
        KeyOperation::RotateKey {
            service: common::guid(common::ADMIND_SVC),
        },
    );
    let approved = d.approve(id, digest, "admin2").unwrap();
    assert!(approved.decision().is_none());
    let view = request_view(&approved);
    assert_eq!((view.approvals, view.quorum), (1, 3));
    assert_eq!(view.state, RequestState::Pending);
}

/// The decision of a quorum-completing `Approve` of `operation`, proposed
/// by admin1 and approved by admin2 against the test domain.
fn decided(name: &str, operation: KeyOperation) -> DecidedOperation {
    let mut d = Domain::new(name);
    with_policy_admin(&mut d);
    let (id, digest) = proposed(&mut d, operation);
    d.approve(id, digest, "admin2")
        .unwrap()
        .decision()
        .unwrap()
        .operation
        .clone()
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
            "kr-r2b-1",
            KeyOperation::RotateKey {
                service: common::guid(common::ADMIND_SVC)
            }
        ),
        DecidedOperation::RotateKey { handle: admin }
    );
    assert_eq!(
        decided(
            "kr-r2b-2",
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
            "kr-r2b-3",
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
/// target's, which only the derivation from the name builds. A proposal for
/// a service object outside the targets is `ValueInvalid`, and an approval
/// naming another digest than the request's is `OperationMismatch`; a kvno
/// of 0 is `ValueInvalid`.
#[test]
fn a_key_operation_cannot_name_a_purpose_against_the_name() {
    let admin = common::guid(common::ADMIND_SVC);
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
    let mut d = Domain::new("kr-r2b-attack");
    with_policy_admin(&mut d);
    for outsider in [
        KeyOperation::RotateKey {
            service: common::guid(common::BOB),
        },
        KeyOperation::RetireKvno {
            key: KeyRef::Krbtgt,
            kvno: 0,
        },
    ] {
        let refused = d
            .propose(ProposedOperation::Key(outsider), "admin1", None)
            .unwrap_err();
        assert_eq!(
            refused.event().stage,
            DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::ValueInvalid))
        );
    }
    let (id, _) = proposed(&mut d, KeyOperation::RotateKey { service: admin });
    let other = common::fingerprint(&KeyOperation::RotateKey {
        service: common::guid(common::BOB),
    });
    let refused = d.approve(id, other, "admin2").unwrap_err();
    assert_eq!(
        refused.event().stage,
        DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::OperationMismatch))
    );
}

/// The state of request `id` as admin1 sees it, or `None` when it is gone
/// (`PendingUnknown`).
fn state_of(d: &mut Domain, id: u64) -> Option<RequestState> {
    match d.step(RequestStep::Show { id }, "admin1") {
        Ok(shown) => match shown.reply() {
            StepReply::Shown(detail) => Some(detail.state),
            other => panic!("{other:?}"),
        },
        Err(refusal) => {
            assert_eq!(
                refusal.event().stage,
                DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::PendingUnknown))
            );
            None
        }
    }
}

/// Task F3 (docs/questions/Q-937 item 6 — the residual of A-159 — and
/// Q-977; docs/52 §4.3, A-102: the decision is registered in keyd at the
/// quorum; class C14, one fact, one holder): a pending key request is
/// withdrawn at once (keyd holds nothing for it). Once its quorum is
/// reached, its requester's `Withdraw` and an approver's `Reject` each
/// yield a [`directory_admin::RevocationStep`] naming the decision —
/// the request's id — and the request **stays approved** until the caller
/// reports keyd's revocation: when keyd refused (the decision ran) the step
/// is a `Conflict`, when keyd was not reached it is `Unavailable` — both
/// with the request kept; once keyd revoked it, `complete_revocation`
/// removes the request and the step's `Decision(Proceed)` event and "done"
/// stand.
#[test]
fn an_approved_key_request_leaves_only_through_keyds_revocation() {
    let mut d = Domain::new("kr-handed-over");
    with_policy_admin(&mut d);
    let (pending, _) = proposed(&mut d, KeyOperation::RotateKrbtgt);
    let withdrawn = d
        .step(RequestStep::Withdraw { id: pending }, "admin1")
        .unwrap();
    assert_eq!(withdrawn.reply(), &StepReply::Done);
    assert_eq!(withdrawn.revocation(), None);
    assert_eq!(state_of(&mut d, pending), None);

    let (id, digest) = proposed(&mut d, KeyOperation::RotateKrbtgt);
    let approved = d.approve(id, digest, "admin2").unwrap();
    assert!(approved.decision().is_some());
    for (step, caller) in [
        (RequestStep::Withdraw { id }, "admin1"),
        (RequestStep::Reject { id, digest }, "admin2"),
    ] {
        let stepped = d.step(step, caller).unwrap();
        assert_eq!(stepped.revocation(), Some(DecisionId::new(id)));
        assert!(stepped.decision().is_none());
        let revocation = stepped.into_revocation().unwrap();
        assert_eq!(revocation.decision(), DecisionId::new(id));
        assert_eq!(revocation.reply(), &StepReply::Done);
        assert_eq!(
            revocation.event().stage,
            DirAdminStage::Decision(DecisionResult::Proceed)
        );
        assert_eq!(revocation.event().pending_request, Some(id));
        assert_eq!(
            revocation.event().key_operation,
            Some(KeydOperation::RotateKrbtgt)
        );
        // keyd refused (the decision ran) / keyd not reached: refused, kept.
        let refused = revocation.refusal(RevocationFailure::Refused);
        assert_eq!(
            refused.event().stage,
            DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::Conflict))
        );
        assert_eq!(refused.status(), RefusalStatus::Conflict);
        assert_eq!(refused.event().pending_request, Some(id));
        let failed = revocation.refusal(RevocationFailure::Unavailable);
        assert_eq!(
            failed.event().stage,
            DirAdminStage::Decision(DecisionResult::Failed(AdminFailure::KeydUnavailable))
        );
        assert_eq!(failed.status(), RefusalStatus::Unavailable);
        assert_eq!(state_of(&mut d, id), Some(RequestState::Approved));
    }
    // keyd revoked it: the request is gone, once.
    let revocation = d
        .step(RequestStep::Withdraw { id }, "admin1")
        .unwrap()
        .into_revocation()
        .unwrap();
    assert!(d.requests.complete_revocation(&revocation));
    assert!(!d.requests.complete_revocation(&revocation));
    assert_eq!(state_of(&mut d, id), None);
}

/// Task F3 (docs/questions/Q-977 items 1, 3; class C14): an approved key
/// request never leaves the table except through keyd's revocation (or
/// expiry) — `discard` (the path of an unrecorded proposal) refuses it,
/// while it still drops a pending one; after a registration whose outcome
/// dird did not learn, keyd's revocation removes it through the
/// `QuorumStep`.
#[test]
fn an_approved_key_request_is_not_discarded() {
    let mut d = Domain::new("kr-not-discarded");
    with_policy_admin(&mut d);
    let (pending, _) = proposed(&mut d, KeyOperation::RotateKrbtgt);
    assert!(d.requests.discard(pending));
    assert_eq!(state_of(&mut d, pending), None);

    let (id, digest) = proposed(&mut d, KeyOperation::RotateKrbtgt);
    let quorum = d
        .approve(id, digest, "admin2")
        .unwrap()
        .into_quorum()
        .unwrap();
    assert!(!d.requests.discard(id));
    assert_eq!(state_of(&mut d, id), Some(RequestState::Approved));
    assert!(d.requests.revoked_after_unknown_registration(&quorum));
    assert_eq!(state_of(&mut d, id), None);
    assert!(!d.requests.revoked_after_unknown_registration(&quorum));
}

/// Task F3 (owner decision A-126 on docs/questions/Q-660 item 11; Q-978;
/// docs/52 R2b — the one derivation): when dird's key targets include the
/// change-password service's key set (`kadmin/changepw` derives
/// `ChangePasswordService`), a `RotateKey` / `RetireKvno` request naming
/// its object goes through the same dual-control path as the other
/// service keys, and the quorum yields the decision on exactly that key
/// set. The object here is the test domain's DC01 computer, named
/// `kadmin/changepw` in the targets (test data).
#[test]
fn the_change_password_key_set_is_a_dual_controlled_target() {
    let mut d = Domain::new("kr-changepw");
    with_policy_admin(&mut d);
    let changepw = common::guid(common::DC01);
    let change_password_name = PrincipalName {
        name_type: krb_proto::constants::KRB_NT_SRV_INST,
        name_string: vec![
            KerberosString::new("kadmin").unwrap(),
            KerberosString::new("changepw").unwrap(),
        ],
    };
    let mut targets = common::domain_targets();
    targets.services.insert(ServiceKeyHandle::of_service(
        principal(changepw),
        &change_password_name,
    ));
    d.requests = directory_admin::PendingRequests::new(
        targets,
        directory_admin::REQUEST_LIFETIME,
        directory_admin::REQUESTS_PER_REQUESTER,
    )
    .unwrap();
    let handle = KeyHandle::new(principal(changepw), KeyPurpose::ChangePasswordService);
    let rotate = KeyOperation::RotateKey { service: changepw };
    let (id, digest) = proposed(&mut d, rotate);
    let decision = d
        .approve(id, digest, "admin2")
        .unwrap()
        .decision()
        .unwrap()
        .clone();
    assert_eq!(decision.id, DecisionId::new(id));
    assert_eq!(decision.operation, DecidedOperation::RotateKey { handle });
    assert!(decision.operation.purposes_permitted());
    let retire = KeyOperation::RetireKvno {
        key: KeyRef::Service(changepw),
        kvno: 1,
    };
    let (id, digest) = proposed(&mut d, retire);
    let decision = d
        .approve(id, digest, "admin2")
        .unwrap()
        .decision()
        .unwrap()
        .clone();
    assert_eq!(
        decision.operation,
        DecidedOperation::RetireKvno {
            handle,
            kvno: Kvno::new(1)
        }
    );
}
