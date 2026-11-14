//! Task A13 (docs/51 §12): the admin plane end to end, over real sockets,
//! from `provision domain` to a new user's login — module `admin_world`
//! builds the world (provisioning, the test-only workstation fixture, the
//! key ceremony, every daemon in the docs/50 §7.5 order, the keyd phases of
//! the single-uid harness).
//!
//! 1. [`provisioning_to_a_new_users_login`] — the whole flow: ceremony and
//!    first administrators' passwords; the first administrators' armored AS,
//!    TGS for `admind/<dc-fqdn>` and AP-REQs (RFC 4120 §3.1-§3.3, §5.5.1;
//!    RFC 6113 §5.4); every admin operation through `admin.sock` (docs/51
//!    §5.2), dual control (P-22), a replay, a self-approval; the new user's
//!    login (AS, TGS for `ldap/<dc-fqdn>`), an ordinary user's writes, the
//!    login after `SetEnabled(false)` and after `Delete`; since A-102 the
//!    ceremony's seal, keyadm's `destroy-sweep` running the destroy decision
//!    dird registered for the deleted account, and a dual-controlled krbtgt
//!    rotation (request, approve — dird registers the decision — keyadm by
//!    decision id); then the verified audit log of the whole run and the
//!    absence of every password from every log and file.
//! 2. [`auditd_down_refuses_admin_writes_and_leaves_the_store_unchanged`].
//! 3. [`admind_down_the_client_sees_closure`].
//!
//! Sources: docs/51 §4.3, §4.4, §5.2, §5.3, §5.6, §5.7, §7.2-§7.6, §9, §12;
//! docs/50 §3.3, §7.5, §8.1, §9; docs/47 §4, §9.2; RFC 4120 §3.1.5, §3.2.2,
//! §3.2.3, §3.3, §5.5.1, §7.5.1; RFC 6113 §5.4.1.1, §5.4.2, §5.4.4; A-26,
//! A-57, A-64, A-85, A-86, A-88, A-91, A-94, A-96; P-10, P-22, P-23;
//! docs/52 §4.2-§4.5 (A-102). Every value is hand-made test data.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

mod admin_world;

use admin_world::*;
use dtyp::Guid;
use ipc_admin::{RefusalStatus, Reply};
use ipc_audit::{
    AdminRefusal, AdmindActivity, DecisionResult, DirAdminEvent, DirAdminOperation, DirAdminStage,
    EventBody, KdcEvent, KdcExchange, KdcOutcome, KeyPurposeCode, KeydOperation, KeydOutcome,
    KeydReason, KeydRecord, KeydRole, OutcomeResult, PasswordFailure, PasswordResult, PasswordStep,
};
use ipc_dird_admin::{Auth, LookupKey, Operation};
use keyadm::ceremony::Step;
use keyd::KeyHandle;
use keyd_types::Kvno;
use krb_proto::constants::{KDC_ERR_CLIENT_REVOKED, KDC_ERR_C_PRINCIPAL_UNKNOWN};
use provision::ObjectRole;
use support::{within, TEST_BOUND};

// ---------------------------------------------------------------------------
// Helpers over the audit log.
// ---------------------------------------------------------------------------

/// The name components of an audited principal.
fn components(principal: &Option<ipc_audit::Principal>) -> Vec<String> {
    principal
        .as_ref()
        .and_then(|p| p.components())
        .map(|c| {
            c.iter()
                .map(|t| t.as_text().unwrap_or("?").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn keyd_records(events: &[(u64, EventBody)]) -> Vec<(u64, &KeydRecord)> {
    events
        .iter()
        .filter_map(|(seq, e)| match e {
            EventBody::Keyd(r) => Some((*seq, r.as_ref())),
            _ => None,
        })
        .collect()
}

fn dir_admin_events(events: &[(u64, EventBody)]) -> Vec<(u64, &DirAdminEvent)> {
    events
        .iter()
        .filter_map(|(seq, e)| match e {
            EventBody::DirAdmin(d) => Some((*seq, d.as_ref())),
            _ => None,
        })
        .collect()
}

fn kdc_events(events: &[(u64, EventBody)]) -> Vec<(u64, &KdcEvent)> {
    events
        .iter()
        .filter_map(|(seq, e)| match e {
            EventBody::Kdc(k) => Some((*seq, k.as_ref())),
            _ => None,
        })
        .collect()
}

/// keyd's two records of one key-state change of `handle` by `op` (A-86 /
/// A-88: the `Intent` acknowledged before the change, then the outcome):
/// their sequence numbers, the intent first.
fn intent_then_success(
    records: &[(u64, &KeydRecord)],
    op: KeydOperation,
    handle: &KeyHandle,
    role: KeydRole,
) -> (u64, u64) {
    intent_then_success_where(records, op, handle, role, |_| true)
}

/// [`intent_then_success`] among the records `keep` admits (A-102: two
/// decisions may name the same key set — a password set and a destruction).
fn intent_then_success_where(
    records: &[(u64, &KeydRecord)],
    op: KeydOperation,
    handle: &KeyHandle,
    role: KeydRole,
    keep: impl Fn(&KeydRecord) -> bool,
) -> (u64, u64) {
    let purpose = match handle.purpose {
        keyd::KeyPurpose::PrincipalLongterm => KeyPurposeCode::PrincipalLongterm,
        keyd::KeyPurpose::Krbtgt => KeyPurposeCode::Krbtgt,
        keyd::KeyPurpose::Service => KeyPurposeCode::Service,
        keyd::KeyPurpose::AdminService => KeyPurposeCode::AdminService,
    };
    let of = |result: KeydOutcome| {
        let found: Vec<u64> = records
            .iter()
            .filter(|(_, r)| {
                r.op == op
                    && r.result == result
                    && r.principal == Some(*handle.principal.as_bytes())
                    && r.purpose == Some(purpose)
                    && keep(r)
            })
            .map(|(seq, r)| {
                assert_eq!(r.caller_role, role, "{op:?} by {role:?}");
                *seq
            })
            .collect();
        assert_eq!(found.len(), 1, "one {result:?} record of {op:?} {handle:?}");
        found[0]
    };
    let intent = of(KeydOutcome::Intent);
    let success = of(KeydOutcome::Success);
    assert!(intent < success, "the intent precedes the outcome (A-86)");
    (intent, success)
}

/// What a `DirAdmin` event says, without its numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Said {
    Proceed,
    Refused(AdminRefusal),
    Committed,
}

fn said(event: &DirAdminEvent) -> Said {
    match event.stage {
        DirAdminStage::Decision(DecisionResult::Proceed) => Said::Proceed,
        DirAdminStage::Decision(DecisionResult::Refused(code)) => Said::Refused(code),
        DirAdminStage::Outcome(OutcomeResult::Committed { .. }) => Said::Committed,
        other => panic!("an unexpected admin event: {other:?}"),
    }
}

fn packet(guid: Guid) -> [u8; 16] {
    guid.to_packet()
}

/// The key set handle of an account (docs/47 §9.1: `(objectGUID,
/// PrincipalLongterm)`; directory-pip: the principal id is the GUID's
/// packet form).
fn longterm(guid: Guid) -> KeyHandle {
    KeyHandle::new(
        keyd_types::PrincipalId::from_bytes(guid.to_packet()),
        keyd::KeyPurpose::PrincipalLongterm,
    )
}

fn create_user(parent: Guid, sam: &str) -> Operation {
    Operation::CreateUser {
        parent,
        sam: sam.to_owned(),
        upn: None,
        description: None,
    }
}

// ---------------------------------------------------------------------------
// 1. The whole flow.
// ---------------------------------------------------------------------------

/// docs/51 §12 (A13), §4.3 steps 1-14, §5.2, §5.6, §7, §9; RFC 4120 §3.1-§3.3,
/// §5.5.1; RFC 6113 §5.4. From `provision domain` to a new user's login and
/// its revocation, every daemon over its real sockets; then the audit log
/// of the run and the absence of every password.
#[test]
fn provisioning_to_a_new_users_login() {
    within(TEST_BOUND, || {
        let _serial = serial();
        let Some(mut w) = World::provisioned() else {
            return;
        };

        // ---- 2. The key ceremony (docs/51 §4.3 steps 10-12) -------------------
        w.start_auditd();
        let ceremony = w.ceremony();
        assert!(ceremony.is_complete(), "keyadm ceremony: {:?}", w.captured);
        assert_eq!(
            ceremony.created(),
            vec![
                (Step::Krbtgt, Kvno::INITIAL),
                (Step::LdapService, Kvno::INITIAL),
                (Step::AdminService, Kvno::INITIAL),
            ],
            "create_key ×3, each a new key set (docs/51 §4.3 step 11)"
        );
        let (secrets, drops) = w.first_admin_secret();
        assert!(secrets.is_complete(), "first-admin-secret");
        assert_eq!(
            secrets.set(),
            vec![(ALICE, Kvno::INITIAL), (BOB, Kvno::INITIAL)],
            "set_secret per first administrator, in the manifest's order"
        );
        assert_eq!(
            drops,
            vec![(w.input.accounts.admind.uid, w.input.accounts.admind.gid)],
            "dropped to admind's account, as Role::Directory (docs/51 §4.3 step 12)"
        );
        for sam in [ALICE, BOB] {
            assert!(!w.dir.join(format!("etc/{sam}.pw")).exists());
        }
        assert_eq!(w.workstation_secret(), vec![Kvno::INITIAL]);

        // ---- 3. The rest of the daemons (docs/50 §7.5) ------------------------
        w.keyd_phase(KeydPhase::Kerberos);
        w.start_dird();
        w.start_kdc();
        w.start_front();
        w.start_admind();

        // ---- 4. The first administrators log in -------------------------------
        let ws = w.bootstrap_workstation();
        let alice_tgt = w
            .armored_as(&ws, ALICE, ALICE_PASSWORD)
            .unwrap_or_else(|e| panic!("alice's armored AS: {}", e.inner.error_code));
        let bob_tgt = w
            .armored_as(&ws, BOB, BOB_PASSWORD)
            .unwrap_or_else(|e| panic!("bob's armored AS: {}", e.inner.error_code));
        let alice = w.persona(ALICE, &alice_tgt);
        let bob = w.persona(BOB, &bob_tgt);
        assert_eq!(alice.ticket.cname, principal(ALICE));

        // ---- 5. Admin operations through admin.sock ---------------------------
        w.advance(10);
        w.keyd_phase(KeydPhase::Admin);
        let tier0 = w.guid(ObjectRole::Tier0Ou);
        let workstations = w.guid(ObjectRole::WorkstationsOu);
        // Under the explicit Tier-0 subtree: dual control (P-22 item 1).
        assert_eq!(
            w.forward(&alice, &[], create_user(tier0, "carol"))
                .refusal(),
            RefusalStatus::ApprovalRequired,
            "a create in the Tier-0 OU needs a second Tier-0 administrator"
        );
        assert_eq!(
            w.forward(&alice, &[&alice], create_user(tier0, "carol"))
                .refusal(),
            RefusalStatus::Denied,
            "the requester cannot approve their own request (docs/51 §5.6)"
        );
        let carol = w
            .forward(&alice, &[&bob], create_user(tier0, "carol"))
            .created();
        // Unclassified: one Tier-0 administrator suffices.
        let dave = w
            .forward(&alice, &[], create_user(workstations, "dave"))
            .created();
        // A replayed AP-REQ (RFC 4120 §3.2.3; keyd's replay cache) — and
        // the same AP-REQ attached to another operation (R2: refused, the
        // binding does not match; docs/52 §3.2, Q-292).
        let group = |sam: &str| Operation::CreateGroup {
            parent: workstations,
            sam: sam.to_owned(),
            group_type: None,
        };
        let once = w.ap_req(&alice, &group("e2e-staff"));
        let staff = w
            .admin(&ipc_admin::Request::Forward {
                auth: Auth {
                    requester: once.clone(),
                    approvals: Vec::new(),
                },
                operation: group("e2e-staff"),
            })
            .created();
        assert_eq!(
            w.admin(&ipc_admin::Request::Forward {
                auth: Auth {
                    requester: once.clone(),
                    approvals: Vec::new(),
                },
                operation: group("e2e-staff"),
            })
            .refusal(),
            RefusalStatus::Denied,
            "a replayed AP-REQ is refused"
        );
        assert_eq!(
            w.admin(&ipc_admin::Request::Forward {
                auth: Auth {
                    requester: once,
                    approvals: Vec::new(),
                },
                operation: group("e2e-other"),
            })
            .refusal(),
            RefusalStatus::Denied,
            "an AP-REQ attached to another operation is refused (R2)"
        );
        // A fresh AP-REQ made for one operation and forwarded with another
        // (what a compromised admind could try, Q-292): refused by keyd's
        // check of the Authenticator's cksum (R2, docs/52 §5).
        let made_for = w.ap_req(&alice, &group("e2e-meant"));
        assert_eq!(
            w.admin(&ipc_admin::Request::Forward {
                auth: Auth {
                    requester: made_for,
                    approvals: Vec::new(),
                },
                operation: group("e2e-hijacked"),
            })
            .refusal(),
            RefusalStatus::Denied,
            "an AP-REQ bound to another operation is refused (R2)"
        );
        // SetPassword: two AP-REQs (A-94).
        match w.set_password(&alice, &[], dave, NEW_USER_PASSWORD).reply() {
            Reply::PasswordChanged(changed) => {
                assert_eq!(changed.kvnos, vec![1], "one set_secret, the first kvno");
                assert!(changed.completion_recorded, "CompletePasswordSet accepted");
            }
            other => panic!("SetPassword: {other:?}"),
        }
        // Task A15a (the attack of docs/questions/Q-291): a Directory client
        // like admind that calls keyd's set_secret with no BeginPasswordSet
        // before it — here for alice, a Tier-0 administrator — is refused
        // with keyd's uniform Denied: dird's PDP never granted it. Nothing
        // changes (alice keeps her password; her later operations work).
        let alice_key_set = w.manifest.first_admins()[0].key_set().clone();
        let mut rogue = key_state_client(&w.aux_keyd_socket, w.uid, keyd::Role::Directory);
        let rogue_call = ipc_keyd::Call::SetSecret {
            handle: alice_key_set.handle,
            binding: alice_key_set.binding.clone(),
            password: ipc_keyd::Password::new(zeroize::Zeroizing::new(ROGUE_PASSWORD.to_owned())),
            salt: format!("{REALM}{ALICE}"),
        };
        assert!(
            matches!(
                rogue.call_with_fate(&rogue_call),
                Ok(ipc_keyd::Answer::SetSecret(Err(keyd_types::Error::Denied)))
            ),
            "a set_secret without dird's grant is refused (task A15a)"
        );
        // CreateUser makes N|D (docs/51 §5.2 row 1): enable before the login.
        assert_eq!(
            w.forward(
                &alice,
                &[],
                Operation::SetEnabled {
                    target: dave,
                    enabled: true
                }
            )
            .reply(),
            Reply::Done
        );
        match w
            .forward(
                &alice,
                &[],
                Operation::Lookup(LookupKey::SamAccountName("dave".to_owned())),
            )
            .reply()
        {
            Reply::Found(found) => {
                assert_eq!(found.guid, dave);
                assert_eq!(found.class, "user");
                assert_eq!(
                    found.dn,
                    ["cn=dave", "ou=Workstations", "dc=example", "dc=org"]
                );
                assert!(found.sid.is_some());
            }
            other => panic!("Lookup: {other:?}"),
        }
        for operation in [
            Operation::AddMember {
                group: staff,
                member: dave,
            },
            Operation::RemoveMember {
                group: staff,
                member: dave,
            },
        ] {
            assert_eq!(w.forward(&alice, &[], operation).reply(), Reply::Done);
        }

        // ---- 6. The new user logs in -----------------------------------------
        w.advance(50);
        w.keyd_phase(KeydPhase::Kerberos);
        let dave_tgt = w
            .armored_as(&ws, "dave", NEW_USER_PASSWORD)
            .unwrap_or_else(|e| panic!("dave's armored AS: {}", e.inner.error_code));
        let ldap = w.ldap_service();
        let dave_ldap = w.service_ticket(&dave_tgt, &ldap);
        assert_eq!(dave_ldap.cname, principal("dave"));
        let dave_admin = w.persona("dave", &dave_tgt);

        // ---- 8. An ordinary user: every write refused --------------------------
        w.advance(10);
        w.keyd_phase(KeydPhase::Admin);
        let alice_guid = w.guid(ObjectRole::FirstAdmin(0));
        let tier0_group = w.guid(ObjectRole::Tier0Group);
        for operation in [
            create_user(workstations, "mallory"),
            create_user(tier0, "mallory"),
            group("mallory-group"),
            Operation::SetEnabled {
                target: alice_guid,
                enabled: false,
            },
            Operation::AddMember {
                group: tier0_group,
                member: dave,
            },
            Operation::AddMember {
                group: staff,
                member: dave,
            },
            Operation::Delete { target: carol },
        ] {
            let status = w.forward(&dave_admin, &[], operation.clone()).refusal();
            assert!(
                matches!(status, RefusalStatus::Denied | RefusalStatus::NotFound),
                "{operation:?}: {status:?} (Denied, or NotFound for an object the \
                 ordinary user cannot see — A-55)"
            );
        }
        let status = w
            .set_password(&dave_admin, &[], alice_guid, NEW_USER_PASSWORD)
            .refusal();
        assert!(matches!(
            status,
            RefusalStatus::Denied | RefusalStatus::NotFound
        ));
        assert_eq!(
            w.forward(
                &alice,
                &[],
                Operation::Lookup(LookupKey::SamAccountName("mallory".to_owned())),
            )
            .refusal(),
            RefusalStatus::NotFound,
            "nothing was created"
        );
        assert_eq!(
            w.forward(
                &alice,
                &[],
                Operation::SetEnabled {
                    target: dave,
                    enabled: false
                }
            )
            .reply(),
            Reply::Done
        );

        // ---- 6. After SetEnabled(false): the AS fails ---------------------------
        w.advance(10);
        w.keyd_phase(KeydPhase::Kerberos);
        let revoked = w
            .armored_as(&ws, "dave", NEW_USER_PASSWORD)
            .err()
            .expect("a disabled account gets no TGT");
        assert_eq!(revoked.inner.error_code, KDC_ERR_CLIENT_REVOKED, "R7");

        // ---- After Delete: the uniform answer ------------------------------------
        w.advance(10);
        w.keyd_phase(KeydPhase::Admin);
        assert_eq!(
            w.forward(&alice, &[], Operation::Delete { target: dave })
                .reply(),
            Reply::Done
        );
        // A-102 (docs/52 §4.3): dird registered a destroy decision for
        // dave's tombstone; keyadm's sweep (Role::Admin on the same keyd)
        // runs exactly it — keyadm destroys only what dird decided.
        let swept = keyadm::sweep::run(&mut key_state_client(
            &w.grant_keyd_socket,
            w.uid,
            keyd::Role::Admin,
        ));
        assert!(swept.is_complete(), "{swept:?}");
        assert_eq!(
            swept
                .destroyed
                .iter()
                .map(|e| e.principal)
                .collect::<Vec<_>>(),
            [longterm(dave).principal],
            "{swept:?}"
        );
        let destroy_decision = swept.destroyed[0].decision;
        // A-102 (docs/52 §4.2): a dual-controlled key operation — alice
        // requests, bob approves (the approval that completes the quorum
        // makes dird register the decision in keyd), keyadm runs it by the
        // request's id; keyd builds the dual-control token itself.
        let rotation = ipc_dird_admin::KeyOperation::RotateKrbtgt;
        let request_id = match w
            .forward(
                &alice,
                &[],
                Operation::RequestKeyOperation {
                    operation: rotation,
                },
            )
            .reply()
        {
            Reply::KeyRequest(state) => state.id,
            other => panic!("RequestKeyOperation: {other:?}"),
        };
        match w
            .forward(
                &bob,
                &[],
                Operation::Approve {
                    id: request_id,
                    operation: rotation,
                },
            )
            .reply()
        {
            Reply::KeyRequest(state) => assert!(state.approved()),
            other => panic!("Approve: {other:?}"),
        }
        let rotated = keyadm::execute::run(
            &mut key_state_client(&w.grant_keyd_socket, w.uid, keyd::Role::Admin),
            keyadm::cli::Approved::RotateKrbtgt,
            request_id,
        );
        assert_eq!(
            rotated.keyd,
            keyadm::ceremony::Outcome::Answered(Ok(Some(Kvno::new(2)))),
            "{rotated:?}"
        );
        w.advance(10);
        w.keyd_phase(KeydPhase::Kerberos);
        let deleted = w
            .armored_as(&ws, "dave", NEW_USER_PASSWORD)
            .err()
            .expect("a deleted account gets no TGT");
        let never = w
            .armored_as(&ws, "nobody", NEW_USER_PASSWORD)
            .err()
            .expect("an account that never existed gets no TGT");
        assert_eq!(deleted.inner.error_code, KDC_ERR_C_PRINCIPAL_UNKNOWN, "R6");
        assert_eq!(
            (deleted.inner.error_code, deleted.padata_types()),
            (never.inner.error_code, never.padata_types()),
            "the deleted account is answered as one that never existed"
        );

        // ---- 7. The audit log of the whole run -----------------------------------
        let events = w.finish();
        let keyd = keyd_records(&events);
        let m = w.manifest.clone();
        // keyd's intents and outcomes (A-86, A-88), lifetime after lifetime.
        let ceremony: Vec<(u64, u64)> = [m.krbtgt(), m.ldap_service(), m.admin_service()]
            .iter()
            .map(|k| {
                intent_then_success(&keyd, KeydOperation::CreateKey, &k.handle, KeydRole::Admin)
            })
            .collect();
        let first_admins: Vec<(u64, u64)> = m
            .first_admins()
            .iter()
            .map(|a| {
                intent_then_success(
                    &keyd,
                    KeydOperation::SetSecret,
                    &a.key_set().handle,
                    KeydRole::Directory,
                )
            })
            .collect();
        let fixture = intent_then_success(
            &keyd,
            KeydOperation::SetSecret,
            &w.workstation.keys[0].handle,
            KeydRole::Directory,
        );
        let dave_secret = intent_then_success(
            &keyd,
            KeydOperation::SetSecret,
            &longterm(dave),
            KeydRole::Directory,
        );
        let last = |pairs: &[(u64, u64)]| pairs.iter().map(|p| p.1).max().unwrap();
        let first = |pairs: &[(u64, u64)]| pairs.iter().map(|p| p.0).min().unwrap();
        assert!(
            last(&ceremony) < first(&first_admins),
            "ceremony, then first admins"
        );
        assert!(
            last(&first_admins) < fixture.0,
            "then the workstation fixture"
        );
        assert!(fixture.1 < dave_secret.0, "then admind's set_secret");
        // The grants (task A15a): the ceremony's for each first
        // administrator (Admin), then — after dird's PDP — dird's for dave
        // (Ldap), each acknowledged as an intent first and before the
        // set_secret it allows.
        let ceremony_grants: Vec<(u64, u64)> = m
            .first_admins()
            .iter()
            .map(|a| {
                intent_then_success(
                    &keyd,
                    KeydOperation::GrantSetSecret,
                    &a.key_set().handle,
                    KeydRole::Admin,
                )
            })
            .collect();
        // A-102: dird's grants are `SetSecret` decisions (`RegisterDecision`,
        // Role::Ldap); a user's names no second key set, the destroy decision
        // of a deleted account names its Service key set as the second.
        let fixture_grant = intent_then_success_where(
            &keyd,
            KeydOperation::RegisterDecision,
            &w.workstation.keys[0].handle,
            KeydRole::Ldap,
            |_| true,
        );
        let dave_grant = intent_then_success_where(
            &keyd,
            KeydOperation::RegisterDecision,
            &longterm(dave),
            KeydRole::Ldap,
            |r| r.secondary.is_none(),
        );
        let dave_destroy_decision = intent_then_success_where(
            &keyd,
            KeydOperation::RegisterDecision,
            &longterm(dave),
            KeydRole::Ldap,
            |r| r.secondary.is_some(),
        );
        let dave_destroyed = intent_then_success(
            &keyd,
            KeydOperation::DestroyKeySet,
            &longterm(dave),
            KeydRole::Admin,
        );
        assert!(dave_secret.1 < dave_destroy_decision.0);
        assert!(
            dave_destroy_decision.1 < dave_destroyed.0,
            "dird's destroy decision, then keyadm's destroy_key_set (A-102)"
        );
        let destroyed = keyd
            .iter()
            .find(|(seq, _)| *seq == dave_destroyed.1)
            .map(|(_, r)| *r)
            .unwrap();
        assert_eq!(destroyed.decision, Some(destroy_decision.get()));
        // The krbtgt rotation: dird's decision, then keyadm's execution —
        // keyd's records carry the decision id and alice's and bob's GUIDs
        // from dird's decision (A-102, docs/52 §4.5).
        let krbtgt_decision = intent_then_success(
            &keyd,
            KeydOperation::RegisterDecision,
            &m.krbtgt().handle,
            KeydRole::Ldap,
        );
        let krbtgt_rotation = intent_then_success(
            &keyd,
            KeydOperation::RotateKrbtgt,
            &m.krbtgt().handle,
            KeydRole::Admin,
        );
        assert!(krbtgt_decision.1 < krbtgt_rotation.0);
        let rotation_record = keyd
            .iter()
            .find(|(seq, _)| *seq == krbtgt_rotation.1)
            .map(|(_, r)| *r)
            .unwrap();
        assert_eq!(rotation_record.decision, Some(request_id));
        assert_eq!(rotation_record.kvno, Some(2));
        assert_eq!(
            rotation_record.approvers,
            Some([
                packet(w.guid(ObjectRole::FirstAdmin(0))),
                packet(w.guid(ObjectRole::FirstAdmin(1)))
            ])
        );
        // The seal (A-102, docs/52 R3): after the ceremony's grants, before
        // the first administrators' secrets — one record, no intent.
        let seals: Vec<u64> = keyd
            .iter()
            .filter(|(_, r)| r.op == KeydOperation::SealCeremony)
            .map(|(seq, r)| {
                assert_eq!(r.result, KeydOutcome::Success);
                assert_eq!(r.caller_role, KeydRole::Admin);
                *seq
            })
            .collect();
        assert_eq!(seals.len(), 1, "one seal, no intent");
        assert!(last(&ceremony) < first(&ceremony_grants));
        assert!(last(&ceremony_grants) < seals[0]);
        assert!(seals[0] < first(&first_admins));
        assert!(last(&ceremony_grants) < first(&first_admins));
        assert!(fixture_grant.1 < fixture.0);
        assert!(
            dave_grant.1 < dave_secret.0,
            "dird's grant, then admind's set_secret"
        );
        // The rogue set_secret: one record, refused at keyd's authorization
        // step for want of a grant — no intent (A-88).
        let rogue: Vec<&KeydRecord> = keyd
            .iter()
            .filter(|(_, r)| {
                r.op == KeydOperation::SetSecret
                    && r.reason == KeydReason::NoGrant
                    && r.principal == Some(*alice_key_set.handle.principal.as_bytes())
            })
            .map(|(_, r)| *r)
            .collect();
        assert_eq!(rogue.len(), 1, "{rogue:?}");
        assert_eq!(rogue[0].result, KeydOutcome::Denied);
        assert_eq!(rogue[0].caller_role, KeydRole::Directory);
        assert!(
            keyd.iter()
                .any(|(_, r)| r.op == KeydOperation::OpenAndVerifyServiceTicket
                    && r.caller_role == KeydRole::Ldap
                    && r.result == KeydOutcome::Success),
            "dird verified the AP-REQs under Role::Ldap (A-73)"
        );
        assert!(
            keyd.iter()
                .any(|(_, r)| r.op == KeydOperation::OpenAndVerifyServiceTicket
                    && r.caller_role == KeydRole::Ldap
                    && r.result == KeydOutcome::Denied
                    && r.reason == KeydReason::Replay),
            "keyd refused the replayed AP-REQ from its replay cache (RFC 4120 §3.2.3)"
        );
        assert_eq!(
            keyd.iter()
                .filter(|(_, r)| r.op == KeydOperation::OpenAndVerifyServiceTicket
                    && r.caller_role == KeydRole::Ldap
                    && r.result == KeydOutcome::Denied
                    && r.reason == KeydReason::OperationDigestMismatch
                    && r.purpose == Some(KeyPurposeCode::AdminService))
                .count(),
            2,
            "keyd refused both AP-REQs attached to another operation by their cksum, \
             under the admin service's own key set (R2, docs/52 §5)"
        );

        // dird's DirAdmin decision → outcome pairs (A-85), in dird's order.
        let admin = dir_admin_events(&events);
        let mut ops: Vec<u64> = admin.iter().map(|(_, e)| e.operation_id).collect();
        ops.dedup();
        assert!(
            ops.windows(2).all(|p| p[0] < p[1]),
            "operation numbers increase"
        );
        for (seq, decision) in &admin {
            if let DirAdminStage::Outcome(_) = decision.stage {
                let opened = admin.iter().any(|(s, d)| {
                    s < seq
                        && d.operation_id == decision.operation_id
                        && d.stage == DirAdminStage::Decision(DecisionResult::Proceed)
                });
                assert!(opened, "every outcome follows its Proceed decision");
            }
        }
        let trail: Vec<(DirAdminOperation, Said)> =
            admin.iter().map(|(_, e)| (e.operation, said(e))).collect();
        use DirAdminOperation as Op;
        use Said::*;
        let mut expected = vec![
            (Op::CreateUser, Refused(AdminRefusal::ApprovalRequired)),
            (Op::CreateUser, Refused(AdminRefusal::ApproverNotDistinct)),
            (Op::CreateUser, Proceed),
            (Op::CreateUser, Committed),
            (Op::CreateUser, Proceed),
            (Op::CreateUser, Committed),
            (Op::CreateGroup, Proceed),
            (Op::CreateGroup, Committed),
            // The replayed AP-REQ, the same AP-REQ attached to another group
            // and a fresh one bound to another operation (R2).
            (Op::CreateGroup, Refused(AdminRefusal::Unauthenticated)),
            (Op::CreateGroup, Refused(AdminRefusal::Unauthenticated)),
            (Op::CreateGroup, Refused(AdminRefusal::Unauthenticated)),
            (Op::BeginPasswordSet, Proceed),
            (Op::BeginPasswordSet, Committed),
            (Op::CompletePasswordSet, Proceed),
            (Op::SetEnabled, Proceed),
            (Op::SetEnabled, Committed),
            (Op::Lookup, Proceed),
            (Op::AddMember, Proceed),
            (Op::AddMember, Committed),
            (Op::RemoveMember, Proceed),
            (Op::RemoveMember, Committed),
        ];
        let ordinary = trail[expected.len()..expected.len() + 8].to_vec();
        for (op, said) in &ordinary {
            assert!(
                matches!(
                    said,
                    Refused(AdminRefusal::PolicyDenied) | Refused(AdminRefusal::NotVisible)
                ),
                "the ordinary user's {op:?}: {said:?}"
            );
        }
        expected.extend(ordinary);
        expected.extend([
            (Op::Lookup, Refused(AdminRefusal::NotFound)),
            (Op::SetEnabled, Proceed),
            (Op::SetEnabled, Committed),
            (Op::Delete, Proceed),
            (Op::Delete, Committed),
            // A-102: the krbtgt rotation — the request, then the approval
            // that completed the quorum and its registration in keyd.
            (Op::RequestKeyOperation, Proceed),
            (Op::Approve, Proceed),
            (Op::Approve, Committed),
        ]);
        assert_eq!(trail, expected, "dird's admin trail of the run");
        let by_op = |op: Op, target: Guid, s: Said| -> u64 {
            admin
                .iter()
                .find(|(_, e)| {
                    e.operation == op && e.target == Some(packet(target)) && said(e) == s
                })
                .map(|(seq, _)| *seq)
                .unwrap_or_else(|| panic!("{op:?} {s:?}"))
        };
        // Dual control: bob's SID among the approvers of carol's create.
        let carol_create = admin
            .iter()
            .find(|(_, e)| e.operation == Op::CreateUser && said(e) == Proceed)
            .unwrap()
            .1;
        assert_eq!(carol_create.approvers.len(), 1, "one approver (P-22)");
        // The password set: dird's begin ⇒ keyd's intent ⇒ dird's completion
        // (each decision acknowledged before the next step, A-85 / A-86).
        let begin = by_op(Op::BeginPasswordSet, dave, Proceed);
        let complete = by_op(Op::CompletePasswordSet, dave, Proceed);
        assert!(begin < dave_secret.0 && dave_secret.0 < complete);

        // admind's SetPassword events (docs/51 §5.7 item 3).
        let admind: Vec<(u64, &AdmindActivity)> = events
            .iter()
            .filter_map(|(seq, e)| match e {
                EventBody::Admind(a) => Some((*seq, &a.activity)),
                _ => None,
            })
            .collect();
        assert!(
            admind.iter().any(|(_, a)| matches!(a,
            AdmindActivity::SetPassword { target, kvnos, result: PasswordResult::Completed }
                if *target == packet(dave) && kvnos.as_slice() == [1])),
            "admind recorded dave's completed SetPassword with kvno 1"
        );
        assert!(
            admind.iter().any(|(_, a)| matches!(a,
            AdmindActivity::SetPassword {
                target,
                result: PasswordResult::Failed {
                    step: PasswordStep::BeginPasswordSet,
                    cause: PasswordFailure::Denied,
                },
                ..
            } if *target == packet(alice_guid))),
            "admind recorded the ordinary user's refused SetPassword"
        );

        // The kdc's AS / TGS events.
        let kdc = kdc_events(&events);
        let kdc_seq = |exchange: KdcExchange,
                       client: &str,
                       service: Option<&str>,
                       outcome: KdcOutcome|
         -> Vec<u64> {
            kdc.iter()
                .filter(|(_, e)| {
                    e.exchange == Some(exchange)
                        && components(&e.client) == [client]
                        && service.is_none_or(|s| {
                            components(&e.service).first().map(String::as_str) == Some(s)
                        })
                        && e.outcome == outcome
                })
                .map(|(seq, _)| *seq)
                .collect()
        };
        let issued = KdcOutcome::Issued;
        assert_eq!(
            kdc_seq(KdcExchange::As, WORKSTATION_SAM, None, issued).len(),
            1
        );
        for sam in [ALICE, BOB] {
            assert_eq!(
                kdc_seq(KdcExchange::As, sam, None, issued).len(),
                1,
                "{sam}'s AS"
            );
            assert_eq!(
                kdc_seq(KdcExchange::Tgs, sam, Some("admind"), issued).len(),
                1,
                "{sam}'s TGS for admind/"
            );
        }
        let armored = kdc
            .iter()
            .filter(|(_, e)| {
                e.exchange == Some(KdcExchange::As) && components(&e.client) == [ALICE]
            })
            .all(|(_, e)| e.reply_armored && components(&e.armor_principal) == [WORKSTATION_SAM]);
        assert!(
            armored,
            "alice's AS armored by the workstation's TGT (RFC 6113)"
        );
        let dave_as = kdc_seq(KdcExchange::As, "dave", None, issued);
        let dave_ldap_tgs = kdc_seq(KdcExchange::Tgs, "dave", Some("ldap"), issued);
        let dave_revoked = kdc_seq(
            KdcExchange::As,
            "dave",
            None,
            KdcOutcome::Refused {
                error_code: KDC_ERR_CLIENT_REVOKED,
            },
        );
        let dave_unknown = kdc_seq(
            KdcExchange::As,
            "dave",
            None,
            KdcOutcome::Refused {
                error_code: KDC_ERR_C_PRINCIPAL_UNKNOWN,
            },
        );
        assert_eq!(
            (
                dave_as.len(),
                dave_ldap_tgs.len(),
                dave_revoked.len(),
                dave_unknown.len()
            ),
            (1, 1, 1, 1)
        );
        assert!(
            dave_secret.1 < dave_as[0],
            "keyd's set_secret before dave's first TGT"
        );
        assert!(dave_as[0] < dave_revoked[0] && dave_revoked[0] < dave_unknown[0]);
        assert!(
            by_op(Op::SetEnabled, dave, Proceed) < dave_as[0],
            "enabled before the login"
        );
        let disabled = admin
            .iter()
            .filter(|(_, e)| e.operation == Op::SetEnabled && e.target == Some(packet(dave)))
            .map(|(seq, _)| *seq)
            .nth(2)
            .expect("the second SetEnabled's decision");
        assert!(disabled < dave_revoked[0], "disabled before the refused AS");
        assert!(
            by_op(Op::Delete, dave, Proceed) < dave_unknown[0],
            "deleted before"
        );

        // ---- No password anywhere ------------------------------------------------
        for (path, octets) in w.files() {
            assert_eq!(holds_a_password(&octets), None, "a password in {path:?}");
        }
        for line in &w.captured {
            assert_eq!(
                holds_a_password(line.as_bytes()),
                None,
                "a password in {line}"
            );
        }
        // The key sets the run left (not secret: kvnos only): krbtgt rotated
        // once by dird's decision, dave's destroyed by keyadm's sweep of
        // dird's destroy decision (A-102), the others untouched.
        for handle in [
            m.ldap_service().handle,
            m.admin_service().handle,
            m.first_admins()[0].key_set().handle,
            m.first_admins()[1].key_set().handle,
            w.workstation.keys[0].handle,
        ] {
            assert_eq!(w.custody.kvno(&handle), Some(Kvno::INITIAL), "{handle:?}");
        }
        assert_eq!(w.custody.kvno(&m.krbtgt().handle), Some(Kvno::new(2)));
        assert_eq!(w.custody.kvno(&longterm(dave)), None);
    });
}

// ---------------------------------------------------------------------------
// 2. auditd down.
// ---------------------------------------------------------------------------

/// docs/51 §5.7 item 2 (R51-12: "auditd unavailable ⇒ the operation is
/// refused (`Unavailable`) before the commit"), A-85; docs/50 §8.1: with
/// auditd stopped an admin write is refused, and once auditd is back the
/// directory shows it was never performed.
#[test]
fn auditd_down_refuses_admin_writes_and_leaves_the_store_unchanged() {
    within(TEST_BOUND, || {
        let _serial = serial();
        let Some(mut w) = World::started() else {
            return;
        };
        let ws = w.bootstrap_workstation();
        let alice_tgt = w.armored_as(&ws, ALICE, ALICE_PASSWORD).ok().unwrap();
        let alice = w.persona(ALICE, &alice_tgt);
        w.advance(10);
        w.keyd_phase(KeydPhase::Admin);
        let workstations = w.guid(ObjectRole::WorkstationsOu);
        w.forward(&alice, &[], create_user(workstations, "before"))
            .created();

        w.stop_auditd();
        let status = w
            .forward(&alice, &[], create_user(workstations, "erin"))
            .refusal();
        assert_eq!(status, RefusalStatus::Unavailable, "no audit, no write");
        // admind's own gate (Q-406 item 1): no audit slot ⇒ the shared Busy;
        // or, if admind has not yet seen auditd go, dird's Unavailable.
        let bob_guid = w.guid(ObjectRole::FirstAdmin(1));
        let got = w.set_password(&alice, &[], bob_guid, REFUSED_PASSWORD);
        assert!(
            matches!(
                got,
                Got::Refused(ipc::Refused::Busy)
                    | Got::Reply(Reply::Refused(RefusalStatus::Unavailable))
            ),
            "SetPassword refused without auditd: {got:?}"
        );

        w.start_auditd();
        // Every sender notices auditd's restart on its own heartbeat and
        // reconnects with its backoff (docs/50 §8.1; keyd answers its gating
        // operations Busy until then): for a few seconds an admin request may
        // still be `Unavailable` — "not carried out; nothing was changed"
        // (ipc-admin `RefusalStatus::Unavailable`) — so the test retries
        // exactly those answers.
        let created_after = w.settled(|w| {
            let operation = create_user(workstations, "after");
            let auth = w.auth(&alice, &[], &operation);
            w.admin(&ipc_admin::Request::Forward { auth, operation })
        });
        assert!(
            matches!(created_after, Got::Reply(Reply::Created { .. })),
            "admin writes are served again: {created_after:?}"
        );
        let lookup = |w: &mut World, sam: &str| {
            let sam = sam.to_owned();
            let alice = &alice;
            w.settled(move |w| {
                w.forward(
                    alice,
                    &[],
                    Operation::Lookup(LookupKey::SamAccountName(sam.clone())),
                )
            })
        };
        assert_eq!(
            lookup(&mut w, "erin"),
            Got::Reply(Reply::Refused(RefusalStatus::NotFound)),
            "the refused create left nothing behind"
        );
        for sam in ["before", "after"] {
            let found = lookup(&mut w, sam);
            assert!(
                matches!(found, Got::Reply(Reply::Found(_))),
                "{sam}: {found:?}"
            );
        }
        // auditd stopped once: a sender may have resent what it had not seen
        // acknowledged (Q-252 item 7). auditd recognises a batch it already
        // persisted — its per-source state recovered from the verified log
        // at the restart — and acknowledges it without appending it again
        // (A-98 follow-up F8; crates/audit-daemon `resend`; Q-445): the log
        // holds no duplicate.
        let (events, duplicates) = w.finish_counting_duplicates();
        assert_eq!(duplicates, 0, "no batch persisted twice across the restart");
        let creates: Vec<(Vec<String>, DirAdminStage)> = dir_admin_events(&events)
            .iter()
            .filter(|(_, e)| e.operation == DirAdminOperation::CreateUser)
            .map(|(_, e)| {
                let names = e
                    .names
                    .as_slice()
                    .iter()
                    .map(|n| n.text.as_text().unwrap_or("?").to_owned())
                    .collect();
                (names, e.stage)
            })
            .collect();
        let committed_users = creates
            .iter()
            .filter(|(_, stage)| {
                matches!(
                    stage,
                    DirAdminStage::Outcome(OutcomeResult::Committed { .. })
                )
            })
            .count();
        assert_eq!(
            committed_users, 2,
            "\"before\" and \"after\" only: {creates:?}"
        );
        // keyd never set a password while auditd was down: bob's key set has
        // the one intent of first-admin-secret, no other.
        let bob_handle = w.manifest.first_admins()[1].key_set().handle;
        let intents = keyd_records(&events)
            .iter()
            .filter(|(_, r)| {
                r.op == KeydOperation::SetSecret
                    && r.principal == Some(*bob_handle.principal.as_bytes())
                    && r.result == KeydOutcome::Intent
            })
            .count();
        assert_eq!(intents, 1, "only first-admin-secret's set_secret of bob");
        assert_eq!(w.custody.kvno(&bob_handle), Some(Kvno::INITIAL));
        // The refused password (and every other) is nowhere.
        for (path, octets) in w.files() {
            assert_eq!(holds_a_password(&octets), None, "a password in {path:?}");
        }
    });
}

// ---------------------------------------------------------------------------
// 3. admind down.
// ---------------------------------------------------------------------------

/// docs/50 §3.7 (a dependency down ⇒ fail closed), §7.5; docs/51 §5.1: with
/// admind stopped, a client's open connection is closed and a new one is
/// refused; admind started again serves again.
#[test]
fn admind_down_the_client_sees_closure() {
    within(TEST_BOUND, || {
        let _serial = serial();
        let Some(mut w) = World::started() else {
            return;
        };
        let ws = w.bootstrap_workstation();
        let alice_tgt = w.armored_as(&ws, ALICE, ALICE_PASSWORD).ok().unwrap();
        let alice = w.persona(ALICE, &alice_tgt);
        w.advance(10);
        w.keyd_phase(KeydPhase::Admin);
        let socket = w.input.paths.admin_socket.as_path().to_path_buf();
        let mut open = AdminConn::connect(&socket).unwrap();
        assert_eq!(
            open.call(&ipc_admin::Request::Ping),
            Got::Reply(Reply::Pong)
        );

        w.stop_admind();
        let workstations = w.guid(ObjectRole::WorkstationsOu);
        let operation = create_user(workstations, "erin");
        let auth = w.auth(&alice, &[], &operation);
        let got = open.call(&ipc_admin::Request::Forward { auth, operation });
        assert_eq!(got, Got::Closed, "the open connection is closed");
        assert!(
            AdminConn::connect(&socket).is_err(),
            "a new connection is refused"
        );

        w.start_admind();
        assert_eq!(
            w.forward(
                &alice,
                &[],
                Operation::Lookup(LookupKey::SamAccountName("erin".to_owned())),
            )
            .refusal(),
            RefusalStatus::NotFound,
            "nothing reached dird while admind was down"
        );
        w.forward(&alice, &[], create_user(workstations, "erin"))
            .created();
        w.finish();
    });
}
