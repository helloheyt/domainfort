//! Invariants I2 (every operation checks the caller's role against the
//! capability table) and I3 (every handle's purpose matches the operation),
//! exhaustively over all operations, roles and purposes. Source: docs/10 §2
//! (capability table; "mismatch -> Denied, recorded"), §12 I2, I3; docs/09
//! א.6 (D31); docs/52 §4, §7 R1, R3, R4 (A-102: the decision operations,
//! `verify_secret` in no role).

mod common;

use common::*;
use keyd::authz::{purpose_permitted, role_permits, HandleSlot, CAPABILITY_TABLE};
use keyd::{
    AccountKind, ArmorId, AuditOutcome, AuditReason, AuthnProof, CallerId, CtxId, DecidedOperation,
    DecisionId, ExchangeId, FastConversation, KeyHandle, KeyPurpose, Operation, PrincipalId, Role,
    SetSecretTarget,
};
use krb_proto::constants::FX_FAST_ARMOR_AP_REQUEST;
use krb_proto::{
    ApOptions, ApReq, Checksum, EncryptedData, KrbFastArmor, KrbFastArmoredReq, Ticket,
};
use zeroize::Zeroizing;

const ROLES: [Role; 4] = [Role::Kdc, Role::Directory, Role::Admin, Role::Ldap];

fn caller(role: Role) -> CallerId {
    CallerId { uid: 900, role }
}

fn dummy_ap_req() -> ApReq {
    ApReq {
        ap_options: ApOptions::empty(),
        ticket: Ticket {
            realm: realm(),
            sname: krbtgt_name(),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: vec![0x11; 64],
            },
        },
        authenticator: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0x22; 64],
        },
    }
}

/// A structurally plausible armored request around [`dummy_ap_req`]
/// (RFC 6113 5.4.1.1, 5.4.2); authorization precedes every check of it.
fn dummy_armored_req() -> KrbFastArmoredReq {
    KrbFastArmoredReq {
        armor: Some(KrbFastArmor {
            armor_type: FX_FAST_ARMOR_AP_REQUEST,
            armor_value: dummy_ap_req().encode().unwrap(),
        }),
        req_checksum: Checksum {
            cksumtype: 16,
            checksum: vec![0x33; 12],
        },
        enc_fast_req: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0x44; 64],
        },
    }
}

/// A creation-valid binding for `handle` (Q-040, A-19; RFC 4120 6.2, 7.3).
fn binding_for(handle: &KeyHandle) -> keyd::PrincipalBinding {
    match handle.purpose {
        KeyPurpose::Krbtgt => krbtgt_binding(),
        KeyPurpose::PrincipalLongterm => alice_binding(),
        KeyPurpose::Service => service_binding(),
        // R2: the admin service's name (A-73).
        KeyPurpose::AdminService => bound(admin_service_name()),
        // Task K3: `kadmin/changepw` (RFC 3244 §2).
        KeyPurpose::ChangePasswordService => bound(change_password_service_name()),
    }
}

/// A decision id no test registered: the four Admin operations that run a
/// decision take only an id (A-102), and the role check precedes the
/// decision's lookup.
const UNREGISTERED: DecisionId = DecisionId::new(0xDEAD_BEEF);

/// A decided operation acting on `handle` (A-102, docs/52 §4.2).
fn decided_for(handle: &KeyHandle) -> DecidedOperation {
    match handle.purpose {
        KeyPurpose::Krbtgt => DecidedOperation::RotateKrbtgt { krbtgt: *handle },
        KeyPurpose::Service | KeyPurpose::AdminService | KeyPurpose::ChangePasswordService => {
            DecidedOperation::RotateKey { handle: *handle }
        }
        KeyPurpose::PrincipalLongterm => DecidedOperation::DestroyKeySet {
            principal: handle.principal,
        },
    }
}

/// Invoke `op` with `caller` on `handle` (other arguments are plausible but
/// irrelevant: authorization is the first step). Returns whether it
/// succeeded.
fn invoke(f: &mut Fixture, op: Operation, caller: &CallerId, handle: &KeyHandle) -> bool {
    let n = now();
    match op {
        Operation::VerifyPreauth => f
            .keyd
            .verify_preauth(
                caller,
                handle,
                &pa_enc_timestamp(&alice_key(), Some(1), n),
                None,
                &n,
            )
            .is_ok(),
        Operation::IssueAsRep => {
            let proof = AuthnProof {
                exchange_id: ExchangeId::from_bytes([3; 16]),
                client: handle.principal,
                authtime: n,
            };
            f.keyd
                .issue_as_rep(caller, handle, &KRBTGT, &proof, None, &as_template(), &n)
                .is_ok()
        }
        Operation::OpenAndVerifyTgt => f
            .keyd
            .open_and_verify_tgt(caller, handle, &dummy_ap_req(), &[0x30, 0x00], None, &n)
            .is_ok(),
        Operation::IssueTgsRep => f
            .keyd
            .issue_tgs_rep(
                caller,
                handle,
                &CtxId::from_bytes([4; 16]),
                &tgs_template(1),
                &n,
            )
            .is_ok(),
        Operation::SetSecret => f
            .keyd
            .set_secret(
                caller,
                handle,
                &binding_for(handle),
                Zeroizing::new("pw".to_owned()),
                "salt",
                &n,
            )
            .is_ok(),
        Operation::VerifySecret => f
            .keyd
            .verify_secret(caller, handle, Zeroizing::new("pw".to_owned()), &n)
            .is_ok(),
        Operation::CreateKey => f
            .keyd
            .create_key(caller, handle, &binding_for(handle), &n)
            .is_ok(),
        Operation::RotateKey => f.keyd.rotate_key(caller, UNREGISTERED, &n).is_ok(),
        Operation::RotateKrbtgt => f.keyd.rotate_krbtgt(caller, UNREGISTERED, &n).is_ok(),
        Operation::RetireKvno => f.keyd.retire_kvno(caller, UNREGISTERED, &n).is_ok(),
        Operation::DestroyKeySet => f.keyd.destroy_key_set(caller, UNREGISTERED, &n).is_ok(),
        Operation::OpenFastArmor => f
            .keyd
            .open_fast_armor(caller, handle, &dummy_armored_req(), &[0x30, 0x00], &n)
            .is_ok(),
        // No handle (docs/48 §2.3): `handle` is unused.
        Operation::SealFastError => f
            .keyd
            .seal_fast_error(
                caller,
                &FastConversation::As(ArmorId::from_bytes([5; 16])),
                &fast_krb_error(25),
                &[],
                &n,
            )
            .is_ok(),
        // R2 / Q-523: the principal only; the purpose is the operation's
        // binding's (Service unbound, AdminService operation-bound).
        Operation::OpenAndVerifyServiceTicket => f
            .keyd
            .open_and_verify_service_ticket(
                caller,
                &handle.principal,
                &dummy_ap_req().encode().unwrap(),
                &n,
            )
            .is_ok(),
        Operation::VerifyOperationTicket => f
            .keyd
            .verify_operation_ticket(
                caller,
                &handle.principal,
                &keyd::OperationDigest::new([0x0D; 32]),
                &dummy_ap_req().encode().unwrap(),
                &n,
            )
            .is_ok(),
        // No handle (docs/50 §3.4): `handle` is unused.
        Operation::DescribeConfig => f.keyd.describe_config(caller, &n).is_ok(),
        Operation::Ping => f.keyd.ping(caller, &n).is_ok(),
        // Task A15a: one key target in the Primary slot.
        Operation::GrantSetSecret => f
            .keyd
            .grant_set_secret(
                caller,
                AccountKind::User,
                &[SetSecretTarget {
                    handle: *handle,
                    binding: binding_for(handle),
                    salt: String::from("salt"),
                }],
                keyd::MAX_SET_SECRET_GRANT_SECS,
                &n,
            )
            .is_ok(),
        // A-102: a decision acting on `handle`.
        Operation::RegisterDecision => {
            let operation = decided_for(handle);
            let approvers = approvers_for(&operation);
            f.keyd
                .register_decision(
                    caller,
                    next_decision_id(),
                    &operation,
                    &approvers,
                    ceiling_for(&operation),
                    &n,
                )
                .is_ok()
        }
        // No handle (A-102): `handle` is unused.
        Operation::SealCeremony => f.keyd.seal_ceremony(caller, &n).is_ok(),
        Operation::ListDestroyDecisions => f.keyd.list_destroy_decisions(caller, None, &n).is_ok(),
        // Task K3: the principal only (the purpose is the binding's, as for
        // the other service-ticket verifications).
        Operation::OpenChangePasswordRequest => f
            .keyd
            .open_change_password_request(
                caller,
                &handle.principal,
                &dummy_ap_req().encode().unwrap(),
                &[0x30, 0x00],
                &keyd::HostAddr::ipv4([192, 0, 2, 10]),
                &keyd::HostAddr::ipv4([192, 0, 2, 1]),
                &n,
            )
            .is_ok(),
        Operation::CompleteChangePassword => f
            .keyd
            .complete_change_password(
                caller,
                &keyd::ChangePasswordCtxId::from_bytes([6; 16]),
                handle,
                &n,
            )
            .is_ok(),
        // No handle (the request context is its authority): `handle` unused.
        Operation::SealChangePasswordError => f
            .keyd
            .seal_change_password_error(
                caller,
                &keyd::ChangePasswordCtxId::from_bytes([6; 16]),
                krb_proto::NonZeroResultCode::HardError,
                &n,
            )
            .is_ok(),
    }
}

/// The handle each operation is valid for.
fn valid_handle(op: Operation) -> KeyHandle {
    match op {
        Operation::VerifyPreauth | Operation::IssueAsRep => ALICE,
        Operation::OpenAndVerifyTgt | Operation::RotateKrbtgt => KRBTGT,
        Operation::OpenFastArmor | Operation::SealFastError => KRBTGT,
        Operation::IssueTgsRep | Operation::RotateKey | Operation::RetireKvno => SERVICE,
        Operation::DestroyKeySet | Operation::OpenAndVerifyServiceTicket => SERVICE,
        Operation::VerifyOperationTicket => ADMIN_SERVICE,
        Operation::SetSecret | Operation::VerifySecret | Operation::GrantSetSecret => ALICE,
        Operation::RegisterDecision => SERVICE,
        Operation::OpenChangePasswordRequest => CHANGE_PASSWORD_SERVICE,
        Operation::CompleteChangePassword => ALICE,
        // No handle (docs/50 §3.4; A-102; task K3); unused.
        Operation::DescribeConfig
        | Operation::Ping
        | Operation::SealCeremony
        | Operation::ListDestroyDecisions
        | Operation::SealChangePasswordError => ALICE,
        Operation::CreateKey => {
            KeyHandle::new(PrincipalId::from_bytes([0x99; 16]), KeyPurpose::Service)
        }
    }
}

/// I2: every role not listed for an operation is refused, the refusal is
/// audited with the operation, the caller and RoleNotPermitted.
/// Source: docs/10 §2, §12 I2.
#[test]
fn wrong_role_is_denied_for_every_operation() {
    let mut f = Fixture::new();
    for op in Operation::ALL {
        for role in ROLES {
            if role_permits(role, op) {
                continue;
            }
            let c = caller(role);
            assert!(
                !invoke(&mut f, op, &c, &valid_handle(op)),
                "{op:?} by {role:?}"
            );
            let last = f.records().last().unwrap();
            assert_eq!(last.op, op);
            assert_eq!(last.caller_role, role);
            assert_eq!(last.caller_uid, 900);
            assert_eq!(last.result, AuditOutcome::Denied);
            assert_eq!(
                last.reason,
                AuditReason::RoleNotPermitted,
                "{op:?} by {role:?}"
            );
        }
    }
    // Nothing changed: the wrong-role create_key created nothing, so the
    // Admin can still create that key now.
    assert!(invoke(
        &mut f,
        Operation::CreateKey,
        &ADMIN,
        &valid_handle(Operation::CreateKey)
    ));
}

/// I3: with the permitted role, a handle of a purpose the operation does not
/// accept is refused with PurposeMismatch. Source: docs/10 §2 ("(b) the
/// KeyPurpose of the handle matches the operation"), §12 I3. The operations
/// that run a decision take no handle since A-102 — the decided handle's
/// purpose is judged at registration (crate decisions.rs tests).
#[test]
fn wrong_purpose_is_denied_for_every_operation() {
    let mut f = Fixture::new();
    let by_purpose = [
        (KeyPurpose::PrincipalLongterm, ALICE),
        (KeyPurpose::Krbtgt, KRBTGT),
        (KeyPurpose::Service, SERVICE),
        (KeyPurpose::AdminService, ADMIN_SERVICE),
        (KeyPurpose::ChangePasswordService, CHANGE_PASSWORD_SERVICE),
    ];
    for op in Operation::ALL {
        // seal_fast_error takes no handle: the armor token is its authority
        // (docs/48 §2.3); describe_config and ping take none either (docs/50
        // §3.4). There is no purpose to mismatch.
        // A-102: the decision operations take no handle either (a decided
        // handle's purpose is judged by `register_decision`, DecisionInvalid),
        // and `verify_secret` has no role (docs/52 R4). R2:
        // `open_and_verify_service_ticket` names a principal and a binding,
        // never a purpose — no purpose can mismatch (crate service_ticket.rs
        // `krbtgt_and_principal_keys_are_never_opened`); Q-523: nor can
        // `verify_operation_ticket`.
        // Task K3: `open_change_password_request` names a principal (its
        // purpose is `AppBinding::ChangePassword`'s) and
        // `seal_change_password_error` no handle.
        if matches!(
            op,
            Operation::OpenAndVerifyServiceTicket
                | Operation::VerifyOperationTicket
                | Operation::OpenChangePasswordRequest
                | Operation::SealChangePasswordError
                | Operation::SealFastError
                | Operation::DescribeConfig
                | Operation::Ping
                | Operation::RotateKey
                | Operation::RotateKrbtgt
                | Operation::RetireKvno
                | Operation::DestroyKeySet
                | Operation::RegisterDecision
                | Operation::SealCeremony
                | Operation::ListDestroyDecisions
                | Operation::VerifySecret
        ) {
            continue;
        }
        let role = ROLES.into_iter().find(|r| role_permits(*r, op)).unwrap();
        for (purpose, handle) in by_purpose {
            if purpose_permitted(op, HandleSlot::Primary, purpose) {
                continue;
            }
            assert!(
                !invoke(&mut f, op, &caller(role), &handle),
                "{op:?} on {purpose:?}"
            );
            let last = f.records().last().unwrap();
            assert_eq!(
                last.reason,
                AuditReason::PurposeMismatch,
                "{op:?} on {purpose:?}"
            );
            assert_eq!(last.purpose, Some(purpose));
        }
    }
}

/// I3 for the second handle of issue_as_rep: the ticket can only be sealed
/// under a Krbtgt-purpose key. Source: docs/10 §4 (`krbtgt: KeyHandle //
/// Krbtgt`), §12 I3.
#[test]
fn issue_as_rep_krbtgt_slot_purpose() {
    let mut f = Fixture::new();
    let proof = f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), now()),
            None,
            &now(),
        )
        .unwrap();
    for wrong in [SERVICE, BOB] {
        assert!(f
            .keyd
            .issue_as_rep(&KDC, &ALICE, &wrong, &proof, None, &as_template(), &now())
            .is_err());
        assert_eq!(
            f.records().last().unwrap().reason,
            AuditReason::PurposeMismatch
        );
    }
    // The purpose refusal precedes the token: the proof is still usable.
    assert!(f
        .keyd
        .issue_as_rep(&KDC, &ALICE, &KRBTGT, &proof, None, &as_template(), &now())
        .is_ok());
}

/// The compile-time capability table is exactly the phase-1 subset of
/// docs/10 §2: Kdc -> AS/TGS operations (and the FAST armor operations of
/// docs/48 §2.3); Directory -> set secret (no longer verify — A-102, R4);
/// Admin -> key lifecycle, the seal, the destroy listing; Ldap ->
/// service-ticket verification and decision registration; plus the
/// daemon-support operations of docs/50 §3.4 — describe_config for Kdc and
/// Ldap, ping for every role.
/// No role holds a read-key operation (none exists).
/// Source: docs/10 §2, §7 ("no read operation for a key — in any role");
/// docs/48 §2.3, §9.1 I2; docs/questions/Q-115 (A-35: destroy_key_set is
/// an Admin operation); docs/questions/Q-165 item 3 (A-46: Role::Ldap);
/// docs/50 §3.4 (`DescribeConfig`: Kdc, Ldap; `Ping`: every mapped role);
/// docs/51 §5.8 option (b), docs/questions/Q-450 (`GrantSetSecret` — task
/// A15a); docs/52 §4, §7 R1, R3, R4 and docs/questions/Q-460, Q-462, Q-465
/// (A-102: `RegisterDecision` Ldap only, `GrantSetSecret` Admin only,
/// `SealCeremony` Admin, `VerifySecret` nobody); task R6 (A-105,
/// docs/questions/Q-503): `ListDestroyDecisions` Admin and Ldap; task K3
/// (docs/53 R53-7, A-117): the three change-password operations, Ldap.
#[test]
fn capability_table_matches_design() {
    use Operation::*;
    let expected: [(Role, &[Operation]); 4] = [
        (
            Role::Kdc,
            &[
                VerifyPreauth,
                IssueAsRep,
                OpenAndVerifyTgt,
                IssueTgsRep,
                OpenFastArmor,
                SealFastError,
                DescribeConfig,
                Ping,
            ],
        ),
        (Role::Directory, &[SetSecret, Ping]),
        (
            Role::Admin,
            &[
                CreateKey,
                RotateKey,
                RotateKrbtgt,
                RetireKvno,
                DestroyKeySet,
                GrantSetSecret,
                SealCeremony,
                ListDestroyDecisions,
                Ping,
            ],
        ),
        (
            Role::Ldap,
            &[
                OpenAndVerifyServiceTicket,
                VerifyOperationTicket,
                RegisterDecision,
                ListDestroyDecisions,
                DescribeConfig,
                Ping,
                OpenChangePasswordRequest,
                CompleteChangePassword,
                SealChangePasswordError,
            ],
        ),
    ];
    assert_eq!(CAPABILITY_TABLE.len(), expected.len());
    for ((role, ops), (exp_role, exp_ops)) in CAPABILITY_TABLE.iter().zip(expected.iter()) {
        assert_eq!(role, exp_role);
        assert_eq!(ops, exp_ops);
    }
    for op in Operation::ALL {
        for role in ROLES {
            let listed = expected
                .iter()
                .any(|(r, ops)| *r == role && ops.contains(&op));
            assert_eq!(role_permits(role, op), listed, "{op:?} {role:?}");
        }
    }
}
