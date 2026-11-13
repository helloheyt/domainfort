//! Invariants I2 (every operation checks the caller's role against the
//! capability table) and I3 (every handle's purpose matches the operation),
//! exhaustively over all operations, roles and purposes. Source: docs/10 §2
//! (capability table; "mismatch -> Denied, recorded"), §12 I2, I3; docs/09
//! א.6 (D31).

mod common;

use common::*;
use keyd::authz::{purpose_permitted, role_permits, HandleSlot, CAPABILITY_TABLE};
use keyd::{
    ArmorId, AuditOutcome, AuditReason, AuthnProof, CallerId, CtxId, DualControlToken, ExchangeId,
    FastConversation, KeyHandle, KeyPurpose, Kvno, Operation, PrincipalId, Role,
};
use krb_proto::constants::FX_FAST_ARMOR_AP_REQUEST;
use krb_proto::{
    ApOptions, ApReq, Checksum, EncryptedData, KrbFastArmor, KrbFastArmoredReq, Ticket,
};
use zeroize::Zeroizing;

const ROLES: [Role; 3] = [Role::Kdc, Role::Directory, Role::Admin];

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
                .issue_as_rep(caller, handle, &KRBTGT, &proof, &as_template(), &n)
                .is_ok()
        }
        Operation::OpenAndVerifyTgt => f
            .keyd
            .open_and_verify_tgt(caller, handle, &dummy_ap_req(), &[0x30, 0x00], &n)
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
        Operation::RotateKey => f.keyd.rotate_key(caller, handle, &n).is_ok(),
        Operation::RotateKrbtgt => f
            .keyd
            .rotate_krbtgt(
                caller,
                handle,
                &DualControlToken {
                    approver_1: PrincipalId::from_bytes([1; 16]),
                    approver_2: PrincipalId::from_bytes([2; 16]),
                },
                &n,
            )
            .is_ok(),
        Operation::RetireKvno => f.keyd.retire_kvno(caller, handle, Kvno::new(1), &n).is_ok(),
        Operation::DestroyKeySet => f.keyd.destroy_key_set(caller, handle, &n).is_ok(),
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
    }
}

/// The handle each operation is valid for.
fn valid_handle(op: Operation) -> KeyHandle {
    match op {
        Operation::VerifyPreauth | Operation::IssueAsRep => ALICE,
        Operation::OpenAndVerifyTgt | Operation::RotateKrbtgt => KRBTGT,
        Operation::OpenFastArmor | Operation::SealFastError => KRBTGT,
        Operation::IssueTgsRep | Operation::RotateKey | Operation::RetireKvno => SERVICE,
        Operation::DestroyKeySet => SERVICE,
        Operation::SetSecret | Operation::VerifySecret => ALICE,
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
/// KeyPurpose of the handle matches the operation"), §12 I3.
#[test]
fn wrong_purpose_is_denied_for_every_operation() {
    let mut f = Fixture::new();
    let by_purpose = [
        (KeyPurpose::PrincipalLongterm, ALICE),
        (KeyPurpose::Krbtgt, KRBTGT),
        (KeyPurpose::Service, SERVICE),
    ];
    for op in Operation::ALL {
        // seal_fast_error takes no handle: the armor token is its authority
        // (docs/48 §2.3); there is no purpose to mismatch.
        if op == Operation::SealFastError {
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
            &now(),
        )
        .unwrap();
    for wrong in [SERVICE, BOB] {
        assert!(f
            .keyd
            .issue_as_rep(&KDC, &ALICE, &wrong, &proof, &as_template(), &now())
            .is_err());
        assert_eq!(
            f.records().last().unwrap().reason,
            AuditReason::PurposeMismatch
        );
    }
    // The purpose refusal precedes the token: the proof is still usable.
    assert!(f
        .keyd
        .issue_as_rep(&KDC, &ALICE, &KRBTGT, &proof, &as_template(), &now())
        .is_ok());
}

/// The compile-time capability table is exactly the phase-1 subset of
/// docs/10 §2: Kdc -> AS/TGS operations (and the FAST armor operations of
/// docs/48 §2.3); Directory -> set/verify secret; Admin -> key lifecycle. No
/// role holds a read-key operation (none exists).
/// Source: docs/10 §2, §7 ("no read operation for a key — in any role");
/// docs/48 §2.3, §9.1 I2; docs/questions/Q-115 (A-35: destroy_key_set is
/// an Admin operation).
#[test]
fn capability_table_matches_design() {
    use Operation::*;
    let expected: [(Role, &[Operation]); 3] = [
        (
            Role::Kdc,
            &[
                VerifyPreauth,
                IssueAsRep,
                OpenAndVerifyTgt,
                IssueTgsRep,
                OpenFastArmor,
                SealFastError,
            ],
        ),
        (Role::Directory, &[SetSecret, VerifySecret]),
        (
            Role::Admin,
            &[
                CreateKey,
                RotateKey,
                RotateKrbtgt,
                RetireKvno,
                DestroyKeySet,
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
