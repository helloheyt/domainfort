//! Caller identity, roles, and the compile-time capability table.
//!
//! Two independent checks guard every operation (invariants I2, I3):
//! 1. the caller's [`Role`] permits the [`Operation`] ([`role_permits`],
//!    driven by [`CAPABILITY_TABLE`]);
//! 2. every handle's [`KeyPurpose`] matches what the operation accepts in
//!    that slot ([`purpose_permitted`]).
//!
//! Both tables are `const` and fixed at compile time: they cannot be changed
//! at run time, and the compile-time assertions at the bottom of this file
//! pin the security-relevant cells. This process-authorization table is
//! independent of the PDP (docs/09 א.6, D31).
//!
//! Spec: docs/10 §2 (caller model, capability table), §12 I2, I3; docs/09 א.6;
//! docs/25 §3.2 (keyd is a PEP).

use crate::model::KeyPurpose;

/// The role a calling process holds.
///
/// Phase 1 has exactly three roles. The other roles of docs/10 §2 (Netlogon,
/// Time, Gkdi, Bkrp, Repl) are out of scope and have no variant.
///
/// Spec: docs/10 §2 (`enum Role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Role {
    /// The KDC process: AS / TGS issuance. Spec: docs/10 §2.
    Kdc = 0,
    /// The directory process (LDAP / SAMR / kpasswd front): set and verify
    /// secrets. Spec: docs/10 §2.
    Directory = 1,
    /// Tier-0 key administration. Spec: docs/10 §2, §7.
    Admin = 2,
}

/// The identity of the calling process.
///
/// It MUST come from the authenticated transport (peer credentials plus the
/// registered service identity, docs/10 §2-3, D34) — never from the request
/// body. In this library it is an explicit argument of every operation.
///
/// Spec: docs/10 §2 (`struct CallerId`); docs/25 §3.1 (D101).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallerId {
    /// The peer's numeric user id (SO_PEERCRED in the later IPC crate).
    pub uid: u32,
    /// The role registered for the peer's service identity.
    pub role: Role,
}

/// Every operation keyd offers in phase 1. There is no read-key operation in
/// any role: `export_key`, `get_key`, `read_secret` and generic
/// `encrypt` / `decrypt` / `sign` do not exist (invariant I1).
///
/// Netlogon, SNTP, GKDI, BackupKey, S4U and replication operations are not
/// implemented and have no variant.
///
/// Spec: docs/10 §2 (capability table), §4, §5, §6, §7; docs/09 א.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Operation {
    /// Spec: docs/10 §4; RFC 4120 5.2.7.2.
    VerifyPreauth = 0,
    /// Spec: docs/10 §4; RFC 4120 3.1.3.
    IssueAsRep = 1,
    /// Spec: docs/10 §5; RFC 4120 3.3.2.
    OpenAndVerifyTgt = 2,
    /// Spec: docs/10 §5; RFC 4120 3.3.3.
    IssueTgsRep = 3,
    /// Spec: docs/10 §6.
    SetSecret = 4,
    /// Spec: docs/10 §6.
    VerifySecret = 5,
    /// Spec: docs/10 §7.
    CreateKey = 6,
    /// Spec: docs/10 §7.
    RotateKey = 7,
    /// Spec: docs/10 §7.
    RotateKrbtgt = 8,
    /// Spec: docs/10 §7.
    RetireKvno = 9,
    /// Spec: docs/10 §5a; docs/48 §2.3; RFC 6113 5.4.1.1, 5.4.2.
    OpenFastArmor = 10,
    /// Spec: docs/10 §5a; docs/48 §2.3, §6; RFC 6113 5.4.4.
    SealFastError = 11,
    /// Spec: docs/10 §7; docs/questions/Q-115 (A-35).
    DestroyKeySet = 12,
}

impl Operation {
    /// Every operation, for exhaustive checks. Spec: docs/10 §2.
    pub const ALL: [Operation; 13] = [
        Operation::VerifyPreauth,
        Operation::IssueAsRep,
        Operation::OpenAndVerifyTgt,
        Operation::IssueTgsRep,
        Operation::SetSecret,
        Operation::VerifySecret,
        Operation::CreateKey,
        Operation::RotateKey,
        Operation::RotateKrbtgt,
        Operation::RetireKvno,
        Operation::OpenFastArmor,
        Operation::SealFastError,
        Operation::DestroyKeySet,
    ];
}

/// The capability table: each role and the operations it may call. Anything
/// not listed is denied.
///
/// Spec: docs/10 §2 (table rows Kdc, Directory, Admin — restricted to the
/// phase-1 operations), §7; docs/09 א.6 (D31); docs/48 §2.3 ("`Kdc` also
/// gets `open_fast_armor`, `seal_fast_error`. No other role");
/// docs/questions/Q-115 (A-35: `destroy_key_set` is an Admin operation).
pub const CAPABILITY_TABLE: [(Role, &[Operation]); 3] = [
    (
        Role::Kdc,
        &[
            Operation::VerifyPreauth,
            Operation::IssueAsRep,
            Operation::OpenAndVerifyTgt,
            Operation::IssueTgsRep,
            Operation::OpenFastArmor,
            Operation::SealFastError,
        ],
    ),
    (
        Role::Directory,
        &[Operation::SetSecret, Operation::VerifySecret],
    ),
    (
        Role::Admin,
        &[
            Operation::CreateKey,
            Operation::RotateKey,
            Operation::RotateKrbtgt,
            Operation::RetireKvno,
            Operation::DestroyKeySet,
        ],
    ),
];

/// `true` if [`CAPABILITY_TABLE`] lists `op` for `role`. Deny by default.
///
/// Spec: docs/10 §2 ("each operation checks (a) the caller's Role has it in
/// the table"), §12 I2.
pub const fn role_permits(role: Role, op: Operation) -> bool {
    let mut i = 0;
    while i < CAPABILITY_TABLE.len() {
        let (table_role, ops) = CAPABILITY_TABLE[i];
        if table_role as u8 == role as u8 {
            let mut j = 0;
            while j < ops.len() {
                if ops[j] as u8 == op as u8 {
                    return true;
                }
                j += 1;
            }
        }
        i += 1;
    }
    false
}

/// Which handle argument of an operation a purpose check is about.
///
/// Spec: docs/10 §4 (issue_as_rep takes a client and a krbtgt handle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandleSlot {
    /// The operation's main handle (the client, service, krbtgt or managed
    /// key, depending on the operation).
    Primary = 0,
    /// The krbtgt handle of `issue_as_rep`.
    Krbtgt = 1,
}

/// The purposes an operation accepts in a handle slot. Anything else is
/// denied (key separation, invariant I3).
///
/// - `verify_preauth`, `issue_as_rep` (client): PrincipalLongterm (docs/10
///   §4 "חייב purpose = PrincipalLongterm").
/// - `issue_as_rep` (krbtgt), `open_and_verify_tgt`, `open_fast_armor`:
///   Krbtgt (docs/10 §4, §5; docs/48 §2.3 "open_fast_armor.krbtgt =
///   Krbtgt").
/// - `seal_fast_error` takes no handle: the armor token is its authority
///   (docs/48 §2.3), so no slot of it is permitted.
/// - `issue_tgs_rep`: Service only. Referral TGTs (Krbtgt in docs/10 §5) are
///   cross-realm, which phase 1 does not implement.
/// - `set_secret`, `verify_secret`, `rotate_key`: PrincipalLongterm or
///   Service. The krbtgt key is never password-derived and is rotated only
///   through `rotate_krbtgt` (dual control, docs/10 §7).
/// - `destroy_key_set`: PrincipalLongterm or Service — never Krbtgt (A-35).
/// - `rotate_krbtgt`: Krbtgt.
/// - `create_key`, `retire_kvno`: any phase-1 purpose (docs/10 §7:
///   create_key also initializes krbtgt).
///
/// Spec: docs/10 §2 ("(b) the KeyPurpose of the handle matches the
/// operation"), §4, §5, §6, §7, §12 I3; docs/48 §2.3, §9.1 I3;
/// docs/questions/Q-115 (A-35).
pub const fn purpose_permitted(op: Operation, slot: HandleSlot, purpose: KeyPurpose) -> bool {
    use KeyPurpose::{Krbtgt, PrincipalLongterm, Service};
    match (op, slot) {
        (Operation::VerifyPreauth, HandleSlot::Primary)
        | (Operation::IssueAsRep, HandleSlot::Primary) => {
            matches!(purpose, PrincipalLongterm)
        }
        (Operation::IssueAsRep, HandleSlot::Krbtgt)
        | (Operation::OpenAndVerifyTgt, HandleSlot::Primary)
        | (Operation::OpenFastArmor, HandleSlot::Primary)
        | (Operation::RotateKrbtgt, HandleSlot::Primary) => matches!(purpose, Krbtgt),
        (Operation::IssueTgsRep, HandleSlot::Primary) => matches!(purpose, Service),
        (Operation::SetSecret, HandleSlot::Primary)
        | (Operation::VerifySecret, HandleSlot::Primary)
        | (Operation::RotateKey, HandleSlot::Primary)
        | (Operation::DestroyKeySet, HandleSlot::Primary) => {
            matches!(purpose, PrincipalLongterm | Service)
        }
        (Operation::CreateKey, HandleSlot::Primary)
        | (Operation::RetireKvno, HandleSlot::Primary) => {
            matches!(purpose, PrincipalLongterm | Service | Krbtgt)
        }
        _ => false,
    }
}

// Compile-time pins of the security-relevant cells (docs/10 §2, §12 I2, I3).
// A table edit that breaks one of these fails the build.
const _: () = {
    assert!(role_permits(Role::Kdc, Operation::IssueAsRep));
    assert!(!role_permits(Role::Kdc, Operation::CreateKey));
    assert!(!role_permits(Role::Kdc, Operation::SetSecret));
    assert!(!role_permits(Role::Directory, Operation::IssueTgsRep));
    assert!(!role_permits(Role::Directory, Operation::RotateKrbtgt));
    assert!(!role_permits(Role::Admin, Operation::VerifyPreauth));
    assert!(!role_permits(Role::Admin, Operation::VerifySecret));
    assert!(!purpose_permitted(
        Operation::SetSecret,
        HandleSlot::Primary,
        KeyPurpose::Krbtgt
    ));
    assert!(!purpose_permitted(
        Operation::RotateKey,
        HandleSlot::Primary,
        KeyPurpose::Krbtgt
    ));
    assert!(!purpose_permitted(
        Operation::IssueTgsRep,
        HandleSlot::Primary,
        KeyPurpose::Krbtgt
    ));
    assert!(!purpose_permitted(
        Operation::VerifyPreauth,
        HandleSlot::Primary,
        KeyPurpose::Service
    ));
    // FAST (docs/48 §2.3, §9.1 I2, I3): Kdc only; the armor ticket is opened
    // only under a Krbtgt-purpose key.
    assert!(role_permits(Role::Kdc, Operation::OpenFastArmor));
    assert!(role_permits(Role::Kdc, Operation::SealFastError));
    assert!(!role_permits(Role::Directory, Operation::OpenFastArmor));
    assert!(!role_permits(Role::Admin, Operation::OpenFastArmor));
    assert!(!role_permits(Role::Directory, Operation::SealFastError));
    assert!(!role_permits(Role::Admin, Operation::SealFastError));
    assert!(!purpose_permitted(
        Operation::OpenFastArmor,
        HandleSlot::Primary,
        KeyPurpose::PrincipalLongterm
    ));
    assert!(!purpose_permitted(
        Operation::OpenFastArmor,
        HandleSlot::Primary,
        KeyPurpose::Service
    ));
    // destroy_key_set (A-35, docs/questions/Q-115): Admin only, and never a
    // Krbtgt key set (krbtgt is only rotated).
    assert!(role_permits(Role::Admin, Operation::DestroyKeySet));
    assert!(!role_permits(Role::Directory, Operation::DestroyKeySet));
    assert!(!role_permits(Role::Kdc, Operation::DestroyKeySet));
    assert!(!purpose_permitted(
        Operation::DestroyKeySet,
        HandleSlot::Primary,
        KeyPurpose::Krbtgt
    ));
    assert!(!purpose_permitted(
        Operation::DestroyKeySet,
        HandleSlot::Krbtgt,
        KeyPurpose::Krbtgt
    ));
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Every operation is granted to exactly one role (docs/10 §2: each
    /// process holds only its own operations).
    #[test]
    fn each_operation_has_exactly_one_role() {
        for op in Operation::ALL {
            let roles = [Role::Kdc, Role::Directory, Role::Admin]
                .iter()
                .filter(|r| role_permits(**r, op))
                .count();
            assert_eq!(roles, 1, "{op:?}");
        }
    }
}
