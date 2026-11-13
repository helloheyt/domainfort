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
/// Phase 1 has exactly four roles. The other roles of docs/10 §2 (Netlogon,
/// Time, Gkdi, Bkrp, Repl) are out of scope and have no variant.
///
/// Spec: docs/10 §2 (`enum Role`); docs/questions/Q-165 item 3 (decided
/// A-46: the new `Ldap` role).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Role {
    /// The KDC process: AS / TGS issuance. Spec: docs/10 §2.
    Kdc = 0,
    /// The directory process (management plane / SAMR / kpasswd front): set
    /// and verify secrets. Not the LDAP front, which holds [`Role::Ldap`]
    /// (docs/questions/Q-165 item 3: "not `Directory`, which holds
    /// `set_secret`"). Spec: docs/10 §2.
    Directory = 1,
    /// Tier-0 key administration. Spec: docs/10 §2, §7.
    Admin = 2,
    /// The LDAP front: verifies the AP-REQ of a GSSAPI Bind inside keyd and
    /// receives only non-secret facts — no key, no session key (D29 strict).
    /// Spec: docs/49 §3.3 (R49-5); docs/questions/Q-165 items 1, 3 (decided
    /// A-46).
    Ldap = 3,
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
    /// Spec: docs/10 §5ב; docs/49 §3.3; RFC 4120 3.2.3;
    /// docs/questions/Q-165 (A-46).
    OpenAndVerifyServiceTicket = 13,
    /// The non-secret part of keyd's configuration, which the kdc needs at
    /// start (`KdcConfig::validate`) — no key, no secret.
    /// Spec: docs/50 §3.4 (`DescribeConfig`), §7.5 step 4.
    DescribeConfig = 14,
    /// Health check. Spec: docs/50 §3.4 (`Ping`), §7.5.
    Ping = 15,
}

impl Operation {
    /// Every operation, for exhaustive checks. Spec: docs/10 §2.
    pub const ALL: [Operation; 16] = [
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
        Operation::OpenAndVerifyServiceTicket,
        Operation::DescribeConfig,
        Operation::Ping,
    ];
}

/// The capability table: each role and the operations it may call. Anything
/// not listed is denied.
///
/// Spec: docs/10 §2 (table rows Kdc, Directory, Admin — restricted to the
/// phase-1 operations), §7; docs/09 א.6 (D31); docs/48 §2.3 ("`Kdc` also
/// gets `open_fast_armor`, `seal_fast_error`. No other role");
/// docs/questions/Q-115 (A-35: `destroy_key_set` is an Admin operation);
/// docs/questions/Q-165 item 3 (A-46: `Ldap` holds only the service-ticket
/// operations — in task L6a, `open_and_verify_service_ticket` alone;
/// `seal_ap_rep` arrives with task L6b, docs/49 §12); docs/50 §3.4
/// (`DescribeConfig`: roles Kdc and Ldap; `Ping`: every mapped role), §7.5.
pub const CAPABILITY_TABLE: [(Role, &[Operation]); 4] = [
    (
        Role::Kdc,
        &[
            Operation::VerifyPreauth,
            Operation::IssueAsRep,
            Operation::OpenAndVerifyTgt,
            Operation::IssueTgsRep,
            Operation::OpenFastArmor,
            Operation::SealFastError,
            Operation::DescribeConfig,
            Operation::Ping,
        ],
    ),
    (
        Role::Directory,
        &[
            Operation::SetSecret,
            Operation::VerifySecret,
            Operation::Ping,
        ],
    ),
    (
        Role::Admin,
        &[
            Operation::CreateKey,
            Operation::RotateKey,
            Operation::RotateKrbtgt,
            Operation::RetireKvno,
            Operation::DestroyKeySet,
            Operation::Ping,
        ],
    ),
    (
        Role::Ldap,
        &[
            Operation::OpenAndVerifyServiceTicket,
            Operation::DescribeConfig,
            Operation::Ping,
        ],
    ),
];

/// `true` if the operation is refused during keyd's startup hold-down: for
/// two `clock_skew_secs` intervals after the start time given to `Keyd::new`
/// (A-62: an authenticator accepted just before the restart may carry a
/// client time up to one skew ahead and stays acceptable for one skew after
/// that).
///
/// keyd's replay cache — the one cache of every AP-REQ it verifies (TGT,
/// FAST armor, service ticket) — and its one-time token tables (AuthnProof,
/// TGS contexts, armors, service contexts) live in memory and are empty
/// after every start. RFC 4120 3.2.3: "If a server loses track of
/// authenticators presented within the allowable clock skew, it MUST reject
/// all requests until the clock skew interval has passed". Held: every
/// operation of the Kerberos exchanges — the authentication steps that
/// create replay-cache entries and tokens and the issuance / error steps
/// that consume those tokens (the operations of roles Kdc and Ldap, docs/50
/// R50-6). Not held: Directory and Admin operations, which use neither
/// ("Directory/Admin are not dependent on the replay cache and are allowed",
/// docs/50 §3.5), and `describe_config` / `ping`, which use neither and
/// which the daemons need at start and for health (docs/50 §7.5) —
/// interpretation recorded in docs/questions/Q-240 item 1.
///
/// The match is exhaustive: a new operation does not compile until it is
/// decided here.
///
/// Spec: RFC 4120 3.2.3; docs/50 R50-6, §3.5, §7.5; docs/questions/Q-222
/// (A-56), Q-240 (A-62).
pub const fn startup_hold_down_applies(op: Operation) -> bool {
    match op {
        Operation::VerifyPreauth
        | Operation::IssueAsRep
        | Operation::OpenAndVerifyTgt
        | Operation::IssueTgsRep
        | Operation::OpenFastArmor
        | Operation::SealFastError
        | Operation::OpenAndVerifyServiceTicket => true,
        Operation::SetSecret
        | Operation::VerifySecret
        | Operation::CreateKey
        | Operation::RotateKey
        | Operation::RotateKrbtgt
        | Operation::RetireKvno
        | Operation::DestroyKeySet
        | Operation::DescribeConfig
        | Operation::Ping => false,
    }
}

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
/// - `describe_config`, `ping` take no handle (docs/50 §3.4: no request
///   fields), so no slot of them is permitted.
/// - `issue_tgs_rep`: Service only. Referral TGTs (Krbtgt in docs/10 §5) are
///   cross-realm, which phase 1 does not implement.
/// - `open_and_verify_service_ticket`: Service only — "only handles of type
///   `Service`" (docs/questions/Q-165 item 3, A-46); a TGT is never opened
///   here (that is the KDC's `open_and_verify_tgt`).
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
/// docs/questions/Q-115 (A-35), Q-165 item 3 (A-46).
pub const fn purpose_permitted(op: Operation, slot: HandleSlot, purpose: KeyPurpose) -> bool {
    use KeyPurpose::{Krbtgt, PrincipalLongterm, Service};
    match (op, slot) {
        (Operation::OpenAndVerifyServiceTicket, HandleSlot::Primary) => matches!(purpose, Service),
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
    // Service-ticket verification (docs/questions/Q-165 item 3, A-46):
    // `Ldap` may call open_and_verify_service_ticket and — docs/50 §3.4 —
    // describe_config and ping, and nothing else; no other role may call
    // open_and_verify_service_ticket, and it opens only Service-purpose
    // handles.
    let mut i = 0;
    while i < Operation::ALL.len() {
        let op = Operation::ALL[i];
        let is_service_ticket = op as u8 == Operation::OpenAndVerifyServiceTicket as u8;
        let is_daemon_support =
            op as u8 == Operation::DescribeConfig as u8 || op as u8 == Operation::Ping as u8;
        assert!(role_permits(Role::Ldap, op) == (is_service_ticket || is_daemon_support));
        if is_service_ticket {
            assert!(!role_permits(Role::Kdc, op));
            assert!(!role_permits(Role::Directory, op));
            assert!(!role_permits(Role::Admin, op));
        }
        i += 1;
    }
    // Daemon support (docs/50 §3.4, §7.5): describe_config for Kdc and Ldap
    // only (Directory and Admin have no use for it); ping for every role.
    // Neither takes a handle, so no purpose is permitted in any slot.
    assert!(role_permits(Role::Kdc, Operation::DescribeConfig));
    assert!(role_permits(Role::Ldap, Operation::DescribeConfig));
    assert!(!role_permits(Role::Directory, Operation::DescribeConfig));
    assert!(!role_permits(Role::Admin, Operation::DescribeConfig));
    assert!(role_permits(Role::Kdc, Operation::Ping));
    assert!(role_permits(Role::Directory, Operation::Ping));
    assert!(role_permits(Role::Admin, Operation::Ping));
    assert!(role_permits(Role::Ldap, Operation::Ping));
    let purposes = [
        KeyPurpose::PrincipalLongterm,
        KeyPurpose::Krbtgt,
        KeyPurpose::Service,
    ];
    let mut p = 0;
    while p < purposes.len() {
        assert!(!purpose_permitted(
            Operation::DescribeConfig,
            HandleSlot::Primary,
            purposes[p]
        ));
        assert!(!purpose_permitted(
            Operation::DescribeConfig,
            HandleSlot::Krbtgt,
            purposes[p]
        ));
        assert!(!purpose_permitted(
            Operation::Ping,
            HandleSlot::Primary,
            purposes[p]
        ));
        assert!(!purpose_permitted(
            Operation::Ping,
            HandleSlot::Krbtgt,
            purposes[p]
        ));
        p += 1;
    }
    // Startup hold-down (RFC 4120 3.2.3; docs/50 R50-6, §3.5; A-56): every
    // operation of the Kerberos exchanges is held; no Directory or Admin
    // operation is (docs/50 §3.5), nor describe_config / ping (Q-240 item 1).
    let mut h = 0;
    while h < Operation::ALL.len() {
        let op = Operation::ALL[h];
        if role_permits(Role::Directory, op) || role_permits(Role::Admin, op) {
            assert!(!startup_hold_down_applies(op));
        }
        h += 1;
    }
    assert!(startup_hold_down_applies(Operation::VerifyPreauth));
    assert!(startup_hold_down_applies(Operation::IssueAsRep));
    assert!(startup_hold_down_applies(Operation::OpenAndVerifyTgt));
    assert!(startup_hold_down_applies(Operation::IssueTgsRep));
    assert!(startup_hold_down_applies(Operation::OpenFastArmor));
    assert!(startup_hold_down_applies(Operation::SealFastError));
    assert!(startup_hold_down_applies(
        Operation::OpenAndVerifyServiceTicket
    ));
    assert!(!startup_hold_down_applies(Operation::DescribeConfig));
    assert!(!startup_hold_down_applies(Operation::Ping));
    assert!(purpose_permitted(
        Operation::OpenAndVerifyServiceTicket,
        HandleSlot::Primary,
        KeyPurpose::Service
    ));
    assert!(!purpose_permitted(
        Operation::OpenAndVerifyServiceTicket,
        HandleSlot::Primary,
        KeyPurpose::Krbtgt
    ));
    assert!(!purpose_permitted(
        Operation::OpenAndVerifyServiceTicket,
        HandleSlot::Primary,
        KeyPurpose::PrincipalLongterm
    ));
    assert!(!purpose_permitted(
        Operation::OpenAndVerifyServiceTicket,
        HandleSlot::Krbtgt,
        KeyPurpose::Service
    ));
};

#[cfg(test)]
mod tests {
    use super::*;

    const ROLES: [Role; 4] = [Role::Kdc, Role::Directory, Role::Admin, Role::Ldap];

    /// Every key operation is granted to exactly one role (docs/10 §2: each
    /// process holds only its own operations); the two daemon-support
    /// operations, which touch no key, are shared as docs/50 §3.4 lists:
    /// `DescribeConfig` — Kdc and Ldap; `Ping` — every mapped role.
    #[test]
    fn each_key_operation_has_exactly_one_role() {
        for op in Operation::ALL {
            let roles: Vec<Role> = ROLES
                .iter()
                .copied()
                .filter(|r| role_permits(*r, op))
                .collect();
            match op {
                Operation::DescribeConfig => assert_eq!(roles, [Role::Kdc, Role::Ldap]),
                Operation::Ping => assert_eq!(roles, ROLES),
                _ => assert_eq!(roles.len(), 1, "{op:?}"),
            }
        }
    }

    /// RFC 4120 3.2.3 / docs/50 R50-6, §3.5: exactly the operations of the
    /// Kerberos exchanges (roles Kdc and Ldap, except the daemon-support
    /// operations — Q-240 item 1) are held after start.
    #[test]
    fn hold_down_covers_exactly_the_kerberos_operations() {
        for op in Operation::ALL {
            let kerberos = (role_permits(Role::Kdc, op) || role_permits(Role::Ldap, op))
                && !matches!(op, Operation::DescribeConfig | Operation::Ping);
            assert_eq!(startup_hold_down_applies(op), kerberos, "{op:?}");
        }
    }
}
