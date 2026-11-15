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

use crate::as_exchange::AsServer;
use crate::model::KeyPurpose;
use crate::service_ticket::{AppBinding, OperationDigest, OPERATION_DIGEST_LEN};

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
    /// secrets, each on a decision dird registered (A-102; `verify_secret`
    /// was removed from it, docs/52 R4). Not the LDAP front, which holds [`Role::Ldap`]
    /// (docs/questions/Q-165 item 3: "not `Directory`, which holds
    /// `set_secret`"). Spec: docs/10 §2.
    Directory = 1,
    /// Tier-0 key administration: before the seal the ceremony
    /// (`create_key`, the first administrators' grants); always, only the
    /// decisions dird registered (A-102). Spec: docs/10 §2, §7; docs/52 §4.
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
    /// Register a one-time, short-lived grant that lets Role::Directory run
    /// `set_secret` on exactly the named key targets: dird (Role::Ldap)
    /// after its PDP allowed a `BeginPasswordSet`; keyadm (Role::Admin) for
    /// the provisioning manifest's first administrators during the
    /// ceremony.
    /// Spec: docs/51 §5.8 (option (b)); docs/questions/Q-291 (A-74: task
    /// A15 before any deployment), Q-450.
    ///
    /// Since A-102 (docs/52 R3) this is Role::Admin's **provisioning-only**
    /// operation ([`provisioning_only`]): keyadm's ceremony grants the first
    /// administrators' initial secrets before the ceremony is sealed. dird's
    /// grants are `SetSecret` decisions registered through
    /// [`Operation::RegisterDecision`].
    GrantSetSecret = 16,
    /// Register a one-time, operation-bound decision: the only way a
    /// state-changing operation of Role::Directory or Role::Admin can run
    /// after the ceremony (docs/52 §4.2). Role::Ldap (dird) only — the PDP
    /// that owns the decision.
    /// Spec: docs/52 §4.2, §4.3, §7 R1; docs/questions/Q-460 (A-102).
    RegisterDecision = 17,
    /// End the provisioning ceremony: keyd moves from `Provisioning` to
    /// `Operational`, after which [`provisioning_only`] operations do not
    /// exist (until the next start of a keyd with an empty store).
    /// Role::Admin (keyadm's ceremony ends with it).
    /// Spec: docs/52 §4.4, §7 R3; docs/questions/Q-462 item 1 (A-102).
    SealCeremony = 18,
    /// List the pending destroy decisions dird registered (decision id and
    /// principal id — not secret), one bounded page at a time: what keyadm's
    /// `destroy-sweep` executes. Role::Admin.
    /// Spec: docs/52 §4.3, §4.6; docs/51 §6, §9; docs/questions/Q-460
    /// (A-102).
    ListDestroyDecisions = 19,
    /// Verify a service AP-REQ bound to one operation (the admin channel's
    /// `AppBinding::OperationDigest`): RFC 4120 3.2.3 under the
    /// AdminService key set, the Authenticator's `cksum` the session key's
    /// MIC over the operation digest (key usage 10) — and **no service
    /// context**: the answer (`OperationTicket`) has no context id and keyd
    /// keeps no session key for it. Role::Ldap (dird). Appended by Q-523;
    /// `OpenAndVerifyServiceTicket` is now the unbound verification only.
    /// Spec: RFC 4120 3.2.3, 5.5.1, 7.5.1 item 10; docs/10 §5ב; docs/52
    /// §3.4 (C4), §5; docs/questions/Q-387 item 4, Q-493 item 3, Q-523.
    VerifyOperationTicket = 20,
    /// Open an RFC 3244 change-password request: the AP-REQ for
    /// `kadmin/changepw` verified by the **same** core as the two
    /// service-ticket verifications (RFC 4120 3.2.3 under the
    /// ChangePasswordService key set; a subkey and a sequence number
    /// required, no `cksum`), the KRB-PRIV decrypted under the subkey (key
    /// usage 13) and its control information checked, the ChangePasswdData
    /// judged — and a one-time request context returned, with no password
    /// leaving keyd. Role::Ldap (dird). Appended by task K3.
    /// Spec: RFC 3244 §2; RFC 4120 3.2.3, 3.5.2, 5.7.1, 7.5.1; docs/53 R53-7,
    /// §5.3-§5.5; docs/questions/Q-601 item 2 (A-117).
    OpenChangePasswordRequest = 21,
    /// Complete a change-password request: on a live `SetSecret` decision
    /// whose one target is the ticket's own client (bound by keyd), install
    /// the context's password through the same install function as
    /// `set_secret`, then seal the success reply (AP-REP + KRB-PRIV with
    /// result code 0). Consumes the context. A key-state change. Role::Ldap
    /// (dird). Appended by task K3.
    /// Spec: RFC 3244 §2; RFC 4120 3.2.4, 5.5.2, 5.7.1; docs/53 R53-5, R53-7,
    /// §4.4, §5.5; docs/questions/Q-601 items 2, 5 (A-117).
    CompleteChangePassword = 22,
    /// Seal a change-password error reply (AP-REP + KRB-PRIV carrying a
    /// non-zero result code, no result string). Consumes the context.
    /// Role::Ldap (dird). Appended by task K3.
    /// Spec: RFC 3244 §2; docs/53 R53-7, R53-11, §5.5, §5.7; docs/questions/
    /// Q-604 (A-117).
    SealChangePasswordError = 23,
    /// Revoke a **key-operation** decision dird registered
    /// (`RotateKrbtgt` / `RotateKey` / `RetireKvno`, named by its id): from
    /// the answer on, no execution can consume it, and keyd keeps the id as
    /// revoked so that no later registration under it is accepted either.
    /// Idempotent (an id already revoked, or one keyd never held, is
    /// answered `Ok`). A decision whose execution already changed key state
    /// cannot be revoked — `Denied` (reason `DecisionExecuted`): the
    /// operation ran, and saying "revoked" would claim a cancellation that
    /// did not happen. Role::Ldap (dird) only — exactly the roles that may
    /// register a decision (pinned below). It changes no key state and only
    /// makes keyd stricter: one record, no intent. Appended by task F3.
    /// Spec: docs/52 §3.1 (C1), §3.14 (C14), §4.2, §4.3 (A-102); docs/10
    /// §2, §6א, §10; docs/questions/Q-937 item 6 (the residual of A-159),
    /// Q-976.
    RevokeDecision = 24,
}

impl Operation {
    /// Every operation, for exhaustive checks. Spec: docs/10 §2.
    pub const ALL: [Operation; 25] = [
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
        Operation::GrantSetSecret,
        Operation::RegisterDecision,
        Operation::SealCeremony,
        Operation::ListDestroyDecisions,
        Operation::VerifyOperationTicket,
        Operation::OpenChangePasswordRequest,
        Operation::CompleteChangePassword,
        Operation::SealChangePasswordError,
        Operation::RevokeDecision,
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
/// (`DescribeConfig`: roles Kdc and Ldap; `Ping`: every mapped role), §7.5;
/// docs/51 §5.8 option (b), docs/questions/Q-291 (A-74), Q-450 items 1, 6;
/// docs/52 §3.4, §4, §7 R1, R3, R4 and docs/questions/Q-460, Q-462, Q-465
/// (A-102): **`RegisterDecision` is Ldap's alone** (dird, the PDP that owns
/// every decision); `GrantSetSecret` is Admin's alone and exists only before
/// the seal ([`provisioning_only`]); `VerifySecret` is in **no** row (N3:
/// no process calls it, and Directory holding it was an AS-bypassing guess
/// oracle — docs/51 §5.3 option B, rejected); Admin's rotations, retirement
/// and destruction run only a decision dird registered
/// ([`requires_decision`]). Task R6 (A-105, docs/questions/Q-470 item 4,
/// Q-503): Ldap may also read `ListDestroyDecisions` — the pending destroy
/// decisions it registered itself — so that dird re-registers only the ones
/// keyd lost (a read: decision ids and tombstones' GUIDs, nothing secret, no
/// state changed). Q-523: Ldap's service-ticket verification is two
/// operations, one per binding — `OpenAndVerifyServiceTicket` (unbound, the
/// LDAP front; keeps a service context) and `VerifyOperationTicket` (bound
/// to an operation digest, dird's admin channel; keeps none). Task K3
/// (docs/53 R53-7, §4.5; Q-601 items 2, 5, A-117): Ldap (dird) also holds the
/// three change-password operations — `OpenChangePasswordRequest`,
/// `CompleteChangePassword` (a key-state change, so `requires_decision`: it
/// redeems a `SetSecret` decision dird itself registered, and the C1 pin now
/// covers every role) and `SealChangePasswordError`. Task F3 (docs/questions/
/// Q-937 item 6, Q-976): Ldap (dird) also holds `RevokeDecision` — the role
/// that registers a decision is the only one that may revoke one (pinned:
/// for every role, `RevokeDecision` ⇔ `RegisterDecision`).
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
    (Role::Directory, &[Operation::SetSecret, Operation::Ping]),
    (
        Role::Admin,
        &[
            Operation::CreateKey,
            Operation::RotateKey,
            Operation::RotateKrbtgt,
            Operation::RetireKvno,
            Operation::DestroyKeySet,
            Operation::GrantSetSecret,
            Operation::SealCeremony,
            Operation::ListDestroyDecisions,
            Operation::Ping,
        ],
    ),
    (
        Role::Ldap,
        &[
            Operation::OpenAndVerifyServiceTicket,
            Operation::VerifyOperationTicket,
            Operation::RegisterDecision,
            Operation::ListDestroyDecisions,
            Operation::DescribeConfig,
            Operation::Ping,
            Operation::OpenChangePasswordRequest,
            Operation::CompleteChangePassword,
            Operation::SealChangePasswordError,
            Operation::RevokeDecision,
        ],
    ),
];

/// `true` if `op` exists only while keyd is in its provisioning ceremony
/// (before `seal_ceremony`): `create_key` (the ceremony draws krbtgt and the
/// two service keys) and Role::Admin's `grant_set_secret` (the first
/// administrators' initial secrets). After the seal both are refused at the
/// authorization step (`CeremonySealed`): Admin can then do nothing that is
/// not a decision dird registered.
///
/// The match is exhaustive: a new operation does not compile until it is
/// decided here.
///
/// Spec: docs/52 §3.4 (C4), §4.4, §7 R3; docs/51 §4.3 steps 11-12, §6;
/// docs/questions/Q-451, Q-462 item 1 (A-102).
#[must_use]
pub const fn provisioning_only(op: Operation) -> bool {
    match op {
        Operation::CreateKey | Operation::GrantSetSecret => true,
        Operation::VerifyPreauth
        | Operation::IssueAsRep
        | Operation::OpenAndVerifyTgt
        | Operation::IssueTgsRep
        | Operation::SetSecret
        | Operation::VerifySecret
        | Operation::RotateKey
        | Operation::RotateKrbtgt
        | Operation::RetireKvno
        | Operation::OpenFastArmor
        | Operation::SealFastError
        | Operation::DestroyKeySet
        | Operation::OpenAndVerifyServiceTicket
        | Operation::VerifyOperationTicket
        | Operation::DescribeConfig
        | Operation::Ping
        | Operation::RegisterDecision
        | Operation::SealCeremony
        | Operation::ListDestroyDecisions
        | Operation::OpenChangePasswordRequest
        | Operation::CompleteChangePassword
        | Operation::SealChangePasswordError
        | Operation::RevokeDecision => false,
    }
}

/// `true` if `op` runs only on a live decision dird registered
/// (`register_decision`): `set_secret` (matched by handle, binding and
/// salt), and Role::Admin's `rotate_key`, `rotate_krbtgt`, `retire_kvno`
/// and `destroy_key_set` (named by decision id; keyd runs the **registered**
/// parameters, never the caller's), and Role::Ldap's
/// `complete_change_password` (task K3: a `SetSecret` decision for the
/// target handle whose one target's binding is the ticket's client — keyd
/// binds it, docs/53 §5.5). No decision ⇒ the uniform `Denied` at the
/// authorization step (`NoDecision` / `NoGrant`).
///
/// The match is exhaustive: a new operation does not compile until it is
/// decided here.
///
/// Spec: docs/52 §3.1 (C1), §4.2, §7 R1; docs/questions/Q-460 (A-102);
/// docs/53 §4.5; docs/questions/Q-601 item 5 (A-117).
#[must_use]
pub const fn requires_decision(op: Operation) -> bool {
    match op {
        Operation::SetSecret
        | Operation::RotateKey
        | Operation::RotateKrbtgt
        | Operation::RetireKvno
        | Operation::DestroyKeySet
        | Operation::CompleteChangePassword => true,
        Operation::VerifyPreauth
        | Operation::IssueAsRep
        | Operation::OpenAndVerifyTgt
        | Operation::IssueTgsRep
        | Operation::VerifySecret
        | Operation::CreateKey
        | Operation::OpenFastArmor
        | Operation::SealFastError
        | Operation::OpenAndVerifyServiceTicket
        | Operation::VerifyOperationTicket
        | Operation::DescribeConfig
        | Operation::Ping
        | Operation::GrantSetSecret
        | Operation::RegisterDecision
        | Operation::SealCeremony
        | Operation::ListDestroyDecisions
        | Operation::OpenChangePasswordRequest
        | Operation::SealChangePasswordError
        | Operation::RevokeDecision => false,
    }
}

/// `true` if `op` installs, rotates, retires or destroys long-term key
/// versions: keyd's key state, which cannot be undone once the operation
/// ran. The throttles, the replay cache and the token tables are
/// bookkeeping, not key state (crate keyd `state_change`, which re-exports
/// this table).
///
/// **One table for both ends of the keyd channel (task R9, docs/52 §3.10
/// (c)).** It lives here, in the crypto-free crate, so that keyd-daemon's
/// classification of a call (crate ipc-keyd-server `classify`, through
/// [`requires_acknowledged_intent`]) and the keyd client's split of its
/// API (crate ipc-keyd: a state call has no fate-dropping path) read the
/// same table — never two lists that could drift apart. Moved here from
/// crate keyd unchanged.
///
/// The match is exhaustive: a new operation does not compile until it is
/// classified here.
///
/// `complete_change_password` (task K3) installs a password-derived key
/// version through the same install function as `set_secret`: key state.
/// `open_change_password_request` and `seal_change_password_error` touch
/// only the replay cache and the request-context table (bookkeeping).
///
/// Spec: docs/10 §6 (`set_secret`), §7 (`create_key`, `rotate_key`,
/// `rotate_krbtgt`, `retire_kvno`, `destroy_key_set`), §10;
/// docs/questions/Q-346 (A-86), Q-466 item 3 (A-102); docs/53 §4.4, §9
/// ("`complete_change_password` — intent + outcome (`changes_key_state`)").
#[must_use]
pub const fn changes_key_state(op: Operation) -> bool {
    match op {
        Operation::SetSecret
        | Operation::CreateKey
        | Operation::RotateKey
        | Operation::RotateKrbtgt
        | Operation::RetireKvno
        | Operation::DestroyKeySet
        | Operation::CompleteChangePassword => true,
        Operation::VerifyPreauth
        | Operation::IssueAsRep
        | Operation::OpenAndVerifyTgt
        | Operation::IssueTgsRep
        | Operation::VerifySecret
        | Operation::OpenFastArmor
        | Operation::SealFastError
        | Operation::OpenAndVerifyServiceTicket
        | Operation::VerifyOperationTicket
        | Operation::DescribeConfig
        | Operation::Ping
        | Operation::GrantSetSecret
        | Operation::RegisterDecision
        | Operation::SealCeremony
        | Operation::ListDestroyDecisions
        | Operation::OpenChangePasswordRequest
        | Operation::SealChangePasswordError
        | Operation::RevokeDecision => false,
    }
}

/// `true` if `op` makes keyd **less** strict without changing key state:
/// `grant_set_secret` (task A15a) and `register_decision` (A-102), each of
/// which lets Role::Directory or Role::Admin run a state change keyd would
/// otherwise refuse. Every other change keyd makes to its in-memory tables
/// only ever makes it stricter — `revoke_decision` (task F3) among them: it
/// takes a decision away, never grants one. Audited like a key-state change: intent
/// acknowledged first, then the outcome ([`requires_acknowledged_intent`]).
/// Moved here from crate keyd unchanged (see [`changes_key_state`]).
///
/// The match is exhaustive: a new operation does not compile until it is
/// classified here.
///
/// Spec: docs/51 §5.8 option (b); docs/52 §4.5; docs/questions/Q-291
/// (A-74), Q-365 item 2 (A-88), Q-452, Q-466 item 3 (A-102).
#[must_use]
pub const fn loosens_authorization(op: Operation) -> bool {
    match op {
        Operation::GrantSetSecret | Operation::RegisterDecision => true,
        Operation::VerifyPreauth
        | Operation::IssueAsRep
        | Operation::OpenAndVerifyTgt
        | Operation::IssueTgsRep
        | Operation::SetSecret
        | Operation::VerifySecret
        | Operation::CreateKey
        | Operation::RotateKey
        | Operation::RotateKrbtgt
        | Operation::RetireKvno
        | Operation::OpenFastArmor
        | Operation::SealFastError
        | Operation::DestroyKeySet
        | Operation::OpenAndVerifyServiceTicket
        | Operation::VerifyOperationTicket
        | Operation::DescribeConfig
        | Operation::Ping
        | Operation::SealCeremony
        | Operation::ListDestroyDecisions
        | Operation::OpenChangePasswordRequest
        | Operation::CompleteChangePassword
        | Operation::SealChangePasswordError
        | Operation::RevokeDecision => false,
    }
}

/// `true` if the daemon must have the intent of `op` acknowledged by auditd
/// before keyd runs it (A-86 / A-88): a key-state change
/// ([`changes_key_state`]) or a change that loosens keyd's authorization
/// ([`loosens_authorization`]).
///
/// The one classification of a keyd call as a **state call**: keyd-daemon
/// runs such a call only with the proof of its acknowledged intent (crate
/// ipc-keyd-server `classify`, `execute_acknowledged`), and the keyd client
/// sends it only through the path that reports the request's fate (crate
/// ipc-keyd `StateCall`, `KeydClient::call_with_fate`) — "not performed"
/// and "outcome unknown" are never folded into one `Unavailable` for it.
///
/// Spec: docs/questions/Q-346 (A-86), Q-365 (A-88), Q-452 item 1, Q-466
/// item 3 (A-102); docs/52 §3.10 (c), §7 R9.
#[must_use]
pub const fn requires_acknowledged_intent(op: Operation) -> bool {
    changes_key_state(op) || loosens_authorization(op)
}

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
/// interpretation recorded in docs/questions/Q-240 item 1. Nor
/// `grant_set_secret`: its grant table lives in memory too, but losing it
/// at a start only makes keyd stricter (a `set_secret` without its grant is
/// refused), so nothing needs holding (docs/questions/Q-450 item 5). Nor the
/// decision operations (`register_decision`, `seal_ceremony`,
/// `list_destroy_decisions`, A-102; `revoke_decision`, task F3): the
/// decision table is lost at a start
/// like the grant table (stricter); the ceremony state restarts as
/// `Provisioning` only for an empty store — docs/52 §4.4 (P-17). Held too
/// (task K3; docs/53 §5.3, §5.8): the three change-password operations —
/// `open_change_password_request` enters the shared replay cache and
/// creates a request context; `complete_change_password` and
/// `seal_change_password_error` consume one (the issuance / error steps of
/// that exchange, like `issue_tgs_rep` / `seal_fast_error`).
///
/// The match is exhaustive: a new operation does not compile until it is
/// decided here.
///
/// Spec: RFC 4120 3.2.3; docs/50 R50-6, §3.5, §7.5; docs/questions/Q-222
/// (A-56), Q-240 (A-62); docs/53 §5.3 (A-117).
pub const fn startup_hold_down_applies(op: Operation) -> bool {
    match op {
        Operation::VerifyPreauth
        | Operation::IssueAsRep
        | Operation::OpenAndVerifyTgt
        | Operation::IssueTgsRep
        | Operation::OpenFastArmor
        | Operation::SealFastError
        | Operation::OpenAndVerifyServiceTicket
        | Operation::VerifyOperationTicket
        | Operation::OpenChangePasswordRequest
        | Operation::CompleteChangePassword
        | Operation::SealChangePasswordError => true,
        Operation::SetSecret
        | Operation::VerifySecret
        | Operation::CreateKey
        | Operation::RotateKey
        | Operation::RotateKrbtgt
        | Operation::RetireKvno
        | Operation::DestroyKeySet
        | Operation::DescribeConfig
        | Operation::Ping
        | Operation::GrantSetSecret
        | Operation::RegisterDecision
        | Operation::SealCeremony
        | Operation::ListDestroyDecisions
        | Operation::RevokeDecision => false,
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
/// `issue_as_rep` takes a client and a server handle; its server slot has
/// two variants, chosen by whether the issuance is FAST-armored
/// ([`as_server_slot`]) — so the capability table itself, and its
/// compile-time pins, say that the change-password service is a server only
/// of an armored issuance (task K3b).
///
/// Spec: docs/10 §4 (issue_as_rep takes a client and a server handle);
/// docs/53 §5.2; docs/questions/Q-915 items 1, 3 (A-151).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandleSlot {
    /// The operation's main handle (the client, service, krbtgt or managed
    /// key, depending on the operation).
    Primary = 0,
    /// The server handle of an **unarmored** `issue_as_rep`: the key set
    /// the ticket is sealed under — this realm's krbtgt only
    /// ([`AsServer::of`] with `armored = false`).
    /// Spec: docs/10 §4; docs/48 §7.3 (the unarmored bootstrap: "only
    /// TGT"); A-142.
    AsServer = 1,
    /// The second key target of `grant_set_secret`: a computer's `Service`
    /// key set (docs/47 §9.1: a computer's password sets its
    /// `PrincipalLongterm` and its `Service` key set).
    /// Spec: docs/51 §5.2 row 5, §7.3; docs/questions/Q-450 item 2.
    Secondary = 2,
    /// The server handle of a **FAST-armored** `issue_as_rep`: krbtgt or the
    /// change-password service's key set ([`AsServer::of`] with `armored =
    /// true`).
    /// Spec: docs/53 §5.2; docs/questions/Q-915 items 1, 3 (A-151); A-117.
    ArmoredAsServer = 3,
}

/// The server slot of an `issue_as_rep` that is `armored` or not — the one
/// choice keyd makes when it admits the call (pinned below).
/// Spec: docs/53 §5.2; docs/questions/Q-915 items 1, 3; A-142.
#[must_use]
pub const fn as_server_slot(armored: bool) -> HandleSlot {
    if armored {
        HandleSlot::ArmoredAsServer
    } else {
        HandleSlot::AsServer
    }
}

/// The purposes an operation accepts in a handle slot. Anything else is
/// denied (key separation, invariant I3).
///
/// - `verify_preauth`, `issue_as_rep` (client): PrincipalLongterm (docs/10
///   §4 "חייב purpose = PrincipalLongterm").
/// - `issue_as_rep` (server): exactly the servers of [`AsServer::of`] — in
///   the unarmored slot Krbtgt only, in the armored slot Krbtgt or
///   ChangePasswordService (docs/53 §5.2: "Krbtgt **or**
///   ChangePasswordService, no other purpose"; A-142: never unarmored).
/// - `open_and_verify_tgt`, `open_fast_armor`: Krbtgt (docs/10 §4, §5;
///   docs/48 §2.3 "open_fast_armor.krbtgt = Krbtgt").
/// - `seal_fast_error` takes no handle: the armor token is its authority
///   (docs/48 §2.3), so no slot of it is permitted.
/// - `describe_config`, `ping` take no handle (docs/50 §3.4: no request
///   fields), so no slot of them is permitted; nor do `register_decision`
///   (the purposes of a decided operation are checked through the operation
///   that will run it — `DecidedOperation::purposes_permitted`),
///   `seal_ceremony` and `list_destroy_decisions` (A-102), nor
///   `revoke_decision` (task F3: it names a decision id only).
/// - `issue_tgs_rep`: Service or AdminService — a service ticket is sealed
///   under the key set of its service's purpose (the admin service's own,
///   R2). Referral TGTs (Krbtgt in docs/10 §5) are cross-realm, which phase
///   1 does not implement.
/// - `open_and_verify_service_ticket`: Service only — "only handles of
///   type `Service`" (docs/questions/Q-165 item 3, A-46) — and
///   `verify_operation_ticket`: AdminService only. R2 made the purpose the
///   binding's (`AppBinding::key_purpose`: `Unbound` ⇒ Service,
///   `OperationDigest` ⇒ AdminService); since Q-523 each binding is its own
///   operation (`AppBinding::operation`), so each row holds exactly its
///   binding's purpose (pinned below). A TGT is never opened here (that is
///   the KDC's `open_and_verify_tgt`).
/// - `set_secret`, `verify_secret`: PrincipalLongterm or Service. The krbtgt
///   key is never password-derived and is rotated only through
///   `rotate_krbtgt` (dual control, docs/10 §7); the admin service key is
///   drawn by keyd and never password-derived either (R2: no Role::Directory
///   `set_secret` can replace the key admin tickets are verified under —
///   the A-50 / Q-180 item 4 rule as a purpose); nor is the change-password
///   service key (docs/53 §4.5, A-117).
/// - `rotate_key`: PrincipalLongterm, Service, AdminService or — task F3,
///   owner decision A-126 on docs/questions/Q-660 item 11 ("ChangePasswordService
///   must be rotatable through a decision (like AdminService)"; a key that
///   cannot be rotated is a weakness class of its own) —
///   ChangePasswordService. `rotate_key` is Role::Admin's and runs **only**
///   on a `RotateKey` decision dird registered (`requires_decision`, never
///   provisioning-only): the slot is open to the change-password service's
///   key set through a dual-controlled decision and in no other way (pinned
///   below). keyd draws the new version itself (`rotate_random`), so the key
///   set stays keyd-drawn — never password-derived (docs/53 §4.5's other
///   rules stand: no `set_secret` / grant / destroy for it). Formerly refused
///   (docs/53 §4.5; Q-601 item 4).
/// - `destroy_key_set`: PrincipalLongterm or Service — never Krbtgt (A-35),
///   never AdminService or ChangePasswordService (a destroy decision names a
///   deleted account's PrincipalLongterm and Service key sets only).
/// - `rotate_krbtgt`: Krbtgt.
/// - `create_key`, `retire_kvno`: any phase-1 purpose (docs/10 §7:
///   create_key also initializes krbtgt; the ceremony draws the admin
///   service key, docs/51 §4.3 step 11, and the change-password service key,
///   docs/53 §5.2).
/// - `open_change_password_request`: ChangePasswordService only — the
///   purpose of `AppBinding::ChangePassword`; no other operation opens a
///   ticket under that key set (docs/53 §4.5, pinned below); the one other
///   operation that uses it is the armored `issue_as_rep`, which seals the
///   service's tickets (task K3b, pinned below).
/// - `complete_change_password`: PrincipalLongterm only — the target is a
///   user's password key set (docs/53 R53-1: users only; the decision's
///   one target).
/// - `seal_change_password_error` takes no handle (the request context is
///   its authority), so no slot of it is permitted.
/// - `grant_set_secret`: PrincipalLongterm first (every account's password
///   key set), Service second (a computer's service key set) — the targets
///   dird's `BeginPasswordSet` returns (docs/51 §5.2 row 5, §7.3). Never
///   Krbtgt: its key is never password-derived.
///
/// Spec: docs/10 §2 ("(b) the KeyPurpose of the handle matches the
/// operation"), §4, §5, §6, §7, §12 I3; docs/48 §2.3, §9.1 I3;
/// docs/questions/Q-115 (A-35), Q-165 item 3 (A-46), Q-450 item 2, Q-463
/// item 4 (A-102; docs/52 §5 item 3), Q-523, Q-915 items 1, 3 (A-151).
pub const fn purpose_permitted(op: Operation, slot: HandleSlot, purpose: KeyPurpose) -> bool {
    use KeyPurpose::{AdminService, ChangePasswordService, Krbtgt, PrincipalLongterm, Service};
    match (op, slot) {
        // The closed server slot (task K3b): defined by the one
        // classification, so the table cannot name a third server.
        (Operation::IssueAsRep, HandleSlot::AsServer) => AsServer::of(purpose, false).is_some(),
        (Operation::IssueAsRep, HandleSlot::ArmoredAsServer) => {
            AsServer::of(purpose, true).is_some()
        }
        (Operation::IssueTgsRep, HandleSlot::Primary) => matches!(purpose, Service | AdminService),
        (Operation::OpenAndVerifyServiceTicket, HandleSlot::Primary) => matches!(purpose, Service),
        (Operation::VerifyOperationTicket, HandleSlot::Primary) => matches!(purpose, AdminService),
        (Operation::OpenChangePasswordRequest, HandleSlot::Primary) => {
            matches!(purpose, ChangePasswordService)
        }
        (Operation::VerifyPreauth, HandleSlot::Primary)
        | (Operation::IssueAsRep, HandleSlot::Primary)
        | (Operation::CompleteChangePassword, HandleSlot::Primary) => {
            matches!(purpose, PrincipalLongterm)
        }
        (Operation::OpenAndVerifyTgt, HandleSlot::Primary)
        | (Operation::OpenFastArmor, HandleSlot::Primary)
        | (Operation::RotateKrbtgt, HandleSlot::Primary) => matches!(purpose, Krbtgt),
        (Operation::SetSecret, HandleSlot::Primary)
        | (Operation::VerifySecret, HandleSlot::Primary)
        | (Operation::DestroyKeySet, HandleSlot::Primary) => {
            matches!(purpose, PrincipalLongterm | Service)
        }
        // Task F3 (A-126; Q-660 item 11): the change-password service's key
        // set is rotatable — through a decision only (pinned below).
        (Operation::RotateKey, HandleSlot::Primary) => {
            matches!(
                purpose,
                PrincipalLongterm | Service | AdminService | ChangePasswordService
            )
        }
        (Operation::CreateKey, HandleSlot::Primary)
        | (Operation::RetireKvno, HandleSlot::Primary) => {
            matches!(
                purpose,
                PrincipalLongterm | Service | Krbtgt | AdminService | ChangePasswordService
            )
        }
        (Operation::GrantSetSecret, HandleSlot::Primary) => matches!(purpose, PrincipalLongterm),
        (Operation::GrantSetSecret, HandleSlot::Secondary) => matches!(purpose, Service),
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
    // R4 (docs/52 §3.4 N3; docs/questions/Q-465, A-102): no role holds
    // `verify_secret` — in particular not Directory (admind), for which it
    // was a second, FAST-bypassing password-guess oracle.
    assert!(!role_permits(Role::Directory, Operation::VerifySecret));
    assert!(!role_permits(Role::Kdc, Operation::VerifySecret));
    assert!(!role_permits(Role::Ldap, Operation::VerifySecret));
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
        HandleSlot::AsServer,
        KeyPurpose::Krbtgt
    ));
    // Service-ticket verification (docs/questions/Q-165 item 3, A-46):
    // `Ldap` may call open_and_verify_service_ticket and — docs/50 §3.4 —
    // describe_config and ping, and — docs/52 §4.2, A-102 —
    // register_decision, and — task R6, A-105 — list_destroy_decisions (a
    // read of its own registrations), and — task K3, A-117 — the three
    // change-password operations, and nothing else; no other role may call
    // either service-ticket verification (Q-523: the unbound one opens only
    // Service-purpose handles, the operation-bound one only AdminService) or
    // any change-password operation.
    let mut i = 0;
    while i < Operation::ALL.len() {
        let op = Operation::ALL[i];
        let is_service_ticket = op as u8 == Operation::OpenAndVerifyServiceTicket as u8
            || op as u8 == Operation::VerifyOperationTicket as u8;
        let is_daemon_support =
            op as u8 == Operation::DescribeConfig as u8 || op as u8 == Operation::Ping as u8;
        // Task F3: the revocation is a decision operation of Ldap's too.
        let is_decision = op as u8 == Operation::RegisterDecision as u8
            || op as u8 == Operation::ListDestroyDecisions as u8
            || op as u8 == Operation::RevokeDecision as u8;
        let is_change_password = op as u8 == Operation::OpenChangePasswordRequest as u8
            || op as u8 == Operation::CompleteChangePassword as u8
            || op as u8 == Operation::SealChangePasswordError as u8;
        assert!(
            role_permits(Role::Ldap, op)
                == (is_service_ticket || is_daemon_support || is_decision || is_change_password)
        );
        if is_service_ticket || is_change_password {
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
        KeyPurpose::AdminService,
        KeyPurpose::ChangePasswordService,
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
            HandleSlot::ArmoredAsServer,
            purposes[p]
        ));
        assert!(!purpose_permitted(
            Operation::Ping,
            HandleSlot::Primary,
            purposes[p]
        ));
        assert!(!purpose_permitted(
            Operation::Ping,
            HandleSlot::ArmoredAsServer,
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
    // Q-523: the operation-bound verification enters the same replay cache.
    assert!(startup_hold_down_applies(Operation::VerifyOperationTicket));
    // Task K3 (docs/53 §5.3): the change-password request enters it too, and
    // its context is consumed by the completion or the error seal.
    assert!(startup_hold_down_applies(
        Operation::OpenChangePasswordRequest
    ));
    assert!(startup_hold_down_applies(Operation::CompleteChangePassword));
    assert!(startup_hold_down_applies(
        Operation::SealChangePasswordError
    ));
    assert!(!startup_hold_down_applies(Operation::DescribeConfig));
    assert!(!startup_hold_down_applies(Operation::Ping));
    // The Admin set_secret grant (docs/51 §5.8 option (b); A-74; Q-450;
    // A-102): never the role it is for (Directory), never the KDC, and since
    // A-102 not dird either (dird registers `SetSecret` decisions); keyadm's
    // ceremony only, before the seal; its targets are a PrincipalLongterm
    // key set, then a computer's Service key set — never krbtgt; it is not
    // held after a start (a lost grant table only makes keyd stricter).
    assert!(!role_permits(Role::Ldap, Operation::GrantSetSecret));
    assert!(role_permits(Role::Admin, Operation::GrantSetSecret));
    assert!(provisioning_only(Operation::GrantSetSecret));
    assert!(provisioning_only(Operation::CreateKey));
    // The decision table (docs/52 §4.2, R1; A-102): only dird (Ldap)
    // registers a decision; the seal and the destroy listing are Admin's.
    assert!(role_permits(Role::Ldap, Operation::RegisterDecision));
    assert!(!role_permits(Role::Kdc, Operation::RegisterDecision));
    assert!(!role_permits(Role::Directory, Operation::RegisterDecision));
    assert!(!role_permits(Role::Admin, Operation::RegisterDecision));
    assert!(role_permits(Role::Admin, Operation::SealCeremony));
    assert!(role_permits(Role::Admin, Operation::ListDestroyDecisions));
    // Task R6 (A-105, Q-503): dird reads its own registrations back, to
    // re-register the destroy decisions keyd lost; never Kdc or Directory.
    assert!(role_permits(Role::Ldap, Operation::ListDestroyDecisions));
    assert!(!role_permits(Role::Kdc, Operation::ListDestroyDecisions));
    assert!(!role_permits(
        Role::Directory,
        Operation::ListDestroyDecisions
    ));
    assert!(!startup_hold_down_applies(Operation::RegisterDecision));
    assert!(!startup_hold_down_applies(Operation::SealCeremony));
    assert!(!startup_hold_down_applies(Operation::ListDestroyDecisions));
    // Task F3 (docs/questions/Q-937 item 6, Q-976): only the role that may
    // register a decision may revoke one — for every role, the two cells are
    // equal (today: Ldap, dird). The revocation changes no key state, loosens
    // nothing (it takes a decision away), needs no decision of its own,
    // exists after the seal, is not held after a start (a lost table is
    // stricter already) and names no handle.
    let roles = [Role::Kdc, Role::Directory, Role::Admin, Role::Ldap];
    let mut rv = 0;
    while rv < roles.len() {
        assert!(
            role_permits(roles[rv], Operation::RevokeDecision)
                == role_permits(roles[rv], Operation::RegisterDecision)
        );
        rv += 1;
    }
    assert!(role_permits(Role::Ldap, Operation::RevokeDecision));
    assert!(!changes_key_state(Operation::RevokeDecision));
    assert!(!loosens_authorization(Operation::RevokeDecision));
    assert!(!requires_acknowledged_intent(Operation::RevokeDecision));
    assert!(!requires_decision(Operation::RevokeDecision));
    assert!(!provisioning_only(Operation::RevokeDecision));
    assert!(!startup_hold_down_applies(Operation::RevokeDecision));
    // C1 closed by construction (docs/52 §3.1, A-102): every operation
    // Directory or Admin may call either runs only on a dird decision, or
    // exists only before the seal, or is one of the three that change no
    // key state and loosen nothing (ping, the seal, the destroy listing).
    // keyd's state_change.rs pins the same against `changes_key_state` /
    // `loosens_authorization`.
    let mut c = 0;
    while c < Operation::ALL.len() {
        let op = Operation::ALL[c];
        if role_permits(Role::Directory, op) || role_permits(Role::Admin, op) {
            let harmless = op as u8 == Operation::Ping as u8
                || op as u8 == Operation::SealCeremony as u8
                || op as u8 == Operation::ListDestroyDecisions as u8;
            assert!(requires_decision(op) || provisioning_only(op) || harmless);
        }
        c += 1;
    }
    // Task K3 (docs/53 §4.5; Q-601 item 5, A-117): the C1 pin for **every**
    // role — an operation that changes key state runs only on a dird
    // decision or exists only before the seal, whoever may call it. Kdc
    // issuance changes no key state; `complete_change_password` (Ldap) does,
    // and must redeem a `SetSecret` decision.
    let mut k = 0;
    while k < Operation::ALL.len() {
        let op = Operation::ALL[k];
        let roles = [Role::Kdc, Role::Directory, Role::Admin, Role::Ldap];
        let mut r = 0;
        while r < roles.len() {
            if role_permits(roles[r], op) && changes_key_state(op) {
                assert!(requires_decision(op) || provisioning_only(op));
            }
            r += 1;
        }
        k += 1;
    }
    assert!(requires_decision(Operation::CompleteChangePassword));
    assert!(changes_key_state(Operation::CompleteChangePassword));
    assert!(!changes_key_state(Operation::OpenChangePasswordRequest));
    assert!(!changes_key_state(Operation::SealChangePasswordError));
    assert!(!loosens_authorization(Operation::OpenChangePasswordRequest));
    assert!(!loosens_authorization(Operation::CompleteChangePassword));
    assert!(!loosens_authorization(Operation::SealChangePasswordError));
    assert!(!role_permits(Role::Directory, Operation::GrantSetSecret));
    assert!(!role_permits(Role::Kdc, Operation::GrantSetSecret));
    assert!(!startup_hold_down_applies(Operation::GrantSetSecret));
    assert!(purpose_permitted(
        Operation::GrantSetSecret,
        HandleSlot::Primary,
        KeyPurpose::PrincipalLongterm
    ));
    assert!(!purpose_permitted(
        Operation::GrantSetSecret,
        HandleSlot::Primary,
        KeyPurpose::Service
    ));
    assert!(!purpose_permitted(
        Operation::GrantSetSecret,
        HandleSlot::Primary,
        KeyPurpose::Krbtgt
    ));
    assert!(purpose_permitted(
        Operation::GrantSetSecret,
        HandleSlot::Secondary,
        KeyPurpose::Service
    ));
    assert!(!purpose_permitted(
        Operation::GrantSetSecret,
        HandleSlot::Secondary,
        KeyPurpose::PrincipalLongterm
    ));
    assert!(!purpose_permitted(
        Operation::GrantSetSecret,
        HandleSlot::Secondary,
        KeyPurpose::Krbtgt
    ));
    assert!(!purpose_permitted(
        Operation::GrantSetSecret,
        HandleSlot::AsServer,
        KeyPurpose::Krbtgt
    ));
    // Only grant_set_secret has a Secondary slot.
    let mut s = 0;
    while s < Operation::ALL.len() {
        let op = Operation::ALL[s];
        if op as u8 != Operation::GrantSetSecret as u8 {
            let mut q = 0;
            while q < purposes.len() {
                assert!(!purpose_permitted(op, HandleSlot::Secondary, purposes[q]));
                q += 1;
            }
        }
        s += 1;
    }
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
        HandleSlot::ArmoredAsServer,
        KeyPurpose::Service
    ));
    // R2 (docs/52 §3.2, §5 item 3; docs/questions/Q-463, A-102): the admin
    // service's key set opens only with an operation digest and the LDAP
    // service's only unbound — the binding, not the caller, names the
    // purpose (`AppBinding::key_purpose`), and each row is fixed here.
    // Q-523: each binding is its own operation (`AppBinding::operation`),
    // which permits exactly the binding's purpose and no other.
    let bound = AppBinding::OperationDigest(OperationDigest::new([0; OPERATION_DIGEST_LEN]));
    assert!(matches!(
        AppBinding::Unbound.key_purpose(),
        KeyPurpose::Service
    ));
    assert!(matches!(bound.key_purpose(), KeyPurpose::AdminService));
    assert!(matches!(
        AppBinding::ChangePassword.key_purpose(),
        KeyPurpose::ChangePasswordService
    ));
    assert!(AppBinding::Unbound.operation() as u8 == Operation::OpenAndVerifyServiceTicket as u8);
    assert!(bound.operation() as u8 == Operation::VerifyOperationTicket as u8);
    assert!(
        AppBinding::ChangePassword.operation() as u8 == Operation::OpenChangePasswordRequest as u8
    );
    let bindings = [AppBinding::Unbound, bound, AppBinding::ChangePassword];
    let mut b = 0;
    while b < bindings.len() {
        let op = bindings[b].operation();
        let mut q = 0;
        while q < purposes.len() {
            let own = purposes[q] as u8 == bindings[b].key_purpose() as u8;
            assert!(purpose_permitted(op, HandleSlot::Primary, purposes[q]) == own);
            q += 1;
        }
        b += 1;
    }
    assert!(!purpose_permitted(
        Operation::OpenAndVerifyServiceTicket,
        HandleSlot::Primary,
        KeyPurpose::AdminService
    ));
    assert!(!purpose_permitted(
        Operation::VerifyOperationTicket,
        HandleSlot::Primary,
        KeyPurpose::Service
    ));
    // The KDC seals the admin service's tickets under its own key set.
    assert!(purpose_permitted(
        Operation::IssueTgsRep,
        HandleSlot::Primary,
        KeyPurpose::AdminService
    ));
    // The admin service key is never password-derived, never granted and
    // never destroyed by a decision: no `set_secret` (Role::Directory) can
    // replace the key admin tickets are verified under (A-50 / Q-180 item 4
    // as a purpose).
    assert!(!purpose_permitted(
        Operation::SetSecret,
        HandleSlot::Primary,
        KeyPurpose::AdminService
    ));
    assert!(!purpose_permitted(
        Operation::VerifySecret,
        HandleSlot::Primary,
        KeyPurpose::AdminService
    ));
    assert!(!purpose_permitted(
        Operation::GrantSetSecret,
        HandleSlot::Primary,
        KeyPurpose::AdminService
    ));
    assert!(!purpose_permitted(
        Operation::GrantSetSecret,
        HandleSlot::Secondary,
        KeyPurpose::AdminService
    ));
    assert!(!purpose_permitted(
        Operation::DestroyKeySet,
        HandleSlot::Primary,
        KeyPurpose::AdminService
    ));
    // Nothing of the AS opens it.
    assert!(!purpose_permitted(
        Operation::VerifyPreauth,
        HandleSlot::Primary,
        KeyPurpose::AdminService
    ));
    assert!(!purpose_permitted(
        Operation::OpenAndVerifyTgt,
        HandleSlot::Primary,
        KeyPurpose::AdminService
    ));
    // Task K3 (docs/53 §4.5, R53-6; Q-601 item 4, A-117): the change-password
    // service's key set is drawn by keyd (`create_key`) and may have a
    // retired kvno named (`retire_kvno`, any purpose) — and is opened **only**
    // by `open_change_password_request`. Task K3b (docs/53 §5.2; Q-915 items
    // 1, 3, A-151): its tickets are sealed only by `issue_as_rep`, only in
    // the ARMORED server slot. Task F3 (A-126, Q-660 item 11): its key set
    // is rotated by `rotate_key` — on a dird decision only (pinned next).
    // No other operation accepts it in any slot: not `set_secret` /
    // `verify_secret` / a grant / `destroy_key_set` (never password-derived,
    // never replaced by a caller's secret), not the TGS issuance or the TGT
    // / armor steps (the TGS refuses the name), not the unarmored AS
    // (A-142), not the two other service-ticket verifications.
    let mut x = 0;
    while x < Operation::ALL.len() {
        let op = Operation::ALL[x];
        let opens_it = op as u8 == Operation::OpenChangePasswordRequest as u8
            || op as u8 == Operation::CreateKey as u8
            || op as u8 == Operation::RetireKvno as u8
            || op as u8 == Operation::RotateKey as u8;
        let issues_it = op as u8 == Operation::IssueAsRep as u8;
        assert!(
            purpose_permitted(op, HandleSlot::Primary, KeyPurpose::ChangePasswordService)
                == opens_it
        );
        assert!(!purpose_permitted(
            op,
            HandleSlot::AsServer,
            KeyPurpose::ChangePasswordService
        ));
        assert!(
            purpose_permitted(
                op,
                HandleSlot::ArmoredAsServer,
                KeyPurpose::ChangePasswordService
            ) == issues_it
        );
        assert!(!purpose_permitted(
            op,
            HandleSlot::Secondary,
            KeyPurpose::ChangePasswordService
        ));
        // Task F3 (A-126): every operation that changes the change-password
        // service's key state runs on a dird decision, or exists only in the
        // ceremony (`create_key`) — whoever may call it. So the rotation slot
        // is open to it **only with a decision**.
        if purpose_permitted(op, HandleSlot::Primary, KeyPurpose::ChangePasswordService)
            && changes_key_state(op)
        {
            assert!(requires_decision(op) || provisioning_only(op));
        }
        x += 1;
    }
    // The revocation (task F3) names a decision id, no key set: no purpose
    // in any slot.
    let mut rp = 0;
    while rp < purposes.len() {
        assert!(!purpose_permitted(
            Operation::RevokeDecision,
            HandleSlot::Primary,
            purposes[rp]
        ));
        assert!(!purpose_permitted(
            Operation::RevokeDecision,
            HandleSlot::Secondary,
            purposes[rp]
        ));
        assert!(!purpose_permitted(
            Operation::RevokeDecision,
            HandleSlot::AsServer,
            purposes[rp]
        ));
        assert!(!purpose_permitted(
            Operation::RevokeDecision,
            HandleSlot::ArmoredAsServer,
            purposes[rp]
        ));
        rp += 1;
    }
    // The rotation of the change-password service's key set (task F3,
    // A-126): Role::Admin's `rotate_key` only, by decision id, never before
    // the seal only, never held, never by Ldap / Directory / the KDC.
    assert!(purpose_permitted(
        Operation::RotateKey,
        HandleSlot::Primary,
        KeyPurpose::ChangePasswordService
    ));
    assert!(requires_decision(Operation::RotateKey));
    assert!(!provisioning_only(Operation::RotateKey));
    assert!(role_permits(Role::Admin, Operation::RotateKey));
    assert!(!role_permits(Role::Ldap, Operation::RotateKey));
    assert!(!role_permits(Role::Directory, Operation::RotateKey));
    assert!(!role_permits(Role::Kdc, Operation::RotateKey));
    assert!(!purpose_permitted(
        Operation::RotateKrbtgt,
        HandleSlot::Primary,
        KeyPurpose::ChangePasswordService
    ));
    // Task K3b (docs/53 §5.2: "`server: KeyHandle` that is Krbtgt **or**
    // ChangePasswordService — no other purpose"; Q-915 items 1, 3, A-151;
    // A-142): the server slot of `issue_as_rep` is closed. Only
    // `issue_as_rep` has server slots; its unarmored slot takes exactly
    // Krbtgt, its armored slot exactly Krbtgt and ChangePasswordService —
    // both exactly the classification `AsServer::of` — and keyd picks the
    // slot from the armor with `as_server_slot`.
    assert!(as_server_slot(false) as u8 == HandleSlot::AsServer as u8);
    assert!(as_server_slot(true) as u8 == HandleSlot::ArmoredAsServer as u8);
    let mut v = 0;
    while v < Operation::ALL.len() {
        let op = Operation::ALL[v];
        let mut q = 0;
        while q < purposes.len() {
            let purpose = purposes[q];
            if op as u8 == Operation::IssueAsRep as u8 {
                let tgt = purpose as u8 == KeyPurpose::Krbtgt as u8;
                let change_password = purpose as u8 == KeyPurpose::ChangePasswordService as u8;
                assert!(purpose_permitted(op, HandleSlot::AsServer, purpose) == tgt);
                assert!(
                    purpose_permitted(op, HandleSlot::ArmoredAsServer, purpose)
                        == (tgt || change_password)
                );
                assert!(
                    purpose_permitted(op, HandleSlot::AsServer, purpose)
                        == AsServer::of(purpose, false).is_some()
                );
                assert!(
                    purpose_permitted(op, HandleSlot::ArmoredAsServer, purpose)
                        == AsServer::of(purpose, true).is_some()
                );
            } else {
                assert!(!purpose_permitted(op, HandleSlot::AsServer, purpose));
                assert!(!purpose_permitted(op, HandleSlot::ArmoredAsServer, purpose));
            }
            q += 1;
        }
        v += 1;
    }
    // The classification itself: each server names the purpose it came from,
    // and only the change-password service requires the armor — so it is
    // never a server of an unarmored issuance.
    let mut w = 0;
    while w < purposes.len() {
        let purpose = purposes[w];
        if let Some(server) = AsServer::of(purpose, true) {
            assert!(server.key_purpose() as u8 == purpose as u8);
        }
        if let Some(server) = AsServer::of(purpose, false) {
            assert!(server.key_purpose() as u8 == purpose as u8);
            assert!(!server.requires_armor());
        }
        w += 1;
    }
    assert!(AsServer::ChangePasswordService.requires_armor());
    assert!(!AsServer::LocalTgt.requires_armor());
    assert!(AsServer::of(KeyPurpose::ChangePasswordService, false).is_none());
    // ... and `open_change_password_request` opens nothing else.
    let mut y = 0;
    while y < purposes.len() {
        let own = purposes[y] as u8 == KeyPurpose::ChangePasswordService as u8;
        assert!(
            purpose_permitted(
                Operation::OpenChangePasswordRequest,
                HandleSlot::Primary,
                purposes[y]
            ) == own
        );
        // The completion targets a user's password key set only; the error
        // seal takes no handle.
        assert!(
            purpose_permitted(
                Operation::CompleteChangePassword,
                HandleSlot::Primary,
                purposes[y]
            ) == (purposes[y] as u8 == KeyPurpose::PrincipalLongterm as u8)
        );
        assert!(!purpose_permitted(
            Operation::SealChangePasswordError,
            HandleSlot::Primary,
            purposes[y]
        ));
        y += 1;
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    const ROLES: [Role; 4] = [Role::Kdc, Role::Directory, Role::Admin, Role::Ldap];

    /// Every key operation is granted to exactly one role (docs/10 §2: each
    /// process holds only its own operations); the two daemon-support
    /// operations, which touch no key, are shared as docs/50 §3.4 lists:
    /// `DescribeConfig` — Kdc and Ldap; `Ping` — every mapped role. The
    /// set_secret grant, which touches no key either, is registered by
    /// dird after its PDP (Ldap) and by keyadm's ceremony for the first
    /// administrators (Admin) — docs/51 §5.8 option (b), Q-450 items 1, 6;
    /// since A-102 the grant is Admin's alone and dird registers decisions
    /// (`RegisterDecision`, Ldap alone). `VerifySecret` has **no** role
    /// (docs/52 R4, Q-465). The destroy listing, which reads decisions and
    /// touches no key, is keyadm's (Admin) and — task R6, Q-503 — dird's
    /// (Ldap), which reads back what it registered.
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
                Operation::VerifySecret => assert!(roles.is_empty()),
                Operation::ListDestroyDecisions => assert_eq!(roles, [Role::Admin, Role::Ldap]),
                _ => assert_eq!(roles.len(), 1, "{op:?}"),
            }
        }
    }

    /// RFC 4120 3.2.3 / docs/50 R50-6, §3.5: exactly the operations of the
    /// Kerberos exchanges (roles Kdc and Ldap, except the daemon-support
    /// operations — Q-240 item 1 — and the decision registration and its
    /// listing — Q-450 item 5, A-102, task R6 — and the revocation — task
    /// F3) are held after start — the three change-password operations
    /// included (docs/53 §5.3, task K3).
    #[test]
    fn hold_down_covers_exactly_the_kerberos_operations() {
        for op in Operation::ALL {
            let kerberos = (role_permits(Role::Kdc, op) || role_permits(Role::Ldap, op))
                && !matches!(
                    op,
                    Operation::DescribeConfig
                        | Operation::Ping
                        | Operation::RegisterDecision
                        | Operation::ListDestroyDecisions
                        | Operation::RevokeDecision
                );
            assert_eq!(startup_hold_down_applies(op), kerberos, "{op:?}");
        }
    }
}
