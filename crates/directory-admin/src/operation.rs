//! The closed operation set: the `dird-admin.sock` requests of docs/51 §7.3
//! that act on the directory, each with exactly the fields that table
//! lists. There is no generic "write an attribute" request (docs/43 §2 and
//! D98 as cited in docs/51 §5.1: no do-everything endpoint, no
//! mass-assignment).
//!
//! Every object an existing-object request names is named by its
//! objectGUID: a member is therefore always an object of this directory —
//! a SID-only member cannot even be expressed (A-79; [MS-SAMR] 3.1.1.8.9
//! item 1: phase 1 has no foreignSecurityPrincipal).
//!
//! The authentication fields (`auth := requester ‖ approvals`, docs/51
//! §7.2) are not here: the caller verifies each AP-REQ through keyd and
//! passes the verified facts ([`crate::VerifiedTicket`]).
//!
//! Spec: docs/51 §5.2, §7.3; A-18, A-19, A-35 (no rename, no move, no
//! sAMAccountName change); A-79.

use dtyp::Guid;
use ipc_audit::{AccountExpiresValue, DirAdminOperation};
use pdp::Dn;

/// `CreateUser {parent, sam, upn?, description?}`. Spec: docs/51 §5.2 row
/// 1, §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUser {
    /// The container (objectGUID).
    pub parent: Guid,
    /// The sAMAccountName (also the cn).
    pub sam: String,
    /// The userPrincipalName, if any.
    pub upn: Option<String>,
    /// The description, if any. Never recorded in an audit event (A-85).
    pub description: Option<String>,
}

/// `CreateComputer {parent, name, dns_host_name, spn?}`. Spec: docs/51 §5.2
/// row 2, §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateComputer {
    /// The container (objectGUID).
    pub parent: Guid,
    /// The computer name, without the trailing "$" (the sAMAccountName is
    /// `name ‖ "$"`; the cn is `name`).
    pub name: String,
    /// The dNSHostName.
    pub dns_host_name: String,
    /// The single servicePrincipalName, if any.
    pub spn: Option<String>,
}

/// `CreateGroup {parent, sam, group_type}`; an absent group type is the
/// default GROUP_TYPE_SECURITY_ACCOUNT. Spec: docs/51 §5.2 row 3, §7.3;
/// [MS-SAMR] 3.1.1.8.1 item 2.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateGroup {
    /// The container (objectGUID).
    pub parent: Guid,
    /// The sAMAccountName (also the cn).
    pub sam: String,
    /// The groupType bit pattern, if the request names one.
    pub group_type: Option<u32>,
}

/// `CreateOu` / `CreateContainer {parent, name}`. Spec: docs/51 §5.2 row 4,
/// §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateContainerLike {
    /// The parent (objectGUID).
    pub parent: Guid,
    /// The RDN value (`ou` or `cn`).
    pub name: String,
}

/// How the keyd steps of a password set ended, as admind reports it.
/// Spec: docs/51 §7.3 (`CompletePasswordSet {target, outcome, kvnos}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasswordSetOutcome {
    /// Every `set_secret` succeeded.
    Completed,
    /// A `set_secret` failed.
    Failed,
}

/// `CompletePasswordSet {target, outcome, kvnos}` — audit only, no state.
/// Spec: docs/51 §7.3, §9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletePasswordSet {
    /// The account (objectGUID).
    pub target: Guid,
    /// The outcome admind reports.
    pub outcome: PasswordSetOutcome,
    /// The key versions keyd chose, in call order (at most two).
    pub kvnos: Vec<u32>,
}

/// `SetEnabled {target, value}`. Spec: docs/51 §5.2 row 6, §7.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetEnabled {
    /// The account (objectGUID).
    pub target: Guid,
    /// `true`: clear UF_ACCOUNTDISABLE; `false`: set it.
    pub enabled: bool,
}

/// `SetAccountExpires {target, never | filetime}`. Spec: docs/51 §5.2 row
/// 7, §7.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetAccountExpires {
    /// The account (objectGUID).
    pub target: Guid,
    /// "Never", or the FILETIME. The same type the audit event records.
    pub value: AccountExpiresValue,
}

/// `AddMember` / `RemoveMember {group, member}`. Spec: docs/51 §5.2 row 8,
/// §7.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Membership {
    /// The group (objectGUID).
    pub group: Guid,
    /// The member (objectGUID).
    pub member: Guid,
}

/// The key of a `Lookup`. Spec: docs/51 §5.2 row 10, §7.3 (`sam | spn |
/// dn`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupKey {
    /// A sAMAccountName, compared octet for octet after the index lookup.
    SamAccountName(String),
    /// A servicePrincipalName, compared octet for octet.
    ServicePrincipalName(String),
    /// A DN as RDN components `att=value`, leaf first (resolved like an
    /// LDAP client's DN, `DirectoryView::lookup_dn`).
    Dn(Dn),
}

/// One admin operation on the directory. Spec: docs/51 §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// docs/51 §5.2 row 1.
    CreateUser(CreateUser),
    /// docs/51 §5.2 row 2.
    CreateComputer(CreateComputer),
    /// docs/51 §5.2 row 3.
    CreateGroup(CreateGroup),
    /// docs/51 §5.2 row 4.
    CreateOu(CreateContainerLike),
    /// docs/51 §5.2 row 4.
    CreateContainer(CreateContainerLike),
    /// docs/51 §5.2 row 5: `pwdLastSet = now`, then the reply admind needs
    /// for keyd `set_secret`.
    BeginPasswordSet {
        /// The account (objectGUID).
        target: Guid,
    },
    /// docs/51 §7.3 (audit only).
    CompletePasswordSet(CompletePasswordSet),
    /// docs/51 §5.2 row 6.
    SetEnabled(SetEnabled),
    /// docs/51 §5.2 row 7.
    SetAccountExpires(SetAccountExpires),
    /// docs/51 §5.2 row 8.
    AddMember(Membership),
    /// docs/51 §5.2 row 8.
    RemoveMember(Membership),
    /// docs/51 §5.2 row 9 (tombstone, A-18).
    Delete {
        /// The object (objectGUID).
        target: Guid,
    },
    /// docs/51 §5.2 row 10.
    Lookup(LookupKey),
}

impl Operation {
    /// The audit code of the operation. Spec: crate ipc-audit
    /// `DirAdminOperation` (docs/51 §7.3 order).
    #[must_use]
    pub fn code(&self) -> DirAdminOperation {
        match self {
            Operation::CreateUser(_) => DirAdminOperation::CreateUser,
            Operation::CreateComputer(_) => DirAdminOperation::CreateComputer,
            Operation::CreateGroup(_) => DirAdminOperation::CreateGroup,
            Operation::CreateOu(_) => DirAdminOperation::CreateOu,
            Operation::CreateContainer(_) => DirAdminOperation::CreateContainer,
            Operation::BeginPasswordSet { .. } => DirAdminOperation::BeginPasswordSet,
            Operation::CompletePasswordSet(_) => DirAdminOperation::CompletePasswordSet,
            Operation::SetEnabled(_) => DirAdminOperation::SetEnabled,
            Operation::SetAccountExpires(_) => DirAdminOperation::SetAccountExpires,
            Operation::AddMember(_) => DirAdminOperation::AddMember,
            Operation::RemoveMember(_) => DirAdminOperation::RemoveMember,
            Operation::Delete { .. } => DirAdminOperation::Delete,
            Operation::Lookup(_) => DirAdminOperation::Lookup,
        }
    }

    /// `true` for the operations that **require an effect plan** (task MA2;
    /// docs/questions/Q-982): their effect reaches beyond their direct
    /// target — a membership change (transitive), an account's enable,
    /// expiry, delete or password set (its tickets; a delete's memberships
    /// and key sets). Decided by the kind alone, never by the target's state
    /// (the requirement itself cannot change between plan and commit). Such
    /// an operation is decided only with the digest of the plan it commits
    /// to (`Request::plan`); the creates, `Lookup` and `CompletePasswordSet`
    /// take none.
    /// Spec: docs/research/r5-a-admin-model.md §3.3, §8.2; docs/questions/
    /// Q-982; crate ipc-dird-admin `request_kind::PLANNED`.
    #[must_use]
    pub fn requires_plan(&self) -> bool {
        matches!(
            self,
            Operation::BeginPasswordSet { .. }
                | Operation::SetEnabled(_)
                | Operation::SetAccountExpires(_)
                | Operation::AddMember(_)
                | Operation::RemoveMember(_)
                | Operation::Delete { .. }
        )
    }

    /// `true` for the operations that commit a directory write (they get a
    /// `Decision` event acknowledged before the commit and an `Outcome`
    /// event after it); `Lookup` and `CompletePasswordSet` commit nothing
    /// and have their `Decision` event only.
    /// Spec: docs/51 §5.7 item 2; Q-340 item 1 (as recorded in crate
    /// ipc-audit admin.rs).
    #[must_use]
    pub fn writes(&self) -> bool {
        !matches!(
            self,
            Operation::Lookup(_) | Operation::CompletePasswordSet(_)
        )
    }
}
