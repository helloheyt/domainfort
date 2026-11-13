//! What a successful operation answers.
//!
//! Spec: docs/51 §7.3 (the reply column: `GUID, SID` for a create; `kind,
//! handles (1 or 2), bindings, salt` for `BeginPasswordSet`; `()`; `GUID,
//! DN, class, SID | NotFound` for `Lookup`).

use directory_pip::AccountKind;
use dtyp::{Guid, Sid};
use keyd_types::{KeyHandle, PrincipalBinding};
use krb_proto::KerberosString;
use pdp::Dn;

/// One key set admind passes to keyd `set_secret`: its handle and the
/// principal name it is bound to.
/// Spec: docs/47 §9.1 (the table: key set, binding); docs/10 §1 as cited
/// there; A-19 (the binding is fixed when the key set is created).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTarget {
    /// `(objectGUID, purpose)`.
    pub handle: KeyHandle,
    /// The realm and principal name the key set is bound to.
    pub binding: PrincipalBinding,
}

/// The `BeginPasswordSet` reply: what admind needs for keyd `set_secret` —
/// the account kind, one key set for a user (`PrincipalLongterm`), two for
/// a computer that has its SPN (`PrincipalLongterm` and `Service`, the same
/// password and the same salt), and the salt.
/// Spec: docs/51 §5.2 row 5, §7.3; docs/47 §9.1, §3.3 (R47-4: the salt from
/// `account_salt`, the same function the account source uses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSetReply {
    /// User or computer.
    pub kind: AccountKind,
    /// The key sets, `PrincipalLongterm` first.
    pub keys: Vec<KeyTarget>,
    /// The key salt ([MS-KILE] 3.1.1.2 via `directory_pip::account_salt`).
    pub salt: KerberosString,
}

/// The `Lookup` reply: only identifiers (docs/51 §5.2 row 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupResult {
    /// The objectGUID.
    pub guid: Guid,
    /// The DN in the directory's canonical form.
    pub dn: Dn,
    /// The lDAPDisplayName of the most specific class.
    pub class: &'static str,
    /// The objectSid, for a security principal (or the NC root).
    pub sid: Option<Sid>,
}

/// The reply of a successful operation. Spec: docs/51 §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A create: the new objectGUID and, for a security principal, its
    /// objectSid.
    Created {
        /// The objectGUID.
        guid: Guid,
        /// The objectSid (user, computer, group).
        sid: Option<Sid>,
    },
    /// `BeginPasswordSet`.
    PasswordSet(PasswordSetReply),
    /// `CompletePasswordSet`, `SetEnabled`, `SetAccountExpires`,
    /// `AddMember`, `RemoveMember`, `Delete`.
    Done,
    /// `Lookup` of a visible object.
    Found(LookupResult),
}
