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

/// What a committed `ChangePassword` hands dird for keyd (task K6): the
/// user's one key set (`(objectGUID, PrincipalLongterm)` bound to
/// NT-PRINCIPAL [sAMAccountName]) and its salt — exactly what dird's
/// `ChangePassword` decision names (`DecidedOperation::ChangePassword
/// { target }`, docs/questions/Q-662) and keyd's `complete_change_password`
/// installs into. Derived by the same `password_targets` as a
/// [`PasswordSetReply`]; never handed to admind (dird keeps it).
/// Spec: docs/53 §4.4 (R53-5), §5.6 steps 5-6; docs/47 §9.1, §3.3 (R47-4);
/// A-126.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordChangeTarget {
    /// The user's password key set and its binding.
    pub key: KeyTarget,
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
    /// `ChangePassword` (task K6; on `dird-kpasswd.sock`, never on the admin
    /// channel).
    PasswordChange(PasswordChangeTarget),
    /// `CompletePasswordSet`, `SetEnabled`, `SetAccountExpires`,
    /// `AddMember`, `RemoveMember`, `Delete`.
    Done,
    /// `Lookup` of a visible object.
    Found(LookupResult),
}
