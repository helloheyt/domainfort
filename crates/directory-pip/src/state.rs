//! Account state from the directory (docs/47 §4; R47-5, R47-6, R47-7).
//!
//! `AccountState { enabled, locked, expires, revoked_before }` is the KDC's
//! record (kdc `accounts.rs`); the KDC checks `usable_at` before
//! pre-authentication and at every TGS, and `revokes(authtime)` at every
//! TGS (Q-070 items 8, 9).
//!
//! Spec: docs/47 §4.1-§4.5; [MS-ADTS] 2.2.16, 3.1.1.4.5.17; [MS-KILE]
//! 3.3.1.1, 3.3.5.6.3; [MS-SAMR] 2.2.6.1, 3.1.1.6 (items 11, 20, 23, 24),
//! 3.1.1.8.1, 3.1.5.14.4; [MS-DTYP] 2.3.3; [MS-DRSR] 5.51; RFC 4120
//! 3.3.3.1.

use crate::error::Fault;
use crate::salt::AccountKind;
use crate::time::{filetime_ceil, filetime_floor, from_seconds, since_1601};
use ad_schema::flags::user_account_control::{
    ADS_UF_ACCOUNT_DISABLE, ADS_UF_DONT_EXPIRE_PASSWD, ADS_UF_INTERDOMAIN_TRUST_ACCOUNT,
    ADS_UF_NORMAL_ACCOUNT, ADS_UF_PASSWORD_EXPIRED, ADS_UF_SERVER_TRUST_ACCOUNT,
    ADS_UF_SMARTCARD_REQUIRED, ADS_UF_WORKSTATION_TRUST_ACCOUNT, ALLOWED,
};
use kdc::AccountState;
use keyd::kerberos_time_seconds;
use krb_proto::KerberosTime;

/// The account-type bits of userAccountControl, of which exactly one is
/// set. Spec: [MS-SAMR] 3.1.1.6 item 20 ("MUST contain one and only one of
/// the following bits": UF_NORMAL_ACCOUNT, UF_INTERDOMAIN_TRUST_ACCOUNT,
/// UF_WORKSTATION_TRUST_ACCOUNT, UF_SERVER_TRUST_ACCOUNT); [MS-ADTS] 2.2.16.
const ACCOUNT_TYPE_BITS: u32 = ADS_UF_NORMAL_ACCOUNT
    | ADS_UF_INTERDOMAIN_TRUST_ACCOUNT
    | ADS_UF_WORKSTATION_TRUST_ACCOUNT
    | ADS_UF_SERVER_TRUST_ACCOUNT;

/// accountExpires "never": the value written when an account is created
/// without one, "0x7FFFFFFF FFFFFFFF (default value)". Spec: [MS-SAMR]
/// 3.1.1.8.1; docs/47 §4.2.
pub(crate) const ACCOUNT_EXPIRES_NEVER: i64 = i64::MAX;

/// The trailing character of a workstation account name. Spec: [MS-SAMR]
/// 3.1.1.6 item 11 ("sAMAccountName MUST end with a single '$' ... if the
/// object's UserAccountControl attribute contains ...
/// UF_WORKSTATION_TRUST_ACCOUNT").
const WORKSTATION_SUFFIX: char = '$';

/// The userAccountControl of an account, checked for consistency with its
/// class. `Ok(None)` if the attribute is absent.
///
/// - a bit phase 1 refuses on write (R46-6 — outside
///   `user_account_control::ALLOWED`) present on read is an inconsistent
///   record (P-7): `Err`;
/// - user ⇒ exactly N among the account-type bits; computer ⇒ exactly one
///   of WT / ST ([MS-SAMR] 3.1.1.6 items 20, 23, 24); anything else is
///   `Err` (docs/47 §4.1, R47-5a; Q-070 item 10);
/// - a WT computer whose sAMAccountName does not end with "$" breaks
///   [MS-SAMR] 3.1.1.6 item 11: `Err` (a stricter reading recorded in
///   Q-136 item 2).
///
/// Spec: docs/47 §4.1 (R47-5a); [MS-ADTS] 2.2.16; [MS-SAMR] 3.1.1.6;
/// Q-136.
pub(crate) fn checked_uac(
    kind: AccountKind,
    uac: Option<u32>,
    sam_account_name: &str,
) -> Result<Option<u32>, Fault> {
    let Some(uac) = uac else {
        return Ok(None);
    };
    if uac & !ALLOWED != 0 {
        return Err(Fault::Unavailable);
    }
    let account_type = uac & ACCOUNT_TYPE_BITS;
    let consistent = match kind {
        AccountKind::User => account_type == ADS_UF_NORMAL_ACCOUNT,
        AccountKind::Computer => {
            account_type == ADS_UF_WORKSTATION_TRUST_ACCOUNT
                || account_type == ADS_UF_SERVER_TRUST_ACCOUNT
        }
    };
    if !consistent {
        return Err(Fault::Unavailable);
    }
    if account_type == ADS_UF_WORKSTATION_TRUST_ACCOUNT
        && !sam_account_name.ends_with(WORKSTATION_SUFFIX)
    {
        return Err(Fault::Unavailable);
    }
    Ok(Some(uac))
}

/// `true` if the checked userAccountControl marks a DC's computer account
/// (ST: "a computer account for a DC"). Spec: [MS-ADTS] 2.2.16; docs/47
/// §6.3 (ST ⇒ Tier0).
pub(crate) fn is_dc_account(uac: Option<u32>) -> bool {
    uac.is_some_and(|u| u & ADS_UF_SERVER_TRUST_ACCOUNT != 0)
}

/// `enabled` (docs/47 §4.1, §4.3; R47-5a, R47-5c), from a userAccountControl
/// already checked by [`checked_uac`]:
///
/// - absent ⇒ `false` (UAC is a may, docs/46 §4.4 — fail closed);
/// - D ("the account is not enabled for authentication", [MS-ADTS] 2.2.16;
///   [MS-KILE] 3.3.1.1 Disabled) ⇒ `false`;
/// - SR (smart card required): password logon gets
///   STATUS_SMARTCARD_LOGON_REQUIRED ([MS-KILE] 3.3.5.6.3) and phase 1 has
///   no PKINIT ⇒ `false`;
/// - PE: [MS-KILE] 3.3.1.1 — "Expired: ... use the userAccountControl
///   attribute PE flag" — and 3.3.5.6.3: "If Expired is TRUE, then the KDC
///   MUST return KDC_ERR_CLIENT_REVOKED" ⇒ `false` (Q-136 item 1);
/// - a user (N) with neither DP nor SR whose pwdLastSet is absent or 0 has
///   an expired password ([MS-ADTS] 3.1.1.4.5.17 PE; [MS-SAMR] 3.1.5.14.4
///   PasswordMustChange = 0) ⇒ `false`, folded into the uniform
///   KDC_ERR_CLIENT_REVOKED (docs/47 §4.3). Computers are exempt (WT / ST
///   are in the same exemption lists).
///
/// Spec: docs/47 §4.1, §4.3; [MS-ADTS] 2.2.16, 3.1.1.4.5.17; [MS-KILE]
/// 3.3.1.1, 3.3.5.6.3; [MS-SAMR] 3.1.5.14.4.
pub(crate) fn enabled(kind: AccountKind, uac: Option<u32>, pwd_last_set: Option<i64>) -> bool {
    let Some(uac) = uac else {
        return false;
    };
    if uac & (ADS_UF_ACCOUNT_DISABLE | ADS_UF_SMARTCARD_REQUIRED | ADS_UF_PASSWORD_EXPIRED) != 0 {
        return false;
    }
    let exempt = uac & (ADS_UF_DONT_EXPIRE_PASSWD | ADS_UF_SMARTCARD_REQUIRED) != 0;
    if kind == AccountKind::User && !exempt && pwd_last_set.unwrap_or(0) == 0 {
        return false;
    }
    true
}

/// `expires` from accountExpires (docs/47 §4.2, R47-5b; Q-113 / A-37):
///
/// - absent or `0x7FFFFFFF FFFFFFFF` ⇒ `None` (never; [MS-SAMR] 3.1.1.8.1);
/// - otherwise the FILETIME ("the time at which an account is no longer
///   permitted to log on", [MS-SAMR] 2.2.6.1; [MS-DTYP] 2.3.3) rounded down
///   to the second. **`0` is 1601-01-01T00:00:00Z: expired** — the literal
///   reading, fail closed (Q-113, A-37);
/// - a negative value, or one after 9999-12-31T23:59:59Z, is `Err`.
///
/// Spec: [MS-SAMR] 2.2.6.1, 3.1.1.8.1; [MS-DTYP] 2.3.3; docs/47 §4.2.
pub(crate) fn expires(account_expires: Option<i64>) -> Result<Option<KerberosTime>, Fault> {
    match account_expires {
        None | Some(ACCOUNT_EXPIRES_NEVER) => Ok(None),
        Some(ticks) => filetime_floor(ticks).map(Some).ok_or(Fault::Unavailable),
    }
}

/// `revoked_before` (docs/47 §4.5, R47-7):
/// `max(whenCreated + 1 s, ceil_s(pwdLastSet))`, pwdLastSet absent or 0 not
/// counted.
///
/// - whenCreated (DSTIME, [MS-DRSR] 5.51) revokes every TGT issued before
///   the current account existed — every TGT of a former holder of the name
///   (RFC 4120 §6.2 "stale entries"; A-18: a delete frees the name). `+1 s`
///   because authtime and DSTIME are whole seconds.
/// - pwdLastSet (FILETIME, [MS-DTYP] 2.3.3) revokes TGTs older than the last
///   password set, rounded UP to the second for the same reason.
/// - whenCreated is set by the system on create (docs/46 §5.4, systemOnly);
///   an account without it is an inconsistent record: `Err` (fail closed —
///   without it a reused name could inherit an older account's TGTs;
///   Q-136 item 3).
///
/// Spec: RFC 4120 3.3.3.1 (the hot-list: "a range of issue timestamps"),
/// §6.2; [MS-DRSR] 5.51; [MS-DTYP] 2.3.3; docs/47 §4.5 (R47-7); A-27.
pub(crate) fn revoked_before(
    when_created: Option<i64>,
    pwd_last_set: Option<i64>,
) -> Result<KerberosTime, Fault> {
    let created = when_created.ok_or(Fault::Unavailable)?;
    let after_creation = created
        .checked_add(1)
        .and_then(since_1601)
        .ok_or(Fault::Unavailable)?;
    let mut cut = kerberos_time_seconds(&after_creation);
    match pwd_last_set {
        None | Some(0) => {}
        Some(ticks) => {
            let set = filetime_ceil(ticks).ok_or(Fault::Unavailable)?;
            cut = cut.max(kerberos_time_seconds(&set));
        }
    }
    from_seconds(cut).ok_or(Fault::Unavailable)
}

/// The whole account state. `locked` is always `false`: phase 1 keeps no
/// lockoutTime and the L bit is refused on write (docs/47 §4.4, R47-6; the
/// online-guessing limit is keyd's, A-34).
///
/// Spec: docs/47 §4 (R47-5, R47-6, R47-7).
pub(crate) fn account_state(
    kind: AccountKind,
    uac: Option<u32>,
    account_expires: Option<i64>,
    pwd_last_set: Option<i64>,
    when_created: Option<i64>,
) -> Result<AccountState, Fault> {
    if pwd_last_set.is_some_and(|p| p < 0) {
        return Err(Fault::Unavailable);
    }
    Ok(AccountState {
        enabled: enabled(kind, uac, pwd_last_set),
        locked: false,
        expires: expires(account_expires)?,
        revoked_before: Some(revoked_before(when_created, pwd_last_set)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: u32 = ADS_UF_NORMAL_ACCOUNT;
    const WT: u32 = ADS_UF_WORKSTATION_TRUST_ACCOUNT;
    const ST: u32 = ADS_UF_SERVER_TRUST_ACCOUNT;

    /// [MS-SAMR] 3.1.1.6 items 11, 20, 23, 24; R46-6 (refused bits);
    /// docs/47 §4.1.
    #[test]
    fn uac_consistency() {
        use AccountKind::{Computer, User};
        assert_eq!(checked_uac(User, None, "a"), Ok(None));
        assert_eq!(checked_uac(User, Some(N), "a"), Ok(Some(N)));
        assert_eq!(checked_uac(Computer, Some(WT), "a$"), Ok(Some(WT)));
        assert_eq!(checked_uac(Computer, Some(ST), "dc"), Ok(Some(ST)));
        for (kind, uac, name) in [
            (User, WT, "a$"),
            (User, ST, "a"),
            (User, 0, "a"),
            (User, N | WT, "a$"),
            (Computer, N, "a$"),
            (Computer, WT | ST, "a$"),
            (Computer, 0, "a$"),
            // WT without the trailing "$" (item 11).
            (Computer, WT, "a"),
            // A refused bit (R46-6): DR, "no preauthentication".
            (User, N | 0x0040_0000, "a"),
            // An unused bit.
            (User, N | 0x0000_0001, "a"),
        ] {
            assert_eq!(
                checked_uac(kind, Some(uac), name),
                Err(Fault::Unavailable),
                "{kind:?} {uac:#x} {name}"
            );
        }
    }

    /// docs/47 §4.1, §4.3 (R47-5a, R47-5c).
    #[test]
    fn enabled_rules() {
        use AccountKind::{Computer, User};
        let set = Some(1);
        assert!(enabled(User, Some(N), set));
        assert!(!enabled(User, None, set));
        assert!(!enabled(User, Some(N | ADS_UF_ACCOUNT_DISABLE), set));
        assert!(!enabled(User, Some(N | ADS_UF_SMARTCARD_REQUIRED), set));
        assert!(!enabled(User, Some(N | ADS_UF_PASSWORD_EXPIRED), set));
        // pwdLastSet absent or 0: a user must change the password.
        assert!(!enabled(User, Some(N), None));
        assert!(!enabled(User, Some(N), Some(0)));
        // ... unless DP ([MS-SAMR] 3.1.5.14.4 item 1).
        assert!(enabled(User, Some(N | ADS_UF_DONT_EXPIRE_PASSWD), Some(0)));
        // Computers are exempt.
        assert!(enabled(Computer, Some(WT), None));
        assert!(enabled(Computer, Some(ST), Some(0)));
    }
}
