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
use crate::time::{filetime_floor, from_seconds, since_1601};
use ad_schema::flags::user_account_control::{
    ADS_UF_ACCOUNT_DISABLE, ADS_UF_DONT_EXPIRE_PASSWD, ADS_UF_INTERDOMAIN_TRUST_ACCOUNT,
    ADS_UF_NORMAL_ACCOUNT, ADS_UF_PASSWORD_EXPIRED, ADS_UF_SERVER_TRUST_ACCOUNT,
    ADS_UF_SMARTCARD_REQUIRED, ADS_UF_WORKSTATION_TRUST_ACCOUNT, ALLOWED,
};
use kdc::AccountState;
use keyd_types::kerberos_time_seconds;
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

/// `revoked_before` (docs/47 §4.5, R47-7; Q-965 option (a), A-161):
/// `max(whenCreated + 1 s, floor_s(pwdLastSet) + 1 s)`, pwdLastSet absent or
/// 0 not counted. This is the one definition of the cut; the one comparison
/// is kdc `AccountState::revokes` (`authtime < revoked_before`), which every
/// revocation path uses (the KDC's AS and TGS, the LDAP bind, the write
/// PEP's `AdminSubject` — admin reset and kpasswd alike).
///
/// authtime is a whole second (KerberosTime has no fractional seconds,
/// RFC 4120 5.2.3), so `authtime < S + 1 s` ⇔ `authtime ≤ S`: an event in
/// second `S` revokes every ticket first authenticated **at or before** `S`.
///
/// - whenCreated (DSTIME, whole seconds, [MS-DRSR] 5.51) revokes every TGT
///   issued at or before the second the current account came to exist —
///   every TGT of a former holder of the name (RFC 4120 §6.2 "stale
///   entries"; A-18: a delete frees the name).
/// - pwdLastSet (FILETIME, 100-ns intervals, [MS-DTYP] 2.3.3) revokes every
///   ticket first authenticated at or before the second of the last
///   password set — including one authenticated in that very second, so a
///   ticket that made a change cannot make another (docs/53 R53-9; Q-965:
///   the earlier `ceil_s(pwdLastSet)` left a ticket of the same second
///   alive when pwdLastSet is a whole second, as dird writes it). The cost
///   — a ticket obtained in the same second **after** a set is revoked too
///   (the client authenticates again) — is the fail-closed side.
/// - whenCreated is set by the system on create (docs/46 §5.4, systemOnly);
///   an account without it is an inconsistent record: `Err` (fail closed —
///   without it a reused name could inherit an older account's TGTs;
///   Q-136 item 3).
///
/// Spec: RFC 4120 3.3.3.1 (the hot-list: "a range of issue timestamps"),
/// 5.2.3, §6.2; [MS-DRSR] 5.51; [MS-DTYP] 2.3.3; docs/47 §4.5 (R47-7);
/// A-27; Q-965 (a) / A-161.
pub(crate) fn revoked_before(
    when_created: Option<i64>,
    pwd_last_set: Option<i64>,
) -> Result<KerberosTime, Fault> {
    let created = when_created.ok_or(Fault::Unavailable)?;
    // The latest second the hot-list covers: whenCreated's, or the second
    // of the last password set if that is later.
    let created_second = since_1601(created).ok_or(Fault::Unavailable)?;
    let mut last_revoked = kerberos_time_seconds(&created_second);
    match pwd_last_set {
        None | Some(0) => {}
        Some(ticks) => {
            let set_second = filetime_floor(ticks).ok_or(Fault::Unavailable)?;
            last_revoked = last_revoked.max(kerberos_time_seconds(&set_second));
        }
    }
    // The cut is the second after it: `authtime < cut` ⇔ `authtime ≤
    // last_revoked` (RFC 4120 5.2.3: whole seconds).
    last_revoked
        .checked_add(1)
        .and_then(from_seconds)
        .ok_or(Fault::Unavailable)
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
    use crate::time::FILETIME_TICKS_PER_SECOND;

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

    fn kt(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
        KerberosTime::new(y, mo, d, h, mi, s).unwrap()
    }

    /// The account state with the rule's two inputs, through the one
    /// comparison (kdc `AccountState::revokes`).
    fn state(when_created: i64, pwd_last_set: Option<i64>) -> AccountState {
        account_state(
            AccountKind::User,
            Some(N),
            None,
            pwd_last_set,
            Some(when_created),
        )
        .unwrap()
    }

    /// Q-965 (a), A-161; docs/53 R53-9; docs/47 §4.5 (R47-7); RFC 4120
    /// 3.3.3.1, 5.2.3 (authtime in whole seconds): a password set at the
    /// whole second `S` — the form dird writes, `filetime(now)` — revokes a
    /// ticket first authenticated in `S` itself and every earlier one; a
    /// ticket of `S + 1 s` survives. A set within `S` (a fractional
    /// FILETIME) gives the same cut.
    ///
    /// Values (hand-derived on the calendar, as in crate::time's tests):
    /// `S` = 2026-11-13T10:00:00Z = 20 770 days after 1970-01-01 (20 758 to
    /// 2026-11-01, + 12) = 1 794 528 000 s, + 10 h = 1 794 564 000 s, +
    /// 11 644 473 600 s (1601 → 1970) = DSTIME 13 439 037 600; FILETIME =
    /// DSTIME × 10^7 ([MS-DTYP] 2.3.3). whenCreated = 2026-11-01T00:00:00Z
    /// = DSTIME 13 437 964 800 ([MS-DRSR] 5.51).
    #[test]
    fn a_password_set_revokes_its_own_second() {
        const CREATED: i64 = 13_437_964_800;
        const SET_DSTIME: i64 = 13_439_037_600;
        let set = SET_DSTIME * FILETIME_TICKS_PER_SECOND;
        let s = kt(2026, 11, 13, 10, 0, 0);
        let s_plus_1 = kt(2026, 11, 13, 10, 0, 1);
        for ticks in [set, set + 1, set + FILETIME_TICKS_PER_SECOND - 1] {
            let account = state(CREATED, Some(ticks));
            assert_eq!(account.revoked_before, Some(s_plus_1), "{ticks}");
            // The same second as the set: revoked (the Q-965 window closed).
            assert!(account.revokes(&s), "{ticks}");
            assert!(account.revokes(&kt(2026, 11, 13, 9, 59, 59)), "{ticks}");
            // One second later: not revoked.
            assert!(!account.revokes(&s_plus_1), "{ticks}");
        }
        // The next whole second of FILETIME moves the cut by one second.
        let next = state(CREATED, Some(set + FILETIME_TICKS_PER_SECOND));
        assert!(next.revokes(&s_plus_1));
        assert!(!next.revokes(&kt(2026, 11, 13, 10, 0, 2)));
    }

    /// docs/47 §4.5 (R47-7), the whenCreated half unchanged: a ticket of
    /// the creation second (a former holder of the name) is revoked, one of
    /// the next second is not; pwdLastSet absent, 0, or earlier than
    /// whenCreated leaves whenCreated's cut. whenCreated absent ⇒ `Err`
    /// (Q-136 item 3).
    #[test]
    fn the_creation_second_is_revoked() {
        const CREATED: i64 = 13_437_964_800; // 2026-11-01T00:00:00Z
        let created = kt(2026, 11, 1, 0, 0, 0);
        let after = kt(2026, 11, 1, 0, 0, 1);
        let earlier_set = (CREATED - 60) * FILETIME_TICKS_PER_SECOND;
        for pwd_last_set in [None, Some(0), Some(earlier_set)] {
            let account = state(CREATED, pwd_last_set);
            assert_eq!(account.revoked_before, Some(after), "{pwd_last_set:?}");
            assert!(account.revokes(&created), "{pwd_last_set:?}");
            assert!(!account.revokes(&after), "{pwd_last_set:?}");
        }
        assert_eq!(
            revoked_before(None, Some(earlier_set)),
            Err(Fault::Unavailable)
        );
    }
}
