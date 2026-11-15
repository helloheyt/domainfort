//! Directory time values as KerberosTime.
//!
//! - FILETIME (accountExpires, pwdLastSet): "the number of 100-nanosecond
//!   intervals that have elapsed since January 1, 1601, Coordinated
//!   Universal Time (UTC)" ([MS-DTYP] 2.3.3).
//! - DSTIME (whenCreated): "the number of seconds since January 1, 1601,
//!   12:00:00 A.M." ([MS-DRSR] 5.51); dirstore holds it as a non-negative
//!   8-byte value (docs/46 §8.1).
//! - KerberosTime: UTC, whole seconds (RFC 4120 5.2.3).
//!
//! The 1601 epoch is not a copied constant: it is the KerberosTime
//! 1601-01-01T00:00:00Z mapped through keyd's public seconds scale
//! ([`keyd_types::kerberos_time_seconds`], seconds since 0000-01-01T00:00:00Z on
//! the proleptic Gregorian calendar — the calendar krb-proto validates
//! against), as docs/47 §4.2 asks ("derive the offset from the calendar").
//! The way back is krb-proto's one inverse of that scale,
//! [`krb_proto::kerberos_time_from_seconds`] (a search over the same forward
//! mapping, so the two can never disagree); an instant outside the
//! KerberosTime range (after 9999-12-31T23:59:59Z) has no KerberosTime and
//! yields `None` — callers fail closed. This module held a copy of that
//! inverse (`from_seconds`) until docs/questions/Q-995 item 5 (b) / A-169
//! folded it into krb-proto (Q-1005).
//!
//! Spec: [MS-DTYP] 2.3.3; [MS-DRSR] 5.51; RFC 4120 5.2.3; docs/47 §4.2, §4.5.

use keyd_types::kerberos_time_seconds;
use krb_proto::{kerberos_time_from_seconds, KerberosTime};

/// Nanoseconds in one second.
const NANOSECONDS_PER_SECOND: i64 = 1_000_000_000;

/// Nanoseconds in one FILETIME interval ("100-nanosecond intervals").
/// Spec: [MS-DTYP] 2.3.3.
const NANOSECONDS_PER_FILETIME_TICK: i64 = 100;

/// FILETIME intervals in one second. Spec: [MS-DTYP] 2.3.3.
pub(crate) const FILETIME_TICKS_PER_SECOND: i64 =
    NANOSECONDS_PER_SECOND / NANOSECONDS_PER_FILETIME_TICK;

/// The FILETIME / DSTIME epoch, 1601-01-01T00:00:00Z, on keyd's seconds
/// scale. Spec: [MS-DTYP] 2.3.3 ("since January 1, 1601"); [MS-DRSR] 5.51.
fn epoch_1601() -> Option<i64> {
    KerberosTime::new(1601, 1, 1, 0, 0, 0)
        .ok()
        .map(|t| kerberos_time_seconds(&t))
}

/// The KerberosTime `seconds` after 1601-01-01T00:00:00Z, or `None` if
/// negative or not representable. Spec: [MS-DRSR] 5.51; RFC 4120 5.2.3.
pub(crate) fn since_1601(seconds: i64) -> Option<KerberosTime> {
    if seconds < 0 {
        return None;
    }
    kerberos_time_from_seconds(epoch_1601()?.checked_add(seconds)?)
}

/// The calendar time of a DSTIME value ("the number of seconds since
/// January 1, 1601, 12:00:00 A.M.") as a KerberosTime (UTC, whole seconds),
/// or `None` if negative or after 9999-12-31T23:59:59Z. The public form of
/// the one conversion this crate uses for whenCreated, so the LDAP layer
/// renders String(Generalized-Time) values on the same scale (D64).
/// Spec: [MS-DRSR] 5.51; RFC 4120 5.2.3; docs/46 §1 (DsTime).
#[must_use]
pub fn time_of_dstime(seconds: i64) -> Option<KerberosTime> {
    since_1601(seconds)
}

/// The DSTIME value of a calendar time: seconds since 1601-01-01T00:00:00Z
/// (negative before it). The inverse of [`time_of_dstime`] on its range.
/// Spec: [MS-DRSR] 5.51; RFC 4120 5.2.3.
#[must_use]
pub fn dstime_of(time: &KerberosTime) -> Option<i64> {
    kerberos_time_seconds(time).checked_sub(epoch_1601()?)
}

/// A FILETIME rounded DOWN to the whole second it falls in: an expiry
/// (earlier is the stricter side, docs/47 §4.2) and the second of a
/// password set, whose every ticket at or before it is revoked (docs/47
/// §4.5; Q-965 (a)). `None` if negative or not representable.
/// Spec: [MS-DTYP] 2.3.3; docs/47 §4.2, §4.5.
pub(crate) fn filetime_floor(ticks: i64) -> Option<KerberosTime> {
    if ticks < 0 {
        return None;
    }
    since_1601(ticks / FILETIME_TICKS_PER_SECOND)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
        KerberosTime::new(y, mo, d, h, mi, s).unwrap()
    }

    /// Hand-derived offsets on the Gregorian calendar (RFC 4120 5.2.3; the
    /// [MS-DTYP] 2.3.3 / [MS-DRSR] 5.51 epoch 1601-01-01):
    /// - 1601-01-01 → 1970-01-01: 369 years, leap years 1604..1968 = 92
    ///   multiples of 4 minus 1700, 1800, 1900 (not multiples of 400) = 89;
    ///   369 × 365 + 89 = 134 774 days = 11 644 473 600 s.
    /// - 1970-01-01 → 2027-01-01: 57 years, leap years 1972..2024 = 14;
    ///   57 × 365 + 14 = 20 819 days = 1 798 761 600 s.
    #[test]
    fn epoch_offsets_follow_the_calendar() {
        assert_eq!(since_1601(0), Some(t(1601, 1, 1, 0, 0, 0)));
        assert_eq!(since_1601(11_644_473_600), Some(t(1970, 1, 1, 0, 0, 0)));
        assert_eq!(
            since_1601(11_644_473_600 + 1_798_761_600),
            Some(t(2027, 1, 1, 0, 0, 0))
        );
        // FILETIME: × 10^7 intervals per second ([MS-DTYP] 2.3.3).
        assert_eq!(FILETIME_TICKS_PER_SECOND, 10_000_000);
        assert_eq!(
            filetime_floor(116_444_736_000_000_000),
            Some(t(1970, 1, 1, 0, 0, 0))
        );
    }

    /// Floor to the second the FILETIME falls in, for expiry and for the
    /// second of a password set alike (docs/47 §4.2, §4.5; Q-965 (a)):
    /// every 100-ns interval of 1970-01-01T00:00:00Z maps to that second.
    #[test]
    fn rounding() {
        let base = 116_444_736_000_000_000i64; // 1970-01-01T00:00:00Z
        assert_eq!(filetime_floor(base), Some(t(1970, 1, 1, 0, 0, 0)));
        assert_eq!(filetime_floor(base + 1), Some(t(1970, 1, 1, 0, 0, 0)));
        assert_eq!(
            filetime_floor(base + 9_999_999),
            Some(t(1970, 1, 1, 0, 0, 0))
        );
        assert_eq!(
            filetime_floor(base + 10_000_000),
            Some(t(1970, 1, 1, 0, 0, 1))
        );
    }

    /// Outside the KerberosTime range, or negative: no value (fail closed).
    /// The DSTIME of 9999-12-31T23:59:59Z — the last instant a KerberosTime
    /// carries (RFC 4120 5.2.3) — still has one; the second after it does
    /// not.
    #[test]
    fn out_of_range() {
        assert_eq!(filetime_floor(-1), None);
        assert_eq!(since_1601(-1), None);
        // i64::MAX intervals is about year 30828 — beyond 9999.
        assert_eq!(filetime_floor(i64::MAX), None);
        assert_eq!(since_1601(i64::MAX), None);
        let last = dstime_of(&t(9999, 12, 31, 23, 59, 59)).unwrap();
        assert_eq!(since_1601(last), Some(t(9999, 12, 31, 23, 59, 59)));
        assert_eq!(since_1601(last + 1), None);
    }

    /// The DSTIME pair is one conversion read both ways ([MS-DRSR] 5.51):
    /// every field comes back, leap days and the 1601 epoch included; a
    /// time before 1601 has a negative DSTIME, which names no time.
    #[test]
    fn round_trip() {
        for kt in [
            t(1601, 1, 1, 0, 0, 0),
            t(2000, 2, 29, 12, 34, 56),
            t(2026, 11, 13, 10, 0, 0),
            t(2026, 12, 31, 23, 59, 59),
        ] {
            assert_eq!(time_of_dstime(dstime_of(&kt).unwrap()), Some(kt));
        }
        let before = dstime_of(&t(0, 1, 1, 0, 0, 0)).unwrap();
        assert!(before < 0);
        assert_eq!(time_of_dstime(before), None);
    }
}
