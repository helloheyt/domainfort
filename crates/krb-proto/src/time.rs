//! The project's one KerberosTime ↔ seconds pair: the KerberosTime-to-seconds
//! scale every component compares times on, and the conversion of a Unix
//! clock reading (whole seconds since 1970-01-01T00:00:00Z) into a
//! KerberosTime and back.
//!
//! RFC 4120 5.2.3: a KerberosTime is a UTC calendar date and time in whole
//! seconds ("shall not include any fractional portions of the seconds … it
//! shall specify the UTC time zone (Z)"). It has no leap second (this crate
//! refuses second 60, docs/questions/Q-030), so a day is always 86,400
//! seconds. Both functions count on the calendar [`KerberosTime::new`]
//! validates against — this crate's `is_leap_year` / `days_in_month`
//! (crate::basic), the one copy of that rule here.
//!
//! **Why here (docs/questions/Q-955 item 5, decision A-158; class C14 "one
//! rule written in two places"):** the scale lived in crates/keyd-types
//! (`time.rs`, moved there from keyd — D182, A-63) and the Unix conversion
//! was written once more in crates/kpasswd-front (`clock.rs`), which links
//! no keyd crate (docs/53 R53-4) and so could not call keyd-types; tests
//! pinned the copy to the original. Both are moved here unchanged in meaning
//! — krb-proto is linked by keyd-types, the kdc and the front alike — and
//! keyd-types re-exports the scale under its old path, so no caller changed.
//!
//! **The copies folded (docs/questions/Q-987 item 5, decision A-165;
//! Q-995):** the clocks of kdc-daemon, keyd-daemon, directory-daemon and
//! admin-daemon and provisioning's time each wrote the Unix conversion once
//! more (a search over the scale, or a walk through directory-pip's DSTIME),
//! and the kdc and the LDAP engine each wrote the reverse difference with
//! the epoch spelled again; they call [`kerberos_time_from_unix`] /
//! [`kerberos_time_to_unix`] now, and a source scan pins that no other crate
//! defines either (`tests/single_name_and_time_definitions.rs`).
//!
//! keyd never reads a clock: every keyd operation takes `now` from its
//! caller. The integrity of the system time source is the platform's (RFC
//! 4120 §1.6 / §10: clock synchronization "MUST itself be secured").
//!
//! Spec: RFC 4120 5.2.3, §1.6, §10; docs/questions/Q-955 item 5 (A-158),
//! Q-987 item 5 (A-165), Q-995.

use crate::basic::{days_in_month, is_leap_year, KerberosTime};

/// Seconds in a day (UTC, no leap seconds — RFC 4120 5.2.3).
const SECONDS_PER_DAY: u64 = 86_400;
/// The same, on the signed scale of [`kerberos_time_seconds`].
const SCALE_SECONDS_PER_DAY: i64 = 86_400;
/// Seconds in an hour.
const SECONDS_PER_HOUR: u64 = 3_600;
/// Seconds in a minute.
const SECONDS_PER_MINUTE: u64 = 60;
/// The year of 1970-01-01T00:00:00Z, where a Unix clock counts from.
const UNIX_EPOCH_YEAR: u16 = 1970;
/// The last year a KerberosTime carries (four digits, RFC 4120 5.2.3;
/// [`KerberosTime::new`] refuses a later one).
const MAX_YEAR: u16 = 9999;

/// Seconds since 0000-01-01T00:00:00Z (proleptic Gregorian) of a validated
/// KerberosTime — the project's one scale for comparing times (clock skew,
/// lifetimes, token expiry). Only differences of these counts are
/// meaningful. Total for every value this crate accepts (years 0000-9999),
/// with no overflow: the result is below 2^39.
///
/// Days before year `y` = 365·y plus the leap years in [0, y): multiples of 4
/// ((y+3)/4) minus multiples of 100 ((y+99)/100) plus multiples of 400
/// ((y+399)/400) — year 0 itself is a leap year under the calendar rule.
///
/// Moved unchanged in meaning from crates/keyd-types `time.rs` (Q-955
/// item 5); keyd-types re-exports it.
///
/// Spec: RFC 4120 5.2.3.
#[must_use]
pub fn kerberos_time_seconds(t: &KerberosTime) -> i64 {
    let year = t.year();
    let y = i64::from(year);
    let leap_years_before = (y + 3) / 4 - (y + 99) / 100 + (y + 399) / 400;
    let mut days = 365 * y + leap_years_before;
    let mut month = 1u8;
    while month < t.month() {
        days += i64::from(days_in_month(year, month));
        month += 1;
    }
    days += i64::from(t.day()) - 1;
    days * SCALE_SECONDS_PER_DAY
        + i64::from(t.hour()) * 3_600
        + i64::from(t.minute()) * 60
        + i64::from(t.second())
}

/// The KerberosTime `secs` whole seconds after 1970-01-01T00:00:00Z — a Unix
/// clock reading — or `None` after 9999-12-31T23:59:59Z (the last instant a
/// KerberosTime carries). Every candidate is built with
/// [`KerberosTime::new`], so nothing outside its range is ever returned (a
/// caller that gets `None` fails closed).
///
/// Bounded: the year walk stops at year 9999 (at most 8,030 steps), the
/// month walk at month 12.
///
/// Moved unchanged in meaning from crates/kpasswd-front `clock.rs`
/// (`kerberos_time_from_unix`, Q-955 item 5).
///
/// Spec: RFC 4120 5.2.3.
#[must_use]
pub fn kerberos_time_from_unix(secs: u64) -> Option<KerberosTime> {
    let mut days = secs / SECONDS_PER_DAY;
    let within_day = secs % SECONDS_PER_DAY;
    let mut year = UNIX_EPOCH_YEAR;
    loop {
        let length = if is_leap_year(year) { 366 } else { 365 };
        if days < length {
            break;
        }
        days -= length;
        if year >= MAX_YEAR {
            return None;
        }
        year += 1;
    }
    let mut month = 1u8;
    while month < 12 && days >= u64::from(days_in_month(year, month)) {
        days -= u64::from(days_in_month(year, month));
        month += 1;
    }
    KerberosTime::new(
        year,
        month,
        u8::try_from(days + 1).ok()?,
        u8::try_from(within_day / SECONDS_PER_HOUR).ok()?,
        u8::try_from(within_day % SECONDS_PER_HOUR / SECONDS_PER_MINUTE).ok()?,
        u8::try_from(within_day % SECONDS_PER_MINUTE).ok()?,
    )
    .ok()
}

/// The Unix clock reading of `t`: its whole seconds after
/// 1970-01-01T00:00:00Z — the inverse of [`kerberos_time_from_unix`] on its
/// range — or `None` for a KerberosTime before that instant (a caller that
/// gets `None` fails closed). The difference of two counts on the project's
/// one scale ([`kerberos_time_seconds`]), so it can never disagree with it.
///
/// The PDP's explicit `Instant` (crate pdp: seconds since
/// 1970-01-01T00:00:00Z, supplied by the PEP — docs/11 §1, §10 P9) is this
/// value; the kdc and the LDAP engine took it from copies of this
/// difference, each spelling the epoch once more (docs/questions/Q-987
/// item 5; Q-995).
///
/// Spec: RFC 4120 5.2.3.
#[must_use]
pub fn kerberos_time_to_unix(t: &KerberosTime) -> Option<u64> {
    let epoch = KerberosTime::new(UNIX_EPOCH_YEAR, 1, 1, 0, 0, 0).ok()?;
    u64::try_from(kerberos_time_seconds(t) - kerberos_time_seconds(&epoch)).ok()
}
