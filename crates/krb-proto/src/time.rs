//! The project's one KerberosTime ↔ seconds pair: the KerberosTime-to-seconds
//! scale every component compares times on, its inverse (a count on that
//! scale back to a KerberosTime — "now + a lifetime"), and the conversion of
//! a Unix clock reading (whole seconds since 1970-01-01T00:00:00Z) into a
//! KerberosTime and back.
//!
//! RFC 4120 5.2.3: a KerberosTime is a UTC calendar date and time in whole
//! seconds ("shall not include any fractional portions of the seconds … it
//! shall specify the UTC time zone (Z)"). It has no leap second (this crate
//! refuses second 60, docs/questions/Q-030), so a day is always 86,400
//! seconds. Every function here counts on the calendar
//! [`KerberosTime::new`] validates against — this crate's `days_in_month`
//! (crate::basic), the one copy of that rule here — and the calendar is
//! walked in one direction only: [`kerberos_time_seconds`]. The inverse
//! [`kerberos_time_from_seconds`] is a search over that forward walk, and
//! the Unix pair is the scale shifted by the scale's reading of
//! 1970-01-01T00:00:00Z, so none of them can disagree with the scale.
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
//! [`kerberos_time_to_unix`] now. The scale's inverse was written twice
//! more, in the kdc (`time.rs`, ticket planning) and in directory-pip
//! (`time.rs`, the DSTIME / FILETIME epoch shift), each a `from_seconds`;
//! both call [`kerberos_time_from_seconds`] now (Q-995 item 5 (b), decision
//! A-169; docs/questions/Q-1005). A source scan pins that no other crate
//! defines any of them (`tests/single_name_and_time_definitions.rs`).
//!
//! keyd never reads a clock: every keyd operation takes `now` from its
//! caller. The integrity of the system time source is the platform's (RFC
//! 4120 §1.6 / §10: clock synchronization "MUST itself be secured").
//!
//! Spec: RFC 4120 5.2.3, §1.6, §10; docs/questions/Q-955 item 5 (A-158),
//! Q-987 item 5 (A-165), Q-995 (A-169), Q-1005.

use crate::basic::{days_in_month, KerberosTime};

/// Seconds in a day (UTC, no leap seconds — RFC 4120 5.2.3), on the signed
/// scale of [`kerberos_time_seconds`].
const SECONDS_PER_DAY: i64 = 86_400;
/// Seconds in an hour.
const SECONDS_PER_HOUR: i64 = 3_600;
/// Seconds in a minute.
const SECONDS_PER_MINUTE: i64 = 60;
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
    days * SECONDS_PER_DAY
        + i64::from(t.hour()) * SECONDS_PER_HOUR
        + i64::from(t.minute()) * SECONDS_PER_MINUTE
        + i64::from(t.second())
}

/// `YYYY-MM-01T00:00:00Z` on the scale of [`kerberos_time_seconds`], or
/// `None` for a year or month a KerberosTime does not carry.
///
/// Spec: RFC 4120 5.2.3.
fn start_of_month(year: u16, month: u8) -> Option<i64> {
    KerberosTime::new(year, month, 1, 0, 0, 0)
        .ok()
        .map(|t| kerberos_time_seconds(&t))
}

/// 1970-01-01T00:00:00Z — where a Unix clock counts from — on the scale of
/// [`kerberos_time_seconds`]: the one place the Unix pair names the epoch.
///
/// Spec: RFC 4120 5.2.3.
fn unix_epoch() -> Option<i64> {
    start_of_month(UNIX_EPOCH_YEAR, 1)
}

/// The KerberosTime at `seconds` on the scale of [`kerberos_time_seconds`]
/// — its exact inverse: `kerberos_time_from_seconds(kerberos_time_seconds(&t))
/// == Some(t)` for every KerberosTime `t`, and
/// `kerberos_time_seconds(&kerberos_time_from_seconds(s)?) == s` for every
/// `s` from 0000-01-01T00:00:00Z to 9999-12-31T23:59:59Z. Outside that
/// range — before year 0000 (a negative count) or after the last instant a
/// KerberosTime carries — there is no KerberosTime, and the result is
/// `None`; a caller that gets `None` fails closed. Never panics, for any
/// `i64`.
///
/// What it is for: a time computed on the scale — "now + a lifetime", a
/// cap, an epoch shift — turned back into a KerberosTime.
///
/// The year is the last one whose 1 January 00:00:00 is not after `seconds`
/// (a binary search over the KerberosTime years, at most 14 steps), the
/// month the last of that year whose first day is not after it (at most 11
/// steps), and the rest whole days, hours, minutes and seconds. Every
/// boundary is read off the forward scale, so the two directions cannot
/// disagree; every candidate is built with [`KerberosTime::new`], so
/// nothing outside its range is ever returned.
///
/// Name: the inverse of [`kerberos_time_seconds`] in the pattern of
/// [`kerberos_time_from_unix`] — `kerberos_time_from_<count>` turns the
/// count it names into a KerberosTime; the count here is the scale's
/// seconds. Moved unchanged in meaning from crates/kdc `time.rs` and
/// crates/directory-pip `time.rs` (`from_seconds`, two copies of one
/// search — docs/questions/Q-995 item 5 (b), A-169; Q-1005).
///
/// Spec: RFC 4120 5.2.3.
#[must_use]
pub fn kerberos_time_from_seconds(seconds: i64) -> Option<KerberosTime> {
    if seconds < start_of_month(0, 1)? {
        return None;
    }
    // The last year whose 1 January 00:00:00 is not after `seconds`.
    let (mut low, mut high) = (0u16, MAX_YEAR);
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if start_of_month(mid, 1)? <= seconds {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    let year = low;
    // The last month of that year whose first day is not after `seconds`.
    let mut month = 1u8;
    while month < 12 && start_of_month(year, month + 1)? <= seconds {
        month += 1;
    }
    let within_month = seconds.checked_sub(start_of_month(year, month)?)?;
    let day = within_month / SECONDS_PER_DAY + 1;
    let within_day = within_month % SECONDS_PER_DAY;
    KerberosTime::new(
        year,
        month,
        u8::try_from(day).ok()?,
        u8::try_from(within_day / SECONDS_PER_HOUR).ok()?,
        u8::try_from(within_day % SECONDS_PER_HOUR / SECONDS_PER_MINUTE).ok()?,
        u8::try_from(within_day % SECONDS_PER_MINUTE).ok()?,
    )
    .ok()
}

/// The KerberosTime `secs` whole seconds after 1970-01-01T00:00:00Z — a Unix
/// clock reading — or `None` after 9999-12-31T23:59:59Z (the last instant a
/// KerberosTime carries). The scale's inverse
/// ([`kerberos_time_from_seconds`]) at the epoch's reading plus `secs`, so
/// the calendar is walked once, by the scale (Q-1005: before, this function
/// walked the calendar itself, year by year — the same values, checked
/// against the former walk this session). A caller that gets `None` fails
/// closed.
///
/// Moved unchanged in meaning from crates/kpasswd-front `clock.rs`
/// (`kerberos_time_from_unix`, Q-955 item 5).
///
/// Spec: RFC 4120 5.2.3.
#[must_use]
pub fn kerberos_time_from_unix(secs: u64) -> Option<KerberosTime> {
    kerberos_time_from_seconds(unix_epoch()?.checked_add(i64::try_from(secs).ok()?)?)
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
    u64::try_from(kerberos_time_seconds(t) - unix_epoch()?).ok()
}
