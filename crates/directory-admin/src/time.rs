//! The time forms the write PEP needs, all from the caller's `now`
//! (KerberosTime, whole seconds, UTC); no clock is read here.
//!
//! Spec: docs/11 §1, §10 P9 (the PEP supplies `Context.time`, seconds since
//! 1970); [MS-DRSR] 5.51 as cited in docs/46 §8.1 (DSTIME: seconds since
//! 1601-01-01); [MS-DTYP] 2.3.3 as cited in docs/47 §4.2 (FILETIME:
//! 100-nanosecond intervals since 1601-01-01); RFC 4120 §5.2.3
//! (KerberosTime); crate ipc-audit `CalendarTime`.

use core::time::Duration;

use dirstore::Timestamp;
use ipc_audit::CalendarTime;
use krb_proto::KerberosTime;
use pdp::Instant;

/// FILETIME ticks (100 ns) per second. Spec: [MS-DTYP] 2.3.3 as cited in
/// docs/47 §4.2 ("100-ns intervals").
const FILETIME_TICKS_PER_SECOND: i64 = 10_000_000;

/// Seconds since 1970-01-01T00:00:00Z: the PDP's explicit `Instant`
/// (docs/11 §1, P9). `None` before 1970 (the caller fails closed).
pub(crate) fn instant(now: &KerberosTime) -> Option<Instant> {
    let epoch = KerberosTime::new(1970, 1, 1, 0, 0, 0).ok()?;
    let seconds =
        keyd_types::kerberos_time_seconds(now) - keyd_types::kerberos_time_seconds(&epoch);
    u64::try_from(seconds).ok().map(Instant)
}

/// The DSTIME of `now` (whenCreated / whenChanged). Spec: [MS-DRSR] 5.51 as
/// cited in docs/46 §8.1; crate directory-pip `dstime_of`.
pub(crate) fn dstime(now: &KerberosTime) -> Option<i64> {
    directory_pip::dstime_of(now)
}

/// The FILETIME of `now` (pwdLastSet). Spec: [MS-DTYP] 2.3.3 as cited in
/// docs/47 §4.2, §4.5.
pub(crate) fn filetime(now: &KerberosTime) -> Option<i64> {
    dstime(now)?.checked_mul(FILETIME_TICKS_PER_SECOND)
}

/// The wall clock of an originating write's `Origin`: the DSTIME of `now`,
/// in seconds. One unit for every writer of the store (dirstore
/// `Timestamp`: "one unit for all calls"); `provision domain` (task A4)
/// must use this function too.
/// Spec: docs/29 §2 (as cited in docs/51 §4.3 step 5: `Origin` = (clock,
/// NodeId, change-seq)); dirstore `Timestamp`.
pub fn wall_clock(now: &KerberosTime) -> Option<Timestamp> {
    u64::try_from(dstime(now)?).ok().map(Timestamp)
}

/// `now − authtime`, zero when the authtime is ahead of `now` (within keyd's
/// clock skew, which keyd already enforced).
/// Spec: docs/51 §5.3 (`ticket_age: now − authtime`); docs/49 §3.2 (the same
/// rule in the LDAP PEP).
pub(crate) fn ticket_age(now: &KerberosTime, authtime: &KerberosTime) -> Duration {
    let delta =
        keyd_types::kerberos_time_seconds(now) - keyd_types::kerberos_time_seconds(authtime);
    u64::try_from(delta).map_or(Duration::ZERO, Duration::from_secs)
}

/// The audit form of `now`. KerberosTime holds only validated calendar
/// fields (crate krb-proto), so the fallback is unreachable.
pub(crate) fn calendar(now: &KerberosTime) -> CalendarTime {
    CalendarTime::new(
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    )
    .unwrap_or(CalendarTime::EPOCH)
}
