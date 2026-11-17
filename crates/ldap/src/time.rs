//! Time arithmetic on the caller's `now` (the engine reads no clock).
//!
//! A KerberosTime is mapped to seconds on keyd's scale
//! ([`keyd_types::kerberos_time_seconds`], seconds since 0000-01-01T00:00:00Z on
//! the proleptic Gregorian calendar krb-proto validates against) — the one
//! scale the project's Kerberos components share. Only differences are
//! meaningful.
//!
//! Spec: RFC 4120 5.2.3 (KerberosTime is UTC, whole seconds); docs/11 §1
//! (`Context.time: Instant`), §10 P9 (the PDP reads no clock — the PEP
//! supplies the time).

use core::time::Duration;

use krb_proto::KerberosTime;
use pdp::Instant;

/// Seconds since 1970-01-01T00:00:00Z: the PDP's explicit `Instant` —
/// krb-proto's one `kerberos_time_to_unix` (this function held a copy of the
/// difference, with the epoch spelled again, until docs/questions/Q-987
/// item 5 / A-165 folded it — Q-995). `None` before 1970 (the caller fails
/// closed).
/// Spec: docs/11 §1, P9; RFC 4120 5.2.3.
pub(crate) fn unix_instant(now: &KerberosTime) -> Option<Instant> {
    krb_proto::kerberos_time_to_unix(now).map(Instant)
}

/// `later − earlier` as a duration; `None` if `earlier` is after `later`.
/// Spec: RFC 4120 5.2.3.
pub(crate) fn seconds_between(later: &KerberosTime, earlier: &KerberosTime) -> Option<Duration> {
    let delta =
        keyd_types::kerberos_time_seconds(later) - keyd_types::kerberos_time_seconds(earlier);
    u64::try_from(delta).ok().map(Duration::from_secs)
}
