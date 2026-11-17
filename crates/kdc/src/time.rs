//! Time arithmetic on caller-supplied KerberosTime values.
//!
//! The KDC reads no clock: `now` always comes from the caller (main-session
//! decision 1). Ticket planning compares times on keyd's scale
//! ([`keyd_types::kerberos_time_seconds`], seconds since
//! 0000-01-01T00:00:00Z on the proleptic Gregorian calendar, the calendar
//! krb-proto validates against) and needs "now + a lifetime" turned back
//! into a KerberosTime: that is krb-proto's one inverse of the scale,
//! [`krb_proto::kerberos_time_from_seconds`] (crate::lifetime), which yields
//! `None` for an instant outside the representable range (after
//! 9999-12-31T23:59:59Z) — callers fail closed. This module held a copy of
//! that inverse (`from_seconds`, a search over the forward scale) until
//! docs/questions/Q-995 item 5 (b) / A-169 folded it into krb-proto
//! (Q-1005).
//!
//! Spec: RFC 4120 5.2.3 (KerberosTime is UTC, whole seconds); 5.4.1 (`till`
//! "19700101000000Z" = maximum endtime permitted by policy).

use krb_proto::KerberosTime;

/// Seconds of `t` on keyd's scale. Spec: RFC 4120 5.2.3.
pub(crate) fn seconds(t: &KerberosTime) -> i64 {
    keyd_types::kerberos_time_seconds(t)
}

/// The `till` value meaning "the maximum endtime permitted according to KDC
/// policy": 19700101000000Z. Spec: RFC 4120 5.4.1 (till).
pub(crate) fn till_maximum() -> Option<KerberosTime> {
    KerberosTime::new(1970, 1, 1, 0, 0, 0).ok()
}

// The PDP's explicit `Instant` (seconds since 1970-01-01T00:00:00Z, docs/11
// §1, P9) is krb-proto's one `kerberos_time_to_unix` (crate::gate); this
// module held a copy until docs/questions/Q-987 item 5 / A-165 folded it
// (Q-995). `till_maximum` above is RFC 4120 5.4.1's `till` value, which only
// happens to be the same instant.
