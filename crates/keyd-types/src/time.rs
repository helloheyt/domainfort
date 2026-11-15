//! The project's one KerberosTime-to-seconds scale, under the path keyd's
//! callers name (`keyd_types::kerberos_time_seconds`).
//!
//! keyd never reads a clock: every operation takes `now` from the caller, so
//! behaviour is deterministic and testable. Residual: keyd therefore trusts
//! the caller's clock; the integrity of the system time source is the
//! platform's (RFC 4120 §1.6 / §10: clock synchronization "MUST itself be
//! secured").
//!
//! Comparisons (clock skew, lifetimes, token expiry) need differences in
//! seconds, so a KerberosTime is mapped to a count of seconds since
//! 0000-01-01T00:00:00Z on the proleptic Gregorian calendar — the calendar
//! `krb_proto::KerberosTime::new` validates against. Only differences of
//! these counts are meaningful. The KDC, the LDAP engine and the directory
//! PIP use the same scale. It was defined here (moved from keyd: D182,
//! decision A-63); it is now defined once in krb-proto, next to that
//! calendar and to the Unix-clock conversion kpasswd-front needs, and
//! re-exported here so no caller changes (docs/questions/Q-955 item 5,
//! A-158; Q-987).
//!
//! Spec: RFC 4120 5.2.3 (KerberosTime is UTC, whole seconds), §1.6, §10.

pub use krb_proto::kerberos_time_seconds;
