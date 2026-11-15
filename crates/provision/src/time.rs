//! The provisioning time: the operating system's clock, whole seconds.
//!
//! Converted with the project's one Unix-clock conversion,
//! `krb_proto::kerberos_time_from_unix` (this module composed its own
//! through directory-pip's DSTIME until docs/questions/Q-987 item 5 / A-165
//! folded it — Q-995). krb-proto is crypto-free and already linked here; no
//! daemon crate is (a daemon's runtime and, for keyd-daemon, keyd's crypto
//! would come with it — D182).
//!
//! Spec: RFC 4120 §5.2.3 (KerberosTime); [MS-ADTS] 3.1.1.5.2.4 (whenCreated
//! = "the current time according to the system clock on this DC");
//! docs/questions/Q-987 item 5 (A-165), Q-995.

use std::time::{SystemTime, UNIX_EPOCH};

use krb_proto::{kerberos_time_from_unix, KerberosTime};

/// Now, from the system clock; `None` if it is before 1970 or out of range.
/// Spec: RFC 4120 §5.2.3; [MS-ADTS] 3.1.1.5.2.4.
#[must_use]
pub fn system_now() -> Option<KerberosTime> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    kerberos_time_from_unix(since.as_secs())
}
