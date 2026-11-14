//! The provisioning time: the operating system's clock, whole seconds.
//!
//! The same composition crates/directory-daemon and crates/keyd-daemon use
//! (`kerberos_time_from_unix`: the DSTIME of 1970-01-01 plus the seconds,
//! mapped back through directory-pip); neither daemon crate is linked here
//! (a daemon's runtime and, for keyd-daemon, keyd's crypto would come with
//! it — D182).
//!
//! Spec: RFC 4120 §5.2.3 (KerberosTime); [MS-DRSR] 5.51 as cited in docs/46
//! §8.1 (DSTIME); [MS-ADTS] 3.1.1.5.2.4 (whenCreated = "the current time
//! according to the system clock on this DC"); directory-pip `dstime_of`,
//! `time_of_dstime`.

use std::time::{SystemTime, UNIX_EPOCH};

use directory_pip::{dstime_of, time_of_dstime};
use krb_proto::KerberosTime;

/// The KerberosTime `secs` whole seconds after 1970-01-01T00:00:00Z, or
/// `None` outside the representable range.
#[must_use]
pub fn kerberos_time_from_unix(secs: u64) -> Option<KerberosTime> {
    let epoch = dstime_of(&KerberosTime::new(1970, 1, 1, 0, 0, 0).ok()?)?;
    time_of_dstime(epoch.checked_add(i64::try_from(secs).ok()?)?)
}

/// Now, from the system clock; `None` if it is before 1970 or out of range.
#[must_use]
pub fn system_now() -> Option<KerberosTime> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    kerberos_time_from_unix(since.as_secs())
}
