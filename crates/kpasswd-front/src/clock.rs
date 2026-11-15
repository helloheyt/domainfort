//! The front's clock, for the `stime` / `susec` of its KRB-ERRORs.
//!
//! docs/53 §5.7: "`stime`/`susec` = the front's clock". RFC 4120 §5.9.1:
//! "stime — This field contains the current time on the server. It is of
//! type KerberosTime"; "susec — … the microsecond part of the server's
//! timestamp. Its value ranges from 0 to 999999". The front reads the
//! operating-system clock (`std::time::SystemTime`) and turns the whole
//! seconds since 1970-01-01T00:00:00Z into a KerberosTime — UTC, whole
//! seconds, no leap second (RFC 4120 §5.2.3) — with
//! `krb_proto::kerberos_time_from_unix`, the project's one Unix-clock
//! conversion: an instant outside the representable range yields `None`,
//! and the front then closes without a reply (fail closed).
//!
//! **One rule, no copy.** The conversion was written once more here (the
//! front links no keyd crate, tests/holds_no_key.rs) and pinned by a test to
//! keyd-types' scale; both now live in krb-proto, which the front, keyd-types
//! and the kdc all link, and the copy and its pin are gone
//! (docs/questions/Q-955 item 5, A-158; Q-987). A KRB-ERROR is not integrity
//! protected and its time is informational only (RFC 4120 §5.9).
//!
//! Spec: docs/53 §5.7; RFC 4120 §5.2.3, §5.9, §5.9.1.

use krb_proto::{kerberos_time_from_unix, KerberosTime, Microseconds};
use std::time::{SystemTime, UNIX_EPOCH};

/// The server time of a KRB-ERROR: `stime` and `susec`.
/// Spec: RFC 4120 §5.9.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerTime {
    /// `stime`.
    pub stime: KerberosTime,
    /// `susec`.
    pub susec: Microseconds,
}

/// The operating system's clock now, as a KRB-ERROR's server time; `None`
/// if it reads before 1970 or after the representable range (fail closed).
/// Spec: RFC 4120 §5.9.1; docs/53 §5.7.
#[must_use]
pub fn server_time_now() -> Option<ServerTime> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    Some(ServerTime {
        stime: kerberos_time_from_unix(since.as_secs())?,
        susec: Microseconds::new(since.subsec_micros()).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4120 §5.9.1 (`susec` 0 ..= 999999); docs/53 §5.7: the host's
    /// clock reads as a server time (the conversion's own behaviour is
    /// tested with its one definition, crates/krb-proto tests/time_scale.rs).
    #[test]
    fn the_clock_reads_as_a_server_time() {
        let time = server_time_now().expect("the host clock is in range");
        assert!(time.susec.get() <= Microseconds::MAX);
    }
}
