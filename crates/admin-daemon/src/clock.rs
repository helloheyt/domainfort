//! admind's clock, for the time of its audit events only (admind decides
//! nothing by time: ticket ages are dird's, key times keyd's).
//!
//! The operating-system clock (`std::time::SystemTime`), whole seconds since
//! 1970-01-01T00:00:00Z, converted to a calendar time with the project's one
//! conversion, `krb_proto::kerberos_time_from_unix` (this module held a copy
//! of it until docs/questions/Q-987 item 5 / A-165 folded it — Q-995). A
//! clock that cannot be read or represented gives the event the calendar
//! epoch (`CalendarTime::EPOCH`): the event is still recorded (auditd stamps
//! its own time on every record, crate audit-log `Record::time`).
//!
//! Spec: RFC 4120 5.2.3 (KerberosTime: UTC, whole seconds); crate ipc-audit
//! `CalendarTime`; docs/50 §8.1; docs/questions/Q-987 item 5 (A-165), Q-995.

use ipc_audit::CalendarTime;
use krb_proto::{kerberos_time_from_unix, KerberosTime};
use std::time::{SystemTime, UNIX_EPOCH};

/// The audit form of a KerberosTime (validated calendar fields, so the
/// fallback is unreachable).
/// Spec: crate ipc-audit `CalendarTime`.
#[must_use]
pub fn calendar(time: &KerberosTime) -> CalendarTime {
    CalendarTime::new(
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
    )
    .unwrap_or(CalendarTime::EPOCH)
}

/// Now, for an audit event (module documentation).
/// Spec: docs/50 §8.1.
#[must_use]
pub fn event_time() -> CalendarTime {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| kerberos_time_from_unix(since.as_secs()))
        .map_or(CalendarTime::EPOCH, |time| calendar(&time))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
        KerberosTime::new(y, mo, d, h, mi, s).unwrap()
    }

    /// crate ipc-audit `CalendarTime`: the audit form keeps every calendar
    /// field of the KerberosTime (hand-picked instant).
    #[test]
    fn calendar_keeps_the_fields() {
        let c = calendar(&t(2000, 1, 1, 0, 1, 1));
        assert_eq!((c.year(), c.month(), c.day()), (2000, 1, 1));
        assert_eq!((c.hour(), c.minute(), c.second()), (0, 1, 1));
    }

    /// The host clock reads (it is after 1970). The conversion's own tests
    /// are krb-proto's (`tests/time_scale.rs`).
    #[test]
    fn reads() {
        assert_ne!(event_time(), CalendarTime::EPOCH);
    }
}
