//! dnsd's clock for the zone image's staleness bound.
//!
//! The age of the image is measured on a monotonic clock, in whole seconds
//! since the daemon started — a wall clock set back or forward does not
//! make the image look fresher or staler (docs/54 §4.4: "if dnsd failed to
//! confirm SERIAL with dird for `zone_image_max_age` … SERVFAIL"). dns-zone
//! reads no clock: its `ZoneState::from_confirmation` takes both times as
//! parameters and treats a time before the confirmation as stale (fail
//! closed).
//!
//! Spec: docs/54 §4.4; crates/dns-zone `ZoneState::from_confirmation`; std
//! API documentation (`time::Instant` — "monotonically nondecreasing").

use std::time::Instant;

/// The clock the staleness bound is measured on: whole seconds, never
/// decreasing.
/// Spec: docs/54 §4.4.
pub trait Clock: Send + Sync {
    /// Seconds since an origin fixed for the daemon's life.
    fn now_secs(&self) -> u64;
}

/// The product clock: [`Instant`] since the daemon started.
/// Spec: docs/54 §4.4.
#[derive(Debug, Clone, Copy)]
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    /// A clock whose origin is now.
    #[must_use]
    pub fn start() -> MonotonicClock {
        MonotonicClock {
            origin: Instant::now(),
        }
    }
}

impl Clock for MonotonicClock {
    fn now_secs(&self) -> u64 {
        self.origin.elapsed().as_secs()
    }
}
