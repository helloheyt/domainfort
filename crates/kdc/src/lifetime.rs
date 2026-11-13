//! Planning a ticket's times within policy (main-session decision 10).
//!
//! The KDC clamps what the client asks for to keyd's TicketPolicy and to the
//! principal-specific limits, exactly as RFC 4120 3.1.3 / 3.3.3 describe;
//! keyd's template validation remains the final check.
//!
//! - **starttime** (`from`): absent, in the past or within the clock skew →
//!   the ticket starts now. Further in the future → KDC_ERR_CANNOT_POSTDATE
//!   (POSTDATED is refused before this point, so "the POSTDATED option has
//!   not been specified" always holds). 3.1.3, 3.3.3.
//! - **endtime** (`till`): "19700101000000Z" asks for "the maximum endtime
//!   permitted according to KDC policy" (5.4.1). Otherwise the endtime is
//!   "the earlier of the requested endtime and a time determined by local
//!   policy" (3.1.3): start + the policy maximum, and the caller's caps
//!   (account expiry; at TGS also the TGT's endtime and the TGT's start +
//!   maximum life, 3.3.3). A far-future `till` is therefore clamped, not
//!   refused. If the resulting life is below the policy minimum →
//!   KDC_ERR_NEVER_VALID (3.1.3).
//! - **renew-till**: only when RENEWABLE may be granted at all
//!   (policy, and at TGS a renewable TGT — 5.4.1). With the RENEWABLE option
//!   the requested value is `rtime`; with RENEWABLE-OK, when "the requested
//!   expiration time for the ticket exceeds what was determined as above",
//!   it is the requested endtime (3.1.3, 2.9.1). It is then "the earliest of"
//!   the requested value, start + the policy's maximum renewable life and the
//!   caller's caps (3.1.3; 3.3.3 for the TGT's renew-till). A renew-till that
//!   would fall before the endtime leaves the ticket non-renewable (the flag
//!   is withheld, as RFC 4120 §2 / 3.1.3 permit) rather than refusing.
//!
//! Spec: RFC 4120 2.3, 2.9.1, 3.1.3, 3.3.3, 5.4.1, §8.2; main-session
//! decision 10.

use crate::options::FlagRequests;
use crate::time::{from_seconds, seconds, till_maximum};
use keyd_types::TicketPolicy;
use krb_proto::KerberosTime;

/// What the client asked for. Spec: RFC 4120 5.4.1 (from, till, rtime).
#[derive(Debug, Clone, Copy)]
pub(crate) struct LifetimeRequest<'a> {
    pub(crate) from: Option<&'a KerberosTime>,
    pub(crate) till: &'a KerberosTime,
    pub(crate) rtime: Option<&'a KerberosTime>,
    pub(crate) flags: FlagRequests,
}

/// The limits that apply. Times are seconds on keyd's scale.
/// Spec: RFC 4120 3.1.3, 3.3.3.
#[derive(Debug, Clone)]
pub(crate) struct Limits {
    pub(crate) policy: TicketPolicy,
    pub(crate) skew_secs: u32,
    /// Latest endtimes allowed by other limits (each one caps the endtime).
    pub(crate) end_caps: Vec<i64>,
    /// Latest renew-till times allowed by other limits.
    pub(crate) renew_caps: Vec<i64>,
    /// RENEWABLE may be granted (policy allows it; at TGS the TGT is
    /// renewable).
    pub(crate) renewable_permitted: bool,
}

/// The planned times. The ticket starts now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Planned {
    pub(crate) endtime: KerberosTime,
    pub(crate) renew_till: Option<KerberosTime>,
}

/// Why the times cannot be planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeRefusal {
    /// RFC 4120 3.1.3 / 3.3.3: KDC_ERR_CANNOT_POSTDATE.
    CannotPostdate,
    /// RFC 4120 3.1.3: KDC_ERR_NEVER_VALID.
    NeverValid,
    /// A time is outside the representable range (fail closed).
    OutOfRange,
}

/// The starttime rule alone (checked before any principal lookup).
/// Spec: RFC 4120 3.1.3, 3.3.3.
pub(crate) fn check_starttime(
    from: Option<&KerberosTime>,
    now: &KerberosTime,
    skew_secs: u32,
) -> Result<(), TimeRefusal> {
    match from {
        Some(from) if seconds(from) > seconds(now) + i64::from(skew_secs) => {
            Err(TimeRefusal::CannotPostdate)
        }
        _ => Ok(()),
    }
}

/// Plan endtime and renew-till for a ticket starting at `now`.
/// Spec: RFC 4120 3.1.3, 3.3.3, 5.4.1; main-session decision 10.
pub(crate) fn plan(
    now: &KerberosTime,
    request: &LifetimeRequest<'_>,
    limits: &Limits,
) -> Result<Planned, TimeRefusal> {
    check_starttime(request.from, now, limits.skew_secs)?;
    let start = seconds(now);
    let policy_end = start + i64::from(limits.policy.max_lifetime_secs);
    let is_maximum = till_maximum().is_some_and(|max| *request.till == max);
    let requested_end = if is_maximum {
        policy_end
    } else {
        seconds(request.till)
    };
    let end = limits
        .end_caps
        .iter()
        .copied()
        .fold(requested_end.min(policy_end), i64::min);
    if end - start < i64::from(limits.policy.min_lifetime_secs) {
        return Err(TimeRefusal::NeverValid);
    }

    let mut wanted = if request.flags.renewable {
        request.rtime.map(seconds)
    } else {
        None
    };
    if wanted.is_none() && request.flags.renewable_ok && requested_end > end {
        wanted = Some(requested_end);
    }
    let renew_till = match wanted {
        Some(asked) if limits.renewable_permitted => {
            let policy_renew = start + i64::from(limits.policy.max_renewable_lifetime_secs);
            let renew = limits
                .renew_caps
                .iter()
                .copied()
                .fold(asked.min(policy_renew), i64::min);
            if renew >= end {
                Some(from_seconds(renew).ok_or(TimeRefusal::OutOfRange)?)
            } else {
                None
            }
        }
        _ => None,
    };
    Ok(Planned {
        endtime: from_seconds(end).ok_or(TimeRefusal::OutOfRange)?,
        renew_till,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kt(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
        KerberosTime::new(y, mo, d, h, mi, s).unwrap()
    }

    fn now() -> KerberosTime {
        kt(2026, 11, 13, 10, 0, 0)
    }

    fn flags(renewable: bool, renewable_ok: bool) -> FlagRequests {
        FlagRequests {
            forwardable: false,
            proxiable: false,
            renewable,
            renewable_ok,
        }
    }

    fn limits(renewable_permitted: bool) -> Limits {
        Limits {
            policy: TicketPolicy::default(),
            skew_secs: 300,
            end_caps: Vec::new(),
            renew_caps: Vec::new(),
            renewable_permitted,
        }
    }

    /// RFC 4120 5.4.1: till 19700101000000Z = policy maximum (1 day, §8.2).
    #[test]
    fn till_zero_is_policy_maximum() {
        let zero = kt(1970, 1, 1, 0, 0, 0);
        let req = LifetimeRequest {
            from: None,
            till: &zero,
            rtime: None,
            flags: flags(false, false),
        };
        let p = plan(&now(), &req, &limits(true)).unwrap();
        assert_eq!(p.endtime, kt(2026, 11, 14, 10, 0, 0));
        assert_eq!(p.renew_till, None);
    }

    /// RFC 4120 3.1.3: a far-future till is clamped to the policy maximum;
    /// a cap (e.g. account expiry) clamps further.
    #[test]
    fn far_future_till_is_clamped() {
        let far = kt(2099, 1, 1, 0, 0, 0);
        let req = LifetimeRequest {
            from: None,
            till: &far,
            rtime: None,
            flags: flags(false, false),
        };
        assert_eq!(
            plan(&now(), &req, &limits(false)).unwrap().endtime,
            kt(2026, 11, 14, 10, 0, 0)
        );
        let mut capped = limits(false);
        capped.end_caps.push(seconds(&kt(2026, 11, 13, 12, 0, 0)));
        assert_eq!(
            plan(&now(), &req, &capped).unwrap().endtime,
            kt(2026, 11, 13, 12, 0, 0)
        );
    }

    /// RFC 4120 3.1.3: KDC_ERR_NEVER_VALID below the minimum lifetime
    /// (5 minutes, §8.2) and for a till in the past; KDC_ERR_CANNOT_POSTDATE
    /// for a start beyond the skew.
    #[test]
    fn refusals() {
        let soon = kt(2026, 11, 13, 10, 4, 0);
        let past = kt(2026, 11, 13, 9, 0, 0);
        for till in [soon, past] {
            let req = LifetimeRequest {
                from: None,
                till: &till,
                rtime: None,
                flags: flags(false, false),
            };
            assert_eq!(
                plan(&now(), &req, &limits(false)),
                Err(TimeRefusal::NeverValid)
            );
        }
        let till = kt(2026, 11, 13, 18, 0, 0);
        let within_skew = kt(2026, 11, 13, 10, 5, 0);
        let beyond_skew = kt(2026, 11, 13, 10, 5, 1);
        let req = LifetimeRequest {
            from: Some(&within_skew),
            till: &till,
            rtime: None,
            flags: flags(false, false),
        };
        assert!(plan(&now(), &req, &limits(false)).is_ok());
        let req = LifetimeRequest {
            from: Some(&beyond_skew),
            ..req
        };
        assert_eq!(
            plan(&now(), &req, &limits(false)),
            Err(TimeRefusal::CannotPostdate)
        );
    }

    /// RFC 4120 3.1.3 renew-till: earliest of request and policy (1 week,
    /// §8.2); RENEWABLE-OK uses the requested endtime when it exceeds the
    /// planned one (2.9.1); withheld when not permitted.
    #[test]
    fn renewal_rules() {
        let till = kt(2026, 11, 13, 18, 0, 0);
        let rtime = kt(2026, 12, 31, 0, 0, 0);
        let req = LifetimeRequest {
            from: None,
            till: &till,
            rtime: Some(&rtime),
            flags: flags(true, false),
        };
        assert_eq!(
            plan(&now(), &req, &limits(true)).unwrap().renew_till,
            Some(kt(2026, 11, 20, 10, 0, 0))
        );
        assert_eq!(plan(&now(), &req, &limits(false)).unwrap().renew_till, None);
        // RENEWABLE without rtime: nothing to renew to.
        let req_no_rtime = LifetimeRequest { rtime: None, ..req };
        assert_eq!(
            plan(&now(), &req_no_rtime, &limits(true))
                .unwrap()
                .renew_till,
            None
        );
        // RENEWABLE-OK: requested 3 days > 1-day maximum.
        let long = kt(2026, 11, 16, 10, 0, 0);
        let req_ok = LifetimeRequest {
            from: None,
            till: &long,
            rtime: None,
            flags: flags(false, true),
        };
        let p = plan(&now(), &req_ok, &limits(true)).unwrap();
        assert_eq!(p.endtime, kt(2026, 11, 14, 10, 0, 0));
        assert_eq!(p.renew_till, Some(long));
        // RENEWABLE-OK when the requested life fits: no renewal.
        let req_fits = LifetimeRequest {
            till: &till,
            ..req_ok
        };
        assert_eq!(
            plan(&now(), &req_fits, &limits(true)).unwrap().renew_till,
            None
        );
        // rtime before the endtime: renewal withheld, not refused.
        let early = kt(2026, 11, 13, 12, 0, 0);
        let req_early = LifetimeRequest {
            rtime: Some(&early),
            ..req
        };
        assert_eq!(
            plan(&now(), &req_early, &limits(true)).unwrap().renew_till,
            None
        );
    }
}
