//! The uniform error model.
//!
//! Callers see only terse, data-free errors: no variant tells an unknown
//! principal from a wrong password from a failed pre-authentication, a
//! replay, a bad checksum or a missing token. The specific reason goes to
//! audit only ([`crate::audit::AuditReason`]).
//!
//! Spec: docs/10 §9 (`AuthnError { Denied }`, `IssueError { Denied,
//! BadTemplate }`, `Error { Denied, Unavailable, RateLimited }`); docs/09 א.3
//! (5) uniform errors; AGENTS.md §6 (no secrets in errors).

use crate::audit::{AuditOutcome, AuditReason};
use core::fmt;

/// Error of an authentication step (`verify_preauth`,
/// `open_and_verify_tgt`). Spec: docs/10 §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthnError {
    /// Uniform refusal. Spec: docs/10 §9.
    Denied,
}

/// Error of an issuance step (`issue_as_rep`, `issue_tgs_rep`).
/// Spec: docs/10 §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError {
    /// Uniform refusal (authorization, token, key or crypto failure).
    Denied,
    /// The ticket template is structurally unacceptable (flags, times, names,
    /// enctype, nonce). Reveals nothing secret: template rules are public
    /// policy. Spec: docs/10 §9 ("BadTemplate only on structure").
    BadTemplate,
}

/// Error of a management or secret operation (`create_key`, `rotate_key`,
/// `rotate_krbtgt`, `retire_kvno`, `set_secret`, `verify_secret`).
/// Spec: docs/10 §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Uniform refusal. Spec: docs/10 §9.
    Denied,
    /// keyd cannot perform the operation now (entropy or capacity failure).
    Unavailable,
    /// Refused by the throttling hook. Spec: docs/10 §6 ("throttled").
    RateLimited,
}

/// Configuration rejected at construction (fail closed before any key is
/// touched).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// No encryption type configured, or one listed twice.
    EncTypes,
    /// The clock skew window is zero or larger than the bound.
    ClockSkew,
    /// The one-time token lifetime is zero or larger than the bound.
    TokenLifetime,
    /// A table capacity is zero or larger than the bound.
    Capacity,
    /// Ticket lifetimes are inconsistent (min > max, max > renewable, zero).
    TicketLifetimes,
    /// The allowed-flags mask contains a flag that has no code path in
    /// phase 1 (forwarded, proxy, may-postdate, postdated, invalid,
    /// ok-as-delegate) or a reserved bit.
    TicketFlags,
    /// The string-to-key parameters exceed the configured iteration cap.
    S2kParams,
    /// The throttle policy is inconsistent (zero failures / window).
    Throttle,
}

macro_rules! impl_display {
    ($ty:ty, $($variant:path => $text:literal),+ $(,)?) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self { $($variant => $text),+ })
            }
        }
        impl std::error::Error for $ty {}
    };
}

impl_display!(AuthnError, AuthnError::Denied => "denied");
impl_display!(IssueError,
    IssueError::Denied => "denied",
    IssueError::BadTemplate => "bad ticket template",
);
impl_display!(Error,
    Error::Denied => "denied",
    Error::Unavailable => "unavailable",
    Error::RateLimited => "rate limited",
);
impl_display!(ConfigError,
    ConfigError::EncTypes => "invalid encryption type list",
    ConfigError::ClockSkew => "invalid clock skew",
    ConfigError::TokenLifetime => "invalid token lifetime",
    ConfigError::Capacity => "invalid capacity",
    ConfigError::TicketLifetimes => "invalid ticket lifetimes",
    ConfigError::TicketFlags => "invalid allowed ticket flags",
    ConfigError::S2kParams => "invalid string-to-key parameters",
    ConfigError::Throttle => "invalid throttle policy",
);

/// Internal refusal: the public error kind plus the audit-only reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Deny {
    pub(crate) outcome: AuditOutcome,
    pub(crate) reason: AuditReason,
}

impl Deny {
    pub(crate) const fn denied(reason: AuditReason) -> Self {
        Deny {
            outcome: AuditOutcome::Denied,
            reason,
        }
    }

    pub(crate) const fn bad_template(reason: AuditReason) -> Self {
        Deny {
            outcome: AuditOutcome::BadTemplate,
            reason,
        }
    }

    pub(crate) const fn unavailable(reason: AuditReason) -> Self {
        Deny {
            outcome: AuditOutcome::Unavailable,
            reason,
        }
    }

    pub(crate) const fn rate_limited(reason: AuditReason) -> Self {
        Deny {
            outcome: AuditOutcome::RateLimited,
            reason,
        }
    }
}

/// Internal result type.
pub(crate) type Internal<T> = core::result::Result<T, Deny>;

impl From<Deny> for AuthnError {
    /// Every refusal of an authentication step is `Denied` (docs/10 §9).
    fn from(_: Deny) -> Self {
        AuthnError::Denied
    }
}

impl From<Deny> for IssueError {
    /// Only template failures surface as `BadTemplate`; everything else is
    /// `Denied` (docs/10 §9).
    fn from(deny: Deny) -> Self {
        match deny.outcome {
            AuditOutcome::BadTemplate => IssueError::BadTemplate,
            _ => IssueError::Denied,
        }
    }
}

impl From<Deny> for Error {
    /// Spec: docs/10 §9.
    fn from(deny: Deny) -> Self {
        match deny.outcome {
            AuditOutcome::Unavailable => Error::Unavailable,
            AuditOutcome::RateLimited => Error::RateLimited,
            _ => Error::Denied,
        }
    }
}
