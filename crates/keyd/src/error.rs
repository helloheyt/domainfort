//! keyd's internal refusal and its mapping to the public errors.
//!
//! The public error enums ([`AuthnError`], [`IssueError`], [`Error`],
//! [`ConfigError`]) and the error model they implement — uniform before the
//! cryptographic chain completes, classified (non-secret) after (A-26);
//! `Unavailable` for the startup hold-down (A-56) — live in the crypto-free
//! `keyd-types` crate (D182; decision A-63, module `error` there) and are
//! re-exported here. What stays in keyd is the internal [`Deny`]: the
//! public error kind plus the audit-only reason, mapped to the public
//! errors by the `From` impls below. The specific reason always goes to
//! audit ([`crate::audit::AuditReason`]), never to the caller.
//!
//! Spec: docs/10 §9 (`AuthnError { Denied }`, `IssueError { Denied,
//! BadTemplate }`, `Error { Denied, Unavailable, RateLimited }`) as amended by
//! A-26 and A-56; docs/09 א.3 (5) uniform errors; RFC 4120 3.2.3, 3.3.2 (the
//! codes these classes correspond to); docs/50 R50-6, R50-8, §3.5, §3.7;
//! AGENTS.md §6 (no secrets in errors).

use crate::audit::{AuditOutcome, AuditReason};
pub use keyd_types::{AuthnError, ConfigError, Error, IssueError};

/// Internal refusal: the public error kind plus the audit-only reason, and
/// the non-secret class reported to the caller — set only for a refusal
/// decided after an authentication step's cryptographic chain completed
/// ([`Deny::classified`], A-26), or for the startup hold-down
/// ([`Deny::startup_hold_down`], A-56: decided before any secret work).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Deny {
    pub(crate) outcome: AuditOutcome,
    pub(crate) reason: AuditReason,
    pub(crate) class: Option<AuthnError>,
}

impl Deny {
    pub(crate) const fn denied(reason: AuditReason) -> Self {
        Deny {
            outcome: AuditOutcome::Denied,
            reason,
            class: None,
        }
    }

    /// A refusal reported as `class`. Call ONLY where every cryptographic
    /// check of the authentication step has already passed (A-26).
    /// Spec: docs/questions/Q-071 (A-26).
    pub(crate) const fn classified(reason: AuditReason, class: AuthnError) -> Self {
        Deny {
            outcome: AuditOutcome::Denied,
            reason,
            class: Some(class),
        }
    }

    pub(crate) const fn bad_template(reason: AuditReason) -> Self {
        Deny {
            outcome: AuditOutcome::BadTemplate,
            reason,
            class: None,
        }
    }

    pub(crate) const fn unavailable(reason: AuditReason) -> Self {
        Deny {
            outcome: AuditOutcome::Unavailable,
            reason,
            class: None,
        }
    }

    pub(crate) const fn rate_limited(reason: AuditReason) -> Self {
        Deny {
            outcome: AuditOutcome::RateLimited,
            reason,
            class: None,
        }
    }

    /// The startup hold-down refusal: reported as `Unavailable` by every
    /// error type (`AuthnError`, `IssueError`, `Error`). Built ONLY by
    /// `Keyd::admit`, after the role and purpose checks and before any key,
    /// token, throttle or replay-cache state is read — so it depends on the
    /// caller's `now` and keyd's start time alone, never on a secret.
    /// Spec: RFC 4120 3.2.3; docs/50 R50-6, §3.5; docs/questions/Q-217,
    /// Q-222 (A-56).
    pub(crate) const fn startup_hold_down() -> Self {
        Deny {
            outcome: AuditOutcome::Unavailable,
            reason: AuditReason::StartupHoldDown,
            class: Some(AuthnError::Unavailable),
        }
    }
}

/// Internal result type.
pub(crate) type Internal<T> = core::result::Result<T, Deny>;

impl From<Deny> for AuthnError {
    /// Every refusal of an authentication step is `Denied` (docs/10 §9),
    /// except one built with [`Deny::classified`] after the cryptographic
    /// chain completed (A-26), and the startup hold-down (`Unavailable`,
    /// A-56). Other `Unavailable` outcomes (entropy, a full table) stay the
    /// uniform `Denied`: some are decided inside the chain, where telling
    /// them apart could be an oracle (A-26).
    fn from(deny: Deny) -> Self {
        deny.class.unwrap_or(AuthnError::Denied)
    }
}

impl From<Deny> for IssueError {
    /// Only template failures surface as `BadTemplate`, and only the startup
    /// hold-down as `Unavailable` (A-56); everything else is `Denied`
    /// (docs/10 §9).
    fn from(deny: Deny) -> Self {
        if deny.class == Some(AuthnError::Unavailable) {
            return IssueError::Unavailable;
        }
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
