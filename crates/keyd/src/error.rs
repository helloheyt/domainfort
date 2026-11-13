//! The error model: uniform before the cryptographic chain completes,
//! classified (non-secret) after.
//!
//! Callers see only terse, data-free errors. Every failure decided BEFORE an
//! authentication step's cryptographic chain has fully passed is the uniform
//! `Denied`: no variant tells an unknown principal from a wrong password, an
//! unknown kvno, a failed decryption, a bad or missing checksum, a name
//! mismatch or a missing token. Only facts learned AFTER every cryptographic
//! check passed — and therefore learnable only by a holder of the key or
//! session key — are reported as a class ([`AuthnError::TicketExpired`],
//! [`AuthnError::TicketNotYetValid`], [`AuthnError::Skew`],
//! [`AuthnError::Replay`]): revealing them is no decryption or MAC oracle
//! (decision A-26, docs/questions/Q-071). The specific reason always goes to
//! audit ([`crate::audit::AuditReason`]).
//!
//! Spec: docs/10 §9 (`AuthnError { Denied }`, `IssueError { Denied,
//! BadTemplate }`, `Error { Denied, Unavailable, RateLimited }`) as amended by
//! A-26; docs/09 א.3 (5) uniform errors; RFC 4120 3.2.3, 3.3.2 (the codes
//! these classes correspond to); AGENTS.md §6 (no secrets in errors).

use crate::audit::{AuditOutcome, AuditReason};
use core::fmt;

/// Error of an authentication step (`verify_preauth`,
/// `open_and_verify_tgt`, `open_fast_armor`).
///
/// `Denied` is returned for every failure decided before the step's
/// cryptographic chain completed. The other variants are returned only after
/// it completed — for `open_and_verify_tgt`: the TGT decrypted, the
/// authenticator decrypted and its checksum over the KDC-REQ-BODY verified;
/// for `open_fast_armor`: the armor TGT and authenticator decrypted, the
/// subkey present, the armor key derived, the req-checksum verified and the
/// enc-fast-req decrypted and decoded (docs/48 §6.3); for `verify_preauth`
/// (only `Skew`): the PA-ENC-TIMESTAMP decrypted with the client key and
/// decoded. A `verify_preauth` refused by its failure throttle is `Denied`
/// (decided before the chain; A-34).
///
/// Spec: docs/10 §9 as amended by A-26 (docs/questions/Q-071); RFC 4120
/// 3.2.3, 3.3.2; docs/48 §6.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthnError {
    /// Uniform refusal. Spec: docs/10 §9.
    Denied,
    /// The ticket's endtime has passed (beyond the clock skew). Spec: RFC 4120
    /// 3.2.3 (KRB_AP_ERR_TKT_EXPIRED); A-26.
    TicketExpired,
    /// The ticket's starttime is in the future (beyond the clock skew).
    /// Spec: RFC 4120 3.2.3 (KRB_AP_ERR_TKT_NYV); A-26.
    TicketNotYetValid,
    /// The client's time (authenticator ctime, or patimestamp) differs from
    /// `now` by more than the clock skew. Spec: RFC 4120 3.2.3
    /// (KRB_AP_ERR_SKEW), 5.2.7.2; A-26.
    Skew,
    /// The authenticator was already presented. Spec: RFC 4120 3.2.3, 3.3.2
    /// (KRB_AP_ERR_REPEAT); A-26.
    Replay,
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

impl_display!(AuthnError,
    AuthnError::Denied => "denied",
    AuthnError::TicketExpired => "ticket expired",
    AuthnError::TicketNotYetValid => "ticket not yet valid",
    AuthnError::Skew => "clock skew too great",
    AuthnError::Replay => "replay",
);
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

/// Internal refusal: the public error kind plus the audit-only reason, and —
/// only for a refusal decided after an authentication step's cryptographic
/// chain completed — the non-secret class reported to the caller.
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
}

/// Internal result type.
pub(crate) type Internal<T> = core::result::Result<T, Deny>;

impl From<Deny> for AuthnError {
    /// Every refusal of an authentication step is `Denied` (docs/10 §9),
    /// except one built with [`Deny::classified`] after the cryptographic
    /// chain completed (A-26).
    fn from(deny: Deny) -> Self {
        deny.class.unwrap_or(AuthnError::Denied)
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
