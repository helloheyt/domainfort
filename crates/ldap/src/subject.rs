//! The PDP request the engine builds, and how a denial becomes a result code.
//!
//! # The Subject (docs/11 P3: nothing client-claimed)
//!
//! - **Anonymous:** principal ANONYMOUS, S-1-5-7 ("A group that represents
//!   an anonymous logon", [MS-DTYP] 2.4.2.4), no groups, no claims,
//!   `AuthContext { Unauth, armored: false, ticket_age: 0, ticket_verified:
//!   false }`, and the tier the PIP gives that principal — the PDP re-checks
//!   the tier against the PIP even for an anonymous subject (Q-170 item 5).
//!   No group is added: Everyone or any other SID could only add grants.
//! - **Bound (task L7):** the account SID, groups and tier of the
//!   per-request re-check (docs/49 §3.2, §4.4), `AuthContext { Kerberos,
//!   armored: false, ticket_age: now − authtime, ticket_verified: true }`
//!   (docs/49 §3.2: the AP exchange is not FAST).
//!
//! # TransportSec (docs/49 §4.3; A-47, Q-163)
//!
//! `encrypted` = the session's TLS layer is established (the front reports it
//! only for AEAD suites, docs/02 §4). `sealed` and `channel_bound` = a bound
//! identity whose channel binding keyd verified, over TLS — never anything
//! the front or the client says. An anonymous session therefore has
//! `{false,false,false}` in cleartext and `{true,false,false}` over TLS.
//!
//! # Context.transport
//!
//! `pdp::Transport` has no variant for cleartext LDAP (docs/49 §4.3 names
//! `Ldaps` for 636 and for 389 after StartTLS, and nothing for 389 before
//! it). The engine reports `Transport::Ldaps` for every LDAP request and
//! carries the truthful security state in `transport_sec`, which is what the
//! PDP decides on; `decide` never reads `Context.transport` (checked in the
//! pdp source). Recorded as docs/questions/Q-190 item 2.
//!
//! # Denial → result code (docs/49 §9, R49-13; Q-169)
//!
//! | PDP reason | resultCode |
//! |---|---|
//! | `Unauthenticated` | operationsError (1) — "not bound", RFC 4511 §4.2.1; Q-169 item 3 |
//! | `WeakTransport`, not encrypted | confidentialityRequired (13) — RFC 4513 §6.1 |
//! | `WeakTransport`, encrypted | strongerAuthRequired (8) — RFC 4511 A.2 |
//! | `CoarseDeny`, `NoGrant`, `Acl`, `TierViolation`, `Sensitive`, `NoSuchPath` | insufficientAccessRights (50) — the target is visible (the rootDSE always is) |
//! | `PipFailure`, `InvalidRequest`, `SubjectMismatch`, anything else | other (80) — fail closed |
//!
//! Spec: docs/11 §1, §2, §4; docs/49 §3.2, §4.3, §9; [MS-DTYP] v20241119
//! 2.4.2.4; A-47; Q-169; Q-170 item 5.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use dtyp::{Sid, SECURITY_NT_AUTHORITY};
use parse_ldap::ResultCode;
use pdp::{AuthContext, AuthStrength, Pip, PipError, ReasonCode, Subject, TransportSec};

use crate::session::{BoundSubject, Channel, Identity, Session};

/// ANONYMOUS, S-1-5-7: "A group that represents an anonymous logon."
/// Spec: [MS-DTYP] v20241119 2.4.2.4.
pub(crate) fn anonymous_sid() -> Option<Sid> {
    Sid::new(SECURITY_NT_AUTHORITY, &[7]).ok()
}

/// Who asks, for one request. Spec: module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Requester {
    /// The anonymous authorization state (RFC 4513 §4).
    Anonymous,
    /// A bound identity, re-checked for this request.
    Bound(BoundSubject),
}

impl Requester {
    /// The SID for the audit record: `None` for anonymous (docs/49 §10.1).
    pub(crate) fn audit_principal(&self) -> Option<Sid> {
        match self {
            Requester::Anonymous => None,
            Requester::Bound(b) => Some(b.sid),
        }
    }
}

/// The PDP Subject of `requester`. `Err` when the PIP cannot give the
/// anonymous principal's tier (fail closed, D40). Spec: module
/// documentation; docs/11 §1, P3.
pub(crate) fn subject(requester: &Requester, pip: &dyn Pip) -> Result<Subject, PipError> {
    match requester {
        Requester::Anonymous => {
            let principal = anonymous_sid().ok_or(PipError::Unavailable)?;
            let groups = BTreeSet::new();
            let tier = pip.tier_of(&principal, &groups)?;
            Ok(Subject {
                principal,
                groups,
                claims: BTreeMap::new(),
                auth: AuthContext {
                    strength: AuthStrength::Unauth,
                    armored: false,
                    ticket_age: Duration::ZERO,
                    ticket_verified: false,
                },
                tier,
            })
        }
        Requester::Bound(b) => Ok(Subject {
            principal: b.sid,
            groups: b.groups.clone(),
            claims: BTreeMap::new(),
            auth: AuthContext {
                strength: AuthStrength::Kerberos,
                armored: false,
                ticket_age: b.ticket_age,
                ticket_verified: true,
            },
            tier: b.tier,
        }),
    }
}

/// The transport security of a request (module documentation).
/// Spec: docs/49 §4.3; A-47 (Q-163).
pub(crate) fn transport_sec(channel: Channel, requester: &Requester) -> TransportSec {
    let channel_bound = matches!(requester, Requester::Bound(b) if b.channel_bound);
    security(channel, channel_bound)
}

/// The transport security of the session as it stands, before the
/// per-request re-check (for the audit record of a message that ends
/// earlier). Spec: docs/49 §4.3, §10.1; A-47.
pub(crate) fn session_transport_sec(session: &Session) -> TransportSec {
    let channel_bound = matches!(&session.identity, Identity::Bound(b) if b.channel_bound);
    security(session.channel, channel_bound)
}

/// `encrypted` = TLS; `sealed` = `channel_bound` = TLS and a keyd-verified
/// channel binding. Spec: docs/49 §4.3; A-47 (Q-163).
fn security(channel: Channel, keyd_verified_channel_binding: bool) -> TransportSec {
    let encrypted = channel.tls();
    let bound = encrypted && keyd_verified_channel_binding;
    TransportSec {
        encrypted,
        sealed: bound,
        channel_bound: bound,
    }
}

/// The result code of a PDP denial (module documentation).
/// Spec: docs/49 §9 (R49-13); Q-169 items 3, 4.
pub(crate) fn denial_code(reason: ReasonCode, transport_sec: TransportSec) -> ResultCode {
    match reason {
        ReasonCode::Unauthenticated => ResultCode::OperationsError,
        ReasonCode::WeakTransport if !transport_sec.encrypted => {
            ResultCode::ConfidentialityRequired
        }
        ReasonCode::WeakTransport => ResultCode::StrongerAuthRequired,
        ReasonCode::CoarseDeny(_)
        | ReasonCode::NoGrant
        | ReasonCode::Acl
        | ReasonCode::TierViolation
        | ReasonCode::Sensitive
        | ReasonCode::NoSuchPath => ResultCode::InsufficientAccessRights,
        ReasonCode::PipFailure
        | ReasonCode::InvalidRequest
        | ReasonCode::SubjectMismatch
        | ReasonCode::Allowed => ResultCode::Other,
    }
}
