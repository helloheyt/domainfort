//! The KDC as a Policy Enforcement Point: every AS and TGS step is a PDP
//! decision (docs/30 §1; main-session decision 7).
//!
//! - **When:** AS after keyd's `verify_preauth`; TGS after keyd's
//!   `open_and_verify_tgt` and the account re-read (D53).
//! - **The request:** `Action::KdcAs` / `Action::KdcTgs`; a Subject built from
//!   the account record (SID, expanded groups, tier — authoritative data,
//!   never client-claimed, docs/11 P3), authenticated: `ticket_verified =
//!   true` (at AS the identity was established by keyd's pre-authentication
//!   check; at TGS by keyd's TGT check); `armored` reported truthfully —
//!   `true`, with strength `KerberosFast`, exactly when keyd verified the
//!   FAST armor of this request and the inner request is the one processed
//!   (AS: the armor opened, the armor principal re-evaluated, and the
//!   encrypted challenge verified under that armor; TGS: the implicit armor
//!   verified by `open_and_verify_tgt`), otherwise `false` with strength
//!   `Kerberos` (docs/48 §4.2, R48-10; docs/11 P3) — this is layer 2 of the
//!   mandatory-FAST enforcement (docs/48 §7.2; `pdp::mandatory_fast_rules`);
//!   the resource is the TGT
//!   (AS) or the requested service (TGS); the context has transport
//!   `Kerberos`, `TransportSec::NONE` (no floor for `Kdc*`, A-22), the
//!   daemon-observed source zone and the caller's `now` (P9).
//! - **Deny →** KDC_ERR_POLICY.
//! - **Obligations** (docs/11 §2: "the PEP must honour obligations"): `Audit`
//!   is the KDC's one audit event; `RateLimit` is passed to the caller's
//!   [`RateLimiter`], and a refusal there is a deny; any other obligation
//!   (`Constrain`) has no meaning for the KDC and is a deny (fail closed).
//!
//! Spec: docs/11 §1, §2, §4, §8; docs/30 §1, §2.4, §3.3; docs/48 §4.2, §7.2
//! (R48-8, R48-10); main-session decision 7; A-22; Q-130 item 5.

use crate::accounts::ClientAccount;
use crate::audit::AuditReason;
use core::time::Duration;
use krb_proto::{kerberos_time_to_unix, KerberosTime};
use pdp::{
    AccessRequest, Action, AuthContext, AuthStrength, Context, Effect, Instant, IpScope,
    Obligation, Pip, PolicySnapshot, Resource, RlKey, Subject, TransportSec,
};
use std::collections::BTreeMap;

/// The policy inputs the caller supplies with each request: one consistent
/// snapshot and its PIP (docs/11 §6 snapshot semantics).
/// Spec: main-session decision 7.
#[derive(Clone, Copy)]
pub struct PolicyInputs<'a> {
    /// The versioned policy snapshot.
    pub snapshot: &'a PolicySnapshot,
    /// The policy information point.
    pub pip: &'a dyn Pip,
}

/// Enforces the PDP's `RateLimit` obligation (docs/11 §8). Supplied by the
/// caller, which owns the rate state and its configuration.
/// Spec: docs/11 §2, §8.
pub trait RateLimiter {
    /// Admit one request under `key` at `now`; `false` refuses it.
    fn admit(&mut self, key: &RlKey, now: &KerberosTime) -> bool;
}

/// The PDP question for one exchange.
pub(crate) struct Question<'a> {
    pub(crate) action: Action,
    pub(crate) client: &'a ClientAccount,
    pub(crate) resource: Resource,
    pub(crate) ticket_age: Duration,
    pub(crate) src_net: IpScope,
    pub(crate) now: &'a KerberosTime,
    /// keyd verified the FAST armor of this request (module docs).
    pub(crate) armored: bool,
}

/// Ask the PDP and enforce its decision and obligations.
/// Spec: docs/11 §2, §4, §8; main-session decision 7.
pub(crate) fn enforce(
    question: Question<'_>,
    inputs: &PolicyInputs<'_>,
    rate: &mut dyn RateLimiter,
) -> Result<(), AuditReason> {
    let time = kerberos_time_to_unix(question.now).ok_or(AuditReason::ClockOutOfRange)?;
    // armored ⇔ KerberosFast: the PEP's contract (docs/48 §4.2; Q-130 item 5).
    let strength = if question.armored {
        AuthStrength::KerberosFast
    } else {
        AuthStrength::Kerberos
    };
    let request = AccessRequest {
        subject: Subject {
            principal: question.client.sid,
            groups: question.client.groups.clone(),
            claims: BTreeMap::new(),
            auth: AuthContext {
                strength,
                armored: question.armored,
                ticket_age: question.ticket_age,
                ticket_verified: true,
            },
            tier: question.client.tier,
        },
        resource: question.resource,
        action: question.action,
        context: Context {
            src_net: question.src_net,
            time: Instant(time),
            transport: pdp::Transport::Kerberos,
            transport_sec: TransportSec::NONE,
        },
    };
    let decision = pdp::decide(&request, inputs.snapshot, inputs.pip);
    if decision.effect != Effect::Allow {
        return Err(AuditReason::PolicyDenied(decision.reason));
    }
    for obligation in &decision.obligations {
        match obligation {
            Obligation::Audit => {}
            Obligation::RateLimit(key) => {
                if !rate.admit(key, question.now) {
                    return Err(AuditReason::RateLimited);
                }
            }
            Obligation::Constrain(_) => return Err(AuditReason::UnsupportedObligation),
        }
    }
    Ok(())
}
