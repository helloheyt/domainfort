//! The per-connection session state (docs/49 §4.4, R49-15).
//!
//! # The state machine
//!
//! ```text
//!   Session::new(Ldap)  ── channel Cleartext ─┐      Session::new(Ldaps) ── channel Ldaps
//!                                             │
//!   Open{Cleartext} ──StartTLS success──► StartTlsPending ──next request, TLS up──► Open{StartTls}
//!                                             └──next request, TLS not up──► Closed
//!   Open{*} ──Unbind / Notice of Disconnection / malformed / transport mismatch──► Closed
//!   identity: Anonymous ◄──every Bind (RFC 4513 §4)── Bound (task L7)
//! ```
//!
//! - **channel** — whether TLS protects the connection, and how it came to:
//!   [`Listener::Ldaps`] has TLS from the first octet ([MS-ADTS] 5.1.2.2);
//!   [`Listener::Ldap`] is cleartext until a successful StartTLS (RFC 4511
//!   §4.14; RFC 4513 §3). The engine owns this state; the front's per-request
//!   report must agree with it, or the connection closes (docs/49 §4.4: TLS
//!   removal always closes — no return to cleartext).
//! - **phase** — `Open`, `StartTlsPending` (a successful StartTLS response was
//!   sent and the TLS layer is not up yet: any request that reaches the
//!   engine now arrived in cleartext after StartTLS — RFC 4511 §4.14.1 "The
//!   client MUST NOT send any LDAP PDUs ... following this request until it
//!   receives a StartTLS Extended response and ... completes TLS
//!   negotiations" — and closes the connection, docs/49 §4.4), or `Closed`.
//! - **identity** — anonymous from the start (RFC 4513 §4: "Upon initial
//!   establishment of the LDAP session, the session has an anonymous
//!   authorization identity"), reset to anonymous on receipt of every Bind
//!   (RFC 4513 §4: "the server immediately moves the session to an anonymous
//!   authorization state"), and bound only by a successful SASL GSSAPI bind
//!   (task L7 — no path in L4).
//!
//! # The bound identity (seam for task L7)
//!
//! A [`BoundIdentity`] records what keyd's `open_and_verify_service_ticket`
//! reports about the client (realm, name, authtime, endtime — keyd
//! `ServiceContext`, L6a) plus the account SID read at bind time and whether
//! keyd verified the channel binding (A-47). Nothing outside this crate can
//! build one: the only producer will be the GSSAPI bind of task L7, after
//! keyd verified the AP-REQ. Until then only this crate's unit tests build
//! one, to exercise the per-request re-check below.
//!
//! # The per-request re-check (R49-15)
//!
//! Identity is fixed at bind; authorization is derived again for every
//! request from the request's fresh view (docs/49 §4.4, docs/11 P8; RFC 4511
//! §6: "credentials could expire, authorization identities or access
//! controls could change"). For a bound identity, before anything else:
//! 1. `now` past the expiry time → Notice of Disconnection ([MS-ADTS]
//!    5.1.1.6: "the DC MUST NOT execute the LDAP request. Instead, the DC
//!    MUST disconnect the connection and send a Notice of Disconnection");
//! 2. the account, read again through the request's ticket-subject lookup
//!    ([`TicketSubjects`] — directory-pip's one lookup path in the
//!    `TicketClient` context, the same exact name rule the KDC applies to an
//!    AS client: docs/49 §3.2, R47-1; docs/59 §6.2, §6.4), must exist, be
//!    usable now, not revoke the identity's authtime (`revoked_before`, the
//!    RFC 4120 3.3.3.1 hot-list — docs/49 §3.2), and still carry the SID
//!    bound at bind time; otherwise Notice of Disconnection. A failing
//!    lookup is a failure too (fail closed).
//!
//! The re-check reads only the facts it uses (state, SID, groups, tier) and
//! never the KDC's account source: those records carry dird's attested name
//! resolution for keyd, which no LDAP session reads (task PN10b;
//! docs/questions/Q-1047, A-187).
//!
//! The groups and tier of the request's PDP subject come from this fresh
//! record, never from bind time. Both failures use `strongerAuthRequired`
//! (docs/49 §4.4, §9; Q-169 item 5 — "an established security association
//! ... has unexpectedly failed", RFC 4511 §4.4.1).
//!
//! Spec: RFC 4511 §4.4.1, §4.14, §6; RFC 4513 §3.1.1, §4; [MS-ADTS]
//! 5.1.1.6, 5.1.2.2; docs/49 §3.2, §4.3, §4.4 (R49-15); A-47 (Q-163).

use core::time::Duration;
use std::collections::BTreeSet;

use directory_pip::TicketSubjects;
use dtyp::Sid;
use kdc::NamedPrincipal;
use krb_proto::KerberosTime;
use parse_ldap::AuthState;
use pdp::Tier;

use crate::time::seconds_between;

/// Which listener accepted the connection. Spec: docs/49 §4.1 (LDAPS on 636,
/// StartTLS on 389); [MS-ADTS] 5.1.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Listener {
    /// Cleartext LDAP; TLS only after a successful StartTLS.
    /// Spec: RFC 4511 §4.14; RFC 4513 §3.
    Ldap,
    /// LDAP over TLS from the first octet. Spec: [MS-ADTS] 5.1.2.2.
    Ldaps,
}

/// Whether TLS protects the connection, and how. Spec: docs/49 §4.3, §10.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Channel {
    /// No TLS layer.
    Cleartext,
    /// TLS from the first octet.
    Ldaps,
    /// TLS installed by StartTLS.
    StartTls,
}

impl Channel {
    pub(crate) fn tls(self) -> bool {
        !matches!(self, Channel::Cleartext)
    }
}

/// Where the session is in its life. Spec: module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Requests are processed.
    Open,
    /// A successful StartTLS response was sent; TLS is not up yet.
    /// Spec: RFC 4511 §4.14.1, §4.14.2; docs/49 §4.4.
    StartTlsPending,
    /// The session ended; nothing more is processed. Spec: RFC 4511 §5.3.
    Closed,
}

/// A bound identity (module documentation: the seam for task L7). Holds no
/// secret: no key, ticket or session key — keyd keeps those (A-46).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundIdentity {
    /// The client principal keyd verified (crealm, cname).
    pub(crate) principal: NamedPrincipal,
    /// The account SID read through the ticket-subject lookup at bind time.
    pub(crate) sid: Sid,
    /// The ticket's authtime (hot-list check). Spec: RFC 4120 5.3.
    pub(crate) authtime: KerberosTime,
    /// The ticket's endtime: the connection's expiry time.
    /// Spec: [MS-ADTS] 5.1.1.6; RFC 4120 5.3.
    pub(crate) endtime: KerberosTime,
    /// keyd verified the channel binding of this bind (A-47). Only then are
    /// `sealed` / `channel_bound` reported to the PDP (docs/49 §4.3).
    pub(crate) channel_bound: bool,
}

/// The session's authorization identity. Spec: RFC 4513 §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Identity {
    /// The anonymous authorization state.
    Anonymous,
    /// A bound identity (task L7).
    // Built by the GSSAPI bind of task L7; in L4 only by the unit tests.
    #[cfg_attr(not(test), allow(dead_code))]
    Bound(BoundIdentity),
}

/// One LDAP connection's state. Created by the front when it accepts a
/// connection and passed to every [`crate::Engine::handle`] call for it.
/// Spec: module documentation; docs/49 §4.4 (R49-15).
#[derive(Debug, Clone)]
pub struct Session {
    pub(crate) connection_id: u64,
    pub(crate) channel: Channel,
    pub(crate) phase: Phase,
    pub(crate) identity: Identity,
}

impl Session {
    /// A new connection: anonymous (RFC 4513 §4), open, with TLS exactly when
    /// it came in on the LDAPS listener.
    /// Spec: RFC 4513 §4; [MS-ADTS] 5.1.2.2; docs/49 §4.4.
    #[must_use]
    pub fn new(connection_id: u64, listener: Listener) -> Session {
        Session {
            connection_id,
            channel: match listener {
                Listener::Ldap => Channel::Cleartext,
                Listener::Ldaps => Channel::Ldaps,
            },
            phase: Phase::Open,
            identity: Identity::Anonymous,
        }
    }

    /// The caller's connection identifier.
    #[must_use]
    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    /// The authentication state whose size bound the front's framer must
    /// apply to the next message (and the engine applies when decoding it).
    /// Spec: docs/49 §2.4 (the bound "of the current authentication state,
    /// before any allocation"); [MS-ADTS] 3.1.1.3.4.6.
    #[must_use]
    pub fn auth_state(&self) -> AuthState {
        match self.identity {
            Identity::Anonymous => AuthState::Unauthenticated,
            Identity::Bound(_) => AuthState::Authenticated,
        }
    }

    /// `true` once the session has ended; the front closes the connection.
    /// Spec: RFC 4511 §5.3.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }

    /// `true` while a successful StartTLS response awaits the TLS layer: the
    /// front must not hand over cleartext octets that followed the StartTLS
    /// request as if they came inside TLS. Spec: RFC 4511 §4.14.1; docs/49
    /// §4.4.
    #[must_use]
    pub fn start_tls_pending(&self) -> bool {
        self.phase == Phase::StartTlsPending
    }

    /// `true` if TLS protects the connection. Spec: docs/49 §4.3.
    #[must_use]
    pub fn tls_established(&self) -> bool {
        self.channel.tls()
    }

    /// A session already bound to `identity` over the given listener
    /// (TESTS ONLY: the production producer is task L7's GSSAPI bind).
    #[cfg(test)]
    pub(crate) fn bound_for_test(
        connection_id: u64,
        listener: Listener,
        identity: BoundIdentity,
    ) -> Session {
        let mut session = Session::new(connection_id, listener);
        session.identity = Identity::Bound(identity);
        session
    }
}

/// The PDP-relevant facts of a bound identity for one request, from the
/// fresh account record. Spec: docs/49 §3.2 (Subject), §4.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundSubject {
    pub(crate) sid: Sid,
    pub(crate) groups: BTreeSet<Sid>,
    pub(crate) tier: Tier,
    pub(crate) ticket_age: Duration,
    pub(crate) channel_bound: bool,
}

/// The result of the per-request re-check (module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Recheck {
    /// The identity still holds; the request's subject facts.
    Valid(BoundSubject),
    /// `now` exceeds the expiry time. Spec: [MS-ADTS] 5.1.1.6.
    Expired,
    /// The account is gone, unusable, revoked, or names another SID.
    Revoked,
    /// The ticket-subject lookup failed (fail closed).
    Unavailable,
}

/// Re-check a bound identity for one request (module documentation).
/// Spec: [MS-ADTS] 5.1.1.6; docs/49 §3.2, §4.4 (R49-15); RFC 4120 3.3.3.1;
/// docs/59 §6.2 (`TicketClient`); docs/questions/Q-1047 (A-187).
pub(crate) fn recheck(
    identity: &BoundIdentity,
    subjects: &dyn TicketSubjects,
    now: &KerberosTime,
) -> Recheck {
    // "where the current time exceeds the expiry time". Spec: [MS-ADTS]
    // 5.1.1.6.
    if *now > identity.endtime {
        return Recheck::Expired;
    }
    let account = match subjects.ticket_subject(&identity.principal.realm, &identity.principal.name)
    {
        Ok(Some(account)) => account,
        Ok(None) => return Recheck::Revoked,
        Err(_) => return Recheck::Unavailable,
    };
    // Usable now, not on the hot-list, and still the same principal (a name
    // reassigned to a new account carries a new SID — R47-7 also sets
    // `revoked_before` past such a reuse). Spec: docs/49 §3.2; RFC 4120
    // 3.3.3.1.
    if !account.state.usable_at(now)
        || account.state.revokes(&identity.authtime)
        || account.sid != identity.sid
    {
        return Recheck::Revoked;
    }
    // ticket_age = now − authtime (docs/49 §3.2); an authtime ahead of `now`
    // (within keyd's clock skew) counts as age zero.
    let ticket_age = seconds_between(now, &identity.authtime).unwrap_or(Duration::ZERO);
    Recheck::Valid(BoundSubject {
        sid: account.sid,
        groups: account.groups,
        tier: account.tier,
        ticket_age,
        channel_bound: identity.channel_bound,
    })
}
