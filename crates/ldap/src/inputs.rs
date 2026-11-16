//! The per-request inputs the caller supplies with each message.
//!
//! As with the KDC (`kdc::Kdc::handle`), the engine is a library PEP: it
//! holds no policy, no directory view and no clock of its own. Each request
//! brings one consistent policy snapshot and its PIP (docs/11 §6 snapshot
//! semantics), the ticket-subject lookup of the same directory view (docs/47
//! §8.1: one view serves as both — `directory_pip::DirectoryView` implements
//! `pdp::Pip` and `directory_pip::TicketSubjects`; never the KDC's account
//! source, whose records carry dird's attested name resolutions — task
//! PN10b, docs/questions/Q-1047), the caller's rate limiter, the
//! caller's `now`, and the transport facts the front observes. For a
//! search, the directory comes as a `directory_pip::PepView`: the
//! visibility gate and the locators of its questions — never the raw
//! snapshot (docs/52 R-a; A-103 on docs/questions/Q-486).
//!
//! Spec: docs/49 §11 (the caller supplies `now`, `source_zone`,
//! `connection_id` and the transport state), §10.2; docs/11 §2, §6, §8;
//! docs/47 §8.1 (R47-11).

use directory_pip::{PepView, TicketSubjects};
use krb_proto::KerberosTime;
use pdp::{IpScope, Pip, PolicySnapshot, RlKey};

/// The transport facts of this message: the zone the caller derived, and
/// what the front observed when it framed the message.
///
/// Deliberately absent: any "channel binding verified" fact. Only keyd's
/// verification of the channel binding inside a GSSAPI bind may set
/// `sealed` / `channel_bound` (A-47, Q-163; docs/49 §4.3: "the PEP never
/// marks `channel_bound` unless keyd returned `channel_bound: true`"); a
/// front-reported flag would let a compromised front claim it (R49-16). The
/// tls-server-end-point value the front computes (docs/49 §4.2) arrives
/// with task L7, which passes it to keyd.
///
/// Spec: docs/49 §4.3, §4.4, §11; RFC 4511 §4.14.1; A-47.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportReport {
    /// The network zone of the peer, as the **caller** derives it — never a
    /// value the front reports: dird gives the zone of the front the client
    /// came through, from the front's peer uid (docs/52 §3.3 C3, §7 R14;
    /// crates/ipc-ldap-server `FrontZone`). Spec: docs/11 §1
    /// (`Context.src_net`); docs/15 §6.
    pub src_net: IpScope,
    /// A TLS layer with an AEAD cipher suite (docs/02 §4) protects the
    /// octets of this message. Must agree with the session's state, which
    /// changes only through LDAPS or StartTLS; a disagreement closes the
    /// connection (docs/49 §4.4).
    pub tls_established: bool,
    /// The front's framer already holds octets after this message: the
    /// client sent more before receiving this message's response. Consulted
    /// for StartTLS only (RFC 4513 §3.1.1: no StartTLS "when there are
    /// outstanding responses for operation requests previously issued";
    /// RFC 4511 §4.14.1; docs/49 §4.4 — injection protection).
    pub input_pending: bool,
}

/// Enforces the PDP's `RateLimit` obligation (docs/11 §8). Supplied by the
/// caller, which owns the rate state and its configuration.
/// Spec: docs/11 §2 ("the PEP must honour obligations"), §8; docs/49 §10.2.
pub trait RateLimiter {
    /// Admit one request under `key` at `now`; `false` refuses it.
    fn admit(&mut self, key: &RlKey, now: &KerberosTime) -> bool;
}

/// The caller's time source during a directory search, which the engine
/// consults between candidates to honour timeLimit and the server's query
/// duration limit. The engine itself reads no clock (docs/49 §11): it asks
/// this source, which the caller owns (and a test drives).
/// Spec: RFC 4511 §4.5.1.5 ("the maximum time (in seconds) allowed for a
/// Search"); [MS-ADTS] 3.1.1.3.4.6 (MaxQueryDuration); docs/49 §6.1 item 7,
/// §11.
pub trait SearchClock {
    /// The caller's current time.
    fn now(&self) -> KerberosTime;
}

/// What a directory search needs beyond the PDP inputs: the request's
/// directory, as a PEP receives it, and the caller's time source.
///
/// The view is one dirstore snapshot (docs/49 §6.1: "against one snapshot";
/// [MS-ADTS] 3.1.1.5.1.4). For a directory search the engine takes every PIP
/// answer from it as well (`PepView::pip`), so the objects it enumerates and
/// the descriptors the PDP reads come from the same snapshot (docs/11 §6
/// P9); the caller passes the same view as `pip` and `accounts` (docs/47
/// §8.1, R47-11). It is a `PepView` — the visibility gate, the locators of
/// its questions and the PIP — never the `DirectoryView`: the engine cannot
/// read a raw object (docs/52 R-a; A-103 on docs/questions/Q-486).
/// Spec: docs/49 §6, §11; docs/47 §8.1; docs/52 R-a.
pub struct DirectoryInputs<'a> {
    /// The request's directory as a PEP receives it
    /// (`PepView::new(&view)`).
    pub view: PepView<'a, 'a>,
    /// The caller's time source (timeLimit).
    pub clock: &'a dyn SearchClock,
}

/// Everything one request is decided against. Spec: module documentation.
pub struct RequestInputs<'a> {
    /// The versioned policy snapshot. Spec: docs/11 §3, §6.
    pub snapshot: &'a PolicySnapshot,
    /// The policy information point of the request's directory view.
    /// Spec: docs/11 §6.
    pub pip: &'a dyn Pip,
    /// The ticket-subject lookup of the same directory view: the
    /// per-request re-check of a bound identity (docs/49 §4.4, R49-15) reads
    /// the bound client's account facts from it — the one lookup path in
    /// the `TicketClient` context, with no name resolution and no signer
    /// (docs/59 §6.2, §6.4; docs/questions/Q-1047, A-187). The field keeps
    /// its name: the account facts of the request's view.
    pub accounts: &'a dyn TicketSubjects,
    /// The caller's rate limiter. Spec: docs/49 §10.2.
    pub rate: &'a mut dyn RateLimiter,
    /// The caller's time. Spec: docs/49 §11; docs/11 P9.
    pub now: KerberosTime,
    /// The transport facts the front observed.
    pub transport: TransportReport,
    /// The directory, for a search of it (docs/49 R49-9, task L8). `None`
    /// for a front that serves only the rootDSE: a directory search is then
    /// unwillingToPerform.
    pub directory: Option<DirectoryInputs<'a>>,
}
