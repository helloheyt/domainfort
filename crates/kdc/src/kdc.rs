//! The [`Kdc`] engine: one request in, one reply out.
//!
//! `handle` follows the same shape for every request:
//! 1. bound the size (RFC 4120 7.2.2; main-session decision 12);
//! 2. answer an identical retransmission from the retransmit cache
//!    (RFC 4120 3.1.2, 3.3.2);
//! 3. decode strictly (krb-proto) and dispatch to the AS or TGS exchange;
//! 4. turn the outcome into an AS-REP / TGS-REP or a terse KRB-ERROR — a
//!    refusal in an open FAST conversation armored by keyd's
//!    `seal_fast_error` (RFC 6113 5.4.4; docs/48 §6.1), or, should keyd
//!    refuse to seal it, the same code unarmored (docs/questions/Q-125 item
//!    10); an unavailable keyd or account source is KDC_ERR_SVC_UNAVAILABLE
//!    over TCP and nothing over UDP (docs/50 §3.7, R50-8; A-56) — apply the
//!    UDP size rule (RFC 4120 7.2.1), and emit exactly one audit event
//!    (main-session decision 14), with the armor principal (R48-11).
//!
//! No input path can panic: there is no indexing, unwrap or unchecked
//! arithmetic on request data, and every fallible step maps to a refusal.
//!
//! Spec: RFC 4120 3.1, 3.3, 5.1.4, 5.9.1, 7.2, 7.5.9; RFC 6113 5.4.4;
//! docs/30 §1-§3; docs/48 §2.4, §6; docs/50 §3.7 (R50-8); main-session
//! decisions 1, 11, 12, 14; A-56.

use crate::accounts::{AccountSource, AccountSourceError, NamedPrincipal};
use crate::audit::{ArmorAudit, AuditEvent, AuditOutcome, AuditReason, AuditSink, Exchange};
use crate::config::{ConfigError, KdcConfig, MAX_REQUEST_LEN};
use crate::fast::armored_error_e_data;
use crate::gate::{PolicyInputs, RateLimiter};
use crate::krb_error::{error_message, krb_error, ErrorContext};
use crate::lifetime::TimeRefusal;
use crate::names::tgs_name;
use crate::retransmit::{RetransmitCache, StoredReply};
use crate::time::seconds;
use crate::transport::{FramingError, KdcReply, Peer, Transport};
use keyd_types::{ArmorId, CtxId, FastConversation, IssueError, KeyCustody};
use krb_proto::constants::{
    KDC_ERR_BAD_PVNO, KDC_ERR_CANNOT_POSTDATE, KDC_ERR_NEVER_VALID, KDC_ERR_POLICY,
    KDC_ERR_SVC_UNAVAILABLE, KRB_AP_ERR_MSG_TYPE, KRB_ERR_FIELD_TOOLONG, KRB_ERR_GENERIC,
    KRB_ERR_RESPONSE_TOO_BIG,
};
use krb_proto::{KdcReqBody, KdcRequest, KerberosTime, PaData, Realm};

/// The names one audit event carries. Spec: main-session decision 14;
/// docs/48 §2.4.
struct EventNames {
    exchange: Exchange,
    client: Option<NamedPrincipal>,
    service: Option<NamedPrincipal>,
    armor: ArmorAudit,
}

/// A refusal: the RFC 4120 error code sent, the audit-only reason, the
/// e-data of the UNARMORED KRB-ERROR (only ever METHOD-DATA for
/// KDC_ERR_PREAUTH_REQUIRED, RFC 4120 5.9.1), and the padata keyd seals into
/// the KrbFastResponse when the request's FAST conversation is open
/// (RFC 6113 5.4.4: "The KDC MUST include all the padata elements such as
/// PA-ETYPE-INFO2 ... in the KrbFastResponse structure").
/// Spec: RFC 4120 5.9.1, 7.5.9; RFC 6113 5.4.4; docs/48 §6.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) code: i32,
    pub(crate) reason: AuditReason,
    pub(crate) e_data: Option<Vec<u8>>,
    pub(crate) fast_padata: Vec<PaData>,
}

impl Refusal {
    pub(crate) fn new(code: i32, reason: AuditReason) -> Self {
        Refusal {
            code,
            reason,
            e_data: None,
            fast_padata: Vec::new(),
        }
    }

    /// The same refusal with `padata` for the sealed KrbFastResponse.
    /// Spec: RFC 6113 5.4.4.
    pub(crate) fn with_fast_padata(mut self, padata: Vec<PaData>) -> Self {
        self.fast_padata = padata;
        self
    }

    /// `true` for the refusal of an unavailable keyd or account source —
    /// the only refusals with code KDC_ERR_SVC_UNAVAILABLE ([`unavailable`]).
    /// Spec: RFC 4120 7.5.9; docs/50 §3.7.
    pub(crate) fn is_unavailable(&self) -> bool {
        self.code == KDC_ERR_SVC_UNAVAILABLE
    }
}

/// Internal failures that leave no specific RFC 4120 code: KRB_ERR_GENERIC
/// ("Generic error", 7.5.9) without e-text (main-session decision 11).
pub(crate) fn internal(reason: AuditReason) -> Refusal {
    Refusal::new(KRB_ERR_GENERIC, reason)
}

/// A dependency did not serve the request: KDC_ERR_SVC_UNAVAILABLE ("29 A
/// service is not available", RFC 4120 7.5.9) — never a code that reads as
/// a wrong password or a forged request (docs/50 §3.7, R50-8). Over UDP
/// nothing is sent (`Kdc::deliver_refusal`).
/// Spec: RFC 4120 7.5.9; docs/50 §3.7 (R50-8); docs/questions/Q-217 (A-56).
pub(crate) fn unavailable(reason: AuditReason) -> Refusal {
    Refusal::new(KDC_ERR_SVC_UNAVAILABLE, reason)
}

/// keyd did not serve a call: the `Unavailable` variant of any of its errors
/// — its startup hold-down (RFC 4120 3.2.3), or keyd down / a deadline /
/// Busy at an IPC client. keyd decides it before any secret-dependent work
/// and independently of the request's content, so the distinct code is no
/// oracle (A-56).
/// Spec: RFC 4120 3.2.3, 7.5.9; docs/50 R50-6, R50-8; docs/questions/Q-217,
/// Q-222 (A-56).
pub(crate) fn custody_unavailable() -> Refusal {
    unavailable(AuditReason::CustodyUnavailable)
}

/// An account-source failure: `Unavailable` (the source cannot be reached)
/// → KDC_ERR_SVC_UNAVAILABLE; `Failed` (it cannot tell) → KRB_ERR_GENERIC
/// (main-session decision 3). Either way the request fails closed.
/// Spec: main-session decision 3; RFC 4120 7.5.9; docs/50 §3.7 (R50-8:
/// "dird down ⇒ fail closed with an explicit `Unavailable`"); A-56.
pub(crate) fn account_source_refusal(error: AccountSourceError) -> Refusal {
    match error {
        AccountSourceError::Unavailable => unavailable(AuditReason::AccountSourceUnavailable),
        AccountSourceError::Failed => internal(AuditReason::AccountSourceFailure),
    }
}

/// RFC 4120 3.1.3 / 3.3.3 time refusals.
pub(crate) fn time_refusal(refusal: TimeRefusal) -> Refusal {
    match refusal {
        TimeRefusal::CannotPostdate => {
            Refusal::new(KDC_ERR_CANNOT_POSTDATE, AuditReason::CannotPostdate)
        }
        TimeRefusal::NeverValid => Refusal::new(KDC_ERR_NEVER_VALID, AuditReason::NeverValid),
        TimeRefusal::OutOfRange => internal(AuditReason::ClockOutOfRange),
    }
}

/// keyd's issuance errors (docs/10 §9). `BadTemplate` means keyd's template
/// validation — the final check (main-session decision 10) — rejected what the
/// KDC planned under the same policy: a policy refusal, KDC_ERR_POLICY.
/// `Denied` is an authorization, token, binding or key failure inside keyd
/// that the KDC cannot explain to the client: KRB_ERR_GENERIC. `Unavailable`
/// is keyd not serving the call: KDC_ERR_SVC_UNAVAILABLE ([`custody_unavailable`]).
/// Spec: docs/10 §9; RFC 4120 7.5.9; A-56.
pub(crate) fn issue_refusal(error: IssueError) -> Refusal {
    match error {
        IssueError::BadTemplate => Refusal::new(KDC_ERR_POLICY, AuditReason::TemplateRejected),
        IssueError::Denied => internal(AuditReason::IssueDenied),
        IssueError::Unavailable => custody_unavailable(),
    }
}

/// What an exchange knows about its request: the names for the audit event
/// and the fields of a KRB-ERROR, and — once keyd opened the request's FAST
/// armor — the armor principal and the conversation whose token seals every
/// later refusal (docs/48 §6).
/// Spec: RFC 4120 5.9.1; RFC 6113 5.4.4; docs/48 §2.4, §6; main-session
/// decisions 11, 14.
#[derive(Debug, Clone)]
pub(crate) struct Scope {
    pub(crate) exchange: Exchange,
    pub(crate) error: ErrorContext,
    pub(crate) client: Option<NamedPrincipal>,
    pub(crate) service: Option<NamedPrincipal>,
    /// The armor ticket's client (R48-11).
    pub(crate) armor: Option<NamedPrincipal>,
    /// The open FAST conversation: refusals are sealed by keyd under its
    /// armor key (docs/48 §6.1, R48-6). `None` before the armor is
    /// established and for unarmored requests (docs/48 §6.2).
    pub(crate) conversation: Option<FastConversation>,
}

impl Scope {
    /// The scope of a decoded request: realm / sname from the body (else the
    /// KDC's own), and — for an AS-REQ — the requested client, which the KDC
    /// "knows" from the request (RFC 4120 5.9.1). A TGS client is known only
    /// once keyd has verified the TGT.
    fn of(exchange: Exchange, body: &KdcReqBody, local: &ErrorContext) -> Self {
        let sname = body.sname.clone().unwrap_or_else(|| local.sname.clone());
        let as_client = match exchange {
            Exchange::As => body.cname.clone(),
            Exchange::Tgs => None,
        };
        Scope {
            exchange,
            error: ErrorContext {
                realm: body.realm.clone(),
                sname,
                crealm: as_client.as_ref().map(|_| body.realm.clone()),
                cname: as_client.clone(),
            },
            client: as_client.map(|name| NamedPrincipal {
                realm: body.realm.clone(),
                name,
            }),
            service: body.sname.clone().map(|name| NamedPrincipal {
                realm: body.realm.clone(),
                name,
            }),
            armor: None,
            conversation: None,
        }
    }

    /// keyd opened the armor of an AS request: from now on the request is
    /// the INNER one — its names identify the client and the service in
    /// replies, errors and audit ("A conforming KDC ignores the outer
    /// KDC-REQ-BODY field"; docs/48 §8) — and every refusal is sealed in the
    /// conversation `armor_id` (docs/48 §6.1).
    /// Spec: RFC 6113 5.4.2, 5.4.5; RFC 4120 5.9.1; docs/48 §4.1 A4, §6.
    pub(crate) fn armor_as(
        &mut self,
        inner: &KdcReqBody,
        local: &ErrorContext,
        armor: NamedPrincipal,
        armor_id: ArmorId,
    ) {
        *self = Scope {
            armor: Some(armor),
            conversation: Some(FastConversation::As(armor_id)),
            ..Scope::of(Exchange::As, inner, local)
        };
    }

    /// Record the client keyd verified (TGS). Spec: RFC 4120 5.9.1.
    pub(crate) fn set_client(&mut self, realm: &Realm, name: &krb_proto::PrincipalName) {
        self.error.crealm = Some(realm.clone());
        self.error.cname = Some(name.clone());
        self.client = Some(NamedPrincipal {
            realm: realm.clone(),
            name: name.clone(),
        });
    }

    /// keyd verified an armored TGS request (implicit armor, RFC 6113
    /// 5.4.2): the TGT's client is the client and also the armor principal
    /// (its TGT is the armor ticket); the service and the KRB-ERROR's realm /
    /// sname are the INNER request's — keyd checked that its realm is this
    /// realm — and every refusal is sealed in the conversation `ctx_id`.
    /// Spec: RFC 6113 5.4.2, 5.4.4; RFC 4120 5.9.1; docs/48 §5.2, §6;
    /// docs/questions/Q-150 item 5.
    pub(crate) fn armor_tgs(
        &mut self,
        inner: &KdcReqBody,
        local: &ErrorContext,
        crealm: &Realm,
        cname: &krb_proto::PrincipalName,
        ctx_id: CtxId,
    ) {
        let mut scope = Scope::of(Exchange::Tgs, inner, local);
        scope.set_client(crealm, cname);
        scope.armor = scope.client.clone();
        scope.conversation = Some(FastConversation::Tgs(ctx_id));
        *self = scope;
    }

    /// The FAST audit facts of this request, given whether the reply sent
    /// was armored. Spec: docs/48 §2.4.
    fn armor_audit(&self, reply_armored: bool) -> ArmorAudit {
        ArmorAudit {
            principal: self.armor.clone(),
            reply_armored,
        }
    }
}

/// The phase-1 KDC.
///
/// Generic over the key custody `K` (keyd), the audit sink `U` and the rate
/// limiter `R`. Holds no secret. The [`AccountSource`] is not held: it is
/// passed with each request, alongside the [`PolicyInputs`], so that the
/// account records and the PIP answers of one request come from one
/// directory snapshot (docs/47 §8.1, R47-14). Operations take `&mut self`;
/// the daemon serializes access (no threads here).
///
/// Spec: docs/30 §1-§3; docs/47 §8.1, §10.1 (R47-14); main-session
/// decisions 1, 3, 7.
pub struct Kdc<K: KeyCustody, U: AuditSink, R: RateLimiter> {
    pub(crate) config: KdcConfig,
    pub(crate) custody: K,
    pub(crate) audit: U,
    pub(crate) rate: R,
    pub(crate) retransmit: RetransmitCache,
    /// The KDC's own realm and TGS name, for KRB-ERRORs about requests whose
    /// names are unknown (RFC 4120 5.9.1, 7.3).
    pub(crate) local: ErrorContext,
}

impl<K: KeyCustody, U: AuditSink, R: RateLimiter> Kdc<K, U, R> {
    /// Build a KDC. The configuration is validated against keyd's first
    /// (fail closed). Spec: RFC 4120 7.2, 7.3; main-session decisions 1, 3.
    pub fn new(config: KdcConfig, custody: K, audit: U, rate: R) -> Result<Self, ConfigError> {
        config.validate(custody.config())?;
        let local = ErrorContext::local(&config.realm).ok_or(ConfigError::RealmMismatch)?;
        Ok(Kdc {
            retransmit: RetransmitCache::new(
                config.retransmit_capacity,
                config.retransmit_max_octets,
            ),
            config,
            custody,
            audit,
            rate,
            local,
        })
    }

    /// Answer one request: an AS-REQ or TGS-REQ message as it arrived (one
    /// UDP datagram, or one TCP record without its length prefix).
    ///
    /// - longer than [`MAX_REQUEST_LEN`]: over TCP KRB_ERR_FIELD_TOOLONG and
    ///   close (RFC 4120 7.2.2, 7.5.9); over UDP nothing;
    /// - identical to a recently answered request: the same reply
    ///   (RFC 4120 3.1.2, 3.3.2);
    /// - not decodable: over UDP nothing (RFC 4120 5.1.4; see below); over
    ///   TCP KRB_AP_ERR_MSG_TYPE for an unknown message tag (5.1.4),
    ///   KDC_ERR_BAD_PVNO for a protocol version other than 5 (7.5.9), and
    ///   KRB_ERR_GENERIC for anything else — no other RFC 4120 code
    ///   describes a malformed AS-REQ / TGS-REQ;
    /// - otherwise the AS or TGS exchange, reading principals from
    ///   `accounts` — the account source of this request, taken from the
    ///   same consistent view as `policy` (docs/47 §8.1, R47-14).
    ///
    /// UDP silence for every undecodable datagram extends 5.1.4's rule for
    /// unknown tags ("in order to avoid denial of service attacks"): an
    /// undecodable datagram has no realm, names or nonce the client could
    /// use, and replying to arbitrary bytes would make the KDC a reflector.
    /// Clients MUST support TCP (7.2.2), where every such request is
    /// answered.
    ///
    /// Spec: RFC 4120 3.1.2, 3.3.2, 5.1.4, 7.2.1, 7.2.2, 7.5.9; docs/47
    /// §10.1 (R47-14); main-session decisions 1, 11, 12.
    pub fn handle(
        &mut self,
        request: &[u8],
        peer: Peer,
        now: KerberosTime,
        policy: &PolicyInputs<'_>,
        accounts: &dyn AccountSource,
    ) -> KdcReply {
        if request.len() > MAX_REQUEST_LEN {
            return self.refuse_unscoped(
                peer,
                now,
                KRB_ERR_FIELD_TOOLONG,
                AuditReason::RequestTooLong,
                true,
            );
        }
        let now_secs = seconds(&now);
        if let Some(stored) = self.retransmit.lookup(request, now_secs).cloned() {
            return self.deliver_reply(&stored, peer, now, AuditReason::Retransmission);
        }
        match KdcRequest::decode(request) {
            Err(error) => {
                let (code, reason) = match error {
                    krb_proto::Error::UnexpectedApplicationTag
                    | krb_proto::Error::ExpectedApplicationTag => {
                        (KRB_AP_ERR_MSG_TYPE, AuditReason::UnsupportedMessageType)
                    }
                    krb_proto::Error::InvalidPvno => {
                        (KDC_ERR_BAD_PVNO, AuditReason::BadProtocolVersion)
                    }
                    krb_proto::Error::MessageTooLarge => {
                        (KRB_ERR_FIELD_TOOLONG, AuditReason::RequestTooLong)
                    }
                    _ => (KRB_ERR_GENERIC, AuditReason::Malformed),
                };
                self.refuse_unscoped(peer, now, code, reason, false)
            }
            Ok(KdcRequest::As(as_req)) => {
                let mut scope = Scope::of(Exchange::As, &as_req.0.req_body, &self.local);
                let result =
                    self.receive_as_req(&as_req.0, &mut scope, peer, &now, policy, accounts);
                self.conclude(request, result, &scope, peer, now)
            }
            Ok(KdcRequest::Tgs(tgs_req)) => {
                let mut scope = Scope::of(Exchange::Tgs, &tgs_req.0.req_body, &self.local);
                let result =
                    self.receive_tgs_req(&tgs_req.0, &mut scope, peer, &now, policy, accounts);
                self.conclude(request, result, &scope, peer, now)
            }
        }
    }

    /// Answer a TCP framing error found by [`crate::tcp_decode_frame`]:
    /// KRB_ERR_FIELD_TOOLONG, then close the stream. RFC 4120 7.2.2 requires
    /// exactly this for a set reserved bit ("MUST return a KRB-ERROR message
    /// with the error KRB_ERR_FIELD_TOOLONG and MUST close the TCP stream");
    /// a length above [`MAX_REQUEST_LEN`] is answered the same way (7.5.9:
    /// "Field is too long for this implementation").
    ///
    /// Spec: RFC 4120 7.2.2, 7.5.9; main-session decision 12.
    pub fn reject_frame(&mut self, error: FramingError, peer: Peer, now: KerberosTime) -> KdcReply {
        let reason = match error {
            FramingError::ReservedBitSet => AuditReason::ReservedLengthBit,
            FramingError::TooLong => AuditReason::RequestTooLong,
        };
        let peer = Peer {
            transport: Transport::Tcp,
            ..peer
        };
        self.refuse_unscoped(peer, now, KRB_ERR_FIELD_TOOLONG, reason, true)
    }

    /// The configuration in force.
    pub fn config(&self) -> &KdcConfig {
        &self.config
    }

    /// The key custody (e.g. to read keyd's own audit).
    pub fn custody(&self) -> &K {
        &self.custody
    }

    /// Mutable access to the key custody.
    pub fn custody_mut(&mut self) -> &mut K {
        &mut self.custody
    }

    /// The audit sink.
    pub fn audit_sink(&self) -> &U {
        &self.audit
    }

    /// Mutable access to the audit sink (e.g. to drain it).
    pub fn audit_sink_mut(&mut self) -> &mut U {
        &mut self.audit
    }

    /// Mutable access to the rate limiter.
    pub fn rate_limiter_mut(&mut self) -> &mut R {
        &mut self.rate
    }

    // ------------------------------------------------------------------
    // Outcome → reply + one audit event.
    // ------------------------------------------------------------------

    /// Emit the one audit event of a request. Spec: main-session decision 14;
    /// docs/48 §2.4 (R48-11).
    fn record(
        &mut self,
        peer: Peer,
        now: KerberosTime,
        names: Option<EventNames>,
        outcome: AuditOutcome,
        reason: AuditReason,
    ) {
        let (exchange, client, service, armor) = match names {
            Some(n) => (Some(n.exchange), n.client, n.service, n.armor),
            None => (None, None, None, ArmorAudit::default()),
        };
        self.audit.record(&AuditEvent {
            time: now,
            transport: peer.transport,
            exchange,
            client,
            service,
            armor,
            outcome,
            reason,
        });
    }

    /// A request refused before any name was known. Over UDP nothing is sent
    /// (RFC 4120 5.1.4); over TCP the KRB-ERROR names the KDC's own realm and
    /// TGS, and `close` asks the daemon to close the stream (7.2.2).
    fn refuse_unscoped(
        &mut self,
        peer: Peer,
        now: KerberosTime,
        code: i32,
        reason: AuditReason,
        close: bool,
    ) -> KdcReply {
        if peer.transport == Transport::Udp {
            self.record(peer, now, None, AuditOutcome::Dropped, reason);
            return KdcReply::Silent;
        }
        match krb_error(code, &self.local, now, None) {
            Some(bytes) => {
                self.record(
                    peer,
                    now,
                    None,
                    AuditOutcome::Refused { error_code: code },
                    reason,
                );
                if close {
                    KdcReply::SendAndClose(bytes)
                } else {
                    KdcReply::Send(bytes)
                }
            }
            None => {
                self.record(peer, now, None, AuditOutcome::Dropped, reason);
                KdcReply::Silent
            }
        }
    }

    /// Finish a decoded request. Spec: RFC 4120 3.1.2, 5.9.1, 7.2.1.
    fn conclude(
        &mut self,
        request: &[u8],
        result: Result<Vec<u8>, Refusal>,
        scope: &Scope,
        peer: Peer,
        now: KerberosTime,
    ) -> KdcReply {
        match result {
            Ok(reply) => {
                let stored = StoredReply {
                    reply,
                    error: scope.error.clone(),
                    exchange: scope.exchange,
                    client: scope.client.clone(),
                    service: scope.service.clone(),
                    // A reply in an armored conversation carries PA-FX-FAST
                    // (RFC 6113 5.4.3; both exchanges frame it).
                    armor: scope.armor_audit(scope.conversation.is_some()),
                };
                let now_secs = seconds(&now);
                let expires_at = now_secs + i64::from(self.custody.config().clock_skew_secs);
                self.retransmit
                    .insert(request, stored.clone(), now_secs, expires_at);
                self.deliver_reply(&stored, peer, now, AuditReason::Issued)
            }
            Err(refusal) => self.deliver_refusal(refusal, scope, peer, now),
        }
    }

    /// Send an AS-REP / TGS-REP, or KRB_ERR_RESPONSE_TOO_BIG if it does not
    /// fit the UDP limit ("the KDC MUST return KRB_ERR_RESPONSE_TOO_BIG,
    /// forcing the client to retry the request using the TCP transport"); the
    /// reply stays in the retransmit cache for that retry.
    /// Spec: RFC 4120 7.2.1, 3.1.2.
    fn deliver_reply(
        &mut self,
        stored: &StoredReply,
        peer: Peer,
        now: KerberosTime,
        reason: AuditReason,
    ) -> KdcReply {
        let mut names = Some(EventNames {
            exchange: stored.exchange,
            client: stored.client.clone(),
            service: stored.service.clone(),
            armor: stored.armor.clone(),
        });
        if peer.transport == Transport::Udp && stored.reply.len() > self.config.udp_max_reply_len {
            // What goes out is the (unarmored) RESPONSE_TOO_BIG.
            if let Some(n) = names.as_mut() {
                n.armor.reply_armored = false;
            }
            return match self.too_big_for_udp(&stored.error, now) {
                Some(bytes) => {
                    self.record(
                        peer,
                        now,
                        names,
                        AuditOutcome::Refused {
                            error_code: KRB_ERR_RESPONSE_TOO_BIG,
                        },
                        AuditReason::ReplyTooBigForUdp,
                    );
                    KdcReply::Send(bytes)
                }
                None => {
                    self.record(peer, now, names, AuditOutcome::Dropped, reason);
                    KdcReply::Silent
                }
            };
        }
        self.record(peer, now, names, AuditOutcome::Issued, reason);
        KdcReply::Send(stored.reply.clone())
    }

    /// The e-data of an ARMORED refusal: keyd seals the KrbFastResponse —
    /// the refusal's padata plus PA-FX-ERROR, the KRB-ERROR without e-data
    /// ("All other fields should be the same as the outer KRB-ERROR") — and
    /// consumes the conversation's token; the KDC frames it as METHOD-DATA
    /// with PA-FX-FAST. `None` if keyd refused or an encoding failed: the
    /// caller then sends the same code unarmored (docs/questions/Q-125 item
    /// 10: an unprotected error rather than silence).
    /// Spec: RFC 6113 5.4.3 (no strengthen-key, no finished in an error —
    /// keyd's check), 5.4.4; docs/48 §6.1, §6.2 item 3.
    fn seal_refusal(
        &mut self,
        conversation: &FastConversation,
        refusal: &Refusal,
        ctx: &ErrorContext,
        now: KerberosTime,
    ) -> Option<Vec<u8>> {
        let fx_error = error_message(refusal.code, ctx, now, None);
        let sealed = self
            .custody
            .seal_fast_error(conversation, &fx_error, &refusal.fast_padata, &now)
            .ok()?;
        armored_error_e_data(sealed)
    }

    /// Send the KRB-ERROR of a refusal (no e-text; e-data only for
    /// PREAUTH_REQUIRED, or the PA-FX-FAST of an armored error), with the
    /// request's names, falling back to the KDC's own; over UDP,
    /// KRB_ERR_RESPONSE_TOO_BIG if it does not fit. In an open FAST
    /// conversation the refusal is armored (docs/48 §6.1, R48-6).
    ///
    /// An unavailable keyd or account source ([`Refusal::is_unavailable`])
    /// is answered KDC_ERR_SVC_UNAVAILABLE over TCP and with nothing over
    /// UDP ("in TCP, and silence in UDP", docs/50 §3.7 — the KDC's UDP
    /// silence rule, RFC 4120 5.1.4, extended as for undecodable datagrams).
    /// When it is keyd that did not serve, the refusal is not sent to keyd to
    /// be sealed — that would meet the same unavailable keyd (over IPC, the
    /// same deadline again) — and goes out unarmored, as when keyd refuses to
    /// seal (docs/questions/Q-125 item 10).
    ///
    /// Spec: RFC 4120 5.1.4, 5.9.1, 7.2.1, 7.5.9; RFC 6113 5.4.4; docs/48 §6;
    /// docs/50 §3.7 (R50-8); main-session decision 11; A-56.
    fn deliver_refusal(
        &mut self,
        refusal: Refusal,
        scope: &Scope,
        peer: Peer,
        now: KerberosTime,
    ) -> KdcReply {
        let names = |armored: bool| {
            Some(EventNames {
                exchange: scope.exchange,
                client: scope.client.clone(),
                service: scope.service.clone(),
                armor: scope.armor_audit(armored),
            })
        };
        if refusal.is_unavailable() && peer.transport == Transport::Udp {
            self.record(
                peer,
                now,
                names(false),
                AuditOutcome::Dropped,
                refusal.reason,
            );
            return KdcReply::Silent;
        }
        let code = refusal.code;
        let (e_data, reply_armored) = match &scope.conversation {
            None => (refusal.e_data.clone(), false),
            Some(_) if refusal.reason == AuditReason::CustodyUnavailable => {
                (refusal.e_data.clone(), false)
            }
            Some(conversation) => {
                match self.seal_refusal(conversation, &refusal, &scope.error, now) {
                    Some(armored) => (Some(armored), true),
                    None => (refusal.e_data.clone(), false),
                }
            }
        };
        // (octets, code sent, whether they carry the armored e-data)
        let encoded = match krb_error(code, &scope.error, now, e_data) {
            Some(bytes) => Some((bytes, reply_armored)),
            None => krb_error(code, &self.local, now, None).map(|bytes| (bytes, false)),
        };
        let sent = match encoded {
            Some((bytes, _))
                if peer.transport == Transport::Udp
                    && bytes.len() > self.config.udp_max_reply_len =>
            {
                self.too_big_for_udp(&scope.error, now)
                    .map(|b| (b, KRB_ERR_RESPONSE_TOO_BIG, false))
            }
            Some((bytes, armored)) => Some((bytes, code, armored)),
            None => None,
        };
        match sent {
            Some((bytes, code, armored)) => {
                self.record(
                    peer,
                    now,
                    names(armored),
                    AuditOutcome::Refused { error_code: code },
                    refusal.reason,
                );
                KdcReply::Send(bytes)
            }
            None => {
                self.record(
                    peer,
                    now,
                    names(false),
                    AuditOutcome::Dropped,
                    refusal.reason,
                );
                KdcReply::Silent
            }
        }
    }

    /// KRB_ERR_RESPONSE_TOO_BIG within the UDP limit: with the request's
    /// names, else the KDC's own (whose size `KdcConfig::validate` checked).
    /// Spec: RFC 4120 7.2.1.
    fn too_big_for_udp(&self, ctx: &ErrorContext, now: KerberosTime) -> Option<Vec<u8>> {
        let limit = self.config.udp_max_reply_len;
        krb_error(KRB_ERR_RESPONSE_TOO_BIG, ctx, now, None)
            .filter(|bytes| bytes.len() <= limit)
            .or_else(|| {
                krb_error(KRB_ERR_RESPONSE_TOO_BIG, &self.local, now, None)
                    .filter(|bytes| bytes.len() <= limit)
            })
    }
}

/// The TGS name of the KDC's realm, for templates. Spec: RFC 4120 7.3.
pub(crate) fn local_tgs_name(realm: &Realm) -> Result<krb_proto::PrincipalName, Refusal> {
    tgs_name(realm).ok_or_else(|| internal(AuditReason::InternalFailure))
}
