//! KDC audit: exactly one event per request, success or failure
//! (main-session decision 14).
//!
//! An event carries only non-secret, fixed-shape data: the caller's time, the
//! transport, which exchange, the client and service names, the outcome (with
//! the RFC 4120 error code sent, if any) and an internal reason code. There is
//! no field that could hold a key, a password, a plaintext, a ticket or any
//! other octet string from the request. The reason goes only here; the client
//! sees the terse KRB-ERROR (no e-text, docs/10 §9, docs/11 §8).
//!
//! Names are client-supplied for refused requests; they are KerberosStrings,
//! which krb-proto restricts to printable ASCII (no control characters, RFC
//! 4120 5.2.1), so a name cannot forge a log line.
//!
//! Spec: main-session decision 14; docs/11 §1b, §8 (reason for audit only;
//! obligation Audit); docs/10 §9-§10; RFC 4120 5.9.1.

use crate::accounts::NamedPrincipal;
use crate::transport::Transport;
use krb_proto::KerberosTime;

/// Which exchange a request belonged to.
/// Spec: RFC 4120 3.1 (AS), 3.3 (TGS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Exchange {
    /// KRB_AS_REQ.
    As,
    /// KRB_TGS_REQ.
    Tgs,
}

/// What the KDC did with a request.
/// Spec: RFC 4120 3.1.3, 3.3.3, 5.9.1, 7.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditOutcome {
    /// An AS-REP or TGS-REP was sent.
    Issued,
    /// A KRB-ERROR with this error code was sent (RFC 4120 7.5.9).
    Refused {
        /// The error code sent.
        error_code: i32,
    },
    /// Nothing was sent (RFC 4120 5.1.4: no reply over UDP to a message the
    /// KDC cannot decode).
    Dropped,
}

/// The internal reason behind an outcome. Never sent to the client.
///
/// Every variant is a unit value or a non-secret code: a reason cannot carry
/// request octets, so it cannot carry a secret.
///
/// Spec: docs/11 §1b, §8; docs/10 §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuditReason {
    /// A ticket was issued.
    Issued,
    /// A retransmitted request was answered with the reply sent the first
    /// time. Spec: RFC 4120 3.1.2, 3.3.2.
    Retransmission,
    /// A ticket was issued, but the reply is too large for UDP; the client
    /// was told to retry over TCP (the reply is kept for that retry).
    /// Spec: RFC 4120 7.2.1, 3.1.2.
    ReplyTooBigForUdp,
    /// The request is longer than [`crate::MAX_REQUEST_LEN`].
    /// Spec: RFC 4120 7.2.2 (KRB_ERR_FIELD_TOOLONG).
    RequestTooLong,
    /// The TCP length prefix had its reserved high bit set.
    /// Spec: RFC 4120 7.2.2.
    ReservedLengthBit,
    /// The message is not an AS-REQ or TGS-REQ (unknown application tag).
    /// Spec: RFC 4120 5.1.4.
    UnsupportedMessageType,
    /// The protocol version number is not 5. Spec: RFC 4120 7.5.6, 7.5.9.
    BadProtocolVersion,
    /// The message has an AS-REQ / TGS-REQ tag but does not decode.
    /// Spec: RFC 4120 5.1.1, 5.4.1.
    Malformed,
    /// The request names another realm (no cross-realm in phase 1).
    /// Spec: main-session decision 4.
    CrossRealm,
    /// AS-REQ without cname, or a request without sname.
    /// Spec: RFC 4120 5.4.1.
    MissingName,
    /// The AS-REQ names a server other than this realm's TGS.
    /// Spec: docs/30 §2 (the AS exchange issues TGTs).
    AsServerNotTgs,
    /// The TGS-REQ asks for a TGS name of this realm. Spec: docs/10 §5.
    TgsForTgs,
    /// A KDC option asks for an operation phase 1 does not implement.
    /// Spec: main-session decision 9.
    UnsupportedOption,
    /// The request carries addresses, additional tickets or
    /// enc-authorization-data, which phase 1 cannot honour.
    /// Spec: RFC 4120 5.4.1; docs/10 §5.
    UnsupportedContent,
    /// The requested starttime is in the future beyond the clock skew.
    /// Spec: RFC 4120 3.1.3, 3.3.3 (KDC_ERR_CANNOT_POSTDATE).
    CannotPostdate,
    /// The ticket would be shorter than the minimum lifetime.
    /// Spec: RFC 4120 3.1.3 (KDC_ERR_NEVER_VALID).
    NeverValid,
    /// The client principal is not in the account source.
    /// Spec: RFC 4120 3.1.3 (KDC_ERR_C_PRINCIPAL_UNKNOWN).
    ClientUnknown,
    /// The service principal is not in the account source.
    /// Spec: RFC 4120 7.5.9 (KDC_ERR_S_PRINCIPAL_UNKNOWN).
    ServiceUnknown,
    /// The client account is disabled, locked, expired or (at TGS time)
    /// no longer present. Spec: main-session decision 8; D53.
    ClientRevoked,
    /// The TGT was issued before the client's revocation instant.
    /// Spec: RFC 4120 3.3.3.1.
    TgtRevoked,
    /// The service account is disabled, locked or expired.
    /// Spec: main-session decision 8.
    ServiceRevoked,
    /// The account source failed (fail closed). Spec: main-session decision 3.
    AccountSourceFailure,
    /// The account source returned an inconsistent record (e.g. a key handle
    /// of the wrong purpose). Spec: docs/10 §2 (I3).
    AccountRecordInvalid,
    /// No requested encryption type is acceptable.
    /// Spec: RFC 4120 3.1.3 (KDC_ERR_ETYPE_NOSUPP); main-session decision 6.
    NoCommonEncType,
    /// The AS-REQ carries no PA-ENC-TIMESTAMP.
    /// Spec: RFC 4120 3.1.3 (KDC_ERR_PREAUTH_REQUIRED).
    PreauthRequired,
    /// The AS-REQ carries more than one PA-ENC-TIMESTAMP (ambiguous).
    PreauthAmbiguous,
    /// The PA-ENC-TIMESTAMP does not decode, or uses an encryption type that
    /// was not negotiated. Spec: RFC 4120 5.2.7.2, 3.1.3.
    PreauthUnacceptable,
    /// keyd refused the pre-authentication (uniform `Denied`: decryption,
    /// key, kvno or decoding failure). Spec: docs/10 §4, §9.
    PreauthDenied,
    /// keyd decrypted the PA-ENC-TIMESTAMP with the client key, but its time
    /// is outside the clock skew (`AuthnError::Skew`, A-26).
    /// Spec: RFC 4120 5.2.7.2, 3.1.3; docs/questions/Q-071.
    PreauthSkew,
    /// The TGS-REQ carries no PA-TGS-REQ.
    /// Spec: RFC 4120 3.3.2 (KDC_ERR_PADATA_TYPE_NOSUPP).
    TgsPadataMissing,
    /// The TGS-REQ carries more than one PA-TGS-REQ (ambiguous).
    TgsPadataAmbiguous,
    /// The PA-TGS-REQ value is not an AP-REQ. Spec: RFC 4120 3.2.3.
    ApReqMalformed,
    /// The presented ticket is not this realm's TGT.
    /// Spec: RFC 4120 3.3.2, 3.2.3 (KRB_AP_ERR_NOT_US).
    NotLocalTgt,
    /// keyd refused the TGT or its authenticator before its cryptographic
    /// chain completed (decryption, kvno, checksum, names, binding, INVALID
    /// flag — keyd does not say which: uniform `Denied`). Spec: docs/10 §5,
    /// §9; RFC 4120 3.3.2; A-26.
    TgtDenied,
    /// The crypto chain passed, but the TGT has expired (A-26).
    /// Spec: RFC 4120 3.2.3 (KRB_AP_ERR_TKT_EXPIRED).
    TgtExpired,
    /// The crypto chain passed, but the TGT is not yet valid (A-26).
    /// Spec: RFC 4120 3.2.3 (KRB_AP_ERR_TKT_NYV).
    TgtNotYetValid,
    /// The crypto chain passed, but the authenticator's ctime is outside the
    /// clock skew (A-26). Spec: RFC 4120 3.2.3 (KRB_AP_ERR_SKEW).
    AuthenticatorSkew,
    /// The crypto chain passed, but the authenticator is a replay (A-26).
    /// Spec: RFC 4120 3.2.3, 3.3.2 (KRB_AP_ERR_REPEAT).
    AuthenticatorReplay,
    /// The PDP denied the request. Spec: docs/11 §4; main-session decision 7.
    PolicyDenied(pdp::ReasonCode),
    /// A PDP RateLimit obligation was not admitted. Spec: docs/11 §2, §8.
    RateLimited,
    /// The PDP attached an obligation the KDC cannot honour (fail closed).
    /// Spec: docs/11 §2 ("the PEP must honour obligations").
    UnsupportedObligation,
    /// The service name cannot be rendered unambiguously for the PDP.
    AmbiguousServiceName,
    /// The caller's `now` is outside the range the KDC can compute with.
    ClockOutOfRange,
    /// keyd refused to issue (token, binding or key failure).
    /// Spec: docs/10 §9 (IssueError::Denied).
    IssueDenied,
    /// keyd rejected the ticket template. Spec: docs/10 §9
    /// (IssueError::BadTemplate).
    TemplateRejected,
    /// An internal encoding step failed.
    InternalFailure,
}

/// One audit event: one per request.
///
/// Spec: main-session decision 14; docs/11 §8 (Audit on every decision).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// The caller-supplied time of the request (the KDC reads no clock).
    pub time: KerberosTime,
    /// The transport the request arrived on.
    pub transport: Transport,
    /// The exchange, when the request decoded as AS-REQ or TGS-REQ.
    pub exchange: Option<Exchange>,
    /// The client: the AS-REQ cname, or the TGT's client once keyd verified
    /// it (TGS).
    pub client: Option<NamedPrincipal>,
    /// The server the ticket was requested for.
    pub service: Option<NamedPrincipal>,
    /// The outcome.
    pub outcome: AuditOutcome,
    /// The internal reason.
    pub reason: AuditReason,
}

/// Where audit events go. The durable sink (append-only, signed, forwarded to
/// the SIEM — docs/37) belongs to the daemon.
///
/// Residual: `record` is infallible here; a durable sink must itself fail
/// closed (e.g. stop the process) if it cannot persist an event.
///
/// Spec: main-session decision 14.
pub trait AuditSink {
    /// Accept one event.
    fn record(&mut self, event: &AuditEvent);
}
