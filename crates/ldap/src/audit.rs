//! LDAP audit: exactly one event per message the engine is handed
//! (docs/49 §10.1, R49-14).
//!
//! Every call of [`crate::Engine::handle`] returns one [`AuditEvent`] inside
//! its [`crate::Outcome`] — success, refusal, malformed input or input after
//! the session closed — so "exactly one" holds by construction (docs/49
//! §11: the engine "returns typed responses + an action + an audit event").
//!
//! An event carries only non-secret, fixed-shape facts: the caller's time,
//! the connection, the source zone, the transport and its security
//! properties, the operation, the MessageID, the principal (a SID — never a
//! client-claimed name), the bind mechanism, the target, the result code
//! sent, the Notice of Disconnection sent, the connection action and an
//! internal reason. There is no field for attribute values, filter assertion
//! values, passwords, SASL credentials or tickets (AGENTS.md §6; docs/07 §8;
//! docs/49 §10.1). A simple-bind password never reaches the engine at all
//! (A-52: the canonical profile carries only an empty-or-placeholder
//! password).
//!
//! Client-supplied strings that docs/49 §10.1 allows in the record (the name
//! of a simple bind, the SASL mechanism name) are kept only when they are
//! printable ASCII of at most [`MAX_AUDIT_TEXT_OCTETS`] octets; otherwise the
//! fixed marker [`AuditText::Withheld`] is recorded, so an attacker cannot
//! forge a log line (docs/07 §8).
//!
//! The reason goes only here; the client sees a bare result code with empty
//! matchedDN and diagnosticMessage (R49-13).
//!
//! Spec: docs/49 §10.1 (R49-14), §9 (R49-13), §11; docs/11 §1b, §8 (the
//! reason is for audit only; obligation Audit); RFC 4513 §5.1.2 (the name of
//! an unauthenticated bind "is intended to be used for trace (e.g., logging)
//! purposes only").

use crate::ConnectionAction;
use dtyp::{Guid, Sid};
use krb_proto::KerberosTime;
use parse_ldap::{MessageId, ResultCode, UnsupportedOp};
use pdp::{IpScope, ReasonCode, TransportSec};

/// Longest client-supplied string kept in an event: 256 octets.
/// Spec: docs/49 §10.1 ("only if printable ASCII and ≤ 256 bytes").
pub const MAX_AUDIT_TEXT_OCTETS: usize = 256;

/// A client-supplied string, kept only when safe to log.
/// Spec: docs/49 §10.1; docs/07 §8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditText {
    /// The string as received: printable ASCII, at most
    /// [`MAX_AUDIT_TEXT_OCTETS`] octets.
    Text(String),
    /// The string was not printable ASCII or was too long; it is not kept.
    Withheld,
}

impl AuditText {
    /// Keep `s` if it is printable ASCII of at most
    /// [`MAX_AUDIT_TEXT_OCTETS`] octets, otherwise the marker.
    /// Spec: docs/49 §10.1.
    pub(crate) fn from_client(s: &str) -> AuditText {
        if s.len() <= MAX_AUDIT_TEXT_OCTETS && s.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
            AuditText::Text(s.to_owned())
        } else {
            AuditText::Withheld
        }
    }
}

/// How the connection is carried, for the record.
/// Spec: docs/49 §10.1 (`transport: Ldap | Ldaps | StartTls`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditTransport {
    /// The cleartext listener, before any TLS layer.
    Ldap,
    /// TLS from the first octet (LDAPS). Spec: [MS-ADTS] 5.1.2.2.
    Ldaps,
    /// The cleartext listener after a successful StartTLS.
    /// Spec: RFC 4511 §4.14; RFC 4513 §3.
    StartTls,
}

/// The operation of the message. Spec: RFC 4511 §4.1.1 (protocolOp);
/// docs/49 §10.1 (`operation: Bind | Search | … | Malformed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOperation {
    /// BindRequest. Spec: RFC 4511 §4.2.
    Bind,
    /// UnbindRequest. Spec: RFC 4511 §4.3.
    Unbind,
    /// SearchRequest. Spec: RFC 4511 §4.5.1.
    Search,
    /// AbandonRequest. Spec: RFC 4511 §4.11.
    Abandon,
    /// ExtendedRequest naming StartTLS. Spec: RFC 4511 §4.14.1.
    StartTls,
    /// ExtendedRequest naming any other operation. Spec: RFC 4511 §4.12.
    Extended,
    /// Modify / Add / Delete / ModifyDN / Compare — recognised, never
    /// performed in phase 1 (A-48). Spec: RFC 4511 §4.6-§4.10.
    NotSupported(UnsupportedOp),
    /// The message did not decode under the canonical profile, or exceeded
    /// the session's size bound. Spec: RFC 4511 §4.1.1; docs/49 §9.
    Malformed,
    /// A message the engine did not decode: the session had closed, a
    /// StartTLS was pending and the message came in cleartext, or the
    /// transport report disagreed with the session (the reason says which).
    /// Spec: RFC 4511 §4.14.1, §5.3; docs/49 §4.4.
    NotDecoded,
}

/// The bind mechanism, as the engine classified it. Never a credential.
/// Spec: RFC 4513 §5.1.1-§5.1.3, §5.2; RFC 4511 §4.2; docs/49 §3.1, §10.1
/// (`bind_mechanism`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindMechanism {
    /// Simple, empty name and empty password. Spec: RFC 4513 §5.1.1.
    SimpleAnonymous,
    /// Simple, non-empty name and empty password. Spec: RFC 4513 §5.1.2.
    SimpleUnauthenticated,
    /// Simple with a non-empty password (whatever the name).
    /// Spec: RFC 4513 §5.1.3.
    SimplePassword,
    /// SASL, with the mechanism name the client sent.
    /// Spec: RFC 4513 §5.2; RFC 4422 §3.1.
    Sasl {
        /// The mechanism name (client-supplied, docs/49 §10.1 rule).
        mechanism: AuditText,
    },
    /// An AuthenticationChoice alternative with no code path here (e.g. the
    /// reserved `[1]`/`[2]`, or the Sicily `[9]`-`[11]` listed in docs/49
    /// §3.1). Spec: RFC 4511 §4.2; docs/49 §2.3 E13, §3.1.
    Unrecognized {
        /// The context-specific tag number.
        tag_number: u8,
    },
}

/// The bind facts of an event. Spec: docs/49 §10.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindAudit {
    /// The LDAP version the client asked for. Spec: RFC 4511 §4.2.
    pub version: u8,
    /// The mechanism.
    pub mechanism: BindMechanism,
    /// The BindRequest name when not empty (client-supplied, never looked
    /// up — docs/49 §3.1; RFC 4513 §5.1.2 "for trace ... purposes only").
    pub name: Option<AuditText>,
}

/// What a request was about, once resolved — never the client's DN string.
/// Spec: docs/49 §10.1 (`target: Option<Guid> — only after resolution`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditTarget {
    /// The rootDSE ([MS-ADTS] 3.1.1.3; `pdp::Resource::RootDse`).
    RootDse,
    /// The directory object a search's base resolved to, by its objectGUID
    /// (recorded whether or not it turned out visible — the record is
    /// internal; the client sees noSuchObject either way). Spec: docs/49
    /// §10.1; [MS-ADTS] 3.1.1.1.3.
    DirObject(Guid),
}

/// The scope of a search. Spec: RFC 4511 §4.5.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditScope {
    /// baseObject.
    BaseObject,
    /// singleLevel.
    SingleLevel,
    /// wholeSubtree.
    WholeSubtree,
    /// A value outside the defined ones (docs/49 §2.3 E14).
    Unrecognized,
}

/// The search facts of an event: counts and schema names only — no
/// attribute value, no assertion value, no client string.
/// Spec: docs/49 §10.1 (`search: { scope, filter_attrs, entries_returned,
/// candidates_visited, pruned_subtrees }`; "DENY is a detection signal" —
/// docs/05 §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchAudit {
    /// The requested scope.
    pub scope: AuditScope,
    /// How many SearchResultEntry messages were sent.
    pub entries_returned: u32,
    /// How many candidate objects were read and evaluated (the visit
    /// budget's counter, crate::search).
    pub candidates_visited: u32,
    /// How many containers were not descended into because the requester
    /// may not list them (docs/49 §6.1 item 3, pruning).
    pub pruned_subtrees: u32,
    /// The lDAPDisplayNames of the recognised attributes the filter names,
    /// sorted, each once (schema constants — never a client spelling).
    /// Lets a broad scan such as `(servicePrincipalName=*)` be detected
    /// (docs/49 §10.1).
    pub filter_attrs: Vec<&'static str>,
}

impl SearchAudit {
    /// The facts of a search of `scope` before anything was counted.
    pub(crate) fn new(scope: AuditScope) -> SearchAudit {
        SearchAudit {
            scope,
            entries_returned: 0,
            candidates_visited: 0,
            pruned_subtrees: 0,
            filter_attrs: Vec::new(),
        }
    }
}

/// The internal reason for an outcome. Never sent to the client.
///
/// Every variant is a unit value or a non-secret code: a reason cannot carry
/// request octets.
///
/// Spec: docs/11 §1b, §8; docs/49 §9, §10.1 (`reason: ReasonCode of the PDP |
/// codec reason | …`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditReason {
    // ---- session and transport ---------------------------------------------
    /// A message was handed over after the session closed.
    SessionClosed,
    /// The message did not decode under the canonical profile.
    /// Spec: RFC 4511 §4.1.1; R49-16; A-52.
    Malformed(parse_ldap::Error),
    /// A response operation reached the engine as a request (parse-ldap's
    /// request direction refuses these; fail closed if one ever arrives).
    /// Spec: RFC 4511 §4.1.1 ("the tag of the protocolOp is not recognized
    /// as a request").
    NotARequest,
    /// The message exceeded the size bound of the session's authentication
    /// state. Spec: [MS-ADTS] 3.1.1.3.4.6 ("drop the connection"); docs/49
    /// §2.4, §9.
    Oversized,
    /// A request arrived after a successful StartTLS response but before the
    /// TLS layer was established. Spec: RFC 4511 §4.14.1; docs/49 §4.4
    /// (R49-15).
    RequestDuringStartTls,
    /// The front's report of the TLS state disagrees with the session's
    /// (including a TLS layer that went away). Spec: RFC 4511 §4.14.3;
    /// docs/49 §4.4 ("always close; no return to cleartext").
    TransportMismatch,
    /// UnbindRequest: the session ends. Spec: RFC 4511 §4.3; [MS-ADTS]
    /// 3.1.1.3.1.12.
    Unbind,
    /// AbandonRequest, discarded. Spec: RFC 4511 §4.11.
    Abandon,

    // ---- the bound identity (re-checked per request) -----------------------
    /// The bound identity's expiry time has passed. Spec: [MS-ADTS] 5.1.1.6;
    /// docs/49 §4.4 (R49-15).
    IdentityExpired,
    /// The bound identity's account is gone, unusable, revoked
    /// (`revoked_before`), or now names another SID. Spec: docs/49 §4.4
    /// (R49-15), §3.2; RFC 4120 3.3.3.1 (hot-list); RFC 4511 §6.
    IdentityRevoked,
    /// The account source could not answer the re-check (fail closed).
    /// Spec: docs/49 §4.4; AGENTS.md §6.
    AccountSourceFailure,

    // ---- controls ----------------------------------------------------------
    /// A critical control was attached; none is supported in phase 1.
    /// Spec: RFC 4511 §4.1.11; docs/49 §5.3 (R49-8).
    UnavailableCriticalControl,

    // ---- Bind ---------------------------------------------------------------
    /// The anonymous simple bind succeeded; the session stays anonymous.
    /// Spec: RFC 4513 §5.1.1, §4.
    AnonymousBind,
    /// A version other than 3. Spec: RFC 4511 §4.2.
    UnsupportedVersion,
    /// The unauthenticated mechanism of simple bind. Spec: RFC 4513 §5.1.2.
    UnauthenticatedBind,
    /// Simple bind with a password: no code path (AGENTS.md §6; P-14).
    /// Refused before any name lookup and before keyd.
    SimplePasswordBind,
    /// SASL with an empty mechanism. Spec: RFC 4511 §4.2.1.
    SaslEmptyMechanism,
    /// SASL GSSAPI before a TLS layer exists. Spec: docs/49 §3.1, §4.1;
    /// RFC 4513 §6.1.
    SaslWithoutTls,
    /// SASL GSSAPI over TLS: the path is task L7, blocked on owner item P-13
    /// (RFC 2743) — not built yet. Spec: docs/49 §12 (L6b, L7).
    SaslGssapiNotAvailable,
    /// Any other SASL mechanism: no code path. Spec: docs/49 §3.1.
    SaslMechanismUnsupported,
    /// An AuthenticationChoice alternative with no code path.
    /// Spec: RFC 4511 §4.2; docs/49 §3.1.
    AuthenticationChoiceUnsupported,

    // ---- Extended -----------------------------------------------------------
    /// StartTLS accepted; the front installs TLS next. Spec: RFC 4511 §4.14.2.
    StartTlsAccepted,
    /// StartTLS on a session whose TLS layer is already established.
    /// Spec: RFC 4513 §3.1.1; RFC 4511 §4.14.1, A.2.
    TlsAlreadyEstablished,
    /// StartTLS while the client had already sent further octets (requests
    /// outstanding at StartTLS time). Spec: RFC 4513 §3.1.1; RFC 4511
    /// §4.14.1; docs/49 §4.4 (injection protection).
    StartTlsWithPendingInput,
    /// StartTLS carrying a requestValue ("always absent").
    /// Spec: RFC 4511 §4.14.1, §4.12.
    StartTlsRequestValue,
    /// An extended operation other than StartTLS. Spec: RFC 4511 §4.12.
    ExtendedOperationUnrecognized,

    // ---- Search -------------------------------------------------------------
    /// The rootDSE entry was returned. Spec: [MS-ADTS] 3.1.1.3; docs/49 §5.2.
    RootDseReturned,
    /// The scope is outside the defined values. Spec: docs/49 §2.3 E14.
    ScopeUnrecognized,
    /// The empty base with a scope other than baseObject. Spec: docs/49
    /// §5.2; RFC 4512 §5.1 ("The root DSE SHALL NOT be included if the
    /// client performs a subtree search starting from the root").
    RootDseScopeNotBase,
    /// A search of the directory when the request inputs carry no directory
    /// view (a front that serves only the rootDSE): unwillingToPerform.
    /// Spec: docs/49 §12; crate::inputs (`directory`).
    SearchNotImplemented,
    /// A directory search completed: every candidate in scope was
    /// considered. Spec: RFC 4511 §4.5.2; docs/49 §6.
    SearchCompleted,
    /// The search base is not a valid LDAPDN (RFC 4514 grammar, a
    /// multi-valued RDN, or an alternative form other than `<GUID=hex>`).
    /// Spec: RFC 4511 A.2 (invalidDNSyntax); docs/49 §9; Q-195 item 4.
    BaseDnSyntax,
    /// The search base names no object of the naming context (absent, a
    /// value no phase-1 object can carry, or outside the NC): noSuchObject.
    /// Spec: RFC 4511 §4.5.3; docs/49 §5.4, §9; Q-195 item 4; A-53.
    BaseNotFound,
    /// The search base exists but is not visible to the requester:
    /// noSuchObject, identical to a nonexistent base (R49-13; A-48).
    /// Spec: [MS-ADTS] 5.1.3.3.6; docs/49 §6.1 item 2, §9.
    BaseNotVisible,
    /// The client's sizeLimit stopped the search; the entries already sent
    /// stand. Spec: RFC 4511 §4.5.1.4, A.2 (sizeLimitExceeded).
    SizeLimitExceeded,
    /// The server's page bound (MaxPageSize, or the PDP's MaxPageSize
    /// obligation) stopped the search: adminLimitExceeded. Spec: [MS-ADTS]
    /// 3.1.1.3.4.6; docs/49 §6.1 item 7; Q-168 item 5.
    PageLimitExceeded,
    /// The fixed visit budget stopped the search: adminLimitExceeded.
    /// Spec: docs/49 §6.1 item 3 (`MAX_CANDIDATES_VISITED`); Q-168 item 5.
    VisitBudgetExceeded,
    /// The response octet bound stopped the search: adminLimitExceeded.
    /// Spec: docs/49 §6.1 item 7 (`MAX_RESPONSE_OCTETS`).
    ResponseTooLarge,
    /// The bound on DN-valued values resolved for one search (member,
    /// memberOf), or on the values of one attribute, stopped the search:
    /// adminLimitExceeded. Spec: docs/49 §6.5 ("bounded").
    ValueBudgetExceeded,
    /// The tree is deeper than the DN bound: adminLimitExceeded.
    /// Spec: AGENTS.md §6 (bounded work); directory-pip `MAX_DN_DEPTH`.
    DepthExceeded,
    /// The client's timeLimit passed (by the caller's clock): the entries
    /// already sent stand. Spec: RFC 4511 §4.5.1.5, A.2 (timeLimitExceeded).
    TimeLimitExceeded,
    /// The server's query duration limit passed: timeLimitExceeded.
    /// Spec: [MS-ADTS] 3.1.1.3.4.6 (MaxQueryDuration); docs/49 §9.
    QueryDurationExceeded,
    /// The directory could not answer (an integrity, consistency or storage
    /// failure, or a PIP failure while reading the base): other, fail
    /// closed. Spec: docs/49 §9 (`Tamper`, `Inconsistent`, I/O → other).
    DirectoryUnavailable,
    /// The directory view's naming context differs from the engine's
    /// configured one (one source of truth, A-53): other, fail closed.
    NamingContextMismatch,
    /// A returned entry's DN cannot be written as an LDAPDN within the codec
    /// bound: other, fail closed. Spec: docs/49 §2.4; RFC 4514 §2.
    UnrepresentableDn,
    /// The PDP denied the request. Spec: docs/11 §4; docs/49 §9.
    PolicyDenied(ReasonCode),
    /// The PDP's RateLimit obligation was not admitted. Spec: docs/11 §2,
    /// §8; docs/49 §10.2.
    RateLimited,
    /// The PDP's MaxPageSize obligation admits no entry. Spec: docs/11 §8;
    /// docs/49 §6.1 item 7, §10.2.
    PageSizeExceeded,
    /// The caller's `now` cannot be expressed as a PDP instant (before
    /// 1970). Spec: docs/11 §1, P9; fail closed.
    ClockOutOfRange,
    /// The PIP could not give the anonymous subject's tier (P3; fail
    /// closed). Spec: docs/11 §6, D40; Q-170 item 5.
    SubjectUnavailable,

    // ---- writes and Compare ------------------------------------------------
    /// Modify / Add / Delete / ModifyDN / Compare: not performed in phase 1.
    /// Spec: A-48; docs/49 §5.1, §8.1; Q-167.
    OperationNotSupported,

    // ---- internal -----------------------------------------------------------
    /// A response could not be encoded (cannot happen with a conforming
    /// codec; fail closed).
    InternalFailure,
}

/// One audit event: one per message handed to the engine.
/// Spec: docs/49 §10.1 (R49-14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// The caller-supplied time (the engine reads no clock).
    pub time: KerberosTime,
    /// The caller's connection identifier.
    pub connection_id: u64,
    /// The source zone the request was decided under (the caller's
    /// `TransportReport::src_net` — in dird, the zone of the front, from its
    /// peer uid; docs/52 R14). Spec: docs/49 §10.1 (`source_zone`).
    pub source_zone: IpScope,
    /// How the connection is carried.
    pub transport: AuditTransport,
    /// The transport security the engine attributed to the request
    /// (docs/49 §4.3).
    pub transport_sec: TransportSec,
    /// The operation.
    pub operation: AuditOperation,
    /// The MessageID, once the message decoded.
    pub message_id: Option<MessageId>,
    /// The requester's SID; `None` = anonymous. Spec: docs/49 §10.1
    /// (`principal: Option<Sid> (None = anonymous)`).
    pub principal: Option<Sid>,
    /// The bind facts, for a BindRequest.
    pub bind: Option<BindAudit>,
    /// The resolved target, if any.
    pub target: Option<AuditTarget>,
    /// The search facts, for a SearchRequest.
    pub search: Option<SearchAudit>,
    /// The resultCode of the response sent, if one was sent.
    pub result_code: Option<ResultCode>,
    /// The resultCode of the Notice of Disconnection sent, if one was sent.
    /// Spec: RFC 4511 §4.4.1.
    pub notice: Option<ResultCode>,
    /// What the front must do with the connection.
    pub action: ConnectionAction,
    /// The internal reason.
    pub reason: AuditReason,
}
