//! The Bind operation (docs/49 §3.1, R49-4).
//!
//! # Processing order (docs/49 §3.1)
//!
//! 1. On receipt the session is already anonymous: the engine resets the
//!    identity before any check (RFC 4513 §4: "Upon receipt of a Bind
//!    request, the server immediately moves the session to an anonymous
//!    authorization state"; done by the dispatcher, before controls).
//! 2. No operation is outstanding: the engine is synchronous, so every
//!    earlier request has completed (RFC 4511 §4.2.1; docs/49 §10.2).
//! 3. The table below, in order. A refused bind leaves the session anonymous
//!    (RFC 4513 §4: "Otherwise, the session remains in an anonymous state").
//!
//! # The table (docs/49 §3.1)
//!
//! | Request | resultCode | Source |
//! |---|---|---|
//! | `version` ≠ 3 | protocolError (2) | RFC 4511 §4.2 ("MUST respond ... protocolError"); no LDAPv2 (R49-17) |
//! | simple, empty name, empty password | success (0) — identity stays anonymous | RFC 4513 §5.1.1, §2 ("MUST support the anonymous authentication mechanism") |
//! | simple, name, empty password | unwillingToPerform (53) | RFC 4513 §5.1.2 ("Servers SHOULD by default fail Unauthenticated Bind requests with a resultCode of unwillingToPerform") |
//! | simple, non-empty password (any name) | authMethodNotSupported (7) | AGENTS.md §6; P-14 (Q-166): no code path, even over TLS; refused before any name lookup and never reaching keyd; RFC 4513 §5.1.3 (empty name + password: "undefined") |
//! | SASL, empty mechanism | authMethodNotSupported (7) | RFC 4511 §4.2.1 ("MUST return ... authMethodNotSupported") |
//! | SASL GSSAPI, no TLS | confidentialityRequired (13) | docs/49 §3.1, §4.1 (R49-6); RFC 4513 §6.1 |
//! | SASL GSSAPI, TLS | authMethodNotSupported (7) until task L7 | docs/49 §12: L7 is blocked on owner item P-13 (RFC 2743) |
//! | SASL, any other mechanism | authMethodNotSupported (7) | docs/49 §3.1 (DIGEST-MD5, GSS-SPNEGO, EXTERNAL, …: no code path in phase 1) |
//! | any other AuthenticationChoice | authMethodNotSupported (7) | RFC 4511 §4.2 ("Servers that do not support a choice ... return ... authMethodNotSupported") |
//!
//! The confidentialityRequired row is applied to GSSAPI — the one mechanism
//! that will reach keyd — and not to mechanisms that have no code path,
//! which are not supported over TLS either (interpretation, Q-190 item 3).
//!
//! # The seam for task L7
//!
//! [`sasl_gssapi`] is the single place the GSSAPI bind will be built: the
//! RFC 4752 profile without a security layer over TLS with channel binding
//! (R49-6), keyd's `open_and_verify_service_ticket` (A-46, L6a) behind a
//! trait like `kdc::KeyCustody`, the Subject of docs/49 §3.2 from the
//! account source, and a [`crate::session::BoundIdentity`] on success. It
//! is reached only after the TLS check above, so a GSSAPI token is never
//! examined on a cleartext connection.
//!
//! Spec: RFC 4511 §4.2, §4.2.1, §4.2.2; RFC 4513 §2, §4, §5.1.1-§5.1.3,
//! §5.2, §6.1; RFC 4422 §3.1; RFC 4752 §3; docs/49 §3.1 (R49-4), §12;
//! P-14 (Q-166); P-13.

use parse_ldap::{AuthenticationChoice, BindRequest, ResultCode};

use crate::audit::{AuditReason, AuditText, BindAudit, BindMechanism};

/// The LDAP version this server implements. Spec: RFC 4511 §4.2 ("This
/// document describes version 3 of the protocol"); R49-17 (no LDAPv2).
const LDAP_VERSION: u8 = 3;

/// The SASL mechanism name of Kerberos V5 GSS-API: compared octet for octet
/// (RFC 4422 §3.1: mechanism names are "ASCII uppercase letters, digits,
/// hyphens, and/or underscores" — no case folding).
/// Spec: RFC 4752 §3 ("The SASL mechanism name for the Kerberos V5 GSS-API
/// mechanism [RFC4121] is 'GSSAPI'"); RFC 4422 §3.1.
const GSSAPI: &str = "GSSAPI";

/// The outcome of a bind. Spec: module documentation.
pub(crate) struct BindOutcome {
    pub(crate) code: ResultCode,
    pub(crate) reason: AuditReason,
    pub(crate) audit: BindAudit,
}

/// Process one BindRequest on a session that is already anonymous.
/// `tls` is whether a TLS layer protects the connection.
/// Spec: module documentation.
pub(crate) fn bind(request: &BindRequest, tls: bool) -> BindOutcome {
    let audit = BindAudit {
        version: request.version,
        mechanism: mechanism(request),
        name: (!request.name.is_empty()).then(|| AuditText::from_client(&request.name)),
    };
    let (code, reason) = decide(request, tls);
    BindOutcome {
        code,
        reason,
        audit,
    }
}

/// The table of the module documentation, in order.
fn decide(request: &BindRequest, tls: bool) -> (ResultCode, AuditReason) {
    if request.version != LDAP_VERSION {
        return (ResultCode::ProtocolError, AuditReason::UnsupportedVersion);
    }
    match &request.authentication {
        AuthenticationChoice::Simple { password_empty } => {
            match (request.name.is_empty(), *password_empty) {
                // Anonymous: the session stays anonymous. Spec: RFC 4513
                // §5.1.1.
                (true, true) => (ResultCode::Success, AuditReason::AnonymousBind),
                // Unauthenticated. Spec: RFC 4513 §5.1.2.
                (false, true) => (
                    ResultCode::UnwillingToPerform,
                    AuditReason::UnauthenticatedBind,
                ),
                // Name/password (or the undefined empty-name form): no code
                // path. The name is not looked up and keyd is not called.
                // Spec: AGENTS.md §6; P-14; RFC 4513 §5.1.3.
                (_, false) => (
                    ResultCode::AuthMethodNotSupported,
                    AuditReason::SimplePasswordBind,
                ),
            }
        }
        AuthenticationChoice::Sasl(credentials) => {
            if credentials.mechanism.is_empty() {
                // Spec: RFC 4511 §4.2.1.
                (
                    ResultCode::AuthMethodNotSupported,
                    AuditReason::SaslEmptyMechanism,
                )
            } else if credentials.mechanism == GSSAPI {
                if tls {
                    sasl_gssapi()
                } else {
                    // Spec: docs/49 §3.1 ("SASL bind in a session without
                    // TLS → confidentialityRequired, refused before keyd");
                    // RFC 4513 §6.1.
                    (
                        ResultCode::ConfidentialityRequired,
                        AuditReason::SaslWithoutTls,
                    )
                }
            } else {
                // Spec: docs/49 §3.1.
                (
                    ResultCode::AuthMethodNotSupported,
                    AuditReason::SaslMechanismUnsupported,
                )
            }
        }
        // Spec: RFC 4511 §4.2; docs/49 §2.3 E13.
        AuthenticationChoice::Unrecognized { .. } => (
            ResultCode::AuthMethodNotSupported,
            AuditReason::AuthenticationChoiceUnsupported,
        ),
    }
}

/// The GSSAPI bind over TLS: task L7 (module documentation). Until it is
/// built, the mechanism is not supported — it is not advertised in
/// supportedSASLMechanisms either (docs/49 §5.2; RFC 4512 §5.1.7).
/// Spec: docs/49 §3.1, §12 (L7, blocked on P-13).
fn sasl_gssapi() -> (ResultCode, AuditReason) {
    (
        ResultCode::AuthMethodNotSupported,
        AuditReason::SaslGssapiNotAvailable,
    )
}

/// The mechanism, for the audit record. Spec: docs/49 §10.1.
fn mechanism(request: &BindRequest) -> BindMechanism {
    match &request.authentication {
        AuthenticationChoice::Simple { password_empty } => {
            match (request.name.is_empty(), *password_empty) {
                (true, true) => BindMechanism::SimpleAnonymous,
                (false, true) => BindMechanism::SimpleUnauthenticated,
                (_, false) => BindMechanism::SimplePassword,
            }
        }
        AuthenticationChoice::Sasl(credentials) => BindMechanism::Sasl {
            mechanism: AuditText::from_client(&credentials.mechanism),
        },
        AuthenticationChoice::Unrecognized { tag_number } => BindMechanism::Unrecognized {
            tag_number: *tag_number,
        },
    }
}
