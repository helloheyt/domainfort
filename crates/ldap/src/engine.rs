//! The engine: one canonical LDAPMessage in, responses + action + one audit
//! event out (docs/49 §11, R49-16).
//!
//! # The order of processing (each step can end the request)
//!
//! 0. A closed session processes nothing: Close, no response (RFC 4511
//!    §5.3).
//! 1. **Transport**, before any octet is decoded. While a StartTLS is
//!    pending, a request must arrive over the new TLS layer (it then becomes
//!    the session's channel); one that arrives in cleartext → Close, its
//!    octets never parsed (RFC 4511 §4.14.1; docs/49 §4.4 — R49-15:
//!    injection protection). Otherwise the front's TLS report must equal the
//!    session's channel; a difference (including TLS that went away) → Close
//!    (docs/49 §4.4: "always close; no return to cleartext").
//! 2. **Decode** with parse-ldap's canonical profile only, bounded by the
//!    session's authentication state (R49-16; docs/49 §2.4). Larger than the
//!    bound → Close with no response ([MS-ADTS] 3.1.1.3.4.6: "it will drop
//!    the connection"; docs/49 §9). Anything else that does not decode — a
//!    non-canonical encoding, a response operation, an unknown protocolOp, a
//!    simple-bind password the front failed to drop (A-52) — → Notice of
//!    Disconnection (protocolError) and Close (RFC 4511 §4.1.1: "SHOULD
//!    return the Notice of Disconnection ... with the resultCode set to
//!    protocolError, and MUST immediately terminate the LDAP session").
//! 3. **Unbind** → Close, no response (RFC 4511 §4.3; [MS-ADTS]
//!    3.1.1.3.1.12). Its controls are not examined (RFC 4511 §4.1.11: for the
//!    UnbindRequest the criticality "MUST be ignored").
//! 4. **Re-check a bound identity** (session module): expired or revoked →
//!    Notice of Disconnection (strongerAuthRequired) and Close, the request
//!    not executed ([MS-ADTS] 5.1.1.6; docs/49 §4.4, §9; Q-169 item 5). An
//!    anonymous identity has nothing to re-check.
//! 5. **Abandon** → no response (RFC 4511 §4.11: "There is no response";
//!    "Servers MUST discard Abandon requests for messageIDs they do not
//!    recognize" — the synchronous engine has no uncompleted operation).
//! 6. **Bind receipt** moves the session to anonymous before anything else
//!    about the bind is looked at (RFC 4513 §4).
//! 7. **Controls:** any critical control → the operation's response with
//!    unavailableCriticalExtension (12), the operation not performed; a
//!    non-critical control is ignored (RFC 4511 §4.1.11; docs/49 §5.3,
//!    R49-8: no control is supported in phase 1). No combination can be
//!    invalid: every non-critical control is ignored, which RFC 4511 §4.1.11
//!    allows "in order to arrive at a valid combination".
//! 8. **Dispatch:** Bind (bind module), Search (the rootDSE, or the
//!    directory — crate::search, task L8), Extended (StartTLS, or protocolError
//!    for any other requestName — RFC 4511 §4.12), and Modify / Add /
//!    Delete / ModifyDN / Compare → unwillingToPerform (53) with the
//!    matching response tag (A-48; docs/49 §5.1, §8.1).
//!
//! Every response carries empty matchedDN and diagnosticMessage (R49-13).
//! Every call returns exactly one audit event (R49-14). A response that
//! cannot be encoded (cannot happen with a conforming codec) replaces every
//! response with a Notice of Disconnection (other) and closes — fail closed.
//!
//! Spec: RFC 4511 §4.1.1, §4.1.11, §4.2.1, §4.3, §4.4.1, §4.5.1, §4.11,
//! §4.12, §4.14, §5.3; RFC 4513 §3.1.1, §4; [MS-ADTS] 3.1.1.3.1.12,
//! 3.1.1.3.4.6, 5.1.1.6; docs/49 §4.4 (R49-15), §5 (R49-7, R49-8), §9
//! (R49-13), §10 (R49-14), §11 (R49-16); A-48, A-52.

use directory_pip::NamingContext;
use dtyp::Sid;
use krb_proto::KerberosTime;
use parse_ldap::{
    decode_message, DecodeOptions, ExtendedRequest, LdapMessage, MessageId, ProtocolOp, ResultCode,
    Scope, SearchRequest,
};
use pdp::{
    AccessRequest, Action, Constraint, Context, Effect, IpScope, Obligation, Resource, TransportSec,
};

use crate::audit::{
    AuditEvent, AuditOperation, AuditReason, AuditScope, AuditTarget, AuditTransport, BindAudit,
    SearchAudit,
};
use crate::bind;
use crate::config::{ConfigError, EngineConfig, RootDseValues};
use crate::inputs::RequestInputs;
use crate::respond::{self, EncodeFailure, ResponseKind};
use crate::root_dse;
use crate::search::{self, SearchLimits, SearchParams};
use crate::session::{recheck, Channel, Identity, Phase, Recheck, Session};
use crate::subject::{
    context_transport, denial_code, session_transport_sec, subject, transport_sec, Requester,
};
use crate::time::unix_instant;

/// What the front does with the connection after sending the responses.
/// Spec: docs/49 §11 (`None | InstallTls | Close { notice }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionAction {
    /// Keep reading requests.
    Continue,
    /// Send the responses (the successful StartTLS response) in cleartext,
    /// then negotiate TLS as the server; hand no further cleartext octets to
    /// the engine. Spec: RFC 4511 §4.14.2; RFC 4513 §3; docs/49 §4.4.
    StartTls,
    /// Send the responses (if any — a Notice of Disconnection is among them
    /// when one is due), then close the connection. Spec: RFC 4511 §5.3.
    Close,
}

/// The result of handling one message. Spec: docs/49 §11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Canonical LDAPMessage encodings to send, in order.
    pub responses: Vec<Vec<u8>>,
    /// What to do with the connection afterwards.
    pub action: ConnectionAction,
    /// The one audit event of this message (R49-14).
    pub audit: AuditEvent,
}

/// The LDAP engine: the configuration shared by every connection.
/// Spec: docs/49 §11.
#[derive(Debug, Clone)]
pub struct Engine {
    root_dse: RootDseValues,
    /// The naming context: the rootDSE's values are its encoding, and a
    /// directory search refuses a view with another one (A-53).
    naming_context: NamingContext,
    /// The bounds of a directory search (crate::search::limits).
    limits: SearchLimits,
}

impl Engine {
    /// An engine with this configuration, checked once.
    /// Spec: crate::config.
    pub fn new(config: EngineConfig) -> Result<Engine, ConfigError> {
        let root_dse = config.root_dse.validate()?;
        Ok(Engine {
            root_dse,
            naming_context: config.root_dse.naming_context,
            limits: SearchLimits::PHASE1,
        })
    }

    /// The same engine with other search bounds (the crate's own tests reach
    /// each bound with a small directory).
    #[cfg(test)]
    pub(crate) fn with_limits(mut self, limits: SearchLimits) -> Engine {
        self.limits = limits;
        self
    }

    /// Handle one LDAPMessage of `session` (module documentation).
    ///
    /// `message` is one complete message, re-encoded by the front in the
    /// canonical form (R49-16). Never panics; every failure fails closed.
    pub fn handle(
        &self,
        session: &mut Session,
        message: &[u8],
        inputs: RequestInputs<'_>,
    ) -> Outcome {
        let mut run = Run::new(session, &inputs);
        let mut inputs = inputs;
        self.process(session, message, &mut inputs, &mut run);
        run.finish(session)
    }

    /// Steps 0-8 of the module documentation.
    fn process(
        &self,
        session: &mut Session,
        message: &[u8],
        inputs: &mut RequestInputs<'_>,
        run: &mut Run,
    ) {
        // 0. Closed. Spec: RFC 4511 §5.3.
        if session.phase == Phase::Closed {
            run.close(AuditReason::SessionClosed);
            return;
        }

        // 1. Transport, before a single octet is decoded: octets that reach
        // the engine in cleartext after a successful StartTLS response, or
        // over a transport the session does not have, are never parsed.
        // Spec: RFC 4511 §4.14.1, §4.14.3; docs/49 §4.4 (R49-15).
        match session.phase {
            Phase::StartTlsPending => {
                if !inputs.transport.tls_established {
                    run.close(AuditReason::RequestDuringStartTls);
                    return;
                }
                session.channel = Channel::StartTls;
                session.phase = Phase::Open;
            }
            Phase::Open => {
                if inputs.transport.tls_established != session.channel.tls() {
                    run.close(AuditReason::TransportMismatch);
                    return;
                }
            }
            Phase::Closed => {
                run.close(AuditReason::SessionClosed);
                return;
            }
        }
        run.transport_sec = session_transport_sec(session);

        // 2. Decode, canonical profile only. Spec: R49-16; RFC 4511 §4.1.1;
        // [MS-ADTS] 3.1.1.3.4.6.
        let options = DecodeOptions::canonical_request(session.auth_state());
        let msg = match decode_message(message, &options) {
            Ok(msg) => msg,
            Err(parse_ldap::Error::MessageTooLarge) => {
                run.operation = AuditOperation::Malformed;
                run.close(AuditReason::Oversized);
                return;
            }
            Err(e) => {
                run.operation = AuditOperation::Malformed;
                run.disconnect(ResultCode::ProtocolError, AuditReason::Malformed(e));
                return;
            }
        };
        run.message_id = Some(msg.message_id);
        run.operation = operation_of(&msg.protocol_op);

        // 3. Unbind. Spec: RFC 4511 §4.3, §4.1.11; [MS-ADTS] 3.1.1.3.1.12.
        if matches!(msg.protocol_op, ProtocolOp::UnbindRequest) {
            run.close(AuditReason::Unbind);
            return;
        }

        // 4. Re-check a bound identity. Spec: [MS-ADTS] 5.1.1.6; docs/49
        // §4.4 (R49-15).
        let requester = match &session.identity {
            Identity::Anonymous => Requester::Anonymous,
            Identity::Bound(identity) => match recheck(identity, inputs.subjects, &inputs.now) {
                Recheck::Valid(bound) => Requester::Bound(bound),
                failed => {
                    run.principal = Some(identity.sid);
                    session.identity = Identity::Anonymous;
                    let reason = match failed {
                        Recheck::Expired => AuditReason::IdentityExpired,
                        Recheck::Unavailable => AuditReason::AccountSourceFailure,
                        Recheck::Revoked | Recheck::Valid(_) => AuditReason::IdentityRevoked,
                    };
                    run.disconnect(ResultCode::StrongerAuthRequired, reason);
                    return;
                }
            },
        };
        run.principal = requester.audit_principal();
        run.transport_sec = transport_sec(session.channel, &requester);

        // 5. Abandon: discarded, no response. Spec: RFC 4511 §4.11.
        if matches!(msg.protocol_op, ProtocolOp::AbandonRequest(_)) {
            run.reason = AuditReason::Abandon;
            return;
        }

        // 6. Bind receipt: anonymous at once. Spec: RFC 4513 §4.
        let requester = if matches!(msg.protocol_op, ProtocolOp::BindRequest(_)) {
            session.identity = Identity::Anonymous;
            run.principal = None;
            run.transport_sec = transport_sec(session.channel, &Requester::Anonymous);
            Requester::Anonymous
        } else {
            requester
        };

        // 7. Controls. Spec: RFC 4511 §4.1.11; docs/49 §5.3 (R49-8).
        let Some(kind) = response_kind(&msg.protocol_op) else {
            // A response operation cannot decode in the request direction;
            // fail closed if one ever arrives. Spec: RFC 4511 §4.1.1.
            run.disconnect(ResultCode::ProtocolError, AuditReason::NotARequest);
            return;
        };
        if has_critical_control(&msg) {
            run.respond(
                respond::result(
                    msg.message_id,
                    kind,
                    ResultCode::UnavailableCriticalExtension,
                ),
                ResultCode::UnavailableCriticalExtension,
                AuditReason::UnavailableCriticalControl,
            );
            return;
        }

        // 8. Dispatch.
        match &msg.protocol_op {
            ProtocolOp::BindRequest(request) => {
                let outcome = bind::bind(request, session.channel.tls());
                run.bind = Some(outcome.audit);
                run.respond(
                    respond::result(msg.message_id, kind, outcome.code),
                    outcome.code,
                    outcome.reason,
                );
            }
            ProtocolOp::SearchRequest(request) => {
                self.search(
                    msg.message_id,
                    request,
                    &requester,
                    session.channel,
                    inputs,
                    run,
                );
            }
            ProtocolOp::ExtendedRequest(request) => {
                extended(
                    session,
                    msg.message_id,
                    request,
                    inputs.transport.input_pending,
                    run,
                );
            }
            // Spec: A-48; docs/49 §5.1, §8.1; Q-167.
            ProtocolOp::Unsupported { .. } => run.respond(
                respond::result(msg.message_id, kind, ResultCode::UnwillingToPerform),
                ResultCode::UnwillingToPerform,
                AuditReason::OperationNotSupported,
            ),
            // Unbind and Abandon were handled above; responses have no
            // response kind.
            ProtocolOp::UnbindRequest
            | ProtocolOp::AbandonRequest(_)
            | ProtocolOp::BindResponse(_)
            | ProtocolOp::SearchResultEntry(_)
            | ProtocolOp::SearchResultDone(_)
            | ProtocolOp::ExtendedResponse(_)
            | ProtocolOp::UnsupportedResponse { .. } => {
                run.disconnect(ResultCode::ProtocolError, AuditReason::NotARequest);
            }
        }
    }

    /// A SearchRequest: the rootDSE (crate::root_dse), or a search of the
    /// directory (crate::search).
    /// Spec: docs/49 §5.2 (R49-10), §6 (R49-9), §2.3 E14.
    fn search(
        &self,
        message_id: MessageId,
        request: &SearchRequest,
        requester: &Requester,
        channel: Channel,
        inputs: &mut RequestInputs<'_>,
        run: &mut Run,
    ) {
        let done = ResponseKind::SearchDone;
        run.search = Some(SearchAudit::new(audit_scope(request.scope)));
        // An unrecognised scope: the operation's response with
        // protocolError. Spec: docs/49 §2.3 E14.
        if matches!(request.scope, Scope::Unrecognized(_)) {
            run.respond(
                respond::result(message_id, done, ResultCode::ProtocolError),
                ResultCode::ProtocolError,
                AuditReason::ScopeUnrecognized,
            );
            return;
        }
        // A search of the directory. Spec: docs/49 §6 (R49-9).
        if !request.base_object.is_empty() {
            self.search_directory(message_id, request, requester, channel, inputs, run);
            return;
        }
        // The empty base with another scope. Spec: docs/49 §5.2; RFC 4512
        // §5.1.
        if request.scope != Scope::BaseObject {
            run.respond(
                respond::result(message_id, done, ResultCode::UnwillingToPerform),
                ResultCode::UnwillingToPerform,
                AuditReason::RootDseScopeNotBase,
            );
            return;
        }
        run.target = Some(AuditTarget::RootDse);

        // One PDP decision: DirRead on the rootDSE. Spec: docs/49 §5.2; L2.
        let Some(time) = unix_instant(&inputs.now) else {
            run.respond(
                respond::result(message_id, done, ResultCode::Other),
                ResultCode::Other,
                AuditReason::ClockOutOfRange,
            );
            return;
        };
        let Ok(subject) = subject(requester, inputs.pip) else {
            run.respond(
                respond::result(message_id, done, ResultCode::Other),
                ResultCode::Other,
                AuditReason::SubjectUnavailable,
            );
            return;
        };
        let access = AccessRequest {
            subject,
            resource: Resource::RootDse,
            action: Action::DirRead,
            context: Context {
                src_net: inputs.transport.src_net,
                time,
                // Spec: docs/49 §4.3; Q-190 item 2 (A-54).
                transport: context_transport(channel),
                transport_sec: run.transport_sec,
            },
        };
        let decision = pdp::decide(&access, inputs.snapshot, inputs.pip);
        if decision.effect != Effect::Allow {
            let code = denial_code(decision.reason, run.transport_sec);
            run.respond(
                respond::result(message_id, done, code),
                code,
                AuditReason::PolicyDenied(decision.reason),
            );
            return;
        }
        // Honour every obligation. Spec: docs/11 §2, §8; docs/49 §10.2.
        for obligation in &decision.obligations {
            match obligation {
                // This request's audit event.
                Obligation::Audit => {}
                Obligation::RateLimit(key) => {
                    if !inputs.rate.admit(key, &inputs.now) {
                        run.respond(
                            respond::result(message_id, done, ResultCode::Busy),
                            ResultCode::Busy,
                            AuditReason::RateLimited,
                        );
                        return;
                    }
                }
                // One entry fits any page of at least one entry.
                // Spec: docs/49 §6.1 item 7.
                Obligation::Constrain(Constraint::MaxPageSize(limit)) => {
                    if *limit == 0 {
                        run.respond(
                            respond::result(message_id, done, ResultCode::AdminLimitExceeded),
                            ResultCode::AdminLimitExceeded,
                            AuditReason::PageSizeExceeded,
                        );
                        return;
                    }
                }
            }
        }

        let entry = root_dse::entry(&self.root_dse, &request.attributes, request.types_only);
        match respond::entry(message_id, entry) {
            Ok(octets) => run.responses.push(octets),
            Err(EncodeFailure) => {
                run.fail_internal();
                return;
            }
        }
        if let Some(search) = run.search.as_mut() {
            search.entries_returned = 1;
        }
        run.respond(
            respond::result(message_id, done, ResultCode::Success),
            ResultCode::Success,
            AuditReason::RootDseReturned,
        );
    }

    /// A search of the directory (crate::search): its entries, then the
    /// SearchResultDone with its code; one audit event with the counts.
    /// Without a directory view in the inputs, unwillingToPerform.
    /// Spec: docs/49 §6 (R49-9), §10.1 (R49-14), §12; RFC 4511 §4.5.2.
    fn search_directory(
        &self,
        message_id: MessageId,
        request: &SearchRequest,
        requester: &Requester,
        channel: Channel,
        inputs: &mut RequestInputs<'_>,
        run: &mut Run,
    ) {
        let done = ResponseKind::SearchDone;
        let Some(directory) = inputs.directory.as_ref() else {
            run.respond(
                respond::result(message_id, done, ResultCode::UnwillingToPerform),
                ResultCode::UnwillingToPerform,
                AuditReason::SearchNotImplemented,
            );
            return;
        };
        let (view, clock) = (directory.view, directory.clock);
        let outcome = search::run(SearchParams {
            message_id,
            request,
            requester,
            policy: inputs.snapshot,
            rate: &mut *inputs.rate,
            now: inputs.now,
            src_net: inputs.transport.src_net,
            channel,
            transport_sec: run.transport_sec,
            view,
            clock,
            naming_context: &self.naming_context,
            limits: self.limits,
        });
        run.target = outcome.target.map(AuditTarget::DirObject);
        run.responses.extend(outcome.entries);
        let mut audit = outcome.audit;
        audit.scope = audit_scope(request.scope);
        run.search = Some(audit);
        run.respond(
            respond::result(message_id, done, outcome.code),
            outcome.code,
            outcome.reason,
        );
    }
}

/// An ExtendedRequest: StartTLS, or protocolError for anything else.
/// Spec: RFC 4511 §4.12, §4.14.1, §4.14.2; RFC 4513 §3.1.1; docs/49 §4.4.
fn extended(
    session: &Session,
    message_id: MessageId,
    request: &ExtendedRequest,
    input_pending: bool,
    run: &mut Run,
) {
    // "Where the requestName is not recognized, the server returns
    // protocolError." Spec: RFC 4511 §4.12.
    if !request.is_start_tls() {
        run.respond(
            respond::result(
                message_id,
                ResponseKind::ExtendedUnrecognized,
                ResultCode::ProtocolError,
            ),
            ResultCode::ProtocolError,
            AuditReason::ExtendedOperationUnrecognized,
        );
        return;
    }
    let start_tls = ResponseKind::StartTls;
    // "the requestValue field is always absent". Spec: RFC 4511 §4.14.1;
    // §4.12 ("The server may return protocolError in other cases").
    if request.request_value.is_some() {
        run.respond(
            respond::result(message_id, start_tls, ResultCode::ProtocolError),
            ResultCode::ProtocolError,
            AuditReason::StartTlsRequestValue,
        );
        return;
    }
    // Not "when TLS is currently established on the session".
    // Spec: RFC 4513 §3.1.1; RFC 4511 §4.14.1, A.2 (operationsError "if a
    // TLS layer was already installed").
    if session.channel.tls() {
        run.respond(
            respond::result(message_id, start_tls, ResultCode::OperationsError),
            ResultCode::OperationsError,
            AuditReason::TlsAlreadyEstablished,
        );
        return;
    }
    // Not "when there are outstanding responses for operation requests
    // previously issued": the client already sent more octets, which RFC
    // 4511 §4.14.1 forbids ("MUST NOT send any LDAP PDUs ... following this
    // request until it receives a StartTLS Extended response"). Refused with
    // operationsError, and the connection closes so that those cleartext
    // octets are never processed (docs/49 §4.4 — injection protection).
    // Spec: RFC 4513 §3.1.1; RFC 4511 §4.14.1, A.2; docs/49 §4.4.
    if input_pending {
        run.respond(
            respond::result(message_id, start_tls, ResultCode::OperationsError),
            ResultCode::OperationsError,
            AuditReason::StartTlsWithPendingInput,
        );
        if run.action == ConnectionAction::Continue {
            run.action = ConnectionAction::Close;
        }
        return;
    }
    // "If the server is willing and able to negotiate TLS, it returns the
    // StartTLS response with the resultCode set to success." Spec: RFC 4511
    // §4.14.2.
    run.respond(
        respond::result(message_id, start_tls, ResultCode::Success),
        ResultCode::Success,
        AuditReason::StartTlsAccepted,
    );
    if run.action == ConnectionAction::Continue {
        run.action = ConnectionAction::StartTls;
    }
}

/// The audit operation of a protocolOp. Spec: RFC 4511 §4.1.1.
fn operation_of(op: &ProtocolOp) -> AuditOperation {
    match op {
        ProtocolOp::BindRequest(_) => AuditOperation::Bind,
        ProtocolOp::UnbindRequest => AuditOperation::Unbind,
        ProtocolOp::SearchRequest(_) => AuditOperation::Search,
        ProtocolOp::AbandonRequest(_) => AuditOperation::Abandon,
        ProtocolOp::ExtendedRequest(e) if e.is_start_tls() => AuditOperation::StartTls,
        ProtocolOp::ExtendedRequest(_) => AuditOperation::Extended,
        ProtocolOp::Unsupported { op_tag } => AuditOperation::NotSupported(*op_tag),
        ProtocolOp::BindResponse(_)
        | ProtocolOp::SearchResultEntry(_)
        | ProtocolOp::SearchResultDone(_)
        | ProtocolOp::ExtendedResponse(_)
        | ProtocolOp::UnsupportedResponse { .. } => AuditOperation::Malformed,
    }
}

/// The response that answers a request, or `None` for a request with no
/// response (Unbind, Abandon) or a response operation.
/// Spec: RFC 4511 §4.1.1, §4.3, §4.11, §4.12, §4.14.2, App. B.
fn response_kind(op: &ProtocolOp) -> Option<ResponseKind> {
    match op {
        ProtocolOp::BindRequest(_) => Some(ResponseKind::Bind),
        ProtocolOp::SearchRequest(_) => Some(ResponseKind::SearchDone),
        ProtocolOp::ExtendedRequest(e) if e.is_start_tls() => Some(ResponseKind::StartTls),
        ProtocolOp::ExtendedRequest(_) => Some(ResponseKind::ExtendedUnrecognized),
        ProtocolOp::Unsupported { op_tag } => Some(ResponseKind::NotSupported(*op_tag)),
        ProtocolOp::UnbindRequest
        | ProtocolOp::AbandonRequest(_)
        | ProtocolOp::BindResponse(_)
        | ProtocolOp::SearchResultEntry(_)
        | ProtocolOp::SearchResultDone(_)
        | ProtocolOp::ExtendedResponse(_)
        | ProtocolOp::UnsupportedResponse { .. } => None,
    }
}

/// Whether any control is critical. Phase 1 recognises no control, so every
/// critical one is unrecognised. Spec: RFC 4511 §4.1.11; docs/49 §5.3.
fn has_critical_control(msg: &LdapMessage) -> bool {
    msg.controls
        .as_ref()
        .is_some_and(|controls| controls.iter().any(|c| c.criticality))
}

/// The audit form of a scope. Spec: RFC 4511 §4.5.1.2.
pub(crate) fn audit_scope(scope: Scope) -> AuditScope {
    match scope {
        Scope::BaseObject => AuditScope::BaseObject,
        Scope::SingleLevel => AuditScope::SingleLevel,
        Scope::WholeSubtree => AuditScope::WholeSubtree,
        Scope::Unrecognized(_) => AuditScope::Unrecognized,
    }
}

/// The audit form of the session's channel. Spec: docs/49 §10.1.
fn audit_transport(channel: Channel) -> AuditTransport {
    match channel {
        Channel::Cleartext => AuditTransport::Ldap,
        Channel::Ldaps => AuditTransport::Ldaps,
        Channel::StartTls => AuditTransport::StartTls,
    }
}

/// The accumulating result of one call: responses, action and audit facts.
struct Run {
    time: KerberosTime,
    connection_id: u64,
    source_zone: IpScope,
    transport_sec: TransportSec,
    operation: AuditOperation,
    message_id: Option<MessageId>,
    principal: Option<Sid>,
    bind: Option<BindAudit>,
    target: Option<AuditTarget>,
    search: Option<SearchAudit>,
    responses: Vec<Vec<u8>>,
    result_code: Option<ResultCode>,
    notice: Option<ResultCode>,
    action: ConnectionAction,
    reason: AuditReason,
}

impl Run {
    fn new(session: &Session, inputs: &RequestInputs<'_>) -> Run {
        Run {
            time: inputs.now,
            connection_id: session.connection_id,
            source_zone: inputs.transport.src_net,
            // The session as it stands, until the request's own requester
            // is known (step 4). Spec: docs/49 §4.3, §10.1.
            transport_sec: session_transport_sec(session),
            operation: AuditOperation::NotDecoded,
            message_id: None,
            principal: match &session.identity {
                Identity::Anonymous => None,
                Identity::Bound(identity) => Some(identity.sid),
            },
            bind: None,
            target: None,
            search: None,
            responses: Vec::new(),
            result_code: None,
            notice: None,
            action: ConnectionAction::Continue,
            reason: AuditReason::InternalFailure,
        }
    }

    /// Send one LDAPResult-bearing response with `code`.
    fn respond(
        &mut self,
        encoded: Result<Vec<u8>, EncodeFailure>,
        code: ResultCode,
        reason: AuditReason,
    ) {
        match encoded {
            Ok(octets) => {
                self.responses.push(octets);
                self.result_code = Some(code);
                self.reason = reason;
            }
            Err(EncodeFailure) => self.fail_internal(),
        }
    }

    /// Send a Notice of Disconnection with `code` and close.
    /// Spec: RFC 4511 §4.4.1, §5.3.
    fn disconnect(&mut self, code: ResultCode, reason: AuditReason) {
        match respond::notice(code) {
            Ok(octets) => {
                self.responses.push(octets);
                self.notice = Some(code);
                self.reason = reason;
                self.action = ConnectionAction::Close;
            }
            Err(EncodeFailure) => self.fail_internal(),
        }
    }

    /// Close with no response. Spec: RFC 4511 §5.3.
    fn close(&mut self, reason: AuditReason) {
        self.reason = reason;
        self.action = ConnectionAction::Close;
    }

    /// An encoding failure: drop every response, send a Notice of
    /// Disconnection (other) if it encodes, close. Fail closed.
    fn fail_internal(&mut self) {
        self.responses.clear();
        self.result_code = None;
        self.notice = None;
        if let Ok(octets) = respond::notice(ResultCode::Other) {
            self.responses.push(octets);
            self.notice = Some(ResultCode::Other);
        }
        self.reason = AuditReason::InternalFailure;
        self.action = ConnectionAction::Close;
    }

    /// Apply the action to the session and build the outcome.
    fn finish(self, session: &mut Session) -> Outcome {
        match self.action {
            ConnectionAction::Close => session.phase = Phase::Closed,
            ConnectionAction::StartTls => session.phase = Phase::StartTlsPending,
            ConnectionAction::Continue => {}
        }
        let audit = AuditEvent {
            time: self.time,
            connection_id: self.connection_id,
            source_zone: self.source_zone,
            transport: audit_transport(session.channel),
            transport_sec: self.transport_sec,
            operation: self.operation,
            message_id: self.message_id,
            principal: self.principal,
            bind: self.bind,
            target: self.target,
            search: self.search,
            result_code: self.result_code,
            notice: self.notice,
            action: self.action,
            reason: self.reason,
        };
        Outcome {
            responses: self.responses,
            action: self.action,
            audit,
        }
    }
}
