//! The conversion from the LDAP engine's audit event (crates/ldap
//! `AuditEvent`) to its wire shape on the audit channel
//! (`ipc_audit::LdapEvent`), with the client address ldap-front reported
//! (docs/52 R14).
//!
//! # Why here (task IB1)
//!
//! Until task IB1 this was `LdapEvent::from_engine` in crate ipc-audit,
//! behind its feature `ldap`, which made ldap, pdp, krb-proto, dtyp and
//! parse-ldap optional dependencies of ipc-audit. Cargo unifies features
//! within one build, so in a shared build the `ldap` feature reached every
//! daemon that linked ipc-audit — and with it crates/ldap, dirstore and
//! redb — while the `keyd` feature put keyd and krb-crypto into this one
//! (class C40; docs/questions/Q-851, decision A-144). Now no manifest
//! declares an `optional` dependency and the conversion lives on the side
//! that already links the engine and its types: this daemon, the only
//! sender of LDAP events (docs/50 §4.2: "the LDAP event is written by dird,
//! the PEP"). An inherent method of a foreign type cannot be defined here,
//! so it is the plain function [`ldap_event`].
//!
//! Every field of the source type is carried; none of them is secret (the
//! engine's event was built without any field that could hold one —
//! crates/ldap audit.rs). Client strings pass the `ipc_audit::AuditText`
//! rule again on the way. Enumerations map variant to same-named table
//! entry (`Source::X => Table::X`), so a misspelled or renamed variant fails
//! to compile; a variant added to a `#[non_exhaustive]` source enumeration
//! later maps to `Unlisted` until its table entry is added (crates/ipc-audit
//! codes.rs).
//!
//! Moved unchanged from crates/ipc-audit `convert.rs` (this project's own
//! code, task P6; R14), written there only from docs/50 §8.1, §8.2, docs/37
//! §2, docs/49 §10.1, docs/52 §7 R14, docs/questions/Q-252 items 3, 4 and
//! the public API of crates/ldap (audit, engine), crates/pdp (model),
//! crates/parse-ldap (error, message), crates/dtyp (sid, guid) and
//! crates/krb-proto (basic). No other implementation was consulted or
//! recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/50 §8.1, §8.2; docs/37 §2; docs/49 §10.1; docs/52 §7 R14;
//! docs/questions/Q-252 items 3, 4. Decision: A-144; Q-851.

use ipc_audit::{
    AuditText, BindMechanism, CalendarTime, CodecError, CodecErrorCode, CodecLimit, IpZone,
    LdapAction, LdapBind, LdapEvent, LdapOperation, LdapReason, LdapSearch, LdapTarget,
    LdapTransport, PdpReason, PdpReasonCode, ReportedAddress, SearchScope, SidValue,
    TransportSecurity, UnsupportedOpCode,
};

/// Map the unit variants of a source enum to the same-named variants of a
/// code table, then any further arms.
macro_rules! map_units {
    ($value:expr, $src:ident => $dst:ident { $($variant:ident),* $(,)? } $($rest:tt)*) => {
        match $value {
            $( $src::$variant => $dst::$variant, )*
            $($rest)*
        }
    };
}

/// `krb_proto::KerberosTime` → [`CalendarTime`].
fn calendar_time(time: &krb_proto::KerberosTime) -> CalendarTime {
    // KerberosTime holds only validated calendar fields (crates/krb-proto
    // basic.rs: year ≤ 9999, month 1-12, day within the month, hour 0-23,
    // minute 0-59, second 0-59), so the ranges always hold; the fallback is
    // unreachable and only avoids a panic path.
    CalendarTime::new(
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
    )
    .unwrap_or(CalendarTime::EPOCH)
}

/// `pdp::ReasonCode` → [`PdpReason`]. Spec: crates/pdp model.rs.
fn pdp_reason(code: &pdp::ReasonCode) -> PdpReason {
    use pdp::ReasonCode as Src;
    let mut rule = None;
    let code = map_units!(code, Src => PdpReasonCode {
        Allowed, InvalidRequest, Unauthenticated, WeakTransport, PipFailure,
        SubjectMismatch, NoGrant, TierViolation, Acl, NoSuchPath, Sensitive,
    }
        Src::CoarseDeny(id) => {
            rule = Some(id.0);
            PdpReasonCode::CoarseDeny
        }
    );
    PdpReason { code, rule }
}

/// `pdp::IpScope` → [`IpZone`]. Spec: docs/11 §1.
fn zone(scope: &pdp::IpScope) -> IpZone {
    use pdp::IpScope as Src;
    map_units!(scope, Src => IpZone { Internal, External })
}

/// `ldap::AuditText` → [`AuditText`] (the same rule, applied again).
fn text(text: &ldap::AuditText) -> AuditText {
    match text {
        ldap::AuditText::Text(kept) => AuditText::from_client(kept),
        ldap::AuditText::Withheld => AuditText::WITHHELD,
    }
}

fn sid(sid: &dtyp::Sid) -> SidValue {
    // dtyp::Sid holds at most SID_MAX_SUB_AUTHORITIES (15), so nothing
    // is ever dropped here.
    SidValue::clamped(sid.identifier_authority(), sid.sub_authority())
}

fn codec_error(error: &parse_ldap::Error) -> CodecError {
    use parse_ldap::Error as Src;
    use parse_ldap::Limit;
    let mut limit = None;
    let error = map_units!(error, Src => CodecErrorCode {
        Truncated, LengthExceedsInput, IndefiniteLength, ReservedLengthOctet,
        TooManyLengthOctets, NonMinimalLength, HighTagNumber, EndOfContents,
        MessageTooLarge, TrailingData, MissingComponent, UnexpectedTag,
        PrimitiveConstructedMismatch, ConstructedOctetString, UnrecognizedComponent,
        NonCanonical, InvalidBoolean, ExplicitDefault, EmptyInteger, NonMinimalInteger,
        IntegerOutOfRange, MessageIdOutOfRange, ZeroMessageId, VersionOutOfRange,
        InvalidNull, InvalidUtf8, UnrecognizedProtocolOp, EmptySet, EmptySubstrings,
        SubstringOrder, MissingMatchingRuleAndType, UnrecognizedResultCode, InvalidValue,
    }
        Src::LimitExceeded(which) => {
            limit = Some(map_units!(which, Limit => CodecLimit {
                TlvDepth, FilterDepth, FilterNodes, SubstringAny, AttributeSelectors,
                Controls, PartialAttributes, AttributeValues, LdapDnOctets,
                IdentifierOctets, ValueOctets,
            }
                _ => CodecLimit::Unlisted,
            ));
            CodecErrorCode::LimitExceeded
        }
        _ => CodecErrorCode::Unlisted,
    );
    CodecError { error, limit }
}

fn reason(reason: &ldap::AuditReason) -> LdapReason {
    use ldap::AuditReason as Src;
    map_units!(reason, Src => LdapReason {
        SessionClosed, NotARequest, Oversized, RequestDuringStartTls, TransportMismatch,
        Unbind, Abandon, IdentityExpired, IdentityRevoked, AccountSourceFailure,
        UnavailableCriticalControl, AnonymousBind, UnsupportedVersion, UnauthenticatedBind,
        SimplePasswordBind, SaslEmptyMechanism, SaslWithoutTls, SaslGssapiNotAvailable,
        SaslMechanismUnsupported, AuthenticationChoiceUnsupported, StartTlsAccepted,
        TlsAlreadyEstablished, StartTlsWithPendingInput, StartTlsRequestValue,
        ExtendedOperationUnrecognized, RootDseReturned, ScopeUnrecognized,
        RootDseScopeNotBase, SearchNotImplemented, SearchCompleted, BaseDnSyntax,
        BaseNotFound, BaseNotVisible, SizeLimitExceeded, PageLimitExceeded,
        VisitBudgetExceeded, ResponseTooLarge, ValueBudgetExceeded, DepthExceeded,
        TimeLimitExceeded, QueryDurationExceeded, DirectoryUnavailable,
        NamingContextMismatch, UnrepresentableDn, RateLimited, PageSizeExceeded,
        ClockOutOfRange, SubjectUnavailable, OperationNotSupported, InternalFailure,
    }
        Src::Malformed(_) => LdapReason::Malformed,
        Src::PolicyDenied(_) => LdapReason::PolicyDenied,
        _ => LdapReason::Unlisted,
    )
}

fn operation(operation: &ldap::AuditOperation) -> LdapOperation {
    use ldap::AuditOperation as Src;
    use parse_ldap::UnsupportedOp;
    map_units!(operation, Src => LdapOperation {
        Bind, Unbind, Search, Abandon, StartTls, Extended, Malformed, NotDecoded,
    }
        Src::NotSupported(op) => LdapOperation::NotSupported(map_units!(
            op,
            UnsupportedOp => UnsupportedOpCode {
                ModifyRequest, AddRequest, DelRequest, ModifyDnRequest, CompareRequest,
            }
        )),
    )
}

fn bind(bind: &ldap::BindAudit) -> LdapBind {
    use ldap::BindMechanism as Src;
    LdapBind {
        version: bind.version,
        mechanism: match &bind.mechanism {
            Src::SimpleAnonymous => BindMechanism::SimpleAnonymous,
            Src::SimpleUnauthenticated => BindMechanism::SimpleUnauthenticated,
            Src::SimplePassword => BindMechanism::SimplePassword,
            Src::Sasl { mechanism } => BindMechanism::Sasl {
                mechanism: text(mechanism),
            },
            Src::Unrecognized { tag_number } => BindMechanism::Unrecognized {
                tag_number: *tag_number,
            },
        },
        name: bind.name.as_ref().map(text),
    }
}

fn search(search: &ldap::SearchAudit) -> LdapSearch {
    use ldap::AuditScope as Src;
    LdapSearch::new(
        map_units!(&search.scope, Src => SearchScope {
            BaseObject, SingleLevel, WholeSubtree, Unrecognized,
        }),
        search.entries_returned,
        search.candidates_visited,
        search.pruned_subtrees,
        search
            .filter_attrs
            .iter()
            .map(|name| AuditText::from_client(name))
            .collect(),
    )
}

/// The LDAP engine's audit event → [`LdapEvent`]: every field of the
/// engine's event, and the client address ldap-front reported for the
/// connection (`reported_peer`, an unverified observation the engine never
/// received — dird passes it beside the event). There is no conversion
/// without it, so no LDAP record lacks the reported address. The former
/// `LdapEvent::from_engine` of crate ipc-audit (feature `ldap`), unchanged.
///
/// Spec: crates/ldap audit.rs; docs/49 §10.1; docs/52 §7 R14. Decision:
/// A-144; Q-851.
#[must_use]
pub fn ldap_event(event: &ldap::AuditEvent, reported_peer: ReportedAddress) -> LdapEvent {
    use ldap::{AuditTarget, AuditTransport, ConnectionAction};
    let policy_reason = match &event.reason {
        ldap::AuditReason::PolicyDenied(code) => Some(pdp_reason(code)),
        _ => None,
    };
    let codec_error = match &event.reason {
        ldap::AuditReason::Malformed(error) => Some(codec_error(error)),
        _ => None,
    };
    LdapEvent {
        time: calendar_time(&event.time),
        connection_id: event.connection_id,
        source_zone: zone(&event.source_zone),
        reported_peer,
        transport: map_units!(&event.transport, AuditTransport => LdapTransport {
            Ldap, Ldaps, StartTls,
        }),
        transport_sec: TransportSecurity {
            encrypted: event.transport_sec.encrypted,
            sealed: event.transport_sec.sealed,
            channel_bound: event.transport_sec.channel_bound,
        },
        operation: operation(&event.operation),
        message_id: event.message_id.map(parse_ldap::MessageId::get),
        principal: event.principal.as_ref().map(sid),
        bind: event.bind.as_ref().map(bind),
        target: event.target.as_ref().map(|target| match target {
            AuditTarget::RootDse => LdapTarget::RootDse,
            AuditTarget::DirObject(guid) => LdapTarget::DirObject(guid.to_packet()),
        }),
        search: event.search.as_ref().map(search),
        result_code: event.result_code.map(parse_ldap::ResultCode::code),
        notice: event.notice.map(parse_ldap::ResultCode::code),
        action: map_units!(&event.action, ConnectionAction => LdapAction {
            Continue, StartTls, Close,
        }),
        reason: reason(&event.reason),
        policy_reason,
        codec_error,
    }
}
