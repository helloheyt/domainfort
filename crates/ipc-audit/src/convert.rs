//! Conversions from each source crate's audit type to its wire shape
//! (features `kdc`, `keyd`, `ldap`).
//!
//! A sender calls `KdcEvent::from(&event)` (or the keyd equivalent;
//! `LdapEvent::from_engine(&event, reported_peer)` for ldap, whose wire shape
//! adds the client address ldap-front reported — docs/52 R14), wraps it in
//! an [`crate::EventBody`] and commits it to its
//! [`crate::SendWindow`]. Every field of the source type is carried; none of
//! them is secret (the source types were built without any field that could
//! hold one — crates/kdc, keyd, ldap audit.rs). Client strings pass the
//! [`crate::AuditText`] rule again on the way.
//!
//! Enumerations map variant to same-named table entry (`Source::X =>
//! Table::X`), so a misspelled or renamed variant fails to compile; a
//! variant added to a `#[non_exhaustive]` source enumeration later maps to
//! `Unlisted` until its table entry is added (crate::codes).
//!
//! Spec: docs/50 §8.1, §8.2; docs/37 §2; docs/questions/Q-252 items 3, 4.

/// Map the unit variants of a source enum to the same-named variants of a
/// code table, then any further arms.
#[cfg(any(feature = "kdc", feature = "keyd", feature = "ldap"))]
macro_rules! map_units {
    ($value:expr, $src:ident => $dst:ident { $($variant:ident),* $(,)? } $($rest:tt)*) => {
        match $value {
            $( $src::$variant => $dst::$variant, )*
            $($rest)*
        }
    };
}

#[cfg(any(feature = "kdc", feature = "keyd", feature = "ldap"))]
fn calendar_time(time: &krb_proto::KerberosTime) -> crate::CalendarTime {
    // KerberosTime holds only validated calendar fields (crates/krb-proto
    // basic.rs: year ≤ 9999, month 1-12, day within the month, hour 0-23,
    // minute 0-59, second 0-59), so the ranges always hold; the fallback is
    // unreachable and only avoids a panic path.
    crate::CalendarTime::new(
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
    )
    .unwrap_or(crate::CalendarTime::EPOCH)
}

#[cfg(any(feature = "kdc", feature = "ldap"))]
mod from_pdp {
    use crate::{PdpReason, PdpReasonCode};

    /// `pdp::ReasonCode` → [`PdpReason`]. Spec: crates/pdp model.rs.
    pub(crate) fn reason(code: &pdp::ReasonCode) -> PdpReason {
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

    /// `pdp::IpScope` → [`crate::IpZone`]. Spec: docs/11 §1.
    #[cfg(feature = "ldap")]
    pub(crate) fn zone(scope: &pdp::IpScope) -> crate::IpZone {
        use crate::IpZone;
        use pdp::IpScope as Src;
        map_units!(scope, Src => IpZone { Internal, External })
    }
}

#[cfg(feature = "kdc")]
mod from_kdc {
    use super::{calendar_time, from_pdp};
    use crate::{AuditText, KdcEvent, KdcExchange, KdcOutcome, KdcReason, KdcTransport, Principal};

    /// `kdc::NamedPrincipal` → [`Principal`] (each string by the
    /// [`AuditText`] rule). Spec: crates/kdc accounts.rs; docs/50 §8.2.
    pub(crate) fn principal(named: &kdc::NamedPrincipal) -> Principal {
        Principal::new(
            AuditText::from_client(named.realm.as_str()),
            named.name.name_type,
            named
                .name
                .name_string
                .iter()
                .map(|component| AuditText::from_client(component.as_str()))
                .collect(),
        )
    }

    fn reason(reason: &kdc::AuditReason) -> KdcReason {
        use kdc::AuditReason as Src;
        map_units!(reason, Src => KdcReason {
            Issued, Retransmission, ReplyTooBigForUdp, RequestTooLong, ReservedLengthBit,
            UnsupportedMessageType, BadProtocolVersion, Malformed, CrossRealm, MissingName,
            AsServerNotTgs, TgsForTgs, UnsupportedOption, UnsupportedContent, CannotPostdate,
            NeverValid, ClientUnknown, ServiceUnknown, ClientRevoked, TgtRevoked,
            ServiceRevoked, AccountSourceFailure, AccountSourceUnavailable, CustodyUnavailable,
            AccountRecordInvalid, NoCommonEncType, PreauthRequired, PreauthAmbiguous,
            PreauthUnacceptable, PreauthDenied, PreauthSkew, TgsPadataMissing,
            TgsPadataAmbiguous, ApReqMalformed, NotLocalTgt, TgtDenied, TgtExpired,
            TgtNotYetValid, AuthenticatorSkew, AuthenticatorReplay, RateLimited,
            UnsupportedObligation, AmbiguousServiceName, ClockOutOfRange, IssueDenied,
            TemplateRejected, InternalFailure, FastRequired, FastPadataAmbiguous,
            FastMalformed, FastArmorMissing, FastArmorTypeUnsupported, TgsExplicitArmor,
            ArmorDenied, ArmorSkew, ArmorNotYetValid, ArmorExpired, ArmorReplay,
            ArmorPrincipalUnknown, ArmorNotComputer, ArmorPrincipalRevoked,
            UnknownCriticalFastOption, CookieMismatch, FastContextMissing,
        }
            Src::PolicyDenied(_) => KdcReason::PolicyDenied,
            _ => KdcReason::Unlisted,
        )
    }

    impl From<&kdc::AuditEvent> for KdcEvent {
        /// Every field of the KDC's event. Spec: crates/kdc audit.rs.
        fn from(event: &kdc::AuditEvent) -> KdcEvent {
            use kdc::{AuditOutcome, Exchange, Transport};
            let policy_reason = match &event.reason {
                kdc::AuditReason::PolicyDenied(code) => Some(from_pdp::reason(code)),
                _ => None,
            };
            KdcEvent {
                time: calendar_time(&event.time),
                transport: map_units!(&event.transport, Transport => KdcTransport { Udp, Tcp }),
                exchange: event
                    .exchange
                    .as_ref()
                    .map(|exchange| map_units!(exchange, Exchange => KdcExchange { As, Tgs })),
                client: event.client.as_ref().map(principal),
                service: event.service.as_ref().map(principal),
                armor_principal: event.armor.principal.as_ref().map(principal),
                reply_armored: event.armor.reply_armored,
                outcome: match event.outcome {
                    AuditOutcome::Issued => KdcOutcome::Issued,
                    AuditOutcome::Refused { error_code } => KdcOutcome::Refused { error_code },
                    AuditOutcome::Dropped => KdcOutcome::Dropped,
                },
                reason: reason(&event.reason),
                policy_reason,
            }
        }
    }
}

#[cfg(feature = "keyd")]
mod from_keyd {
    use super::calendar_time;
    use crate::{
        KeyPurposeCode, KeyRef, KeydOperation, KeydOutcome, KeydReason, KeydRecord, KeydRole,
    };

    fn purpose(purpose: &keyd::KeyPurpose) -> KeyPurposeCode {
        use keyd::KeyPurpose as Src;
        map_units!(purpose, Src => KeyPurposeCode {
            PrincipalLongterm, Krbtgt, Service, AdminService, ChangePasswordService,
        })
    }

    fn reason(reason: &keyd::AuditReason) -> KeydReason {
        use keyd::AuditReason as Src;
        map_units!(reason, Src => KeydReason {
            None, RoleNotPermitted, PurposeMismatch, KeyNotFound, KeyExists,
            StoreRefusedCritical, StoreFull, NameBindingMismatch, InvalidNameBinding,
            KvnoExhausted, KvnoNotRetirable, KvnoMismatch, DualControlRejected,
            EntropyFailure, UnsupportedEncType, UnsupportedPadataType, MalformedInput,
            IntegrityFailure, ClockSkew, TicketNotYetValid, TicketExpired, TicketInvalidFlag,
            NotLocalTgt, WrongRealm, UnsupportedApOption, UnsupportedContent, NameMismatch,
            ChecksumMissing, ChecksumUnsupported, ChecksumMismatch, Replay, ReplayCacheFull,
            TokenUnknown, TokenExpired, TokenCallerMismatch, TokenPrincipalMismatch,
            TokenTableFull, TemplateFlags, TemplateTimes, TemplateNames, TemplateEncType,
            TemplateNonce, SecretMismatch, NoPasswordKey, Throttled, S2kRefused,
            InternalFailure, ArmorMissing, ArmorTypeUnsupported, ArmorSubkeyMissing,
            ArmorChecksumPresent, FastChecksumMismatch, FastErrorContentRefused,
            FastErrorPadataRefused, ArmorAlreadyAttempted, ChallengeEncTypeMismatch,
            ArmorProofMismatch, FastBindingMismatch, TgsExplicitArmor, FastApReqMismatch,
            ArmorConversationMismatch, ServiceKeyNotRandom, TransitedNotLocal,
            ApChecksumUnsupported, StartupHoldDown, NoGrant, GrantMismatch, GrantInvalid,
            GrantTableFull, NoDecision, DecisionMismatch, DecisionInvalid, DecisionTableFull,
            DecisionConflict, DecisionReplayed, CeremonySealed, OperationDigestMissing,
            OperationDigestMismatch, SecretDecisionDiscarded, SubkeyMissing,
            SequenceNumberMissing, KrbPrivSequenceMismatch, KrbPrivTimestampSkew,
            KrbPrivAddressMismatch, PasswordPolicyRefused, ChangePasswordNotAcceptable,
            ResultCodeNotPermitted, KpasswdMalformed, KpasswdHardError, KpasswdAuthError,
            KpasswdSoftError, KpasswdAccessDenied, KpasswdInitialFlagNeeded,
        }
            _ => KeydReason::Unlisted,
        )
    }

    impl From<&keyd::AuditRecord> for KeydRecord {
        /// Every field of keyd's record (I8: none is secret).
        /// Spec: crates/keyd audit.rs; docs/10 §10.
        fn from(record: &keyd::AuditRecord) -> KeydRecord {
            use keyd::{AuditOutcome, Operation, Role};
            KeydRecord {
                ts: calendar_time(&record.ts),
                caller_role: map_units!(&record.caller_role, Role => KeydRole {
                    Kdc, Directory, Admin, Ldap,
                }),
                caller_uid: record.caller_uid,
                op: map_units!(&record.op, Operation => KeydOperation {
                    VerifyPreauth, IssueAsRep, OpenAndVerifyTgt, IssueTgsRep, SetSecret,
                    VerifySecret, CreateKey, RotateKey, RotateKrbtgt, RetireKvno,
                    OpenFastArmor, SealFastError, DestroyKeySet, OpenAndVerifyServiceTicket,
                    DescribeConfig, Ping, GrantSetSecret, RegisterDecision, SealCeremony,
                    ListDestroyDecisions, VerifyOperationTicket, OpenChangePasswordRequest,
                    CompleteChangePassword, SealChangePasswordError,
                }),
                principal: record.principal.map(|id| *id.as_bytes()),
                purpose: record.purpose.as_ref().map(purpose),
                kvno: record.kvno.map(keyd::Kvno::get),
                secondary: record.secondary.as_ref().map(|key| KeyRef {
                    principal: *key.principal.as_bytes(),
                    purpose: purpose(&key.purpose),
                    kvno: key.kvno.map(keyd::Kvno::get),
                }),
                approvers: record
                    .approvers
                    .map(|[a, b]| [*a.as_bytes(), *b.as_bytes()]),
                result: map_units!(&record.result, AuditOutcome => KeydOutcome {
                    Success, Denied, BadTemplate, Unavailable, RateLimited,
                }),
                reason: reason(&record.reason),
                decision: record.decision.map(keyd::DecisionId::get),
            }
        }
    }
}

#[cfg(feature = "ldap")]
mod from_ldap {
    use super::{calendar_time, from_pdp};
    use crate::{
        AuditText, BindMechanism, CodecError, CodecErrorCode, CodecLimit, LdapAction, LdapBind,
        LdapEvent, LdapOperation, LdapReason, LdapSearch, LdapTarget, LdapTransport,
        ReportedAddress, SearchScope, SidValue, TransportSecurity, UnsupportedOpCode,
    };

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

    impl LdapEvent {
        /// Every field of the LDAP engine's event, and the client address
        /// ldap-front reported for the connection (`reported_peer`, an
        /// unverified observation the engine never received — dird passes
        /// it beside the event). There is no conversion without it, so no
        /// LDAP record lacks the reported address.
        /// Spec: crates/ldap audit.rs; docs/49 §10.1; docs/52 §7 R14.
        #[must_use]
        pub fn from_engine(event: &ldap::AuditEvent, reported_peer: ReportedAddress) -> LdapEvent {
            use ldap::{AuditTarget, AuditTransport, ConnectionAction};
            let policy_reason = match &event.reason {
                ldap::AuditReason::PolicyDenied(code) => Some(from_pdp::reason(code)),
                _ => None,
            };
            let codec_error = match &event.reason {
                ldap::AuditReason::Malformed(error) => Some(codec_error(error)),
                _ => None,
            };
            LdapEvent {
                time: calendar_time(&event.time),
                connection_id: event.connection_id,
                source_zone: from_pdp::zone(&event.source_zone),
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
    }
}
