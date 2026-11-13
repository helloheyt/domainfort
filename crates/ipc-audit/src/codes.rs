//! The closed code tables of the event encoding.
//!
//! Each table mirrors one enumeration that a source crate exposes in its
//! audit type (crates/kdc `audit`, crates/keyd `audit` / `authz` / `model`,
//! crates/ldap `audit`, crates/pdp `model`, crates/parse-ldap `error` /
//! `message`): one variant per source variant, **with the same name**, in
//! the source's declaration order. On the wire a value is one `u8`: its
//! position in the table plus one (0 is never a code) — docs/50 §3.3 ("enum
//! = `u8` from a closed table"). A code outside the table is refused when
//! decoding.
//!
//! The tables of source enumerations marked `#[non_exhaustive]` end in
//! `Unlisted`: a variant added to the source crate after this table was
//! written is still recorded (as `Unlisted`) rather than dropped — an audit
//! event is never lost to a missing table entry. New variants are appended
//! at the end of a table, before `Unlisted` moves; existing codes never
//! change meaning (the log keeps them forever). The conversions (features
//! `kdc`, `keyd`, `ldap`) map `Source::X => Table::X` by name, so a renamed
//! or misspelled variant does not compile.
//!
//! Every variant carries no data: a code cannot hold a secret (docs/37 §2:
//! "only identifiers and metadata"; AGENTS.md §6).
//!
//! Spec: docs/50 §3.3, §8.1, §8.2; docs/37 §2; docs/questions/Q-252
//! items 3, 4.

/// Defines a closed code table: a field-less enum with `ALL`, `code`,
/// `from_code` and `name`.
macro_rules! code_table {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $($variant:ident),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        #[allow(missing_docs)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// Every value, in code order (code = position + 1).
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The wire code: the position in [`Self::ALL`] plus one.
            /// Spec: docs/50 §3.3 ("enum = `u8` from a closed table").
            #[must_use]
            pub const fn code(self) -> u8 {
                // Discriminants are the declaration positions 0.., and the
                // table has fewer than 255 entries (checked below).
                (self as u8) + 1
            }

            /// The value of a wire code, or `None` outside the closed table.
            /// Spec: docs/50 §3.3.
            #[must_use]
            pub fn from_code(code: u8) -> Option<$name> {
                let index = usize::from(code).checked_sub(1)?;
                Self::ALL.get(index).copied()
            }

            /// The variant's name — the source variant's name.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $($name::$variant => stringify!($variant)),+
                }
            }
        }

        const _: () = assert!($name::ALL.len() < 255);
    };
}

// ---- crates/kdc -------------------------------------------------------------

code_table! {
    /// `kdc::Transport`. Spec: RFC 4120 7.2 (as cited in crates/kdc).
    pub enum KdcTransport { Udp, Tcp }
}

code_table! {
    /// `kdc::Exchange`. Spec: RFC 4120 3.1, 3.3 (as cited in crates/kdc).
    pub enum KdcExchange { As, Tgs }
}

code_table! {
    /// `kdc::AuditReason` (non-exhaustive: ends in `Unlisted`).
    /// `PolicyDenied` is followed on the wire by the PDP reason
    /// ([`crate::KdcEvent::policy_reason`]).
    /// Spec: crates/kdc audit.rs; docs/11 §1b, §8.
    pub enum KdcReason {
        Issued,
        Retransmission,
        ReplyTooBigForUdp,
        RequestTooLong,
        ReservedLengthBit,
        UnsupportedMessageType,
        BadProtocolVersion,
        Malformed,
        CrossRealm,
        MissingName,
        AsServerNotTgs,
        TgsForTgs,
        UnsupportedOption,
        UnsupportedContent,
        CannotPostdate,
        NeverValid,
        ClientUnknown,
        ServiceUnknown,
        ClientRevoked,
        TgtRevoked,
        ServiceRevoked,
        AccountSourceFailure,
        AccountSourceUnavailable,
        CustodyUnavailable,
        AccountRecordInvalid,
        NoCommonEncType,
        PreauthRequired,
        PreauthAmbiguous,
        PreauthUnacceptable,
        PreauthDenied,
        PreauthSkew,
        TgsPadataMissing,
        TgsPadataAmbiguous,
        ApReqMalformed,
        NotLocalTgt,
        TgtDenied,
        TgtExpired,
        TgtNotYetValid,
        AuthenticatorSkew,
        AuthenticatorReplay,
        PolicyDenied,
        RateLimited,
        UnsupportedObligation,
        AmbiguousServiceName,
        ClockOutOfRange,
        IssueDenied,
        TemplateRejected,
        InternalFailure,
        FastRequired,
        FastPadataAmbiguous,
        FastMalformed,
        FastArmorMissing,
        FastArmorTypeUnsupported,
        TgsExplicitArmor,
        ArmorDenied,
        ArmorSkew,
        ArmorNotYetValid,
        ArmorExpired,
        ArmorReplay,
        ArmorPrincipalUnknown,
        ArmorNotComputer,
        ArmorPrincipalRevoked,
        UnknownCriticalFastOption,
        CookieMismatch,
        FastContextMissing,
        Unlisted,
    }
}

// ---- crates/pdp -------------------------------------------------------------

code_table! {
    /// `pdp::ReasonCode`. `CoarseDeny` is followed on the wire by its rule
    /// id ([`crate::PdpReason::rule`]).
    /// Spec: crates/pdp model.rs; docs/11 §1b, §4, §8.
    pub enum PdpReasonCode {
        Allowed,
        InvalidRequest,
        Unauthenticated,
        WeakTransport,
        PipFailure,
        SubjectMismatch,
        CoarseDeny,
        NoGrant,
        TierViolation,
        Acl,
        NoSuchPath,
        Sensitive,
    }
}

code_table! {
    /// `pdp::IpScope`. Spec: docs/11 §1; docs/49 §10.1 (`source_zone`).
    pub enum IpZone { Internal, External }
}

// ---- crates/keyd ------------------------------------------------------------

code_table! {
    /// `keyd::Role`. Spec: docs/10 §2; crates/keyd authz.rs.
    pub enum KeydRole { Kdc, Directory, Admin, Ldap }
}

code_table! {
    /// `keyd::Operation`. Spec: docs/10 §2-§7; crates/keyd authz.rs.
    pub enum KeydOperation {
        VerifyPreauth,
        IssueAsRep,
        OpenAndVerifyTgt,
        IssueTgsRep,
        SetSecret,
        VerifySecret,
        CreateKey,
        RotateKey,
        RotateKrbtgt,
        RetireKvno,
        OpenFastArmor,
        SealFastError,
        DestroyKeySet,
        OpenAndVerifyServiceTicket,
        DescribeConfig,
        Ping,
    }
}

code_table! {
    /// `keyd::KeyPurpose`. Spec: docs/10 §2 (I3); crates/keyd model.rs.
    pub enum KeyPurposeCode { PrincipalLongterm, Krbtgt, Service }
}

code_table! {
    /// `keyd::AuditOutcome`. Spec: docs/10 §9, §10.
    pub enum KeydOutcome { Success, Denied, BadTemplate, Unavailable, RateLimited }
}

code_table! {
    /// `keyd::AuditReason` (non-exhaustive: ends in `Unlisted`).
    /// Spec: crates/keyd audit.rs; docs/10 §9, §10, I8.
    pub enum KeydReason {
        None,
        RoleNotPermitted,
        PurposeMismatch,
        KeyNotFound,
        KeyExists,
        StoreRefusedCritical,
        StoreFull,
        NameBindingMismatch,
        InvalidNameBinding,
        KvnoExhausted,
        KvnoNotRetirable,
        KvnoMismatch,
        DualControlRejected,
        EntropyFailure,
        UnsupportedEncType,
        UnsupportedPadataType,
        MalformedInput,
        IntegrityFailure,
        ClockSkew,
        TicketNotYetValid,
        TicketExpired,
        TicketInvalidFlag,
        NotLocalTgt,
        WrongRealm,
        UnsupportedApOption,
        UnsupportedContent,
        NameMismatch,
        ChecksumMissing,
        ChecksumUnsupported,
        ChecksumMismatch,
        Replay,
        ReplayCacheFull,
        TokenUnknown,
        TokenExpired,
        TokenCallerMismatch,
        TokenPrincipalMismatch,
        TokenTableFull,
        TemplateFlags,
        TemplateTimes,
        TemplateNames,
        TemplateEncType,
        TemplateNonce,
        SecretMismatch,
        NoPasswordKey,
        Throttled,
        S2kRefused,
        InternalFailure,
        ArmorMissing,
        ArmorTypeUnsupported,
        ArmorSubkeyMissing,
        ArmorChecksumPresent,
        FastChecksumMismatch,
        FastErrorContentRefused,
        FastErrorPadataRefused,
        ArmorAlreadyAttempted,
        ChallengeEncTypeMismatch,
        ArmorProofMismatch,
        FastBindingMismatch,
        TgsExplicitArmor,
        FastApReqMismatch,
        ArmorConversationMismatch,
        ServiceKeyNotRandom,
        TransitedNotLocal,
        ApChecksumUnsupported,
        StartupHoldDown,
        Unlisted,
    }
}

// ---- crates/ldap ------------------------------------------------------------

code_table! {
    /// `ldap::AuditTransport`. Spec: docs/49 §10.1.
    pub enum LdapTransport { Ldap, Ldaps, StartTls }
}

code_table! {
    /// `parse_ldap::UnsupportedOp`. Spec: RFC 4511 §4.6-§4.10 (as cited in
    /// crates/parse-ldap); A-48.
    pub enum UnsupportedOpCode {
        ModifyRequest,
        AddRequest,
        DelRequest,
        ModifyDnRequest,
        CompareRequest,
    }
}

code_table! {
    /// `ldap::AuditScope`. Spec: RFC 4511 §4.5.1.2 (as cited in crates/ldap).
    pub enum SearchScope { BaseObject, SingleLevel, WholeSubtree, Unrecognized }
}

code_table! {
    /// `ldap::ConnectionAction`. Spec: docs/49 §11; crates/ldap engine.rs.
    pub enum LdapAction { Continue, StartTls, Close }
}

code_table! {
    /// `ldap::AuditReason` (non-exhaustive: ends in `Unlisted`).
    /// `Malformed` is followed on the wire by the codec error
    /// ([`crate::LdapEvent::codec_error`]); `PolicyDenied` by the PDP reason
    /// ([`crate::LdapEvent::policy_reason`]).
    /// Spec: crates/ldap audit.rs; docs/49 §9, §10.1.
    pub enum LdapReason {
        SessionClosed,
        Malformed,
        NotARequest,
        Oversized,
        RequestDuringStartTls,
        TransportMismatch,
        Unbind,
        Abandon,
        IdentityExpired,
        IdentityRevoked,
        AccountSourceFailure,
        UnavailableCriticalControl,
        AnonymousBind,
        UnsupportedVersion,
        UnauthenticatedBind,
        SimplePasswordBind,
        SaslEmptyMechanism,
        SaslWithoutTls,
        SaslGssapiNotAvailable,
        SaslMechanismUnsupported,
        AuthenticationChoiceUnsupported,
        StartTlsAccepted,
        TlsAlreadyEstablished,
        StartTlsWithPendingInput,
        StartTlsRequestValue,
        ExtendedOperationUnrecognized,
        RootDseReturned,
        ScopeUnrecognized,
        RootDseScopeNotBase,
        SearchNotImplemented,
        SearchCompleted,
        BaseDnSyntax,
        BaseNotFound,
        BaseNotVisible,
        SizeLimitExceeded,
        PageLimitExceeded,
        VisitBudgetExceeded,
        ResponseTooLarge,
        ValueBudgetExceeded,
        DepthExceeded,
        TimeLimitExceeded,
        QueryDurationExceeded,
        DirectoryUnavailable,
        NamingContextMismatch,
        UnrepresentableDn,
        PolicyDenied,
        RateLimited,
        PageSizeExceeded,
        ClockOutOfRange,
        SubjectUnavailable,
        OperationNotSupported,
        InternalFailure,
        Unlisted,
    }
}

// ---- crates/parse-ldap ------------------------------------------------------

code_table! {
    /// `parse_ldap::Error` (non-exhaustive: ends in `Unlisted`).
    /// `LimitExceeded` is followed on the wire by the limit
    /// ([`crate::CodecError::limit`]).
    /// Spec: crates/parse-ldap error.rs; docs/49 §2.3, §9.
    pub enum CodecErrorCode {
        Truncated,
        LengthExceedsInput,
        IndefiniteLength,
        ReservedLengthOctet,
        TooManyLengthOctets,
        NonMinimalLength,
        HighTagNumber,
        EndOfContents,
        LimitExceeded,
        MessageTooLarge,
        TrailingData,
        MissingComponent,
        UnexpectedTag,
        PrimitiveConstructedMismatch,
        ConstructedOctetString,
        UnrecognizedComponent,
        NonCanonical,
        InvalidBoolean,
        ExplicitDefault,
        EmptyInteger,
        NonMinimalInteger,
        IntegerOutOfRange,
        MessageIdOutOfRange,
        ZeroMessageId,
        VersionOutOfRange,
        InvalidNull,
        InvalidUtf8,
        UnrecognizedProtocolOp,
        EmptySet,
        EmptySubstrings,
        SubstringOrder,
        MissingMatchingRuleAndType,
        UnrecognizedResultCode,
        InvalidValue,
        Unlisted,
    }
}

code_table! {
    /// `parse_ldap::Limit` (non-exhaustive: ends in `Unlisted`).
    /// Spec: crates/parse-ldap error.rs.
    pub enum CodecLimit {
        TlvDepth,
        FilterDepth,
        FilterNodes,
        SubstringAny,
        AttributeSelectors,
        Controls,
        PartialAttributes,
        AttributeValues,
        LdapDnOctets,
        IdentifierOctets,
        ValueOctets,
        Unlisted,
    }
}

// ---- event shapes and the window summary -------------------------------------

code_table! {
    /// `kdc::AuditOutcome`'s variants (the wire tag of
    /// [`crate::KdcOutcome`]). Spec: crates/kdc audit.rs; RFC 4120 7.5.9.
    pub enum KdcOutcomeCode { Issued, Refused, Dropped }
}

code_table! {
    /// `ldap::AuditOperation`'s variants (the wire tag of
    /// [`crate::LdapOperation`]). Spec: crates/ldap audit.rs; docs/49 §10.1.
    pub enum LdapOperationCode {
        Bind,
        Unbind,
        Search,
        Abandon,
        StartTls,
        Extended,
        NotSupported,
        Malformed,
        NotDecoded,
    }
}

code_table! {
    /// `ldap::BindMechanism`'s variants (the wire tag of
    /// [`crate::BindMechanism`]). Spec: crates/ldap audit.rs; RFC 4513 §5.
    pub enum BindMechanismCode {
        SimpleAnonymous,
        SimpleUnauthenticated,
        SimplePassword,
        Sasl,
        Unrecognized,
    }
}

code_table! {
    /// `ldap::AuditTarget`'s variants (the wire tag of
    /// [`crate::LdapTarget`]). Spec: crates/ldap audit.rs; docs/49 §10.1.
    pub enum LdapTargetCode { RootDse, DirObject }
}

code_table! {
    /// The event shapes (the wire tag of [`crate::EventBody`]).
    /// Spec: docs/50 §8.1; docs/questions/Q-252 item 3.
    pub enum EventShape { Kdc, Keyd, Ldap, WindowSummary }
}
