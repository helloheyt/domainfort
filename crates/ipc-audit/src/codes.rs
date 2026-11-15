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
//! change meaning (the log keeps them forever). The conversions — on the
//! side that already links each source crate since task IB1
//! (docs/questions/Q-851, A-144): crates/kdc-daemon `audit_convert`,
//! crates/ipc-keyd-server `audit_convert`, crates/directory-daemon
//! `audit_convert` — map `Source::X => Table::X` by name, so a renamed or
//! misspelled variant does not compile.
//!
//! One table extends its source: [`KeydOutcome`] appends, after keyd's five
//! outcomes, the two phase codes keyd-daemon writes around a key-state
//! change (`Intent`, `NotPerformed`; decision A-86, docs/questions/Q-365).
//! No source variant maps to them, and the five existing codes keep their
//! meaning.
//!
//! Every variant carries no data: a code cannot hold a secret (docs/37 §2:
//! "only identifiers and metadata"; AGENTS.md §6).
//!
//! The admin-plane tables (`DirAdmin`, `Admind` shapes — docs/51 §5.7, task
//! A7) have no source crate yet; they mirror the operation and step names of
//! docs/51 and are documented where they are defined.
//!
//! Spec: docs/50 §3.3, §8.1, §8.2; docs/37 §2; docs/questions/Q-252
//! items 3, 4; docs/51 §5.7; docs/questions/Q-340.

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
    /// `keyd::Operation`. `GrantSetSecret` (code 17) was appended by task
    /// A15a (docs/51 §5.8 option (b); docs/questions/Q-450); codes 1-16 keep
    /// their meaning. `RegisterDecision`, `SealCeremony`,
    /// `ListDestroyDecisions` (codes 18-20) were appended by A-102 (docs/52
    /// R1, R3). `VerifyOperationTicket` (code 21) was appended by Q-523 (the
    /// operation-bound service-ticket verification, which keeps no service
    /// context); codes 1-20 keep their meaning. `OpenChangePasswordRequest`,
    /// `CompleteChangePassword`, `SealChangePasswordError` (codes 22-24) were
    /// appended by task K3 (docs/53 §5.5, §9); codes 1-21 keep their meaning.
    /// `RevokeDecision` (code 25) was appended by task F3 (docs/questions/
    /// Q-976); codes 1-24 keep their meaning.
    /// Spec: docs/10 §2-§7; crates/keyd authz.rs; docs/52 §4; docs/53 §9.
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
        GrantSetSecret,
        RegisterDecision,
        SealCeremony,
        ListDestroyDecisions,
        VerifyOperationTicket,
        OpenChangePasswordRequest,
        CompleteChangePassword,
        SealChangePasswordError,
        RevokeDecision,
    }
}

code_table! {
    /// `keyd::KeyPurpose`. `AdminService` (code 4) appended by R2 (A-102,
    /// docs/52 §5 item 3); 1-3 keep their codes. `ChangePasswordService`
    /// (code 5) appended by task K3 (docs/53 §5.2); 1-4 keep their codes.
    /// Spec: docs/10 §2 (I3); crates/keyd-types model.rs.
    pub enum KeyPurposeCode {
        PrincipalLongterm,
        Krbtgt,
        Service,
        AdminService,
        ChangePasswordService,
    }
}

code_table! {
    /// `keyd::AuditOutcome` (codes 1-5, by name), then two **phase** codes
    /// appended for decision A-86 (codes 6-7), which no `keyd::AuditOutcome`
    /// maps to: keyd-daemon writes them itself around an operation whose
    /// intent must be acknowledged first (`keyd::requires_acknowledged_intent`):
    /// one that changes keyd's key state (`keyd::changes_key_state`:
    /// `SetSecret`, `CreateKey`, `RotateKey`, `RotateKrbtgt`, `RetireKvno`,
    /// `DestroyKeySet`) or one that loosens keyd's authorization
    /// (`keyd::loosens_authorization`: `GrantSetSecret`, task A15a —
    /// docs/questions/Q-452; `RegisterDecision`, A-102):
    ///
    /// * `Intent` — the record of the intent, committed and **acknowledged
    ///   by auditd before keyd runs the operation**; keyd does not run it
    ///   without that acknowledgement.
    /// * `NotPerformed` — the outcome when the intent was not acknowledged
    ///   in time: keyd did not run the operation, and the caller was
    ///   answered `Unavailable`.
    ///
    /// Otherwise the outcome record of such an operation is keyd's own
    /// record (codes 1-5) with its true result. So every intent is followed
    /// by exactly one outcome record; an intent with none means the outcome
    /// was lost (the sender counts it).
    ///
    /// Spec: docs/10 §9, §10; docs/questions/Q-346 (A-86), Q-365.
    pub enum KeydOutcome {
        Success,
        Denied,
        BadTemplate,
        Unavailable,
        RateLimited,
        Intent,
        NotPerformed,
    }
}

code_table! {
    /// `keyd::AuditReason` (non-exhaustive: ends in `Unlisted`). The four
    /// grant reasons (`NoGrant` … `GrantTableFull`, codes 66-69) were
    /// appended by task A15a before `Unlisted`, which moved from 66 to 70
    /// (the table's rule for appended variants; nothing is deployed —
    /// docs/questions/Q-452 item 4). The seven decision reasons
    /// (`NoDecision` … `CeremonySealed`, codes 70-76) were appended by A-102
    /// the same way; `Unlisted` moved from 70 to 77. The two operation-binding
    /// reasons (`OperationDigestMissing`, `OperationDigestMismatch`, codes
    /// 77-78) were appended by R2 (A-102, docs/52 §5 item 3) the same way;
    /// `Unlisted` moved from 77 to 79. `SecretDecisionDiscarded` (code 79)
    /// was appended by R6b (docs/questions/Q-520) the same way; `Unlisted`
    /// moved from 79 to 80. The fourteen change-password reasons
    /// (`SubkeyMissing` … `KpasswdInitialFlagNeeded`, codes 80-93) were
    /// appended by task K3 (docs/53 §9) the same way; `Unlisted` moved from
    /// 80 to 94. The two revocation reasons (`DecisionRevoked`,
    /// `DecisionExecuted`, codes 94-95) were appended by task F3
    /// (docs/questions/Q-976) the same way; `Unlisted` moved from 94 to 96.
    /// Spec: crates/keyd audit.rs; docs/10 §9, §10, I8; docs/53 §9.
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
        NoGrant,
        GrantMismatch,
        GrantInvalid,
        GrantTableFull,
        NoDecision,
        DecisionMismatch,
        DecisionInvalid,
        DecisionTableFull,
        DecisionConflict,
        DecisionReplayed,
        CeremonySealed,
        OperationDigestMissing,
        OperationDigestMismatch,
        SecretDecisionDiscarded,
        SubkeyMissing,
        SequenceNumberMissing,
        KrbPrivSequenceMismatch,
        KrbPrivTimestampSkew,
        KrbPrivAddressMismatch,
        PasswordPolicyRefused,
        ChangePasswordNotAcceptable,
        ResultCodeNotPermitted,
        KpasswdMalformed,
        KpasswdHardError,
        KpasswdAuthError,
        KpasswdSoftError,
        KpasswdAccessDenied,
        KpasswdInitialFlagNeeded,
        DecisionRevoked,
        DecisionExecuted,
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
    /// The event shapes (the wire tag of [`crate::EventBody`]). `DirAdmin`
    /// and `Admind` were appended for the admin plane (docs/51 §5.7, R51-12,
    /// task A7); the codes of the first four are unchanged. `ZoneSerial` (7)
    /// was appended by task DN10b for dird's serial-only zone write
    /// (crate::zone; docs/questions/Q-1002, Q-1013); no earlier code moved.
    /// Spec: docs/50 §8.1; docs/questions/Q-252 item 3; docs/51 §5.7, §12
    /// (A7); docs/questions/Q-340, Q-1002 (A-172), Q-1013.
    pub enum EventShape { Kdc, Keyd, Ldap, WindowSummary, DirAdmin, Admind, ZoneSerial }
}

// ---- dird's serial-only zone write: the `ZoneSerial` shape (task DN10b) -------

code_table! {
    /// Why dird advances the zone's SOA SERIAL without a content write — the
    /// two instances of the class "the zone's content changes while its
    /// SERIAL does not" that no commit can see (docs/questions/Q-1002 item
    /// 1, Q-993 item 3):
    ///
    /// * `ServiceStart` — dird's DNS service starts: every image of the new
    ///   process gets a SERIAL after every SERIAL an earlier process served,
    ///   whatever changed in dird's zone configuration (Q-1002 item 4 (b);
    ///   docs/54 §5.4: "a change of the DC / of the SOA parameters
    ///   (configuration) ⇒ increment at dird's next start");
    /// * `ContentAged` — the clock changed the projection's answer under the
    ///   current SERIAL: an address reached `dns_record_max_age`, an account
    ///   its accountExpires (`ZoneProjection::valid_until` passed — Q-1002
    ///   item 4 (a)), or dird's clock went back past a change.
    ///
    /// Spec: RFC 2136 §3.6 (autoincrement events; "If the zone appears to
    /// change, the SOA must appear to change as well"); docs/54 §5.4;
    /// docs/questions/Q-1002 (A-172), Q-1013.
    pub enum ZoneSerialCause { ServiceStart, ContentAged }
}

code_table! {
    /// When dird sent a `ZoneSerial` event: `Decision` — before the write,
    /// acknowledged by auditd before the write commits; `Outcome` — after
    /// the commit (or its failure). The wire tag of
    /// [`crate::ZoneSerialStage`].
    /// Spec: docs/51 §5.7 item 2 ("decide ⇒ a decision event acknowledged
    /// ⇒ commit ⇒ an outcome event") as every dird state change (A-57,
    /// A-85); docs/52 §3.11 R6.
    pub enum ZoneSerialPhase { Decision, Outcome }
}

code_table! {
    /// What a `ZoneSerial` outcome says: the serial advanced (the new SERIAL
    /// follows on the wire), not needed (the counter moved after the
    /// decision — another write advanced it; nothing written), or failed
    /// (a [`ZoneSerialFailure`] follows). The wire tag of
    /// [`crate::ZoneSerialOutcome`].
    /// Spec: RFC 2136 §3.6, §7.10 ("Deferral of SOA SERIAL autoincrements is
    /// made possible so that serial numbers can be conserved"); docs/questions
    /// Q-1013.
    pub enum ZoneSerialOutcomeCode { Advanced, NotNeeded, Failed }
}

code_table! {
    /// Why a decided serial advance was not written — a class only.
    ///
    /// * `AuditUnacknowledged` — auditd did not acknowledge the decision
    ///   event within dird's deadline: not performed (docs/51 §5.7 item 2;
    ///   A-85 — the `DirAdmin` code of the same name, A-91).
    /// * `StoreFailure` — the store could not begin, read or commit the
    ///   transaction.
    /// * `CounterUnavailable` — the `dns-zone-serial` counter is missing or
    ///   exhausted (A-83: never created at run time).
    /// * `InternalFailure` — a misassembled caller or a time out of range.
    ///
    /// Spec: docs/51 §5.7 item 2; A-83; A-85; docs/questions/Q-1013.
    pub enum ZoneSerialFailure {
        AuditUnacknowledged,
        StoreFailure,
        CounterUnavailable,
        InternalFailure,
    }
}

// ---- the admin plane: dird's `DirAdmin` shape (docs/51 §5.7) -----------------
//
// There is no source crate for these yet (the write PEP is task A3, the
// channel task A8), so these tables mirror the **operation and step names of
// docs/51** instead of a Rust enumeration. They are closed and append-only
// like every table here; none ends in `Unlisted`, because no
// `#[non_exhaustive]` source enumeration is converted into them — a reason
// A3/A8 need that is not listed is appended here first
// (docs/questions/Q-340 item 3).

code_table! {
    /// The admin operation dird decided on: the request kinds of
    /// `dird-admin.sock` that act on the directory or on the pending
    /// key-operation requests (docs/51 §7.3, in its order). `Lookup` is
    /// audited too: "every operation = Action in PDP + audit" (D175, docs/43
    /// §1 as cited in docs/51 §5.7), as every LDAP read is (A-70). `Ping` is
    /// a health check, not an operation; `IssueJoinToken` is deferred with
    /// task A12 (A-78) and is appended when that is built.
    /// `FetchApproved`, `Complete` and `ListPendingDestruction` are
    /// **retired** by A-102 (docs/52 §4.6; docs/questions/Q-460): no
    /// producer sends them any more; their codes keep their meaning and are
    /// never reused.
    /// `ChangePolicy` (appended by task A16): the online `PolicyAdmin` path
    /// of docs/51 §5.10 (R51-21; A-80 on Q-299 option (b)) — a tier-map edit
    /// under mandatory dual control, which dird writes as `policy.next` for
    /// root to activate; its events name each change in the edit's own
    /// spelling (`AdminNameKind::PolicyChange`).
    /// **One dual-control mechanism (task D2-c; docs/questions/Q-882,
    /// A-148):** `Propose`, `Reject`, `Withdraw`, `ListRequests` and
    /// `ShowRequest` are appended — the steps on the pending requests dird
    /// holds for every dual-controlled operation (r5-a MA5); `Approve` keeps
    /// its code and now approves any pending request (`Approve {id,
    /// digest}`); `RequestKeyOperation` is **retired** (a key operation is
    /// proposed with `Propose`): no producer sends it any more, its code
    /// keeps its meaning and is never reused. The operation a pending
    /// request is for is in [`crate::DirAdminEvent::proposed`] (or, for a
    /// key operation, `key_operation`).
    /// `ChangePassword` (appended by task K6): a user's change of its own
    /// password through kpasswd (RFC 3244 §2) — the `DirAdmin` shape with
    /// the requester's own account as `target` and its objectSid as
    /// `requester` (docs/53 §9); dird decides it on `dird-kpasswd.sock`, not
    /// on `dird-admin.sock`.
    /// `PlanOperation` (appended by task MA2; docs/research/
    /// r5-a-admin-model.md §3.3, §11 MA2; docs/questions/Q-874, Q-980): the
    /// requester asks dird for the effect plan of an operation — the same
    /// checks as its execution, committing nothing; the plan's digest is in
    /// [`crate::DirAdminEvent::plan_digest`], the operation planned in
    /// `proposed`. The execution itself (`Commit`) keeps the code of the
    /// operation it executes.
    /// Spec: docs/51 §5.2, §5.7, §5.10, §6, §7.3; docs/questions/Q-340
    /// item 2, Q-592, Q-882, Q-938; docs/53 §4.4, §9 (K6); Q-980.
    pub enum DirAdminOperation {
        CreateUser,
        CreateComputer,
        CreateGroup,
        CreateOu,
        CreateContainer,
        BeginPasswordSet,
        CompletePasswordSet,
        SetEnabled,
        SetAccountExpires,
        AddMember,
        RemoveMember,
        Delete,
        Lookup,
        RequestKeyOperation,
        Approve,
        FetchApproved,
        Complete,
        ListPendingDestruction,
        ChangePolicy,
        Propose,
        Reject,
        Withdraw,
        ListRequests,
        ShowRequest,
        ChangePassword,
        PlanOperation,
    }
}

code_table! {
    /// When dird sent the event: `Decision` — after `decide`, **before**
    /// the commit, and acknowledged by auditd before the commit happens;
    /// `Outcome` — after the commit (or its failure). The wire tag of
    /// [`crate::DirAdminStage`].
    /// Spec: docs/51 §5.7 item 2 ("decide ⇒ a decision event acknowledged
    /// ⇒ commit ⇒ an outcome event"), §7.4 steps 5-6.
    pub enum AdminPhase { Decision, Outcome }
}

code_table! {
    /// What a `Decision` event says: proceed to the commit, refused, or
    /// failed before any decision could be made. The wire tag of
    /// [`crate::DecisionResult`].
    /// Spec: docs/51 §5.7, §7.4 steps 1-5.
    pub enum DecisionResultCode { Proceed, Refused, Failed }
}

code_table! {
    /// What an `Outcome` event says: committed, refused at the commit, or
    /// failed. The wire tag of [`crate::OutcomeResult`].
    /// Spec: docs/51 §5.7, §7.4 steps 5-6.
    pub enum OutcomeResultCode { Committed, Refused, Failed }
}

code_table! {
    /// Why dird refused an admin operation — the check of docs/51 that
    /// stopped it. A class only: no attribute value, no name, no password
    /// (docs/37 §2).
    ///
    /// * `Unauthenticated` — the requester's AP-REQ did not verify (§7.4
    ///   step 1; the reply is the uniform `Denied`, A-26).
    /// * `TicketAge` — the requester's `ticket_age` is over the threshold
    ///   (§5.5, §7.4 step 2).
    /// * `PolicyDenied` — `decide` answered Deny for the requester (§7.4
    ///   step 3); the PDP reason is in [`crate::DirAdminEvent::pdp`].
    /// * `ApprovalRequired` — dual control applies and the approvals do not
    ///   reach the quorum (§5.6).
    /// * `ApproverUnauthenticated` — an approver's AP-REQ did not verify
    ///   (§5.6, §7.4 step 1).
    /// * `ApproverNotDistinct` — an approver is the requester, or two
    ///   approvers are the same principal (§5.6: "another, different").
    /// * `ApproverDenied` — `decide` answered Deny for an approver (§5.6:
    ///   each approval passes the PDP for the same Action and Resource).
    /// * `AccountNameInvalid` — a sAMAccountName rule of §11 (rows 1-3).
    /// * `ValueInvalid` — another value rule of §11 / §5.2 (UAC, groupType,
    ///   accountExpires 0, …).
    /// * `MembershipInvalid` — a membership rule of §11 (groupType rules,
    ///   cycle, member limit, unresolved SID-only member).
    /// * `TargetProtected` — an object the operation must never touch
    ///   (krbtgt, the DC, service objects, the NC root, groups the policy
    ///   names — §5.2 rows 6, 9; §11).
    /// * `NotFound` — the target, parent or member does not exist (§5.2
    ///   row 10).
    /// * `NotVisible` — it exists but is not visible to the requester (the
    ///   reply says "not found", docs/11 §7 as cited in §5.2 row 10; the log
    ///   keeps the difference, as the LDAP events do).
    /// * `Conflict` — a unique value is taken at the commit (docs/46 §8.5,
    ///   as cited in §11); also used by `directory-admin` (task A3) when the
    ///   state the write depends on changed between the decision and the
    ///   commit, or a container to delete still has children — the write
    ///   meets a directory that no longer matches the decision.
    /// * `RidExhausted` — no RID is left in the range (§8.3, fail closed).
    /// * `PendingUnknown` — the pending key-operation request id is unknown
    ///   or expired (§5.6: in dird's memory, with a TTL).
    /// * `PendingLimit` — too many pending requests (§5.6: bounded in
    ///   number).
    /// * `NotApproved` — `FetchApproved` / `Complete` for a request not
    ///   (yet) approved (§6).
    /// * `SelfLockout` — the self-lockout guard: a disable, delete, expiry
    ///   or membership removal that would leave fewer enabled Tier-0
    ///   administrators than the dual-control quorum (Q-295 item 4, owner
    ///   item P-22). Appended by task A3: no earlier code names this check.
    /// * `ObligationRefused` — the PDP **allowed** the requester (the PDP
    ///   reason in [`crate::DirAdminEvent::pdp`] stays `Allowed`), but dird
    ///   could not honour an obligation of that Allow: the `RateLimit`
    ///   obligation's limit for the requester is reached, or a
    ///   `Constrain(MaxPageSize(0))` leaves a `Lookup` no entry to answer
    ///   with (docs/11 §2: "the PEP must honour obligations", §8;
    ///   docs/questions/Q-358 item 7, Q-388 item 2). Appended by task F4
    ///   (A-91): before it, dird recorded this as `PolicyDenied` with an
    ///   `Allowed` PDP reason — a refusal no reader could tell apart from a
    ///   PDP deny without comparing two fields.
    /// * `OperationMismatch` — an `Approve` names an operation other than
    ///   the one the pending key-operation request holds: the operation
    ///   digest of what the approver approves differs from the request's
    ///   (docs/51 §5.6; docs/24 §6 principle "sign the exact operation, not
    ///   a general approve"). Appended by task A10 (docs/questions/Q-421).
    /// * `KeyOperationRefused` — in the `Outcome` event of a `Complete`:
    ///   keyadm reports that keyd answered the approved key operation with
    ///   a refusal (`Denied` / `RateLimited` / `Unavailable` — keyd stores
    ///   nothing then, docs/10 §9). Appended by task A10 (Q-421).
    /// * `ApprovalNotNeeded` — a `Propose` for an operation whose rule needs
    ///   no approver (P-22: e.g. a write that is Tier0 only because it is
    ///   unclassified): it is executed directly, never queued for a human
    ///   (class C47 — fewer approvals, not faster ones; r5-a §8.2 item 1).
    ///   Appended by task D2-c (docs/questions/Q-882, Q-938).
    /// * `RequestStale` — a pending request whose basis changed since it was
    ///   proposed: an object it names (any attribute), the policy version,
    ///   or the requester's or an approver's standing (account unusable,
    ///   name re-bound, ticket revoked, PDP no longer Allow) — at an
    ///   `Approve` or at the execution; the request is dropped (class C43:
    ///   an approval is never applied to a state other than the one it was
    ///   judged on). Appended by task D2-c (Q-882 item 2, Q-938).
    /// * `RequesterLimit` — the requester already holds the most open
    ///   pending requests one requester may hold (interim cap while owner
    ///   item P-78 / Q-878 is open; class C47 — no flooding of the
    ///   approvers). Appended by task D2-c (Q-938, Q-940).
    /// * `PlanRequired` — an operation that requires an effect plan
    ///   (docs/questions/Q-982) arrived without one: it has no wire form
    ///   without one (crate ipc-dird-admin), so this is the PEP's own
    ///   defence in depth. Appended by task MA2 (r5-a §3.3; Q-980).
    /// * `PlanChanged` — the effect plan dird recomputed at the execution,
    ///   at an `Approve` or at a `Propose` differs from the plan the request
    ///   commits to (its digest is inside the operation digest the AP-REQ
    ///   is bound to): the effect closure is no longer the one that was
    ///   approved (class C46) — nothing is written; plan again. Appended by
    ///   task MA2 (Q-874 item 2, Q-980).
    /// * `PlanNotVisible` — an effect of the plan names a principal the
    ///   requester (or the approver) may not see: whoever cannot see the
    ///   results of an operation does not perform or approve it (Q-874
    ///   item 4, Q-983). Appended by task MA2.
    /// * `PlanTooLarge` — the effect closure exceeds the plan's bounds (it
    ///   could not be shown, so it is not performed — fail closed, Q-981).
    ///   Appended by task MA2.
    ///
    /// Spec: docs/51 §5.2, §5.5, §5.6, §6, §7.4, §8.3, §11;
    /// docs/questions/Q-340 item 3; Q-295 item 4 (P-22); docs/11 §2, §8;
    /// docs/questions/Q-388 items 1-2 (A-91), Q-397.
    pub enum AdminRefusal {
        Unauthenticated,
        TicketAge,
        PolicyDenied,
        ApprovalRequired,
        ApproverUnauthenticated,
        ApproverNotDistinct,
        ApproverDenied,
        AccountNameInvalid,
        ValueInvalid,
        MembershipInvalid,
        TargetProtected,
        NotFound,
        NotVisible,
        Conflict,
        RidExhausted,
        PendingUnknown,
        PendingLimit,
        NotApproved,
        SelfLockout,
        ObligationRefused,
        OperationMismatch,
        KeyOperationRefused,
        ApprovalNotNeeded,
        RequestStale,
        RequesterLimit,
        PlanRequired,
        PlanChanged,
        PlanNotVisible,
        PlanTooLarge,
    }
}

code_table! {
    /// Why an admin operation failed — something broke; nothing was
    /// decided against the requester.
    ///
    /// * `KeydUnavailable` — the AP-REQ could not be verified because keyd
    ///   did not answer (§7.4 step 1: "keyd down ⇒ `Unavailable`", A-56).
    /// * `StoreFailure` — a read of the directory during the checks, or the
    ///   `WriteTxn`'s writes / commit, failed (§7.4 step 5). (Failing to
    ///   begin the transaction or take the view at all, before any check,
    ///   is `ViewUnavailable`.)
    /// * `IntegrityFailure` — the store refused a record whose integrity tag
    ///   did not verify (docs/32, as cited in §5.8).
    /// * `InternalFailure` — any other local failure.
    /// * `ViewUnavailable` — dird could not begin the operation's `WriteTxn`
    ///   or take the one view its checks run on (§7.4 steps 2-3 in the
    ///   order A-89 fixed: the transaction first, so the view is its
    ///   starting state — docs/questions/Q-358 item 1): **no check ran and
    ///   nothing was decided**. dird sends it in a `Decision` event (like
    ///   `KeydUnavailable`, the codec does not tie a failure code to a
    ///   phase). Appended by task F4
    ///   (A-91; docs/questions/Q-388 item 1): before it, dird recorded this
    ///   as `StoreFailure`, the code of a read that fails inside the checks.
    /// * `AuditUnacknowledged` — the operation's `Decision` event was
    ///   committed but auditd did not acknowledge it within dird's deadline,
    ///   so dird did **not** perform the operation (the transaction was
    ///   aborted; nothing was written): docs/51 §5.7 item 2 ("decision
    ///   acknowledged ⇒ commit"), A-85. dird sends it in the `Outcome`
    ///   event, with the decision's operation number — the admin plane's
    ///   counterpart of keyd-daemon's `NotPerformed` (A-86). Appended by task
    ///   F4 (A-91; Q-388 item 1): before it, dird recorded this as
    ///   `InternalFailure`.
    /// * `KeyOperationNotPerformed` — in the `Outcome` event of a
    ///   `Complete`: keyadm reports that the approved key operation was not
    ///   performed (never sent to keyd, or refused by keyd's transport
    ///   before keyd ran it — A-88). Appended by task A10
    ///   (docs/questions/Q-421).
    /// * `KeyOperationOutcomeUnknown` — in the `Outcome` event of a
    ///   `Complete`: keyadm sent the approved key operation to keyd and no
    ///   usable answer came back; keyd's own records (intent + outcome)
    ///   say whether it ran (A-88, A-90). Appended by task A10 (Q-421).
    ///
    /// Spec: docs/51 §5.7 item 2, §7.4; A-56; A-85; A-89; docs/questions/
    /// Q-340 item 3, Q-358 item 1, Q-388 item 1 (A-91), Q-397.
    pub enum AdminFailure {
        KeydUnavailable,
        StoreFailure,
        IntegrityFailure,
        InternalFailure,
        ViewUnavailable,
        AuditUnacknowledged,
        KeyOperationNotPerformed,
        KeyOperationOutcomeUnknown,
    }
}

code_table! {
    /// Which name a [`crate::TargetName`] is: the name fields of the
    /// `dird-admin.sock` requests (docs/51 §7.3: `sam`, `upn`, `name`,
    /// `dns_host_name`, `spn`, and `dn` for `Lookup`), by the attribute they
    /// name in docs/51 §11. `PolicyChange` (appended by task A16): one
    /// tier-map change of a `ChangePolicy` request, in the command-line
    /// spelling of `provision policy` (`--add-principal <SID> <TierN>`, …;
    /// crate policy-store module `edit`) — SIDs and DNs only, not secret
    /// (docs/47 §2.3).
    /// Spec: docs/51 §5.2, §5.10, §7.3, §11; docs/questions/Q-340 item 4,
    /// Q-592.
    pub enum AdminNameKind {
        SamAccountName,
        UserPrincipalName,
        Name,
        DnsHostName,
        ServicePrincipalName,
        DistinguishedName,
        PolicyChange,
    }
}

code_table! {
    /// The direction of a `SetEnabled` request: clear or set the D bit of
    /// userAccountControl (docs/51 §5.2 row 6: "only the D bit"). Metadata
    /// of the request, not a secret (docs/37 §2); recorded so the log says
    /// which way an account was switched (decided on Q-340 item 5).
    /// Spec: docs/51 §5.2 row 6, §7.3 (`SetEnabled {target, value}`);
    /// docs/questions/Q-340 item 5.
    pub enum EnableDirection { Enable, Disable }
}

code_table! {
    /// The wire tag of [`crate::AccountExpiresValue`]: `Never` (the request's
    /// "never", which the admin plane writes as `0x7FFFFFFFFFFFFFFF` only —
    /// docs/47 R47-5b) or `At` followed by the FILETIME the request named.
    /// Spec: docs/51 §5.2 row 7 (`SetAccountExpires {target, never |
    /// filetime}`); docs/47 §4.2 ([MS-SAMR] 2.2.6.1 as quoted there);
    /// docs/questions/Q-340 item 5.
    pub enum AccountExpiresCode { Never, At }
}

code_table! {
    /// The groupType of a `CreateGroup` request: the six values phase 1
    /// accepts — exactly one of ACCOUNT / RESOURCE / UNIVERSAL, optionally
    /// with SECURITY_ENABLED — in the order of crates/ad-schema
    /// `flags::group_type::ALLOWED_VALUES` ([MS-ADTS] 2.2.12 as cited there;
    /// docs/46 §8.2, R46-6). A request naming any other value is refused
    /// (`ValueInvalid`) and its event carries no group type.
    /// Spec: docs/51 §5.2 row 3 ("groupType from the 6 values, default
    /// `0x80000002`"); docs/46 §8.2; docs/questions/Q-340 item 5.
    pub enum GroupTypeCode {
        AccountGroup,
        ResourceGroup,
        UniversalGroup,
        SecurityAccountGroup,
        SecurityResourceGroup,
        SecurityUniversalGroup,
    }
}

impl GroupTypeCode {
    /// GROUP_TYPE_ACCOUNT_GROUP. Spec: [MS-ADTS] 2.2.12 via crates/ad-schema
    /// flags.rs and docs/46 §8.2.
    const ACCOUNT: u32 = 0x0000_0002;
    /// GROUP_TYPE_RESOURCE_GROUP. Spec: as above.
    const RESOURCE: u32 = 0x0000_0004;
    /// GROUP_TYPE_UNIVERSAL_GROUP. Spec: as above.
    const UNIVERSAL: u32 = 0x0000_0008;
    /// GROUP_TYPE_SECURITY_ENABLED. Spec: as above.
    const SECURITY_ENABLED: u32 = 0x8000_0000;

    /// The groupType value (as the unsigned 32-bit pattern).
    /// Spec: docs/46 §8.2 ("{2, 4, 8, 0x80000002, 0x80000004,
    /// 0x80000008}").
    #[must_use]
    pub const fn group_type(self) -> u32 {
        match self {
            GroupTypeCode::AccountGroup => Self::ACCOUNT,
            GroupTypeCode::ResourceGroup => Self::RESOURCE,
            GroupTypeCode::UniversalGroup => Self::UNIVERSAL,
            GroupTypeCode::SecurityAccountGroup => Self::SECURITY_ENABLED | Self::ACCOUNT,
            GroupTypeCode::SecurityResourceGroup => Self::SECURITY_ENABLED | Self::RESOURCE,
            GroupTypeCode::SecurityUniversalGroup => Self::SECURITY_ENABLED | Self::UNIVERSAL,
        }
    }

    /// The code of a groupType value, or `None` if it is not one of the six.
    /// Spec: docs/46 §8.2 (R46-6).
    #[must_use]
    pub fn from_group_type(value: u32) -> Option<GroupTypeCode> {
        Self::ALL
            .iter()
            .copied()
            .find(|code| code.group_type() == value)
    }
}

// ---- the admin plane: admind's `Admind` shape (docs/51 §5.7 item 3) ---------

code_table! {
    /// What admind recorded: the wire tag of [`crate::AdmindActivity`].
    /// Spec: docs/51 §5.7 item 3 (refused connection, malformed frame,
    /// `SetPassword` completed / failed), §6 and §7.3 (the keyadm-only
    /// requests admind forwarded only from `keyadm_uid` — `KeyadmForward`,
    /// **retired** by A-102: admind is no longer in keyadm's path, docs/52
    /// §4.6; no producer sends it; its code is never reused). `RateLimited` (a
    /// frame dropped undecoded because its peer uid is over admind's
    /// request rate, docs/50 §3.6; noise) was appended by task F6 (A-94,
    /// docs/questions/Q-406 item 3).
    pub enum AdmindActivityCode {
        ConnectionRefused,
        MalformedFrame,
        SetPassword,
        KeyadmForward,
        RateLimited,
    }
}

code_table! {
    /// Why admind refused an `admin.sock` connection.
    ///
    /// * `PeerUnidentified` — the peer credentials could not be read, so no
    ///   uid is known (docs/50 §3.2: identity only from peer credentials).
    /// * `ConnectionLimit` — over admind's connection quota (docs/50 §3.6:
    ///   a connection quota per caller; docs/51 §7.5).
    ///
    /// Spec: docs/50 §3.2, §3.6; docs/51 §5.1, §5.7 item 3;
    /// docs/questions/Q-340 item 6.
    pub enum ConnectionRefusal { PeerUnidentified, ConnectionLimit }
}

code_table! {
    /// `ipc::Error` (non-exhaustive: `Unlisted` after its variants): which
    /// framing, envelope or field rule an `admin.sock` frame broke. The
    /// class only — never an octet of the frame (docs/50 §8.2; the frame
    /// may hold a password, docs/51 §7.6).
    ///
    /// `ValueRefused` is not an `ipc::Error`: the frame passed every wire
    /// rule and the typed layer refused a value (text that is not UTF-8, a
    /// second spelling of "never", a password that is not UTF-8). Appended
    /// by task F6 **after** `Unlisted`, so every earlier code — `Unlisted`'s
    /// included — keeps its meaning (A-94, docs/questions/Q-406 item 3).
    ///
    /// Spec: crates/ipc error.rs; docs/50 §3.3, §8.2; docs/51 §5.7 item 3;
    /// docs/questions/Q-406 item 3.
    pub enum FrameErrorCode {
        FrameTooShort,
        FrameTooLarge,
        WrongMagic,
        VersionMismatch,
        UnknownKind,
        Truncated,
        TrailingBytes,
        InvalidBoolean,
        InvalidOptionMarker,
        LengthOverBound,
        CountOverBound,
        UnknownCode,
        NestingTooDeep,
        BodyOverBound,
        Unlisted,
        ValueRefused,
    }
}

impl FrameErrorCode {
    /// The code of an `ipc::Error`, by variant name; a variant added to
    /// `ipc::Error` after this table was written is `Unlisted` (the event is
    /// still recorded).
    /// Spec: crates/ipc error.rs; docs/questions/Q-252 item 3 (mirror by
    /// name, `Unlisted` for non-exhaustive sources).
    #[must_use]
    pub fn of(error: ipc::Error) -> FrameErrorCode {
        match error {
            ipc::Error::FrameTooShort => FrameErrorCode::FrameTooShort,
            ipc::Error::FrameTooLarge => FrameErrorCode::FrameTooLarge,
            ipc::Error::WrongMagic => FrameErrorCode::WrongMagic,
            ipc::Error::VersionMismatch => FrameErrorCode::VersionMismatch,
            ipc::Error::UnknownKind => FrameErrorCode::UnknownKind,
            ipc::Error::Truncated => FrameErrorCode::Truncated,
            ipc::Error::TrailingBytes => FrameErrorCode::TrailingBytes,
            ipc::Error::InvalidBoolean => FrameErrorCode::InvalidBoolean,
            ipc::Error::InvalidOptionMarker => FrameErrorCode::InvalidOptionMarker,
            ipc::Error::LengthOverBound => FrameErrorCode::LengthOverBound,
            ipc::Error::CountOverBound => FrameErrorCode::CountOverBound,
            ipc::Error::UnknownCode => FrameErrorCode::UnknownCode,
            ipc::Error::NestingTooDeep => FrameErrorCode::NestingTooDeep,
            ipc::Error::BodyOverBound => FrameErrorCode::BodyOverBound,
            _ => FrameErrorCode::Unlisted,
        }
    }
}

code_table! {
    /// How a `SetPassword` ended: the wire tag of [`crate::PasswordResult`].
    /// Spec: docs/51 §5.7 item 3 ("`SetPassword` completed / failed"),
    /// §7.6.
    pub enum PasswordResultCode { Completed, Failed }
}

code_table! {
    /// Which step of admind's `SetPassword` failed (docs/51 §7.6: admind
    /// calls `BeginPasswordSet`, `set_secret` ×1 / ×2, then
    /// `CompletePasswordSet`): the wire tag of [`crate::PasswordStep`].
    /// `Validation` is admind's own check of the request before dird is
    /// asked (docs/51 R51-5, §11 row "password"; A-79). `SetSecret` is
    /// followed on the wire by the key purpose of that call.
    /// Spec: docs/51 §5.2 row 5, §7.6, §9 ("password set" row), §11.
    pub enum PasswordStepCode { Validation, BeginPasswordSet, SetSecret, CompletePasswordSet }
}

code_table! {
    /// Why a `SetPassword` step failed — a class only, never the password
    /// or anything derived from it (docs/37 §2).
    ///
    /// * `PasswordPolicy` — the password broke a rule admind checks (no
    ///   detail of which, docs/37 §2).
    /// * `Denied`, `RateLimited` — dird's uniform refusal, or keyd's
    ///   `Error::Denied` / `Error::RateLimited` (crates/keyd-types error.rs).
    /// * `Busy`, `Unavailable`, `Malformed`, `VersionMismatch` — the shared
    ///   `ipc::Refused` reply by name, or (`Unavailable`) a transport failure
    ///   or deadline, or (`Malformed`) a reply that did not decode (docs/50
    ///   §3.3, §3.7; A-59, A-63).
    /// * `OutcomeUnknown` — the step's request was handed to dird or keyd
    ///   and no usable answer came back (a transport failure or deadline
    ///   after sending): it may have been carried out — the peer's own
    ///   records say (A-88, A-90: "check before retrying"). Appended by task
    ///   F6 (A-94, docs/questions/Q-406 item 2): before it, admind recorded
    ///   this as `Unavailable`.
    ///
    /// Spec: docs/51 §5.7 item 3, §7.6; crates/keyd-types error.rs; crates/ipc
    /// refused.rs; docs/questions/Q-340 item 7, Q-406 item 2.
    pub enum PasswordFailure {
        PasswordPolicy,
        Denied,
        RateLimited,
        Busy,
        Unavailable,
        Malformed,
        VersionMismatch,
        OutcomeUnknown,
    }
}

code_table! {
    /// The `admin.sock` requests admind forwarded **only** when the peer uid
    /// was `keyadm_uid` (docs/51 §6, §7.3 row "admind forwards only from
    /// `keyadm_uid`"). **Retired** by A-102 (docs/52 §4.6; docs/questions/
    /// Q-460) with the `KeyadmForward` activity: kept so that a log written
    /// before still decodes; never produced, never reused.
    /// Spec: docs/51 §6, §7.3.
    pub enum KeyadmOperation { FetchApproved, Complete, ListPendingDestruction }
}

code_table! {
    /// What admind did with a keyadm-only request: forwarded it to dird, or
    /// refused it because the peer uid is not `keyadm_uid`. **Retired** by
    /// A-102 with `KeyadmForward` (never produced, never reused).
    /// Spec: docs/51 §6 ("admind forwards only if the peer uid =
    /// `keyadm_uid`", peer credentials, docs/50 §3.2).
    pub enum ForwardDecision { Forwarded, PeerNotKeyadm }
}
