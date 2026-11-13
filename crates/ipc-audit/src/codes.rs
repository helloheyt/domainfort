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
    /// `keyd::AuditOutcome` (codes 1-5, by name), then two **phase** codes
    /// appended for decision A-86 (codes 6-7), which no `keyd::AuditOutcome`
    /// maps to: keyd-daemon writes them itself around an operation that
    /// changes keyd's key state (`keyd::changes_key_state`: `SetSecret`,
    /// `CreateKey`, `RotateKey`, `RotateKrbtgt`, `RetireKvno`,
    /// `DestroyKeySet`):
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
    /// The event shapes (the wire tag of [`crate::EventBody`]). `DirAdmin`
    /// and `Admind` were appended for the admin plane (docs/51 §5.7, R51-12,
    /// task A7); the codes of the first four are unchanged.
    /// Spec: docs/50 §8.1; docs/questions/Q-252 item 3; docs/51 §5.7, §12
    /// (A7); docs/questions/Q-340.
    pub enum EventShape { Kdc, Keyd, Ldap, WindowSummary, DirAdmin, Admind }
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
    /// Spec: docs/51 §5.2, §5.7, §6, §7.3; docs/questions/Q-340 item 2.
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
    ///
    /// Spec: docs/51 §5.2, §5.5, §5.6, §6, §7.4, §8.3, §11;
    /// docs/questions/Q-340 item 3; Q-295 item 4 (P-22).
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
    }
}

code_table! {
    /// Why an admin operation failed — something broke; nothing was
    /// decided against the requester.
    ///
    /// * `KeydUnavailable` — the AP-REQ could not be verified because keyd
    ///   did not answer (§7.4 step 1: "keyd down ⇒ `Unavailable`", A-56).
    /// * `StoreFailure` — reading the directory view or the `WriteTxn` /
    ///   commit failed (§7.4 step 5).
    /// * `IntegrityFailure` — the store refused a record whose integrity tag
    ///   did not verify (docs/32, as cited in §5.8).
    /// * `InternalFailure` — any other local failure.
    ///
    /// Spec: docs/51 §7.4; A-56; docs/questions/Q-340 item 3.
    pub enum AdminFailure { KeydUnavailable, StoreFailure, IntegrityFailure, InternalFailure }
}

code_table! {
    /// Which name a [`crate::TargetName`] is: the name fields of the
    /// `dird-admin.sock` requests (docs/51 §7.3: `sam`, `upn`, `name`,
    /// `dns_host_name`, `spn`, and `dn` for `Lookup`), by the attribute they
    /// name in docs/51 §11.
    /// Spec: docs/51 §5.2, §7.3, §11; docs/questions/Q-340 item 4.
    pub enum AdminNameKind {
        SamAccountName,
        UserPrincipalName,
        Name,
        DnsHostName,
        ServicePrincipalName,
        DistinguishedName,
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
    /// requests admind forwards only from `keyadm_uid`).
    pub enum AdmindActivityCode {
        ConnectionRefused,
        MalformedFrame,
        SetPassword,
        KeyadmForward,
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
    /// `ipc::Error` (non-exhaustive: ends in `Unlisted`): which framing,
    /// envelope or field rule an `admin.sock` frame broke. The class only —
    /// never an octet of the frame (docs/50 §8.2; the frame may hold a
    /// password, docs/51 §7.6).
    /// Spec: crates/ipc error.rs; docs/50 §3.3, §8.2; docs/51 §5.7 item 3.
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
    ///
    /// Spec: docs/51 §5.7 item 3, §7.6; crates/keyd-types error.rs; crates/ipc
    /// refused.rs; docs/questions/Q-340 item 7.
    pub enum PasswordFailure {
        PasswordPolicy,
        Denied,
        RateLimited,
        Busy,
        Unavailable,
        Malformed,
        VersionMismatch,
    }
}

code_table! {
    /// The `admin.sock` requests admind forwards **only** when the peer uid
    /// is `keyadm_uid` (docs/51 §6, §7.3 row "admind forwards only from
    /// `keyadm_uid`").
    /// Spec: docs/51 §6, §7.3.
    pub enum KeyadmOperation { FetchApproved, Complete, ListPendingDestruction }
}

code_table! {
    /// What admind did with a keyadm-only request: forwarded it to dird, or
    /// refused it because the peer uid is not `keyadm_uid`.
    /// Spec: docs/51 §6 ("admind forwards only if the peer uid =
    /// `keyadm_uid`", peer credentials, docs/50 §3.2).
    pub enum ForwardDecision { Forwarded, PeerNotKeyadm }
}
