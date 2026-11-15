//! The conversion from keyd's audit record (crates/keyd `AuditRecord`) to
//! its wire shape on the audit channel (`ipc_audit::KeydRecord`).
//!
//! # Why here (task IB1)
//!
//! Until task IB1 this was `From<&keyd::AuditRecord> for KeydRecord` in
//! crate ipc-audit, behind its feature `keyd`, which made keyd an optional
//! dependency of ipc-audit. Cargo unifies features within one build, so in
//! a shared build every daemon that linked ipc-audit linked keyd and
//! krb-crypto (class C40; docs/questions/Q-851, decision A-144). Now no
//! manifest declares an `optional` dependency and the conversion lives on
//! the side that already links keyd: this crate (linked only by
//! keyd-daemon, D182 / A-63). Both types are foreign here, so the Rust
//! orphan rule allows no `From` impl: it is the plain function
//! [`keyd_record`].
//!
//! Every field of the source type is carried; none of them is secret (keyd's
//! record was built without any field that could hold one — crates/keyd
//! audit.rs; docs/10 I8). Enumerations map variant to same-named table
//! entry (`Source::X => Table::X`), so a misspelled or renamed variant fails
//! to compile; a variant added to a `#[non_exhaustive]` source enumeration
//! later maps to `Unlisted` until its table entry is added (crates/ipc-audit
//! codes.rs).
//!
//! Moved unchanged from crates/ipc-audit `convert.rs` (this project's own
//! code, task P6), written there only from docs/50 §8.1, §8.2, docs/37 §2,
//! docs/questions/Q-252 items 3, 4 and the public API of crates/keyd (audit,
//! authz, model) and crates/krb-proto (basic). No other implementation was
//! consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/50 §8.1, §8.2; docs/37 §2; docs/10 §10; docs/questions/Q-252
//! items 3, 4. Decision: A-144; Q-851.

use ipc_audit::{
    CalendarTime, KeyPurposeCode, KeyRef, KeydOperation, KeydOutcome, KeydReason, KeydRecord,
    KeydRole,
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
        DecisionRevoked, DecisionExecuted,
    }
        _ => KeydReason::Unlisted,
    )
}

/// keyd's audit record → [`KeydRecord`]: every field of keyd's record (I8:
/// none is secret). The former `KeydRecord::from(&record)` of crate
/// ipc-audit (feature `keyd`), unchanged.
///
/// Spec: crates/keyd audit.rs; docs/10 §10; docs/50 §8.1. Decision: A-144;
/// Q-851.
#[must_use]
pub fn keyd_record(record: &keyd::AuditRecord) -> KeydRecord {
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
            CompleteChangePassword, SealChangePasswordError, RevokeDecision,
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
