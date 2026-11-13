//! Audit records: every operation emits exactly one record, success or
//! failure, and no record ever carries a secret (invariant I8).
//!
//! A record holds only fixed-shape, non-secret data: the caller's timestamp,
//! role and uid, the operation, principal ids, purposes, key version numbers,
//! approver ids, the outcome and an internal reason code. There is no field
//! that could hold key octets, plaintext, ciphertext, names or any
//! caller-supplied byte string. The detailed reason goes only here — the
//! caller sees the uniform error of docs/10 §9, or, for a refusal decided
//! after an authentication step's cryptographic chain completed, one of the
//! four non-secret `AuthnError` classes (A-26).
//!
//! `duration_ns` from docs/10 §10 is not recorded: keyd reads no clock (time
//! is passed in by the caller), so the IPC layer that owns the clock adds it.
//!
//! Spec: docs/10 §9, §10, §12 I8; docs/07 §7-8 (reason only to internal
//! audit; SIEM forwarding is the sink's job).

use crate::authz::{Operation, Role};
use crate::model::{KeyPurpose, Kvno, PrincipalId};
use krb_proto::KerberosTime;

/// Outcome of an operation as recorded in audit.
///
/// Spec: docs/10 §9 (error model), §10 (`result`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditOutcome {
    /// The operation completed.
    Success,
    /// Refused (any authorization, binding, crypto or policy failure).
    Denied,
    /// Refused because the ticket template was structurally unacceptable.
    BadTemplate,
    /// keyd could not perform the operation (entropy or capacity failure).
    Unavailable,
    /// Refused by the throttling hook.
    RateLimited,
}

/// The internal reason behind an outcome. Never returned to the caller.
///
/// Every variant is a unit value: a reason cannot carry data, so it cannot
/// carry a secret.
///
/// Spec: docs/10 §9 ("the full reason only to the internal audit").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuditReason {
    /// No reason (success).
    None,
    /// The caller's role does not permit the operation (I2). Spec: docs/10 §2.
    RoleNotPermitted,
    /// A handle's purpose does not match the operation (I3). Spec: docs/10 §2.
    PurposeMismatch,
    /// No key set is stored for the handle (or no key of the needed enctype).
    KeyNotFound,
    /// `create_key` on a handle that already has a key set.
    KeyExists,
    /// The key store refused to hold a critical key (krbtgt) because it is
    /// not an HSM-backed / explicitly-development store. Spec: docs/33 §6.1
    /// (D178); docs/10 D35.
    StoreRefusedCritical,
    /// The key store has no room for another key set.
    StoreFull,
    /// A name in the request (template cname / sname, or the TGS name) is
    /// not the name the key set is bound to. Spec: docs/questions/Q-040
    /// (A-19); RFC 4120 6.2 (equivalence ignores name-type only).
    NameBindingMismatch,
    /// The binding supplied when creating a key set is not acceptable: not
    /// this realm, no name components, or a krbtgt name for a non-krbtgt key
    /// (or the reverse). Spec: RFC 4120 6.2 ("Names of any type with an
    /// initial component of 'krbtgt' are reserved for the Kerberos
    /// ticket-granting service"), 7.3 (two-part TGS name).
    InvalidNameBinding,
    /// The requested new kvno is not greater than the current one.
    KvnoNotIncreasing,
    /// The kvno range is exhausted.
    KvnoExhausted,
    /// `retire_kvno` named a kvno that is not the retained previous kvno.
    KvnoNotRetirable,
    /// The kvno in an EncryptedData does not match a usable key version.
    /// Spec: RFC 4120 3.2.3 (KRB_AP_ERR_BADKEYVER).
    KvnoMismatch,
    /// The dual-control token does not name two distinct approvers.
    DualControlRejected,
    /// The entropy source failed (fail closed; AGENTS.md §6).
    EntropyFailure,
    /// An encryption type outside the configured set (I5).
    UnsupportedEncType,
    /// A pre-authentication type other than PA-ENC-TIMESTAMP.
    /// Spec: RFC 4120 5.2.7.
    UnsupportedPadataType,
    /// Input did not decode as the expected RFC 4120 structure.
    MalformedInput,
    /// Decryption failed its integrity check. Spec: RFC 4120 3.2.3
    /// (KRB_AP_ERR_BAD_INTEGRITY); RFC 3961 §3.
    IntegrityFailure,
    /// A timestamp is outside the acceptable clock skew. Spec: RFC 4120
    /// 3.2.3 (KRB_AP_ERR_SKEW), 5.2.7.2.
    ClockSkew,
    /// The ticket's starttime is in the future. Spec: RFC 4120 3.2.3
    /// (KRB_AP_ERR_TKT_NYV).
    TicketNotYetValid,
    /// The ticket has expired. Spec: RFC 4120 3.2.3 (KRB_AP_ERR_TKT_EXPIRED).
    TicketExpired,
    /// The ticket carries the INVALID flag. Spec: RFC 4120 2.2, 3.2.3.
    TicketInvalidFlag,
    /// The ticket is not a TGT of this realm. Spec: RFC 4120 3.3.2, 7.3.
    NotLocalTgt,
    /// A realm is not the configured realm (no cross-realm in phase 1).
    WrongRealm,
    /// The AP-REQ asks for an option keyd does not implement
    /// (USE-SESSION-KEY). Spec: RFC 4120 5.5.1, 3.7.
    UnsupportedApOption,
    /// Authorization data or addresses keyd would have to carry or enforce
    /// but does not implement in phase 1 (refused rather than dropped:
    /// dropping a restriction widens the ticket). Spec: RFC 4120 3.3.3,
    /// 5.3 (authorization-data are "restrictions"), 5.4.1.
    UnsupportedContent,
    /// Authenticator crealm/cname do not match the ticket. Spec: RFC 4120
    /// 3.2.3 (KRB_AP_ERR_BADMATCH).
    NameMismatch,
    /// The authenticator carries no checksum. Spec: RFC 4120 3.3.2.
    ChecksumMissing,
    /// The checksum type is not supported for the session key.
    /// Spec: RFC 4120 3.3.2 (KDC_ERR_SUMTYPE_NOSUPP, KRB_AP_ERR_INAPP_CKSUM).
    ChecksumUnsupported,
    /// The checksum does not match the request body. Spec: RFC 4120 3.3.2
    /// (KRB_AP_ERR_MODIFIED).
    ChecksumMismatch,
    /// The authenticator was already seen. Spec: RFC 4120 3.2.3
    /// (KRB_AP_ERR_REPEAT).
    Replay,
    /// The replay cache is full of unexpired entries; the request is refused
    /// rather than evicting a live entry. Spec: RFC 4120 3.2.3; docs/10 D33.
    ReplayCacheFull,
    /// The one-time token (AuthnProof / ctx id) is unknown or already used.
    /// Spec: docs/10 §8, D36.
    TokenUnknown,
    /// The one-time token has expired. Spec: docs/10 D36.
    TokenExpired,
    /// The one-time token was issued to another caller. Spec: docs/10 §8.
    TokenCallerMismatch,
    /// The one-time token is bound to another principal. Spec: docs/10 §4.
    TokenPrincipalMismatch,
    /// The one-time token table is full of live entries. Spec: docs/10 D36.
    TokenTableFull,
    /// Template flags outside the allowed mask or the RFC 4120 rules.
    TemplateFlags,
    /// Template times outside policy. Spec: RFC 4120 3.1.3, 3.3.3.
    TemplateTimes,
    /// Template names/realms not acceptable for the key used.
    TemplateNames,
    /// Template session-key enctype not in the configured set (I5).
    TemplateEncType,
    /// Template nonce does not match the authenticated request.
    TemplateNonce,
    /// The candidate secret does not match. Spec: docs/10 §6.
    SecretMismatch,
    /// The stored key set was not derived from a password (no salt).
    NoPasswordKey,
    /// The throttling hook refused the attempt — `verify_secret` (reported
    /// as `Error::RateLimited`), or `verify_preauth` (reported as the uniform
    /// `AuthnError::Denied`: decided before any secret work, A-26). Spec:
    /// docs/10 §6; decision A-34.
    Throttled,
    /// string-to-key refused the parameters (e.g. iteration cap).
    /// Spec: RFC 3962 §4.
    S2kRefused,
    /// Encoding a structure or a crypto operation failed unexpectedly.
    InternalFailure,
    /// The KrbFastArmoredReq carries no armor (it "MUST be present in
    /// AS-REQ"). Spec: RFC 6113 5.4.2.
    ArmorMissing,
    /// The armor type is not FX_FAST_ARMOR_AP_REQUEST. Spec: RFC 6113 5.4.1.
    ArmorTypeUnsupported,
    /// The armor AP-REQ authenticator carries no subkey ("The subkey field
    /// in the AP-REQ MUST be present"). Spec: RFC 6113 5.4.1.1.
    ArmorSubkeyMissing,
    /// The armor AP-REQ authenticator carries a checksum; the armor has no
    /// application data to checksum, so phase 1 refuses one.
    /// Spec: RFC 4120 5.5.1 (cksum); docs/questions/Q-120 item 3 (A-32).
    ArmorChecksumPresent,
    /// The KrbFastArmoredReq req-checksum does not verify over the outer
    /// request body under the armor key. Spec: RFC 6113 5.4.2.
    FastChecksumMismatch,
    /// `seal_fast_error`: the KRB-ERROR is not one keyd may seal — e-data or
    /// e-text present, KDC_ERR_NONE, stime other than now, or names other
    /// than those of the stored inner request. Spec: RFC 6113 5.4.4;
    /// docs/48 §6.1.
    FastErrorContentRefused,
    /// `seal_fast_error`: a padata entry outside the allowlist, repeated, or
    /// with an unacceptable value. Spec: docs/48 §2.3, §6.1.
    FastErrorPadataRefused,
}

/// A key referenced by an operation, for audit (no key material).
///
/// Spec: docs/10 §10 (principal, purpose, kvno).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditKeyRef {
    /// The principal id of the key set.
    pub principal: PrincipalId,
    /// The key set's purpose.
    pub purpose: KeyPurpose,
    /// The key version used, when one was resolved.
    pub kvno: Option<Kvno>,
}

/// One audit record.
///
/// Fields follow docs/10 §10: `{ ts, caller_role, caller_uid, op, principal,
/// purpose, kvno, result }`, plus the internal `reason`, the `secondary` key
/// of two-key operations (the krbtgt key of `issue_as_rep`), and the
/// dual-control `approvers` of `rotate_krbtgt`. None of them is secret.
///
/// Spec: docs/10 §10, §12 I8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// The caller-supplied time of the operation (keyd reads no clock).
    pub ts: KerberosTime,
    /// The caller's role.
    pub caller_role: Role,
    /// The caller's uid.
    pub caller_uid: u32,
    /// The operation.
    pub op: Operation,
    /// The primary handle's principal, when the operation has one.
    pub principal: Option<PrincipalId>,
    /// The primary handle's purpose.
    pub purpose: Option<KeyPurpose>,
    /// The key version used or produced, when resolved.
    pub kvno: Option<Kvno>,
    /// A second key used by the operation (krbtgt in `issue_as_rep`).
    pub secondary: Option<AuditKeyRef>,
    /// Dual-control approvers (`rotate_krbtgt`).
    pub approvers: Option<[PrincipalId; 2]>,
    /// The outcome.
    pub result: AuditOutcome,
    /// The internal reason (never shown to the caller).
    pub reason: AuditReason,
}

/// Where audit records go. The production sink (append-only, signed,
/// forwarded to the SIEM — docs/10 §10) belongs to the daemon crate.
///
/// Residual: `record` is infallible here; a durable sink must itself fail
/// closed (e.g. stop the process) if it cannot persist a record.
///
/// Spec: docs/10 §10.
pub trait AuditSink {
    /// Accept one record.
    fn record(&mut self, record: &AuditRecord);
}
