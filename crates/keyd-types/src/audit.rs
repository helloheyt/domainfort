//! Audit records: every operation emits exactly one record, success or
//! failure, and no record ever carries a secret (invariant I8). The one
//! exception adds records, never removes one: a `DestroyKeySet` registration
//! also emits one record per set-secret entry it discarded
//! ([`AuditReason::SecretDecisionDiscarded`], R6b — docs/questions/Q-520).
//!
//! A record holds only fixed-shape, non-secret data: the caller's timestamp,
//! role and uid, the operation, principal ids, purposes, key version numbers,
//! approver ids, the outcome and an internal reason code. There is no field
//! that could hold key octets, plaintext, ciphertext, names or any
//! caller-supplied byte string. The detailed reason goes only here — the
//! caller sees the uniform error of docs/10 §9, or, for a refusal decided
//! after an authentication step's cryptographic chain completed, one of the
//! four non-secret `AuthnError` classes (A-26), or `Unavailable` for the
//! startup hold-down (A-56).
//!
//! `duration_ns` from docs/10 §10 is not recorded: keyd reads no clock (time
//! is passed in by the caller), so the IPC layer that owns the clock adds it.
//!
//! Spec: docs/10 §9, §10, §12 I8; docs/07 §7-8 (reason only to internal
//! audit; SIEM forwarding is the sink's job).

use crate::authz::{Operation, Role};
use crate::decision::DecisionId;
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
    /// keyd could not perform the operation (entropy or capacity failure), or
    /// did not serve it (the startup hold-down — reason
    /// [`AuditReason::StartupHoldDown`]).
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
    /// The kvno range is exhausted: the next kvno (`rotate_key`,
    /// `rotate_krbtgt`, `set_secret`) would wrap. Spec: RFC 4120 5.2.9
    /// (UInt32); docs/questions/Q-115 (A-35: keyd chooses the kvno).
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
    /// A pre-authentication type keyd does not accept here: anything but
    /// PA-ENC-TIMESTAMP without armor, anything but PA-ENCRYPTED-CHALLENGE
    /// with armor (a FAST factor is not used outside FAST; PA-ENC-TIMESTAMP
    /// is not a factor inside FAST in phase 1). Spec: RFC 4120 5.2.7; RFC
    /// 6113 5.4, 5.4.6; docs/48 §4.5.
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
    /// in the AP-REQ MUST be present") — or, in an armored TGS request, the
    /// PA-TGS-REQ authenticator carries none ("a subkey MUST be included in
    /// the PA-TGS-REQ authenticator"). Spec: RFC 6113 5.4.1.1, 5.4.2.
    ArmorSubkeyMissing,
    /// The armor AP-REQ authenticator carries a checksum; the armor has no
    /// application data to checksum, so phase 1 refuses one.
    /// Spec: RFC 4120 5.5.1 (cksum); docs/questions/Q-120 item 3 (A-32).
    ArmorChecksumPresent,
    /// The KrbFastArmoredReq req-checksum does not verify under the armor
    /// key over the outer request body (AS) or the PA-TGS-REQ AP-REQ (TGS).
    /// Spec: RFC 6113 5.4.2.
    FastChecksumMismatch,
    /// `seal_fast_error`: the KRB-ERROR is not one keyd may seal — e-data or
    /// e-text present, KDC_ERR_NONE, stime other than now, or names other
    /// than those of the stored inner request. Spec: RFC 6113 5.4.4;
    /// docs/48 §6.1.
    FastErrorContentRefused,
    /// `seal_fast_error`: a padata entry outside the allowlist, repeated, or
    /// with an unacceptable value. Spec: docs/48 §2.3, §6.1.
    FastErrorPadataRefused,
    /// `verify_preauth`: the armor already had its one pre-authentication
    /// attempt (success or failure). Spec: docs/48 §2.3 ("one attempt per
    /// armor"), §9.1 I4.
    ArmorAlreadyAttempted,
    /// `verify_preauth`: the EncryptedChallenge is not of the armor key's
    /// enctype, which is the challenge key's (KRB-FX-CF2 yields the enctype
    /// of k1). Spec: RFC 6113 5.1, 5.4.6; docs/questions/Q-123 (A-32).
    ChallengeEncTypeMismatch,
    /// `issue_as_rep`: the proof and the armor are not one conversation — an
    /// armored proof without its armor, an unarmored proof with an armor, or
    /// a proof bound to another armor. Spec: docs/48 §2.3 ("None↔None,
    /// Some(a)↔Some(a)"), §9.2 item 8.
    ArmorProofMismatch,
    /// `issue_as_rep`: the template's crealm, cname or nonce is not that of
    /// the inner request keyd stored when it opened the armor;
    /// `issue_tgs_rep` on an armored context: the template's sname or nonce
    /// is not that of the stored inner request. Spec: RFC 6113 5.4.2 (inner
    /// req-body preferred), 5.4.3 (nonce); docs/48 §3.4, §9.2 items 7, 8.
    FastBindingMismatch,
    /// `open_and_verify_tgt`: the KrbFastArmoredReq of a TGS request carries
    /// an explicit armor field; implicit armor is the only TGS armor. Spec:
    /// RFC 6113 5.4.1.1 ("This armor type is only valid for AS requests"),
    /// 5.4.2; docs/questions/Q-124 item 2 (A-32).
    TgsExplicitArmor,
    /// `open_and_verify_tgt`: the AP-REQ octets given for the req-checksum
    /// do not decode to the AP-REQ being opened. Spec: RFC 6113 5.4.2 (the
    /// checksum is "performed over the type AP-REQ in the PA-TGS-REQ
    /// padata"); docs/48 §5.2 step 4.
    FastApReqMismatch,
    /// `seal_fast_error(Tgs)`: the context names no armored conversation —
    /// it was opened without FAST, so there is no armor key to seal under.
    /// Spec: docs/48 §2.4 (`ArmorConversationMismatch`), §9.1 I4.
    ArmorConversationMismatch,
    /// `open_and_verify_service_ticket`: the service key set holds no key
    /// version that keyd drew itself (`create_key` / `rotate_key`) — only
    /// password-derived ones (`set_secret`), whose key may be known outside
    /// keyd. A-46: the LDAP service key "is created in `create_key` and
    /// never leaves keyd". Spec: docs/questions/Q-165 item 4 (A-46);
    /// docs/questions/Q-180 item 4.
    ServiceKeyNotRandom,
    /// `open_and_verify_service_ticket`: the service ticket's transited
    /// field is not the empty encoding of local authentication, and keyd
    /// cannot check a transited path itself (no cross-realm in phase 1).
    /// Spec: RFC 4120 3.3.3.2 ("both local and single-hop inter-realm
    /// authentication result in a transited field that is empty"), 5.3
    /// (transited-policy-checked: "if unable to do so, it must reject the
    /// authentication").
    TransitedNotLocal,
    /// `open_and_verify_service_ticket`: the AP-REQ authenticator carries a
    /// checksum of application data. Task L6a has no application data to
    /// verify it over (the GSS checksum, RFC 4121, is task L6b), so it is
    /// refused rather than ignored. Spec: RFC 4120 5.5.1 (cksum, key usage
    /// 10); docs/49 §3.3, §12; docs/questions/Q-180 item 3.
    ApChecksumUnsupported,
    /// The operation depends on the replay cache or the one-time token
    /// tables, which keyd holds in memory and lost when it started; it is
    /// refused until two clock-skew intervals after the start time have
    /// passed ("If a server loses track of authenticators presented within
    /// the allowable clock skew, it MUST reject all requests until the clock
    /// skew interval has passed"; two intervals because a client clock may
    /// be up to one skew ahead, A-62). Decided after the role / purpose checks
    /// and before anything else (A-56).
    /// Spec: RFC 4120 3.2.3; docs/50 R50-6, §3.5; docs/questions/Q-222
    /// (A-56), Q-240 item 3 (A-62).
    StartupHoldDown,
    /// `set_secret`: no live grant names the handle — none was registered
    /// (dird's PDP never allowed this password set), it expired, or it was
    /// already consumed. Reported as the uniform `Denied` (A-26: decided
    /// before any secret work). Decided at the operation's authorization
    /// step, so it changes nothing and has no intent record (A-88).
    /// Spec: docs/51 §5.8 option (b); docs/questions/Q-291 (A-74), Q-450
    /// items 1, 7.
    NoGrant,
    /// `set_secret`: the live grant of the handle names another binding, or
    /// it is an initial-secret grant (Role::Admin) and the key set exists by
    /// now. The grant is consumed (treated as misused). Reported as the
    /// uniform `Denied`.
    /// Spec: docs/51 §5.8 option (b); docs/questions/Q-450 item 7, Q-451
    /// item 2.
    GrantMismatch,
    /// `grant_set_secret` refused its arguments: no key target, too many,
    /// targets that do not fit the account kind (one for a user; one or two
    /// of the same principal for a computer), a lifetime of zero or above
    /// the caller's ceiling, or — for Role::Admin — an account that is not a
    /// user. Spec: docs/questions/Q-450 items 2, 3, Q-451 items 2, 3.
    GrantInvalid,
    /// `grant_set_secret`: the grant table is full of live grants; the grant
    /// is refused (fail closed) rather than evicting a live one.
    /// Spec: docs/questions/Q-450 item 4; AGENTS.md §6 (bounded).
    GrantTableFull,
    /// A Role::Admin key operation (`rotate_key`, `rotate_krbtgt`,
    /// `retire_kvno`, `destroy_key_set`) named no live decision of its
    /// family: none registered (dird never decided it), expired, or the id
    /// is unknown. Decided at the authorization step — nothing changed, no
    /// intent (A-88). Reported as the uniform `Denied`.
    /// Spec: docs/52 §4.2, §7 R1; docs/questions/Q-460 (A-102).
    NoDecision,
    /// The decision the id names is of another kind than the operation that
    /// presented it (e.g. `rotate_key` naming a `RetireKvno` decision). Not
    /// executed and not consumed. Reported as the uniform `Denied`.
    /// Spec: docs/52 §4.2 ("keyd … requires that the call's kind match").
    DecisionMismatch,
    /// `register_decision` refused its arguments: a malformed decided
    /// operation (shape, kvno 0), a purpose the executing operation does not
    /// accept, approvers out of range or not distinct, or a lifetime of zero
    /// or above the family's ceiling.
    /// Spec: docs/52 §4.2; crate decision `DecidedOperation`.
    DecisionInvalid,
    /// `register_decision`: the decision's family is full of live
    /// decisions; refused (fail closed), never evicting one. Reported as
    /// `Unavailable`.
    /// Spec: docs/52 §4.2 ("bounded"); AGENTS.md §6.
    DecisionTableFull,
    /// `register_decision`: the id already names a different live decision
    /// of the family (an identical one is accepted without change).
    /// Spec: docs/52 §4.3 (re-registration is harmless only when it is the
    /// same decision).
    DecisionConflict,
    /// A key operation presented the id of a decision keyd already executed:
    /// the recorded result is returned again and nothing is run (exactly
    /// once, docs/52 §3.10 (a)). The record's outcome is the recorded one.
    /// Spec: docs/52 §3.10, §4.2.
    DecisionReplayed,
    /// `create_key`, Role::Admin's `grant_set_secret` or
    /// `install_attestation_key` (task PN8) after `seal_ceremony` — or on a
    /// keyd that started operational: those operations exist only in the
    /// provisioning ceremony. Reported as the uniform `Denied`.
    /// Spec: docs/52 §4.4, §7 R3; docs/questions/Q-462 item 1 (A-102);
    /// docs/questions/Q-1011 item 2 (A-173).
    CeremonySealed,
    /// `verify_operation_ticket` (the operation-digest binding, the admin
    /// service key; Q-523): the Authenticator carries no `cksum`, so
    /// the AP-REQ is bound to no operation. Part of the cryptographic chain
    /// — the uniform `Denied` (A-26), before the replay cache.
    /// Spec: RFC 4120 5.5.1 (cksum), 7.5.1 item 10; docs/52 §5 item 3 (R2);
    /// docs/questions/Q-463 (A-102).
    OperationDigestMissing,
    /// `verify_operation_ticket` (the operation-digest binding; Q-523):
    /// the Authenticator's `cksum` is not the session key's MIC over the
    /// operation digest dird computed — another checksum type than the
    /// session key's required one, another length, or a MIC that does not
    /// verify (an AP-REQ made for another operation: the confused-deputy
    /// attempt of docs/52 §3.2, Q-292). The uniform `Denied` (A-26), before
    /// the replay cache.
    /// Spec: RFC 4120 3.3.3 (the KDC's rule for its own checksum: "rejected
    /// if the checksums do not match"), 5.5.1, 7.5.1 item 10; RFC 3961 §3
    /// ("required checksum mechanism"), §4 (verify_mic); docs/52 §5 item 3.
    OperationDigestMismatch,
    /// `register_decision` of a `DestroyKeySet`: a live set-secret entry
    /// (a dird decision, or the ceremony's grant) for one of the deleted
    /// principal's two handles was discarded — the registration is dird's
    /// statement that the principal is deleted, so no key set may come to
    /// exist for it afterwards. One extra record per discarded entry, after
    /// the registration's own record: the handle, and the discarded entry's
    /// decision id (none for the ceremony's grant). Outcome `Success`.
    /// Spec: docs/questions/Q-501 (R6b), Q-520; docs/10 §6א, §7.
    SecretDecisionDiscarded,
    // ---- task K3: the change-password operations (docs/53 §5, §9) --------
    /// `open_change_password_request`: the Authenticator carries no subkey —
    /// RFC 3244 §2: "The authenticator in the AP-REQ must include a
    /// subsession key". Uniform `Denied`, before the replay cache.
    /// Spec: RFC 3244 §2; docs/53 §5.3 (step 10); RFC 4120 5.5.1.
    SubkeyMissing,
    /// `open_change_password_request`: the Authenticator carries no
    /// sequence number — RFC 3244 §2: "the seq-number in the authenticator
    /// will be present" (the RFC 4120 5.5.1 leniency for an omitted zero is
    /// not taken, Q-603 item 3). Uniform `Denied`, before the replay cache.
    /// Spec: RFC 3244 §2; RFC 4120 5.5.1; docs/53 §5.3.
    SequenceNumberMissing,
    /// `open_change_password_request`: the KRB-PRIV's `seq-number` is absent
    /// or differs from the Authenticator's (RFC 4120 3.5.2: "If an incorrect
    /// sequence number is included, or if a sequence number is expected but
    /// not present, the KRB_AP_ERR_BADORDER error is generated"; RFC 3244
    /// §2: present and equal). Uniform `Denied`.
    /// Spec: RFC 4120 3.5.2; RFC 3244 §2; docs/53 §5.4 item 2; Q-603 item 2.
    KrbPrivSequenceMismatch,
    /// `open_change_password_request`: the KRB-PRIV's `timestamp` is present
    /// but not within the clock skew of keyd's clock (RFC 4120 3.5.2:
    /// "present but not current"). Uniform `Denied`.
    /// Spec: RFC 4120 3.5.2; docs/53 §5.4 item 2.
    KrbPrivTimestampSkew,
    /// `open_change_password_request`: the KRB-PRIV's `s-address` is neither
    /// the directional address 0 nor the peer address the front's kernel
    /// reported (an IPv4-mapped address as type 2 only) — RFC 4120 3.5.2
    /// KRB_AP_ERR_BADADDR. Uniform `Denied`.
    /// Spec: RFC 4120 3.5.2, 7.1; docs/53 §5.4 item 3; Q-603 item 8.
    KrbPrivAddressMismatch,
    /// A password broke the password policy at keyd's install path — the
    /// one place every password, on every path, is cleartext (the length
    /// in code points / UTF-16 units, or the account name as a substring).
    /// Which rule is never recorded. Uniform `Denied`.
    /// Spec: [MS-SAMR] 3.1.1.7.2 items 2, 3.2.1, 3.2.2; docs/53 §6; Q-605
    /// item 1 (A-117).
    PasswordPolicyRefused,
    /// `complete_change_password` on a context whose verdict is not
    /// `Acceptable`: only an error reply may be sealed for it. Uniform
    /// `Denied`; the context stays for that error reply.
    /// Spec: docs/53 §5.5 ("verdict ≠ Acceptable ⇒ Denied").
    ChangePasswordNotAcceptable,
    /// `seal_change_password_error` with a result code the context's verdict
    /// does not permit (`ChangePasswordVerdict::permits_error`): a reply
    /// would state an outcome keyd did not establish. Uniform `Denied`; the
    /// context stays.
    /// Spec: docs/53 §5.5, §5.7; RFC 3244 §2.
    ResultCodeNotPermitted,
    /// The result code KRB5_KPASSWD_MALFORMED (1): the verdict of an opened
    /// request (outcome `Success`), or the code an error reply was sealed
    /// with. Spec: RFC 3244 §2; docs/53 §9 (one record "with the code").
    KpasswdMalformed,
    /// The result code KRB5_KPASSWD_HARDERROR (2) an error reply was sealed
    /// with (outcome `Success`). Spec: RFC 3244 §2; docs/53 §5.7, §9.
    KpasswdHardError,
    /// The result code KRB5_KPASSWD_AUTHERROR (3) an error reply was sealed
    /// with (outcome `Success`). Spec: RFC 3244 §2; docs/53 §5.7, §9.
    KpasswdAuthError,
    /// The result code KRB5_KPASSWD_SOFTERROR (4): the verdict of an opened
    /// request whose new password was refused, or the code an error reply
    /// was sealed with (outcome `Success`). Spec: RFC 3244 §2; docs/53 §5.7,
    /// §9.
    KpasswdSoftError,
    /// The result code KRB5_KPASSWD_ACCESSDENIED (5): the verdict of an
    /// opened set request, or the code an error reply was sealed with
    /// (outcome `Success`). Spec: RFC 3244 §2; docs/53 §5.7, §9.
    KpasswdAccessDenied,
    /// The result code KRB5_KPASSWD_INITIAL_FLAG_NEEDED (7): the verdict of
    /// an opened request whose ticket is not INITIAL, or the code an error
    /// reply was sealed with (outcome `Success`). Spec: RFC 3244 §2; RFC
    /// 4120 2.1; docs/53 §5.7, §9.
    KpasswdInitialFlagNeeded,
    // ---- task F3: revoking a key-operation decision (Q-976) -------------
    /// An execution (`rotate_key`, `rotate_krbtgt`, `retire_kvno`) or a
    /// registration named a key-operation decision id that dird revoked
    /// (`revoke_decision`): nothing runs and nothing is registered under it.
    /// Decided at the authorization step — no intent (A-88). Reported as the
    /// uniform `Denied`.
    /// Spec: docs/52 §4.2; docs/questions/Q-937 item 6, Q-976.
    DecisionRevoked,
    /// `revoke_decision` named a key-operation decision whose execution
    /// already changed key state (a rotation recorded its kvno, a
    /// retirement its success): it cannot be undone, so it is not revoked —
    /// answering "revoked" would claim a cancellation that did not happen.
    /// Nothing changes. Reported as the uniform `Denied`.
    /// Spec: docs/52 §3.10 (C10: the recorded result), §4.2; docs/questions/
    /// Q-937 item 6, Q-976.
    DecisionExecuted,
    // ---- task PN8: the attestation key and the name resolution (docs/59 §7)
    /// `install_attestation_key`: keyd already holds an attestation key. A
    /// key is installed once per start, in the ceremony, and never replaced
    /// (a second key would let whoever presents it decide which resolutions
    /// keyd believes). Nothing changes. Reported as the uniform `Denied`.
    /// Spec: docs/59 §7.4; docs/questions/Q-1011 item 2 (A-173: "delivered to
    /// keyd in ceremony mode only, never exported").
    AttestationKeyInstalled,
    /// A name resolution reached keyd while it holds no attestation key (it
    /// was never installed in this start's ceremony): no resolution can be
    /// verified, so every one is refused (fail closed). Reported as the
    /// uniform `Denied`.
    /// Spec: docs/59 §7.2 step 1, §7.4; docs/questions/Q-1011 item 2;
    /// AGENTS.md §6 (fail closed).
    AttestationKeyMissing,
    /// The name resolution's tag does not verify under the attestation key
    /// (or a field is outside its bound): it is not dird's statement — the
    /// fields are never used. Reported as the uniform `Denied`.
    /// Spec: docs/59 §7.2 step 1, §7.5; docs/questions/Q-1011 item 4
    /// (A-173: "NameResolutionInvalid").
    NameResolutionInvalid,
    /// The (verified) name resolution was issued more than
    /// `NAME_RESOLUTION_WINDOW_SECS` (30 s) before or after keyd's own `now`.
    /// Reported as the uniform `Denied`.
    /// Spec: docs/59 §7.2 step 3, §7.5; docs/questions/Q-1011 items 3, 4
    /// (A-173: W = 30 s on keyd's own clock; "NameResolutionStale").
    NameResolutionStale,
    /// The verified name resolution does not name the key set it was
    /// presented for: another principal or another purpose than the key
    /// set's handle, a canonical name that is not the key set's bound name
    /// in the namespace's equivalence (principal-names), or a krbtgt key set
    /// (bound only by its exact stored binding, never by a resolution).
    /// Reported as the uniform `Denied`.
    /// Spec: docs/59 §7.2 step 4, §7.5; docs/questions/Q-1011 item 4
    /// (A-173: "NameResolutionMismatch"); RFC 4120 §6.2, §7.3.
    NameResolutionMismatch,
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
/// of two-key operations (the krbtgt key of `issue_as_rep`), the
/// dual-control `approvers` of `rotate_krbtgt`, and the `decision` a
/// Directory / Admin state change ran on (A-102, docs/52 §4.5 — the field a
/// detection rule matches against dird's `DirAdmin` event). None of them is
/// secret.
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
    /// Dual-control approvers (`rotate_krbtgt`; the first two approvers of
    /// any decision).
    pub approvers: Option<[PrincipalId; 2]>,
    /// The decision the operation registered or ran (A-102): its id for a
    /// key-operation or destroy decision; a set-secret decision's id at its
    /// registration and on the `set_secret` that consumed it.
    pub decision: Option<DecisionId>,
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
