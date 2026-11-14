#![forbid(unsafe_code)]
//! `keyd`: the secret-custody core — "compute, don't give".
//!
//! **No operation of keyd returns long-term key material.** keyd performs
//! operations *with* secrets and returns results — never the secret itself
//! (docs/09 א.1; docs/10 invariant I1).
//!
//! # Scope (phase 1, native face)
//!
//! A pure library — no sockets, no IPC, no daemon (the IPC codec and the
//! process are a later crate, D34). It implements docs/10 for:
//!
//! | Role        | Operations |
//! |-------------|------------|
//! | `Kdc`       | [`Keyd::verify_preauth`], [`Keyd::issue_as_rep`], [`Keyd::open_and_verify_tgt`], [`Keyd::issue_tgs_rep`], [`Keyd::open_fast_armor`], [`Keyd::seal_fast_error`], [`Keyd::describe_config`], [`Keyd::ping`] |
//! | `Directory` | [`Keyd::set_secret`] (on a dird decision), [`Keyd::ping`] |
//! | `Admin`     | before the seal: [`Keyd::create_key`], [`Keyd::grant_set_secret`] (initial secrets of users); always: [`Keyd::rotate_key`], [`Keyd::rotate_krbtgt`], [`Keyd::retire_kvno`], [`Keyd::destroy_key_set`] (each by dird decision id), [`Keyd::seal_ceremony`], [`Keyd::list_destroy_decisions`], [`Keyd::ping`] |
//! | `Ldap`      | [`Keyd::open_and_verify_service_ticket`], [`Keyd::register_decision`], [`Keyd::describe_config`], [`Keyd::ping`] |
//!
//! [`Keyd::verify_secret`] is in no role's row (A-102, docs/52 R4).
//!
//! **The decision table** (A-102; docs/52 R1, §4; docs/questions/Q-460,
//! Q-461): keyd performs **no** state change for Role::Directory or
//! Role::Admin without a one-time, operation-bound decision that dird
//! (Role::Ldap, the PDP that owns it) registered with
//! [`Keyd::register_decision`] — a [`DecidedOperation`]: a password set
//! (handle, binding **and salt**; A-100's grant generalized, N4), a krbtgt
//! or key rotation, a kvno retirement, or the destruction of a deleted
//! account's key sets. keyd runs exactly the registered parameters; Admin's
//! operations name only the [`DecisionId`]; `rotate_krbtgt`'s dual-control
//! token is built inside keyd from the decision's approvers. A decision is
//! consumed by its first presentation and its result kept until it
//! expires: presenting the id again returns that result. Bounded, in
//! memory, lost at every start (stricter). Registration loosens keyd, so it
//! is audited like a key-state change ([`requires_acknowledged_intent`]).
//!
//! **The ceremony state** (A-102; docs/52 R3; docs/questions/Q-462 item 1):
//! keyd starts in [`CeremonyState::Provisioning`] only with an empty key
//! store; [`Keyd::create_key`] and Admin's [`Keyd::grant_set_secret`] (a
//! first administrator's initial secret, ≤ [`MAX_INITIAL_SECRET_GRANT_SECS`],
//! docs/questions/Q-451) exist only there; [`Keyd::seal_ceremony`] ends it.
//!
//! **Types and seam** (D182; decision A-63): every crypto-free type of this
//! interface — ids and handles, roles, operations and the capability table,
//! the error enums, the argument and result types below, the token ids, the
//! configuration and audit types, [`kerberos_time_seconds`] and the KDC's
//! [`KeyCustody`] seam — lives in the `keyd-types` crate and is re-exported
//! here unchanged, so that the kdc, ldap, directory-pip and ipc-keyd link no
//! crypto code. Encryption types cross the interface as [`EncTypeId`]
//! identifiers; keyd converts them to krb-crypto's type internally. keyd
//! provides the in-process custody, [`LocalKeyd`] (moved from the kdc
//! crate).
//!
//! **Daemon support** (docs/50 §3.4, §7.5): [`Keyd::describe_config`]
//! returns the non-secret [`ConfigDescription`] the kdc validates its own
//! configuration against before it binds its ports; [`Keyd::ping`] is the
//! health check. Neither touches a key.
//!
//! **Startup hold-down** (RFC 4120 3.2.3; docs/50 R50-6, §3.5; decision
//! A-56, docs/questions/Q-222): the replay cache and the token tables live in
//! memory and are empty after every start, so every operation of the
//! Kerberos exchanges ([`authz::startup_hold_down_applies`]) is refused as
//! `Unavailable` until `now` is later than the start time given to
//! [`Keyd::new`] plus two `clock_skew_secs` intervals (A-62: an
//! authenticator accepted just before a restart may carry a client time up
//! to one skew ahead and stays acceptable one skew after that, while the
//! replay cache that would catch it is gone). Decided right after the role and
//! purpose checks, before any secret-dependent work — no oracle (A-56,
//! docs/questions/Q-217). Directory, Admin, `describe_config` and `ping` are
//! not held.
//!
//! **Service-ticket verification** (docs/49 §3.3, task L6a; decision A-46,
//! docs/questions/Q-165): [`Keyd::open_and_verify_service_ticket`] runs RFC
//! 4120 §3.2.3 on a service AP-REQ inside keyd under the LDAP service key —
//! a Service key set that keyd drew itself (`create_key`) and that never
//! leaves — and returns only non-secret facts ([`ServiceContext`]) and a
//! one-time [`ServiceCtxId`]; the session key and subkey stay in keyd. The
//! GSS framing, the GSS authenticator checksum, channel binding and the
//! AP-REP are task L6b (docs/49 §12). **R2 (docs/52 §3.2, §5; A-102):** the
//! caller names the service key set by its principal and an
//! [`AppBinding`]; the binding fixes the key set's purpose
//! ([`AppBinding::key_purpose`]) — `Unbound` opens a `Service` key set
//! (the LDAP service: no `cksum` allowed), `OperationDigest` an
//! `AdminService` key set (the admin service: the Authenticator's `cksum`
//! must be the session key's MIC over the operation digest, key usage 10,
//! RFC 4120 §5.5.1 / §7.5.1). An admin ticket without its operation
//! binding cannot be verified at all.
//!
//! **Key-state changes** (decision A-86, docs/questions/Q-346):
//! [`changes_key_state`] names the six operations that install, rotate,
//! retire or destroy long-term key versions, and [`Keyd::admits`] runs an
//! operation's authorization step (role, purpose, hold-down) on its own, with
//! no record — so that the daemon can have the record of a change's intent
//! acknowledged by auditd before keyd performs it.
//!
//! Key lifecycle (decision A-35, docs/questions/Q-115): keyd chooses every
//! kvno itself — `set_secret` returns the kvno it installed — and a deleted
//! account's key set is destroyed (zeroized) by `destroy_key_set`, never a
//! krbtgt key set.
//!
//! Key purposes: PrincipalLongterm, Krbtgt, Service, AdminService (R2: the
//! admin service's key set, bound only to `admind/<host>`). Encryption types: the
//! AES types of `krb-crypto` (17, 18, 19, 20) — no weak type is expressible.
//!
//! **FAST (RFC 6113)** (docs/48 tasks T1, T2, T3): the AS armor
//! (FX_FAST_ARMOR_AP_REQUEST) is opened and its KrbFastReq decrypted inside
//! keyd; [`Keyd::verify_preauth`] with an armor verifies the encrypted
//! challenge FAST factor (one attempt per armor); [`Keyd::issue_as_rep`]
//! with that armor seals the reply under the strengthened reply key and
//! returns the sealed KrbFastResponse (`fast_rep`: the KDC's encrypted
//! challenge, the strengthen key, KrbFastFinished). In the TGS,
//! [`Keyd::open_and_verify_tgt`] with a [`TgsFastRequest`] derives the
//! implicit armor key from the PA-TGS-REQ subkey and the TGT session key,
//! verifies the req-checksum over the AP-REQ and decrypts the KrbFastReq;
//! [`Keyd::issue_tgs_rep`] on that context strengthens the reply key and
//! returns the sealed KrbFastResponse. Armored errors of either exchange
//! are sealed inside keyd ([`Keyd::seal_fast_error`]). No FAST key — armor,
//! challenge, strengthen, reply — leaves keyd (docs/48 §2, A-33).
//! Computer-account-only armor (D126) is the KDC's check — keyd holds no
//! account kind.
//!
//! **Not implemented — no code path, no enum variant:** Netlogon, SNTP,
//! GKDI, BackupKey, S4U, replication, PKINIT, anonymous FAST armor,
//! user-to-user, renewal / validation, forwarded / proxy tickets,
//! cross-realm. **No PAC** in phase 1 (MS-PAC + NDR is phase 2, where D124
//! applies): tickets carry no authorization-data.
//!
//! # Invariants (docs/10 §12) and where they are enforced
//!
//! - **I1** no long-term key bytes out: [`store::StoredKeySet`] is opaque;
//!   operations return only kvnos, one-time tokens, non-secret ticket facts
//!   and sealed `EncryptedData`.
//! - **I2** role check: [`authz::role_permits`] over the compile-time
//!   [`authz::CAPABILITY_TABLE`], first step of every operation.
//! - **I3** purpose check: [`authz::purpose_permitted`] for every handle.
//! - **I4** issuance needs a valid, one-time, caller-bound token
//!   ([`AuthnProof`] / [`TgtContext`] ctx id), bounded tables (the service
//!   contexts of verified service tickets are one too); an armored
//!   error needs the one-time token of its conversation ([`ArmorId`], or the
//!   ctx id of an armored TGS context); an armor allows one
//!   pre-authentication attempt, its proof issues only with it (and an
//!   unarmored proof only without one), and it is consumed once — as is an
//!   armored TGS context (by a successful issuance or by the armored error).
//! - **I5** only configured AES enctypes ([`KeydConfig::enctypes`]).
//! - **I6** secret comparisons via approved constant-time facilities
//!   (krb-crypto `verify_mic` / integrity checks). Errors are uniform for
//!   every failure decided before the cryptographic chain completes;
//!   classified after (A-26, docs/questions/Q-071): only once the TGT and the
//!   authenticator decrypted and the req-body checksum verified — and, under
//!   FAST, the req-checksum verified and the KrbFastReq decrypted and decoded
//!   (`open_and_verify_tgt`), or the PA-ENC-TIMESTAMP — or, armored, the
//!   encrypted challenge — decrypted and decoded (`verify_preauth`), or the
//!   armor TGT, authenticator, subkey, armor key,
//!   req-checksum and enc-fast-req all passed (`open_fast_armor`), or the
//!   service ticket and its authenticator decrypted
//!   (`open_and_verify_service_ticket`), may an
//!   [`AuthnError`] other than `Denied` be returned — `TicketExpired`,
//!   `TicketNotYetValid`, `Skew`, `Replay`. A `verify_preauth` refused by its
//!   failure throttle (A-34) is the uniform `Denied`. **By type since R7**
//!   (docs/52 §3.6 (a)): a classified refusal is built only by a
//!   `ChainVerified` (crate::chain), which is minted only from the evidence
//!   of the chain's cryptographic steps — each made by one real decryption or
//!   checksum verification — so no refusal before the chain completes can
//!   carry a class.
//! - **I7** plaintext secrets are taken as `Zeroizing<String>` by value.
//! - **I8** every operation emits exactly one [`AuditRecord`], with no
//!   field able to hold a secret — plus, for a `DestroyKeySet` registration
//!   only, one record per set-secret entry it discarded (R6b, Q-520).
//!
//! Name binding (docs/questions/Q-040, decided A-19): every key set is bound,
//! at creation and for good, to one principal name ([`PrincipalBinding`]).
//! keyd refuses to issue a ticket naming a client other than the client
//! key's bound name, to seal a service ticket for an sname other than the
//! service key's bound name, and to use a krbtgt key not bound to
//! krbtgt/REALM. Name equivalence follows RFC 4120 6.2 (realm and
//! components octet for octet; name-type not significant). **By type since
//! R7** (docs/52 §3.5; [`store`]): a stored key is reachable only through
//! the proof of its binding (`StoredKeySet::bound_to`) or a declared
//! `UnboundUse` (the pre-authentication check and `verify_secret`, which
//! issue nothing under a name); a password-derived version is installed only
//! under its binding, and a key set is created only from the creation rule's
//! proof — an operation that skips the check does not compile.
//!
//! Destroy decisions (R6b; docs/questions/Q-501, Q-520): a `DestroyKeySet`
//! registration first discards every live set-secret entry of the
//! principal's two handles (one `SecretDecisionDiscarded` record each — the
//! deleted principal can get no key set afterwards), then is refused for a
//! principal that has no `PrincipalLongterm` or `Service` key set
//! (`KeyNotFound`, no table slot), checked before the table — so "destroyed"
//! is read from the key store, and a re-registration after the destruction
//! schedules nothing.
//!
//! # Time and randomness
//!
//! keyd reads no clock: every operation takes `now` from the caller, and the
//! constructor takes the start time of the hold-down. The keyd daemon reads
//! both from its OWN clock; an IPC layer never takes them from the peer
//! (docs/50 R50-5: otherwise a compromised kdc could "turn the time back" to
//! use an expired TGT, or end the hold-down early). The only production
//! entropy source is the kernel CSPRNG ([`OsEntropy`], `/dev/urandom`, fail
//! closed); tests inject a deterministic source through the test-only
//! [`Keyd::with_entropy`].
//!
//! # Residuals (documented, not hidden)
//!
//! - Key material is in process memory: no HSM yet (D30, D35). The krbtgt key
//!   is held only by the explicitly insecure development store (D178).
//! - `parse-asn1` encode temporaries (intermediate `Vec`s and growth copies
//!   while encoding EncTicketPart / EncKDCRepPart, which contain the session
//!   key) are freed without being wiped — not fixable in keyd. krb-proto
//!   scrubs its value tree, and the final encodings (and every decrypted
//!   plaintext) are held in `Zeroizing` buffers that keyd drops as soon as
//!   they are sealed or decoded. Rust moves of `ProtocolKey` values may leave
//!   stack copies. `mlock`, no core dumps and guard pages belong to the
//!   daemon (docs/10 §11).
//! - Name binding compares names exactly as given: canonicalization (case,
//!   aliases, enterprise names) is the KDC's job before it calls keyd, and a
//!   binding is only as correct as the Admin / Directory caller that created
//!   the key set. There is no rename in phase 1 (follow-up: a rename
//!   interface, docs/10 §7).
//! - keyd trusts the caller's `now` and start time (the daemon's own clock,
//!   docs/50 R50-5) and dird's decisions — the approvers a decision names
//!   were verified by dird, not by keyd (dird ≡ tier-0 for keyd's
//!   mutations, docs/52 §4.7, C16; docs/questions/Q-464, R5).
//! - The ceremony state is held in memory: a keyd started with an empty
//!   store — in development mode, every start (A-77, P-17) — is
//!   `Provisioning` again until the next seal, and while dird runs every
//!   account then has no key set, so keyadm + admind could set initial
//!   secrets until the seal (docs/52 §4.4 residual; closed with a
//!   persistent store, P-17).
//! - The startup hold-down makes every Kerberos operation unavailable for
//!   two clock-skew intervals after each start (10 minutes with the RFC 4120
//!   §8.2 default skew) — the availability price of closing the replay
//!   window (A-62). (The `verify_secret` failure throttle has no caller
//!   since A-102 — no role holds the operation.)
//! - A full replay cache or token table refuses new requests (fail closed),
//!   a denial-of-service trade-off (D33).
//! - The `verify_preauth` failure throttle (A-34) lets anyone who can reach
//!   the KDC lock a principal out of the AS exchange for one window by
//!   sending wrong timestamps, and refuses untracked principals while its
//!   table is full of live windows (fail closed) — the price of bounding
//!   online password guessing, as for `verify_secret`.
//! - The armor AP-REQ shares the TGS replay cache (Q-120): a client that
//!   reuses one armor AP-REQ across a conversation is refused as a replay;
//!   the native client builds a fresh one per request (lab check before
//!   Windows clients, D8).
//! - Armored AS interpretations awaiting the lab (docs/questions/Q-121,
//!   Q-122, Q-123, Q-145): usage 3 and the client kvno under the
//!   strengthened reply key; the ticket-checksum over the full Ticket DER;
//!   keyd's single choice of the challenge's long-term key (the KDC must
//!   advertise the same one in PA-ETYPE-INFO2 — task T5); an
//!   EncryptedChallenge carries no kvno. A client that reads them otherwise
//!   is refused (fail closed), never accepted wrongly.
//! - Armored TGS interpretations awaiting the lab (docs/questions/Q-121,
//!   Q-122, Q-124, Q-150): usage 9 under the strengthened reply key; the
//!   PA-TGS-REQ authenticator checksum still covers the OUTER body, which is
//!   still checked (realm, no enc-authorization-data); an armored context
//!   survives a refused `issue_tgs_rep` so that the error can be armored.
//! - Service-ticket verification interpretations awaiting review
//!   (docs/questions/Q-180): the A-19 binding is checked before decryption;
//!   INVALID is the uniform `Denied`; an authenticator checksum is refused
//!   on an unbound verification until task L6b; only keyd-drawn (never
//!   password-derived) service key versions open a ticket; Role::Ldap may
//!   name any Service key set (keyd has no notion of "the LDAP key set" —
//!   the binding check is what ties a ticket to its key). In task L6a
//!   nothing consumes a service context: it expires with the token
//!   lifetime (and dird's admin verifications leave one each, Q-387 item 4).
//! - The operation binding (R2) proves what the admin client's host signed,
//!   not what its operator meant: a compromised administrator workstation
//!   can still sign another operation (docs/52 §5 item 8). The binding's
//!   `cksum` is keyed with the ticket session key, not a subkey (RFC 4120
//!   §7.5.1 item 10: "keyed with the application session key";
//!   docs/questions/Q-490).
//!
//! # Provenance
//!
//! Written only from the allowed sources, opened in-session (AGENTS.md
//! §1-3): RFC 4120 (§1.6, §2, §3.1-3.3, §4, §5.2.7-5.2.9, §5.3, §5.4.1,
//! §5.4.2, §5.5.1, §5.5.2, §5.9.1, §6.1, §6.2, §7.3, §7.5.1, §7.5.3-7.5.5,
//! §7.5.9, §8.2, §10),
//! RFC 3961 §3, RFC 3962 §3-4, RFC 6113 (§2.1, §2.4, §5.1, §5.2,
//! §5.4-§5.4.6, §6.2, §8),
//! [MS-KILE] v20260928 (§1.3.3, §3.1.1.1, §3.1.5.1, §3.1.5.9, §3.2.5.4,
//! §3.2.5.7, §3.3.5.1, §3.3.5.7.4 — checked against Q-120..Q-124), and this
//! project's design documents docs/09, docs/10, docs/25 §3, docs/30,
//! docs/33 §6.1, docs/45, docs/47 §9, docs/48, docs/49 §3.3, §12,
//! docs/50 (R50-5, R50-6, R50-8, §3.4, §3.5, §3.7, §7.5),
//! docs/questions/Q-040, Q-115 (A-35), Q-120..Q-127, Q-145, Q-150, Q-165
//! (A-46), Q-180, Q-217 and Q-222 (A-56), Q-240 (A-62), Q-245 item 3 (A-63:
//! the keyd-types split, D182); for the key-state classification and
//! `Keyd::admits` (task F2), docs/51 §5.7 and decision A-86 (Q-346, as
//! stated in the task; Q-365); for the set_secret grant (task A15a), docs/51
//! §4.3, §5.2, §5.8, §7.3, §9, docs/47 §9.1-§9.2, docs/10 §2, §6, §8-§11,
//! docs/questions/Q-291 (A-74), Q-365 (A-88) and Q-450..Q-453; for the
//! decision table and the ceremony state (A-102), docs/52 §3.1, §3.3, §3.4,
//! §3.10, §4, §7 and docs/questions/Q-460..Q-462, Q-465; for the operation
//! binding and the admin service purpose (R2, A-102), RFC 4120 §4, §3.3.3,
//! §5.2.9, §5.5.1, §7.5.1, RFC 3961 §2-§4, §5.3, §5.4, §8, RFC 3962 §6, §7,
//! RFC 8009 §1, §6, §7 (pinned copies, SHA-256 verified), docs/52 §3.2, §5
//! and docs/questions/Q-463, Q-490..Q-493; for the binding and chain proof
//! types (R7) and the destroy-registration rule (R6b), docs/52 §3.5, §3.6,
//! §7, docs/10 §6א, §7, §9, §12 I6, docs/25 §3.2, RFC 4120 §3.2.3, §6.2
//! (pinned copy, SHA-256 verified), docs/questions/Q-040, Q-071, Q-470,
//! Q-471, Q-501, Q-503 and decisions A-19, A-26, A-105, A-107. No other
//! implementation was consulted or recalled.
//!
//! Spec: docs/10; docs/09 א; RFC 4120 §3, §5.

mod admin;
mod as_exchange;
mod chain;
mod custody;
mod decision;
mod directory;
mod enctype;
pub mod entropy;
mod error;
mod fast_armor;
#[allow(clippy::module_inception)]
mod keyd;
mod replay;
mod runtime;
mod service_ticket;
mod state_change;
pub mod store;
mod template;
mod tgs_exchange;
pub mod throttle;
mod time;
mod tokens;
mod usage;

// The crypto-free types of keyd's interface live in keyd-types (D182;
// decision A-63) and are re-exported here unchanged: `keyd::X` and
// `keyd_types::X` are the same item. The modules `audit`, `authz`, `config`
// and `model` keep their paths.
pub use keyd_types::{audit, authz, config, model};

pub use custody::LocalKeyd;
pub use entropy::{EntropyError, EntropySource, OsEntropy};
pub use keyd::Keyd;
pub use keyd_types::kerberos_time_seconds;
pub use keyd_types::{
    is_admin_service_name, AppBinding, OperationDigest, ADMIN_SERVICE_CLASS, OPERATION_DIGEST_LEN,
};
pub use keyd_types::{
    AccountKind, SetSecretTarget, MAX_GRANT_TARGETS, MAX_INITIAL_SECRET_GRANT_SECS,
    MAX_SET_SECRET_GRANTS, MAX_SET_SECRET_GRANT_SECS,
};
pub use keyd_types::{
    ArmorId, AsRepParts, AsTicketTemplate, AuditKeyRef, AuditOutcome, AuditReason, AuditRecord,
    AuditSink, AuthnError, AuthnProof, CallerId, ConfigDescription, ConfigError, CtxId, EncTypeId,
    Error, ExchangeId, FastArmor, FastConversation, IssueError, KeyCustody, KeyHandle, KeyPurpose,
    KeydConfig, Kvno, Operation, PrincipalBinding, PrincipalId, Role, ServiceContext, ServiceCtxId,
    TgsFastRequest, TgsRepParts, TgsTicketTemplate, TgtContext, ThrottlePolicy, TicketPolicy,
    MAX_FX_COOKIE_LENGTH, TOKEN_ID_LENGTH,
};
pub use keyd_types::{
    CeremonyState, DecidedOperation, DecisionId, DecisionIntent, DestructionPage,
    PendingDestruction, MAX_DECISION_APPROVERS, MAX_DESTROY_DECISIONS, MAX_DESTROY_DECISION_PAGE,
    MAX_DESTROY_DECISION_SECS, MAX_KEY_DECISIONS, MAX_KEY_DECISION_SECS,
    MIN_KEY_DECISION_APPROVERS,
};
pub use state_change::{changes_key_state, loosens_authorization, requires_acknowledged_intent};
pub use store::{InMemoryKeyStore, KeyStore, StoreError, StoredKeySet};
pub use throttle::{FailureWindowThrottle, SecretThrottle};
