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
//! | `Kdc`       | [`Keyd::verify_preauth`], [`Keyd::issue_as_rep`], [`Keyd::open_and_verify_tgt`], [`Keyd::issue_tgs_rep`], [`Keyd::open_fast_armor`], [`Keyd::seal_fast_error`] |
//! | `Directory` | [`Keyd::set_secret`], [`Keyd::verify_secret`] |
//! | `Admin`     | [`Keyd::create_key`], [`Keyd::rotate_key`], [`Keyd::rotate_krbtgt`], [`Keyd::retire_kvno`], [`Keyd::destroy_key_set`] |
//!
//! Key lifecycle (decision A-35, docs/questions/Q-115): keyd chooses every
//! kvno itself — `set_secret` returns the kvno it installed — and a deleted
//! account's key set is destroyed (zeroized) by `destroy_key_set`, never a
//! krbtgt key set.
//!
//! Key purposes: PrincipalLongterm, Krbtgt, Service. Encryption types: the
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
//!   ([`AuthnProof`] / [`TgtContext`] ctx id), bounded tables; an armored
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
//!   req-checksum and enc-fast-req all passed (`open_fast_armor`), may an
//!   [`AuthnError`] other than `Denied` be returned — `TicketExpired`,
//!   `TicketNotYetValid`, `Skew`, `Replay`. A `verify_preauth` refused by its
//!   failure throttle (A-34) is the uniform `Denied`.
//! - **I7** plaintext secrets are taken as `Zeroizing<String>` by value.
//! - **I8** every operation emits exactly one [`AuditRecord`], with no
//!   field able to hold a secret.
//!
//! Name binding (docs/questions/Q-040, decided A-19): every key set is bound,
//! at creation and for good, to one principal name ([`PrincipalBinding`]).
//! keyd refuses to issue a ticket naming a client other than the client
//! key's bound name, to seal a service ticket for an sname other than the
//! service key's bound name, and to use a krbtgt key not bound to
//! krbtgt/REALM. Name equivalence follows RFC 4120 6.2 (realm and
//! components octet for octet; name-type not significant).
//!
//! # Time and randomness
//!
//! keyd reads no clock: every operation takes `now` from the caller. The only
//! production entropy source is the kernel CSPRNG ([`OsEntropy`],
//! `/dev/urandom`, fail closed); tests inject a deterministic source through
//! the test-only [`Keyd::with_entropy`].
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
//! - keyd trusts the caller's `now` and the Admin caller's dual-control
//!   approvals (authenticity is the admin plane's, docs/43).
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
//!
//! # Provenance
//!
//! Written only from the allowed sources, opened in-session (AGENTS.md
//! §1-3): RFC 4120 (§1.6, §2, §3.1-3.3, §4, §5.2.7-5.2.9, §5.3, §5.4.1,
//! §5.4.2, §5.5.1, §5.9.1, §6.1, §6.2, §7.3, §7.5.1, §7.5.9, §8.2, §10),
//! RFC 3961 §3, RFC 3962 §3-4, RFC 6113 (§2.1, §2.4, §5.1, §5.2,
//! §5.4-§5.4.6, §6.2, §8),
//! [MS-KILE] v20260928 (§1.3.3, §3.1.1.1, §3.1.5.1, §3.1.5.9, §3.2.5.4,
//! §3.2.5.7, §3.3.5.1, §3.3.5.7.4 — checked against Q-120..Q-124), and this
//! project's design documents docs/09, docs/10, docs/25 §3, docs/30,
//! docs/33 §6.1, docs/45, docs/47 §9, docs/48, docs/questions/Q-040, Q-115
//! (A-35), Q-120..Q-127, Q-145, Q-150. No other implementation was consulted
//! or recalled.
//!
//! Spec: docs/10; docs/09 א; RFC 4120 §3, §5.

mod admin;
mod as_exchange;
pub mod audit;
pub mod authz;
pub mod config;
mod directory;
pub mod entropy;
mod error;
mod fast_armor;
#[allow(clippy::module_inception)]
mod keyd;
pub mod model;
mod replay;
pub mod store;
mod template;
mod tgs_exchange;
pub mod throttle;
mod time;
mod tokens;
mod usage;

pub use as_exchange::{AsRepParts, AsTicketTemplate, AuthnProof};
pub use audit::{AuditKeyRef, AuditOutcome, AuditReason, AuditRecord, AuditSink};
pub use authz::{CallerId, Operation, Role};
pub use config::{KeydConfig, ThrottlePolicy, TicketPolicy};
pub use entropy::{EntropyError, EntropySource, OsEntropy};
pub use error::{AuthnError, ConfigError, Error, IssueError};
pub use fast_armor::{FastArmor, FastConversation, MAX_FX_COOKIE_LENGTH};
pub use keyd::Keyd;
pub use model::{DualControlToken, KeyHandle, KeyPurpose, Kvno, PrincipalBinding, PrincipalId};
pub use store::{InMemoryKeyStore, KeyStore, StoreError, StoredKeySet};
pub use tgs_exchange::{TgsFastRequest, TgsRepParts, TgsTicketTemplate, TgtContext};
pub use throttle::{FailureWindowThrottle, SecretThrottle};
pub use time::kerberos_time_seconds;
pub use tokens::{ArmorId, CtxId, ExchangeId, TOKEN_ID_LENGTH};
