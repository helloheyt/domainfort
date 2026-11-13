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
//! | `Kdc`       | [`Keyd::verify_preauth`], [`Keyd::issue_as_rep`], [`Keyd::open_and_verify_tgt`], [`Keyd::issue_tgs_rep`] |
//! | `Directory` | [`Keyd::set_secret`], [`Keyd::verify_secret`] |
//! | `Admin`     | [`Keyd::create_key`], [`Keyd::rotate_key`], [`Keyd::rotate_krbtgt`], [`Keyd::retire_kvno`] |
//!
//! Key purposes: PrincipalLongterm, Krbtgt, Service. Encryption types: the
//! AES types of `krb-crypto` (17, 18, 19, 20) — no weak type is expressible.
//!
//! **Not implemented — no code path, no enum variant:** Netlogon, SNTP,
//! GKDI, BackupKey, S4U, replication, PKINIT, FAST, user-to-user, renewal /
//! validation, forwarded / proxy tickets, cross-realm. **No PAC** in phase 1
//! (MS-PAC + NDR is phase 2, where D124 applies): tickets carry no
//! authorization-data.
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
//!   ([`AuthnProof`] / [`TgtContext`] ctx id), bounded tables.
//! - **I5** only configured AES enctypes ([`KeydConfig::enctypes`]).
//! - **I6** secret comparisons via approved constant-time facilities
//!   (krb-crypto `verify_mic` / integrity checks). Errors are uniform for
//!   every failure decided before the cryptographic chain completes;
//!   classified after (A-26, docs/questions/Q-071): only once the TGT and the
//!   authenticator decrypted and the req-body checksum verified
//!   (`open_and_verify_tgt`), or the PA-ENC-TIMESTAMP decrypted and decoded
//!   (`verify_preauth`), may an [`AuthnError`] other than `Denied` be
//!   returned — `TicketExpired`, `TicketNotYetValid`, `Skew`, `Replay`.
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
//!
//! # Provenance
//!
//! Written only from the allowed sources, opened in-session (AGENTS.md
//! §1-3): RFC 4120 (§1.6, §2, §3.1-3.3, §4, §5.2.7-5.2.9, §5.3, §5.4.1,
//! §5.4.2, §5.5.1, §6.1, §6.2, §7.3, §7.5.1, §8.2, §10), RFC 3961 §3,
//! RFC 3962 §3-4, and this project's design documents docs/09, docs/10,
//! docs/25 §3, docs/30, docs/33 §6.1, docs/45, docs/questions/Q-040. No
//! other implementation was consulted or recalled.
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
pub use keyd::Keyd;
pub use model::{DualControlToken, KeyHandle, KeyPurpose, Kvno, PrincipalBinding, PrincipalId};
pub use store::{InMemoryKeyStore, KeyStore, StoreError, StoredKeySet};
pub use tgs_exchange::{TgsRepParts, TgsTicketTemplate, TgtContext};
pub use throttle::{FailureWindowThrottle, SecretThrottle};
pub use time::kerberos_time_seconds;
pub use tokens::{CtxId, ExchangeId, TOKEN_ID_LENGTH};
