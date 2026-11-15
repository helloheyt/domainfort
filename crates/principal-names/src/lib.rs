#![forbid(unsafe_code)]
//! `principal-names`: the one name equivalence of the principal namespace
//! (docs/59 §4.2-§4.4, task PN1; decision A-173).
//!
//! # What it is
//!
//! Every string that names a principal — a sAMAccountName, a computer's
//! base name, a userPrincipalName's local part, a servicePrincipalName, a
//! computer's dNSHostName, a realm alias — is one key in one key space,
//! `fold(string)`; the kind of the name is metadata re-derived from the
//! object, never part of the key (docs/59 §4.1, R59-1; RFC 4120 §6.2: "The
//! name type does not partition the name space. Ignoring the name type, no
//! two names can be the same"). This crate is the only definition of that
//! equivalence:
//!
//! | item | what | docs/59 |
//! |---|---|---|
//! | [`fold`], [`PrincipalKey`], [`MAX_KEY_OCTETS`] | the one ASCII fold; a key, built only here | §4.2 |
//! | [`NameKind`], [`KindSet`] | the kinds a key carries | §4.1 |
//! | [`NameContext`] | the realm's alias set (phase 1: its DNS name only — P-84) | §4.2 |
//! | [`keys_of_names`], [`PrincipalNames`], [`PrincipalClass`], [`KeySet`] | the write side: the keys an object's stored names produce | §4.3, §4.4 |
//! | [`key_of_request`], [`RequestKey`] | the lookup side: the one key a request probes | §4.2 |
//! | [`reserved_name_of`], [`ReservedName`] | the reserved names, judged on the folded form | §4.2, Q-1009 |
//! | [`NameRefused`] | why a stored name has no key | §4.4 |
//!
//! The writer (crates/directory-admin, task PN5), the lookup
//! (crates/directory-pip, tasks PN1/PN4) and keyd's acceptor compare (task
//! PN11) call it. No store, no I/O, no clock, no secret.
//!
//! # The classes this closes (AGENTS.md §6.1)
//!
//! - **C31 (M1, docs/59 §3) — an identity lookup through a fallback chain of
//!   separate name spaces.** [`key_of_request`] gives at most ONE key for
//!   any request: the chains of [MS-KILE] 3.3.5.6.1 (sAMAccountName ⇒
//!   cname + "$" ⇒ `cname@realm`) and 3.3.5.1.1 collapse into one probe,
//!   because [`keys_of_names`] stores every form an object answers to
//!   (`x$` and `x` for computer `x$`; the UPN's local part) in the same key
//!   space, where the store's unique index makes each key name at most one
//!   object (task PN2). `krbtgt/X` never reaches the index.
//! - **C31 / W3 (M2) — uniqueness per attribute, not over the union.** One
//!   key space for every kind: a computer `dc$` (key `dc`) and a user `dc`
//!   (key `dc`) cannot both exist, nor a UPN `bob@<realm>` beside another
//!   object's sAMAccountName `bob`, nor one SPN in two spellings.
//! - **C49 (M3) — name equivalence computed by more than one function.**
//!   One fold ([`fold`]), one key builder, one set of reserved-name
//!   predicates on the folded form ([`reserved_name_of`]); the names
//!   themselves stay defined in keyd-types (`ADMIN_SERVICE_CLASS`) and
//!   krb-proto (`CHANGE_PASSWORD_SERVICE_NAME`).
//!
//! By construction: a [`PrincipalKey`] can only be built here, never holds
//! "@", uses "/" only between non-empty components, and is folded — so
//! joining cannot give one key for two different component lists (docs/59
//! §4.2 "injectivity"), and a name in "@" form is never itself a key.
//!
//! # Residuals (documented, not hidden)
//!
//! - The fold is a second definition beside `dirstore`'s comparison key
//!   (dirstore is a leaf and must not depend on this crate); the two are
//!   pinned equal on all 95 printable octets by crates/directory-pip
//!   `tests/principal_names.rs` (Q-1008 item 4; docs/59 §9 S1).
//! - The realm alias set is the realm's DNS name only, and
//!   userPrincipalName suffixes are that name only (P-84, Q-1012): clients
//!   naming the realm by its flat name fail closed (docs/59 §9 S8).
//! - Nothing calls this crate yet except tests: the lookup, the writer and
//!   keyd adopt it in tasks PN4, PN5 and PN11 (docs/59 §10).
//! - Which N-rules of docs/59 §4.4 live here and which stay in the admin
//!   plane: module `stored` and docs/questions/Q-1018 item 2.
//!
//! # Provenance
//!
//! Written only from docs/59 (in full; §2-§4, §6, §8-§10), the decided
//! questions docs/questions/Q-1007..Q-1012 (A-173), Q-080 (A-29, P-9),
//! Q-1008 item 2, PENDING-OWNER A-139, A-163, A-170, A-173, and the
//! pinned specifications opened in-session from `tools/spec-pin/cache/`
//! (SHA-256 verified against `tools/spec-pin/manifest.json`): [MS-KILE]
//! v20261110 3.1.5.7, 3.1.5.11, 3.3.5.1.1, 3.3.5.1.2, 3.3.5.6.1; [MS-ADTS]
//! v20261026 2.2.21, 3.1.1.5.3.1.1.2, 3.1.1.5.3.1.1.4, 3.1.1.13.6,
//! 3.1.1.13.7; [MS-SAMR] v20260427 3.1.1.6 items 8-14, 3.1.1.8.4;
//! [MS-DRSR] v20260309 4.1.4.2.22; RFC 4120 §6.1, §6.2, §6.2.1, §7.3; RFC
//! 3244 §2. This project's crates krb-proto, keyd-types, directory-admin
//! (`names.rs`), directory-pip and dirstore were read for their APIs and
//! rules only. No other implementation was consulted or recalled
//! (AGENTS.md §1-3).
//!
//! Spec: docs/59 §4.1-§4.4, §8 (the PN1 row), §10; A-139; A-173.

mod context;
mod error;
mod key;
mod request;
mod reserved;
mod stored;

pub use context::NameContext;
pub use error::NameRefused;
pub use key::{fold, KindSet, NameKind, PrincipalKey, MAX_KEY_COMPONENTS, MAX_KEY_OCTETS};
pub use request::{key_of_request, RequestKey};
pub use reserved::{reserved_name_of, ReservedName};
pub use stored::{
    keys_of_names, KeySet, PrincipalClass, PrincipalNames, MAX_KEYS_PER_OBJECT,
    MAX_SERVICE_PRINCIPAL_NAMES,
};
