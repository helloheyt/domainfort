#![forbid(unsafe_code)]
//! `directory-pip`: the KDC's [`kdc::AccountSource`] and the PDP's
//! [`pdp::Pip`] over the directory — dirstore + the phase-1 AD schema
//! (docs/47, decided as A-38).
//!
//! # What it is
//!
//! A [`DirectoryContext`] is built once from the phase-1 schema and keyd's
//! configuration. For each request the caller takes a [`DirectoryView`] —
//! ONE dirstore snapshot plus the request's [`TierMap`] — and hands the same
//! view to the KDC twice: as the request's account source and as the PIP in
//! its `PolicyInputs` (docs/47 §8.1, R47-11, R47-14). Groups, tier and state
//! therefore come from one consistent picture.
//!
//! # The rules (docs/47 §12, all accepted)
//!
//! - **Names (R47-1):** AS client = exactly one component, looked up by
//!   sAMAccountName through the unique index, then re-compared octet for
//!   octet; user or computer only; never the krbtgt account (RID 502). TGS
//!   server = two or more components joined with "/", looked up by
//!   servicePrincipalName, octet for octet, on computers only. No UPN, "$",
//!   enterprise or canonicalisation fallbacks.
//! - **krbtgt (R47-2):** never a client or a service;
//!   [`DirectoryView::krbtgt_handle`] gives `KdcConfig.krbtgt`.
//! - **Keys (R47-3):** `KeyHandle = (objectGUID, purpose)`.
//! - **Salt (R47-4):** [`account_salt`], [MS-KILE] 3.1.1.2 — one public
//!   function for the password path and PA-ETYPE-INFO2.
//! - **State (R47-5, R47-6, R47-7):** enabled / expired / usable from
//!   userAccountControl, accountExpires, pwdLastSet; `locked = false`;
//!   `revoked_before = max(whenCreated + 1 s, ceil_s(pwdLastSet))`.
//! - **Groups (R47-8):** a bounded transitive closure over memberOf, security
//!   groups only; a cycle or a bound exceeded is an error.
//! - **Tier (R47-9):** a [`TierMap`] passed in as data, plus DC accounts,
//!   krbtgt and the domain root as Tier0; an unclassified object is Tier0
//!   for writes.
//! - **Enctypes (R47-10):** keyd's configured list and s2kparams.
//! - **Kind and armor policy (docs/48 §3.1, §7.2; Q-127 interim, P-10):**
//!   from the most specific objectClass — a computer object is
//!   `AccountKind::Computer` with `ArmorPolicy::BootstrapAllowed` (it may get
//!   its TGT unarmored, and its TGT may armor others' AS requests); a user is
//!   `AccountKind::User` with `ArmorPolicy::Required`.
//!
//! Every failure fails closed: `AccountSourceError` (the KDC refuses) or a
//! `PipError` (the PDP denies).
//!
//! # Residuals and follow-ups (documented, not hidden)
//!
//! - The tier map is trusted as given: verifying the signed policy store
//!   over it (docs/06 §9, D17) is a follow-up.
//! - DNs are accepted only in the directory's own form ([`DirectoryView::dn_of`]);
//!   RFC 4514 parsing is the LDAP layer's (docs/47 §8.2 ⚠).
//! - Phase 1 has no primaryGroupID, no builtin groups, no sIDHistory and no
//!   contextual SIDs in the expansion (docs/47 §5.3 item 6).
//! - No fuzz target: no network parser here — the input is MAC-verified
//!   dirstore records and names already decoded by krb-proto (docs/47
//!   §10.2).
//!
//! # Provenance
//!
//! Written only from docs/47 (in full; R47-1..R47-14, A-38), docs/48 §3.1,
//! §7.2-§7.3 (A-33), the decided questions Q-110..Q-117, Q-127 (interim),
//! PENDING-OWNER (A-18, A-19, A-27..A-38, P-6, P-9, P-10, P-11), docs/46,
//! and the pinned specifications opened in-session from
//! `tools/spec-pin/cache/` (SHA-256 verified against
//! `tools/spec-pin/manifest.json`): [MS-KILE] v20260928 3.1.1.2, 3.3.1.1,
//! 3.3.3, 3.3.5.6.3, 4.4; [MS-ADTS] v20261026 2.2.12, 2.2.16, 3.1.1.4.5.17;
//! [MS-SAMR] v20260427 2.2.1.14, 2.2.6.1, 3.1.1.6 (items 11-24), 3.1.1.8.1,
//! 3.1.5.14.4; [MS-DRSR] v20260309 4.1.8.2.2, 4.1.8.2.6, 4.1.8.3, 5.51;
//! [MS-DTYP] v20241119 2.3.3, 2.4.2.4; RFC 4120 3.3.3.1, 6.2. The source and
//! documentation of this project's own crates dirstore, ad-schema, kdc, pdp,
//! keyd, krb-proto and dtyp were read for their APIs. No other
//! implementation was consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/47 §1-§12; docs/11 §6; docs/06 §8-§10.

mod error;
mod groups;
mod names;
mod record;
mod salt;
mod state;
mod tier;
mod time;
mod view;

pub use error::ViewError;
pub use groups::{MAX_EXPANDED_GROUPS, MAX_NESTING_DEPTH};
pub use salt::{account_salt, AccountKind, SaltError};
pub use tier::TierMap;
pub use view::{DirectoryContext, DirectoryView, MAX_DN_DEPTH};
