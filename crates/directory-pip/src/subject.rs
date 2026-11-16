//! The subject lookup of a ticket's client — the one lookup path in the
//! `TicketClient` context, answering only the facts the subject checks read
//! (task PN10b; docs/59 §6.2, §6.4; decision A-187 on docs/questions/
//! Q-1047).
//!
//! # Who asks
//!
//! A service that holds a ticket keyd verified builds the PDP Subject of the
//! client the ticket names from the directory, never from the ticket's
//! holder (docs/51 §5.3, R51-8; docs/49 §3.2; docs/11 P3): the admin plane
//! (its requesters and approvers), kpasswd and the DNS update — one
//! construction, crates/directory-admin `AdminSubject::from_verified_ticket`
//! — and the LDAP session's per-request re-check of a bound identity
//! (crates/ldap `session::recheck`; docs/49 §4.4, R49-15). The admin
//! plane's self-lockout guard asks whether a Tier-0 administrator could
//! still be such a Subject now (crates/directory-admin `checks`; Q-295
//! item 4, P-22). docs/59 §6.2 names their context: `TicketClient`.
//!
//! # What it answers — derived from those checks
//!
//! | check | reads |
//! |---|---|
//! | `AdminSubject::from_verified_ticket` | `state.usable_at`, `state.revokes`, `sid`, `groups`, `tier`, `guid` (the approver identity of a dual-control token) |
//! | LDAP `recheck` | `state.usable_at`, `state.revokes`, `sid` (still the bound one), `groups`, `tier` |
//! | the self-lockout guard | `state.usable_at` and `guid` (the very object it counts) — of an administrator whose Subject **could be built**: the guard counts who could still administer, so an account whose expansion or tier cannot be computed (an expansion over its bound, a cycle written beneath the checker) makes the count fail, as before, instead of being counted |
//!
//! So [`TicketSubjects::ticket_subject`] answers one record, a
//! [`TicketSubject`]: `guid`, `sid`, `state`, `groups`, `tier` — the union of
//! those reads; a lighter record without the expansion would let the guard
//! count an administrator no Subject check would accept (less fail-closed
//! than before — AGENTS.md §6). Each fact comes from the function the KDC's
//! account record takes it from — `state_of` (docs/47 §4, R47-5..R47-7), the group
//! expansion (§5.3, R47-8), `subject_tier_in` (§6.3, R47-9; so the PDP's P3
//! check holds by construction, as for `ClientAccount.tier`) — over the one
//! lookup path by name in the `TicketClient` context
//! (`DirectoryView::canonical_principal`; in wave 2 it accepts exactly what
//! the AS client context accepts: the configured realm, one component, the
//! stored sAMAccountName octet for octet, a user or computer account, never
//! the krbtgt account — docs/59 §6.3; docs/47 §1.3, R47-1). Nothing else of
//! an account record is computed: no key handle, no salt or ETYPE-INFO2, no
//! account kind or armor policy, and **no name resolution**.
//!
//! # The class it closes (AGENTS.md §6.1)
//!
//! "A component obtains a capability it does not need" (Q-1047 item 1).
//! Until this module the subject checks read the KDC's account source
//! (`kdc::AccountSource`), whose records carry a resolution attested with
//! dird's attestation key — a statement keyd honours for 30 s (docs/59
//! §7.2) — that no subject check ever reads; and every directory context of
//! dird had to carry the signer, or the subject checks failed closed.
//!
//! The root change — the capability is removed from the components that
//! should not have it, and the remaining paths are made unrepresentable:
//!
//! - **The record carries none.** [`TicketSubject`] has no resolution, no
//!   key handle and no field of the KDC's records beyond the facts above;
//!   a subject check that holds one holds no statement of dird's.
//! - **The lookup cannot reach the signer.** This module computes from the
//!   one lookup path (`resolve_principal`) and the view's own fact
//!   functions only. The signer is a private field of
//!   `DirectoryContext` and the one attesting function is private to
//!   module `view` — neither can be named here (module privacy, compile
//!   time). The remaining route, the view's public `kdc::AccountSource`
//!   impl, is not named here — pinned by the source scan
//!   tests/only_the_kdc_channel_attests.rs, since Rust cannot forbid a
//!   module to call a public trait impl of its own crate.
//! - **The consumers cannot reach it.** The subject checks receive a
//!   `&dyn TicketSubjects`, whose one method answers a [`TicketSubject`];
//!   a PEP's [`crate::PepView`] hands out that trait object
//!   ([`crate::PepView::subjects`]) and no account source; crate ldap's
//!   request inputs carry no account source; and crate directory-admin no
//!   longer links crate kdc, so its code cannot even name the KDC's trait
//!   on the raw view its `checks` module holds (compile time).
//! - **dird installs the signer on the KDC channel's context only**
//!   (crates/directory-daemon `daemon::kdc_channel_context`); its admin,
//!   kpasswd, DNS and LDAP contexts are built without one, so a regression
//!   that reached `AccountSource` there would fail closed (`Failed`),
//!   never attest.
//!
//! Every failure is a [`TicketSubjectError`] — "cannot tell", which every
//! caller refuses (AGENTS.md §6: fail closed); "no such principal" is
//! `Ok(None)`.
//!
//! Spec: docs/59 §6.1-§6.4, §7.2, §7.5, §10; docs/questions/Q-1047 (A-187),
//! Q-1046 item 5, Q-1027 item 2 (A-178); docs/51 §5.3 (R51-8); docs/49
//! §3.2, §4.4 (R49-15); docs/47 §1.3 (R47-1), §4 (R47-5..R47-7), §5.3
//! (R47-8), §6.3 (R47-9), §8.1 (R47-11); Q-295 item 4 (P-22); docs/11 P3;
//! AGENTS.md §6, §6.1.

use crate::error::Fault;
use crate::groups;
use crate::resolve::LookupCtx;
use crate::view::DirectoryView;
use dtyp::{Guid, Sid};
use kdc::AccountState;
use krb_proto::{PrincipalName, Realm};
use pdp::Tier;
use std::collections::BTreeSet;

/// The facts of a ticket client's account that the subject checks read
/// (module documentation, the table): the Subject of the admin plane,
/// kpasswd and the DNS update, the LDAP session's re-check and the
/// self-lockout guard. Values, no capability: no resolution, no key handle.
/// Spec: docs/59 §6.2 (`TicketClient`); docs/51 §5.3; docs/49 §3.2, §4.4;
/// docs/questions/Q-1047 item 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketSubject {
    /// The account's objectGUID (docs/47 §2.3) — what a dual-control token
    /// names an approver by (docs/51 §5.6; crates/keyd-types
    /// `DualControlToken`).
    pub guid: Guid,
    /// The account's objectSid — the Subject's principal (docs/51 §5.3).
    pub sid: Sid,
    /// The account's state: usable at `now`, and the RFC 4120 3.3.3.1
    /// hot-list (`revoked_before`). Spec: docs/47 §4 (R47-5..R47-7).
    pub state: AccountState,
    /// Its transitive security groups (docs/47 §5.3, R47-8).
    pub groups: BTreeSet<Sid>,
    /// Its tier as a Subject — the function of `Pip::tier_of` (docs/47
    /// §6.3, R47-9; docs/11 P3).
    pub tier: Tier,
}

/// The subject lookup could not tell: the store failed, a record is
/// inconsistent, or a bound was exceeded. No data — nothing about the
/// directory can reach it. Every caller refuses (fail closed).
/// Spec: AGENTS.md §6 (fail closed; nothing an attacker could use as an
/// oracle in an error); docs/47 §8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TicketSubjectError;

impl core::fmt::Display for TicketSubjectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ticket subject lookup failed")
    }
}

impl std::error::Error for TicketSubjectError {}

impl From<Fault> for TicketSubjectError {
    /// Every internal fault is "cannot tell". Spec: AGENTS.md §6.
    fn from(_: Fault) -> TicketSubjectError {
        TicketSubjectError
    }
}

/// Where a subject check reads the client of a verified ticket from (module
/// documentation): the request's directory view in the product
/// (`DirectoryView`, or a PEP's [`crate::PepView::subjects`]); an in-memory
/// stand-in in a consumer's unit tests.
/// Spec: docs/59 §6.2, §6.4; docs/questions/Q-1047 item 1 (A-187).
pub trait TicketSubjects {
    /// The facts of the client principal (`realm`, `name`) of a ticket keyd
    /// verified, resolved in the `TicketClient` context. `Ok(None)`: no such
    /// principal (the caller refuses as for an unusable account).
    ///
    /// # Errors
    /// [`TicketSubjectError`] when the directory cannot tell.
    fn ticket_subject(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<TicketSubject>, TicketSubjectError>;
}

impl DirectoryView<'_> {
    /// [`TicketSubjects::ticket_subject`] with internal faults: the one
    /// lookup path in the `TicketClient` context, then the facts of the
    /// account it resolved — its state, its expansion and its subject tier,
    /// from the functions `ClientAccount.state`, `.groups` and `.tier` come
    /// from (one derivation each). `Ok(None)`: no such principal in that
    /// context.
    /// Spec: docs/59 §6.1, §6.2; docs/47 §1.3 (R47-1), §4, §5.3 (R47-8),
    /// §6.3 (R47-9); docs/51 §5.3.
    fn ticket_subject_facts(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<TicketSubject>, Fault> {
        let Some(resolved) = self.resolve_principal(realm, name, LookupCtx::TicketClient)? else {
            return Ok(None);
        };
        let obj = resolved.object();
        // The admitted classes are user / computer accounts (docs/59 §6.2).
        let account = self.account(obj)?.ok_or(Fault::Unavailable)?;
        let state = self.state_of(obj, &account)?;
        let groups = groups::expand(self, obj)?;
        let tier = self.subject_tier_in(self.tiers, &account.sid, &groups)?;
        Ok(Some(TicketSubject {
            guid: resolved.guid(),
            sid: account.sid,
            state,
            groups,
            tier,
        }))
    }
}

impl TicketSubjects for DirectoryView<'_> {
    /// Spec: docs/59 §6.2, §6.4; docs/47 §1.3, §4-§6.
    fn ticket_subject(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<TicketSubject>, TicketSubjectError> {
        Ok(self.ticket_subject_facts(realm, name)?)
    }
}
