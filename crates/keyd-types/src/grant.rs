//! The arguments and bounds of `grant_set_secret`: the one-time grant
//! without which keyd refuses Role::Directory's `set_secret` (task A15a).
//!
//! # Why (docs/51 §5.8; docs/questions/Q-291, decided A-74)
//!
//! keyd checks a caller's role, a handle's purpose and the key set's binding
//! — not whether dird's PDP allowed the password set. Without a grant,
//! admind (Role::Directory) could set any account's secret on its own, and
//! so was equivalent to tier-0 (A-74's phase-1 residual). Option (b): after
//! dird's PDP allowed a `BeginPasswordSet` and the write committed, dird
//! (Role::Ldap) registers in keyd a grant for exactly the key targets it
//! returned; keyd's `set_secret` from Role::Directory is refused unless a
//! matching, unexpired grant exists, and consumes it.
//!
//! # What a grant holds
//!
//! One entry per key target — a handle and the binding the `set_secret`
//! must name — with the expiry keyd computed from its own clock and the
//! caller's lifetime (never a time from the caller, docs/50 R50-5). A
//! computer's two key targets (docs/47 §9.1) are registered by **one**
//! call, both or neither, and each is consumed by its own `set_secret`
//! (docs/questions/Q-450 item 2).
//!
//! # Who may register one
//!
//! * **Role::Ldap** (dird): any account kind, lifetime at most
//!   [`MAX_SET_SECRET_GRANT_SECS`].
//! * **Role::Admin** (keyadm's ceremony, docs/51 §4.3 step 11): the
//!   provisioning manifest's first administrators, before dird exists —
//!   user accounts only, only for a key set that does not exist yet (an
//!   **initial** secret: never a replacement of a password, which only
//!   dird's PDP may allow), lifetime at most [`MAX_INITIAL_SECRET_GRANT_SECS`]
//!   (docs/questions/Q-451).
//!
//! Spec: docs/51 §4.3 steps 11-12, §5.2 row 5, §5.8, §7.3, §9; docs/47
//! §9.1, §9.2; docs/10 §2, §6, §8; docs/questions/Q-291 (A-74), Q-450,
//! Q-451.

use crate::authz::Role;
use crate::model::{KeyHandle, PrincipalBinding};

/// Which account a grant is for: the `kind` dird's `BeginPasswordSet`
/// answers (docs/51 §7.3: "`kind` (User/Computer)").
///
/// keyd uses it only to check the shape of the targets: a user has exactly
/// one key target (its `PrincipalLongterm` key set); a computer has its
/// `PrincipalLongterm` key set and, when it has a service principal name,
/// its `Service` key set (docs/47 §9.1; crates/directory-admin
/// `password_targets`).
///
/// Spec: docs/51 §5.2 row 5, §7.3; docs/47 §9.1; docs/questions/Q-450
/// item 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountKind {
    /// A user account: one key target.
    User,
    /// A computer account: one or two key targets.
    Computer,
}

/// One key target of a grant: the handle `set_secret` will name and the
/// binding it must name with it. Not secret.
///
/// Spec: docs/51 §7.3 ("handles (1 or 2), bindings"); docs/10 §6
/// (`set_secret(principal, purpose, …)`, with the binding of A-19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetSecretTarget {
    /// The key set's handle.
    pub handle: KeyHandle,
    /// The principal name the `set_secret` must name, octet for octet.
    pub binding: PrincipalBinding,
}

/// Most key targets one grant names: a computer's `PrincipalLongterm` and
/// `Service` key sets (docs/47 §9.1).
/// Spec: docs/51 §5.2 row 5 ("`set_secret` ×1 (user) / ×2 (computer)").
pub const MAX_GRANT_TARGETS: usize = 2;

/// The longest lifetime, in seconds, of a grant registered by Role::Ldap
/// (dird): 30 s.
///
/// dird registers the grant right before it answers `BeginPasswordSet`;
/// admind then sends at most two `set_secret` calls at once, each within
/// the keyd client's 2 s deadline (docs/50 §3.6) — about 4 s plus the
/// reply's way back in the worst case. 30 s leaves a margin of more than
/// seven times that, and equals keyd's own default lifetime of a one-time
/// token (`KeydConfig::token_lifetime_secs`, docs/10 D36: "short
/// (seconds)"). Project choice (docs/questions/Q-450 item 3).
pub const MAX_SET_SECRET_GRANT_SECS: u32 = 30;

/// The longest lifetime, in seconds, of a grant registered by Role::Admin
/// (keyadm's ceremony): 900 s (15 minutes).
///
/// Between the ceremony (docs/51 §4.3 step 11) and `provision
/// first-admin-secret` (step 12) the operator starts the next command and
/// may type every first administrator's password twice at a terminal
/// (docs/51 §4.4 source (a); 2 to 8 administrators). Only initial secrets
/// of user accounts can be granted by Admin, and admind does not run yet
/// during provisioning. Project choice (docs/questions/Q-451 item 3).
pub const MAX_INITIAL_SECRET_GRANT_SECS: u32 = 900;

/// How many key targets keyd's grant table holds at once (live or not yet
/// swept): 64. Grants are human-paced (one admin operation at a time in
/// dird's admin thread, docs/51 §7.5) and short-lived; the ceremony grants
/// at most eight first administrators. A full table refuses a new grant
/// (fail closed) — it never evicts a live one. Project choice
/// (docs/questions/Q-450 item 4).
pub const MAX_SET_SECRET_GRANTS: usize = 64;

/// The longest grant lifetime `role` may ask for, or `None` for a role that
/// may not register grants.
///
/// The match is exhaustive: a new role does not compile until it is decided
/// here.
///
/// Spec: docs/questions/Q-450 item 3, Q-451 item 3.
#[must_use]
pub const fn max_grant_lifetime_secs(role: Role) -> Option<u32> {
    match role {
        Role::Ldap => Some(MAX_SET_SECRET_GRANT_SECS),
        Role::Admin => Some(MAX_INITIAL_SECRET_GRANT_SECS),
        Role::Kdc | Role::Directory => None,
    }
}

// Every role that may register a grant has a lifetime ceiling, and no other
// role has one (docs/10 §2, the capability table).
const _: () = {
    let roles = [Role::Kdc, Role::Directory, Role::Admin, Role::Ldap];
    let mut i = 0;
    while i < roles.len() {
        let permitted =
            crate::authz::role_permits(roles[i], crate::authz::Operation::GrantSetSecret);
        assert!(permitted == max_grant_lifetime_secs(roles[i]).is_some());
        i += 1;
    }
    assert!(MAX_SET_SECRET_GRANT_SECS > 0);
    assert!(MAX_SET_SECRET_GRANT_SECS <= MAX_INITIAL_SECRET_GRANT_SECS);
    assert!(MAX_SET_SECRET_GRANTS >= MAX_GRANT_TARGETS);
};
