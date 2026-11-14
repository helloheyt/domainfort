//! The tier-map edit — **the one implementation** both policy-change paths
//! use (docs/51 §5.10, R51-21; decision A-80 on docs/questions/Q-299):
//!
//! * the offline path, `provision policy` (root, with dird and kdc stopped —
//!   option (a)), which decodes the installed file, applies the edit and
//!   installs the result;
//! * the online path (option (b), task A16): `PolicyAdmin` through admind
//!   under dual control, where dird applies **this same edit** to the policy
//!   it loaded and writes the result as `policy.next` for root to activate.
//!
//! Before task A16 the edit lived in crates/provision; dird's online path
//! would have needed a second copy, and two implementations of one rule
//! drift apart (docs/52 C14, the lesson of R13: "a write invariant enforced
//! in only one of the write paths"). Here there is one vocabulary
//! ([`TierChange`]), one edit ([`edit_tier_map`]) and one rule for what a
//! file reachable by the edit looks like ([`check_tier_map_successor`]) —
//! the rule root's activation applies to a `policy.next` it did not write
//! (docs/questions/Q-590).
//!
//! # The edit
//!
//! Add / remove `SID → tier` and `subtree → tier` rows, in order; bump
//! `policy_version` by one; encode (the format's own content rules run
//! again, [`DevelopmentPolicy::encode`]). Refused: no change, an add of a row
//! already present (an edit says what it replaces), a remove of a row
//! absent, an edit that leaves no Tier0 principal in the map
//! (docs/questions/Q-379: no administrator could be Tier0 any more), a
//! version overflow, and whatever the format refuses (an Untiered row, an
//! invalid DN, a bound).
//!
//! # The successor rule
//!
//! A file `next` is a tier-map successor of the installed file `current`
//! exactly when the edit could have produced it from `current`:
//! `next.version = current.version + 1`; the rule set, the anonymous
//! allowlist and the mandatory-FAST entry are **unchanged**; and the map
//! still has a Tier0 principal. Nothing else is expressible by the edit, so
//! a `policy.next` that changes anything else did not come from it and is
//! refused at activation (fail closed).
//!
//! # The spelling
//!
//! [`TierChange`]'s `Display` is the command-line spelling of `provision
//! policy` (`--add-principal <SID> <TierN>`, `--remove-principal <SID>`,
//! `--add-subtree <TierN> <att=value> …`, `--remove-subtree <att=value> …`) —
//! the same vocabulary in the operator's command, in dird's audit record of
//! an online change, and in root's activation report. SIDs and DNs are not
//! secret (docs/47 §2.3).
//!
//! Spec: docs/51 §5.10 (R51-21), §5.2 row 13; docs/06 §9; A-36; A-69 (the
//! version every view compares); A-80; docs/52 §3.14 (C14); docs/questions
//! Q-299, Q-379, Q-590.

use core::fmt;

use dtyp::Sid;
use pdp::{Dn, PolicyVersion, Tier};

use crate::policy::{DevelopmentPolicy, PolicyError};

/// One tier-map edit.
/// Spec: docs/51 §5.10 ("add / remove rows of the map"); A-36; A-80.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TierChange {
    /// Add `SID → tier`.
    AddPrincipal(Sid, Tier),
    /// Remove the row of this SID.
    RemovePrincipal(Sid),
    /// Add `subtree → tier`.
    AddSubtree(Dn, Tier),
    /// Remove the row of this subtree.
    RemoveSubtree(Dn),
}

/// The command-line name of a map tier (`Untiered` is never a map row; it
/// is spelled for completeness and refused by the edit).
/// Spec: crates/pdp `Tier`; this module's documentation ("the spelling").
fn tier_name(tier: Tier) -> &'static str {
    match tier {
        Tier::Tier0 => "Tier0",
        Tier::Tier1 => "Tier1",
        Tier::Tier2 => "Tier2",
        Tier::Untiered => "Untiered",
    }
}

/// The RDN components of a DN, leaf first, separated by single spaces (one
/// command-line argument each).
fn components(f: &mut fmt::Formatter<'_>, dn: &Dn) -> fmt::Result {
    for (index, component) in dn.rdns().iter().enumerate() {
        if index > 0 {
            f.write_str(" ")?;
        }
        f.write_str(component)?;
    }
    Ok(())
}

impl fmt::Display for TierChange {
    /// The command-line spelling of `provision policy` (module
    /// documentation, "the spelling").
    /// Spec: crates/provision cli.rs (`<change>`); [MS-DTYP] 2.4.2.1 (the
    /// SID string form, through dtyp).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TierChange::AddPrincipal(sid, tier) => write!(
                f,
                "--add-principal {} {}",
                sid.to_sid_string(),
                tier_name(*tier)
            ),
            TierChange::RemovePrincipal(sid) => {
                write!(f, "--remove-principal {}", sid.to_sid_string())
            }
            TierChange::AddSubtree(dn, tier) => {
                write!(f, "--add-subtree {} ", tier_name(*tier))?;
                components(f, dn)
            }
            TierChange::RemoveSubtree(dn) => {
                f.write_str("--remove-subtree ")?;
                components(f, dn)
            }
        }
    }
}

/// Why a tier-map edit was refused. Fixed text.
/// Spec: this module's documentation ("the edit").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditError {
    /// No change was given.
    NoChange,
    /// The SID already has a row (remove it first: an edit says what it
    /// replaces).
    PrincipalPresent,
    /// The SID has no row.
    PrincipalAbsent,
    /// The subtree already has a row.
    SubtreePresent,
    /// The subtree has no row.
    SubtreeAbsent,
    /// The edit would leave no Tier0 principal in the map (no
    /// administrator could be Tier0 any more — docs/questions/Q-379).
    NoTier0Principal,
    /// `policy_version` would overflow.
    VersionOverflow,
    /// The policy format refused the result (an Untiered row, an invalid
    /// DN, a bound).
    Refused(PolicyError),
}

impl fmt::Display for EditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditError::NoChange => f.write_str("no tier-map change given"),
            EditError::PrincipalPresent => f.write_str("the SID already has a tier-map row"),
            EditError::PrincipalAbsent => f.write_str("the SID has no tier-map row"),
            EditError::SubtreePresent => f.write_str("the subtree already has a tier-map row"),
            EditError::SubtreeAbsent => f.write_str("the subtree has no tier-map row"),
            EditError::NoTier0Principal => {
                f.write_str("the edit would leave no Tier0 principal in the tier map")
            }
            EditError::VersionOverflow => f.write_str("policy_version would overflow"),
            EditError::Refused(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EditError {}

/// Whether the map has at least one Tier0 principal (docs/questions/Q-379).
fn has_tier0_principal(policy: &DevelopmentPolicy) -> bool {
    policy.principals.values().any(|tier| *tier == Tier::Tier0)
}

/// The version after `version`, or `None` on overflow.
fn next_version(version: PolicyVersion) -> Option<PolicyVersion> {
    version.0.checked_add(1).map(PolicyVersion)
}

/// Apply `changes` in order to `policy`, bump the version by one, and
/// return the new policy with its file encoding (module documentation, "the
/// edit").
///
/// # Errors
/// [`EditError`].
///
/// Spec: docs/51 §5.10 (R51-21); A-80; A-69 (the version every view
/// compares); [`DevelopmentPolicy::encode`] (the format's content rules);
/// docs/questions/Q-379.
pub fn edit_tier_map(
    policy: &DevelopmentPolicy,
    changes: &[TierChange],
) -> Result<(DevelopmentPolicy, Vec<u8>), EditError> {
    if changes.is_empty() {
        return Err(EditError::NoChange);
    }
    let mut next = policy.clone();
    for change in changes {
        match change {
            TierChange::AddPrincipal(sid, tier) => {
                if next.principals.insert(*sid, *tier).is_some() {
                    return Err(EditError::PrincipalPresent);
                }
            }
            TierChange::RemovePrincipal(sid) => {
                if next.principals.remove(sid).is_none() {
                    return Err(EditError::PrincipalAbsent);
                }
            }
            TierChange::AddSubtree(dn, tier) => {
                if next.subtrees.iter().any(|(d, _)| d == dn) {
                    return Err(EditError::SubtreePresent);
                }
                next.subtrees.push((dn.clone(), *tier));
            }
            TierChange::RemoveSubtree(dn) => {
                let before = next.subtrees.len();
                next.subtrees.retain(|(d, _)| d != dn);
                if next.subtrees.len() == before {
                    return Err(EditError::SubtreeAbsent);
                }
            }
        }
    }
    if !has_tier0_principal(&next) {
        return Err(EditError::NoTier0Principal);
    }
    next.version = next_version(policy.version).ok_or(EditError::VersionOverflow)?;
    let file = next.encode().map_err(EditError::Refused)?;
    Ok((next, file))
}

/// Why a file is not a tier-map successor of the installed one (module
/// documentation, "the successor rule"). Fixed text.
/// Spec: docs/51 §5.10; A-69; docs/questions/Q-590.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuccessorError {
    /// Its version is not the installed version plus one (an older, equal
    /// or skipped version).
    Version,
    /// Its rule set, anonymous allowlist or mandatory-FAST entry differs
    /// from the installed file's: the tier-map edit cannot express that.
    NotATierMapEdit,
    /// Its map has no Tier0 principal (docs/questions/Q-379).
    NoTier0Principal,
}

impl fmt::Display for SuccessorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SuccessorError::Version => "its policy_version is not the installed version plus one",
            SuccessorError::NotATierMapEdit => {
                "it changes more than the tier map (rules, anonymous allowlist or mandatory FAST)"
            }
            SuccessorError::NoTier0Principal => "its tier map has no Tier0 principal",
        })
    }
}

impl std::error::Error for SuccessorError {}

/// Whether `next` is a tier-map successor of `current` (module
/// documentation, "the successor rule"): exactly what [`edit_tier_map`] can
/// produce from `current`, by one version.
///
/// # Errors
/// [`SuccessorError`], in the order: version, the parts the edit never
/// touches, the Tier0 principal.
///
/// Spec: docs/51 §5.10 (the online path's `policy.next`, version + 1);
/// A-69; A-80; docs/questions/Q-379, Q-590.
pub fn check_tier_map_successor(
    current: &DevelopmentPolicy,
    next: &DevelopmentPolicy,
) -> Result<(), SuccessorError> {
    if next_version(current.version) != Some(next.version) {
        return Err(SuccessorError::Version);
    }
    if next.rules != current.rules
        || next.anonymous != current.anonymous
        || next.mandatory_fast != current.mandatory_fast
    {
        return Err(SuccessorError::NotATierMapEdit);
    }
    if !has_tier0_principal(next) {
        return Err(SuccessorError::NoTier0Principal);
    }
    Ok(())
}

/// The rows `next` has and `current` does not ("added") and the rows
/// `current` has and `next` does not ("removed"), as changes in the edit's
/// vocabulary: what root's activation reports. A row whose tier changed is
/// a removal and an addition.
/// Spec: this module's documentation ("the spelling"); docs/51 §5.10.
#[must_use]
pub fn tier_map_difference(
    current: &DevelopmentPolicy,
    next: &DevelopmentPolicy,
) -> Vec<TierChange> {
    let mut changes = Vec::new();
    for (sid, tier) in &current.principals {
        if next.principals.get(sid) != Some(tier) {
            changes.push(TierChange::RemovePrincipal(*sid));
        }
    }
    for (dn, tier) in &current.subtrees {
        if !next.subtrees.iter().any(|(d, t)| d == dn && t == tier) {
            changes.push(TierChange::RemoveSubtree(dn.clone()));
        }
    }
    for (sid, tier) in &next.principals {
        if current.principals.get(sid) != Some(tier) {
            changes.push(TierChange::AddPrincipal(*sid, *tier));
        }
    }
    for (dn, tier) in &next.subtrees {
        if !current.subtrees.iter().any(|(d, t)| d == dn && t == tier) {
            changes.push(TierChange::AddSubtree(dn.clone(), *tier));
        }
    }
    changes
}
