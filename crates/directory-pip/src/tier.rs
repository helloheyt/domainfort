//! The tier map (docs/47 §6.3, R47-9; Q-117 / A-36).
//!
//! "Tier" is a project concept (docs/06 §10; not found in the opened
//! specification sections). Its source of truth is policy data: a map
//! `SID → Tier` and `DN subtree → Tier`, which lives in the signed,
//! versioned policy store (docs/06 §9, D17) and is changed only by
//! POLICY_ADMIN (tier-0). That store does not exist yet: the caller passes
//! the map in with each view, taken from the same policy version as the
//! request's `PolicySnapshot`. **Follow-up:** verify the policy store's
//! signature over the map before it reaches this crate (D17); until then
//! the map is trusted as given by the caller.
//!
//! The structural rules that need no map are applied on top, in the view:
//! a DC account (userAccountControl ST), the krbtgt account (RID 502) and
//! the domain root are Tier0.
//!
//! Subtree entries carry a tier, not only Tier0: A-36 decides that an
//! unclassified resource is Tier0 for writes "so an administrator must
//! classify an OU to let a lower tier write in it", which needs a
//! lower-tier classification of a subtree (recorded as an interpretation in
//! docs/questions/Q-135). Where several entries apply, the most privileged
//! (the minimum, `Tier0 < Tier1 < Tier2 < Untiered`) wins — never less
//! strict than any single entry.
//!
//! Spec: docs/47 §6.3 (R47-9); docs/06 §9, §10; docs/11 §1 (tier "derived
//! from membership by the PIP — not claimed"); Q-117 (A-36); Q-135.

use crate::error::ViewError;
use dtyp::Sid;
use pdp::{Dn, Tier};
use std::collections::BTreeMap;

/// The tier map of one policy version (module docs).
/// Spec: docs/47 §6.3 (R47-9); A-36.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TierMap {
    principals: BTreeMap<Sid, Tier>,
    subtrees: Vec<(Dn, Tier)>,
}

impl TierMap {
    /// A map with no entry: every subject is `Untiered`, every directory
    /// object that no structural rule classifies is Tier0 for writes.
    #[must_use]
    pub fn empty() -> TierMap {
        TierMap::default()
    }

    /// Build a map from its `SID → Tier` entries and its `DN subtree → Tier`
    /// entries (DNs in the directory's own canonical form, see
    /// [`crate::DirectoryView::dn_of`]). A subtree with no RDN component
    /// would classify the whole directory: refused (fail closed).
    /// Spec: docs/47 §6.3; A-36.
    pub fn new(
        principals: BTreeMap<Sid, Tier>,
        subtrees: Vec<(Dn, Tier)>,
    ) -> Result<TierMap, ViewError> {
        if subtrees.iter().any(|(dn, _)| dn.rdns().is_empty()) {
            return Err(ViewError::TierMap);
        }
        Ok(TierMap {
            principals,
            subtrees,
        })
    }

    /// The most privileged tier the map gives to any of `sids`, if any.
    /// Spec: docs/47 §6.3 ("the minimum ... over the map values for
    /// {p} ∪ g").
    pub(crate) fn principal_tier<'s>(
        &self,
        sids: impl IntoIterator<Item = &'s Sid>,
    ) -> Option<Tier> {
        sids.into_iter()
            .filter_map(|s| self.principals.get(s).copied())
            .min()
    }

    /// The most privileged tier of the subtrees that contain `dn`, if any.
    /// Spec: docs/47 §6.3 ("DN subtree → Tier0"); A-36; pdp `Dn::is_within`.
    pub(crate) fn subtree_tier(&self, dn: &Dn) -> Option<Tier> {
        self.subtrees
            .iter()
            .filter(|(base, _)| dn.is_within(base))
            .map(|(_, tier)| *tier)
            .min()
    }
}

/// The most privileged of two optional classifications.
pub(crate) fn most_privileged(a: Option<Tier>, b: Option<Tier>) -> Option<Tier> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}
