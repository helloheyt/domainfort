//! The policy store dird loads at start: the shared `policy-store` crate
//! (decision A-68) — the clearly marked, UNSIGNED development format only.
//!
//! The decoder and encoder that were here (format 1, the tier map) moved to
//! crates/policy-store unchanged for the tier map, so that dird and the kdc
//! load **the same file** (docs/50 §7.2); format 2 adds the kdc's PDP rule
//! set, the anonymous allowlist and the mandatory-FAST bootstrap group,
//! which dird carries but does not use yet (the LDAP engine, task P10, will
//! decide with the same snapshot). A format-1 file is refused as superseded
//! (`PolicyError::Superseded`). What stays here is the one thing that needs
//! directory code: the `directory_pip::TierMap` the views carry (the
//! policy-store crate links no directory code, so the kdc never links the
//! store — docs/50 R50-2).
//!
//! Spec: docs/50 §3.4, §7.2; docs/47 §6.3 (R47-9); A-36; A-68;
//! docs/questions/Q-219 (A-57), Q-270 item 2.

pub use policy_store::{
    codes, read_file, DevelopmentPolicy, LoadError, MandatoryFast, PolicyError, FORMAT, MARKER,
    MAX_COMPONENT, MAX_DN_COMPONENTS, MAX_POLICY_FILE, MAX_PRINCIPALS, MAX_SUBTREES,
    SUPERSEDED_FORMAT, UNSIGNED_DEVELOPMENT_WARNING,
};

use directory_pip::TierMap;

// The DN bound of the file is directory-pip's (format 1's assertion, kept
// where both crates are linked).
const _: () = assert!(MAX_DN_COMPONENTS as usize == directory_pip::MAX_DN_DEPTH);

/// The tier map the views carry, from the policy's `SID → tier` and
/// `subtree → tier` entries.
///
/// # Errors
/// [`PolicyError::Subtree`] if directory-pip refuses the map (an empty
/// DN — already refused by [`DevelopmentPolicy::decode`] and
/// [`DevelopmentPolicy::validate`]).
///
/// Spec: docs/47 §6.3 (R47-9); A-36.
pub fn tier_map(policy: &DevelopmentPolicy) -> Result<TierMap, PolicyError> {
    TierMap::new(policy.principals.clone(), policy.subtrees.clone())
        .map_err(|_| PolicyError::Subtree)
}
