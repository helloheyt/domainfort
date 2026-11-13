#![no_main]
//! Fuzz target for dird's policy-store parser — the UNSIGNED development
//! format (`directory_daemon::policy::DevelopmentPolicy::decode`): the size
//! bound, the marker, ipc's bounded primitives, then the content rules
//! (SIDs strict and ascending, DNs non-empty printable `att=value` and
//! unique, no Untiered entry).
//!
//! AGENTS.md §6 / docs/50 §9 (R50-19: `policy_store`): arbitrary bytes →
//! decoder; never a panic, bounded allocation. Whatever decodes must
//! re-encode to exactly the input (docs/50 §3.3: "a single encoding per
//! value"; A-57: "the same discipline as the IPC codec") and give a tier
//! map.
//!
//! Spec: docs/50 §3.3, §7.2, §9; A-57; docs/questions/Q-270 item 2.

use directory_daemon::policy::DevelopmentPolicy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(policy) = DevelopmentPolicy::decode(data) {
        let again = policy.encode().expect("a decoded policy re-encodes");
        assert_eq!(again, data, "canonical round trip");
        assert!(policy.tier_map().is_ok(), "a decoded policy gives a tier map");
    }
});
