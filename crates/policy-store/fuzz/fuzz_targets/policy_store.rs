#![no_main]
//! Fuzz target for the shared policy-store parser — the UNSIGNED
//! development format 2 (`policy_store::DevelopmentPolicy::decode`): the
//! size bound, the marker, the format number, ipc's bounded primitives, the
//! closed code tables, then the content rules (tier map as format 1; SIDs,
//! texts, DN components and time windows inside rules; the construction
//! refusals of the rule model, A-51; rule ids unique and clear of the
//! mandatory-FAST range).
//!
//! docs/CLEAN-ROOM.md / docs/50 §9 (R50-19: `policy_store`): arbitrary bytes →
//! decoder; never a panic, bounded allocation. Whatever decodes must
//! re-encode to exactly the input (docs/50 §3.3: "a single encoding per
//! value"; A-57: "the same discipline as the IPC codec") and give a
//! snapshot (crates/pdp: no snapshot from a refused load — so every
//! accepted file gives one).
//!
//! Spec: docs/50 §3.3, §7.2, §9; A-51; A-57; A-68.

use libfuzzer_sys::fuzz_target;
use policy_store::DevelopmentPolicy;

fuzz_target!(|data: &[u8]| {
    if let Ok(policy) = DevelopmentPolicy::decode(data) {
        let again = policy.encode().expect("a decoded policy re-encodes");
        assert_eq!(again, data, "canonical round trip");
        let snapshot = policy
            .snapshot()
            .expect("a decoded policy gives a snapshot");
        assert_eq!(snapshot.version(), policy.version);
    }
});
