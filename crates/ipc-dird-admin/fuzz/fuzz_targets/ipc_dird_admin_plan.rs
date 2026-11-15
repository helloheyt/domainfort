#![no_main]
//! Fuzz target for the effect plan's strict decoder (task MA2):
//! `EffectPlan::decode` — the layout octet, the bounded principal and
//! effect sequences, the closed tag and code tables, every canonical rule
//! (ascending SIDs, every SID named exactly by the table, distinct effect
//! heads, non-empty sets, a changing `TierDelta`), no trailing octet — what
//! a client does with the plan bytes of a `Plan` or `RequestShown` reply
//! before it renders them.
//!
//! Arbitrary bytes → decoder; never a panic, bounded allocation; whatever
//! decodes re-encodes to exactly the input, with the same digest.
//!
//! Spec: docs/research/r5-a-admin-model.md §3.3; docs/50 §3.3, §9;
//! AGENTS.md §6 (every parser gets a fuzz target); docs/questions/Q-981.

use ipc_dird_admin::{plan_digest, EffectPlan};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(plan) = EffectPlan::decode(data) {
        let again = plan.encode().expect("a decoded plan re-encodes");
        assert_eq!(again, data, "canonical round trip");
        assert_eq!(
            plan.digest().expect("a decoded plan has a digest"),
            plan_digest(data)
        );
    }
});
