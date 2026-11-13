#![no_main]
//! Fuzz target for ad-schema's string inputs: `make_attid` (an OID string,
//! [MS-DRSR] 5.16.4 over X.690 8.19) and the lDAPDisplayName lookups.
//!
//! AGENTS.md §6 requires a fuzz target for every parser before it merges to
//! `main`. Any input must fail closed (`OidError` / `None`) without a
//! panic, hang or over-allocation. When `make_attid` accepts an OID, its
//! result is a prefix-table ATTRTYP: the upper word is one of the
//! NewPrefixTable() indexes (at most 26) and the value is below
//! 0x8000_0000 ([MS-ADTS] 3.1.1.2.6: the prefix-table range).
//!
//! Not built or run: the fuzz dependencies await owner approval (P-1).
//!
//! Spec: [MS-DRSR] 5.16.4; X.690 8.19; [MS-ADTS] 3.1.1.2.6; docs/46 §3.3.

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn schema() -> &'static ad_schema::Phase1Schema {
    static SCHEMA: OnceLock<ad_schema::Phase1Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| ad_schema::phase1().expect("the phase-1 schema builds"))
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(attrtyp) = ad_schema::make_attid(s) {
        assert!(attrtyp >> 16 <= 26, "upper word is a NewPrefixTable() index");
        assert!(attrtyp < 0x8000_0000, "prefix-table ATTRTYP range");
    }
    let p1 = schema();
    if let Some(id) = p1.attribute_by_name(s) {
        assert!(p1.attribute(id).is_some());
    }
    if let Some(id) = p1.class_by_name(s) {
        assert!(p1.class(id).is_some());
    }
});
