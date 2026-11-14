#![no_main]
//! Fuzz target for `provision-manifest`, the strict provisioning-manifest
//! parser.
//!
//! AGENTS.md §6 (every parser gets a fuzz target before it merges to
//! main); docs/50 §9 (fuzz targets in detached workspaces until P-1). On
//! any octets `Manifest::parse` must return without panicking, and:
//!
//! * input over the size bound, or not ending in LF, is refused (docs/50
//!   §7.1);
//! * an error names, at most, a key of the closed table — never input text
//!   (AGENTS.md §6; A-60);
//! * an accepted manifest came from printable ASCII and LF only (docs/50
//!   §7.1; P-6);
//! * an accepted manifest encodes to text that parses back to the same
//!   manifest, and that text is a fixed point of encode ∘ parse (one
//!   canonical spelling);
//! * an accepted manifest has 2 ..= 8 first administrators and no two
//!   objects with the same GUID (docs/51 §4.3 steps 2, 8; Q-295);
//! * the line layer is crates/config's (task F7, A-86 follow-up): input the
//!   manifest accepts is accepted by `config::line_format` over the
//!   manifest's table, and input the line layer refuses is refused by the
//!   manifest at the same line and key.
//!
//! Spec: docs/51 §4.3 step 8; docs/50 R50-15, §7.1, §9; A-86.

use libfuzzer_sys::fuzz_target;
use provision_manifest::limits::{MAX_FILE_OCTETS, MAX_FIRST_ADMINS, MIN_FIRST_ADMINS};
use provision_manifest::Manifest;

fuzz_target!(|data: &[u8]| {
    let result = Manifest::parse(data);
    match config::line_format::Entries::parse(data, Manifest::KEYS) {
        Ok(_) => {}
        Err(line) => {
            let err = result.as_ref().expect_err("the line layer refused it");
            assert_eq!(err.line(), line.line());
            assert_eq!(err.key(), line.key());
        }
    }
    let cut = !data.is_empty() && data.last() != Some(&b'\n');
    if data.len() > MAX_FILE_OCTETS || cut {
        assert!(result.is_err(), "bound and final LF enforced");
    }
    match result {
        Err(err) => {
            if let Some(key) = err.key() {
                assert!(
                    Manifest::KEYS.contains(&key),
                    "error key comes from the table"
                );
            }
        }
        Ok(manifest) => {
            assert!(config::line_format::Entries::parse(data, Manifest::KEYS).is_ok());
            assert!(data
                .iter()
                .all(|&b| b == b'\n' || (0x20..=0x7E).contains(&b)));
            let text = manifest.encode();
            let again = Manifest::parse(text.as_bytes()).expect("encoder output parses");
            assert_eq!(again, manifest, "encode/parse round trip");
            assert_eq!(again.encode(), text, "canonical text is a fixed point");
            let admins = manifest.first_admins();
            assert!((MIN_FIRST_ADMINS..=MAX_FIRST_ADMINS).contains(&admins.len()));
            let mut handles = vec![
                manifest.krbtgt().handle,
                manifest.ldap_service().handle,
                manifest.admin_service().handle,
            ];
            handles.extend(admins.iter().map(|a| a.key_set().handle));
            for (i, h) in handles.iter().enumerate() {
                assert!(handles[..i].iter().all(|o| o.principal != h.principal));
            }
        }
    }
});
