//! The inventory of keyd's declared unbound key uses (task R7; docs/52
//! §3.5, class C5).
//!
//! Inside keyd a stored key is reachable only through the proof of its name
//! binding (`StoredKeySet::bound_to`) or through
//! `StoredKeySet::unbound_current`, which names a closed `UnboundUse` — the
//! declared uses in which the principal's name is not an input (crate
//! store). The first is enforced by the compiler (the raw accessors are
//! private to the store module). The second is a declaration, so this test
//! pins where it is made: a new unbound use must add a variant (with the
//! reason A-19 holds without the check) **and** a line here — both visible
//! in review — or this test fails.
//!
//! A source scan of `src/` at test time (the precedent is directory-admin's
//! `tests/single_write_path.rs`, A-106), with a positive control: the scan
//! must find exactly the known sites, so it cannot pass vacuously.
//!
//! Source: docs/52 §3.5 ("operations in which the name is not an input …
//! receive a separate, declared accessor, so that every access is marked"),
//! §7 R7; docs/questions/Q-040 (A-19), Q-521.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// The declared unbound uses: (source file, `UnboundUse` variant) → how
/// many call sites.
const DECLARED: &[(&str, &str, usize)] = &[
    // verify_preauth: PA-ENC-TIMESTAMP and the encrypted challenge; the
    // proof is bound to the handle and issue_as_rep binds the name.
    ("as_exchange.rs", "Preauthentication", 2),
    // verify_secret: compares, issues nothing; no role holds it (R4).
    ("directory.rs", "SecretComparison", 1),
];

/// The call sites of `unbound_current(` in `src/` outside the store
/// module, by (file, variant), comment lines skipped.
fn unbound_call_sites() -> BTreeMap<(String, String), usize> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sites = BTreeMap::new();
    for entry in fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        if !file.ends_with(".rs") || file == "store.rs" {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        for line in text.lines() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            let Some(at) = code.find("unbound_current(") else {
                continue;
            };
            let rest = &code[at..];
            let variant = rest
                .split("UnboundUse::")
                .nth(1)
                .map(|tail| {
                    tail.chars()
                        .take_while(char::is_ascii_alphanumeric)
                        .collect::<String>()
                })
                .unwrap_or_default();
            *sites.entry((file.clone(), variant)).or_insert(0) += 1;
        }
    }
    sites
}

/// R7: the unbound key uses are exactly the declared ones (positive
/// control: the scan finds every declared site, so it is not vacuous).
#[test]
fn unbound_key_uses_are_exactly_the_declared_ones() {
    let found = unbound_call_sites();
    let declared: BTreeMap<(String, String), usize> = DECLARED
        .iter()
        .map(|(file, variant, count)| (((*file).to_owned(), (*variant).to_owned()), *count))
        .collect();
    assert!(
        !found.is_empty(),
        "the scan found no site: it reads nothing"
    );
    assert_eq!(
        found, declared,
        "an unbound key use was added, moved or removed: declare it (crate \
         store `UnboundUse`, with where A-19 holds instead) and list it here"
    );
}
