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
//! Task PN11 adds the inventory of the four doors to a key set's keys
//! (crate store, "The doors"): which file uses `bound_by`,
//! `ticket_granting`, `accepting` and `bound_to`, so "`bound_to` leaves the
//! issuance path" (docs/59 §10, the PN11 row) stays true.
//!
//! Source: docs/52 §3.5 ("operations in which the name is not an input …
//! receive a separate, declared accessor, so that every access is marked"),
//! §7 R7; docs/questions/Q-040 (A-19), Q-521; docs/59 §7.2; docs/questions/
//! Q-1011 items 4, 6 (A-173).

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

/// The doors to a stored key set's keys and the files that use each (task
/// PN11; crate store, "The doors"): (source file, door, call sites).
/// Issuance reaches a client or service key only through `bound_by` (dird's
/// verified name resolution), the krbtgt only through `ticket_granting`
/// (its exact TGS name), the acceptor only through `accepting` (the
/// namespace key); `bound_to` — a compare of a caller-supplied name — is
/// left only to `set_secret` on an existing set, never to an issuance.
/// A new use of a door, or a new door, must be listed here (visible in
/// review) or this test fails.
const DOORS: &[(&str, &str, usize)] = &[
    // issue_as_rep: the client key set; the change-password service's.
    ("as_exchange.rs", "bound_by", 2),
    // issue_as_rep: the krbtgt that seals a TGT.
    ("as_exchange.rs", "ticket_granting", 1),
    // issue_tgs_rep: the service key set.
    ("tgs_exchange.rs", "bound_by", 1),
    // open_local_tgt: the krbtgt that opens a TGT or an armor ticket.
    ("tgs_exchange.rs", "ticket_granting", 1),
    // verify_service_ap_req: the acceptor.
    ("service_ticket.rs", "accepting", 1),
    // set_secret on an existing set: the request's own binding.
    ("directory.rs", "bound_to", 1),
];

/// The doors scanned for.
const DOOR_NAMES: [&str; 4] = ["bound_by", "ticket_granting", "accepting", "bound_to"];

/// The call sites of each door (`.<door>(`) in the product source of `src/`
/// outside the store module: comment lines skipped, and each file read up
/// to its `#[cfg(test)] mod tests` (unit tests may call any door).
fn door_call_sites() -> BTreeMap<(String, String), usize> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sites = BTreeMap::new();
    for entry in fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        if !file.ends_with(".rs") || file == "store.rs" {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let product = text
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or_default();
        for line in product.lines() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for door in DOOR_NAMES {
                let count = code.matches(&format!(".{door}(")).count();
                if count > 0 {
                    *sites.entry((file.clone(), door.to_owned())).or_insert(0) += count;
                }
            }
        }
    }
    sites
}

/// Task PN11 (docs/59 §7.2, §10 the PN11 row: "`bound_to` leaves the
/// issuance path"; docs/questions/Q-1011 items 4, 6): the doors are used
/// exactly where listed — positive control: the scan finds every listed
/// site, so it cannot pass vacuously.
#[test]
fn keys_are_reached_only_through_the_listed_doors() {
    let found = door_call_sites();
    let listed: BTreeMap<(String, String), usize> = DOORS
        .iter()
        .map(|(file, door, count)| (((*file).to_owned(), (*door).to_owned()), *count))
        .collect();
    assert!(
        !found.is_empty(),
        "the scan found no site: it reads nothing"
    );
    assert_eq!(
        found, listed,
        "a door to a stored key was used, moved or removed: an issuance \
         reaches a client or service key only through `bound_by` (dird's \
         verified resolution) — list any other use here, with its reason"
    );
}
