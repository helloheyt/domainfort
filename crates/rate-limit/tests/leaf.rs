//! Guard of the crate's place in the build (task DN3): rate-limit is a leaf
//! — its manifest lists no dependency of any kind, in no table (normal,
//! dev, build, or a `[target.…]` variant) — so dnsd, which must link no
//! dirstore, krb-crypto or keyd (docs/54 §4.7), can link the one limiter it
//! shares with the KDC (docs/54 §6.7). A dependency added later fails here,
//! not in dnsd's guard after the fact. The manifest is read as text (no TOML
//! crate: the leaf takes none); a positive control shows the scan sees a
//! dependency table when there is one.
//!
//! Sources: docs/54 §4.7, §6.7, §10 (DN3); AGENT-ONBOARDING §12 ("zero or
//! minimal runtime dependencies for leaf crates").

/// The `(table, line)` pairs of every entry inside a dependency table of
/// `manifest`: a table whose header names `dependencies`, whatever its
/// prefix (`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`,
/// `[target.'cfg(…)'.dependencies]`) or dotted form.
fn dependency_entries(manifest: &str) -> Vec<(String, String)> {
    let mut table = String::new();
    let mut entries = Vec::new();
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            table = line.to_owned();
            continue;
        }
        if table.contains("dependencies") {
            entries.push((table.clone(), line.to_owned()));
        }
    }
    entries
}

/// docs/54 §4.7, §6.7: the manifest holds no dependency.
#[test]
fn the_rate_limit_crate_has_no_dependency() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        manifest.contains("name = \"rate-limit\""),
        "read the wrong manifest"
    );
    let entries = dependency_entries(manifest);
    assert!(entries.is_empty(), "rate-limit depends on {entries:?}");
}

/// Positive control: the same scan finds an entry in each kind of
/// dependency table, so the guard cannot pass vacuously.
#[test]
fn the_scan_sees_every_dependency_table() {
    for table in [
        "[dependencies]",
        "[dev-dependencies]",
        "[build-dependencies]",
        "[target.'cfg(target_os = \"linux\")'.dependencies]",
    ] {
        let manifest = format!("[package]\nname = \"x\"\n\n{table}\n# note\nfoo = \"1\"\n");
        assert_eq!(
            dependency_entries(&manifest),
            vec![(table.to_owned(), "foo = \"1\"".to_owned())],
            "{table}"
        );
    }
    let dotted = "[package]\nname = \"x\"\n[dependencies.foo]\npath = \"../foo\"\n";
    assert_eq!(dependency_entries(dotted).len(), 1);
}
