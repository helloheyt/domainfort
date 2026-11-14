//! Guard of docs/52 R15 (class C18, "a product API exposes a test seam";
//! docs/questions/Q-570): the daemons' test seams exist only in test builds
//! and no product path names them.
//!
//! Each daemon with seams (keyd-daemon, kdc-daemon, directory-daemon,
//! admin-daemon, ldap-front) keeps every value its production start path
//! never takes from the configuration — queue capacities, audit windows,
//! bounded waits, extra listeners, clocks, connectors, links, verifiers, an
//! already-opened store — out of its product parameters; the alternatives
//! live only in its module `test_seams`, declared
//! `#[cfg(feature = "test-seams")] #[doc(hidden)]`. auditd has **no** seam
//! left: its shape↔source binding table and connection quota are not
//! parameters at all (R15, after task R9b gave every test sender its own
//! listener). dirstore's path-taking `Store::open` (A-113) is gated by the
//! same feature. This test checks the things that keep that true by
//! construction in a product build:
//!
//! 1. every daemon with seams declares `test_seams` behind the feature, and
//!    its own `[features]` table has `test-seams = []`, outside `default`;
//!    dirstore's `Store::open` carries `#[cfg(feature = "test-seams")]`;
//!    auditd has neither the module nor the feature;
//! 2. no `Cargo.toml` of the workspace enables `test-seams` anywhere but in
//!    a `[dev-dependencies]` table (cargo's resolver 2 — `resolver = "2"` in
//!    the workspace manifest, checked here too — activates a dev-dependency's
//!    features only in builds of test targets, so `cargo build` of a daemon
//!    has no `test_seams` module and no product source could compile
//!    against one);
//! 3. no non-test source of the workspace (`crates/*/src`, every `main.rs`
//!    and start-up path included) names `test_seams` in code, except the
//!    declaration itself — so a test build, in which the module does exist,
//!    gives no product path a seam either.
//!
//! Comments are not code: `//` comments in sources and `#` comments in
//! manifests are skipped. Files under a `tests/` directory and files named
//! `tests.rs` / `*_tests.rs` are test code and not scanned. Positive
//! controls check that each scan finds what it must and would see a planted
//! violation.
//!
//! Source: docs/52 §3.18, §7 R15; AGENTS.md §6.1 ("a single chokepoint";
//! "removing the capability from the component that should not have it");
//! the precedent crates/directory-admin `tests/single_write_path.rs` (R13)
//! and crates/ipc-keyd-server's `loopback` feature (docs/questions/Q-500).
//! Test-only.

use std::path::{Path, PathBuf};

/// The daemon crates whose test seams live in their `test_seams` module
/// (docs/52 §3.18).
const DAEMONS: [&str; 5] = [
    "keyd-daemon",
    "kdc-daemon",
    "directory-daemon",
    "admin-daemon",
    "ldap-front",
];

/// The crates that declare the feature: the daemons above and dirstore (its
/// path-taking `Store::open`, A-113).
const DECLARING: [&str; 6] = [
    "keyd-daemon",
    "kdc-daemon",
    "directory-daemon",
    "admin-daemon",
    "ldap-front",
    "dirstore",
];

/// The feature name.
const FEATURE: &str = "test-seams";

/// The module name.
const MODULE: &str = "test_seams";

/// The workspace's `crates/` directory.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ directory")
        .to_path_buf()
}

/// Every crate directory with a manifest.
fn crate_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(crates_dir())
        .expect("readable crates/")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();
    dirs.sort();
    dirs
}

/// Every `.rs` file below `dir`, recursively, without test code
/// (directories named `tests`, files named `tests.rs` or `*_tests.rs`).
fn product_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = read.map(|e| e.expect("entry").path()).collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "tests" {
                product_sources(&path, out);
            }
        } else if name.ends_with(".rs") && name != "tests.rs" && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

/// The lines of `text` that name the module in code (outside `//`
/// comments): `(line number, code)`.
fn mentions(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter_map(|(n, line)| {
            let code = line.split("//").next().unwrap_or("");
            code.contains(MODULE)
                .then(|| (n + 1, code.trim().to_owned()))
        })
        .collect()
}

/// A manifest's lines without `#` comments, each with the table it is in.
fn manifest_lines(text: &str) -> Vec<(String, String)> {
    let mut table = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let code = line.split('#').next().unwrap_or("").trim().to_owned();
        if code.starts_with('[') && code.ends_with(']') {
            table = code.trim_matches(|c| c == '[' || c == ']').to_owned();
            continue;
        }
        if !code.is_empty() {
            out.push((table.clone(), code));
        }
    }
    out
}

/// The violations of rule 2 in one manifest: a line naming the feature in
/// any table but a dev-dependencies table — except the daemon's own
/// `test-seams = []` in `[features]`.
fn manifest_violations(text: &str, own_feature_allowed: bool) -> Vec<String> {
    manifest_lines(text)
        .into_iter()
        .filter(|(_, code)| code.contains(FEATURE))
        .filter(|(table, code)| {
            let dev = table == "dev-dependencies" || table.ends_with(".dev-dependencies");
            let own = own_feature_allowed
                && table == "features"
                && code.replace(' ', "") == format!("{FEATURE}=[]");
            !(dev || own)
        })
        .map(|(table, code)| format!("[{table}] {code}"))
        .collect()
}

/// Rule 1: each daemon declares the module behind the feature, hidden, and
/// its manifest has the feature outside `default`.
#[test]
fn every_daemon_declares_its_test_seams_behind_the_feature() {
    let crates = crates_dir();
    for daemon in DAEMONS {
        let lib = std::fs::read_to_string(crates.join(daemon).join("src/lib.rs")).expect("lib.rs");
        let code: Vec<&str> = lib
            .lines()
            .map(|l| l.split("//").next().unwrap_or("").trim())
            .filter(|l| !l.is_empty())
            .collect();
        let at = code
            .iter()
            .position(|l| *l == format!("pub mod {MODULE};"))
            .unwrap_or_else(|| panic!("{daemon}: no `pub mod {MODULE};`"));
        assert!(at >= 2, "{daemon}: attributes before the declaration");
        let attributes = [code[at - 2], code[at - 1]];
        assert!(
            attributes.contains(&format!("#[cfg(feature = \"{FEATURE}\")]").as_str()),
            "{daemon}: the declaration is not behind the feature: {attributes:?}"
        );
        assert!(
            attributes.contains(&"#[doc(hidden)]"),
            "{daemon}: the declaration is not hidden: {attributes:?}"
        );
        assert!(
            crates
                .join(daemon)
                .join(format!("src/{MODULE}.rs"))
                .is_file(),
            "{daemon}: no src/{MODULE}.rs"
        );
        let manifest =
            std::fs::read_to_string(crates.join(daemon).join("Cargo.toml")).expect("manifest");
        let lines = manifest_lines(&manifest);
        assert!(
            lines
                .iter()
                .any(|(t, c)| t == "features" && c.replace(' ', "") == format!("{FEATURE}=[]")),
            "{daemon}: no `{FEATURE} = []` in [features]"
        );
        assert!(
            !lines
                .iter()
                .any(|(t, c)| t == "features" && c.starts_with("default") && c.contains(FEATURE)),
            "{daemon}: `{FEATURE}` in the default features"
        );
    }
    // dirstore: the path-taking constructor exists only with the feature.
    let store = std::fs::read_to_string(crates.join("dirstore/src/store.rs")).expect("store.rs");
    let lines: Vec<&str> = store.lines().map(str::trim).collect();
    let open = lines
        .iter()
        .position(|l| l.starts_with("pub fn open("))
        .expect("dirstore Store::open");
    assert_eq!(
        lines[open - 1],
        format!("#[cfg(feature = \"{FEATURE}\")]"),
        "dirstore: Store::open is not behind the feature"
    );
    let dirstore =
        std::fs::read_to_string(crates.join("dirstore/Cargo.toml")).expect("dirstore manifest");
    assert!(manifest_lines(&dirstore)
        .iter()
        .any(|(t, c)| t == "features" && c.replace(' ', "") == format!("{FEATURE}=[]")));
    // auditd: no seam at all — no module, no feature.
    assert!(!crates
        .join(format!("audit-daemon/src/{MODULE}.rs"))
        .exists());
    let auditd =
        std::fs::read_to_string(crates.join("audit-daemon/Cargo.toml")).expect("auditd manifest");
    assert!(
        !manifest_lines(&auditd)
            .iter()
            .any(|(_, c)| c.contains(FEATURE)),
        "audit-daemon declares or enables `{FEATURE}`"
    );
}

/// Rule 2: the feature is enabled only by dev-dependencies, in every
/// manifest of the workspace; the workspace resolver is 2.
#[test]
fn only_dev_dependencies_enable_the_test_seams() {
    let root = crates_dir().parent().expect("workspace root").to_path_buf();
    let workspace = std::fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest");
    assert!(
        manifest_lines(&workspace)
            .iter()
            .any(|(t, c)| t == "workspace" && c.replace(' ', "") == "resolver=\"2\""),
        "the workspace must use resolver 2"
    );
    assert!(
        manifest_violations(&workspace, false).is_empty(),
        "the workspace manifest names `{FEATURE}`"
    );
    let mut violations = Vec::new();
    let mut dev_enables = 0usize;
    for dir in crate_dirs() {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        let text = std::fs::read_to_string(dir.join("Cargo.toml")).expect("manifest");
        let own = DECLARING.contains(&name.as_str());
        for v in manifest_violations(&text, own) {
            violations.push(format!("{name}: {v}"));
        }
        dev_enables += manifest_lines(&text)
            .iter()
            .filter(|(t, c)| t.ends_with("dev-dependencies") && c.contains(FEATURE))
            .count();
    }
    assert!(
        violations.is_empty(),
        "`{FEATURE}` enabled outside a dev-dependencies table (docs/52 R15): {violations:#?}"
    );
    // Positive control: the declaring crates' own tests and their
    // dependents enable it — at least each one's self dev-dependency.
    assert!(dev_enables >= DECLARING.len(), "{dev_enables}");
}

/// Rule 3: no product source names the module in code, but the five
/// declarations.
#[test]
fn no_product_source_names_the_test_seams() {
    let crates = crates_dir();
    let mut violations = Vec::new();
    let mut declarations = Vec::new();
    let mut scanned = 0usize;
    for dir in crate_dirs() {
        let mut files = Vec::new();
        product_sources(&dir.join("src"), &mut files);
        for file in files {
            scanned += 1;
            let rel = file.strip_prefix(&crates).unwrap_or(&file).to_path_buf();
            let is_module = rel.file_name().and_then(|n| n.to_str()) == Some("test_seams.rs");
            let daemon_lib = DAEMONS
                .iter()
                .any(|d| rel == Path::new(d).join("src/lib.rs"));
            if is_module && DAEMONS.iter().any(|d| rel.starts_with(d)) {
                continue;
            }
            let text = std::fs::read_to_string(&file).expect("UTF-8 source");
            for (line, code) in mentions(&text) {
                if daemon_lib && code == format!("pub mod {MODULE};") {
                    declarations.push(rel.display().to_string());
                } else {
                    violations.push(format!("{}:{line}: {code}", rel.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "a product source names `{MODULE}` (docs/52 R15): {violations:#?}"
    );
    // Positive controls: every declaration was seen, and the scan covered
    // the workspace (every daemon's main.rs among the files).
    assert_eq!(declarations.len(), DAEMONS.len(), "{declarations:?}");
    assert!(scanned > 100, "{scanned}");
    for daemon in DAEMONS {
        assert!(
            crates.join(daemon).join("src/main.rs").is_file(),
            "{daemon}"
        );
    }
}

/// Positive control of the scanners: a planted mention in code is seen, a
/// commented one is not; a planted `[dependencies]` enable is a violation,
/// a dev-dependency one and the daemon's own feature line are not, and a
/// `default` that names the feature is a violation.
#[test]
fn the_scanners_see_planted_violations() {
    let text = "use keyd_daemon::test_seams::serve;\n// test_seams in a comment\n\
                let x = 1; // test_seams\n    crate::test_seams::opened(s)\n";
    assert_eq!(
        mentions(text)
            .into_iter()
            .map(|(n, _)| n)
            .collect::<Vec<_>>(),
        vec![1, 4]
    );
    let manifest = "[features]\n# test-seams in a comment\ntest-seams = []\n\
                    default = [\"test-seams\"]\n\
                    [dependencies]\nkeyd-daemon = { path = \"../keyd-daemon\", features = [\"test-seams\"] }\n\
                    [dev-dependencies]\nkdc-daemon = { path = \"../kdc-daemon\", features = [\"test-seams\"] }\n\
                    [target.'cfg(unix)'.dev-dependencies]\nx = { path = \"x\", features = [\"test-seams\"] }\n\
                    [target.'cfg(unix)'.dependencies]\ny = { path = \"y\", features = [\"test-seams\"] }\n";
    let found = manifest_violations(manifest, true);
    assert_eq!(found.len(), 3, "{found:#?}");
    assert!(found[0].starts_with("[features] default"));
    assert!(found[1].starts_with("[dependencies]"));
    assert!(found[2].starts_with("[target.'cfg(unix)'.dependencies]"));
    // Another crate may not even declare the feature line.
    assert_eq!(
        manifest_violations("[features]\ntest-seams = []\n", false).len(),
        1
    );
}
