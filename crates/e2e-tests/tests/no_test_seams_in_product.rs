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
//! same feature. ipc-audit-client's `test_seams` (task R15b, docs/questions/
//! Q-630; in crate ipc-audit-client, with the gate and the one client, since
//! task IB1 — docs/questions/Q-851) reaches the audit gate's crate-private
//! link side — auditd reachable, the
//! batch to send, auditd's `Ack`, a lost batch — which in a product only the
//! one audit client drives; it exists only for the in-process tier-1 tests
//! of keyd's and the kdc's gate wrappers. This test checks the things that
//! keep that true by construction in a product build:
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
//!    gives no product path a seam either;
//! 4. ipc-audit-client's seams (the evidence an `AckedIntent` rests on) are
//!    the narrowest: ipc-audit-client declares its module like the daemons
//!    (rule 1), only keyd-daemon's and kdc-daemon's `[dev-dependencies]`
//!    enable ipc-audit-client's feature, and only their tier-1 test files
//!    name `ipc_audit_client::test_seams` — in **any** source of the
//!    workspace, test code included. Every other test obtains an
//!    acknowledged intent from a fake auditd through the real client
//!    (crates/ipc-audit-client `tests/linked`).
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

/// The crates that declare the feature: the daemons above, dirstore (its
/// path-taking `Store::open`, A-113) and ipc-audit-client (the audit gate's
/// link side, task R15b; moved from ipc-audit with the gate by task IB1).
const DECLARING: [&str; 7] = [
    "keyd-daemon",
    "kdc-daemon",
    "directory-daemon",
    "admin-daemon",
    "ldap-front",
    "dirstore",
    "ipc-audit-client",
];

/// The library crates (not daemons: no `main.rs`) that declare a
/// `test_seams` module in `src/lib.rs`, behind the feature (rule 1).
const LIBRARY_MODULES: [&str; 1] = ["ipc-audit-client"];

/// The only crates whose `[dev-dependencies]` enable ipc-audit-client's
/// feature (rule 4): their in-process tier-1 tests play the audit client.
const IPC_AUDIT_SEAM_USERS: [&str; 2] = ["keyd-daemon", "kdc-daemon"];

/// The only files, relative to `crates/`, that name
/// `ipc_audit_client::test_seams` (rule 4).
const IPC_AUDIT_SEAM_FILES: [&str; 3] = [
    "keyd-daemon/src/audit_tests.rs",
    "keyd-daemon/src/tier1_tests.rs",
    "kdc-daemon/src/audit_tests.rs",
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

/// Rule 1: each daemon (and ipc-audit-client, task R15b) declares the module
/// behind the feature, hidden, and its manifest has the feature outside
/// `default`.
#[test]
fn every_daemon_declares_its_test_seams_behind_the_feature() {
    let crates = crates_dir();
    for daemon in DAEMONS.into_iter().chain(LIBRARY_MODULES) {
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
            let declaring = || DAEMONS.iter().chain(LIBRARY_MODULES.iter());
            let daemon_lib = declaring().any(|d| rel == Path::new(d).join("src/lib.rs"));
            if is_module && declaring().any(|d| rel.starts_with(d)) {
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
    assert_eq!(
        declarations.len(),
        DAEMONS.len() + LIBRARY_MODULES.len(),
        "{declarations:?}"
    );
    assert!(scanned > 100, "{scanned}");
    for daemon in DAEMONS {
        assert!(
            crates.join(daemon).join("src/main.rs").is_file(),
            "{daemon}"
        );
    }
}

/// Every `.rs` file below `dir`, recursively, test code included (rule 4);
/// build output (`target`) skipped.
fn all_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = read.map(|e| e.expect("entry").path()).collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "target" {
                all_sources(&path, out);
            }
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// Whether `text` names ipc-audit-client's seams in code (outside `//`
/// comments): a path `ipc_audit_client::test_seams`, or a
/// `use ipc_audit_client::{…}` group — over any number of lines — that lists
/// `test_seams`.
fn names_ipc_audit_seams(text: &str) -> bool {
    let compact: String = text
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    if compact.contains("ipc_audit_client::test_seams") {
        return true;
    }
    const GROUP: &str = "ipc_audit_client::{";
    let mut rest = compact.as_str();
    while let Some(at) = rest.find(GROUP) {
        let after = &rest[at + GROUP.len()..];
        let mut depth = 1usize;
        let mut end = after.len();
        for (i, c) in after.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let group = &after[..end];
        if group
            .split([',', '{', '}'])
            .any(|item| item == MODULE || item.starts_with("test_seams::"))
        {
            return true;
        }
        rest = &after[end..];
    }
    false
}

/// Rule 4 (task R15b, docs/questions/Q-630): ipc-audit-client's seams — the
/// evidence an `AckedIntent` rests on — are enabled only by keyd-daemon's
/// and kdc-daemon's dev-dependencies and named only by their tier-1 test
/// files, in any source of the workspace (test code included).
#[test]
fn only_the_tier_1_gate_tests_reach_ipc_audits_seams() {
    let crates = crates_dir();
    let mut enabling = Vec::new();
    let mut violations = Vec::new();
    for dir in crate_dirs() {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        let text = std::fs::read_to_string(dir.join("Cargo.toml")).expect("manifest");
        for (table, code) in manifest_lines(&text) {
            if code.starts_with("ipc-audit-client") && code.contains(FEATURE) {
                if table.ends_with("dev-dependencies")
                    && IPC_AUDIT_SEAM_USERS.contains(&name.as_str())
                {
                    enabling.push(name.clone());
                } else {
                    violations.push(format!("{name}: [{table}] {code}"));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "ipc-audit-client's `{FEATURE}` enabled outside keyd-daemon's / kdc-daemon's \
         dev-dependencies: \
         {violations:#?}"
    );
    enabling.sort();
    let mut users = IPC_AUDIT_SEAM_USERS.to_vec();
    users.sort_unstable();
    assert_eq!(enabling, users, "positive control");

    let this_file = Path::new(file!())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let mut naming = Vec::new();
    let mut scanned = 0usize;
    for dir in crate_dirs() {
        let mut files = Vec::new();
        all_sources(&dir, &mut files);
        for file in files {
            let rel = file.strip_prefix(&crates).unwrap_or(&file).to_path_buf();
            if rel == Path::new("e2e-tests/tests").join(this_file) {
                continue;
            }
            scanned += 1;
            let text = std::fs::read_to_string(&file).expect("UTF-8 source");
            if names_ipc_audit_seams(&text) {
                naming.push(rel.display().to_string());
            }
        }
    }
    let unexpected: Vec<&String> = naming
        .iter()
        .filter(|f| !IPC_AUDIT_SEAM_FILES.contains(&f.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "a source outside the tier-1 gate tests names ipc_audit_client::test_seams: \
         {unexpected:#?}"
    );
    // Positive control: each allowed file is seen, and the scan covered
    // test code too (far more files than the product scan).
    naming.sort();
    let mut expected: Vec<String> = IPC_AUDIT_SEAM_FILES
        .iter()
        .map(|f| (*f).to_owned())
        .collect();
    expected.sort();
    assert_eq!(naming, expected);
    assert!(scanned > 300, "{scanned}");
}

/// Positive control of rule 4's scanner: a path, a one-line and a
/// multi-line `use` group naming the module are seen; a comment, another
/// crate's module and an ipc-audit-client group without it are not.
#[test]
fn the_ipc_audit_scanner_sees_planted_uses() {
    assert!(names_ipc_audit_seams(
        "fn f(g: &G) { ipc_audit_client::test_seams::set_reachable(g, true); }"
    ));
    assert!(names_ipc_audit_seams(
        "use ipc_audit_client::{test_seams, AuditGate};"
    ));
    assert!(names_ipc_audit_seams(
        "use ipc_audit_client::{\n    AckedIntent, AuditGate,\n    test_seams,\n};\n"
    ));
    assert!(names_ipc_audit_seams(
        "use ipc_audit_client::{gate::{X}, test_seams::acknowledge};"
    ));
    assert!(!names_ipc_audit_seams(
        "// ipc_audit_client::test_seams in a comment\nuse ipc_audit_client::{AuditGate};\n\
         use ipc_audit::{Ack};\nuse keyd_daemon::test_seams::serve;\n"
    ));
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
