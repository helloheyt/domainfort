//! Guard of docs/questions/Q-987 item 5 (decision A-165; Q-995) — the class
//! Q-987 item 1 and A-165 file under C14 (docs/52 §3.14): one rule written
//! in two places, a divergence that fails open or closed by luck (docs/CLEAN-ROOM.md
//! ): the change-password service's name and the KerberosTime ↔
//! Unix-seconds conversions are defined once, in this crate, and every other
//! crate calls them.
//!
//! Before Q-995 the Unix → KerberosTime conversion was written in five more
//! crates (the clocks of kdc-daemon, keyd-daemon, directory-daemon and
//! admin-daemon, provisioning's time — each a `kerberos_time_from_unix`),
//! the reverse difference in two (the kdc's `unix_seconds`, the LDAP
//! engine's `unix_instant`, each spelling the epoch as a KerberosTime), and
//! directory-daemon spelled the service name's components as literals
//! (`KerberosString::new("kadmin")`, `("changepw")`). Before Q-1005 the
//! scale's inverse (a count on the scale back to a KerberosTime) was
//! written in two more (the kdc's and directory-pip's `time.rs`, each a
//! `from_seconds` — a name rule 1 would never have seen, hence rule 4).
//!
//! What this test pins, in the workspace's non-test source (`crates/*/src`):
//!
//! 1. `fn kerberos_time_seconds`, `fn kerberos_time_from_seconds`,
//!    `fn kerberos_time_from_unix`, `fn kerberos_time_to_unix` (RFC 4120
//!    5.2.3) are defined only in krb-proto `time.rs`;
//!    `const CHANGE_PASSWORD_SERVICE_NAME` and
//!    `fn is_change_password_service_name` (RFC 3244 §2; RFC 4120 §6.2) only
//!    in krb-proto `kpasswd.rs`. Other crates call or re-export them
//!    (keyd-types re-exports two under their former paths).
//! 2. The service name's components are spelled as string literals
//!    (`"kadmin"`, `"changepw"`, or a joined `"kadmin/changepw…"`) only in
//!    krb-proto `kpasswd.rs` — the shape of directory-daemon's former copy,
//!    which a definition scan alone would not see.
//! 3. The Unix epoch is spelled as a KerberosTime
//!    (`KerberosTime::new(1970, 1, 1, 0, 0, 0)`, whitespace ignored) only
//!    where [`EPOCH_SPELLED_ELSEWHERE`] lists it, each with its reason — the
//!    shape every hand-written Unix conversion of the workspace had.
//! 4. A KerberosTime is built from computed fields (`KerberosTime::new(`
//!    with an argument that is not an integer literal) outside krb-proto
//!    only where [`FIELDS_COMPUTED_ELSEWHERE`] lists it, each with its
//!    reason. Turning any count — seconds on the scale, Unix seconds, a
//!    DSTIME — into a KerberosTime means computing its calendar fields and
//!    building it, whatever the function is called: the shape both former
//!    `from_seconds` had (the first-of-month probe
//!    `KerberosTime::new(year, month, 1, 0, 0, 0)` and the final
//!    construction), and the shape of every Unix copy Q-995 removed. The
//!    listed files build a KerberosTime from fields they decode, not from a
//!    count; a literal instant (`KerberosTime::new(1601, 1, 1, 0, 0, 0)`)
//!    is not a conversion and is not flagged.
//!
//! A lexical scan, not a type: it catches the shape of the regression, and a
//! reviewer decides any new hit. Test code is not scanned (directories
//! named `tests`, files whose name ends in `tests.rs`, and a file's
//! `#[cfg(test)] mod … {` block to its end); line comments are dropped.
//! Positive controls: the scanner flags planted copies — among them the
//! exact lines Q-995 and Q-1005 removed — and not calls, longer
//! identifiers, literal instants, comments or test modules; and each
//! workspace scan must find krb-proto's own definition (rules 1, 2), the
//! listed `till` value (rule 3) or exactly the listed field decoders (rule
//! 4), so it cannot pass vacuously or keep a stale entry.
//!
//! Source: RFC 3244 §2 ("the service principal kadmin/changepw@REALM");
//! RFC 4120 5.2.3 (KerberosTime), §6.2, 5.4.1 (`till` 19700101000000Z);
//! RFC 4517 §3.3.13 (Generalized Time); docs/52 §3.14 (C14);
//! docs/questions/Q-955 item 5 (A-158), Q-987 item 5 (A-165), Q-995
//! (A-169), Q-1005; docs/CLEAN-ROOM.md. Test-only; modelled on crates/keyd-types
//! `tests/one_service_purpose_derivation.rs` (this project's own code).

use std::path::{Path, PathBuf};

/// Rule 1: each single definition and the one file that holds it.
const DEFINITIONS: [(&str, &str); 6] = [
    ("fn kerberos_time_seconds", "krb-proto/src/time.rs"),
    ("fn kerberos_time_from_seconds", "krb-proto/src/time.rs"),
    ("fn kerberos_time_from_unix", "krb-proto/src/time.rs"),
    ("fn kerberos_time_to_unix", "krb-proto/src/time.rs"),
    (
        "const CHANGE_PASSWORD_SERVICE_NAME",
        "krb-proto/src/kpasswd.rs",
    ),
    (
        "fn is_change_password_service_name",
        "krb-proto/src/kpasswd.rs",
    ),
];

/// Rule 2: the service name's components as string literals (a joined form
/// is matched by its opening).
const NAME_LITERALS: [&str; 3] = ["\"kadmin\"", "\"changepw\"", "\"kadmin/changepw"];

/// Rule 2: the one file that spells them — the definition.
const NAME_DEFINED_IN: &str = "krb-proto/src/kpasswd.rs";

/// Rule 3: the Unix epoch as a KerberosTime, whitespace removed.
const EPOCH_AS_KERBEROS_TIME: &str = "KerberosTime::new(1970,1,1,0,0,0)";

/// Rule 3: the files outside krb-proto that may spell the epoch, with the
/// reason.
const EPOCH_SPELLED_ELSEWHERE: [(&str, &str); 1] = [(
    "kdc/src/time.rs",
    "RFC 4120 5.4.1: the `till` value 19700101000000Z (\"the maximum endtime \
     permitted\") — a protocol value, not a Unix conversion",
)];

/// Rule 4: the constructor whose arguments the scan reads.
const CONSTRUCTOR: &str = "KerberosTime::new(";

/// Rule 4: the type's home, where a KerberosTime is built from computed
/// fields by design (the decoder and the single conversions).
const FIELDS_HOME: &str = "krb-proto/src/";

/// Rule 4: the files outside krb-proto that build a KerberosTime from
/// computed fields, with the reason — each decodes fields, none converts a
/// count.
const FIELDS_COMPUTED_ELSEWHERE: [(&str, &str); 3] = [
    (
        "ipc-directory/src/typed.rs",
        "the kdc ↔ dird channel's wire time: its six calendar fields, \
         validated by KerberosTime::new on decode (RFC 4120 5.2.3; docs/50 §3.3)",
    ),
    (
        "ipc-keyd/src/typed.rs",
        "the kdc ↔ keyd channel's wire time: its six calendar fields, \
         validated by KerberosTime::new on decode (RFC 4120 5.2.3; Q-245 item 1)",
    ),
    (
        "ldap/src/search/syntax.rs",
        "an asserted Generalized Time's fields, parsed from the assertion \
         value and then read through directory-pip's DSTIME (RFC 4517 §3.3.13)",
    ),
];

/// The workspace's `crates/` directory.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ directory")
        .to_path_buf()
}

/// Every crate directory with a `src/`, sorted.
fn crate_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(crates_dir())
        .expect("readable crates/")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.join("src").is_dir())
        .collect();
    dirs.sort();
    dirs
}

/// Every non-test `.rs` file below `dir`, recursively.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("readable source directory")
        .map(|e| e.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "tests" {
                sources(&path, out);
            }
        } else if name.ends_with(".rs") && !name.ends_with("tests.rs") {
            out.push(path);
        }
    }
}

/// The non-test code of a file: line comments removed, and everything from
/// a `#[cfg(test)]` line followed by an inline `mod … {` to the end of the
/// file dropped (a `#[cfg(test)] mod x;` declaration is only skipped).
fn code_of(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.trim() == "#[cfg(test)]" {
            let next = lines.get(i + 1).map(|l| l.trim()).unwrap_or("");
            if next.starts_with("mod ") && next.ends_with('{') {
                break;
            }
            i += 1;
            continue;
        }
        out.push_str(line.split("//").next().unwrap_or(""));
        out.push('\n');
        i += 1;
    }
    out
}

/// `true` for a character of a Rust identifier.
fn ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Whether `code` defines `item` (`fn name` / `const NAME`): the item
/// followed by something that is not part of an identifier, and preceded by
/// something that is not either.
fn defines(code: &str, item: &str) -> bool {
    let mut from = 0;
    while let Some(at) = code[from..].find(item) {
        let start = from + at;
        let end = start + item.len();
        from = end;
        let before = code[..start].chars().next_back();
        let after = code[end..].chars().next();
        if !before.is_some_and(ident) && !after.is_some_and(ident) {
            return true;
        }
    }
    false
}

/// Every rule-2 literal in `code`: `(line, literal)`.
fn name_literals(code: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (index, line) in code.lines().enumerate() {
        for literal in NAME_LITERALS {
            if line.contains(literal) {
                found.push((index + 1, literal));
            }
        }
    }
    found
}

/// The lines of `code` that spell the Unix epoch as a KerberosTime.
fn epoch_lines(code: &str) -> Vec<usize> {
    code.lines()
        .enumerate()
        .filter(|(_, line)| {
            let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            compact.contains(EPOCH_AS_KERBEROS_TIME)
        })
        .map(|(index, _)| index + 1)
        .collect()
}

/// Whether `argument` (trimmed) is an integer literal: digits, with `_`
/// separators.
fn integer_literal(argument: &str) -> bool {
    !argument.is_empty() && argument.chars().all(|c| c.is_ascii_digit() || c == '_')
}

/// Rule 4: the lines of `code` where a `KerberosTime::new(` starts whose
/// arguments — the text to its matching `)`, split at commas, a trailing
/// comma ignored — are not all integer literals. `MyKerberosTime::new(` is
/// another type and is not read.
fn computed_constructions(code: &str) -> Vec<usize> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find(CONSTRUCTOR) {
        let start = from + at;
        let open = start + CONSTRUCTOR.len();
        from = open;
        if code[..start].chars().next_back().is_some_and(ident) {
            continue;
        }
        let mut depth = 1usize;
        let mut close = code.len();
        for (offset, c) in code[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        let literal = code[open..close]
            .split(',')
            .map(str::trim)
            .filter(|argument| !argument.is_empty())
            .all(integer_literal);
        if !literal {
            found.push(code[..start].matches('\n').count() + 1);
        }
    }
    found
}

/// Every non-test source file of the workspace with its path relative to
/// `crates/` and its non-test code.
fn workspace_code() -> Vec<(String, String)> {
    let crates = crates_dir();
    let dirs = crate_dirs();
    assert!(dirs.len() > 10, "{dirs:?}");
    let mut out = Vec::new();
    for dir in dirs {
        let mut files = Vec::new();
        sources(&dir.join("src"), &mut files);
        for file in files {
            let text = std::fs::read_to_string(&file).expect("UTF-8 source");
            let rel = file
                .strip_prefix(&crates)
                .unwrap_or(&file)
                .display()
                .to_string();
            out.push((rel, code_of(&text)));
        }
    }
    out
}

/// Rule 1: each conversion of the KerberosTime ↔ seconds pair and each part
/// of the service-name rule is defined in exactly one file, krb-proto's — the
/// positive control is that very file being found.
#[test]
fn the_name_and_the_time_conversions_are_defined_once() {
    let code = workspace_code();
    for (item, home) in DEFINITIONS {
        let found: Vec<&str> = code
            .iter()
            .filter(|(_, text)| defines(text, item))
            .map(|(rel, _)| rel.as_str())
            .collect();
        assert_eq!(
            found,
            vec![home],
            "`{item}` must be defined only in {home} (Q-987 item 5, Q-995, \
             Q-1005): call krb_proto's instead of writing a copy"
        );
    }
}

/// Rule 2: the service name's components are spelled only in the
/// definition — positive control: the definition's own literals are found.
#[test]
fn the_service_name_is_spelled_only_in_its_definition() {
    let mut elsewhere = Vec::new();
    let mut at_home = Vec::new();
    for (rel, text) in workspace_code() {
        for (line, literal) in name_literals(&text) {
            if rel == NAME_DEFINED_IN {
                at_home.push(literal);
            } else {
                elsewhere.push(format!("{rel}:{line}: {literal}"));
            }
        }
    }
    assert!(
        elsewhere.is_empty(),
        "the change-password service name spelled outside krb_proto::\
         CHANGE_PASSWORD_SERVICE_NAME (RFC 3244 §2; Q-995): {elsewhere:#?}"
    );
    assert!(
        at_home.contains(&"\"kadmin\"") && at_home.contains(&"\"changepw\""),
        "the scan must see the definition itself: {at_home:?}"
    );
}

/// Rule 3: the Unix epoch is spelled as a KerberosTime only where listed —
/// positive control: the kdc's `till` value (RFC 4120 5.4.1) is found.
#[test]
fn the_unix_epoch_is_spelled_only_where_listed() {
    let mut unlisted = Vec::new();
    let mut listed = Vec::new();
    for (rel, text) in workspace_code() {
        for line in epoch_lines(&text) {
            if EPOCH_SPELLED_ELSEWHERE.iter().any(|(file, _)| *file == rel) {
                listed.push(rel.clone());
            } else {
                unlisted.push(format!("{rel}:{line}"));
            }
        }
    }
    assert!(
        unlisted.is_empty(),
        "the Unix epoch spelled as a KerberosTime — a hand-written Unix \
         conversion? Call krb_proto::kerberos_time_from_unix / \
         kerberos_time_to_unix (Q-995), or list the file with its reason: \
         {unlisted:#?}"
    );
    assert!(
        listed.iter().any(|rel| rel == "kdc/src/time.rs"),
        "the scan must see the kdc's `till` value: {listed:?}"
    );
}

/// Rule 4: a KerberosTime is built from computed fields outside krb-proto
/// only in the listed field decoders — positive control: exactly the
/// listed files are found (each one, so the scan is not vacuous and no
/// entry outlives its reason).
#[test]
fn kerberos_time_is_built_from_computed_fields_only_where_listed() {
    let mut unlisted = Vec::new();
    let mut listed = Vec::new();
    for (rel, text) in workspace_code() {
        if rel.starts_with(FIELDS_HOME) {
            continue;
        }
        for line in computed_constructions(&text) {
            if FIELDS_COMPUTED_ELSEWHERE
                .iter()
                .any(|(file, _)| *file == rel)
            {
                listed.push(rel.clone());
            } else {
                unlisted.push(format!("{rel}:{line}"));
            }
        }
    }
    assert!(
        unlisted.is_empty(),
        "a KerberosTime built from computed fields outside krb-proto — a \
         hand-written conversion of a count? Call krb_proto::\
         kerberos_time_from_seconds / kerberos_time_from_unix (Q-995, \
         Q-1005), or list the file with its reason: {unlisted:#?}"
    );
    listed.sort();
    listed.dedup();
    let expected: Vec<&str> = FIELDS_COMPUTED_ELSEWHERE
        .iter()
        .map(|(file, _)| *file)
        .collect();
    assert_eq!(
        listed, expected,
        "every listed field decoder must still be found (a stale entry is \
         removed with its reason)"
    );
}

/// Positive control of the scanners: planted copies are flagged — among
/// them the lines Q-995 removed from directory-daemon (`kpasswd_service.rs`,
/// `clock.rs`), the daemons' clocks and the LDAP engine — while calls,
/// re-exports, longer identifiers, comments and a test module are not.
#[test]
fn the_scanners_tell_a_copy_from_a_call() {
    let text = "\
pub fn kerberos_time_from_unix(secs: u64) -> Option<KerberosTime> {
            KerberosString::new(\"kadmin\").ok()?,
            KerberosString::new(\"changepw\").ok()?,
    let epoch = dstime_of(&KerberosTime::new(1970, 1, 1, 0, 0, 0).ok()?)?;
    let epoch = KerberosTime::new(1970,1,1, 0,0,0).ok()?;
const CHANGE_PASSWORD_SERVICE_NAME: [&str; 2] = [\"kadmin/changepw\", \"\"];
    kerberos_time_from_unix(since.as_secs())
pub use krb_proto::{kerberos_time_from_unix, CHANGE_PASSWORD_SERVICE_NAME};
fn kerberos_time_from_unix_checked(secs: u64) {}
    let epoch = KerberosTime::new(1970, 1, 2, 0, 0, 0);
// pub fn kerberos_time_to_unix(t: &KerberosTime) -> Option<u64> {
let a = 1; // KerberosString::new(\"kadmin\")
#[cfg(test)]
mod tests {
    fn kerberos_time_to_unix() {}
    let n = [\"kadmin\", \"changepw\"];
    let e = KerberosTime::new(1970, 1, 1, 0, 0, 0);
}
";
    let code = code_of(text);
    assert!(defines(&code, "fn kerberos_time_from_unix"));
    assert!(defines(&code, "const CHANGE_PASSWORD_SERVICE_NAME"));
    assert!(
        !defines(&code, "fn kerberos_time_to_unix"),
        "a comment and a test module define nothing"
    );
    assert!(
        !defines(
            "pub use krb_proto::kerberos_time_from_unix;\nlet t = kerberos_time_from_unix(0);\n\
             fn kerberos_time_from_unix_checked() {}\nfn my_kerberos_time_from_unix() {}\n",
            "fn kerberos_time_from_unix"
        ),
        "a re-export, a call and longer identifiers are not definitions"
    );
    assert_eq!(
        name_literals(&code),
        vec![
            (2, "\"kadmin\""),
            (3, "\"changepw\""),
            (6, "\"kadmin/changepw")
        ]
    );
    assert_eq!(epoch_lines(&code), vec![4, 5]);
}

/// Positive control of rules 1 and 4 for the scale's inverse (Q-1005):
/// planted copies are flagged — a definition of `kerberos_time_from_seconds`;
/// the exact lines removed from the kdc's and directory-pip's `from_seconds`
/// (the first-of-month probe, the multi-line final construction); and a
/// path-qualified construction from a named constant (krb-proto's own
/// former epoch line, path added) — while literal instants (the kdc's
/// `till`, directory-pip's 1601 epoch, the kdc's configuration probe, a
/// multi-line literal with `_` separators and a trailing comma), calls,
/// imports, a function passed by name, another type's `new`, a comment and
/// a test module are not.
#[test]
fn the_scanners_tell_a_conversion_from_a_literal_instant() {
    let text = "\
pub fn kerberos_time_from_seconds(seconds: i64) -> Option<KerberosTime> {
    KerberosTime::new(year, month, 1, 0, 0, 0)
    KerberosTime::new(
        year,
        month,
        u8::try_from(day).ok()?,
        u8::try_from(rest / SECONDS_PER_HOUR).ok()?,
        u8::try_from(rest % SECONDS_PER_HOUR / SECONDS_PER_MINUTE).ok()?,
        u8::try_from(rest % SECONDS_PER_MINUTE).ok()?,
    )
    .ok()
    let epoch = krb_proto::KerberosTime::new(UNIX_EPOCH_YEAR, 1, 1, 0, 0, 0).ok()?;
    KerberosTime::new(1970, 1, 1, 0, 0, 0).ok()
    KerberosTime::new(1601, 1, 1, 0, 0, 0)
        KerberosTime::new(2000, 1, 1, 0, 0, 0).map_err(|_| ConfigError::UdpReplyLimit)?;
    KerberosTime::new(
        10_000,
        1,
        1,
        0,
        0,
        0,
    )
use krb_proto::{kerberos_time_from_seconds, KerberosTime};
        Some(kerberos_time_from_seconds(renew).ok_or(TimeRefusal::OutOfRange)?)
        .and_then(kerberos_time_from_seconds)
    MyKerberosTime::new(year, month)
// KerberosTime::new(year, month, 1, 0, 0, 0)
#[cfg(test)]
mod tests {
    fn kerberos_time_from_seconds() {}
    KerberosTime::new(y, mo, d, h, mi, s).unwrap()
}
";
    let code = code_of(text);
    assert!(defines(&code, "fn kerberos_time_from_seconds"));
    assert!(
        !defines(
            "use krb_proto::{kerberos_time_from_seconds, KerberosTime};\n\
             let end = kerberos_time_from_seconds(end);\n\
             .and_then(kerberos_time_from_seconds)\n\
             fn kerberos_time_from_seconds_checked() {}\n",
            "fn kerberos_time_from_seconds"
        ),
        "an import, a call, a function passed by name and a longer \
         identifier are not definitions"
    );
    assert_eq!(computed_constructions(&code), vec![2, 3, 12]);
    let after_comments_and_tests = "\
// pub fn kerberos_time_from_seconds(seconds: i64) -> Option<KerberosTime> {
#[cfg(test)]
mod tests {
    pub fn kerberos_time_from_seconds(seconds: i64) -> Option<KerberosTime> {
}
";
    assert!(
        !defines(
            &code_of(after_comments_and_tests),
            "fn kerberos_time_from_seconds"
        ),
        "a comment and a test module define nothing"
    );
}
