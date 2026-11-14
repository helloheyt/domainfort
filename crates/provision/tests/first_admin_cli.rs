//! The command line of `provision first-admin-secret` (crates/provision
//! cli.rs): the documented shape, and every malformed one refused before
//! anything else happens. No password is ever an argument: only a password
//! file's **path** is (docs/51 §4.4; D95 as cited in docs/51 §3).
//!
//! Sources: docs/51 §4.3 step 12, §4.4; docs/questions/Q-411 item 1. Values
//! are obviously fake test data.

use std::ffi::OsString;

use provision::cli::{parse, CliError, Command};

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

/// docs/51 §4.3 step 12: the manifest, admind's file, and one password file
/// per administrator (or none — the terminal).
#[test]
fn the_documented_shapes_parse() {
    let Command::FirstAdminSecret(request) = parse(os(&[
        "first-admin-secret",
        "--manifest-path",
        "/etc/p/provision.manifest",
        "--admind-config",
        "/etc/p/admind.conf",
        "--password-file",
        "alice=/root/pw/alice",
        "--password-file",
        "bob=/root/pw/bob",
    ]))
    .unwrap() else {
        panic!("not first-admin-secret");
    };
    assert_eq!(request.manifest.as_str(), "/etc/p/provision.manifest");
    assert_eq!(request.admind_config.as_str(), "/etc/p/admind.conf");
    let files: Vec<(&str, &str)> = request
        .password_files
        .iter()
        .map(|f| (f.sam.as_str(), f.path.as_str()))
        .collect();
    assert_eq!(
        files,
        [("alice", "/root/pw/alice"), ("bob", "/root/pw/bob")]
    );

    let Command::FirstAdminSecret(request) = parse(os(&[
        "first-admin-secret",
        "--admind-config",
        "/etc/p/admind.conf",
        "--manifest-path",
        "/etc/p/provision.manifest",
    ]))
    .unwrap() else {
        panic!("not first-admin-secret");
    };
    assert!(request.password_files.is_empty());
}

/// Malformed command lines are usage or input errors.
#[test]
fn malformed_commands_are_refused() {
    let base = [
        "first-admin-secret",
        "--manifest-path",
        "/etc/p/provision.manifest",
        "--admind-config",
        "/etc/p/admind.conf",
    ];
    let with = |extra: &[&'static str]| {
        let mut v: Vec<&str> = base.to_vec();
        v.extend_from_slice(extra);
        v
    };
    for (args, what) in [
        (vec!["first-admin-secret"], "nothing"),
        (base[..3].to_vec(), "no admind file"),
        (vec![base[0], base[3], base[4]], "no manifest"),
        (with(&["--manifest-path", "/etc/p/other"]), "manifest twice"),
        (with(&["--password-file"]), "no value"),
        (
            with(&["--password-file", "--manifest-path"]),
            "flag as value",
        ),
        (with(&["--password-file", "alice"]), "no ="),
        (with(&["--password-file", "=/root/pw/alice"]), "no name"),
        (
            with(&["--password", "Velvet-Harbor-Quince-58"]),
            "a password flag",
        ),
        (with(&["--force"]), "unknown flag"),
    ] {
        assert!(
            matches!(parse(os(&args)), Err(CliError::Usage(_))),
            "{what}"
        );
    }
    for (args, what) in [
        (
            with(&["--password-file", "alice=relative/path"]),
            "relative path",
        ),
        (with(&["--password-file", "alice=/root/../pw"]), "dot-dot"),
        (
            vec![
                base[0],
                "--manifest-path",
                "manifest",
                "--admind-config",
                "/etc/p/admind.conf",
            ],
            "relative manifest",
        ),
    ] {
        assert!(
            matches!(parse(os(&args)), Err(CliError::Input(_))),
            "{what}"
        );
    }
}
