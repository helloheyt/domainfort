//! keyadm's configuration schema (`KeyadmSettings`): the closed key table,
//! the required keys, the uid and deadline rules, and no echo.
//!
//! Each test names its source: docs/50 R50-3 / R50-15 / §3.2 / §3.6 / §7.1,
//! docs/51 §6, or the Q-230 interpretation (A-60) the input exercises. The
//! sample is constructed by hand for this test (obviously fake paths and
//! uids); no vector comes from any other implementation.

use config::limits::MAX_FILE_OCTETS;
use config::{ErrorKind, KeyadmSettings};
use std::time::Duration;

/// A valid keyadm file. Source: docs/51 §6 (keyadm talks only to keyd);
/// docs/50 §3.2 (the client checks the server's uid), §3.6 (deadline 2 s).
const SAMPLE: &str = "\
# keyadm: the one-shot Role::Admin tool (docs/51 6)
keyd_socket = /run/test-keyd/keyd.sock
keyd_uid = 4101
keyd_deadline = 2s
";

fn set(key: &str, value: &str) -> String {
    let prefix = format!("{key} = ");
    SAMPLE
        .lines()
        .map(|line| {
            if line.starts_with(&prefix) {
                format!("{prefix}{value}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn remove(key: &str) -> String {
    let prefix = format!("{key} = ");
    SAMPLE
        .lines()
        .filter(|line| !line.starts_with(&prefix))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn kind(text: &str) -> ErrorKind {
    KeyadmSettings::parse(text.as_bytes())
        .expect_err("must be rejected")
        .kind()
}

/// docs/50 R50-3, §3.2 (socket and the uid keyd must present), §3.6
/// (deadline): the sample is accepted with its values.
#[test]
fn the_sample_is_accepted() {
    let settings = KeyadmSettings::parse(SAMPLE.as_bytes()).unwrap();
    assert_eq!(
        settings.keyd().socket().as_str(),
        "/run/test-keyd/keyd.sock"
    );
    assert_eq!(settings.keyd().uid(), 4101);
    assert_eq!(settings.keyd_deadline(), Duration::from_secs(2));
}

/// docs/50 §3.6 ("deadline in the client — keyd: 2 s") and Q-230 item 4
/// (the docs/50 value is the default and the ceiling): absent ⇒ 2 s; 1 s is
/// accepted; 3 s and 0 s are out of range.
#[test]
fn the_deadline_defaults_to_and_is_capped_at_two_seconds() {
    let settings = KeyadmSettings::parse(remove("keyd_deadline").as_bytes()).unwrap();
    assert_eq!(settings.keyd_deadline(), Duration::from_secs(2));
    let settings = KeyadmSettings::parse(set("keyd_deadline", "1s").as_bytes()).unwrap();
    assert_eq!(settings.keyd_deadline(), Duration::from_secs(1));
    assert_eq!(kind(&set("keyd_deadline", "3s")), ErrorKind::OutOfRange);
    assert_eq!(kind(&set("keyd_deadline", "0s")), ErrorKind::OutOfRange);
    assert_eq!(kind(&set("keyd_deadline", "2")), ErrorKind::InvalidDuration);
}

/// docs/50 §7.1 ("missing-required ⇒ do not start"): keyd_socket and
/// keyd_uid are required.
#[test]
fn the_keyd_endpoint_is_required() {
    for key in ["keyd_socket", "keyd_uid"] {
        let err = KeyadmSettings::parse(remove(key).as_bytes()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingKey, "{key}");
        assert_eq!(err.key(), Some(key));
    }
}

/// docs/50 R50-3 ("uid 0 is never mapped"; the keyd client refuses a root
/// server uid) and Q-230 item 6 (never all-ones): keyd_uid 0 and
/// 4294967295 are refused; a non-canonical integer too.
#[test]
fn keyd_uid_zero_and_all_ones_are_refused() {
    assert_eq!(kind(&set("keyd_uid", "0")), ErrorKind::ReservedId);
    assert_eq!(kind(&set("keyd_uid", "4294967295")), ErrorKind::ReservedId);
    assert_eq!(kind(&set("keyd_uid", "04101")), ErrorKind::InvalidInteger);
    assert_eq!(kind(&set("keyd_uid", "-1")), ErrorKind::InvalidInteger);
}

/// docs/50 R50-15 (a closed key table per file): keys of other daemons'
/// files are unknown here — keyadm has no run_as account (docs/51 §6:
/// started under its own uid), no dird or audit endpoint (it talks only to
/// keyd).
#[test]
fn keys_of_other_files_are_unknown() {
    for line in [
        "run_as_uid = 4102",
        "dird_admin_socket = /run/test-dird/dird-admin.sock",
        "audit_socket = /run/test-audit/audit.sock",
        "realm = EXAMPLE.TEST",
    ] {
        let text = format!("{SAMPLE}{line}\n");
        assert_eq!(kind(&text), ErrorKind::UnknownKey, "{line}");
    }
}

/// docs/50 §7.1 (duplicate ⇒ refuse; printable ASCII only; LF after the
/// last line; ≤ 64 KiB); Q-230 item 16 (canonical absolute path).
#[test]
fn format_and_path_rules_apply() {
    let text = format!("{SAMPLE}keyd_uid = 4103\n");
    assert_eq!(kind(&text), ErrorKind::DuplicateKey);
    assert_eq!(
        kind(&set("keyd_socket", "/run/t\u{e9}st/keyd.sock")),
        ErrorKind::InvalidCharacter
    );
    assert_eq!(kind(SAMPLE.trim_end()), ErrorKind::MissingFinalNewline);
    let big = SAMPLE.to_owned() + &"#\n".repeat(MAX_FILE_OCTETS / 2 + 1);
    assert_eq!(kind(&big), ErrorKind::FileTooLarge);
    for bad in [
        "run/keyd.sock",
        "/run/../keyd.sock",
        "/run/keyd.sock/",
        "$HOME/keyd.sock",
    ] {
        assert_eq!(
            kind(&set("keyd_socket", bad)),
            ErrorKind::InvalidPath,
            "{bad}"
        );
    }
}

/// docs/CLEAN-ROOM.md / A-60 ("an error never shows the value that was
/// written"): a rejected value does not appear in the error text.
#[test]
fn errors_do_not_echo_values() {
    let marker = "/run/SECRET-LOOKING-VALUE/../x";
    let err = KeyadmSettings::parse(set("keyd_socket", marker).as_bytes()).unwrap_err();
    assert!(!err.to_string().contains("SECRET-LOOKING-VALUE"), "{err}");
    assert_eq!(err.key(), Some("keyd_socket"));
}

/// A-102 (docs/52 §4.6; docs/51 §6: "keyadm talks to keyd only"): the
/// `admin_socket` + `admind_uid` pair of task A10 is gone with the keyadm
/// channel — both keys are unknown now (docs/50 R50-15: a closed key table).
#[test]
fn the_admind_pair_is_gone() {
    for line in [
        "admin_socket = /run/test-admind/admin.sock",
        "admind_uid = 4105",
    ] {
        let text = format!("{SAMPLE}{line}\n");
        assert_eq!(kind(&text), ErrorKind::UnknownKey, "{line}");
    }
}
