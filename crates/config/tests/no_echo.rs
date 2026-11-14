//! Errors never contain the offending value, or any other text of the file.
//!
//! A value written in the wrong place could be a secret by mistake, and
//! secrets never reach errors or logs. Each case puts a distinctive marker in
//! the offending position and checks that neither `Display` nor `Debug` of the
//! error contains it.
//!
//! Spec: AGENTS.md §6 ("secrets never appear in logs, panics, debug output, or
//! error messages"); docs/50 §8.2 ("errors carry a code, not content"), R50-15
//! ("no secrets").

mod common;

use common::{append, remove, replace, set, Daemon, DIRD, KDC, KEYD, LDAP_FRONT};

/// The marker standing in for a mistakenly pasted secret.
const MARKER: &str = "S3cr3tMarkerQ7";

fn assert_no_echo(daemon: Daemon, input: &[u8]) {
    let err = daemon
        .parse(input)
        .expect_err("the marked input must be rejected");
    let shown = format!("{err} / {err:?}").to_ascii_lowercase();
    assert!(
        !shown.contains(&MARKER.to_ascii_lowercase()),
        "error echoes input: {shown}"
    );
    if let Some(key) = err.key() {
        assert!(daemon.keys().contains(&key), "key is from the schema table");
    }
}

fn check(daemon: Daemon, text: &str) {
    assert_no_echo(daemon, text.as_bytes());
}

/// Unknown key: neither its name nor its value is echoed.
/// Spec: docs/50 R50-15, §7.1; AGENTS.md §6.
#[test]
fn unknown_key_is_not_echoed() {
    check(Daemon::Keyd, &append(KEYD, &format!("password = {MARKER}")));
    check(
        Daemon::Keyd,
        &append(KEYD, &format!("{} = 1", MARKER.to_ascii_lowercase())),
    );
}

/// Malformed lines: a bare secret on a line, or a mis-spaced entry.
/// Spec: docs/50 R50-15; AGENTS.md §6.
#[test]
fn malformed_line_is_not_echoed() {
    check(Daemon::Keyd, &append(KEYD, MARKER));
    check(
        Daemon::Keyd,
        &replace(KEYD, "realm", &format!("realm={MARKER}")),
    );
    check(
        Daemon::Keyd,
        &replace(KEYD, "realm", &format!(" realm = {MARKER}")),
    );
    check(
        Daemon::Keyd,
        &replace(KEYD, "realm", &format!("realm = {MARKER} ")),
    );
    check(Daemon::Keyd, &append(KEYD, &format!("[{MARKER}]")));
}

/// Values of the wrong type, for every value type.
/// Spec: docs/50 §7.1 ("every value typed"); AGENTS.md §6.
#[test]
fn bad_values_are_not_echoed() {
    let m = MARKER;
    let cases: Vec<(Daemon, &str, &str, String)> = vec![
        (Daemon::Keyd, KEYD, "run_as_uid", m.to_owned()),
        (Daemon::Keyd, KEYD, "frame_timeout", format!("{m}s")),
        (Daemon::Keyd, KEYD, "max_connections_per_uid", m.to_owned()),
        (Daemon::Keyd, KEYD, "keyd_socket", m.to_owned()),
        (Daemon::Keyd, KEYD, "keyd_socket", format!("/run/{m}/../x")),
        (Daemon::Keyd, KEYD, "realm", format!("{m}!")),
        (Daemon::Keyd, KEYD, "uid_roles", format!("803:{m}")),
        (Daemon::Keyd, KEYD, "uid_roles", format!("{m}:Kdc")),
        (Daemon::Keyd, KEYD, "key_store", m.to_owned()),
        (Daemon::Dird, DIRD, "naming_context", format!("dc={m}!")),
        (
            Daemon::LdapFront,
            LDAP_FRONT,
            "internal_networks",
            format!("{m}/8"),
        ),
        (Daemon::Kdc, KDC, "listen", format!("{m}:88")),
        (Daemon::Kdc, KDC, "listen", format!("10.0.0.5:88,{m}")),
        (
            Daemon::LdapFront,
            LDAP_FRONT,
            "dird_deadline",
            format!("{m}s"),
        ),
    ];
    for (daemon, sample, key, value) in cases {
        check(daemon, &set(sample, key, &value));
    }
}

/// A duplicate key whose second value is the secret.
/// Spec: docs/50 §7.1; AGENTS.md §6.
#[test]
fn duplicate_key_is_not_echoed() {
    check(
        Daemon::Keyd,
        &append(KEYD, &format!("realm = {m}", m = MARKER)),
    );
}

/// A duplicate path, a duplicate list item, a duplicate uid.
/// Spec: docs/50 §3.1, §3.2; AGENTS.md §6.
#[test]
fn duplicates_are_not_echoed() {
    let path = format!("/run/{MARKER}");
    let text = set(&set(KDC, "keyd_socket", &path), "dird_kdc_socket", &path);
    check(Daemon::Kdc, &text);
    let net = format!("10.0.0.0/8, 10.0.0.0/8, {MARKER}");
    check(Daemon::Kdc, &set(KDC, "internal_networks", &net));
}

/// A non-printable octet next to the secret; an overlong value made of it; a
/// cut last line holding it. Spec: docs/50 §7.1; AGENTS.md §6.
#[test]
fn bound_and_character_errors_are_not_echoed() {
    check(Daemon::Keyd, &set(KEYD, "realm", &format!("{MARKER}\u{1}")));
    check(
        Daemon::Keyd,
        &set(KEYD, "realm", &format!("{MARKER}\u{e9}")),
    );
    check(Daemon::Keyd, &set(KEYD, "realm", &MARKER.repeat(70)));
    check(
        Daemon::Keyd,
        &append(KEYD, &format!("#{}", MARKER.repeat(80))),
    );
    let cut = format!("{}realm = {MARKER}", remove(KEYD, "realm"));
    check(Daemon::Keyd, &cut);
    let mut raw = KEYD.as_bytes().to_vec();
    raw.extend_from_slice(MARKER.as_bytes());
    raw.extend_from_slice(b"\xff\n");
    assert_no_echo(Daemon::Keyd, &raw);
}
