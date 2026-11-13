//! Every format and schema rule rejects what it must, with its typed error,
//! its line and its key.
//!
//! Each test names its source: the docs/50 rule (R50-x / §x) or the Q-230
//! interpretation the input violates. Inputs are the `common` samples with
//! one line changed.

mod common;

use common::{append, remove, replace, set, Daemon, ADMIND, AUDITD, DIRD, KDC, KEYD, LDAP_FRONT};
use config::limits::{MAX_FILE_OCTETS, MAX_KEY_OCTETS, MAX_LINES, MAX_LINE_OCTETS};
use config::{
    AuditdSettings, DirdSettings, Error, ErrorKind, KdcSettings, KeydSettings, LdapFrontSettings,
};

/// The 1-based line of `key` in `text`.
fn line_of(text: &str, key: &str) -> Option<u32> {
    let prefix = format!("{key} = ");
    text.lines()
        .position(|line| line.starts_with(&prefix))
        .and_then(|index| u32::try_from(index + 1).ok())
}

/// The error of parsing `text` as `daemon`.
fn error(daemon: Daemon, text: &str) -> Error {
    daemon
        .parse(text.as_bytes())
        .expect_err("the input must be rejected")
}

/// `daemon`'s sample with `key` set to `value` is rejected with `kind`, at
/// `key`'s line, naming `key`.
fn rejects_value(daemon: Daemon, sample: &str, key: &'static str, value: &str, kind: ErrorKind) {
    let text = set(sample, key, value);
    let err = error(daemon, &text);
    assert_eq!(err.kind(), kind, "{daemon:?} {key} = {value}: {err}");
    assert_eq!(err.key(), Some(key), "{daemon:?} {key} = {value}");
    assert_eq!(
        err.line(),
        line_of(&text, key),
        "{daemon:?} {key} = {value}"
    );
}

/// `daemon`'s sample with `key` set to `value` is accepted.
fn accepts_value(daemon: Daemon, sample: &str, key: &str, value: &str) {
    let text = set(sample, key, value);
    assert_eq!(
        daemon.parse(text.as_bytes()),
        Ok(()),
        "{daemon:?} {key} = {value}"
    );
}

// ---- the closed key table ---------------------------------------------------

/// Spec: docs/50 R50-15 ("a closed key table per daemon"), §7.1 ("unknown key
/// ⇒ do not start").
#[test]
fn unknown_key_is_rejected() {
    let text = append(KEYD, "max_connections = 4");
    let err = error(Daemon::Keyd, &text);
    assert_eq!(err.kind(), ErrorKind::UnknownKey);
    assert_eq!(err.line(), u32::try_from(text.lines().count()).ok());
    assert_eq!(err.key(), None, "an unknown key is never echoed");
}

/// A key from another daemon's table is unknown here: each table is closed
/// per daemon. Spec: docs/50 R50-15, §7.1.
#[test]
fn another_daemons_key_is_unknown() {
    let err = error(Daemon::Kdc, &append(KDC, "uid_roles = 808:Kdc"));
    assert_eq!(err.kind(), ErrorKind::UnknownKey);
    let err = error(
        Daemon::LdapFront,
        &append(LDAP_FRONT, "listen = 10.0.0.5:88"),
    );
    assert_eq!(err.kind(), ErrorKind::UnknownKey);
}

/// There are no includes: an `include` line is just an unknown key.
/// Spec: docs/50 §7.1 ("no includes").
#[test]
fn include_is_an_unknown_key() {
    let err = error(
        Daemon::Dird,
        &append(DIRD, "include = /etc/domain/extra.conf"),
    );
    assert_eq!(err.kind(), ErrorKind::UnknownKey);
}

/// Spec: docs/50 §7.1 ("duplicate key ⇒ do not start") — even with the same
/// value, reported at the second occurrence.
#[test]
fn duplicate_key_is_rejected() {
    for (value, daemon, sample) in [
        ("EXAMPLE.TEST", Daemon::Keyd, KEYD),
        ("OTHER.TEST", Daemon::Keyd, KEYD),
    ] {
        let text = append(sample, &format!("realm = {value}"));
        let err = error(daemon, &text);
        assert_eq!(err.kind(), ErrorKind::DuplicateKey);
        assert_eq!(err.key(), Some("realm"));
        assert_eq!(err.line(), u32::try_from(text.lines().count()).ok());
    }
}

/// An empty file lacks every required key. Spec: docs/50 §7.1
/// ("missing-required ⇒ do not start").
#[test]
fn empty_file_is_missing_keys() {
    for &(daemon, ..) in common::ALL {
        let err = error(daemon, "");
        assert_eq!(err.kind(), ErrorKind::MissingKey, "{daemon:?}");
        assert_eq!(err.key(), Some("run_as_uid"));
    }
}

// ---- size bounds --------------------------------------------------------------

/// A file of exactly 64 KiB is accepted; one octet more is refused before any
/// line is read. Spec: docs/50 §7.1 ("file ≤ 64 KiB").
#[test]
fn file_size_bound() {
    let mut text = String::from(KEYD);
    while text.len() + MAX_LINE_OCTETS < MAX_FILE_OCTETS {
        text.push('#');
        text.push_str(&"x".repeat(MAX_LINE_OCTETS - 1));
        text.push('\n');
    }
    let rest = MAX_FILE_OCTETS - text.len();
    text.push('#');
    text.push_str(&"y".repeat(rest - 2));
    text.push('\n');
    assert_eq!(text.len(), MAX_FILE_OCTETS);
    assert!(text.lines().count() <= MAX_LINES);
    assert_eq!(Daemon::Keyd.parse(text.as_bytes()), Ok(()));
    let over = format!("#{text}");
    let err = error(Daemon::Keyd, &over);
    assert_eq!(err.kind(), ErrorKind::FileTooLarge);
    assert_eq!((err.line(), err.key()), (None, None));
}

/// 1024 lines are accepted; line 1025 is refused. Spec: AGENTS.md §6
/// (bounded parsers); docs/questions/Q-230 (MAX_LINES).
#[test]
fn line_count_bound() {
    let mut text = String::from(KEYD);
    while text.lines().count() < MAX_LINES {
        text.push('\n');
    }
    assert_eq!(Daemon::Keyd.parse(text.as_bytes()), Ok(()));
    text.push('\n');
    let err = error(Daemon::Keyd, &text);
    assert_eq!(err.kind(), ErrorKind::TooManyLines);
    assert_eq!(err.line(), u32::try_from(MAX_LINES + 1).ok());
}

/// A 1024-octet line is accepted; 1025 octets is refused. Spec: docs/50 §7.1
/// ("line ≤ 1024").
#[test]
fn line_length_bound() {
    let at_bound = format!("#{}", "c".repeat(MAX_LINE_OCTETS - 1));
    assert_eq!(
        Daemon::Keyd.parse(append(KEYD, &at_bound).as_bytes()),
        Ok(())
    );
    let over = format!("#{}", "c".repeat(MAX_LINE_OCTETS));
    let text = append(KEYD, &over);
    let err = error(Daemon::Keyd, &text);
    assert_eq!(err.kind(), ErrorKind::LineTooLong);
    assert_eq!(err.line(), u32::try_from(text.lines().count()).ok());
    // An overlong `key = value` line too.
    let err = error(
        Daemon::Keyd,
        &set(KEYD, "realm", &"R".repeat(MAX_LINE_OCTETS)),
    );
    assert_eq!(err.kind(), ErrorKind::LineTooLong);
}

/// Spec: AGENTS.md §6 (bounds); docs/questions/Q-230 (MAX_KEY_OCTETS).
#[test]
fn key_length_bound() {
    let long_key = "k".repeat(MAX_KEY_OCTETS + 1);
    let err = error(Daemon::Keyd, &append(KEYD, &format!("{long_key} = 1")));
    assert_eq!(err.kind(), ErrorKind::KeyTooLong);
    let at_bound = "k".repeat(MAX_KEY_OCTETS);
    let err = error(Daemon::Keyd, &append(KEYD, &format!("{at_bound} = 1")));
    assert_eq!(
        err.kind(),
        ErrorKind::UnknownKey,
        "a bounded key is looked up"
    );
}

/// A value longer than a maximal key would leave on a maximal line is
/// refused even though its line fits. Spec: docs/questions/Q-230
/// (MAX_VALUE_OCTETS).
#[test]
fn value_length_bound() {
    let max = config::limits::MAX_VALUE_OCTETS;
    accepts_value(Daemon::Keyd, KEYD, "realm", &"R".repeat(max));
    let text = set(KEYD, "realm", &"R".repeat(max + 1));
    assert!(text.lines().all(|line| line.len() <= MAX_LINE_OCTETS));
    let err = error(Daemon::Keyd, &text);
    assert_eq!(err.kind(), ErrorKind::ValueTooLong);
    assert_eq!(err.key(), Some("realm"));
}

// ---- characters ---------------------------------------------------------------

/// Non-UTF-8 octets, non-ASCII UTF-8, TAB, CR (CRLF line ends) and NUL are
/// all refused, at their line. Spec: docs/50 §7.1 ("printable ASCII only").
#[test]
fn non_printable_octets_are_rejected() {
    let base = KEYD.as_bytes();
    let line_count = u32::try_from(KEYD.lines().count()).unwrap_or(0);
    for bad in [
        &b"# \xff\xfe\n"[..],
        b"# \xc3\x28\n",
        "# caf\u{e9}\n".as_bytes(),
        b"#\tcomment\n",
        b"# comment\r\n",
        b"# nul\x00\n",
        b"\x7f\n",
    ] {
        let mut input = base.to_vec();
        input.extend_from_slice(bad);
        let err = Daemon::Keyd
            .parse(&input)
            .expect_err("a non-printable octet is rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidCharacter, "{bad:?}");
        assert_eq!(err.line(), Some(line_count + 1), "{bad:?}");
    }
    // Inside a value as well.
    let err = error(Daemon::Keyd, &set(KEYD, "realm", "EXAMPLE\u{2024}TEST"));
    assert_eq!(err.kind(), ErrorKind::InvalidCharacter);
    let err = error(Daemon::Keyd, &set(KEYD, "realm", "EXAMPLE\tTEST"));
    assert_eq!(err.kind(), ErrorKind::InvalidCharacter);
}

/// A file whose last line has no LF is a cut file: refused even when that
/// line would parse. Spec: docs/50 §7.1 (fail closed); Q-230 item 2.
#[test]
fn missing_final_newline_is_rejected() {
    let text = KEYD.trim_end_matches('\n');
    let err = error(Daemon::Keyd, text);
    assert_eq!(err.kind(), ErrorKind::MissingFinalNewline);
    assert_eq!(err.line(), u32::try_from(KEYD.lines().count()).ok());
}

// ---- line shape ---------------------------------------------------------------

/// Only `key = value` with single spaces, `#` in column 1, and truly empty
/// lines exist. Spec: docs/50 R50-15 ("`key = value`"), §7.1; Q-230 items 2,
/// 3.
#[test]
fn malformed_lines_are_rejected() {
    for line in [
        "realm=EXAMPLE.TEST",
        "realm =EXAMPLE.TEST",
        "realm= EXAMPLE.TEST",
        "realm  = EXAMPLE.TEST",
        " realm = EXAMPLE.TEST",
        "\u{20}",
        "  # indented comment",
        "[keyd]",
        "Realm = EXAMPLE.TEST",
        "_realm = EXAMPLE.TEST",
        "9realm = EXAMPLE.TEST",
        "realm-name = EXAMPLE.TEST",
        "realm =",
        "realm",
        "= EXAMPLE.TEST",
        "export realm = EXAMPLE.TEST",
    ] {
        let text = append(&remove(KEYD, "realm"), line);
        let err = error(Daemon::Keyd, &text);
        assert_eq!(err.kind(), ErrorKind::MalformedLine, "{line:?}");
        assert_eq!(err.line(), u32::try_from(text.lines().count()).ok());
    }
}

/// Space around a value, or an empty value, is malformed (no trimming).
/// Spec: docs/50 R50-15; docs/questions/Q-230 item 2.
#[test]
fn surrounding_space_and_empty_value_are_rejected() {
    for line in [
        "realm =  EXAMPLE.TEST",
        "realm = EXAMPLE.TEST ",
        "realm = ",
        "realm =   ",
    ] {
        let text = replace(KEYD, "realm", line);
        let err = error(Daemon::Keyd, &text);
        assert_eq!(err.kind(), ErrorKind::MalformedLine, "{line:?}");
        assert_eq!(err.key(), Some("realm"));
    }
}

/// There are no trailing comments: `#` after a value is part of the value,
/// which its type then refuses. Spec: docs/50 §7.1; Q-230 item 2.
#[test]
fn trailing_comment_is_part_of_the_value() {
    rejects_value(
        Daemon::Keyd,
        KEYD,
        "realm",
        "EXAMPLE.TEST # the realm",
        ErrorKind::InvalidRealm,
    );
    rejects_value(
        Daemon::Keyd,
        KEYD,
        "frame_timeout",
        "5s #",
        ErrorKind::InvalidDuration,
    );
}

// ---- integers, durations, account ids ---------------------------------------

/// Spec: docs/50 §7.1 ("integer in range"), §3.6 ("kdc ≤ 8"); Q-230 item 4.
#[test]
fn integers_are_canonical_and_in_range() {
    let key = "max_connections_per_uid";
    for value in ["eight", "08", "+8", "-1", "8.0", "0x8", "4294967296", "1_0"] {
        rejects_value(Daemon::Keyd, KEYD, key, value, ErrorKind::InvalidInteger);
    }
    rejects_value(Daemon::Keyd, KEYD, key, "0", ErrorKind::OutOfRange);
    rejects_value(Daemon::Keyd, KEYD, key, "9", ErrorKind::OutOfRange);
    rejects_value(Daemon::Keyd, KEYD, key, "4294967295", ErrorKind::OutOfRange);
    accepts_value(Daemon::Keyd, KEYD, key, "1");
    accepts_value(Daemon::Keyd, KEYD, key, "8");
}

/// Spec: docs/50 §7.1 ("a duration with a unit"), §3.6 (5 s); Q-230 items 4,
/// 13.
#[test]
fn durations_have_one_spelling_and_a_range() {
    let key = "frame_timeout";
    for value in [
        "5", "5ms", "5S", "05s", "s", "5 s", "5.0s", "1m", "5sec", "-5s",
    ] {
        rejects_value(Daemon::Keyd, KEYD, key, value, ErrorKind::InvalidDuration);
    }
    rejects_value(Daemon::Keyd, KEYD, key, "0s", ErrorKind::OutOfRange);
    rejects_value(Daemon::Keyd, KEYD, key, "6s", ErrorKind::OutOfRange);
    accepts_value(Daemon::Keyd, KEYD, key, "1s");
}

/// uid/gid 0 and the all-ones id are never accepted; names are not resolved.
/// Spec: docs/50 R50-3 ("uid 0 never mapped"), §7.1 ("uids/gids numeric — no
/// NSS lookup"); Q-230 item 6.
#[test]
fn account_ids_are_numeric_and_never_reserved() {
    for key in ["run_as_uid", "run_as_gid", "auditd_uid"] {
        rejects_value(Daemon::Keyd, KEYD, key, "0", ErrorKind::ReservedId);
        rejects_value(Daemon::Keyd, KEYD, key, "4294967295", ErrorKind::ReservedId);
        rejects_value(Daemon::Keyd, KEYD, key, "root", ErrorKind::InvalidInteger);
        rejects_value(Daemon::Keyd, KEYD, key, "-1", ErrorKind::InvalidInteger);
    }
    accepts_value(Daemon::Keyd, KEYD, "run_as_uid", "4294967294");
}

// ---- paths ------------------------------------------------------------------

/// Spec: docs/50 §7.1 ("absolute path"); Q-230 item 16.
#[test]
fn paths_are_canonical_and_absolute() {
    let key = "keyd_socket";
    for value in [
        "run/keyd/keyd.sock",
        "keyd.sock",
        "./keyd.sock",
        "/",
        "//run/keyd.sock",
        "/run//keyd.sock",
        "/run/keyd/",
        "/run/./keyd.sock",
        "/run/../etc/keyd.sock",
        "/run/..",
        "/run/key d.sock",
        "/run/keyd:sock",
        "/run/keyd\\sock",
        "/run/k*",
    ] {
        rejects_value(Daemon::Keyd, KEYD, key, value, ErrorKind::InvalidPath);
    }
    accepts_value(Daemon::Keyd, KEYD, key, "/run/keyd/.keyd-1_A.sock");
    accepts_value(Daemon::Keyd, KEYD, key, "/k");
}

/// Environment-looking values are rejected by every value type — never
/// expanded, never taken literally. Spec: docs/50 §7.1 ("no override from the
/// environment"); docs/21 D95; Q-230 item 9.
#[test]
fn environment_references_are_rejected_not_expanded() {
    let cases: &[(Daemon, &str, &'static str, &str, ErrorKind)] = &[
        (
            Daemon::Keyd,
            KEYD,
            "keyd_socket",
            "$HOME/keyd.sock",
            ErrorKind::InvalidPath,
        ),
        (
            Daemon::Keyd,
            KEYD,
            "keyd_socket",
            "${RUNTIME_DIRECTORY}/keyd.sock",
            ErrorKind::InvalidPath,
        ),
        (
            Daemon::Keyd,
            KEYD,
            "keyd_socket",
            "/run/$USER/keyd.sock",
            ErrorKind::InvalidPath,
        ),
        (
            Daemon::Keyd,
            KEYD,
            "keyd_socket",
            "~/keyd.sock",
            ErrorKind::InvalidPath,
        ),
        (
            Daemon::Keyd,
            KEYD,
            "keyd_socket",
            "/run/%t/keyd.sock",
            ErrorKind::InvalidPath,
        ),
        (
            Daemon::Keyd,
            KEYD,
            "run_as_uid",
            "$UID",
            ErrorKind::InvalidInteger,
        ),
        (
            Daemon::Keyd,
            KEYD,
            "realm",
            "$REALM",
            ErrorKind::InvalidRealm,
        ),
        (
            Daemon::Keyd,
            KEYD,
            "frame_timeout",
            "${TIMEOUT}s",
            ErrorKind::InvalidDuration,
        ),
        (
            Daemon::Keyd,
            KEYD,
            "uid_roles",
            "803:$ROLE",
            ErrorKind::UnknownName,
        ),
        (
            Daemon::Keyd,
            KEYD,
            "key_store",
            "$KEY_STORE",
            ErrorKind::UnknownName,
        ),
        (
            Daemon::Dird,
            DIRD,
            "naming_context",
            "dc=$DOMAIN,dc=test",
            ErrorKind::InvalidNamingContext,
        ),
        (
            Daemon::Kdc,
            KDC,
            "listen",
            "$LISTEN:88",
            ErrorKind::InvalidSocketAddress,
        ),
        (
            Daemon::Kdc,
            KDC,
            "internal_networks",
            "$NETWORK/8",
            ErrorKind::InvalidNetwork,
        ),
    ];
    for &(daemon, sample, key, value, kind) in cases {
        rejects_value(daemon, sample, key, value, kind);
    }
}

// ---- names ------------------------------------------------------------------

/// Spec: docs/50 §7.1 ("realm"); Q-230 item 15.
#[test]
fn realm_character_set() {
    for value in [
        "EXAMPLE TEST",
        "EXAMPLE/TEST",
        "EXAMPLE@TEST",
        "EXAMPLE:TEST",
    ] {
        rejects_value(Daemon::Keyd, KEYD, "realm", value, ErrorKind::InvalidRealm);
    }
    accepts_value(Daemon::Keyd, KEYD, "realm", "corp-1.example.test");
}

/// Spec: [MS-ADTS] 3.1.1.3.2.4 (dNSHostName); docs/questions/Q-280 item 6
/// (labels of `A-Z a-z 0-9 -` separated by single dots, at most 255
/// octets; a missing key is refused).
#[test]
fn dns_host_name_form() {
    let long = format!("{}.test", "a".repeat(251));
    for value in [
        "dc1..example.test",
        ".dc1.example.test",
        "dc1.example.test.",
        "dc1 example.test",
        "dc1_example.test",
        "dc1.ex@mple.test",
        long.as_str(),
    ] {
        rejects_value(
            Daemon::Dird,
            DIRD,
            "dns_host_name",
            value,
            ErrorKind::InvalidHostName,
        );
    }
    accepts_value(Daemon::Dird, DIRD, "dns_host_name", "DC-1.Example.test");
    accepts_value(Daemon::Dird, DIRD, "dns_host_name", "localhost");
    let err = error(Daemon::Dird, &remove(DIRD, "dns_host_name"));
    assert_eq!(err.kind(), ErrorKind::MissingKey);
}

/// Spec: docs/50 §7.1 ("naming context (A-53)"); PENDING-OWNER A-53 (no
/// space after a comma); crates/directory-pip `MAX_NC_LABELS`; Q-230 item 15.
#[test]
fn naming_context_form() {
    let key = "naming_context";
    for value in [
        "DC=example,dc=test",
        "dc=example, dc=test",
        "dc=example,,dc=test",
        "dc=,dc=test",
        "dc=example,",
        ",dc=test",
        "cn=users,dc=example,dc=test",
        "dc=ex.ample,dc=test",
        "dc=ex ample",
        "dc=example\\,x",
        "example.test",
        "dc = example",
    ] {
        rejects_value(
            Daemon::Dird,
            DIRD,
            key,
            value,
            ErrorKind::InvalidNamingContext,
        );
    }
    let sixteen = vec!["dc=a"; 16].join(",");
    accepts_value(Daemon::Dird, DIRD, key, &sixteen);
    let seventeen = vec!["dc=a"; 17].join(",");
    rejects_value(
        Daemon::Dird,
        DIRD,
        key,
        &seventeen,
        ErrorKind::InvalidNamingContext,
    );
    accepts_value(Daemon::Dird, DIRD, key, "dc=Corp-1");
}

/// Spec: docs/50 R50-18, §7.3 (insecure development is the only store until
/// P-17); Q-230 item 10.
#[test]
fn key_store_kind_is_a_fixed_name() {
    for value in [
        "production",
        "Insecure-Development",
        "insecure_development",
        "hsm",
    ] {
        rejects_value(
            Daemon::Keyd,
            KEYD,
            "key_store",
            value,
            ErrorKind::UnknownName,
        );
    }
}

/// Spec: docs/50 §7.2, §7.4; docs/questions/Q-213, Q-219 (A-57), Q-270
/// items 1-2: the dirstore integrity key comes only from the development
/// file, and the policy store is only the unsigned development format, each
/// named explicitly — no other spelling, no production kind yet.
#[test]
fn dird_development_sources_are_fixed_names() {
    for value in [
        "sealed",
        "Insecure-Development-File",
        "insecure_development_file",
        "file",
    ] {
        rejects_value(
            Daemon::Dird,
            DIRD,
            "integrity_key_source",
            value,
            ErrorKind::UnknownName,
        );
    }
    for value in ["signed", "Unsigned-Development", "unsigned", "none"] {
        rejects_value(
            Daemon::Dird,
            DIRD,
            "policy_store_format",
            value,
            ErrorKind::UnknownName,
        );
    }
}

/// Spec: docs/50 §7.2 (kdc and dird load the same file); A-68;
/// docs/questions/Q-270 item 2, Q-275 item 2: the kdc names the policy
/// store's format explicitly too — only the unsigned development format,
/// no other spelling, and never silently by default.
#[test]
fn kdc_policy_store_format_is_a_fixed_required_name() {
    for value in ["signed", "Unsigned-Development", "unsigned", "none"] {
        rejects_value(
            Daemon::Kdc,
            KDC,
            "policy_store_format",
            value,
            ErrorKind::UnknownName,
        );
    }
    let without = remove(KDC, "policy_store_format");
    assert!(KdcSettings::parse(without.as_bytes()).is_err());
}

// ---- keyd's uid → Role map -------------------------------------------------------

/// "uid 0 is never mapped". Spec: docs/50 R50-3, §3.2.
#[test]
fn role_map_rejects_uid_zero() {
    rejects_value(
        Daemon::Keyd,
        KEYD,
        "uid_roles",
        "0:Kdc",
        ErrorKind::ReservedId,
    );
    rejects_value(
        Daemon::Keyd,
        KEYD,
        "uid_roles",
        "803:Kdc, 0:Admin",
        ErrorKind::ReservedId,
    );
}

/// "Role אחד ל-uid"; "a uid that appears twice ⇒ keyd does not start".
/// Spec: docs/50 R50-3, §3.2.
#[test]
fn role_map_rejects_the_same_uid_twice() {
    for value in [
        "803:Kdc, 803:Admin",
        "803:Kdc, 803:Kdc",
        "803:Kdc, 806:Directory, 803:Ldap",
    ] {
        rejects_value(
            Daemon::Keyd,
            KEYD,
            "uid_roles",
            value,
            ErrorKind::DuplicateId,
        );
    }
}

/// Role names are exactly the keyd `Role` variants, case-sensitive.
/// Spec: docs/50 §3.2; crates/keyd authz.rs (`Role`).
#[test]
fn role_map_rejects_unknown_role_names() {
    for value in ["803:Root", "803:kdc", "803:KDC", "803:Ldap-front", "803:"] {
        rejects_value(
            Daemon::Keyd,
            KEYD,
            "uid_roles",
            value,
            ErrorKind::UnknownName,
        );
    }
}

/// Each role at most one uid in phase 1. Spec: docs/50 §2.4 (one account per
/// process), §4.1 ("no multiple engines in phase 1"); Q-230 item 5.
#[test]
fn role_map_rejects_the_same_role_twice() {
    rejects_value(
        Daemon::Keyd,
        KEYD,
        "uid_roles",
        "803:Kdc, 808:Kdc",
        ErrorKind::DuplicateEntry,
    );
}

/// Spec: docs/50 §3.2 (static map of `uid:Role` pairs); Q-230 items 5, 14.
#[test]
fn role_map_entry_shape() {
    for value in ["803", "803=Kdc", "Kdc:803", ":Kdc"] {
        let text = set(KEYD, "uid_roles", value);
        let err = error(Daemon::Keyd, &text);
        assert!(
            matches!(
                err.kind(),
                ErrorKind::InvalidMapEntry | ErrorKind::InvalidInteger
            ),
            "{value}: {err}"
        );
        assert_eq!(err.key(), Some("uid_roles"));
    }
    for value in [
        "803:Kdc,806:Directory",
        "803:Kdc,  806:Directory",
        "803 :Kdc",
        "803: Kdc",
    ] {
        rejects_value(
            Daemon::Keyd,
            KEYD,
            "uid_roles",
            value,
            ErrorKind::InvalidList,
        );
    }
}

/// A mapped uid may not be keyd's own uid or auditd's (every uid in a file
/// is a distinct account). Spec: docs/50 §2.4; Q-214 (A-57); Q-230 item 6.
#[test]
fn role_map_uid_must_differ_from_other_accounts() {
    // keyd's own uid (`run_as_uid`, line 2) — reported at the later line,
    // `uid_roles`.
    rejects_value(
        Daemon::Keyd,
        KEYD,
        "uid_roles",
        "801:Kdc",
        ErrorKind::DuplicateId,
    );
    // auditd's uid: `auditd_uid` comes after `uid_roles` in the sample, so
    // the later line is `auditd_uid`'s.
    let text = set(KEYD, "uid_roles", "805:Kdc");
    let err = error(Daemon::Keyd, &text);
    assert_eq!(err.kind(), ErrorKind::DuplicateId);
    assert_eq!(err.key(), Some("auditd_uid"));
    assert_eq!(err.line(), line_of(&text, "auditd_uid"));
}

/// A uid accepted in the map is the only one with that role; unmapped uids
/// and uid 0 have none. Spec: docs/50 §3.2.
#[test]
fn role_map_lookup_is_exact() {
    let s =
        KeydSettings::parse(set(KEYD, "uid_roles", "1000:Admin").as_bytes()).expect("valid file");
    assert_eq!(s.uid_roles().role_of(1000), Some(config::RoleName::Admin));
    for uid in [0, 1, 999, 1001, 803, u32::MAX] {
        assert_eq!(s.uid_roles().role_of(uid), None, "uid {uid}");
    }
}

// ---- auditd's uid → source map ---------------------------------------------------

/// Spec: docs/50 §3.2 (source set from the uid), R50-3 applied to auditd;
/// Q-230 items 5, 6.
#[test]
fn source_map_rules() {
    let key = "uid_sources";
    rejects_value(Daemon::Auditd, AUDITD, key, "0:keyd", ErrorKind::ReservedId);
    rejects_value(
        Daemon::Auditd,
        AUDITD,
        key,
        "801:keyd, 801:kdc",
        ErrorKind::DuplicateId,
    );
    rejects_value(
        Daemon::Auditd,
        AUDITD,
        key,
        "801:keyd, 808:keyd",
        ErrorKind::DuplicateEntry,
    );
    rejects_value(
        Daemon::Auditd,
        AUDITD,
        key,
        "801:ldap_front",
        ErrorKind::UnknownName,
    );
    rejects_value(
        Daemon::Auditd,
        AUDITD,
        key,
        "801:auditd",
        ErrorKind::UnknownName,
    );
    rejects_value(
        Daemon::Auditd,
        AUDITD,
        key,
        "801:Keyd",
        ErrorKind::UnknownName,
    );
    rejects_value(
        Daemon::Auditd,
        AUDITD,
        key,
        "805:kdc",
        ErrorKind::DuplicateId,
    );
    let s = AuditdSettings::parse(set(AUDITD, key, "900:kdc").as_bytes()).expect("valid");
    assert_eq!(
        s.uid_sources().source_of(900),
        Some(config::AuditSource::Kdc)
    );
}

// ---- addresses ----------------------------------------------------------------

/// Spec: docs/50 §7.1 ("listen addresses"), §4.1 ("bind to internal
/// interfaces only"); Q-230 item 7.
#[test]
fn listener_addresses() {
    let key = "listen";
    for value in [
        "10.0.0.5",
        "10.0.0.5:0",
        "10.0.0.5:088",
        "10.0.0.5:65536",
        "010.0.0.5:88",
        "10.0.0.5:kerberos",
        "kdc.example.test:88",
        "[FD00:1234::5]:88",
        "[fd00:1234:0:0:0:0:0:5]:88",
        "fd00:1234::5:88",
        "[fe80::1%2]:88",
        "[fe80::1%eth0]:88",
        "10.0.0.5:88:88",
    ] {
        rejects_value(
            Daemon::Kdc,
            KDC,
            key,
            value,
            ErrorKind::InvalidSocketAddress,
        );
    }
    for value in [
        "0.0.0.0:88",
        "[::]:88",
        "224.0.0.1:88",
        "[ff02::1]:88",
        "255.255.255.255:88",
    ] {
        rejects_value(
            Daemon::Kdc,
            KDC,
            key,
            value,
            ErrorKind::NotAnInterfaceAddress,
        );
    }
    rejects_value(
        Daemon::Kdc,
        KDC,
        key,
        "10.0.0.5:88, 10.0.0.5:88",
        ErrorKind::DuplicateEntry,
    );
    for value in [
        "10.0.0.5:88,10.0.0.6:88",
        "10.0.0.5:88,, 10.0.0.6:88",
        ", 10.0.0.5:88",
    ] {
        rejects_value(Daemon::Kdc, KDC, key, value, ErrorKind::InvalidList);
    }
    accepts_value(
        Daemon::Kdc,
        KDC,
        key,
        "[::1]:8888, 127.0.0.1:88, 10.0.0.5:89",
    );
}

/// Spec: AGENTS.md §6 (bounds); docs/questions/Q-230 (MAX_LIST_ITEMS = 32).
#[test]
fn list_item_bound() {
    let max = config::limits::MAX_LIST_ITEMS;
    let items = |n: usize| {
        (1..=n)
            .map(|i| format!("10.0.1.{i}:88"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    accepts_value(Daemon::Kdc, KDC, "listen", &items(max));
    rejects_value(
        Daemon::Kdc,
        KDC,
        "listen",
        &items(max + 1),
        ErrorKind::TooManyItems,
    );
}

/// Spec: docs/50 §7.1 ("CIDR"), §4.1 ("CIDR → IpScope::Internal"); Q-230
/// item 8.
#[test]
fn networks() {
    let key = "internal_networks";
    for value in [
        "10.0.0.0",
        "10.0.0.0/33",
        "fd00::/129",
        "10.0.0.0/08",
        "10.0.0.0/8/8",
        "10.0.0.0/",
        "/8",
        "10.0.0.0/-8",
        "FD00::/16",
        "10.0.0.0/8 ",
    ] {
        let text = set(KDC, key, value);
        let err = error(Daemon::Kdc, &text);
        assert!(
            matches!(
                err.kind(),
                ErrorKind::InvalidNetwork | ErrorKind::MalformedLine
            ),
            "{value}: {err}"
        );
        assert_eq!(err.key(), Some(key), "{value}");
    }
    for value in [
        "10.0.0.1/8",
        "192.168.10.128/24",
        "fd00:1234::1/32",
        "10.0.0.5/31",
    ] {
        rejects_value(Daemon::Kdc, KDC, key, value, ErrorKind::NetworkHostBits);
    }
    for value in ["0.0.0.0/0", "::/0"] {
        rejects_value(Daemon::Kdc, KDC, key, value, ErrorKind::NetworkTooBroad);
    }
    rejects_value(
        Daemon::Kdc,
        KDC,
        key,
        "10.0.0.0/8, 10.0.0.0/8",
        ErrorKind::DuplicateEntry,
    );
    accepts_value(
        Daemon::Kdc,
        KDC,
        key,
        "10.0.0.5/32, fd00:1234::5/128, 128.0.0.0/1",
    );
    accepts_value(Daemon::Kdc, KDC, key, "10.0.0.0/8, 10.1.0.0/16");
}

// ---- whole-file consistency ----------------------------------------------------

/// The same uid under two settings is refused at the later line.
/// Spec: docs/50 §2.4 (a separate account per process), §3.2; Q-214 (A-57);
/// Q-230 item 6.
#[test]
fn the_same_uid_under_two_settings_is_rejected() {
    // (daemon, sample, key changed, new value, the key it now collides with)
    let cases: &[(Daemon, &str, &str, &str, &str)] = &[
        (Daemon::Kdc, KDC, "dird_uid", "801", "keyd_uid"),
        (Daemon::Kdc, KDC, "keyd_uid", "803", "run_as_uid"),
        (Daemon::Kdc, KDC, "auditd_uid", "802", "dird_uid"),
        (Daemon::Dird, DIRD, "ldap_front_uid", "803", "kdc_uid"),
        (Daemon::Dird, DIRD, "admind_uid", "802", "run_as_uid"),
        (
            Daemon::LdapFront,
            LDAP_FRONT,
            "dird_uid",
            "804",
            "run_as_uid",
        ),
        (Daemon::Admind, ADMIND, "keyd_uid", "802", "dird_uid"),
    ];
    for &(daemon, sample, key, value, other) in cases {
        let text = set(sample, key, value);
        let err = error(daemon, &text);
        assert_eq!(err.kind(), ErrorKind::DuplicateId, "{daemon:?} {key}");
        let (line, other_line) = (line_of(&text, key), line_of(&text, other));
        let expected = if line >= other_line {
            (line, key)
        } else {
            (other_line, other)
        };
        assert_eq!(
            (err.line(), err.key()),
            (expected.0, Some(expected.1)),
            "{daemon:?}"
        );
    }
}

/// gids may be shared (socket groups, docs/50 §3.1); only uids must differ.
/// Spec: docs/50 §3.1, §2.4.
#[test]
fn gid_may_equal_another_daemons_uid() {
    accepts_value(Daemon::Kdc, KDC, "run_as_gid", "801");
}

/// The same path under two settings is refused.
/// Spec: docs/50 §3.1 (a socket per server and channel); Q-230 item 16.
#[test]
fn the_same_path_under_two_settings_is_rejected() {
    let cases: &[(Daemon, &str, &'static str, &str)] = &[
        (Daemon::Kdc, KDC, "dird_kdc_socket", "/run/keyd/keyd.sock"),
        (
            Daemon::Dird,
            DIRD,
            "policy_store_path",
            "/var/lib/dird/directory.redb",
        ),
        (
            Daemon::Dird,
            DIRD,
            "dird_ldap_socket",
            "/run/dird/kdc/dird-kdc.sock",
        ),
        (
            Daemon::Dird,
            DIRD,
            "dird_admin_socket",
            "/run/auditd/audit.sock",
        ),
        (
            Daemon::LdapFront,
            LDAP_FRONT,
            "tls_private_key_path",
            "/etc/ldap-front/dc-cert.der",
        ),
        (
            Daemon::Auditd,
            AUDITD,
            "audit_log_path",
            "/run/auditd/audit.sock",
        ),
        (
            Daemon::Admind,
            ADMIND,
            "admin_socket",
            "/run/keyd/keyd.sock",
        ),
    ];
    for &(daemon, sample, key, value) in cases {
        let err = error(daemon, &set(sample, key, value));
        assert_eq!(err.kind(), ErrorKind::DuplicatePath, "{daemon:?} {key}");
    }
}

/// The admin channel needs both its socket and its uid, or neither.
/// Spec: docs/50 §3.2; docs/questions/Q-220 (admind blocked); Q-230 item 11.
#[test]
fn dird_admin_pair_is_both_or_neither() {
    let text = remove(DIRD, "admind_uid");
    let err = error(Daemon::Dird, &text);
    assert_eq!(err.kind(), ErrorKind::IncompletePair);
    assert_eq!(err.key(), Some("dird_admin_socket"));
    assert_eq!(err.line(), line_of(&text, "dird_admin_socket"));
    let text = remove(DIRD, "dird_admin_socket");
    let err = error(Daemon::Dird, &text);
    assert_eq!(err.kind(), ErrorKind::IncompletePair);
    assert_eq!(err.key(), Some("admind_uid"));
    let both_removed = remove(&remove(DIRD, "dird_admin_socket"), "admind_uid");
    let s = DirdSettings::parse(both_removed.as_bytes()).expect("valid without admin");
    assert!(s.admin_channel().is_none());
}

/// The per-source TCP bound may not exceed the global one — including the
/// per-source default against a tightened global bound.
/// Spec: docs/50 §4.1; Q-230 item 4.
#[test]
fn kdc_connection_bounds_are_consistent() {
    let text = set(KDC, "max_tcp_connections", "4");
    let err = error(Daemon::Kdc, &text);
    assert_eq!(err.kind(), ErrorKind::InconsistentLimits);
    assert_eq!(err.key(), Some("max_tcp_connections_per_source"));
    let minimal = append(common::KDC_MINIMAL, "max_tcp_connections = 8");
    let err = error(Daemon::Kdc, &minimal);
    assert_eq!(err.kind(), ErrorKind::InconsistentLimits);
    assert_eq!(err.key(), Some("max_tcp_connections"));
    assert_eq!(err.line(), line_of(&minimal, "max_tcp_connections"));
    accepts_value(Daemon::Kdc, KDC, "max_tcp_connections", "8");
    rejects_value(
        Daemon::Kdc,
        KDC,
        "max_tcp_connections",
        "1025",
        ErrorKind::OutOfRange,
    );
    rejects_value(
        Daemon::Kdc,
        KDC,
        "max_tcp_connections_per_source",
        "17",
        ErrorKind::OutOfRange,
    );
}

/// Every kdc limit stops at its docs/50 value. Spec: docs/50 §3.6, §4.1;
/// Q-230 item 4.
#[test]
fn kdc_limits_stop_at_the_documented_value() {
    for (key, over) in [
        ("tcp_first_frame_timeout", "11s"),
        ("tcp_frame_timeout", "11s"),
        ("tcp_idle_timeout", "31s"),
        ("max_requests_per_tcp_connection", "65"),
        ("keyd_deadline", "3s"),
        ("dird_deadline", "3s"),
    ] {
        rejects_value(Daemon::Kdc, KDC, key, over, ErrorKind::OutOfRange);
    }
    rejects_value(
        Daemon::Dird,
        DIRD,
        "view_lifetime",
        "6s",
        ErrorKind::OutOfRange,
    );
}

/// ldap-front needs at least one listener; no address serves both 389 and
/// 636. Spec: docs/50 §4.2, §4.3; Q-230 item 7.
#[test]
fn ldap_front_listeners() {
    let none = remove(&remove(LDAP_FRONT, "ldap_listen"), "ldaps_listen");
    let err = error(Daemon::LdapFront, &none);
    assert_eq!(err.kind(), ErrorKind::NoListener);
    let text = set(LDAP_FRONT, "ldaps_listen", "10.0.0.5:389");
    let err = error(Daemon::LdapFront, &text);
    assert_eq!(err.kind(), ErrorKind::DuplicateEntry);
    assert_eq!(err.key(), Some("ldaps_listen"));
    let only_ldap = remove(LDAP_FRONT, "ldaps_listen");
    let s = LdapFrontSettings::parse(only_ldap.as_bytes()).expect("StartTLS only is valid");
    assert!(s.ldaps_listen().is_empty());
}

/// The dird-ldap deadline stays above the engine's 60-second query bound and
/// at most 65 s. Spec: docs/50 §3.6; crates/ldap `MAX_QUERY_SECONDS`.
#[test]
fn ldap_front_dird_deadline_range() {
    rejects_value(
        Daemon::LdapFront,
        LDAP_FRONT,
        "dird_deadline",
        "60s",
        ErrorKind::OutOfRange,
    );
    rejects_value(
        Daemon::LdapFront,
        LDAP_FRONT,
        "dird_deadline",
        "66s",
        ErrorKind::OutOfRange,
    );
    accepts_value(Daemon::LdapFront, LDAP_FRONT, "dird_deadline", "61s");
    for (key, over) in [
        ("init_recv_timeout", "31s"),
        ("max_conn_idle_time", "301s"),
        ("tls_handshake_timeout", "11s"),
    ] {
        rejects_value(
            Daemon::LdapFront,
            LDAP_FRONT,
            key,
            over,
            ErrorKind::OutOfRange,
        );
    }
}

/// A kdc file is not a keyd file: parsing one daemon's sample with another
/// daemon's schema fails closed. Spec: docs/50 R50-15 (closed table per
/// daemon).
#[test]
fn a_file_parses_only_as_its_own_daemon() {
    for &(daemon, sample, _) in common::ALL {
        for &(other, ..) in common::ALL {
            let result = other.parse(sample.as_bytes());
            assert_eq!(result.is_ok(), daemon == other, "{daemon:?} as {other:?}");
        }
    }
}

/// The message is fixed text: line, schema key name, rule — nothing else.
/// Spec: docs/50 §8.2 ("errors carry a code, not content"); AGENTS.md §6.
#[test]
fn error_display_is_fixed_text() {
    let err = KdcSettings::parse(set(KDC, "listen", "0.0.0.0:88").as_bytes())
        .expect_err("unspecified address");
    let line = line_of(KDC, "listen").unwrap_or(0);
    assert_eq!(
        err.to_string(),
        format!(
            "configuration line {line} key `listen`: listener address names no single interface"
        )
    );
}
