//! dird's kpasswd channel keys (task K7): `dird_kpasswd_socket` and
//! `kpasswd_front_uid` — both or neither, only beside the admin channel, a
//! uid and a path distinct from every other of the file.
//!
//! Sources: docs/53 §5.6 step 1 ("the peer on dird-kpasswd.sock = the
//! front's uid only (R50-3)"), step 4 (the kpasswd service shares the admin
//! channel's `ticket_age` threshold — R51-10); docs/50 R50-3, R50-15, §2.4
//! (one account per process), §3.1, §3.2; docs/questions/Q-955 item 13 (the
//! two keys; the front's file uses the same socket key), Q-230 items 6, 16.
//! The values are this test's own (obviously fake uids and paths); no vector
//! comes from any other implementation.

mod common;

use common::*;
use config::{DirdSettings, ErrorKind, KpasswdFrontSettings};

/// The full dird sample has the kpasswd channel (tests/common `DIRD`:
/// `/run/dird/kpasswd/dird-kpasswd.sock`, uid 807).
fn with_kpasswd() -> String {
    DIRD.to_owned()
}

/// The full sample without it.
fn without_kpasswd() -> String {
    remove(&remove(DIRD, "dird_kpasswd_socket"), "kpasswd_front_uid")
}

fn parse_error(text: &str) -> config::Error {
    DirdSettings::parse(text.as_bytes()).expect_err("refused")
}

/// The 1-based line of `key` in `text` (the line an error is reported at).
fn line_of(text: &str, key: &str) -> Option<u32> {
    let prefix = format!("{key} = ");
    text.lines()
        .position(|line| line.starts_with(&prefix))
        .and_then(|index| u32::try_from(index + 1).ok())
}

/// docs/53 §5.6 step 1; Q-955 item 13: both keys give the channel — its
/// socket and the one peer uid dird admits on it; neither is valid too (no
/// kpasswd service).
#[test]
fn the_kpasswd_channel_is_read() {
    let s = DirdSettings::parse(with_kpasswd().as_bytes()).expect("valid");
    let channel = s.kpasswd_channel().expect("configured");
    assert_eq!(
        channel.socket().as_path(),
        std::path::Path::new("/run/dird/kpasswd/dird-kpasswd.sock")
    );
    assert_eq!(channel.peer_uid(), 807);
    let s = DirdSettings::parse(without_kpasswd().as_bytes()).expect("valid without");
    assert!(s.kpasswd_channel().is_none());
    assert!(s.admin_channel().is_some());
}

/// docs/50 §3.2 (a channel is its socket and its one peer): one key alone is
/// refused at its own line (`IncompletePair`), never half-configured.
#[test]
fn the_kpasswd_pair_is_both_or_neither() {
    for (missing, key) in [
        ("kpasswd_front_uid", "dird_kpasswd_socket"),
        ("dird_kpasswd_socket", "kpasswd_front_uid"),
    ] {
        let text = remove(DIRD, missing);
        let err = parse_error(&text);
        assert_eq!(err.kind(), ErrorKind::IncompletePair, "{key}");
        assert_eq!(err.key(), Some(key));
        assert_eq!(err.line(), line_of(&text, key));
    }
}

/// docs/53 §5.6 step 4 (the admin channel's threshold — one rule): the
/// kpasswd channel without the admin channel is refused (`IncompletePair`,
/// at the earlier of its two lines), never silently ignored.
#[test]
fn the_kpasswd_channel_needs_the_admin_channel() {
    let mut text = remove(
        &remove(&remove(DIRD, "dird_admin_socket"), "admind_uid"),
        "policy_next_path",
    );
    for key in ["admin_ticket_age_max", "admin_quorum", "provision_manifest"] {
        text = remove(&text, key);
    }
    let without = remove(&remove(&text, "dird_kpasswd_socket"), "kpasswd_front_uid");
    DirdSettings::parse(without.as_bytes()).expect("valid without the admin channel");
    let err = parse_error(&text);
    assert_eq!(err.kind(), ErrorKind::IncompletePair);
    assert_eq!(err.key(), Some("dird_kpasswd_socket"));
    assert_eq!(err.line(), line_of(&text, "dird_kpasswd_socket"));
}

/// docs/50 R50-3 ("uid 0 is never mapped"), §2.4 (a separate account per
/// process), §3.1 (a socket per channel): the front's uid is never 0, never
/// another account of the file; the socket is never another path of it.
#[test]
fn the_front_uid_and_the_socket_are_distinct() {
    let err = parse_error(&set(&with_kpasswd(), "kpasswd_front_uid", "0"));
    assert_eq!(err.kind(), ErrorKind::ReservedId);
    for taken in ["802", "803", "804", "806", "801", "805"] {
        let err = parse_error(&set(&with_kpasswd(), "kpasswd_front_uid", taken));
        assert_eq!(err.kind(), ErrorKind::DuplicateId, "{taken}");
    }
    for taken in [
        "/run/dird/admin/dird-admin.sock",
        "/run/dird/ldap/dird-ldap.sock",
        "/run/keyd/keyd.sock",
    ] {
        let err = parse_error(&set(&with_kpasswd(), "dird_kpasswd_socket", taken));
        assert_eq!(err.kind(), ErrorKind::DuplicatePath, "{taken}");
    }
}

/// Q-955 item 13 ("the front's file uses the same key"): one spelling of the
/// socket key in both tables.
#[test]
fn the_socket_key_is_the_fronts() {
    assert!(DirdSettings::KEYS.contains(&"dird_kpasswd_socket"));
    assert!(KpasswdFrontSettings::KEYS.contains(&"dird_kpasswd_socket"));
    assert!(DirdSettings::KEYS.contains(&"kpasswd_front_uid"));
}
