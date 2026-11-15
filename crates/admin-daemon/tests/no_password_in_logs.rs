//! The password is never in any log line, event or file (docs/51 §7.6: "the
//! password never reaches dird"; docs/50 §3.3, §8.2; AGENTS.md §6: "secrets
//! never in logs, panics, debug output, or error messages").
//!
//! The whole world of tests/support (auditd, two keyds, dird, admind) runs
//! in a CHILD process of this test binary — this very test, re-run with a
//! marker in its environment — so that every line any of the daemons
//! writes to stderr or stdout is captured by the parent. The child runs
//! password operations that succeed, that break each rule, and a malformed
//! frame that carries a password; then it scans every file the world left
//! (the directory, auditd's verified log segments, everything in the test
//! directories) for the passwords' octets. The parent scans everything the
//! child printed.
//!
//! Sources: docs/51 §5.7, §7.6; docs/50 §3.3, §8.2; docs/37 §2. Every value
//! is constructed by hand for this test.

mod support;

use ipc_admin::{Request, SetPassword};
use std::process::Command;
use support::{begin_auth, completion, g, Got, Options, World, BOB, WS9};
use zeroize::Zeroizing;

/// The marker that makes this test run the scenario (the child).
const CHILD: &str = "ADMIND_A9_PASSWORD_LOG_CHILD";

/// The child's last line when the scenario ran to its end.
const DONE: &str = "A9-PASSWORD-SCENARIO-DONE";

/// The passwords the scenario uses (test data); none may appear anywhere.
const PASSWORDS: [&str; 5] = [
    "Velvet-Harbor-Quince-58",
    "Tiny-Pw-9",
    "Lantern-BOB-Quartz-33",
    "Cobalt-Meadow-Ferry-17",
    "Malformed-Frame-Secret-Pw",
];

fn set_password(target: dtyp::Guid, text: &str) -> Request {
    Request::SetPassword(SetPassword {
        auth: begin_auth("admin1", target),
        completion: completion("admin1", target),
        target,
        password: ipc_admin::Password::new(Zeroizing::new(text.to_owned())),
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The child: password operations, then a scan of every file.
fn scenario() {
    let Some(mut world) = World::new(Options::default()) else {
        println!("skipped: running as root");
        return;
    };
    let mut conn = world.connect();
    assert!(matches!(
        conn.call(&set_password(g(BOB), PASSWORDS[0])),
        Got::Reply(ipc_admin::Reply::PasswordChanged(_))
    ));
    assert_eq!(
        conn.call(&set_password(g(BOB), PASSWORDS[1])),
        Got::Reply(ipc_admin::Reply::Refused(ipc_admin::RefusalStatus::Invalid))
    );
    assert_eq!(
        conn.call(&set_password(g(BOB), PASSWORDS[2])),
        Got::Reply(ipc_admin::Reply::Refused(ipc_admin::RefusalStatus::Invalid))
    );
    assert!(matches!(
        conn.call(&set_password(g(WS9), PASSWORDS[3])),
        Got::Reply(ipc_admin::Reply::PasswordChanged(_))
    ));
    // A SetPassword frame with a trailing octet: malformed, refused, closed
    // — a noise event naming the rule, never an octet of the frame.
    let frame = ipc_admin::encode_request(&set_password(g(BOB), PASSWORDS[4])).unwrap();
    let mut octets = frame.as_bytes().to_vec();
    octets.push(0);
    let length = u32::try_from(octets.len() - 4).unwrap();
    octets[..4].copy_from_slice(&length.to_be_bytes());
    let mut bad = world.connect();
    bad.send_raw(&octets);
    assert_eq!(bad.receive(), Got::Refused(ipc::Refused::Malformed));
    let events = world.finish();
    assert!(!events.is_empty());
    let printed = format!("{events:?}");
    let mut scanned = 0usize;
    for (path, contents) in world.all_file_octets() {
        scanned += 1;
        for password in PASSWORDS {
            assert!(
                !contains(&contents, password.as_bytes()),
                "a password in {path:?}"
            );
        }
    }
    for password in PASSWORDS {
        assert!(!printed.contains(password));
    }
    assert!(scanned >= 2, "the directory and auditd's log were scanned");
    println!("{DONE} files={scanned}");
}

/// docs/50 §8.2; AGENTS.md §6: no password in anything any daemon printed,
/// in admind's events, or in any file the world wrote.
#[test]
fn the_password_is_never_logged() {
    if std::env::var_os(CHILD).is_some() {
        scenario();
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "the_password_is_never_logged",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let mut everything = output.stdout.clone();
    everything.extend_from_slice(&output.stderr);
    let text = String::from_utf8_lossy(&everything);
    assert!(output.status.success(), "the child failed:\n{text}");
    if text.contains("skipped: running as root") {
        return;
    }
    assert!(text.contains(DONE), "the scenario ran to its end:\n{text}");
    // The daemons' own lines were captured (positive control).
    for line in [
        "admin-daemon: listening on the admin socket",
        "admin-daemon: connection closed: frame did not decode",
        "directory-daemon: listening",
        "keyd-daemon: listening",
    ] {
        assert!(text.contains(line), "{line} not captured:\n{text}");
    }
    for password in PASSWORDS {
        assert!(
            !contains(&everything, password.as_bytes()),
            "{password} printed"
        );
    }
}
