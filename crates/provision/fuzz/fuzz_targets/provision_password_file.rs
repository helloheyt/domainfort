#![no_main]
//! Fuzz target for the content rule of a first administrator's password
//! file (`provision::first_admin::password_file::parse_password_file`).
//!
//! AGENTS.md §6 (every parser gets a fuzz target before it merges to
//! main); docs/51 §12 task A6; docs/50 §9 (fuzz targets in detached
//! workspaces until P-1). On any octets the parser must return without
//! panicking, and:
//!
//! * content over 1024 octets is refused (docs/51 §4.4: "≤ 1024 bytes");
//! * an accepted password is not empty, at most 1024 octets, valid UTF-8,
//!   and holds no C0 control character and no DEL (Q-411 item 3);
//! * an accepted password is the content itself, or the content without
//!   its one final LF ("exactly one line").
//!
//! Spec: docs/51 §4.4; docs/questions/Q-411.

use libfuzzer_sys::fuzz_target;
use provision::first_admin::password_file::{parse_password_file, MAX_PASSWORD_FILE_OCTETS};

fuzz_target!(|data: &[u8]| {
    let result = parse_password_file(data);
    if data.len() > MAX_PASSWORD_FILE_OCTETS {
        assert!(result.is_err(), "the size bound is enforced");
    }
    if let Ok(password) = result {
        let text = password.expose().as_bytes();
        assert!(!text.is_empty());
        assert!(text.len() <= MAX_PASSWORD_FILE_OCTETS);
        assert!(text.iter().all(|&b| b >= 0x20 && b != 0x7F));
        assert!(text == data || (data.last() == Some(&b'\n') && text == &data[..data.len() - 1]));
    }
});
