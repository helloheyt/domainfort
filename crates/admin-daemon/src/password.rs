//! admind's password rules — **keyd's** rule set (crate
//! `admin-password-policy`: the owner's rules, docs/56 §7 P-24, on top of
//! [MS-SAMR] 3.1.1.7.2), applied by admind as a non-authoritative pre-check;
//! keyd's install path is the one authoritative enforcement point
//! (docs/questions/Q-605, Q-664, Q-910).
//!
//! The rules live in that one crate, shared with keyd and with `provision
//! first-admin-secret`, so no caller can apply different or partial rules
//! (class C14, docs/52): the crate exposes only the whole set
//! ([`check_password`]) and its part on the password's text alone
//! ([`check_password_text`]).
//!
//! What admind applies (the worker's `SetPassword`, docs/51 §7.6):
//! [`check_password_text`] — the maximum, admind's `min_password_length`,
//! the character classes, no sequence, no repeat, no weak word — before
//! dird is asked anything, so a password refused on its text alone never
//! makes dird write `pwdLastSet`; then [`check_password`] with the inputs
//! keyd uses (the account's sAMAccountName and the realm of the binding
//! dird named — keyd binds every key set to its own realm) once dird has
//! named the account. Which rule failed is never reported
//! ([`PasswordRefused`]; docs/37 §2).
//!
//! Spec: [MS-SAMR] 3.1.1.7.2 items 1, 2, 3; docs/56 §7 (P-24); docs/51 §5.2
//! row 5, §7.6, §11; R51-5; A-79; docs/questions/Q-401, Q-410, Q-605,
//! Q-910 item 13.

pub use admin_password_policy::{
    check_password, check_password_text, PasswordRefused, PolicyInputs, MAX_PASSWORD_UTF16_UNITS,
};
