//! admind's password rules — the cleartext password policy of [MS-SAMR]
//! 3.1.1.7.2 as phase 1 can apply it (docs/51 §11, the password row; R51-5;
//! decision A-79), checked before the password goes anywhere.
//!
//! The rules live in crate `admin-password-policy`, shared with
//! `provision first-admin-secret` (task A6: "the same rules admind
//! enforces"; docs/51 §4.4) so the two can never differ. They were written
//! here in task A9 and moved there unchanged, with their unit tests; this
//! module re-exports them under the names admind's worker has always used
//! (`password::check_length`, `password::check_account_name`).
//!
//! What admind applies (see the crate for the full readings, Q-401):
//! [`check_length`] — at most [`MAX_PASSWORD_UTF16_UNITS`] UTF-16 code units
//! and at least `min_password_length` code points — before dird is asked
//! anything; [`check_account_name`] — the sAMAccountName (more than
//! [`ACCOUNT_NAME_CHARS_CHECKED_ABOVE`] characters) not a case-insensitive
//! substring — once dird has named the account. Which rule failed is never
//! reported ([`PasswordRefused`]; docs/37 §2).
//!
//! Spec: [MS-SAMR] 3.1.1.7.2 items 1, 2, 3; docs/51 §5.2 row 5, §7.6, §11;
//! R51-5; A-79; P-24; docs/questions/Q-401, Q-410.

pub use admin_password_policy::{
    check_account_name, check_length, contains_account_name, PasswordRefused,
    ACCOUNT_NAME_CHARS_CHECKED_ABOVE, MAX_PASSWORD_UTF16_UNITS,
};
