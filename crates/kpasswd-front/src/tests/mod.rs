//! The tests that run the front's real start path — the product entry,
//! `serve`, with the product audit source (task DN12: the source is a
//! constant, so there is no test seam at all — docs/52 C18) — end to end
//! against a test dird and a test auditd, and, for the product start, the
//! real auditd. They are crate-internal `#[cfg(test)]` modules under a
//! `tests/` directory, which the workspace's source-scan guards treat as
//! test code (crates/e2e-tests `no_test_seams_in_product.rs`; crates/
//! protected-file `single_open_path.rs`). Sources: see each module.

/// crates/audit-daemon's tier-2 harness, reused through `#[path]` (as
/// crates/ldap-front's tests do): the **real** auditd listener and writer
/// over a log in a scratch directory.
#[path = "../../../audit-daemon/tests/common/mod.rs"]
mod auditd_support;
mod front;
mod startup;
mod world;
