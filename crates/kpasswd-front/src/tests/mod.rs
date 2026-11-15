//! The tests that run the front's real start path, `serve_with`, end to end
//! with a stand-in audit source — no kpasswd-front audit source exists yet
//! (docs/questions/Q-955 item 1). They are crate-internal `#[cfg(test)]`
//! modules under a `tests/` directory, not a test seam: no build of any
//! other crate can reach the entry that takes the source (docs/52 C18), and
//! the workspace's source-scan guards treat them as test code (crates/
//! e2e-tests `no_test_seams_in_product.rs`; crates/protected-file
//! `single_open_path.rs`). Sources: see each module.

mod front;
mod startup;
mod world;
