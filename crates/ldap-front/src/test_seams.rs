//! The test seams of ldap-front (docs/52 §3.18, class C18; task R15).
//!
//! **Not part of the product API.** This module exists only in a build with
//! the feature `test-seams`, which only `[dev-dependencies]` enable (cargo's
//! resolver 2 activates a dev-dependency's features only in builds of test
//! targets), and no product source names it (the source scan in crates/e2e-tests
//! `tests/no_test_seams_in_product.rs`). A product front is built only from
//! its configuration — [`crate::FrontParams::from_settings`] — and run by
//! [`crate::serve`], which supplies every value below itself.
//!
//! | seam | what it varies | production value (`crate::serve`) |
//! |---|---|---|
//! | [`FrontParams::timeouts`]`.client_write` | one write to the client | `CLIENT_WRITE_TIMEOUT` |
//! | [`FrontParams::limits`] | the global, per-source and unauthenticated connection bounds | `ConnectionLimits::DEFAULT` |
//!
//! Spec: docs/52 §3.18, §7 R15; docs/questions/Q-570.
//!
//! Written only from this project's documents (docs/52 §3.18, §7 R15; the
//! questions cited; the dev-only feature precedent of docs/questions/Q-500
//! item 6, A-107) and this repository's own code. No other implementation
//! was consulted or recalled (AGENTS.md §1-3).

pub use crate::daemon::{serve_with as serve, ServeParams as FrontParams};
