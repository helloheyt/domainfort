//! The test seams of admind (docs/52 §3.18, class C18; task R15).
//!
//! **Not part of the product API.** This module exists only in a build with
//! the feature `test-seams`, which only `[dev-dependencies]` enable (cargo's
//! resolver 2 activates a dev-dependency's features only in builds of test
//! targets), and no product source names it (the source scan in crates/e2e-tests
//! `tests/no_test_seams_in_product.rs`). A product admind is built only from
//! its configuration — [`crate::startup::params`] — and run by
//! [`crate::serve`], which supplies every value below itself.
//!
//! | seam | what it varies | production value (`crate::serve`) |
//! |---|---|---|
//! | [`DaemonParams::dird`], [`DaemonParams::keyd`] | the clients of dird and keyd — any [`crate::DirdLink`] / [`crate::KeydLink`] | [`crate::UnixDird`], [`crate::UnixKeyd`] |
//! | [`DaemonParams::limits`] | the per-uid limits of `admin.sock` | `Limits::DEFAULT` |
//! | [`DaemonParams::queue_capacity`] | the worker queue | `WORKER_QUEUE_CAPACITY` |
//! | [`DaemonParams::audit_window`] | admind's audit window (A-57) | `WindowConfig::DEFAULT` |
//!
//! Spec: docs/52 §3.18, §7 R15; docs/questions/Q-570.
//!
//! Written only from this project's documents (docs/52 §3.18, §7 R15; the
//! questions cited; the dev-only feature precedent of docs/questions/Q-500
//! item 6, A-107) and this repository's own code. No other implementation
//! was consulted or recalled (AGENTS.md §1-3).

pub use crate::daemon::{serve_with as serve, ServeParams as DaemonParams};
