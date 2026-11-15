//! The test seams of the keyd daemon (docs/52 §3.18, class C18; task R15).
//!
//! **Not part of the product API.** This module exists only in a build with
//! the feature `test-seams`, which only `[dev-dependencies]` enable (cargo's
//! resolver 2 activates a dev-dependency's features only in builds of test
//! targets), and no product source names it (the source scan in crates/e2e-tests
//! `tests/no_test_seams_in_product.rs`). A product daemon is built only from
//! the configuration — [`crate::DaemonParams::from_settings`] — and run by
//! [`crate::serve`], which supplies every value below itself.
//!
//! | seam | what it varies | production value (`crate::serve`) |
//! |---|---|---|
//! | [`DaemonParams::queue_capacity`] | the engine queue (R50-7) | `ENGINE_QUEUE_CAPACITY` |
//! | [`DaemonParams::window`] | the audit window (A-57) | `WindowConfig::DEFAULT` |
//! | [`DaemonParams::intent_ack_budget`] | the intent-acknowledgement wait (A-86), bounded by its type at `MAX_INTENT_ACK_BUDGET` (docs/questions/Q-415) | `IntentAckBudget::PRODUCTION` |
//! | [`DaemonParams::extra_listeners`] | more sockets on the same engine (docs/questions/Q-453) | none |
//! | [`serve`]'s clock | keyd's clock (R50-5) | the system clock |
//! | [`serve`]'s keyd builder | the key store and entropy source | the development store (R50-18; P-17), OS entropy |
//!
//! Spec: docs/52 §3.18, §7 R15; docs/questions/Q-415 (A-95), Q-453 (A-100),
//! Q-570.
//!
//! Written only from this project's documents (docs/52 §3.18, §7 R15; the
//! questions cited; the dev-only feature precedent of docs/questions/Q-500
//! item 6, A-107) and this repository's own code. No other implementation
//! was consulted or recalled (docs/CLEAN-ROOM.md).

pub use crate::daemon::{serve_with as serve, ExtraListener, ServeParams as DaemonParams};
