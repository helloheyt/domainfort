//! The test seams of the kdc daemon (docs/52 §3.18, class C18; task R15).
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
//! | [`DaemonParams::udp`] | the UDP limits (docs/questions/Q-223) | `rate::UDP_LIMITS` (crate rate-limit's `SourceLimits`, task DN3) |
//! | [`DaemonParams::as_queue_capacity`], [`DaemonParams::tgs_queue_capacity`] | the request queues (R50-9) | `AS_QUEUE_CAPACITY`, `TGS_QUEUE_CAPACITY` |
//! | [`DaemonParams::window`] | the audit window (A-57) | `WindowConfig::DEFAULT` |
//! | [`DaemonParams::udp_max_reply_len`] | the UDP reply bound (RFC 4120 §7.2.1) | `kdc::DEFAULT_UDP_MAX_REPLY_LEN` |
//! | [`serve`]'s connectors | the transport to keyd and dird | `ipc_keyd::UnixConnector`, `ipc_directory::UnixConnector` |
//! | [`serve`]'s clock | the kdc's clock | the system clock |
//!
//! Spec: docs/52 §3.18, §7 R15; docs/questions/Q-570.
//!
//! Written only from this project's documents (docs/52 §3.18, §7 R15; the
//! questions cited; the dev-only feature precedent of docs/questions/Q-500
//! item 6, A-107) and this repository's own code. No other implementation
//! was consulted or recalled (docs/CLEAN-ROOM.md).

pub use crate::daemon::{serve_with as serve, ServeParams as DaemonParams};
