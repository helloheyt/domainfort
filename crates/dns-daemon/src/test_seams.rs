//! The test seams of dnsd (docs/52 §3.18, class C18; task R15 pattern).
//!
//! **Not part of the product API.** This module exists only in a build with
//! the feature `test-seams`, which only `[dev-dependencies]` enable (cargo's
//! resolver 2 activates a dev-dependency's features only in builds of test
//! targets), and no product source names it. A product daemon is built only
//! from the configuration — [`crate::DaemonParams::from_settings`] — and run
//! by [`crate::serve`], which supplies every value below itself.
//!
//! The audit source is **not** a seam (task DN12, docs/questions/Q-960):
//! every build expects `audit::AUDIT_SOURCE` (`dnsd`); tests vary what the
//! auditd at the socket names instead.
//!
//! | seam | what it varies | production value (`crate::serve`) |
//! |---|---|---|
//! | [`DaemonParams::udp`], [`DaemonParams::tcp_messages`], [`DaemonParams::forwards`] | the rate limits (docs/54 §6.7) | `limits::UDP_LIMITS`, `TCP_MESSAGE_LIMITS`, `FORWARD_LIMITS` |
//! | [`DaemonParams::forward_queue_capacity`] | the forwarding queue | `limits::FORWARD_QUEUE_CAPACITY` |
//! | [`DaemonParams::refresh_interval`], [`DaemonParams::refresh_wait`], [`DaemonParams::forward_answer_timeout`], [`DaemonParams::dird_deadline`] | the dird timings | `limits::REFRESH_INTERVAL`, `REFRESH_WAIT`, `FORWARD_ANSWER_TIMEOUT`, `DIRD_DEADLINE` |
//! | [`DaemonParams::tcp`], [`DaemonParams::zone_image_max_age`] | any value, also below the configuration's floors | the configuration's |
//! | [`serve`]'s connectors | the transport to dird | `ipc_dns::UnixConnector` |
//! | [`serve`]'s clock | the staleness clock | `clock::MonotonicClock` |
//!
//! Spec: docs/52 §3.18, §7 R15; docs/questions/Q-570.
//!
//! Written only from this project's documents (docs/52 §3.18, §7 R15; the
//! questions cited) and this repository's own code (the kdc-daemon and
//! ldap-front seams as the pattern). No other implementation was consulted
//! or recalled (docs/CLEAN-ROOM.md).

pub use crate::daemon::{serve_with as serve, ServeParams as DaemonParams};
