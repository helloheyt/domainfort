//! Support of the end-to-end tests (task P12; docs/50 §9 tier 2 across all
//! daemons).
//!
//! * `kdcd` — crates/kdc-daemon's tier-2 support, reused through `#[path]`
//!   (it reuses crates/directory-daemon's, which reuses crates/keyd-daemon's
//!   in turn): the temporary directory, the test uid, the keyd / dird / kdc
//!   runners, the directory of the kdc fixtures' identities, the kdc side's
//!   connectors, and the RFC 4120 §7.2.1 / §7.2.2 client transport;
//! * `auditd` — crates/audit-daemon's tier-2 harness, reused through
//!   `#[path]`: the **real** auditd listener and writer;
//! * [`harness`] — the five daemons together ([`harness::Harness`]);
//! * [`tls`] / [`ldap_client`] — the LDAP client side (RFC 4511 over rustls);
//! * [`probes`] — one Kerberos request or one rootDSE, classified.
//!
//! Each test binary declares `mod common;` — the kdc crate's integration
//! fixtures (crates/kdc/tests/common: the Kerberos client of RFC 4120 /
//! RFC 6113) — at its root, as crates/kdc-daemon's tests do; the kdc
//! support refers to it as `crate::common`.
//!
//! Every piece reused is this project's own test-support code. No fixture,
//! vector or helper comes from any other implementation.
#![allow(dead_code, unused_imports)]

#[path = "../../../kdc-daemon/tests/support/mod.rs"]
pub mod kdcd;

#[path = "../../../audit-daemon/tests/common/mod.rs"]
pub mod auditd;

pub mod harness;
pub mod ldap_client;
pub mod probes;
pub mod tls;

pub use harness::*;
