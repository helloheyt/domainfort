#![forbid(unsafe_code)]
//! `config`: the strict, hand-parsed configuration of the phase-1 daemons
//! (docs/50 R50-15, §7.1; build task P2 of docs/50 §10).
//!
//! # Scope
//!
//! One file per daemon, each parsed by its own closed schema into a typed,
//! validated value:
//!
//! | daemon | type | docs/50 |
//! |---|---|---|
//! | keyd | [`KeydSettings`] | §2.4, R50-3 (the `uid → Role` map), R50-18 |
//! | dird | [`DirdSettings`] | §2.4, R50-2, §3.2, §3.4, §4.2, §7.2 |
//! | kdc | [`KdcSettings`] | §2.4, R50-9, §4.1, §7.2 |
//! | ldap-front | [`LdapFrontSettings`] | §2.4, R50-10, R50-12, §4.2, §5.3 |
//! | auditd | [`AuditdSettings`] | §2.4, R50-17, §8.1 |
//! | admind | [`AdmindSettings`] | §2.4 (blocked on Q-220) |
//!
//! Each type has `parse(&[u8])` and a public `KEYS` table. Parsing is pure: it
//! opens no file, reads no environment, resolves no name and checks no file
//! mode — the daemon does those (docs/50 §7.1: the configuration file is
//! root:0644; §5.3: the TLS key file is 0400), which also makes the parser a
//! fuzz target (docs/50 §9: `config_file`).
//!
//! # The format (docs/50 §7.1, option A)
//!
//! ```text
//! file    = *( line LF )                     ; ≤ 64 KiB, ≤ 1024 lines, ends with LF
//! line    = "" / "#" *pchar / key " = " value   ; ≤ 1024 octets
//! key     = lower *( lower / digit / "_" )   ; ≤ 48 octets, in the daemon's table
//! value   = vchar [ *pchar vchar ]           ; ≤ 973 octets, then typed per key
//! pchar   = %x20-7E ; vchar = %x21-7E        ; printable ASCII only
//! ```
//!
//! Strictness: unknown, duplicate and missing-required keys are refused;
//! every line has exactly one spelling (no indentation, no trailing space, `#`
//! only in the first column, no section headers — one file per daemon); every
//! value is typed (canonical integer in its documented range, duration `<n>s`,
//! numeric account id, canonical absolute path, realm, `dc=` naming context,
//! canonical socket address, canonical network `address/prefix`, a fixed name,
//! and `", "`-separated lists and `<uid>:<name>` maps of those). There is **no
//! environment interpolation and no include**: no value type admits `$`, so an
//! environment-looking value is rejected, never expanded (docs/50 §7.1: "no
//! override from the environment, no includes"). Details in [`limits`] and
//! docs/questions/Q-230.
//!
//! # No secrets
//!
//! No setting can hold a key, password, seed or token. Long-term keys live in
//! keyd's store (docs/50 §7.3); the DC's TLS key is an operator-supplied file
//! the configuration only **points to** (R50-12); the dirstore integrity key
//! is not a setting at all (§7.4, Q-213). docs/50 §7.1: "no secrets in the
//! configuration — only paths to protected files"; docs/21 D95: "secrets never
//! in argv/env". Errors never echo input (see [`Error`]).
//!
//! # Provenance
//!
//! Written only from the project's decided design docs/50 (A-58: R50-1 …
//! R50-20, §2.4, §3.1–§3.6, §4.1–§4.3, §5.3, §6, §7.1–§7.5, §8.1, §9, §10)
//! and the decisions it cites (docs/questions Q-213, Q-214, Q-219–Q-223 →
//! A-56/A-57; PENDING-OWNER A-36, A-53, A-55), plus the public API of this
//! project's crates `keyd` (`Role`), `directory-pip` (`NamingContext`) and
//! `ldap` (`MAX_QUERY_SECONDS`), all opened in-session (AGENTS.md §1-3). Socket
//! addresses and IP addresses are parsed and printed by the Rust standard
//! library (`core::net`), used through its API. No other implementation —
//! of this protocol stack or of any configuration format — was consulted or
//! recalled.
//!
//! Spec: docs/50 R50-15, §7.1, §10 (P2).

mod admind;
mod auditd;
mod dird;
mod error;
mod format;
mod kdc;
mod keyd;
mod ldap_front;
pub mod limits;
mod schema;
mod value;

pub use admind::AdmindSettings;
pub use auditd::{AuditSource, AuditdSettings, SourceMap};
pub use dird::{Channel, DirdSettings, VIEW_LIFETIME_SECS};
pub use error::{Error, ErrorKind};
pub use kdc::{
    KdcLimits, KdcSettings, DIRD_KDC_DEADLINE_SECS, MAX_REQUESTS_PER_TCP_CONNECTION_BOUND,
    MAX_TCP_CONNECTIONS_BOUND, MAX_TCP_CONNECTIONS_PER_SOURCE_BOUND, TCP_FIRST_FRAME_TIMEOUT_SECS,
    TCP_FRAME_TIMEOUT_SECS, TCP_IDLE_TIMEOUT_SECS,
};
pub use keyd::{KeyStoreKind, KeydSettings, RoleMap, RoleName, MAX_CONNECTIONS_PER_UID_BOUND};
pub use ldap_front::{
    LdapFrontLimits, LdapFrontSettings, DIRD_LDAP_DEADLINE_SECS, INIT_RECV_TIMEOUT_SECS,
    MAX_CONN_IDLE_TIME_SECS, TLS_HANDSHAKE_TIMEOUT_SECS,
};
pub use schema::{Account, Endpoint};
pub use value::{AbsolutePath, NamingContextLabels, Network, MAX_NAMING_CONTEXT_LABELS};
