#![forbid(unsafe_code)]
//! `kpasswd-front`: the network front of the Kerberos change-password
//! service, RFC 3244 on TCP 464 (docs/53 R53-3, R53-4, §3.3, §5.1, §5.7;
//! decision A-117; build task K8).
//!
//! The front owns the TCP socket and the RFC 3244 framing; everything else
//! is dird's and keyd's (docs/53 §4.2 option D): dird decides and writes,
//! keyd verifies the AP-REQ, **alone decrypts the KRB-PRIV** (the new
//! password), installs, and seals the reply (docs/53 §4.3). The front holds
//! **no key, no store and no keyd channel** — it links no krb-crypto, keyd,
//! keyd-types, ipc-keyd, dirstore, redb or directory crate
//! (`tests/holds_no_key.rs`, with a positive control) — and so cannot read
//! the password, forge a request (that needs a ticket) or forge a success
//! (that needs the subkey) (docs/53 §8, "front compromised").
//!
//! # Start-up (as built; docs/50 R50-14, R50-16, §6.2, §7.5)
//!
//! 1. claim the `SingleThreadProof` — the first statement of `main`;
//! 2. read the configuration path from argv and parse
//!    `KpasswdFrontSettings` ([`startup::read_settings`]: root-owned, not
//!    group/other-writable, bounded);
//! 3. as root, before the drop: bind the TCP listeners
//!    ([`startup::bind_listeners`]; **no UDP socket** — A-117);
//! 4. apply the hardening plan ([`startup::hardening_plan`]) while the
//!    process has one thread (R50-14);
//! 5. only then build the tokio runtime (current-thread) and run [`serve`]:
//!    every listener inside the internal networks, the realm valid, auditd
//!    verified (its uid, and a `Pong` naming the front's own source
//!    `kpasswd-front` — [`audit`]; task DN12, docs/questions/Q-955 item 1,
//!    Q-960) and that connection kept, dird verified on the
//!    kpasswd channel (`Ping` → `Pong` naming the internal zone), and only
//!    now are the listeners served — with the audit link attached to the
//!    kept connection, delivering the front's noise counts as
//!    `WindowSummary` events, at most one per heartbeat ([`audit`];
//!    docs/questions/Q-961 item 7, Q-988).
//!
//! # Per connection ([`connection`] module)
//!
//! Source inside `internal_networks` and a connection slot, or closed
//! without a byte → the 4-octet TCP header bounded before any allocation →
//! the message within the first-frame deadline → `RequestMessage::parse`
//! (0xff80 only: another version ⇒ BAD_VERSION; any other framing failure ⇒
//! MALFORMED) → the AP-REQ and KRB-PRIV by their identifier octets → dird
//! (a free channel slot or HARDERROR) → keyd's sealed reply relayed, or the
//! front's KRB-ERROR (dird's code, or HARDERROR when dird does not serve) →
//! the reply written within its bound → close.
//!
//! | case | the front answers | counted (noise ⇒ also `WindowSummary`, [`log`]) |
//! |---|---|---|
//! | source outside `internal_networks` | nothing — closed before a byte | `source_not_internal` — noise |
//! | global / per-source connection bound reached | nothing — closed before a byte | `connection_limited` — noise |
//! | header or message not whole within `tcp_first_frame_timeout`, or the client closed first | nothing — closed | `timed_out` — noise |
//! | TCP header announcing < 6 or > 65,535 octets | KRB-ERROR MALFORMED (1), before any allocation | `malformed` — noise |
//! | any other framing failure (length fields, `AP_REQ length` 0, empty KRB-PRIV) | KRB-ERROR MALFORMED (1) | `malformed` — noise |
//! | `protocol version number` ≠ 0xff80 (version 1 included) | KRB-ERROR BAD_VERSION (6) | `bad_version` — noise |
//! | the messages are not an AP-REQ and a KRB-PRIV (identifier octets) | KRB-ERROR MALFORMED (1) | `malformed` — noise |
//! | every dird channel slot in use | KRB-ERROR HARDERROR (2) | `dird_busy` — noise |
//! | dird not serving (down, wrong uid / zone, refusal, deadline, unknown outcome) | KRB-ERROR HARDERROR (2) | `dird_not_serving` — operational log only |
//! | dird's `Unsealed { code }` | KRB-ERROR with that code (2 or 3) | — (dird audits) |
//! | dird's `Sealed` | keyd's AP-REP + KRB-PRIV, unchanged | — (dird and keyd audit) |
//!
//! Every KRB-ERROR: `error-code` KRB_ERR_GENERIC (60), `e-data` the 2-octet
//! result code, no result string, no e-text / crealm / cname / ctime /
//! cusec; never result code 0 (the type cannot hold it) — [`reply`].
//!
//! # Modules
//!
//! | module | what |
//! |---|---|
//! | [`connection`] | one client connection: framing, timeouts, the dird call, the reply |
//! | [`reply`] | the KRB-ERROR encoder and the framing of keyd's sealed reply |
//! | [`clock`] | the KRB-ERROR's server time |
//! | `daemon` | [`serve`], the start-up checks, accept loops, connection limits |
//! | [`audit`] | the start-up check of auditd (the front's own source, `kpasswd-front`), the audit link and the summary pace |
//! | [`startup`] | configuration, binding, hardening plan |
//! | [`log`] | fixed stderr messages and the counted events — noise and failures (docs/53 §9) |
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests. Nothing logged carries request octets, names, addresses or any
//! peer-supplied string (AGENTS.md §6; docs/53 §9; docs/50 §8.2); the
//! request buffer is wiped. Weak options have no code path: no UDP
//! (A-117), no version 1 (P-31 open; A-142), no result string, no
//! unauthenticated success.
//!
//! # Residuals (documented, not hidden)
//!
//! - The front's audit is counts only: its noise as `WindowSummary` counts
//!   (`suppressed_noise`, at most one summary per heartbeat — docs/53 §9,
//!   A-57; docs/questions/Q-961 item 7, Q-988), no record per connection,
//!   no breakdown by kind on the log (the kinds are on stderr). Counts the
//!   stop's bounded flush cannot deliver (auditd unreachable, or the grace
//!   spent) are lost with the process; they remain on the operational log.
//!   The product front starts once auditd's `uid_sources` maps its uid to
//!   `kpasswd-front` (task DN12); provisioning that entry is task K9's.
//! - A compromised front can drop, delay or forge a KRB-ERROR (confusion
//!   only — RFC 4120 §5.9), lie about the client's address (skipping only
//!   keyd's `s-address` check) and relay other hosts' requests in its own
//!   rights (docs/53 §8; Q-603 item 8; A-114).
//! - The realm is configured in the front's file as in dird's and keyd's
//!   (Q-955 item 4). The service name and the clock conversion are no
//!   longer the front's: they are krb-proto's one definitions
//!   (`CHANGE_PASSWORD_SERVICE_NAME`, `kerberos_time_from_unix` — Q-955
//!   item 5, A-158; Q-987).
//! - SIGTERM is not handled; no chroot, no seccomp / landlock / namespaces
//!   (Q-216, P-19). The code has never run on Linux (P-27).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! AGENT-ONBOARDING, AGENTS, docs/53 (all; esp. R53-2, R53-3, R53-4, §3.2,
//! §3.3, §4, §5.1, §5.5–§5.9, §8, §9, §10 K8), docs/50 (R50-3, R50-14,
//! R50-16, R50-17; §3.1–§3.7; §4.1; §6; §7.1, §7.5; §8.1, §8.2), docs/52 §7
//! R14, docs/research/r3-e (§3), docs/questions PENDING-OWNER (A-57, A-87,
//! A-114, A-117, A-121, A-126, A-142, A-151, A-156, A-158, A-160),
//! Q-600..Q-605, Q-609, Q-620, Q-621, Q-660..Q-664, Q-830, Q-831, Q-945,
//! Q-955, Q-960, Q-961, Q-987, Q-988; crates/dns-daemon's audit (the house
//! pattern of a counters-only sender — this project's own code); RFC 3244
//! §2 (pinned, SHA-256
//! `45b9130f…dec378`, re-verified this session); RFC 4120 (pinned,
//! `368d3cd1…f75b`) §5.2.3, §5.9, §5.9.1, §6.2, §7.2.2, §7.5.9; ITU-T X.680
//! 46.2–46.3 as krb-proto cites them; the public API of this project's
//! crates parse-kpasswd, krb-proto, ipc-kpasswd, ipc-audit,
//! ipc-audit-client, config, daemon-sandbox, protected-file (ldap-front and
//! kdc-daemon as the pattern); and the docs.rs API pages of tokio 1.54.1
//! and zeroize 1.9.1 — API documentation only, never source (P-2). No other
//! implementation, kpasswd server, daemon or server framework was consulted
//! or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/53 R53-2, R53-3, R53-4, §3.3, §5.1, §5.7, §9, §10 (K8); RFC
//! 3244 §2; RFC 4120 §5.9.1; A-57; A-117; A-121; A-142; A-160.

pub mod audit;
pub mod clock;
pub mod connection;
mod daemon;
pub mod log;
pub mod reply;
pub mod startup;

pub use daemon::{
    serve, ConnectionLimits, DaemonControl, DaemonError, Endpoint, FrontParams, Listeners, Timeouts,
};
pub use log::Counts;

// The tests that run `serve` end to end against a test dird and a test (or
// the real) auditd. They are crate-internal `#[cfg(test)]` modules; since
// task DN12 they run the product entry itself — there is no test seam
// (docs/52 C18). Sources: see each module.
#[cfg(test)]
mod tests;
