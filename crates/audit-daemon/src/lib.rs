#![forbid(unsafe_code)]
//! `audit-daemon`: the auditd process (docs/50 R50-1, R50-17, §8, §10 task
//! P6b). The binary (`src/main.rs`) is a thin start-up sequence over this
//! library, so every part is testable in-process and over real temp-dir
//! sockets (docs/50 §9).
//!
//! | module | what | docs |
//! |---|---|---|
//! | [`startup`] | argument, configuration file checks, hardening plan, exit codes, the start-up order | docs/50 R50-14..R50-16, §6, §7 |
//! | [`recovery`] | verify every segment at start; recover a torn tail into a new segment; refuse a break | docs/50 §7.5; docs/37 §2; Q-250 item 8 |
//! | [`segments`] | segment file names next to `audit_log_path`; strict listing | Q-250 item 6; Q-265 item 2 |
//! | [`writer`] | the single writer thread, its bounded queue, ack after sync, rotation | docs/50 §3.6, §8.1; A-57 |
//! | [`listener`] | `audit.sock`: peer uid → source, frames, deadlines, `Append` / `Ping` | docs/50 R50-3, §3.1-§3.3, §3.6 |
//! | [`own_event`] | the payload of auditd's own records | docs/50 §3.2; Q-250 items 5, 8 |
//! | [`signing`] | the chain-head signing hook, UNSIGNED until P-20 | docs/37 §2; Q-251 |
//!
//! # Security
//!
//! No `unsafe`; no `unwrap`, `expect` or panic on a non-test path. The
//! event payloads are stored opaque (the senders' canonical encoding,
//! crate `ipc-audit`), are never printed, and no error or stderr line
//! carries them: stderr lines are fixed texts with codes and numbers
//! (docs/50 §8.2; AGENTS.md §6). There is no secret in this process at all
//! (the chain is unsigned in phase 1 — P-20).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! docs/50 (§1 R50-1, R50-3, R50-7, R50-14..R50-17; §2.4; §3.1-§3.3;
//! §3.6; §3.7; §6.1-§6.4; §7.1; §7.5; §8; §9; §10; the closing decision
//! A-58 and the channel-magic registry A-64), docs/37 (all), docs/07 §8,
//! docs/questions Q-218 (A-57), Q-230 (A-60), Q-235 (A-61), Q-250 / Q-252
//! (A-64), Q-251 and PENDING-OWNER (A-57, A-64, P-2, P-12, P-18, P-20); the
//! public API of this project's crates audit-log, ipc-audit, ipc, config and
//! daemon-sandbox; and the docs.rs API pages of tokio 1.54.1 (P-2; never its
//! source). No existing log daemon, journal or audit implementation was
//! consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/50 R50-17, §8, §10 (P6b); docs/37 §2; Q-218 (A-57);
//! Q-250 / Q-252 (A-64); Q-251 (P-20); Q-265.

pub mod listener;
pub mod own_event;
pub mod recovery;
pub mod segments;
pub mod signing;
pub mod startup;
pub mod writer;
