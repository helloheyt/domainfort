#![forbid(unsafe_code)]
//! `keyadm`: the Role::Admin one-shot tool (docs/51 §6; docs/50 §2.4;
//! decisions A-57, A-72) — in this task, the `ceremony` command.
//!
//! keyadm runs by hand under its own uid, which keyd maps to `Role::Admin`
//! ("Tier-0 key administration", crates/keyd-types authz.rs). It talks only
//! to keyd, through the ipc-keyd client; it has no Kerberos client, no
//! access to dird, and links no crypto (D182; A-73). keyd computes every
//! key; keyadm asks, and prints handles, bindings and kvnos.
//!
//! # `keyadm <configuration file> ceremony <manifest file>`
//!
//! Provisioning step 11 (docs/51 §4.3): after auditd and keyd start, create
//! the key sets the manifest of `provision domain` names — the krbtgt key
//! set and the LDAP and admin service key sets — with `create_key`. In
//! development mode keyd keeps keys in memory only, so the ceremony is
//! repeated after every keyd start (A-77; docs/51 §4.5); there is no key
//! file. See [`ceremony`] for the steps, the outcomes, and why it stops at
//! the first failure without retrying.
//!
//! Order of the run (the binary, src/main.rs): parse the
//! command line → refuse root ([`identity`]) → read the configuration
//! ([`settings`]: root-owned, not group/other-writable) → read the manifest
//! (`provision_manifest::read_manifest`: the same rule) → connect to keyd,
//! verify its peer uid before anything is sent → `ping` → three
//! `create_key` → print the [`report`] → exit 0 (complete), 1 (nothing
//! attempted) or 2 (stopped after an attempt).
//!
//! # Not in this task
//!
//! `destroy-sweep`, `rotate-key`, `rotate-krbtgt`, `retire-kvno` (docs/51
//! §6) arrive with tasks A9 / A10 (they need admind's `FetchApproved` /
//! `ListPendingDestruction`, docs/51 §6, §7.3); there is no code path for
//! them yet.
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or panic outside tests.
//! keyadm holds no secret and prints none. Its authority is its uid's
//! `Role::Admin` mapping in keyd (docs/50 §3.2); it refuses to run as root
//! and refuses a keyd socket whose peer uid is not the configured one.
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! AGENT-ONBOARDING, AGENTS, docs/51 (whole), docs/10 (§1, §2, §5ב, §7,
//! §7א, §9-§11), docs/47 (§1.1-§1.4, §2.3, §9.1), docs/50 (§2.4, §3.1-§3.7,
//! §6.1-§6.4, §7.1, §9, magic registry), docs/questions Q-290, Q-295, Q-296
//! and PENDING-OWNER (A-19, A-35, A-57, A-63, A-72, A-73, A-77, P-17, P-22);
//! RFC 4120 §6.2, §6.2.1, §7.3 (pinned, SHA-256 verified); and the public
//! API of this project's crates config, ipc, ipc-keyd, keyd-types,
//! provision-manifest and daemon-sandbox. No other implementation and no
//! existing key-administration or provisioning tool — its commands, names,
//! file formats or messages — was consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/51 §4.3 step 11, §4.5, §6, §12 (A5); docs/50 §2.4, R50-3;
//! A-57; A-72; A-73; A-77.

pub mod ceremony;
pub mod cli;
pub mod identity;
pub mod report;
pub mod settings;
