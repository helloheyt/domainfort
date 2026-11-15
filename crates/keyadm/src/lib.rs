#![forbid(unsafe_code)]
//! `keyadm`: the Role::Admin one-shot tool (docs/51 §6; docs/50 §2.4;
//! decisions A-57, A-72, A-102).
//!
//! keyadm runs by hand under its own uid, which keyd maps to `Role::Admin`
//! ("Tier-0 key administration", crates/keyd-types authz.rs). It talks to
//! **keyd only**, through the ipc-keyd client (docs/51 §6; A-102, docs/52
//! §4.6 — the admind forwards of task A10 are retired); it has no Kerberos
//! client, no access to dird, and links no crypto (D182; A-73). keyd
//! computes every key; keyadm asks, and prints handles, bindings, decision
//! ids and kvnos.
//!
//! **What keyadm can do** (A-102, docs/52 R1, R3): before keyd's ceremony
//! is sealed, `create_key` and the first administrators' initial-secret
//! grants; after it, nothing that is not a decision dird registered in keyd
//! — and keyadm names a decision only by its id: keyd runs the parameters it
//! holds.
//!
//! # `keyadm <configuration file> ceremony <manifest file> [<attestation key file>]`
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
//! (`provision_manifest::read_manifest`: the same rule; every first
//! administrator must have its salt, A-102 / N4) → read the attestation key
//! file, when one is named ([`attestation_key`]: the running account's,
//! 0400/0600, exactly 32 octets, not all zero — task PN9) → connect to keyd, verify
//! its peer uid before anything is sent → `ping` → four `create_key` (task K9: the fourth for `kadmin/changepw`) →
//! `install_attestation_key` when a key file was named (task PN9; docs/59
//! §7.4, §7.5) → one
//! `grant_set_secret` per first administrator, binding the manifest's salt
//! (task A15a: the initial-secret grants without which keyd refuses
//! `provision first-admin-secret`'s `set_secret`, live 15 minutes — docs/51
//! §5.8, docs/questions/Q-451) → `seal_ceremony` (A-102, docs/52 R3) →
//! print the [`report`] → exit 0 (complete and sealed), 1 (nothing
//! attempted) or 2 (stopped after an attempt).
//!
//! # `keyadm <configuration file> rotate-krbtgt | rotate-key | retire-kvno <decision id>`
//!
//! A-102 (docs/52 §4.2): run the key operation dird decided — dird registered
//! it in keyd at the `Approve` that completed the quorum, under the request
//! id the operator read from the `Approve` reply. keyadm sends keyd only that
//! id; keyd runs its registered operation once and keeps the result
//! ([`execute`]).
//!
//! # `keyadm <configuration file> destroy-sweep`
//!
//! A-102 (docs/52 §4.3): run the destroy decisions dird registered after each
//! `Delete` of a user or computer — keyd's `list_destroy_decisions` pages,
//! then `destroy_key_set(decision id)` for each; idempotent ([`sweep`]).
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
//! The decision commands, the sweep over keyd's destroy decisions and the
//! seal (A-102) are written from docs/52 §3.1, §3.3, §3.10, §4 and
//! docs/questions/Q-460..Q-462, opened in-session, and the API of this
//! project's keyd-types / ipc-keyd as changed by A-102.
//!
//! Spec: docs/51 §4.3 step 11, §4.5, §6, §12 (A5); docs/50 §2.4, R50-3;
//! A-57; A-72; A-73; A-77; docs/52 §4 (A-102).

pub mod attestation_key;
pub mod ceremony;
pub mod cli;
pub mod execute;
pub mod identity;
pub mod ports;
pub mod report;
pub mod settings;
pub mod sweep;
