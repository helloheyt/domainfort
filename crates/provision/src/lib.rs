#![forbid(unsafe_code)]
//! `provision`: the one-shot, offline domain-provisioning tool (docs/51 §4,
//! §12 task A4; decided A-72).
//!
//! # `provision domain` — part A of R51-1 (docs/51 §4.3 steps 1-9)
//!
//! Root, before any daemon runs, no secret anywhere (argv, environment,
//! output, manifest) and no password at all:
//!
//! 1. **checks** — the input ([`DomainInput`]: uids distinct and not 0,
//!    realm = the DNS name in upper case, the names by directory-admin's
//!    own [MS-SAMR] rules, at least two first administrators — P-22, each
//!    socket in its own directory) and the filesystem
//!    ([`install::precheck`]: every target and the staging directory
//!    absent, parents real directories on one filesystem, every directory
//!    on every path walked from `/` — crates/protected-file, task R11c);
//! 2. **draws** from the CSPRNG — the domain SID, every objectGUID, the
//!    NodeId, the integrity key ([`Plan`]); the source is
//!    `directory_admin::OsRandom`, keyd's (A-15 / A-77) behind
//!    `directory_admin::RandomSource`;
//! 3. **staging** directory (root, 0700) on the targets' filesystem;
//! 4. the **integrity key** (root:0400, 32 octets);
//! 5. the **database** — one `WriteTxn` with both named counters and every
//!    domain object (module [`plan`] lists them; module `store`), owner
//!    dird, 0600;
//! 6. the **policy** (format 2, version 1; module [`policy`]), root:0644;
//! 7. every **configuration file** (module [`configs`]), root:0644, each
//!    parsed back by its own schema first;
//! 8. the **manifest** (crates/provision-manifest), root:0644;
//! 9. **install**: fsync everything, rename into place — the database
//!    last — and remove the staging directory (module [`install`], with
//!    the crash analysis).
//!
//! Part B (the online key ceremony) is `keyadm ceremony` (task A5, crate
//! keyadm) and `provision first-admin-secret` (task A6, below).
//!
//! # `provision first-admin-secret` — docs/51 §4.3 step 12 (task A6)
//!
//! Module [`first_admin`]: root, after `keyadm ceremony`, keyd up, dird not
//! required. Reads the manifest and admind's configuration as root, opens
//! the password files (or uses the terminal: no echo, entered twice), drops
//! to admind's account through daemon-sandbox (Role::Directory in keyd;
//! not dumpable, memory locked), checks every password by admind's own
//! rules (crate admin-password-policy), then calls keyd's `set_secret` for
//! each first administrator with `call_with_fate` and prints handles,
//! bindings and kvnos. The drop is behind [`first_admin::privilege::
//! PrivilegeDrop`] (as the installer's [`Ownership`]); the binary uses
//! [`first_admin::privilege::SandboxDrop`], which refuses to exist unless
//! the effective uid is 0.
//!
//! # `provision policy` — the offline tier-map edit (R51-21, A-80)
//!
//! Module [`update`]: decode the root-owned policy, add / remove tier-map
//! rows, bump `policy_version`, write atomically (root:0644), and tell the
//! operator to restart dird and kdc (A-69).
//!
//! # Design for testing without root
//!
//! [`Plan::build`] is pure (input, time, CSPRNG ⇒ objects, policy,
//! configuration texts, manifest). The installer's only privileged
//! operation (`fchown`) is behind [`Ownership`]; the binary uses
//! [`RootOwnership`], which refuses to exist unless the effective uid is 0.
//! Tests record and check the requested owners instead. Nothing selects a
//! check-skipping path in production.
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests. The integrity key lives in zeroizing buffers, is written only to
//! its 0400 file, and never appears in a message or a `Debug` output; so do
//! the first administrators' passwords of `first-admin-secret`, which are
//! never written anywhere (they go to keyd only). Every
//! file is created exclusively without following links (O_EXCL |
//! O_NOFOLLOW) and renamed without replacing (RENAME_NOREPLACE); nothing
//! existing is ever overwritten (no `--force`). Every creation, rename,
//! removal and directory `fsync` is made relative to a directory walked
//! from `/` by crates/protected-file — no directory component is followed
//! through a link, every directory is root's and not writable by group or
//! others (task R11c, A-109). This crate does not link
//! krb-crypto or keyd (D182; guarded by
//! crates/keyd-types/tests/no_crypto_dependency.rs).
//!
//! # Residuals (documented, not hidden)
//!
//! - **Development sources only**: the integrity key is a development file
//!   and the policy is unsigned (Q-270 items 1-2, A-68); keyd's store is
//!   in-memory (P-17), so part B repeats after every keyd restart (A-77).
//! - The CSPRNG readiness threshold of D74 is not checked (A-77, until
//!   P-18).
//! - `fsync` on Apple platforms is not a persistence guarantee (rustix
//!   docs); the product target is Linux.
//! - dird's six admin-channel keys of task A8 (`keyd_socket`, `keyd_uid`,
//!   `node_id`, `admin_ticket_age_max`, `admin_quorum`,
//!   `provision_manifest`) are emitted but parsed back without them until
//!   that schema is merged (module [`configs`]).
//!
//! # Provenance
//!
//! Written only from, opened in this session: AGENT-ONBOARDING, AGENTS,
//! docs/51 (whole), docs/46 (§4, §5.4, §8), docs/47 (§1.3, §1.4, §3.3, §4,
//! §6.3), docs/50 (§2.4, §3.1-§3.2, §6.4, §7), docs/32, HANDOFF,
//! PENDING-OWNER (A-15, A-19, A-57, A-60, A-68, A-69, A-72..A-89, P-2,
//! P-18, P-22..P-24), the questions Q-270, Q-293, Q-294, Q-296, Q-298,
//! Q-299, Q-330, Q-335, Q-336, Q-345, Q-355..Q-358; the pinned
//! specifications from tools/spec-pin/cache/ (SHA-256 verified against
//! tools/spec-pin/manifest.json): [MS-DTYP] v20241119 (0f4a3744…83b3)
//! 2.4.2.4, 2.4.4.1, 2.4.4.2, 2.4.4.3, 2.4.4.4, 2.4.5, 2.4.6; [MS-ADTS]
//! v20261026 (55b59eb1…b2b1) 3.1.1.5.2.4, 5.1.3.2, 6.1.3, 6.1.3.1;
//! [MS-SAMR] v20260427 (083fe00a…8a4e) 2.2.1.14, 3.1.1.6, 3.1.1.8.1; the
//! public APIs of this workspace's crates; and the docs.rs API pages of
//! rustix 1.1.6 and redb 4.5.0 (API documentation only, never source —
//! P-2). No other implementation and no existing provisioning tool was
//! consulted or recalled (AGENTS.md §1-3).
//!
//! Interpretations and gaps: docs/questions/Q-375 … Q-379; for
//! `first-admin-secret` (task A6): Q-410 … Q-414 — that module's own
//! provenance is in its documentation.

pub mod cli;
pub mod configs;
mod descriptor;
pub mod first_admin;
mod ids;
pub mod input;
pub mod install;
pub mod ownership;
pub mod plan;
pub mod policy;
mod store;
pub mod time;
pub mod update;

pub use configs::{ConfigFile, Daemon, DIRD_ADMIN_CHANNEL_KEYS};
pub use descriptor::{ROOT_ACE_FLAGS, ROOT_OBJECT_RIGHTS};
pub use input::{Account, Accounts, DomainInput, FilePath, InputError, Names, Network, Paths};
pub use install::{
    install, precheck, InstallError, InstallState, Installed, Progress, Step, Target,
};
pub use ownership::{NotRoot, Ownership, OwnershipError, RootOwnership, Staged};
pub use plan::{ObjectRole, Owner, Plan, PlanError, PlannedObject, RidSource};
pub use store::StoreError;

use core::fmt;

use directory_admin::RandomSource;
use krb_proto::KerberosTime;

/// Why `provision domain` stopped.
#[derive(Debug)]
pub enum ProvisionError {
    /// No plan: nothing was written.
    Plan(PlanError),
    /// The installer stopped; its state says what was left.
    Install(InstallError),
}

impl ProvisionError {
    /// The state left behind.
    #[must_use]
    pub fn state(&self) -> InstallState {
        match self {
            ProvisionError::Plan(_) => InstallState::NothingWritten,
            ProvisionError::Install(e) => e.state,
        }
    }
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProvisionError::Plan(e) => write!(f, "{e} (nothing was written)"),
            ProvisionError::Install(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProvisionError {}

/// `provision domain`: check, plan, install (crate documentation, steps
/// 1-9). The filesystem pre-check runs before the draws, so a run that
/// would be refused for an existing target consumes no randomness; it is
/// repeated by the installer.
///
/// # Errors
/// [`ProvisionError`].
///
/// Spec: docs/51 §4.3 steps 1-9, §4.4.
pub fn provision_domain<R: RandomSource, O: Ownership, P: Progress>(
    input: &DomainInput,
    now: KerberosTime,
    rng: &mut R,
    ownership: &mut O,
    progress: &mut P,
) -> Result<(Plan, Installed), ProvisionError> {
    input
        .check()
        .map_err(|e| ProvisionError::Plan(PlanError::Input(e)))?;
    precheck(&input.paths, ownership.root_uid()).map_err(ProvisionError::Install)?;
    let plan = Plan::build(input, now, rng).map_err(ProvisionError::Plan)?;
    let installed = install(&plan, ownership, progress).map_err(ProvisionError::Install)?;
    Ok((plan, installed))
}
