//! dird's attestation of a name resolution (task PN10; docs/59 §7.1, §7.4;
//! decision A-173 — docs/questions/Q-1011 items 1-3): the signer dird
//! installs on every directory context it builds
//! (`directory_pip::DirectoryContext::with_name_resolution_signer`), so each
//! account record it answers the KDC with carries
//! `keyd_types::AttestedNameResolution` (docs/59 §7.5).
//!
//! # What it computes — exactly what keyd verifies
//!
//! keyd's `verify_name_resolution` (crates/keyd `name_resolution.rs`, task
//! PN8) checks, in order: the tag — HMAC-SHA-256 under the attestation key
//! over `NameResolution::mac_input` (crate name-attestation `verify`); the
//! canonical realm equal to keyd's realm octet for octet; and
//! `|now − issued_at| ≤ 30 s` on keyd's clock (`NameResolution::is_fresh_at`,
//! `NAME_RESOLUTION_WINDOW_SECS`). [`ResolutionSigner`] therefore:
//!
//! * takes the resolution's fields from the lookup itself —
//!   `ResolvedPrincipal::name_resolution`, whose canonical realm is the
//!   context's configured realm (the realm keyd and dird share, R47-10);
//! * stamps `issued_at` with dird's own clock at the moment of the lookup
//!   (the host keyd runs on — the window is for one request on one host,
//!   Q-1011 item 3); a clock that cannot be read refuses (fail closed);
//! * tags it with `name_attestation::tag` — the same crate, label and MAC
//!   input keyd verifies with (docs/59 §7.1, C44). No primitive is
//!   implemented here (AGENTS.md §6).
//!
//! # Classes closed by construction (AGENTS.md §6.1)
//!
//! * **dird's key attesting a mapping no lookup made** (C3 on dird's side):
//!   the key is private to [`ResolutionSigner`], whose one operation takes a
//!   `directory_pip::ResolvedPrincipal` — built only by the one lookup path
//!   (`canonical_principal`). No dird code holds the key elsewhere, and none
//!   can have a hand-built `NameResolution` tagged through it.
//! * **Key export / a MAC oracle** (D28 / D29; A-145 RC-6, C42): nothing
//!   hands the key out — `AttestationKey` has no accessor, `Debug` or
//!   `Clone` (crate name-attestation); [`SharedAttestationKey`] shares it
//!   between dird's contexts by reference count only and prints nothing.
//! * **Secrets in output** (AGENTS.md §6): neither type's `Debug` shows a
//!   key octet; every refusal is the data-free `SignerRefused`.
//!
//! # Provenance
//!
//! Written only from docs/59 §7 (§7.1-§7.5, §10 the PN10 row),
//! docs/questions/Q-1011 (A-173), Q-1027 (A-178), PENDING-OWNER A-63, A-145,
//! A-173, RFC 4120 §5.2.3 (pinned, SHA-256 re-checked against
//! tools/spec-pin/manifest.json) and the public APIs of this project's
//! crates keyd-types, name-attestation, directory-pip and keyd (read: keyd's
//! verifier, to match it). No other implementation was consulted or
//! recalled (AGENTS.md §1-3).
//!
//! Spec: docs/59 §7.1, §7.2, §7.4, §7.5; docs/questions/Q-1011 items 1-3
//! (A-173); A-145 RC-6; AGENTS.md §6, §6.1.

use core::fmt;
use directory_pip::{NameResolutionSigner, ResolvedPrincipal, SignerRefused};
use keyd_types::AttestedNameResolution;
use krb_proto::KerberosTime;
use name_attestation::{AttestationKey, KeyRefused, ATTESTATION_KEY_LEN};
use std::sync::Arc;

/// dird's attestation key, shared by the signers of the directory contexts
/// dird builds (one key per process — Q-1011 item 2: one key, held by dird
/// and keyd). Cloning shares the one key; nothing reads it out, and `Debug`
/// prints no octet.
/// Spec: docs/59 §7.4; docs/questions/Q-1011 item 2 (A-173); AGENTS.md §6.
#[derive(Clone)]
pub struct SharedAttestationKey(Arc<AttestationKey>);

impl SharedAttestationKey {
    /// The key from its octets (read once, as root before the drop, from
    /// dird's key file — crates/directory-daemon `startup`): copied into the
    /// key's wiped-on-drop buffer; the caller wipes its own copy. The
    /// all-zero key is refused (crate name-attestation: a buffer never
    /// filled — fail closed).
    ///
    /// # Errors
    /// `KeyRefused` (no data).
    ///
    /// Spec: docs/59 §7.4; docs/questions/Q-1011 item 2; AGENTS.md §6.
    pub fn from_bytes(
        octets: &[u8; ATTESTATION_KEY_LEN],
    ) -> Result<SharedAttestationKey, KeyRefused> {
        Ok(SharedAttestationKey(Arc::new(AttestationKey::from_bytes(
            octets,
        )?)))
    }
}

impl fmt::Debug for SharedAttestationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedAttestationKey(..)")
    }
}

/// The clock a [`ResolutionSigner`] stamps `issued_at` with: dird's (the
/// daemon's shared clock — the system clock in the product, a test's own
/// in tests). `None` ⇒ the time cannot be read or represented.
/// Spec: docs/59 §7.1 (`issued_at`); RFC 4120 §5.2.3.
pub type IssueClock = Arc<dyn Fn() -> Option<KerberosTime> + Send + Sync>;

/// dird's signer of name resolutions (module documentation): its
/// attestation key and its clock.
/// Spec: docs/59 §7.1, §7.4; docs/questions/Q-1011 items 1-3 (A-173).
pub struct ResolutionSigner {
    key: SharedAttestationKey,
    clock: IssueClock,
}

impl ResolutionSigner {
    /// A signer with dird's `key` and `clock`.
    /// Spec: docs/59 §7.4.
    #[must_use]
    pub fn new(key: SharedAttestationKey, clock: IssueClock) -> ResolutionSigner {
        ResolutionSigner { key, clock }
    }
}

impl fmt::Debug for ResolutionSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResolutionSigner")
    }
}

impl NameResolutionSigner for ResolutionSigner {
    /// `resolved`'s resolution (`ResolvedPrincipal::name_resolution`) issued
    /// at dird's clock now, tagged with dird's attestation key
    /// (`name_attestation::tag`). A clock that cannot be read, a name outside
    /// a resolution's bounds, or a MAC failure ⇒ [`SignerRefused`] (the
    /// record is not answered — fail closed).
    /// Spec: docs/59 §7.1, §7.2 (the checks this must pass), §7.4;
    /// docs/questions/Q-1011 items 1-3 (A-173); AGENTS.md §6.
    fn attest(
        &self,
        resolved: &ResolvedPrincipal,
    ) -> Result<AttestedNameResolution, SignerRefused> {
        let issued_at = (self.clock)().ok_or(SignerRefused)?;
        let resolution = resolved
            .name_resolution(issued_at)
            .map_err(|_| SignerRefused)?;
        name_attestation::tag(&self.key.0, &resolution).map_err(|_| SignerRefused)
    }
}
