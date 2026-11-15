//! Custody backends of the sealed key store (task KL2): the interface every
//! backend implements, the properties it must declare, the start-up probe,
//! and the one backend that exists today — the declared **insecure
//! development** backend.
//!
//! A custody backend holds what the store file cannot hold for itself
//! (r4-c §3.2): the **store wrapping key** (SWK) that seals every key record
//! and the header, and a **named monotonic anchor** — a counter outside the
//! file that never goes down — against which the header's generation G is
//! checked at start (r4-c §3.6). The name `CustodyBackend` was chosen so as
//! not to collide with the kdc's `KeyCustody` seam (r4-c §3.2).
//!
//! # The properties (r4-c §3.2) and the probe (§3.7 step 1)
//!
//! Each backend declares [`CustodyProperties`]: whether it provides sealing
//! of the SWK at rest, a monotonic anchor that survives a restart and tells
//! "never initialized" apart, non-exportable computation, wrapped escrow
//! export and destruction — and which [`CustodyProfile`] it is. [`probe`]
//! compares the declared profile with the configured one (in both
//! directions: a development backend never satisfies a production
//! configuration, and a development backend runs only when the
//! configuration names it), checks every property the profile requires
//! ([`CustodyProfile::required`], the table of §3.2), and reads the anchor.
//! Any mismatch, missing property or failed read is a [`ProbeError`]: keyd
//! does not start (fail closed). Only a [`Probed`] backend can be used — the
//! backend's own operations take a token only this module can build — so no
//! store can be opened on a backend that was not probed.
//!
//! # "Absence of state" is never "initial state" (class C38, A-143)
//!
//! **The class (C38, r4-c §9.1):** when persistent state is missing
//! (deleted, hidden, not loaded), a component falls back to its initial
//! state — the most permissive one; with a persistent store, deleting the
//! file would give back `Provisioning` and with it `create_key` and the
//! first administrators' grants (N1 again). **The root-level change, by
//! construction:**
//!
//! * the backend's reading ([`AnchorReading`]) has no "absent", "empty" or
//!   default value: `NeverInitialized` is a **positive** fact the backend
//!   asserts (the fuse is intact), and a failure to read is an error, never
//!   that fact; "an anchor above zero bound to no store" is not
//!   representable — a bound reading always names its store id;
//! * the only source of the evidence that a new store may start in its
//!   ceremony — [`ProvisioningEvidence`] — is [`Probed::bind_new_store`],
//!   which requires the probe's positive `NeverInitialized` reading, consumes
//!   it (once per probe), binds the backend, and reads back that the binding
//!   took. Once bound, a backend never reads `NeverInitialized` again; the
//!   anchor only moves forward, one step at a time
//!   ([`Probed::advance_anchor`]).
//!
//! The rest of the C38 closure is the store's and the start sequence's
//! (tasks KL3, KL4): keyd's ceremony state comes from this evidence or from
//! an authenticated header, never from `KeyStore::is_empty` (today's
//! `Keyd::new` still derives it from an empty in-memory store — the
//! development residual of A-77, docs/52 §4.4).
//!
//! # The insecure development backend
//!
//! [`InsecureDevelopmentCustody`] provides **none** of the protected
//! properties, and says so: its SWK is drawn from the kernel CSPRNG and held
//! only in process memory (zeroized on drop), its anchor lives in process
//! memory too and so reads `NeverInitialized` after every process start
//! (with it, a store file left from an earlier run is not this backend's —
//! the start sequence refuses it, r4-c §3.7 step 2). It announces itself:
//! its profile is [`CustodyProfile::InsecureDevelopment`], the probe accepts
//! it only when the configuration names that profile, and
//! [`Probed::notice`] returns [`INSECURE_DEVELOPMENT_NOTICE`] for the
//! daemon's log (R50-18: "clearly marked"). It needs no primitive beyond
//! the kernel CSPRNG keyd already reads ([`OsEntropy`]; docs/CLEAN-ROOM.md —
//! nothing implemented here). Protects against: nothing (r4-c §3.2, the
//! "Dev" column).
//!
//! # Not here
//!
//! The TPM backend (task KL5, P-52) and the HSM backends (KL6, Q-861) — no
//! code path, no type; the sealed store itself (KL3); the start sequence
//! (KL4); escrow export and destruction as operations (declared properties
//! only — their operations come with their consumers, KL7 and
//! decommissioning).
//!
//! Spec: docs/research/r4-c-key-lifecycle.md §3.2 (the properties and the
//! profiles), §3.6 (the anchor), §3.7 steps 1-3 (probe, anchor, SWK), §9.1
//! (C38), R4C-3, R4C-5, R4C-14 (named anchors); PENDING-OWNER A-143;
//! docs/50 R50-18; docs/52 §4.4; docs/research/r4-a-crypto-inventory.md
//! R4A-5 (AES-256 where there is a choice); docs/CLEAN-ROOM.md, §6.1.

use crate::entropy::{EntropySource, OsEntropy};
use core::fmt;
use keyd_types::StoreId;
use zeroize::Zeroizing;

/// Octets of a store wrapping key: 256 bits — the project's preference for
/// 256-bit symmetric keys wherever there is a choice.
/// Spec: docs/research/r4-a-crypto-inventory.md R4A-5; r4-c §3.3 (the SWK).
pub const STORE_KEY_OCTETS: usize = 32;

/// The fixed text the daemon logs when the insecure development backend is
/// in use (R50-18). No key, no id, no peer data.
/// Spec: docs/50 R50-18; r4-c §3.2 (Dev: "insecure, declared"), §3.7 step 1
/// ("Dev ⇒ a prominent warning").
pub const INSECURE_DEVELOPMENT_NOTICE: &str = "INSECURE DEVELOPMENT KEY CUSTODY: the store \
     wrapping key and the anti-rollback anchor are held in process memory only; nothing at rest \
     is protected — never use in a deployment";

/// The custody profiles of r4-c §3.2 / §3.7: what the configuration names
/// (`key_store = tpm | hsm-h1 | hsm-h2 | insecure-development`) and what a
/// backend declares. Only the insecure development profile has a backend in
/// this build (KL5: P-52; KL6: Q-861).
/// Spec: r4-c §3.2 (R4C-5: "four custody profiles"), §3.7 step 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustodyProfile {
    /// Insecure, declared: nothing at rest is protected.
    InsecureDevelopment,
    /// The SWK sealed to this machine's TPM, opened into keyd's memory at
    /// start.
    Tpm,
    /// The SWK non-exportable in an HSM; keys opened into keyd's memory for
    /// use.
    HsmH1,
    /// The keys never leave the HSM; the computation is inside (D30).
    HsmH2,
}

/// One property of r4-c §3.2's table.
/// Spec: r4-c §3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustodyProperty {
    /// "seal/unseal of the SWK": the SWK exists at rest only sealed to the
    /// backend.
    StoreKeySealing,
    /// "named monotonic anchor": a counter that never goes down, survives a
    /// restart, and whose "never initialized" is distinguished.
    MonotonicAnchor,
    /// "non-exportable key object": computation inside the backend.
    NonExportableCompute,
    /// "wrapped escrow export": only in the ceremony, only to registered
    /// recipients.
    WrappedEscrowExport,
    /// "destruction": an object or key deleted cannot be recovered from the
    /// backend.
    Destruction,
}

impl CustodyProfile {
    /// The properties a backend of this profile must provide — the ✔ / ⚠
    /// cells of r4-c §3.2's table (the anchor is a requirement of every
    /// production profile even where §3.2 marks it ⚠: the requirement stands,
    /// what is open is whether the hardware meets it, Q-860 / Q-861). The
    /// insecure development profile requires nothing: it protects nothing.
    /// Spec: r4-c §3.2 (the property table; "missing ⇒ keyd does not
    /// start").
    #[must_use]
    pub const fn required(self) -> &'static [CustodyProperty] {
        const SEALED_AT_REST: &[CustodyProperty] = &[
            CustodyProperty::StoreKeySealing,
            CustodyProperty::MonotonicAnchor,
            CustodyProperty::WrappedEscrowExport,
            CustodyProperty::Destruction,
        ];
        const KEYS_STAY_INSIDE: &[CustodyProperty] = &[
            CustodyProperty::StoreKeySealing,
            CustodyProperty::MonotonicAnchor,
            CustodyProperty::NonExportableCompute,
            CustodyProperty::WrappedEscrowExport,
            CustodyProperty::Destruction,
        ];
        match self {
            CustodyProfile::InsecureDevelopment => &[],
            CustodyProfile::Tpm | CustodyProfile::HsmH1 => SEALED_AT_REST,
            CustodyProfile::HsmH2 => KEYS_STAY_INSIDE,
        }
    }
}

/// What a backend declares about itself (r4-c §3.2).
/// Spec: r4-c §3.2 ("the properties every backend must declare (probe at
/// start; missing ⇒ keyd does not start)").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyProperties {
    /// The backend's profile.
    pub profile: CustodyProfile,
    /// [`CustodyProperty::StoreKeySealing`].
    pub store_key_sealing: bool,
    /// [`CustodyProperty::MonotonicAnchor`].
    pub monotonic_anchor: bool,
    /// [`CustodyProperty::NonExportableCompute`].
    pub non_exportable_compute: bool,
    /// [`CustodyProperty::WrappedEscrowExport`].
    pub wrapped_escrow_export: bool,
    /// [`CustodyProperty::Destruction`].
    pub destruction: bool,
}

impl CustodyProperties {
    /// Whether the backend declares `property`. Spec: r4-c §3.2.
    #[must_use]
    pub const fn provides(&self, property: CustodyProperty) -> bool {
        match property {
            CustodyProperty::StoreKeySealing => self.store_key_sealing,
            CustodyProperty::MonotonicAnchor => self.monotonic_anchor,
            CustodyProperty::NonExportableCompute => self.non_exportable_compute,
            CustodyProperty::WrappedEscrowExport => self.wrapped_escrow_export,
            CustodyProperty::Destruction => self.destruction,
        }
    }
}

/// A named monotonic anchor. One today — the key store's; the same
/// interface is to carry the other rollback-sensitive counters (dirstore
/// commits, the policy release sequence, the audit head) when their
/// consumers exist (R4C-14, Q-869).
/// Spec: r4-c §3.6 ("named counters: `keyd-store`, ..."), R4C-14.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorName {
    /// The anchor of keyd's sealed key store.
    KeydStore,
}

/// What a backend reads for an anchor: a positive fact either way (module
/// documentation, C38). A backend that cannot read its anchor — device
/// absent, I/O failure, record missing — returns [`CustodyError`], never
/// `NeverInitialized`.
/// Spec: r4-c §3.7 step 2 ("anchor = 0 **and** the backend reports 'bound
/// to no `store_id`' ⇒ never initialized ⇒ `Provisioning` (only here)";
/// "anchor > 0 ⇒ there must be a file with the same `store_id`"), §9.1
/// (C38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorReading {
    /// The backend asserts that this anchor was never set and that it is
    /// bound to no store.
    NeverInitialized,
    /// The backend is bound to `store_id` and the anchor reads `generation`
    /// (0 right after binding, until the first commit advances it).
    Bound {
        /// The store the backend is bound to.
        store_id: StoreId,
        /// The anchor's value.
        generation: u64,
    },
}

/// A backend operation failed. Carries no data (docs/CLEAN-ROOM.md). Every case
/// is fail closed: keyd does not start, or the operation is not performed.
/// Spec: r4-c §3.7 ("missing ⇒ keyd does not start"), §3.8 (backend
/// unavailable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyError {
    /// The backend could not be reached or could not complete the operation
    /// (device, I/O, entropy).
    Unavailable,
    /// The backend's state contradicts the request: binding a bound
    /// backend, unsealing or advancing for another store, advancing from a
    /// value that is not the anchor's, or past the counter's end.
    Refused,
}

/// Why the probe refused a backend: keyd does not start.
/// Spec: r4-c §3.7 step 1 ("backend missing / property missing ⇒ do not
/// start").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    /// The backend's profile is not the configured one.
    ProfileMismatch,
    /// The backend does not provide a property its profile requires.
    MissingProperty(CustodyProperty),
    /// The anchor could not be read.
    Backend(CustodyError),
}

/// The store wrapping key, held in zeroizing memory. Opaque: no accessor
/// outside keyd, no octet in `Debug` (docs/CLEAN-ROOM.md). The sealed store (KL3)
/// reads it inside keyd.
/// Spec: r4-c §3.3 (the SWK), §3.7 step 3; docs/10 §11 (zeroize).
pub struct StoreWrappingKey {
    octets: Zeroizing<[u8; STORE_KEY_OCTETS]>,
}

impl StoreWrappingKey {
    /// A fresh key from `entropy` (the kernel CSPRNG in the development
    /// backend); entropy failure is `Unavailable` (fail closed, no
    /// fallback).
    /// Spec: docs/CLEAN-ROOM.md (never implement an RNG); RFC 4120 §3.1.3 ("See
    /// \[RFC4086\]" — keys must be unguessable).
    fn draw<E: EntropySource>(entropy: &mut E) -> Result<Self, CustodyError> {
        let mut octets = Zeroizing::new([0u8; STORE_KEY_OCTETS]);
        entropy
            .fill(&mut octets[..])
            .map_err(|_| CustodyError::Unavailable)?;
        Ok(StoreWrappingKey { octets })
    }

    /// A copy in its own zeroizing buffer (the development backend hands
    /// keyd a copy and keeps its own).
    fn copy(&self) -> Self {
        StoreWrappingKey {
            octets: Zeroizing::new(*self.octets),
        }
    }

    /// The key octets (tests of this module; the sealed store, KL3).
    #[cfg(test)]
    fn octets(&self) -> &[u8; STORE_KEY_OCTETS] {
        &self.octets
    }
}

impl fmt::Debug for StoreWrappingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoreWrappingKey(..)")
    }
}

/// Sealing of the backend trait: only this crate implements a backend, and
/// only this module calls a backend's operations (they take an [`Access`]
/// token no other code can build). A backend declares hardware properties;
/// a backend outside keyd could declare them falsely.
/// Spec: docs/CLEAN-ROOM.md ("a single chokepoint"); r4-c §3.2.
mod sealed {
    /// Implemented only by this crate's backends.
    pub trait Sealed {}

    /// The token a backend operation takes: built only by the probe's
    /// module, so only a [`super::Probed`] backend is ever driven.
    #[derive(Debug)]
    pub struct Access(());

    impl Access {
        /// Spec: docs/CLEAN-ROOM.md
        pub(super) const fn new() -> Self {
            Access(())
        }
    }
}

/// A custody backend (r4-c §3.2). Implemented only inside keyd (sealed);
/// driven only through [`probe`] and [`Probed`].
///
/// Every operation fails closed: an error leaves the backend's state as it
/// was, and a reading is a positive fact or an error (C38).
///
/// Spec: r4-c §3.2, §3.6, §3.7 steps 1-3; A-143.
pub trait CustodyBackend: sealed::Sealed {
    /// The properties this backend declares (r4-c §3.2).
    fn properties(&self) -> CustodyProperties;

    /// Read `anchor` and the store binding.
    ///
    /// # Errors
    /// [`CustodyError::Unavailable`] when the reading cannot be made — never
    /// a `NeverInitialized` in its place (C38).
    fn read_anchor(
        &mut self,
        access: sealed::Access,
        anchor: AnchorName,
    ) -> Result<AnchorReading, CustodyError>;

    /// Bind a never-initialized backend to `store_id`: create the SWK
    /// sealed to the backend, the anchor at 0.
    ///
    /// # Errors
    /// [`CustodyError::Refused`] when already bound;
    /// [`CustodyError::Unavailable`] when the key cannot be made.
    fn bind_store(
        &mut self,
        access: sealed::Access,
        anchor: AnchorName,
        store_id: StoreId,
    ) -> Result<(), CustodyError>;

    /// The SWK of the bound store `store_id`, opened into keyd's memory.
    ///
    /// # Errors
    /// [`CustodyError::Refused`] when not bound to `store_id`;
    /// [`CustodyError::Unavailable`] when it cannot be opened.
    fn unseal_store_key(
        &mut self,
        access: sealed::Access,
        store_id: &StoreId,
    ) -> Result<StoreWrappingKey, CustodyError>;

    /// Advance `anchor` of the bound store `store_id` from `from` to
    /// `from + 1`, and return the new value. Only ever one step up.
    ///
    /// # Errors
    /// [`CustodyError::Refused`] when not bound to `store_id`, when the
    /// anchor does not read `from`, or at the counter's end.
    fn advance_anchor(
        &mut self,
        access: sealed::Access,
        anchor: AnchorName,
        store_id: &StoreId,
        from: u64,
    ) -> Result<u64, CustodyError>;
}

/// Probe `backend` against the configured `expected` profile (r4-c §3.7
/// step 1) and read the key store's anchor (step 2).
///
/// # Errors
/// [`ProbeError`]: keyd does not start.
///
/// Spec: r4-c §3.2, §3.7 steps 1-2; docs/50 R50-18.
pub fn probe<B: CustodyBackend>(
    mut backend: B,
    expected: CustodyProfile,
) -> Result<Probed<B>, ProbeError> {
    let properties = backend.properties();
    if properties.profile != expected {
        return Err(ProbeError::ProfileMismatch);
    }
    if let Some(missing) = expected
        .required()
        .iter()
        .find(|property| !properties.provides(**property))
    {
        return Err(ProbeError::MissingProperty(*missing));
    }
    let state = backend
        .read_anchor(sealed::Access::new(), AnchorName::KeydStore)
        .map_err(ProbeError::Backend)?;
    Ok(Probed {
        backend,
        properties,
        state,
    })
}

/// A backend that passed the probe: the only handle through which a backend
/// is used (module documentation).
/// Spec: r4-c §3.7 steps 1-3.
pub struct Probed<B> {
    backend: B,
    properties: CustodyProperties,
    /// The key store anchor as last read or moved through this handle.
    state: AnchorReading,
}

impl<B: CustodyBackend> Probed<B> {
    /// The backend's declared properties.
    #[must_use]
    pub fn properties(&self) -> CustodyProperties {
        self.properties
    }

    /// The key store anchor: as the probe read it, then as this handle
    /// bound or advanced it.
    /// Spec: r4-c §3.7 step 2.
    #[must_use]
    pub fn state(&self) -> AnchorReading {
        self.state
    }

    /// The notice the daemon must log at start, for an insecure profile;
    /// `None` otherwise.
    /// Spec: docs/50 R50-18; r4-c §3.7 step 1.
    #[must_use]
    pub fn notice(&self) -> Option<&'static str> {
        match self.properties.profile {
            CustodyProfile::InsecureDevelopment => Some(INSECURE_DEVELOPMENT_NOTICE),
            CustodyProfile::Tpm | CustodyProfile::HsmH1 | CustodyProfile::HsmH2 => None,
        }
    }

    /// Bind the backend to a new store `store_id` — only when the probe read
    /// `NeverInitialized` — and return the evidence that this store may start
    /// in its ceremony. The binding is read back: a backend that does not
    /// then read `Bound { store_id, 0 }` is refused.
    ///
    /// # Errors
    /// [`CustodyError::Refused`] when the probe did not read
    /// `NeverInitialized` (or this handle already bound), or the read-back
    /// disagrees; [`CustodyError::Unavailable`] from the backend.
    ///
    /// Spec: r4-c §3.7 step 2, §9.1 (C38), R4C-3; A-143.
    pub fn bind_new_store(
        &mut self,
        store_id: StoreId,
    ) -> Result<ProvisioningEvidence, CustodyError> {
        if self.state != AnchorReading::NeverInitialized {
            return Err(CustodyError::Refused);
        }
        self.backend
            .bind_store(sealed::Access::new(), AnchorName::KeydStore, store_id)?;
        let bound = self
            .backend
            .read_anchor(sealed::Access::new(), AnchorName::KeydStore)?;
        let expected = AnchorReading::Bound {
            store_id,
            generation: 0,
        };
        if bound != expected {
            // The backend did not do what it said: fail closed, and never
            // read this handle as never-initialized again.
            self.state = bound;
            return Err(CustodyError::Refused);
        }
        self.state = bound;
        Ok(ProvisioningEvidence { store_id })
    }

    /// The SWK of the bound store.
    ///
    /// # Errors
    /// [`CustodyError::Refused`] when the backend is not bound;
    /// [`CustodyError::Unavailable`] / `Refused` from the backend.
    ///
    /// Spec: r4-c §3.7 step 3.
    pub fn unseal_store_key(&mut self) -> Result<StoreWrappingKey, CustodyError> {
        match self.state {
            AnchorReading::Bound { store_id, .. } => self
                .backend
                .unseal_store_key(sealed::Access::new(), &store_id),
            AnchorReading::NeverInitialized => Err(CustodyError::Refused),
        }
    }

    /// Advance the key store anchor from `from` to `from + 1` (a commit's
    /// last step before its answer, or an interrupted commit found at start
    /// — r4-c §3.5, §3.6), and return the new value.
    ///
    /// # Errors
    /// [`CustodyError::Refused`] when the backend is not bound, or from the
    /// backend (the anchor does not read `from`; the counter's end).
    ///
    /// Spec: r4-c §3.5 step 4, §3.6.
    pub fn advance_anchor(&mut self, from: u64) -> Result<u64, CustodyError> {
        let AnchorReading::Bound { store_id, .. } = self.state else {
            return Err(CustodyError::Refused);
        };
        let generation = self.backend.advance_anchor(
            sealed::Access::new(),
            AnchorName::KeydStore,
            &store_id,
            from,
        )?;
        if Some(generation) != from.checked_add(1) {
            return Err(CustodyError::Refused);
        }
        self.state = AnchorReading::Bound {
            store_id,
            generation,
        };
        Ok(generation)
    }

    /// The backend itself, to probe it again (a restart of the store layer
    /// within one process — the development backend's state is in memory).
    /// Its operations stay reachable only through a new probe.
    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }
}

impl<B> fmt::Debug for Probed<B> {
    /// Properties and anchor only — never a key (docs/CLEAN-ROOM.md).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Probed")
            .field("properties", &self.properties)
            .field("state", &self.state)
            .finish()
    }
}

/// The evidence that a newly bound store may start in its ceremony
/// (`Provisioning`). Built only by [`Probed::bind_new_store`] from the
/// backend's positive "never initialized" reading; not `Clone`. The start
/// sequence (KL4) consumes it — the ceremony state never comes from an empty
/// or missing store (C38).
/// Spec: r4-c §3.7 step 2, §9.1 (C38), R4C-3; A-143.
#[derive(Debug, PartialEq, Eq)]
pub struct ProvisioningEvidence {
    store_id: StoreId,
}

impl ProvisioningEvidence {
    /// The store the evidence is for.
    #[must_use]
    pub fn store_id(&self) -> StoreId {
        self.store_id
    }
}

/// **INSECURE — DEVELOPMENT AND TESTS ONLY.** The custody backend that
/// protects nothing (module documentation): the SWK and the anchor live in
/// process memory, so every process start reads `NeverInitialized`, and a
/// memory read exposes the SWK. Its profile is
/// [`CustodyProfile::InsecureDevelopment`]; the probe accepts it only for a
/// configuration that names that profile.
/// Spec: r4-c §3.2 (Dev), §3.7 step 1; docs/50 R50-18; A-16 (the insecure
/// development store); D178.
pub struct InsecureDevelopmentCustody {
    state: DevelopmentState,
}

/// The development backend's in-memory state.
enum DevelopmentState {
    /// Fresh in this process.
    NeverInitialized,
    /// Bound to a store.
    Bound {
        store_id: StoreId,
        generation: u64,
        store_key: StoreWrappingKey,
    },
}

impl InsecureDevelopmentCustody {
    /// A fresh development backend: never initialized (in this process).
    /// Spec: r4-c §3.2 (Dev); docs/50 R50-18.
    #[must_use]
    pub const fn new_insecure_development() -> Self {
        InsecureDevelopmentCustody {
            state: DevelopmentState::NeverInitialized,
        }
    }
}

impl sealed::Sealed for InsecureDevelopmentCustody {}

impl CustodyBackend for InsecureDevelopmentCustody {
    /// No protected property (r4-c §3.2: Dev protects against nothing).
    fn properties(&self) -> CustodyProperties {
        CustodyProperties {
            profile: CustodyProfile::InsecureDevelopment,
            store_key_sealing: false,
            monotonic_anchor: false,
            non_exportable_compute: false,
            wrapped_escrow_export: false,
            destruction: false,
        }
    }

    fn read_anchor(
        &mut self,
        _access: sealed::Access,
        anchor: AnchorName,
    ) -> Result<AnchorReading, CustodyError> {
        match anchor {
            AnchorName::KeydStore => {}
        }
        Ok(match &self.state {
            DevelopmentState::NeverInitialized => AnchorReading::NeverInitialized,
            DevelopmentState::Bound {
                store_id,
                generation,
                ..
            } => AnchorReading::Bound {
                store_id: *store_id,
                generation: *generation,
            },
        })
    }

    fn bind_store(
        &mut self,
        _access: sealed::Access,
        anchor: AnchorName,
        store_id: StoreId,
    ) -> Result<(), CustodyError> {
        match anchor {
            AnchorName::KeydStore => {}
        }
        if !matches!(self.state, DevelopmentState::NeverInitialized) {
            return Err(CustodyError::Refused);
        }
        let store_key = StoreWrappingKey::draw(&mut OsEntropy::new())?;
        self.state = DevelopmentState::Bound {
            store_id,
            generation: 0,
            store_key,
        };
        Ok(())
    }

    fn unseal_store_key(
        &mut self,
        _access: sealed::Access,
        store_id: &StoreId,
    ) -> Result<StoreWrappingKey, CustodyError> {
        match &self.state {
            DevelopmentState::Bound {
                store_id: bound,
                store_key,
                ..
            } if bound == store_id => Ok(store_key.copy()),
            _ => Err(CustodyError::Refused),
        }
    }

    fn advance_anchor(
        &mut self,
        _access: sealed::Access,
        anchor: AnchorName,
        store_id: &StoreId,
        from: u64,
    ) -> Result<u64, CustodyError> {
        match anchor {
            AnchorName::KeydStore => {}
        }
        match &mut self.state {
            DevelopmentState::Bound {
                store_id: bound,
                generation,
                ..
            } if bound == store_id && *generation == from => {
                let next = from.checked_add(1).ok_or(CustodyError::Refused)?;
                *generation = next;
                Ok(next)
            }
            _ => Err(CustodyError::Refused),
        }
    }
}

impl fmt::Debug for InsecureDevelopmentCustody {
    /// The declaration and the anchor — never the SWK (docs/CLEAN-ROOM.md).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("InsecureDevelopmentCustody");
        s.field("insecure_development", &true);
        match &self.state {
            DevelopmentState::NeverInitialized => s.field("state", &"NeverInitialized"),
            DevelopmentState::Bound {
                store_id,
                generation,
                ..
            } => s
                .field("store_id", store_id)
                .field("generation", generation),
        };
        s.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> StoreId {
        StoreId::from_bytes([byte; 16])
    }

    /// A backend that declares whatever a test gives it (tests only — the
    /// trait is sealed to this crate).
    struct Declared {
        properties: CustodyProperties,
        reading: Result<AnchorReading, CustodyError>,
        bind_reads_back: Option<AnchorReading>,
    }

    impl sealed::Sealed for Declared {}

    impl CustodyBackend for Declared {
        fn properties(&self) -> CustodyProperties {
            self.properties
        }
        fn read_anchor(
            &mut self,
            _access: sealed::Access,
            _anchor: AnchorName,
        ) -> Result<AnchorReading, CustodyError> {
            self.reading
        }
        fn bind_store(
            &mut self,
            _access: sealed::Access,
            _anchor: AnchorName,
            _store_id: StoreId,
        ) -> Result<(), CustodyError> {
            if let Some(reading) = self.bind_reads_back {
                self.reading = Ok(reading);
            }
            Ok(())
        }
        fn unseal_store_key(
            &mut self,
            _access: sealed::Access,
            _store_id: &StoreId,
        ) -> Result<StoreWrappingKey, CustodyError> {
            Err(CustodyError::Unavailable)
        }
        fn advance_anchor(
            &mut self,
            _access: sealed::Access,
            _anchor: AnchorName,
            _store_id: &StoreId,
            from: u64,
        ) -> Result<u64, CustodyError> {
            // A misbehaving backend: jumps two steps.
            Ok(from.saturating_add(2))
        }
    }

    fn all(profile: CustodyProfile) -> CustodyProperties {
        CustodyProperties {
            profile,
            store_key_sealing: true,
            monotonic_anchor: true,
            non_exportable_compute: true,
            wrapped_escrow_export: true,
            destruction: true,
        }
    }

    fn declared(
        properties: CustodyProperties,
        reading: Result<AnchorReading, CustodyError>,
    ) -> Declared {
        Declared {
            properties,
            reading,
            bind_reads_back: None,
        }
    }

    /// r4-c §3.2: the requirement table — TPM and H1 need the sealed SWK,
    /// the anchor, escrow and destruction; H2 also non-exportable
    /// computation; development nothing.
    #[test]
    fn the_requirement_table_follows_r4c_3_2() {
        use CustodyProperty::*;
        assert!(CustodyProfile::InsecureDevelopment.required().is_empty());
        let at_rest = [
            StoreKeySealing,
            MonotonicAnchor,
            WrappedEscrowExport,
            Destruction,
        ];
        assert_eq!(CustodyProfile::Tpm.required(), &at_rest[..]);
        assert_eq!(CustodyProfile::HsmH1.required(), &at_rest[..]);
        let h2 = CustodyProfile::HsmH2.required();
        assert_eq!(h2.len(), 5);
        assert!(h2.contains(&NonExportableCompute));
        assert!(at_rest.iter().all(|p| h2.contains(p)));
    }

    /// r4-c §3.2, §3.7 step 1; R50-18: the development backend declares
    /// itself, provides nothing, and announces itself; the probe accepts it
    /// only for its own profile.
    #[test]
    fn the_development_backend_declares_and_announces_itself() {
        let dev = InsecureDevelopmentCustody::new_insecure_development();
        let properties = dev.properties();
        assert_eq!(properties.profile, CustodyProfile::InsecureDevelopment);
        for property in [
            CustodyProperty::StoreKeySealing,
            CustodyProperty::MonotonicAnchor,
            CustodyProperty::NonExportableCompute,
            CustodyProperty::WrappedEscrowExport,
            CustodyProperty::Destruction,
        ] {
            assert!(!properties.provides(property), "{property:?}");
        }
        for production in [
            CustodyProfile::Tpm,
            CustodyProfile::HsmH1,
            CustodyProfile::HsmH2,
        ] {
            let refused = probe(
                InsecureDevelopmentCustody::new_insecure_development(),
                production,
            );
            assert_eq!(
                refused.map(|_| ()).unwrap_err(),
                ProbeError::ProfileMismatch
            );
        }
        let probed = probe(dev, CustodyProfile::InsecureDevelopment).unwrap();
        assert_eq!(probed.notice(), Some(INSECURE_DEVELOPMENT_NOTICE));
        assert_eq!(probed.state(), AnchorReading::NeverInitialized);
        assert!(format!("{probed:?}").contains("InsecureDevelopment"));
    }

    /// r4-c §3.7 step 1: a production configuration never runs a backend of
    /// another profile, nor one that lacks a required property; a
    /// production backend is never accepted for a development configuration.
    #[test]
    fn the_probe_refuses_mismatches_and_missing_properties() {
        let ok = probe(
            declared(
                all(CustodyProfile::Tpm),
                Ok(AnchorReading::NeverInitialized),
            ),
            CustodyProfile::Tpm,
        )
        .unwrap();
        assert_eq!(ok.notice(), None);
        for (profile, missing) in [
            (CustodyProfile::Tpm, CustodyProperty::MonotonicAnchor),
            (CustodyProfile::HsmH1, CustodyProperty::StoreKeySealing),
            (CustodyProfile::HsmH2, CustodyProperty::NonExportableCompute),
            (CustodyProfile::Tpm, CustodyProperty::WrappedEscrowExport),
            (CustodyProfile::HsmH1, CustodyProperty::Destruction),
        ] {
            let mut properties = all(profile);
            match missing {
                CustodyProperty::StoreKeySealing => properties.store_key_sealing = false,
                CustodyProperty::MonotonicAnchor => properties.monotonic_anchor = false,
                CustodyProperty::NonExportableCompute => properties.non_exportable_compute = false,
                CustodyProperty::WrappedEscrowExport => properties.wrapped_escrow_export = false,
                CustodyProperty::Destruction => properties.destruction = false,
            }
            let refused = probe(
                declared(properties, Ok(AnchorReading::NeverInitialized)),
                profile,
            );
            assert_eq!(
                refused.map(|_| ()).unwrap_err(),
                ProbeError::MissingProperty(missing)
            );
        }
        // A TPM backend lacking non-exportable computation is still a TPM.
        let mut tpm = all(CustodyProfile::Tpm);
        tpm.non_exportable_compute = false;
        assert!(probe(
            declared(tpm, Ok(AnchorReading::NeverInitialized)),
            CustodyProfile::Tpm
        )
        .is_ok());
        // Production backends for a development configuration, and across
        // production profiles.
        for (backend, expected) in [
            (CustodyProfile::Tpm, CustodyProfile::InsecureDevelopment),
            (CustodyProfile::HsmH2, CustodyProfile::InsecureDevelopment),
            (CustodyProfile::HsmH1, CustodyProfile::Tpm),
            (CustodyProfile::HsmH1, CustodyProfile::HsmH2),
        ] {
            let refused = probe(
                declared(all(backend), Ok(AnchorReading::NeverInitialized)),
                expected,
            );
            assert_eq!(
                refused.map(|_| ()).unwrap_err(),
                ProbeError::ProfileMismatch
            );
        }
    }

    /// C38 (r4-c §9.1): a backend that cannot read its anchor is refused —
    /// the failure is never taken for "never initialized".
    #[test]
    fn an_unreadable_anchor_is_never_initial_state() {
        for error in [CustodyError::Unavailable, CustodyError::Refused] {
            let refused = probe(
                declared(all(CustodyProfile::Tpm), Err(error)),
                CustodyProfile::Tpm,
            );
            assert_eq!(refused.map(|_| ()).unwrap_err(), ProbeError::Backend(error));
        }
    }

    /// C38, R4C-3: the ceremony evidence comes only from binding a backend
    /// the probe read as never initialized, once; a bound backend — even one
    /// whose anchor still reads 0 — never yields it.
    #[test]
    fn provisioning_evidence_only_from_a_never_initialized_backend() {
        let mut probed = probe(
            InsecureDevelopmentCustody::new_insecure_development(),
            CustodyProfile::InsecureDevelopment,
        )
        .unwrap();
        let evidence = probed.bind_new_store(id(1)).unwrap();
        assert_eq!(evidence.store_id(), id(1));
        assert_eq!(
            probed.state(),
            AnchorReading::Bound {
                store_id: id(1),
                generation: 0
            }
        );
        assert_eq!(probed.bind_new_store(id(2)), Err(CustodyError::Refused));
        // A restart of the store layer: the backend is probed again and
        // reads Bound — never NeverInitialized again.
        let mut again = probe(probed.into_backend(), CustodyProfile::InsecureDevelopment).unwrap();
        assert_eq!(
            again.state(),
            AnchorReading::Bound {
                store_id: id(1),
                generation: 0
            }
        );
        assert_eq!(again.bind_new_store(id(1)), Err(CustodyError::Refused));
        // A probe that read Bound never binds.
        let mut bound = probe(
            declared(
                all(CustodyProfile::Tpm),
                Ok(AnchorReading::Bound {
                    store_id: id(3),
                    generation: 5,
                }),
            ),
            CustodyProfile::Tpm,
        )
        .unwrap();
        assert_eq!(bound.bind_new_store(id(4)), Err(CustodyError::Refused));
    }

    /// The binding is read back: a backend that claims to bind but does not
    /// read `Bound { store_id, 0 }` afterwards is refused, and the handle
    /// is not left never-initialized.
    #[test]
    fn a_binding_that_does_not_read_back_is_refused() {
        for read_back in [
            None,
            Some(AnchorReading::Bound {
                store_id: id(9),
                generation: 0,
            }),
            Some(AnchorReading::Bound {
                store_id: id(1),
                generation: 1,
            }),
        ] {
            let mut backend = declared(
                all(CustodyProfile::Tpm),
                Ok(AnchorReading::NeverInitialized),
            );
            backend.bind_reads_back = read_back;
            let mut probed = probe(backend, CustodyProfile::Tpm).unwrap();
            assert_eq!(probed.bind_new_store(id(1)), Err(CustodyError::Refused));
            assert_eq!(probed.bind_new_store(id(1)), Err(CustodyError::Refused));
        }
    }

    /// r4-c §3.6: the anchor moves one step at a time, from its current
    /// value only; a backend that moves it otherwise is refused.
    #[test]
    fn the_anchor_moves_one_step_from_its_value() {
        let mut probed = probe(
            InsecureDevelopmentCustody::new_insecure_development(),
            CustodyProfile::InsecureDevelopment,
        )
        .unwrap();
        assert_eq!(probed.advance_anchor(0), Err(CustodyError::Refused));
        probed.bind_new_store(id(1)).unwrap();
        assert_eq!(probed.advance_anchor(1), Err(CustodyError::Refused));
        assert_eq!(probed.advance_anchor(0), Ok(1));
        assert_eq!(probed.advance_anchor(0), Err(CustodyError::Refused));
        assert_eq!(probed.advance_anchor(1), Ok(2));
        assert_eq!(
            probed.state(),
            AnchorReading::Bound {
                store_id: id(1),
                generation: 2
            }
        );
        // Another store's id, at the backend.
        let mut dev = probed.into_backend();
        assert_eq!(
            dev.advance_anchor(sealed::Access::new(), AnchorName::KeydStore, &id(2), 2),
            Err(CustodyError::Refused)
        );
        // The counter's end.
        let mut full = InsecureDevelopmentCustody {
            state: DevelopmentState::Bound {
                store_id: id(1),
                generation: u64::MAX,
                store_key: StoreWrappingKey::draw(&mut OsEntropy::new()).unwrap(),
            },
        };
        assert_eq!(
            full.advance_anchor(
                sealed::Access::new(),
                AnchorName::KeydStore,
                &id(1),
                u64::MAX
            ),
            Err(CustodyError::Refused)
        );
        // A backend that jumps is refused.
        let mut jumping = probe(
            declared(
                all(CustodyProfile::Tpm),
                Ok(AnchorReading::Bound {
                    store_id: id(1),
                    generation: 4,
                }),
            ),
            CustodyProfile::Tpm,
        )
        .unwrap();
        assert_eq!(jumping.advance_anchor(4), Err(CustodyError::Refused));
    }

    /// r4-c §3.7 step 3: the SWK is unsealed only for the bound store, is
    /// the same on every unseal, and appears in no Debug output.
    #[test]
    fn the_store_key_is_unsealed_only_when_bound() {
        let mut probed = probe(
            InsecureDevelopmentCustody::new_insecure_development(),
            CustodyProfile::InsecureDevelopment,
        )
        .unwrap();
        assert_eq!(
            probed.unseal_store_key().map(|_| ()),
            Err(CustodyError::Refused)
        );
        probed.bind_new_store(id(1)).unwrap();
        let first = probed.unseal_store_key().unwrap();
        let second = probed.unseal_store_key().unwrap();
        assert_eq!(first.octets(), second.octets());
        assert_ne!(first.octets(), &[0u8; STORE_KEY_OCTETS]);
        let mut dev = probed.into_backend();
        assert_eq!(
            dev.unseal_store_key(sealed::Access::new(), &id(2))
                .map(|_| ()),
            Err(CustodyError::Refused)
        );
        // Debug: no key octet.
        let hex: String = first.octets().iter().map(|b| format!("{b:02x}")).collect();
        for text in [format!("{first:?}"), format!("{dev:?}")] {
            assert!(!text.contains(&hex[..8]), "{text}");
        }
        assert_eq!(format!("{first:?}"), "StoreWrappingKey(..)");
        assert!(format!("{dev:?}").contains("insecure_development: true"));
        // A fresh development backend is a different store key.
        let mut other = probe(
            InsecureDevelopmentCustody::new_insecure_development(),
            CustodyProfile::InsecureDevelopment,
        )
        .unwrap();
        other.bind_new_store(id(1)).unwrap();
        assert_ne!(other.unseal_store_key().unwrap().octets(), first.octets());
    }
}
