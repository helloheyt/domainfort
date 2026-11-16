//! The test signer of name resolutions (task PN10; docs/59 §7.1, §7.4):
//! the account records a `DirectoryView` answers carry dird's attested
//! resolution of the lookup (`ClientAccount` / `ServiceAccount`
//! `resolution`), made by the signer installed on the context
//! (`DirectoryContext::with_name_resolution_signer`) — a context without one
//! answers no record (fail closed). In the product the signer is crates/
//! ipc-directory-server's `ResolutionSigner` (dird's attestation key and
//! clock). The fixtures of crates that cannot reach it install this one:
//! the same construction — `ResolvedPrincipal::name_resolution` at a time,
//! tagged with crate name-attestation's `tag` — under the test key
//! [`TEST_ATTESTATION_KEY`] and a fixed issue time.
//!
//! The ONE test signer the directory fixtures share (crates/directory-pip
//! tests/common, and through it crates/ipc-directory-server and
//! crates/ipc-ldap-server), each with name-attestation as a dev-dependency.
//! Only the KDC's account records need it: the subject checks (crates
//! directory-admin and ldap) read the ticket-subject lookup, which attests
//! nothing, so their fixtures install no signer (task PN10b; docs/
//! questions/Q-1047).
//!
//! Source: docs/59 §7.1, §7.4; docs/questions/Q-1011 items 1-3 (A-173),
//! Q-1046, Q-1047 (A-187). Test-only; this project's own code, no other
//! implementation consulted.
#![allow(dead_code)] // each including test binary uses a different subset

use directory_pip::{NameResolutionSigner, ResolvedPrincipal, SignerRefused};
use keyd_types::AttestedNameResolution;
use krb_proto::KerberosTime;
use name_attestation::{AttestationKey, ATTESTATION_KEY_LEN};
use std::sync::Arc;

/// The test attestation key (made up here; the value crates/kdc
/// tests/common uses for its records too).
pub const TEST_ATTESTATION_KEY: [u8; ATTESTATION_KEY_LEN] = [0x4B; ATTESTATION_KEY_LEN];

/// A signer with the test key and a fixed issue time.
/// Spec: docs/59 §7.1, §7.4.
pub struct TestSigner {
    key: AttestationKey,
    issued_at: KerberosTime,
}

impl NameResolutionSigner for TestSigner {
    /// `resolved`'s resolution at the fixed time, tagged with the test key —
    /// the construction of dird's `ResolutionSigner`.
    fn attest(
        &self,
        resolved: &ResolvedPrincipal,
    ) -> Result<AttestedNameResolution, SignerRefused> {
        let resolution = resolved
            .name_resolution(self.issued_at)
            .map_err(|_| SignerRefused)?;
        name_attestation::tag(&self.key, &resolution).map_err(|_| SignerRefused)
    }
}

/// The test signer issuing at `issued_at`.
pub fn test_signer_at(issued_at: KerberosTime) -> Arc<dyn NameResolutionSigner> {
    Arc::new(TestSigner {
        key: AttestationKey::from_bytes(&TEST_ATTESTATION_KEY).expect("a non-zero test key"),
        issued_at,
    })
}

/// The test signer issuing at a fixed time of the fixtures (2026-11-16
/// 12:00:00Z).
pub fn test_signer() -> Arc<dyn NameResolutionSigner> {
    test_signer_at(KerberosTime::new(2026, 11, 16, 12, 0, 0).expect("a valid time"))
}
