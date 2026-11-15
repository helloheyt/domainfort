#![forbid(unsafe_code)]
//! `name-attestation`: dird's attestation of a name resolution to keyd
//! (task PN3; docs/59 §7.4; decision A-173 — docs/questions/Q-1011 item 2).
//!
//! | item | who | what |
//! |---|---|---|
//! | [`AttestationKey`] | dird, keyd | the attestation key: one purpose, wiped on drop, never printed, never handed out |
//! | [`tag`] | dird (the signer) | `NameResolution` ⇒ `AttestedNameResolution` |
//! | [`verify`] | keyd (the verifier) | `AttestedNameResolution` ⇒ [`AuthenticatedNameResolution`] — the tag compared in constant time |
//!
//! # The construction (this project's, on the approved primitive)
//!
//! ```text
//! tag = HMAC-SHA-256(K, NameResolution::mac_input())
//! mac_input = len(label) ‖ "principal-name-resolution.v1" ‖ the fields (keyd-types)
//! ```
//!
//! HMAC is FIPS 198-1 §4 with H = SHA-256 (FIPS 180-4; B = 64, L = 32 —
//! FIPS 180-4 §1 Figure 1: a 512-bit block, a 256-bit digest), computed by
//! the approved RustCrypto `hmac` and `sha2` (OD-9) — no primitive is
//! implemented here (AGENTS.md §6). The tag is the full L = 32 octets (FIPS
//! 198-1 §5: no truncation is used), its length fixed by the type
//! (`keyd_types::NAME_RESOLUTION_TAG_LEN`, checked against the MAC's output
//! size at compile time), never by the wire (A-145 RC-4). The key is
//! [`ATTESTATION_KEY_LEN`] = 32 octets, below B, so FIPS 198-1 step 3 pads
//! it with zeros to K0 (step 2, hashing a long key, never applies).
//!
//! What is tagged is defined once, in keyd-types
//! (`NameResolution::mac_input`, crypto-free — A-65): dird and keyd call the
//! same encoder (docs/59 §7.1, C44). It begins with the length-prefixed
//! label, so a tag of another use of the same key (the future PAC-facts
//! attestation, Q-722 item 1 / A-129, with its own label) is never valid
//! here (docs/59 §7.4).
//!
//! # Classes closed by construction (AGENTS.md §6.1)
//!
//! * **C42 — a general MAC oracle over a long-term key** (A-145 RC-6). The
//!   public operations take a `NameResolution` (or the attested pair), never
//!   caller-chosen octets: the only input a caller controls is the value of
//!   bounded, typed fields, always behind the label — so whoever can call
//!   [`tag`] obtains tags only for name resolutions, never for a message of
//!   another protocol or another use. There is no public function that MACs
//!   bytes (pinned by `tests/api_surface.rs`). And keyd never computes tags
//!   for dird: dird holds the key itself (Q-1011 item 2 — keyd tagging on
//!   request would be exactly such an oracle).
//! * **Key export** (D28 / D29: no operation returns key material). The key
//!   enters once ([`AttestationKey::from_bytes`]) and never leaves: no
//!   accessor, no `Debug`, no `Display`, no `Clone`, no `PartialEq` (the
//!   `compile_fail` examples on [`AttestationKey`]). keyd receives it in
//!   ceremony mode only and never hands it back (Q-1011 item 2; task PN9).
//! * **Use before verification** (docs/59 §7.2 step 1: the MAC comes before
//!   any use of the fields). [`AuthenticatedNameResolution`] has private fields
//!   and is built only by [`verify`], after the tag compared equal — so
//!   keyd's `VerifiedNameResolution` (task PN8), built from it, cannot exist
//!   for a resolution whose tag was not checked.
//! * **Timing of the comparison** (RC-7's spirit: one opaque failure). The
//!   received tag is compared with the computed one through `CtOutput`'s
//!   equality, which the `digest` API documents as running in constant
//!   time; every failure (bad bound, bad tag) is the one
//!   [`AttestationError`], carrying no data.
//!
//! Freshness (W = 30 s on keyd's clock) and the realm and handle checks are
//! keyd's (docs/59 §7.2 steps 2–4; `NameResolution::is_fresh_at`): this crate
//! answers one question — did the key's holder state exactly this?
//!
//! # Provenance
//!
//! Written only from docs/59 §7, docs/questions/Q-1011, Q-792, Q-722,
//! PENDING-OWNER A-65, A-145, A-173, FIPS 198-1 (July 2008) §2.3, §3, §4,
//! §5 and FIPS 180-4 §1 (csrc.nist.gov, opened in-session — the csrc-hosted
//! FIPS 180-4 text is the August 2014 draft, whose cover says the August
//! 2015 release "updates only the Applicability Clause";
//! docs/questions/Q-1022), RFC 8009 §3, §5 and App. A (pinned,
//! SHA-256 re-checked against tools/spec-pin/manifest.json), and the docs.rs
//! API pages of hmac 0.13.0, digest 0.11.3, crypto-common 0.2.2,
//! hybrid-array 0.4.15 and sha2 0.11.1. No other implementation was
//! consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/59 §7.1, §7.2, §7.4; docs/questions/Q-1011 items 1–3 (A-173);
//! A-145 RC-1, RC-4, RC-6, RC-7 (C42); FIPS 198-1 §4, §5; FIPS 180-4 §1.

use core::fmt;
use hmac::digest::CtOutput;
use hmac::{Hmac, KeyInit, Mac};
use keyd_types::{AttestedNameResolution, NameResolution, NAME_RESOLUTION_TAG_LEN};
use sha2::Sha256;
use zeroize::Zeroizing;

/// HMAC with H = SHA-256. Spec: FIPS 198-1 §4; FIPS 180-4 §6.2.
type HmacSha256 = Hmac<Sha256>;

/// Octets of the attestation key: L, the SHA-256 output size (FIPS 180-4 §1
/// Figure 1: 256 bits) — a project choice, as for the store's integrity key
/// (D135). Below B (64 octets), so FIPS 198-1 step 3 zero-pads it to K0.
/// Spec: FIPS 198-1 §2.3, §3, §4 steps 1–3; FIPS 180-4 §1; docs/59 §7.4.
pub const ATTESTATION_KEY_LEN: usize = 32;

/// The attestation key dird tags name resolutions with and keyd verifies
/// them with — one key, typed for this purpose (A-145 RC-1); its other use,
/// the future PAC-facts attestation (Q-722 item 1), is separated by the
/// label in what is tagged, not by a second key (Q-1011 item 2).
///
/// Held in a [`Zeroizing`] buffer (wiped on drop). It enters once
/// ([`AttestationKey::from_bytes`]) and never leaves: there is no accessor,
/// and no `Debug`, `Display`, `Clone` or `PartialEq`:
///
/// ```compile_fail,E0277
/// fn show(key: &name_attestation::AttestationKey) -> String {
///     format!("{key:?}")
/// }
/// ```
///
/// ```compile_fail,E0277
/// fn show(key: &name_attestation::AttestationKey) -> String {
///     format!("{key}")
/// }
/// ```
///
/// ```compile_fail,E0277
/// fn copy(key: &name_attestation::AttestationKey) -> name_attestation::AttestationKey {
///     Clone::clone(key)
/// }
/// ```
///
/// ```compile_fail,E0369
/// fn same(a: &name_attestation::AttestationKey, b: &name_attestation::AttestationKey) -> bool {
///     a == b
/// }
/// ```
///
/// Spec: docs/59 §7.4 (an `AttestationKey` that zeroizes and has no
/// `Debug` or `Clone`); docs/questions/Q-1011 item 2 (A-173: never
/// exported); D28 / D29; A-145 RC-1; AGENTS.md §6 (secrets never in logs).
pub struct AttestationKey {
    key: Zeroizing<[u8; ATTESTATION_KEY_LEN]>,
}

impl AttestationKey {
    /// Take a copy of the key (the caller wipes its own copy). Refuses the
    /// all-zero key: provisioning draws the key at random (Q-1011 item 2),
    /// so all zeros means a buffer that was never filled — fail closed.
    /// Spec: docs/questions/Q-1011 item 2; FIPS 198-1 §3 (a key "of
    /// appropriate security strength"); AGENTS.md §6 (fail closed).
    pub fn from_bytes(bytes: &[u8; ATTESTATION_KEY_LEN]) -> Result<AttestationKey, KeyRefused> {
        if bytes.iter().all(|&octet| octet == 0) {
            return Err(KeyRefused);
        }
        Ok(AttestationKey {
            key: Zeroizing::new(*bytes),
        })
    }
}

/// The attestation key was refused (all zeros). No data.
/// Spec: [`AttestationKey::from_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRefused;

impl fmt::Display for KeyRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("attestation key refused")
    }
}

impl std::error::Error for KeyRefused {}

/// A name resolution could not be tagged, or its tag is not right. One
/// error for every failure (a field outside its bound, a wrong tag), with no
/// data: nothing about the key or the computed tag can reach it.
/// Spec: A-145 RC-7 (one error for every failure); AGENTS.md §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationError;

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("name resolution attestation refused")
    }
}

impl std::error::Error for AttestationError {}

/// A name resolution whose tag [`verify`] accepted under the attestation
/// key — the only proof that the key's holder (dird) stated exactly this.
/// Its fields are private and only [`verify`] builds one, so keyd's
/// `VerifiedNameResolution` (docs/59 §7.2, task PN8), built from it, never
/// holds a resolution whose tag was not checked. It says nothing about
/// freshness, the realm or the handle: those are keyd's checks (steps 2–4).
/// Spec: docs/59 §7.2 step 1; AGENTS.md §6.1 ("a type that can only be
/// built after the check").
#[derive(Debug, Clone)]
pub struct AuthenticatedNameResolution {
    resolution: NameResolution,
}

impl AuthenticatedNameResolution {
    /// The resolution. Spec: docs/59 §7.1.
    #[must_use]
    pub fn resolution(&self) -> &NameResolution {
        &self.resolution
    }

    /// The resolution, by value. Spec: docs/59 §7.1.
    #[must_use]
    pub fn into_resolution(self) -> NameResolution {
        self.resolution
    }
}

/// dird's side: tag `resolution` under `key` — HMAC-SHA-256 over
/// `resolution.mac_input()` (the label and the fields, keyd-types) — and
/// pair the two. Fails only for a value outside its bounds (which
/// `NameResolution::new` already refuses).
/// Spec: docs/59 §7.1, §7.4; docs/questions/Q-1011 item 2; FIPS 198-1 §4.
pub fn tag(
    key: &AttestationKey,
    resolution: &NameResolution,
) -> Result<AttestedNameResolution, AttestationError> {
    let input = resolution.mac_input().map_err(|_| AttestationError)?;
    let tag = hmac_sha256(key, &input)?;
    Ok(AttestedNameResolution::new(resolution.clone(), tag))
}

/// keyd's side: recompute the tag over the received resolution's MAC input
/// and compare it with the received tag in constant time (`CtOutput`'s
/// equality, documented constant-time by the `digest` API), **before**
/// anything else uses the fields. Equal ⇒ the proof
/// [`AuthenticatedNameResolution`]; otherwise [`AttestationError`].
/// Spec: docs/59 §7.2 step 1 (the MAC with a constant-time comparison,
/// before any use of the fields); docs/questions/Q-1011 item 4; FIPS 198-1
/// §4; A-145 RC-4 (the length is the type's).
pub fn verify(
    key: &AttestationKey,
    attested: &AttestedNameResolution,
) -> Result<AuthenticatedNameResolution, AttestationError> {
    let resolution = attested.resolution();
    let input = resolution.mac_input().map_err(|_| AttestationError)?;
    let mut mac = keyed(key)?;
    mac.update(&input);
    let received = CtOutput::<HmacSha256>::new((*attested.tag()).into());
    if mac.finalize() == received {
        Ok(AuthenticatedNameResolution {
            resolution: resolution.clone(),
        })
    } else {
        Err(AttestationError)
    }
}

/// An HMAC-SHA-256 instance keyed with the attestation key. HMAC accepts a
/// key of any length (FIPS 198-1 §4 steps 1–3); the error arm is mapped,
/// not unwrapped (no panic path).
/// Spec: FIPS 198-1 §4; crypto-common 0.2.2 `KeyInit::new_from_slice`.
fn keyed(key: &AttestationKey) -> Result<HmacSha256, AttestationError> {
    <HmacSha256 as KeyInit>::new_from_slice(&key.key[..]).map_err(|_| AttestationError)
}

/// HMAC-SHA-256(K, message), the full L = 32 octets. **Private**: the
/// public operations call it only on a `NameResolution`'s MAC input, so no
/// caller can have caller-chosen octets tagged (C42, RC-6). The conversion
/// to `[u8; NAME_RESOLUTION_TAG_LEN]` compiles only if that length is the
/// MAC's output size.
/// Spec: FIPS 198-1 §4, §5; FIPS 180-4 §1; A-145 RC-4, RC-6.
fn hmac_sha256(
    key: &AttestationKey,
    message: &[u8],
) -> Result<[u8; NAME_RESOLUTION_TAG_LEN], AttestationError> {
    let mut mac = keyed(key)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    //! Sources: RFC 8009 App. A (pinned, SHA-256 re-checked against
    //! tools/spec-pin/manifest.json) — the HMAC-SHA-256 keys, input messages
    //! and outputs of its PRF and key-derivation samples, read through §3
    //! (K1 = HMAC-SHA-256(key, 0x00000001 | label | 0x00 | [context |] k))
    //! and §5 (PRF = KDF-HMAC-SHA2(input-key, "prf", octet-string, 256));
    //! FIPS 198-1 §4 step 3 (a key shorter than B is zero-padded to B, so a
    //! 16-octet key and the same key followed by 16 zero octets give the
    //! same K0 and the same MAC); docs/59 §7 and docs/questions/Q-1011 for
    //! the attestation's behaviour. RFC 4231 is not pinned and not in
    //! specs/SOURCES.md, so none of its vectors is used (docs/questions/
    //! Q-1022). Every other value is constructed by hand; no vector comes
    //! from any other implementation.

    use super::*;
    use keyd_types::{KeyPurpose, NameResolutionFields, PrincipalId};
    use krb_proto::{KerberosString, KerberosTime, PrincipalName};

    /// RFC 8009 App. A: the aes128-cts-hmac-sha256-128 "input-key value /
    /// HMAC-SHA-256 key" of the PRF sample, which is also the "128-bit
    /// base-key" of the key-derivation samples.
    const RFC8009_KEY_128: [u8; 16] = [
        0x37, 0x05, 0xD9, 0x60, 0x80, 0xC1, 0x77, 0x28, 0xA0, 0xE8, 0x00, 0xEA, 0xB6, 0xE0, 0xD2,
        0x3C,
    ];

    /// FIPS 198-1 §4 step 3: the 16-octet RFC 8009 key followed by 16 zero
    /// octets pads to the same 64-octet K0 as the 16-octet key itself.
    fn rfc8009_key() -> AttestationKey {
        let mut k = [0u8; ATTESTATION_KEY_LEN];
        k[..16].copy_from_slice(&RFC8009_KEY_128);
        AttestationKey::from_bytes(&k).unwrap()
    }

    /// RFC 8009 App. A, "Sample pseudorandom function (PRF) invocations",
    /// enctype aes128-cts-hmac-sha256-128: the "HMAC-SHA-256 input message"
    /// and the 256-bit "PRF output" — k = 256, so k-truncate keeps the whole
    /// HMAC-SHA-256 output (§3, §5). A full 32-octet known answer for the
    /// primitive as this crate wires it.
    #[test]
    fn hmac_sha256_gives_the_rfc8009_prf_output() {
        let message = [
            0x00, 0x00, 0x00, 0x01, 0x70, 0x72, 0x66, 0x00, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00,
            0x01, 0x00,
        ];
        let expected = [
            0x9D, 0x18, 0x86, 0x16, 0xF6, 0x38, 0x52, 0xFE, 0x86, 0x91, 0x5B, 0xB8, 0x40, 0xB4,
            0xA8, 0x86, 0xFF, 0x3E, 0x6B, 0xB0, 0xF8, 0x19, 0xB4, 0x9B, 0x89, 0x33, 0x93, 0xD3,
            0x93, 0x85, 0x42, 0x95,
        ];
        assert_eq!(hmac_sha256(&rfc8009_key(), &message).unwrap(), expected);
    }

    /// RFC 8009 App. A, "Sample results for key derivation", enctype
    /// aes128-cts-hmac-sha256-128, key usage 2: Kc / Ke / Ki are the
    /// leftmost 128 bits of HMAC-SHA-256(base-key, 0x00000001 | usage |
    /// 0x99/0xAA/0x55 | 0x00 | 0x00000080) (§3 with no context; §5
    /// "Kc = KDF-HMAC-SHA2(base-key, usage | 0x99, 128)"). Three more known
    /// answers, for the first half of the output.
    #[test]
    fn hmac_sha256_gives_the_rfc8009_derived_keys() {
        let samples: [(u8, [u8; 16]); 3] = [
            (
                0x99,
                [
                    0xB3, 0x1A, 0x01, 0x8A, 0x48, 0xF5, 0x47, 0x76, 0xF4, 0x03, 0xE9, 0xA3, 0x96,
                    0x32, 0x5D, 0xC3,
                ],
            ),
            (
                0xAA,
                [
                    0x9B, 0x19, 0x7D, 0xD1, 0xE8, 0xC5, 0x60, 0x9D, 0x6E, 0x67, 0xC3, 0xE3, 0x7C,
                    0x62, 0xC7, 0x2E,
                ],
            ),
            (
                0x55,
                [
                    0x9F, 0xDA, 0x0E, 0x56, 0xAB, 0x2D, 0x85, 0xE1, 0x56, 0x9A, 0x68, 0x86, 0x96,
                    0xC2, 0x6A, 0x6C,
                ],
            ),
        ];
        for (constant, expected) in samples {
            let message = [
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, constant, 0x00, 0x00, 0x00, 0x00,
                0x80,
            ];
            let k1 = hmac_sha256(&rfc8009_key(), &message).unwrap();
            assert_eq!(&k1[..16], &expected[..], "constant {constant:#04x}");
        }
    }

    /// FIPS 198-1 §4 steps 1–3: K0 holds every octet of a key shorter than
    /// B, so changing any one of the 32 key octets changes the MAC (the
    /// RFC 8009 key exercises only the first 16).
    #[test]
    fn every_key_octet_reaches_the_mac() {
        let message = b"FIPS 198-1 step 3";
        let base = [0x5Au8; ATTESTATION_KEY_LEN];
        let reference = hmac_sha256(&AttestationKey::from_bytes(&base).unwrap(), message).unwrap();
        for i in 0..ATTESTATION_KEY_LEN {
            let mut k = base;
            k[i] ^= 0x01;
            let other = hmac_sha256(&AttestationKey::from_bytes(&k).unwrap(), message).unwrap();
            assert_ne!(other, reference, "key octet {i}");
        }
    }

    fn s(text: &str) -> KerberosString {
        KerberosString::new(text).unwrap()
    }

    fn name(name_type: i32, parts: &[&str]) -> PrincipalName {
        PrincipalName {
            name_type,
            name_string: parts.iter().map(|p| s(p)).collect(),
        }
    }

    fn fields() -> NameResolutionFields {
        NameResolutionFields {
            realm_as_sent: s("LAB.TEST"),
            name_as_sent: name(1, &["ws01$"]),
            canonical_realm: s("LAB.TEST"),
            canonical_name: name(1, &["ws01$"]),
            principal: PrincipalId::from_bytes([0x42; 16]),
            key_purpose: KeyPurpose::PrincipalLongterm,
            snapshot: 7,
            issued_at: KerberosTime::new(2026, 11, 15, 12, 0, 0).unwrap(),
        }
    }

    fn resolution() -> NameResolution {
        NameResolution::new(fields()).unwrap()
    }

    fn key() -> AttestationKey {
        AttestationKey::from_bytes(&[0xC3; ATTESTATION_KEY_LEN]).unwrap()
    }

    /// The tag is HMAC-SHA-256 over exactly keyd-types' MAC input — nothing
    /// added, nothing left out (docs/59 §7.1: one encoding for signer and
    /// verifier).
    #[test]
    fn the_tag_is_the_mac_of_the_one_encoding() {
        let r = resolution();
        let attested = tag(&key(), &r).unwrap();
        assert_eq!(attested.resolution(), &r);
        assert_eq!(
            attested.tag(),
            &hmac_sha256(&key(), &r.mac_input().unwrap()).unwrap()
        );
        // Deterministic: the same key and resolution give the same tag.
        assert_eq!(tag(&key(), &r).unwrap().tag(), attested.tag());
    }

    /// What dird tags, keyd accepts, and the proof carries it unchanged.
    #[test]
    fn a_tagged_resolution_verifies() {
        let attested = tag(&key(), &resolution()).unwrap();
        let proof = verify(&key(), &attested).unwrap();
        assert_eq!(proof.resolution(), &resolution());
        assert_eq!(proof.into_resolution(), resolution());
    }

    /// docs/59 §10.1 (attacks): a resolution changed in any field after
    /// tagging — another principal, another purpose, another name or realm,
    /// a stale or future issue time, another snapshot — is refused.
    #[test]
    fn a_changed_field_is_refused() {
        let original = tag(&key(), &resolution()).unwrap();
        let changed: Vec<(&str, NameResolutionFields)> = vec![
            ("realm_as_sent", {
                let mut f = fields();
                f.realm_as_sent = s("lab.test");
                f
            }),
            ("name_as_sent", {
                let mut f = fields();
                f.name_as_sent = name(1, &["administrator"]);
                f
            }),
            ("name_as_sent type", {
                let mut f = fields();
                f.name_as_sent = name(10, &["ws01$"]);
                f
            }),
            ("canonical_realm", {
                let mut f = fields();
                f.canonical_realm = s("OTHER.TEST");
                f
            }),
            ("canonical_name", {
                let mut f = fields();
                f.canonical_name = name(2, &["host", "ws01.lab.test"]);
                f
            }),
            ("principal", {
                let mut f = fields();
                f.principal = PrincipalId::from_bytes([0x43; 16]);
                f
            }),
            ("key_purpose", {
                let mut f = fields();
                f.key_purpose = KeyPurpose::Krbtgt;
                f
            }),
            ("snapshot", {
                let mut f = fields();
                f.snapshot = 8;
                f
            }),
            ("issued_at", {
                let mut f = fields();
                f.issued_at = KerberosTime::new(2026, 11, 15, 12, 0, 1).unwrap();
                f
            }),
        ];
        for (what, f) in changed {
            let forged =
                AttestedNameResolution::new(NameResolution::new(f).unwrap(), *original.tag());
            assert_eq!(
                verify(&key(), &forged).unwrap_err(),
                AttestationError,
                "{what}"
            );
        }
    }

    /// Every bit of the tag matters (the full L = 32 octets are compared —
    /// FIPS 198-1 §5: no truncation; A-145 RC-4).
    #[test]
    fn a_changed_tag_bit_is_refused() {
        let original = tag(&key(), &resolution()).unwrap();
        for octet in 0..NAME_RESOLUTION_TAG_LEN {
            for bit in 0..8 {
                let mut t = *original.tag();
                t[octet] ^= 1 << bit;
                let forged = AttestedNameResolution::new(resolution(), t);
                assert!(verify(&key(), &forged).is_err(), "octet {octet} bit {bit}");
            }
        }
        let zero = AttestedNameResolution::new(resolution(), [0; NAME_RESOLUTION_TAG_LEN]);
        assert!(verify(&key(), &zero).is_err());
    }

    /// A tag under another key is refused (only the key's holder attests).
    #[test]
    fn another_key_is_refused() {
        let attested = tag(&key(), &resolution()).unwrap();
        let other = AttestationKey::from_bytes(&[0xC4; ATTESTATION_KEY_LEN]).unwrap();
        assert!(verify(&other, &attested).is_err());
    }

    /// docs/59 §7.4, §10.1 (a resolution of another use — another label — is
    /// denied): the same fields tagged under another label — as another use
    /// of the one key would — do not verify here. The input is built by
    /// hand: keyd-types' encoding with only the label replaced.
    #[test]
    fn a_tag_of_another_use_is_refused() {
        let r = resolution();
        let ours = r.mac_input().unwrap();
        let label = keyd_types::NAME_RESOLUTION_LABEL;
        let other_label = b"pac-facts-attestation.v1";
        let mut theirs = vec![u8::try_from(other_label.len()).unwrap()];
        theirs.extend_from_slice(other_label);
        theirs.extend_from_slice(&ours[1 + label.len()..]);
        assert_ne!(theirs, ours);
        let other_use = hmac_sha256(&key(), &theirs).unwrap();
        let forged = AttestedNameResolution::new(r, other_use);
        assert!(verify(&key(), &forged).is_err());
    }

    /// The all-zero key is refused (fail closed — a buffer never filled).
    #[test]
    fn the_all_zero_key_is_refused() {
        assert!(AttestationKey::from_bytes(&[0; ATTESTATION_KEY_LEN]).is_err());
        let mut one = [0; ATTESTATION_KEY_LEN];
        one[ATTESTATION_KEY_LEN - 1] = 1;
        assert!(AttestationKey::from_bytes(&one).is_ok());
    }

    /// The errors carry no data (AGENTS.md §6: nothing secret in an error).
    #[test]
    fn the_errors_carry_no_data() {
        assert_eq!(
            AttestationError.to_string(),
            "name resolution attestation refused"
        );
        assert_eq!(KeyRefused.to_string(), "attestation key refused");
        assert_eq!(format!("{AttestationError:?}"), "AttestationError");
        assert_eq!(format!("{KeyRefused:?}"), "KeyRefused");
    }
}
