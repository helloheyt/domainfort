//! The dird-attested name resolution keyd binds a request's name by (task
//! PN3; docs/59 §7; decision A-173 — docs/questions/Q-1011): the types,
//! their bounds, the freshness window, and the **one** encoding of the MAC
//! input.
//!
//! # What it is
//!
//! dird resolves the name a request carries (`canonical_principal`, docs/59
//! §6) and states the result as a [`NameResolution`]: the realm and name as
//! sent, the canonical realm and name they resolved to, the principal
//! ([`PrincipalId`]) and key purpose ([`KeyPurpose`]) of the key set they
//! name, the snapshot of the view it read, and when it was issued (Q-792's
//! fields plus the two canonical names — Q-1011 item 1). dird tags it with
//! the attestation key ([`AttestedNameResolution`]); the KDC only forwards
//! it; keyd verifies the tag **before** it uses any field, then the realm,
//! the freshness ([`NameResolution::is_fresh_at`]) and that the principal and
//! purpose are the handle's (docs/59 §7.2, task PN8). So the KDC no longer
//! asserts which key set a name maps to — the fact comes from its owner
//! (class C3; docs/59 §3 M4).
//!
//! # No crypto here (A-65, D182)
//!
//! This crate links no MAC. It defines **what** is tagged —
//! [`NameResolution::mac_input`], beginning with the label
//! [`NAME_RESOLUTION_LABEL`] — and the tag's length
//! ([`NAME_RESOLUTION_TAG_LEN`]); the crate `name-attestation` computes and
//! verifies the HMAC-SHA-256 over exactly these octets. The signer (dird)
//! and the verifier (keyd) call the same encoder, so they cannot encode
//! differently (docs/59 §7.1, C44).
//!
//! # The MAC input
//!
//! ```text
//! mac_input = label_len:u8 ‖ label
//!           ‖ realm(realm_as_sent)   ‖ name(name_as_sent)
//!           ‖ realm(canonical_realm) ‖ name(canonical_name)
//!           ‖ principal[16] ‖ key_purpose:u8 ‖ snapshot:u64
//!           ‖ year:u16 ‖ month:u8 ‖ day:u8 ‖ hour:u8 ‖ minute:u8 ‖ second:u8
//!
//! realm(r) = len:u16 ‖ r
//! name(n)  = name_type:i32 ‖ count:u8 ‖ (len:u16 ‖ component)*
//! ```
//!
//! Integers are big-endian. Every variable-length field carries its length
//! (and a name its component count) before its octets, and every other
//! field has a fixed length, so the input is read left to right in exactly
//! one way: two different resolutions never give the same octets
//! (moving an octet from one component, realm or name to the next changes
//! a length prefix). The label is length-prefixed at the start, so an input
//! of another use of the same key (another label — the future PAC-facts
//! attestation, Q-722 / A-129) can never equal one of these (docs/59 §7.4).
//! The name-type is authenticated too: it is a hint for equivalence (RFC
//! 4120 §6.2) but part of the name dird saw, and everything the value
//! carries is covered — nothing in it can change unseen. `issued_at` is its
//! six calendar fields (RFC 4120 §5.2.3 `YYYYMMDDHHMMSSZ`); the purpose is
//! its explicit code [`KeyPurpose::code`] — the one table of it, which the
//! sealed store persists too ([`KeyPurpose`] gains no variant without one;
//! docs/questions/Q-1023 item 4).
//!
//! # Bounds (docs/CLEAN-ROOM.md)
//!
//! Each name has 1 ..= `krb_proto::limits::MAX_NAME_COMPONENTS` components;
//! each component and each realm is at most
//! [`crate::sealed_store::MAX_NAME_OCTETS`] octets — the bounds of the stored
//! binding (`PrincipalBinding`), so any name keyd can bind can be attested
//! and nothing larger is. krb-proto bounds the component count but not the
//! octets of a component or a realm (RFC 4120 §5.2.1 sets none), so the
//! octet bound is the binding's (docs/questions/Q-1023 item 3). A value is
//! checked when it is built ([`NameResolution::new`]); the encoder checks
//! again and refuses rather than truncate.
//!
//! Spec: docs/59 §3 (M4), §7.1, §7.2, §7.4; docs/questions/Q-1011 items
//! 1–3 (A-173), Q-792, Q-722 item 1 (A-129); RFC 4120 §5.2.2, §5.2.3, §6.2;
//! docs/10 §1; A-65; docs/CLEAN-ROOM.md.

use crate::model::{KeyPurpose, PrincipalId};
use crate::sealed_store::MAX_NAME_OCTETS;
use crate::time::kerberos_time_seconds;
use core::fmt;
use krb_proto::limits::MAX_NAME_COMPONENTS;
use krb_proto::{KerberosString, KerberosTime, PrincipalName, Realm};

/// The label at the start of every MAC input of a name resolution: the
/// attestation key serves more than one use (Q-722 item 1), each with its
/// own label, so a tag of one use is never valid for another.
/// Spec: docs/59 §7.4 ("`principal-name-resolution.v1`"); docs/questions/
/// Q-1011 item 2 (A-173).
pub const NAME_RESOLUTION_LABEL: &[u8] = b"principal-name-resolution.v1";

/// Octets of a name resolution's tag: the full, untruncated HMAC-SHA-256
/// output (FIPS 198-1 §2.3 L, the output size of H; FIPS 180-4 §1 Figure 1:
/// SHA-256's digest is 256 bits). Fixed by the type, never by a length on
/// the wire (A-145 RC-4); `name-attestation` pins it to its MAC's output
/// size at compile time.
/// Spec: docs/59 §7.1 (`tag: [u8; 32]`); FIPS 198-1 §2.3, §5 (no truncation
/// is used); FIPS 180-4 §1; A-145 RC-4.
pub const NAME_RESOLUTION_TAG_LEN: usize = 32;

/// The freshness window W: keyd accepts a resolution only if
/// `|now − issued_at| ≤ W`, `now` on keyd's own clock (never from the
/// wire, R50-5). Short, because a resolution is made for one request on the
/// same host; it narrows the one residual — a compromised KDC replaying a
/// true, fresh resolution (docs/59 §7.5, S4).
/// Spec: docs/questions/Q-1011 item 3 (A-173: "W = 30 s on keyd's own
/// clock"); docs/59 §7.2 step 3; docs/50 §3.5 (R50-5).
pub const NAME_RESOLUTION_WINDOW_SECS: u64 = 30;

/// Octets of the longest MAC input: the label, two realms and two names at
/// their bounds, and the fixed fields.
/// Spec: this module's encoding; docs/CLEAN-ROOM.md (bounded).
pub const MAX_NAME_RESOLUTION_MAC_INPUT: usize = 1
    + NAME_RESOLUTION_LABEL.len()
    + 2 * (2 + MAX_NAME_OCTETS)
    + 2 * (4 + 1 + MAX_NAME_COMPONENTS * (2 + MAX_NAME_OCTETS))
    + 16
    + 1
    + 8
    + 7;

/// Bound of a realm of a name resolution on an ipc channel — dird → kdc
/// (crate ipc-directory, task PN10) and kdc → keyd (crate ipc-keyd, task
/// PN11): the bound this module puts on every realm of a resolution
/// ([`MAX_NAME_OCTETS`]), so nothing a resolution cannot hold is read off
/// either wire. Defined once, here, beside the bounds it is derived from:
/// one resolution, one bound on both of its channels (A-190 on
/// docs/questions/Q-1062 item 1).
/// Spec: docs/59 §7.1 (the bounds of krb-proto and the binding), §7.5
/// ("size bounds"); this module's bounds; docs/CLEAN-ROOM.md.
pub const MAX_RESOLUTION_REALM: u32 = MAX_NAME_OCTETS as u32;

/// Octets of a DER header around contents of at most 65 535 octets: one
/// identifier octet (a tag number from 0 to 30 — X.690 §8.1.2.2) and at most
/// three length octets (the definite form in the fewest octets — X.690
/// §10.1; up to 65 535 the long form's initial octet and two more — X.690
/// §8.1.3.5).
/// Spec: ITU-T X.690 (02/2021) §8.1.2.2, §8.1.3.3-§8.1.3.5, §10.1.
const DER_HEADER: usize = 1 + 3;

/// Octets of a resolution name's `name-type [0] Int32` at most: the context
/// tag around an INTEGER of at most four contents octets (Int32's range —
/// RFC 4120 §5.2.4 — in the fewest two's-complement octets, X.690 §8.3.2,
/// §8.3.3), each header in the short form (contents ≤ 127 octets — X.690
/// §8.1.3.4).
/// Spec: RFC 4120 §5 (`DEFINITIONS EXPLICIT TAGS`), §5.2.2 (`name-type [0]
/// Int32`), §5.2.4 (`Int32`); X.690 §8.1.3.4, §8.3.1-§8.3.3.
const RESOLUTION_NAME_TYPE_DER: usize = 2 + 2 + 4;

/// Bound of a `PrincipalName` DER of a name resolution on an ipc channel
/// (the two of [`MAX_RESOLUTION_REALM`]): the largest encoding of a name a
/// resolution can hold — `MAX_NAME_COMPONENTS` components of at most
/// [`MAX_NAME_OCTETS`] octets each (this module's bounds) — as `SEQUENCE {
/// name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }` under
/// explicit tags: the outer header, the name-type, the `[1]` and `SEQUENCE
/// OF` headers, and one header plus the octets per component. 16 468
/// octets; every contents length involved is under 65 536, so
/// [`DER_HEADER`] holds for each (checked below).
/// Spec: RFC 4120 §5 (`DEFINITIONS EXPLICIT TAGS`), §5.2.1
/// (`KerberosString`), §5.2.2 (`PrincipalName`); X.690 §8.1.2.2, §8.1.3,
/// §10.1; docs/59 §7.1, §7.5; docs/CLEAN-ROOM.md.
pub const MAX_RESOLUTION_NAME: u32 = (DER_HEADER
    + RESOLUTION_NAME_TYPE_DER
    + DER_HEADER
    + DER_HEADER
    + MAX_NAME_COMPONENTS * (DER_HEADER + MAX_NAME_OCTETS))
    as u32;

/// Body octets of the largest name resolution on an ipc channel (the two of
/// [`MAX_RESOLUTION_REALM`], which encode it alike): two realms and two
/// names at their bounds, each behind its `u32` length, the principal id,
/// the purpose, the snapshot, the issue time and the tag.
/// Spec: docs/50 §3.3 (`bytes<max>` = `u32` length + octets; fixed-width
/// integers); docs/59 §7.1; this module's fields.
pub const LARGEST_RESOLUTION: usize = 2 * (4 + MAX_RESOLUTION_REALM as usize)
    + 2 * (4 + MAX_RESOLUTION_NAME as usize)
    + 16
    + 1
    + 8
    + 7
    + NAME_RESOLUTION_TAG_LEN;

// The wire bounds agree with the values they are derived from: the realm
// bound is this module's; every contents length inside a resolution name is
// under 65 536, so each header takes at most DER_HEADER octets (X.690
// §8.1.3.5). Checked at compile time, never at run time.
const _: () = {
    assert!(MAX_RESOLUTION_REALM as usize == MAX_NAME_OCTETS);
    assert!((MAX_RESOLUTION_NAME as usize) - DER_HEADER <= 0xFFFF);
    assert!(MAX_NAME_COMPONENTS * (DER_HEADER + MAX_NAME_OCTETS) <= 0xFFFF);
};

/// Why a name resolution was refused: the value is outside the bounds. No
/// data is carried (names are not secret, but nothing needs to be).
/// Spec: this module's bounds; docs/CLEAN-ROOM.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameResolutionError {
    /// A name has no component, or more than
    /// `krb_proto::limits::MAX_NAME_COMPONENTS`.
    BadComponentCount,
    /// A realm or a name component is longer than
    /// [`crate::sealed_store::MAX_NAME_OCTETS`].
    TooLong,
}

impl fmt::Display for NameResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameResolutionError::BadComponentCount => "name resolution: bad component count",
            NameResolutionError::TooLong => "name resolution: realm or component too long",
        })
    }
}

impl std::error::Error for NameResolutionError {}

/// The fields of a [`NameResolution`], by name — two realms and two names of
/// the same types, so a positional constructor could swap them unseen.
/// Plain data; [`NameResolution::new`] checks the bounds.
/// Spec: docs/59 §7.1; docs/questions/Q-1011 item 1, Q-792.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameResolutionFields {
    /// The realm the request carried. Spec: docs/59 §4.7 (`realm_as_sent`).
    pub realm_as_sent: Realm,
    /// The name the request carried. Spec: docs/59 §4.7 (`name_as_sent`).
    pub name_as_sent: PrincipalName,
    /// The realm dird resolved it in (the configured realm). Spec: docs/59
    /// §4.7, §7.2 step 2.
    pub canonical_realm: Realm,
    /// The stored name it resolved to (sAMAccountName for a client, the
    /// servicePrincipalName for a service). Spec: docs/59 §4.7.
    pub canonical_name: PrincipalName,
    /// The principal whose key set the name names. Spec: docs/10 §1;
    /// docs/59 §7.2 step 4.
    pub principal: PrincipalId,
    /// The purpose of that key set (from the canonical name and the claim,
    /// docs/questions/Q-1009). Spec: docs/10 §1; docs/59 §7.2 step 4.
    pub key_purpose: KeyPurpose,
    /// The change sequence of the view dird read. Spec: docs/59 §4.7
    /// (`snapshot`); Q-792.
    pub snapshot: u64,
    /// When dird issued it (dird's clock). Spec: docs/59 §7.1; Q-792
    /// (`issued_at`); RFC 4120 §5.2.3.
    pub issued_at: KerberosTime,
}

/// A name resolution as dird states it: the request's realm and name, the
/// canonical realm and name, the principal and key purpose they name, the
/// snapshot and the issue time — always within the bounds (see the module
/// documentation).
///
/// Not secret. It proves nothing by itself: anyone can build one. Only its
/// tag ([`AttestedNameResolution`]), verified with the attestation key by
/// `name-attestation`, makes it dird's statement.
///
/// Spec: docs/59 §7.1; docs/questions/Q-1011 item 1, Q-792.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameResolution {
    fields: NameResolutionFields,
}

impl NameResolution {
    /// Build a resolution, refusing a name with no component or more than
    /// `krb_proto::limits::MAX_NAME_COMPONENTS`, and a realm or component
    /// longer than [`crate::sealed_store::MAX_NAME_OCTETS`].
    /// Spec: docs/59 §7.1 (the bounds); docs/CLEAN-ROOM.md.
    pub fn new(fields: NameResolutionFields) -> Result<NameResolution, NameResolutionError> {
        check_realm(&fields.realm_as_sent)?;
        check_name(&fields.name_as_sent)?;
        check_realm(&fields.canonical_realm)?;
        check_name(&fields.canonical_name)?;
        Ok(NameResolution { fields })
    }

    /// The realm the request carried. Spec: docs/59 §7.1.
    #[must_use]
    pub fn realm_as_sent(&self) -> &Realm {
        &self.fields.realm_as_sent
    }

    /// The name the request carried. Spec: docs/59 §7.1.
    #[must_use]
    pub fn name_as_sent(&self) -> &PrincipalName {
        &self.fields.name_as_sent
    }

    /// The realm dird resolved the name in. Spec: docs/59 §7.1.
    #[must_use]
    pub fn canonical_realm(&self) -> &Realm {
        &self.fields.canonical_realm
    }

    /// The stored name the request's name resolved to. Spec: docs/59 §7.1.
    #[must_use]
    pub fn canonical_name(&self) -> &PrincipalName {
        &self.fields.canonical_name
    }

    /// The principal whose key set the name names. Spec: docs/59 §7.1.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.fields.principal
    }

    /// The purpose of that key set. Spec: docs/59 §7.1.
    #[must_use]
    pub const fn key_purpose(&self) -> KeyPurpose {
        self.fields.key_purpose
    }

    /// The change sequence of the view dird read. Spec: docs/59 §7.1.
    #[must_use]
    pub const fn snapshot(&self) -> u64 {
        self.fields.snapshot
    }

    /// When dird issued it. Spec: docs/59 §7.1.
    #[must_use]
    pub const fn issued_at(&self) -> KerberosTime {
        self.fields.issued_at
    }

    /// The fields, by name. Spec: docs/59 §7.1.
    #[must_use]
    pub fn into_fields(self) -> NameResolutionFields {
        self.fields
    }

    /// `true` if `|now − issued_at| ≤` [`NAME_RESOLUTION_WINDOW_SECS`], both
    /// on the project's one KerberosTime scale ([`kerberos_time_seconds`]).
    /// `now` is the verifier's own clock (keyd's — R50-5), never a value
    /// from the request. The difference cannot overflow: both counts lie in
    /// 0000–9999 (RFC 4120 §5.2.3 four-digit years).
    /// Spec: docs/questions/Q-1011 item 3 (A-173); docs/59 §7.2 step 3;
    /// docs/50 §3.5 (R50-5); RFC 4120 §5.2.3.
    #[must_use]
    pub fn is_fresh_at(&self, now: &KerberosTime) -> bool {
        kerberos_time_seconds(now).abs_diff(kerberos_time_seconds(&self.fields.issued_at))
            <= NAME_RESOLUTION_WINDOW_SECS
    }

    /// The MAC input — the one encoding the signer and the verifier both use
    /// (see the module documentation), at most
    /// [`MAX_NAME_RESOLUTION_MAC_INPUT`] octets. Refuses (never truncates) a
    /// field outside its bound; a value built by [`NameResolution::new`] is
    /// always within them.
    /// Spec: docs/59 §7.1 (lengths prefixed, krb-proto's bounds; C44), §7.4
    /// (the label); RFC 4120 §5.2.2, §5.2.3.
    pub fn mac_input(&self) -> Result<Vec<u8>, NameResolutionError> {
        let f = &self.fields;
        let mut out = Vec::new();
        let label_len =
            u8::try_from(NAME_RESOLUTION_LABEL.len()).map_err(|_| NameResolutionError::TooLong)?;
        out.push(label_len);
        out.extend_from_slice(NAME_RESOLUTION_LABEL);
        put_realm(&mut out, &f.realm_as_sent)?;
        put_name(&mut out, &f.name_as_sent)?;
        put_realm(&mut out, &f.canonical_realm)?;
        put_name(&mut out, &f.canonical_name)?;
        out.extend_from_slice(f.principal.as_bytes());
        out.push(f.key_purpose.code());
        out.extend_from_slice(&f.snapshot.to_be_bytes());
        put_time(&mut out, &f.issued_at);
        Ok(out)
    }
}

/// A name resolution with the tag dird computed over its MAC input
/// ([`NameResolution::mac_input`]) under the attestation key.
///
/// Carrying a tag is not being verified: the resolution is readable (the
/// channel codecs encode it), and only `name_attestation::verify` — which
/// keyd's `VerifiedNameResolution` is built from (docs/59 §7.2, task PN8) —
/// says the tag is right. No `PartialEq`: a tag is compared only in constant
/// time, by `name-attestation`. The tag is not secret.
///
/// Spec: docs/59 §7.1 (`AttestedNameResolution { resolution, tag: [u8;
/// 32] }`), §7.2 step 1; A-145 RC-4.
#[derive(Debug, Clone)]
pub struct AttestedNameResolution {
    resolution: NameResolution,
    tag: [u8; NAME_RESOLUTION_TAG_LEN],
}

impl AttestedNameResolution {
    /// Pair a resolution with its tag (dird's signer after tagging; a codec
    /// after decoding). Spec: docs/59 §7.1, §7.5.
    #[must_use]
    pub const fn new(
        resolution: NameResolution,
        tag: [u8; NAME_RESOLUTION_TAG_LEN],
    ) -> AttestedNameResolution {
        AttestedNameResolution { resolution, tag }
    }

    /// The resolution — **not yet verified** until `name_attestation::verify`
    /// accepts the tag. Spec: docs/59 §7.2 step 1.
    #[must_use]
    pub const fn resolution(&self) -> &NameResolution {
        &self.resolution
    }

    /// The tag. Spec: docs/59 §7.1.
    #[must_use]
    pub const fn tag(&self) -> &[u8; NAME_RESOLUTION_TAG_LEN] {
        &self.tag
    }
}

/// A realm: within [`MAX_NAME_OCTETS`]. Spec: RFC 4120 §5.2.2; this module's
/// bounds.
fn check_realm(realm: &Realm) -> Result<(), NameResolutionError> {
    if realm.as_bytes().len() > MAX_NAME_OCTETS {
        return Err(NameResolutionError::TooLong);
    }
    Ok(())
}

/// A name: 1 ..= `MAX_NAME_COMPONENTS` components, each within
/// [`MAX_NAME_OCTETS`]. Spec: RFC 4120 §5.2.2; this module's bounds.
fn check_name(name: &PrincipalName) -> Result<(), NameResolutionError> {
    let count = name.name_string.len();
    if count == 0 || count > MAX_NAME_COMPONENTS {
        return Err(NameResolutionError::BadComponentCount);
    }
    if name
        .name_string
        .iter()
        .any(|c| c.as_bytes().len() > MAX_NAME_OCTETS)
    {
        return Err(NameResolutionError::TooLong);
    }
    Ok(())
}

/// `len:u16 ‖ octets`, refusing more than [`MAX_NAME_OCTETS`].
/// Spec: this module's encoding.
fn put_string(out: &mut Vec<u8>, s: &KerberosString) -> Result<(), NameResolutionError> {
    let octets = s.as_bytes();
    if octets.len() > MAX_NAME_OCTETS {
        return Err(NameResolutionError::TooLong);
    }
    let len = u16::try_from(octets.len()).map_err(|_| NameResolutionError::TooLong)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(octets);
    Ok(())
}

/// `realm(r) = len:u16 ‖ r`. Spec: RFC 4120 §5.2.2 (Realm ::= KerberosString).
fn put_realm(out: &mut Vec<u8>, realm: &Realm) -> Result<(), NameResolutionError> {
    put_string(out, realm)
}

/// `name(n) = name_type:i32 ‖ count:u8 ‖ (len:u16 ‖ component)*`.
/// Spec: RFC 4120 §5.2.2 (PrincipalName { name-type Int32, name-string
/// SEQUENCE OF KerberosString }), §6.2.
fn put_name(out: &mut Vec<u8>, name: &PrincipalName) -> Result<(), NameResolutionError> {
    let count = name.name_string.len();
    if count == 0 || count > MAX_NAME_COMPONENTS {
        return Err(NameResolutionError::BadComponentCount);
    }
    out.extend_from_slice(&name.name_type.to_be_bytes());
    out.push(u8::try_from(count).map_err(|_| NameResolutionError::BadComponentCount)?);
    for component in &name.name_string {
        put_string(out, component)?;
    }
    Ok(())
}

/// `year:u16 ‖ month:u8 ‖ day:u8 ‖ hour:u8 ‖ minute:u8 ‖ second:u8` — the
/// fields of `YYYYMMDDHHMMSSZ`. Spec: RFC 4120 §5.2.3.
fn put_time(out: &mut Vec<u8>, t: &KerberosTime) {
    out.extend_from_slice(&t.year().to_be_bytes());
    out.extend_from_slice(&[t.month(), t.day(), t.hour(), t.minute(), t.second()]);
}

// The bounds fit the prefixes that carry them.
const _: () = {
    assert!(MAX_NAME_OCTETS <= u16::MAX as usize);
    assert!(MAX_NAME_COMPONENTS <= u8::MAX as usize);
    assert!(NAME_RESOLUTION_LABEL.len() <= u8::MAX as usize);
};

#[cfg(test)]
mod tests {
    //! Sources: docs/59 §7.1, §7.4 and docs/questions/Q-1011 items 1–3
    //! (A-173) for the fields, the label and the window; RFC 4120 §5.2.2,
    //! §5.2.3 for the name and time fields; this module's encoding for the
    //! layout. Every value is constructed by hand for these tests; no vector
    //! comes from any other implementation.

    use super::*;

    fn s(text: &str) -> KerberosString {
        KerberosString::new(text).unwrap()
    }

    fn name(name_type: i32, parts: &[&str]) -> PrincipalName {
        PrincipalName {
            name_type,
            name_string: parts.iter().map(|p| s(p)).collect(),
        }
    }

    fn time(second: u8) -> KerberosTime {
        KerberosTime::new(2026, 11, 15, 10, 20, second).unwrap()
    }

    fn fields() -> NameResolutionFields {
        NameResolutionFields {
            realm_as_sent: s("LAB.TEST"),
            name_as_sent: name(1, &["alice"]),
            canonical_realm: s("LAB.TEST"),
            canonical_name: name(1, &["alice"]),
            principal: PrincipalId::from_bytes([0x11; 16]),
            key_purpose: KeyPurpose::PrincipalLongterm,
            snapshot: 0x0102_0304_0506_0708,
            issued_at: time(30),
        }
    }

    fn input_of(f: NameResolutionFields) -> Vec<u8> {
        NameResolution::new(f).unwrap().mac_input().unwrap()
    }

    /// The layout of the module documentation, octet for octet, for one
    /// hand-built resolution (docs/59 §7.1, §7.4; RFC 4120 §5.2.2, §5.2.3).
    #[test]
    fn the_mac_input_has_the_documented_layout() {
        let mut f = fields();
        f.name_as_sent = name(10, &["Alice@lab.test"]);
        f.canonical_name = name(1, &["alice"]);
        f.key_purpose = KeyPurpose::Service;
        let input = input_of(f);
        let mut expected = vec![28u8];
        expected.extend_from_slice(b"principal-name-resolution.v1");
        expected.extend_from_slice(&[0, 8]);
        expected.extend_from_slice(b"LAB.TEST");
        expected.extend_from_slice(&[0, 0, 0, 10, 1, 0, 14]);
        expected.extend_from_slice(b"Alice@lab.test");
        expected.extend_from_slice(&[0, 8]);
        expected.extend_from_slice(b"LAB.TEST");
        expected.extend_from_slice(&[0, 0, 0, 1, 1, 0, 5]);
        expected.extend_from_slice(b"alice");
        expected.extend_from_slice(&[0x11; 16]);
        expected.push(2);
        expected.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        expected.extend_from_slice(&[0x07, 0xEA, 11, 15, 10, 20, 30]);
        assert_eq!(input, expected);
        assert_eq!(NAME_RESOLUTION_LABEL.len(), 28);
    }

    /// The encoding is deterministic and every field changes it — including
    /// the name-type (authenticated, though only a hint — RFC 4120 §6.2) and
    /// each calendar field of `issued_at` (RFC 4120 §5.2.3).
    #[test]
    fn every_field_changes_the_mac_input() {
        let base = input_of(fields());
        assert_eq!(base, input_of(fields()));
        let variants: Vec<(&str, NameResolutionFields)> = vec![
            ("realm_as_sent", {
                let mut f = fields();
                f.realm_as_sent = s("lab.test");
                f
            }),
            ("name_as_sent", {
                let mut f = fields();
                f.name_as_sent = name(1, &["Alice"]);
                f
            }),
            ("name_as_sent type", {
                let mut f = fields();
                f.name_as_sent = name(10, &["alice"]);
                f
            }),
            ("canonical_realm", {
                let mut f = fields();
                f.canonical_realm = s("LAB.TESU");
                f
            }),
            ("canonical_name", {
                let mut f = fields();
                f.canonical_name = name(1, &["alicf"]);
                f
            }),
            ("principal", {
                let mut f = fields();
                f.principal = PrincipalId::from_bytes([0x12; 16]);
                f
            }),
            ("key_purpose", {
                let mut f = fields();
                f.key_purpose = KeyPurpose::Krbtgt;
                f
            }),
            ("snapshot", {
                let mut f = fields();
                f.snapshot += 1;
                f
            }),
            ("issued_at second", {
                let mut f = fields();
                f.issued_at = time(31);
                f
            }),
            ("issued_at year", {
                let mut f = fields();
                f.issued_at = KerberosTime::new(2027, 11, 15, 10, 20, 30).unwrap();
                f
            }),
            ("issued_at month", {
                let mut f = fields();
                f.issued_at = KerberosTime::new(2026, 10, 15, 10, 20, 30).unwrap();
                f
            }),
            ("issued_at day", {
                let mut f = fields();
                f.issued_at = KerberosTime::new(2026, 11, 16, 10, 20, 30).unwrap();
                f
            }),
            ("issued_at hour", {
                let mut f = fields();
                f.issued_at = KerberosTime::new(2026, 11, 15, 11, 20, 30).unwrap();
                f
            }),
            ("issued_at minute", {
                let mut f = fields();
                f.issued_at = KerberosTime::new(2026, 11, 15, 10, 21, 30).unwrap();
                f
            }),
        ];
        for (what, variant) in variants {
            assert_ne!(input_of(variant), base, "{what}");
        }
    }

    /// Injectivity at the joints: moving octets between components, between
    /// a realm and a name, or between the sent and the canonical pair gives
    /// a different input (the length prefixes and counts; module docs).
    #[test]
    fn shifted_boundaries_give_different_inputs() {
        let with = |realm_as_sent: &str, sent: &[&str], realm: &str, canonical: &[&str]| {
            let mut f = fields();
            f.realm_as_sent = s(realm_as_sent);
            f.name_as_sent = name(1, sent);
            f.canonical_realm = s(realm);
            f.canonical_name = name(1, canonical);
            input_of(f)
        };
        let pairs = [
            (
                with("R", &["ab", "c"], "R", &["x"]),
                with("R", &["a", "bc"], "R", &["x"]),
            ),
            (
                with("R", &["host/a"], "R", &["x"]),
                with("R", &["host", "a"], "R", &["x"]),
            ),
            (
                with("RA", &["b"], "R", &["x"]),
                with("R", &["Ab"], "R", &["x"]),
            ),
            (
                with("R", &["a"], "R", &["b"]),
                with("R", &["b"], "R", &["a"]),
            ),
            (
                with("R1", &["a"], "R2", &["a"]),
                with("R2", &["a"], "R1", &["a"]),
            ),
        ];
        for (i, (a, b)) in pairs.iter().enumerate() {
            assert_ne!(a, b, "pair {i}");
        }
    }

    /// The bounds of the module documentation: 1 ..= MAX_NAME_COMPONENTS
    /// components, MAX_NAME_OCTETS per component and realm — on every one of
    /// the four name fields; at the bounds the input is exactly
    /// MAX_NAME_RESOLUTION_MAC_INPUT octets.
    #[test]
    fn the_bounds_are_enforced_on_every_name_field() {
        let long = "a".repeat(MAX_NAME_OCTETS);
        let too_long = "a".repeat(MAX_NAME_OCTETS + 1);
        let most: Vec<&str> = vec![long.as_str(); MAX_NAME_COMPONENTS];
        let too_many: Vec<&str> = vec!["a"; MAX_NAME_COMPONENTS + 1];

        let mut f = fields();
        f.realm_as_sent = s(&long);
        f.canonical_realm = s(&long);
        f.name_as_sent = name(1, &most);
        f.canonical_name = name(1, &most);
        assert_eq!(input_of(f).len(), MAX_NAME_RESOLUTION_MAC_INPUT);

        type Edit = fn(&mut NameResolutionFields, PrincipalName);
        let names: [Edit; 2] = [|f, n| f.name_as_sent = n, |f, n| f.canonical_name = n];
        for set in names {
            for (bad, why) in [
                (name(1, &[]), NameResolutionError::BadComponentCount),
                (name(1, &too_many), NameResolutionError::BadComponentCount),
                (
                    name(1, &["a", too_long.as_str()]),
                    NameResolutionError::TooLong,
                ),
            ] {
                let mut f = fields();
                set(&mut f, bad);
                assert_eq!(NameResolution::new(f), Err(why));
            }
        }
        let mut f = fields();
        f.realm_as_sent = s(&too_long);
        assert_eq!(NameResolution::new(f), Err(NameResolutionError::TooLong));
        let mut f = fields();
        f.canonical_realm = s(&too_long);
        assert_eq!(NameResolution::new(f), Err(NameResolutionError::TooLong));
    }

    /// W = 30 s either side, on the KerberosTime scale (Q-1011 item 3,
    /// A-173), across a minute and a day boundary.
    #[test]
    fn freshness_is_thirty_seconds_either_side() {
        let mut f = fields();
        f.issued_at = KerberosTime::new(2026, 12, 31, 23, 59, 50).unwrap();
        let r = NameResolution::new(f).unwrap();
        let at = |y, mo, d, h, mi, se| KerberosTime::new(y, mo, d, h, mi, se).unwrap();
        assert!(r.is_fresh_at(&at(2026, 12, 31, 23, 59, 50)));
        assert!(r.is_fresh_at(&at(2026, 12, 31, 23, 59, 20)));
        assert!(!r.is_fresh_at(&at(2026, 12, 31, 23, 59, 19)));
        assert!(r.is_fresh_at(&at(2027, 1, 1, 0, 0, 20)));
        assert!(!r.is_fresh_at(&at(2027, 1, 1, 0, 0, 21)));
        assert!(!r.is_fresh_at(&at(9999, 12, 31, 23, 59, 59)));
        assert!(!r.is_fresh_at(&at(0, 1, 1, 0, 0, 0)));
        assert_eq!(NAME_RESOLUTION_WINDOW_SECS, 30);
    }

    /// Every purpose puts its own code — `KeyPurpose::code`, the one table
    /// the sealed store persists too (Q-1023 item 4) — at the purpose's
    /// position of the MAC input, after the label, the two realms and names
    /// of `fields()` and the principal id; the numbers are pinned literally.
    #[test]
    fn every_purpose_has_its_own_code() {
        let all = [
            (KeyPurpose::PrincipalLongterm, 0u8),
            (KeyPurpose::Krbtgt, 1),
            (KeyPurpose::Service, 2),
            (KeyPurpose::AdminService, 3),
            (KeyPurpose::ChangePasswordService, 4),
        ];
        // label (1 + 28), realm (2 + 8), name (4 + 1 + 2 + 5), twice, then
        // the principal id (16).
        let at = 1 + 28 + 2 * ((2 + 8) + (4 + 1 + 2 + 5)) + 16;
        for (purpose, code) in all {
            let mut f = fields();
            f.key_purpose = purpose;
            assert_eq!(input_of(f)[at], code, "{purpose:?}");
            assert_eq!(purpose.code(), code, "{purpose:?}");
        }
    }

    /// The accessors return what was built; the attested pair keeps its tag.
    #[test]
    fn the_accessors_return_the_fields() {
        let r = NameResolution::new(fields()).unwrap();
        assert_eq!(r.realm_as_sent(), &s("LAB.TEST"));
        assert_eq!(r.name_as_sent(), &name(1, &["alice"]));
        assert_eq!(r.canonical_realm(), &s("LAB.TEST"));
        assert_eq!(r.canonical_name(), &name(1, &["alice"]));
        assert_eq!(r.principal(), PrincipalId::from_bytes([0x11; 16]));
        assert_eq!(r.key_purpose(), KeyPurpose::PrincipalLongterm);
        assert_eq!(r.snapshot(), 0x0102_0304_0506_0708);
        assert_eq!(r.issued_at(), time(30));
        let attested = AttestedNameResolution::new(r.clone(), [0xA5; NAME_RESOLUTION_TAG_LEN]);
        assert_eq!(attested.resolution(), &r);
        assert_eq!(attested.tag(), &[0xA5; NAME_RESOLUTION_TAG_LEN]);
        assert_eq!(r.into_fields(), fields());
    }
}
