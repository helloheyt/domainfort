//! Owned field values with special handling: the secret byte string and the
//! opaque DER blob.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A secret byte string (for example the password of `SetSecret` /
/// `VerifySecret`), held in a zeroizing buffer.
///
/// * The octets live in one heap buffer allocated at its exact size and never
///   grown, so no reallocation can leave a stray copy (the `zeroize` docs warn
///   that earlier reallocations cannot be wiped); the buffer is zeroized when
///   the value is dropped ([`ZeroizeOnDrop`]) or when [`Zeroize::zeroize`] is
///   called.
/// * `Debug` prints neither the octets nor their length.
/// * No `Clone` (no silent second copy), no `PartialEq` (a variable-time
///   comparison of secret material would be a timing leak — docs/10 I6), no
///   `Display`.
/// * The octets are reachable only through [`Secret::expose`], so every place
///   that touches them is easy to audit.
///
/// Spec: docs/50 §3.3 ("the `SetSecret`/`VerifySecret` body (password) is read
/// into `Zeroizing` … in both sides"); R50-4; docs/10 I6, I7; docs/CLEAN-ROOM.md
pub struct Secret {
    octets: Zeroizing<Vec<u8>>,
}

impl Secret {
    /// Copy `octets` into a new zeroizing buffer of exactly their length. The
    /// caller stays responsible for wiping its own copy.
    ///
    /// Spec: docs/50 §3.3; docs/10 I7.
    #[must_use]
    pub fn from_slice(octets: &[u8]) -> Secret {
        let mut buffer = Zeroizing::new(Vec::with_capacity(octets.len()));
        // Within the reserved capacity: no reallocation.
        buffer.extend_from_slice(octets);
        Secret { octets: buffer }
    }

    /// Take ownership of an existing zeroizing buffer without copying it.
    /// Spec: docs/50 §3.3; docs/10 I7.
    #[must_use]
    pub fn from_zeroizing(octets: Zeroizing<Vec<u8>>) -> Secret {
        Secret { octets }
    }

    /// The secret octets. Named so every use is visible in review.
    /// Spec: docs/CLEAN-ROOM.md (secrets never in logs, panics or errors).
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.octets
    }

    /// Hand the zeroizing buffer to the consumer (for example keyd's
    /// password operations) without an intermediate copy.
    /// Spec: docs/10 I7.
    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.octets
    }

    /// Number of secret octets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.octets.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.octets.is_empty()
    }
}

impl Zeroize for Secret {
    /// Wipe the octets now (the drop of the inner `Zeroizing` wipes them
    /// again, harmlessly).
    fn zeroize(&mut self) {
        self.octets.zeroize();
    }
}

// The only field is a `Zeroizing<Vec<u8>>`, whose drop zeroizes it (docs.rs
// zeroize 1.9.1, `Zeroizing`: "implements a Drop handler which zeroizes"), so
// dropping a `Secret` zeroizes its octets.
impl ZeroizeOnDrop for Secret {}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not even the length: a password length is itself information.
        f.write_str("Secret(<redacted>)")
    }
}

/// An opaque DER encoding of a Kerberos value (`PA-DATA`, `AP-REQ`,
/// `KrbFastArmoredReq`, `KRB-ERROR`, `EncryptedData`, `Ticket`, `KrbFastReq`,
/// `PrincipalName`, `Realm`, `KerberosTime`, …).
///
/// This crate never looks inside: on the wire it is a bounded byte string, and
/// the receiver hands it to `krb-proto`'s strict DER decoder (this crate does
/// not depend on `krb-proto`). Keeping one type for "DER to be decoded later"
/// means there is no second representation of any Kerberos type on the wire.
///
/// `Debug` prints only the length: raw request octets (tickets, PA-DATA) are
/// never logged (docs/50 §8.2).
///
/// Spec: docs/50 §3.3 ("Kerberos values … as `bytes<max>` holding DER, decoded
/// in `krb-proto`"; "no second representation of Kerberos types"); R50-4;
/// docs/questions/Q-225 item 6.
#[derive(Clone, PartialEq, Eq)]
pub struct DerBlob {
    der: Vec<u8>,
}

impl DerBlob {
    /// Wrap an encoding produced (or to be decoded) by `krb-proto`.
    /// Spec: docs/50 §3.3.
    #[must_use]
    pub fn new(der: Vec<u8>) -> DerBlob {
        DerBlob { der }
    }

    /// Copy an encoding into a new blob.
    /// Spec: docs/50 §3.3.
    #[must_use]
    pub fn from_slice(der: &[u8]) -> DerBlob {
        DerBlob { der: der.to_vec() }
    }

    /// The DER octets, for `krb-proto` to decode.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// The DER octets, by value.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.der
    }

    /// Number of octets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.der.len()
    }

    /// Whether the blob is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.der.is_empty()
    }
}

impl fmt::Debug for DerBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerBlob")
            .field("len", &self.der.len())
            .finish()
    }
}
