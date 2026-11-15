//! Internal macros that add the public `decode` / `encode` entry points to a
//! type that implements the crate-private `from_value` / `to_value` pair.

/// Public strict-DER `decode` and canonical-DER `encode` for a type whose
/// contents are not secret.
///
/// The optional third argument names the ASN.1 module that defines the type
/// (default: RFC 4120 Appendix A; the FAST types pass RFC 6113 Appendix B).
///
/// Spec: RFC 4120 5.1.1 (DER); framing per X.690 clauses 8 and 10.
macro_rules! der_codec {
    ($ty:ident, $asn1:literal) => {
        der_codec!($ty, $asn1, "RFC 4120 Appendix A");
    };
    ($ty:ident, $asn1:literal, $module:literal) => {
        impl $ty {
            #[doc = concat!(
                                "Decode one complete DER encoding of `", $asn1, "`.\n\n",
                                "Strict: DER only, no trailing data, every constraint of the ",
                                "ASN.1 definition checked; any violation is a distinct ",
                                "[`crate::Error`].\n\n",
                                "Spec: RFC 4120 5.1.1; ", $module, " (`", $asn1, "`)."
                            )]
            pub fn decode(bytes: &[u8]) -> $crate::Result<Self> {
                let value = $crate::der::decode_top(bytes)?;
                Self::from_value(&value)
            }

            #[doc = concat!(
                                "Encode as the canonical DER encoding of `", $asn1, "`.\n\n",
                                "Fails (rather than emitting something this crate would not ",
                                "decode) if a constraint or resource bound is violated.\n\n",
                                "Spec: RFC 4120 5.1.1; ", $module, " (`", $asn1, "`)."
                            )]
            pub fn encode(&self) -> $crate::Result<Vec<u8>> {
                $crate::der::encode_top(&self.to_value()?)
            }
        }
    };
}

/// Like [`der_codec`], for a type that carries secret octets (an
/// EncryptionKey, a KRB-PRIV `user-data`, a ChangePasswdData `newpasswd`):
/// the intermediate value tree is scrubbed and the encoding is returned in a
/// `Zeroizing` buffer.
///
/// Spec: RFC 4120 5.1.1, 5.2.9; docs/CLEAN-ROOM.md (secrets).
macro_rules! der_codec_secret {
    ($ty:ident, $asn1:literal) => {
        der_codec_secret!($ty, $asn1, "RFC 4120 Appendix A");
    };
    ($ty:ident, $asn1:literal, $module:literal) => {
        impl $ty {
            #[doc = concat!(
                                "Decode one complete DER encoding of `", $asn1, "`.\n\n",
                                "Strict: DER only, no trailing data, every constraint of the ",
                                "ASN.1 definition checked. The intermediate value tree (which ",
                                "holds secret octets) is zeroized on success and on error.\n\n",
                                "Spec: RFC 4120 5.1.1, 5.2.9; ", $module, " (`", $asn1, "`)."
                            )]
            pub fn decode(bytes: &[u8]) -> $crate::Result<Self> {
                $crate::der::decode_secret(bytes, Self::from_value)
            }

            #[doc = concat!(
                                "Encode as the canonical DER encoding of `", $asn1, "`.\n\n",
                                "The result contains secret octets and is returned in a ",
                                "`Zeroizing` buffer that wipes itself on drop.\n\n",
                                "Spec: RFC 4120 5.1.1, 5.2.9; ", $module, " (`", $asn1, "`)."
                            )]
            pub fn encode(&self) -> $crate::Result<zeroize::Zeroizing<Vec<u8>>> {
                $crate::der::encode_secret(self.to_value()?)
            }
        }
    };
}

/// Define a newtype over secret octets — the single definition behind every
/// secret-octet field type of this crate ([`crate::KeyValue`],
/// [`crate::UserData`], [`crate::NewPasswd`]), so no such type can forget a
/// property:
///
/// - held in a RustCrypto `zeroize::Zeroizing` buffer, wiped on drop;
/// - `Debug` prints only the type name and `<redacted>`, never the octets;
/// - equality compares every octet without an early exit on the first
///   difference (for bookkeeping and tests — not a verified constant-time
///   primitive; no authentication decision compares secrets);
/// - no `Display`, no `Hash`, no conversion that copies the octets out
///   except [`as_bytes`](crate::KeyValue::as_bytes).
///
/// Class closed by construction (docs/CLEAN-ROOM.md): "a secret-bearing type that
/// is missing its wipe or its redaction" — the properties live in one place.
///
/// Spec: docs/CLEAN-ROOM.md (secrets never in logs, panics or debug output).
macro_rules! secret_octets {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name(zeroize::Zeroizing<Vec<u8>>);

        impl $name {
            /// Take ownership of the octets (no copy is made).
            pub fn new(bytes: Vec<u8>) -> Self {
                $name(zeroize::Zeroizing::new(bytes))
            }

            /// Copy the octets into a new zeroizing buffer of exactly the
            /// right capacity (so no reallocation leaves a stale copy behind).
            pub fn from_slice(bytes: &[u8]) -> Self {
                let mut buffer = Vec::with_capacity(bytes.len());
                buffer.extend_from_slice(bytes);
                $name(zeroize::Zeroizing::new(buffer))
            }

            /// The octets.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Number of octets.
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// `true` if there are no octets.
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // Secrets never appear in debug output (docs/CLEAN-ROOM.md).
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                if self.0.len() != other.0.len() {
                    return false;
                }
                // Accumulate differences over every octet; no early exit.
                let difference = self
                    .0
                    .iter()
                    .zip(other.0.iter())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b));
                difference == 0
            }
        }

        impl Eq for $name {}
    };
}
