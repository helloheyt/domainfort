//! Internal macros that add the public `decode` / `encode` entry points to a
//! type that implements the crate-private `from_value` / `to_value` pair.

/// Public strict-DER `decode` and canonical-DER `encode` for a type whose
/// contents are not secret.
///
/// Spec: RFC 4120 5.1.1 (DER); framing per X.690 clauses 8 and 10.
macro_rules! der_codec {
    ($ty:ident, $asn1:literal) => {
        impl $ty {
            #[doc = concat!(
                                "Decode one complete DER encoding of `", $asn1, "`.\n\n",
                                "Strict: DER only, no trailing data, every RFC 4120 constraint ",
                                "checked; any violation is a distinct [`crate::Error`].\n\n",
                                "Spec: RFC 4120 5.1.1; Appendix A (`", $asn1, "`)."
                            )]
            pub fn decode(bytes: &[u8]) -> $crate::Result<Self> {
                let value = $crate::der::decode_top(bytes)?;
                Self::from_value(&value)
            }

            #[doc = concat!(
                                "Encode as the canonical DER encoding of `", $asn1, "`.\n\n",
                                "Fails (rather than emitting something this crate would not ",
                                "decode) if a constraint or resource bound is violated.\n\n",
                                "Spec: RFC 4120 5.1.1; Appendix A (`", $asn1, "`)."
                            )]
            pub fn encode(&self) -> $crate::Result<Vec<u8>> {
                $crate::der::encode_top(&self.to_value()?)
            }
        }
    };
}

/// Like [`der_codec`], for a type that carries key material (an
/// EncryptionKey): the intermediate value tree is scrubbed and the encoding is
/// returned in a `Zeroizing` buffer.
///
/// Spec: RFC 4120 5.1.1, 5.2.9; AGENTS.md §6 (secrets).
macro_rules! der_codec_secret {
    ($ty:ident, $asn1:literal) => {
        impl $ty {
            #[doc = concat!(
                                "Decode one complete DER encoding of `", $asn1, "`.\n\n",
                                "Strict: DER only, no trailing data, every RFC 4120 constraint ",
                                "checked. The intermediate value tree (which holds key octets) ",
                                "is zeroized on success and on error.\n\n",
                                "Spec: RFC 4120 5.1.1, 5.2.9; Appendix A (`", $asn1, "`)."
                            )]
            pub fn decode(bytes: &[u8]) -> $crate::Result<Self> {
                $crate::der::decode_secret(bytes, Self::from_value)
            }

            #[doc = concat!(
                                "Encode as the canonical DER encoding of `", $asn1, "`.\n\n",
                                "The result contains key material and is returned in a ",
                                "`Zeroizing` buffer that wipes itself on drop.\n\n",
                                "Spec: RFC 4120 5.1.1, 5.2.9; Appendix A (`", $asn1, "`)."
                            )]
            pub fn encode(&self) -> $crate::Result<zeroize::Zeroizing<Vec<u8>>> {
                $crate::der::encode_secret(self.to_value()?)
            }
        }
    };
}
