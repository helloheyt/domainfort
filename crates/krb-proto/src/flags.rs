//! KerberosFlags and its uses: TicketFlags, KDCOptions, APOptions (RFC 4120)
//! and FastOptions (RFC 6113).
//!
//! ```text
//! KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
//!                     -- minimum number of bits shall be sent,
//!                     -- but no fewer than 32
//! ```
//!
//! Wire rule enforced here: **exactly 32 bits** (a BIT STRING of four content
//! octets with zero unused bits). RFC 4120 5.2.8 lets a lenient implementation
//! accept fewer than 32 bits; that option is not taken. No use defines more
//! than 32 flags and the minimum number of bits "shall be sent", so a longer
//! value is also rejected (fail closed). All 32 bits — named, unused and
//! reserved — are preserved exactly, so unknown flag bits round-trip.
//!
//! Bit numbering: bit 0 is the leading bit (X.680 22.2, 22.4), placed in bit 8
//! (the most significant bit) of the first content octet (X.690 8.6.2.1). The
//! raw `u32` used by [`KerberosFlags::from_bits`] / [`KerberosFlags::bits`] is
//! therefore the four octets read big-endian: bit `n` has mask
//! `0x8000_0000 >> n`.
//!
//! Spec: RFC 4120 5.2.8, 5.3 (TicketFlags), 5.4.1 (KDCOptions), 5.5.1
//! (APOptions); RFC 6113 5.4.2, 7.3 (FastOptions); X.680 (02/2021) 22.2,
//! 22.4; X.690 (02/2021) 8.6.2.

use crate::error::{Error, Result};
use parse_asn1::Value;

/// `KerberosFlags ::= BIT STRING (SIZE (32..MAX))`, exactly 32 bits on the wire.
///
/// Spec: RFC 4120 5.2.8; X.690 8.6.2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct KerberosFlags(u32);

impl KerberosFlags {
    /// Build from the raw 32 bits (bit 0 = most significant bit).
    pub const fn from_bits(bits: u32) -> Self {
        KerberosFlags(bits)
    }

    /// The raw 32 bits (bit 0 = most significant bit).
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// `true` if bit number `n` (0 = leading bit) is set; `false` for `n >= 32`.
    /// Spec: X.680 22.4 (bit numbering).
    pub fn is_set(self, n: u32) -> bool {
        match 0x8000_0000u32.checked_shr(n) {
            Some(mask) => self.0 & mask != 0,
            None => false,
        }
    }

    /// `true` if every bit set in `other` is set in `self`.
    pub const fn contains(self, other: KerberosFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Set every bit that is set in `other`.
    pub fn insert(&mut self, other: KerberosFlags) {
        self.0 |= other.0;
    }

    /// Clear every bit that is set in `other`.
    pub fn remove(&mut self, other: KerberosFlags) {
        self.0 &= !other.0;
    }

    /// A value with only bit `n` set. Used only to define the named flag
    /// constants below, where `n` is a literal < 32 (a larger literal fails at
    /// compile time).
    const fn bit(n: u32) -> KerberosFlags {
        KerberosFlags(0x8000_0000u32 >> n)
    }

    /// Spec: RFC 4120 5.2.8; X.690 8.6.2 (primitive BIT STRING).
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::BitString {
                unused_bits: 0,
                bytes,
            } => match <[u8; 4]>::try_from(bytes.as_slice()) {
                Ok(octets) => Ok(KerberosFlags(u32::from_be_bytes(octets))),
                Err(_) => Err(Error::KerberosFlagsLength),
            },
            Value::BitString { .. } => Err(Error::KerberosFlagsLength),
            _ => Err(Error::ExpectedBitString),
        }
    }

    /// Spec: RFC 4120 5.2.8 (32 bits); X.690 8.6.2.1, 8.6.2.2.
    pub(crate) fn to_value(self) -> Value {
        Value::BitString {
            unused_bits: 0,
            bytes: self.0.to_be_bytes().to_vec(),
        }
    }
}

/// Define a KerberosFlags use with its named bits from RFC 4120.
macro_rules! flags_use {
    (
        $(#[$type_doc:meta])*
        $name:ident {
            $( $(#[$flag_doc:meta])* $flag:ident = $bit:literal; )*
        }
    ) => {
        $(#[$type_doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name(pub KerberosFlags);

        impl $name {
            $(
                $(#[$flag_doc])*
                pub const $flag: $name = $name(KerberosFlags::bit($bit));
            )*

            /// No bits set.
            pub const fn empty() -> Self {
                $name(KerberosFlags(0))
            }

            /// `true` if every bit set in `other` is set in `self`.
            pub const fn contains(self, other: Self) -> bool {
                self.0.contains(other.0)
            }

            /// Set every bit that is set in `other`.
            pub fn insert(&mut self, other: Self) {
                self.0.insert(other.0);
            }

            /// Clear every bit that is set in `other`.
            pub fn remove(&mut self, other: Self) {
                self.0.remove(other.0);
            }

            /// The bits set in either value.
            pub const fn union(self, other: Self) -> Self {
                $name(KerberosFlags(self.0 .0 | other.0 .0))
            }

            pub(crate) fn from_value(value: &Value) -> Result<Self> {
                KerberosFlags::from_value(value).map($name)
            }

            pub(crate) fn to_value(self) -> Value {
                self.0.to_value()
            }
        }
    };
}

flags_use! {
    /// `TicketFlags ::= KerberosFlags` with the named bits of RFC 4120 5.3.
    /// Bits 0 and 14-31 are reserved; they are preserved but have no name.
    ///
    /// Spec: RFC 4120 5.3; Appendix A.
    TicketFlags {
        /// forwardable(1). Spec: RFC 4120 5.3.
        FORWARDABLE = 1;
        /// forwarded(2). Spec: RFC 4120 5.3.
        FORWARDED = 2;
        /// proxiable(3). Spec: RFC 4120 5.3.
        PROXIABLE = 3;
        /// proxy(4). Spec: RFC 4120 5.3.
        PROXY = 4;
        /// may-postdate(5). Spec: RFC 4120 5.3.
        MAY_POSTDATE = 5;
        /// postdated(6). Spec: RFC 4120 5.3.
        POSTDATED = 6;
        /// invalid(7). Spec: RFC 4120 5.3.
        INVALID = 7;
        /// renewable(8). Spec: RFC 4120 5.3.
        RENEWABLE = 8;
        /// initial(9). Spec: RFC 4120 5.3.
        INITIAL = 9;
        /// pre-authent(10). Spec: RFC 4120 5.3.
        PRE_AUTHENT = 10;
        /// hw-authent(11). Spec: RFC 4120 5.3.
        HW_AUTHENT = 11;
        /// transited-policy-checked(12). Spec: RFC 4120 5.3.
        TRANSITED_POLICY_CHECKED = 12;
        /// ok-as-delegate(13). Spec: RFC 4120 5.3.
        OK_AS_DELEGATE = 13;
    }
}

flags_use! {
    /// `KDCOptions ::= KerberosFlags` with the named bits of RFC 4120 5.4.1.
    /// Unused and reserved bits (0, 7, 9, 10, 12-25, 29; 15 "reserved for
    /// canonicalize") are preserved but have no name here.
    ///
    /// Spec: RFC 4120 5.4.1; Appendix A.
    KdcOptions {
        /// forwardable(1). Spec: RFC 4120 5.4.1.
        FORWARDABLE = 1;
        /// forwarded(2). Spec: RFC 4120 5.4.1.
        FORWARDED = 2;
        /// proxiable(3). Spec: RFC 4120 5.4.1.
        PROXIABLE = 3;
        /// proxy(4). Spec: RFC 4120 5.4.1.
        PROXY = 4;
        /// allow-postdate(5). Spec: RFC 4120 5.4.1.
        ALLOW_POSTDATE = 5;
        /// postdated(6). Spec: RFC 4120 5.4.1.
        POSTDATED = 6;
        /// renewable(8). Spec: RFC 4120 5.4.1.
        RENEWABLE = 8;
        /// opt-hardware-auth(11). Spec: RFC 4120 5.4.1.
        OPT_HARDWARE_AUTH = 11;
        /// disable-transited-check(26). Spec: RFC 4120 5.4.1.
        DISABLE_TRANSITED_CHECK = 26;
        /// renewable-ok(27). Spec: RFC 4120 5.4.1.
        RENEWABLE_OK = 27;
        /// enc-tkt-in-skey(28). Spec: RFC 4120 5.4.1.
        ENC_TKT_IN_SKEY = 28;
        /// renew(30). Spec: RFC 4120 5.4.1.
        RENEW = 30;
        /// validate(31). Spec: RFC 4120 5.4.1.
        VALIDATE = 31;
    }
}

flags_use! {
    /// `APOptions ::= KerberosFlags` with the named bits of RFC 4120 5.5.1.
    /// Bits 0 and 3-31 are reserved; they are preserved but have no name.
    ///
    /// Spec: RFC 4120 5.5.1; Appendix A.
    ApOptions {
        /// use-session-key(1). Spec: RFC 4120 5.5.1.
        USE_SESSION_KEY = 1;
        /// mutual-required(2). Spec: RFC 4120 5.5.1.
        MUTUAL_REQUIRED = 2;
    }
}

flags_use! {
    /// `FastOptions ::= KerberosFlags` with the named bit of RFC 6113 5.4.2.
    ///
    /// Bit 0 is reserved ("Reserved for future expansion of this field") and
    /// bit 16, kdc-follow-referrals, is "reserved [REFERRALS]"; like every
    /// other bit they are preserved but have no name here. RFC 6113 5.4.2 makes
    /// bits 1-15 critical and bits 16 onward non-critical: a KDC that does not
    /// support a critical option MUST fail the request with
    /// KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS, and ignores unknown non-critical
    /// ones. That check needs the KDC's set of supported options, so the KDC
    /// makes it on the decoded value; this codec only carries the 32 bits.
    /// (Whether reserved bit 0 is critical — 7.3 says "Bits 0-15 are
    /// critical" — is docs/questions/Q-033.)
    ///
    /// Spec: RFC 6113 5.4.2, 7.3; Appendix B.
    FastOptions {
        /// hide-client-names(1). Spec: RFC 6113 5.4.2, 7.3.
        HIDE_CLIENT_NAMES = 1;
    }
}
