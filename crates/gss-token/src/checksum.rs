//! The authenticator checksum of the Kerberos V5 mechanism (checksum type
//! 0x8003).
//!
//! ```text
//! Octet   Name   Description
//! 0..3    Lgth   number of octets in Bnd, little-endian — 16
//! 4..19   Bnd    channel binding information (opaque here)
//! 20..23  Flags  context-establishment flags, little-endian
//! 24..    (DlgOpt, Dlgth, Deleg — only with GSS_C_DELEG_FLAG, refused here)
//! ..last  Exts   extensions — ignored
//! ```
//!
//! [`AuthenticatorChecksum::from_authenticator`] is the one place where the
//! RFC 4121 §4.1.1 requirements on the Authenticator of a GSS initial token
//! are checked, together with the docs/60 profile (Q-1093 items 1–3, 5;
//! docs/60 R60-1): the `cksum` and `seq-number` fields are present, the type
//! is 0x8003, the field is at least 24 octets, `Lgth` is 16, GSS_C_DELEG_FLAG
//! is clear, GSS_C_INTEG_FLAG and GSS_C_MUTUAL_FLAG are set, and `Bnd` is not
//! GSS_C_NO_BINDINGS. Unknown flags are ignored and the octets past `Flags`
//! (Exts) are not read, as RFC 4121 §4.1.1 / §4.1.1.1 require of an acceptor
//! that does not understand them. The result is the only way to the `Bnd`,
//! the flags and the initiator's initial sequence number, so keyd cannot reach
//! them without these checks.
//!
//! No hashing here: `Bnd` is kept as 16 opaque octets for keyd to compare, in
//! constant time, with the channel-binding digest dird computed (docs/60
//! §4.3; the MD5 lives elsewhere, task LC1).
//!
//! Spec: RFC 4121 §4.1.1, §4.1.1.1, §4.1.1.2; RFC 4120 §5.5.1; RFC 4752 §3.1;
//! docs/60 §3.4 step 4, §10.1; Q-1093.

use crate::error::{Error, Result};
use crate::limits::{AUTHENTICATOR_CHECKSUM_MIN_LEN, BND_LEN, MAX_CONTEXT_TOKEN_LEN};
use core::fmt;

/// "The checksum type MUST be 0x8003." Spec: RFC 4121 §4.1.1.
pub const GSS_CHECKSUM_TYPE: i32 = 0x8003;

/// The `Lgth` field: "Currently contains hex value 10 00 00 00 (16)" — the
/// length of `Bnd`, little-endian. Spec: RFC 4121 §4.1.1.
const LGTH: [u8; 4] = [0x10, 0x00, 0x00, 0x00];
const _: () = assert!(u32::from_le_bytes(LGTH) as usize == BND_LEN);

/// GSS_C_DELEG_FLAG = 1. Spec: RFC 4121 §4.1.1.1 (values defined in RFC 2744).
pub const GSS_C_DELEG_FLAG: u32 = 1;
/// GSS_C_MUTUAL_FLAG = 2. Spec: RFC 4121 §4.1.1.1.
pub const GSS_C_MUTUAL_FLAG: u32 = 2;
/// GSS_C_REPLAY_FLAG = 4. Spec: RFC 4121 §4.1.1.1.
pub const GSS_C_REPLAY_FLAG: u32 = 4;
/// GSS_C_SEQUENCE_FLAG = 8. Spec: RFC 4121 §4.1.1.1.
pub const GSS_C_SEQUENCE_FLAG: u32 = 8;
/// GSS_C_CONF_FLAG = 16. Spec: RFC 4121 §4.1.1.1.
pub const GSS_C_CONF_FLAG: u32 = 16;
/// GSS_C_INTEG_FLAG = 32. Spec: RFC 4121 §4.1.1.1.
pub const GSS_C_INTEG_FLAG: u32 = 32;

/// The `cksum` field of a decoded Authenticator: RFC 4120's `Checksum`
/// (`cksumtype [0] Int32`, `checksum [1] OCTET STRING`), borrowed from the
/// caller's decoded value. Spec: RFC 4120 §5.2.9, §5.5.1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChecksumField<'a> {
    /// `cksumtype`.
    pub cksumtype: i32,
    /// `checksum`: the octets laid out by RFC 4121 §4.1.1.
    pub checksum: &'a [u8],
}

impl fmt::Debug for ChecksumField<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChecksumField")
            .field("cksumtype", &self.cksumtype)
            .field("checksum_len", &self.checksum.len())
            .finish()
    }
}

/// The checksum `Flags` field, as received: every bit is kept (so it can be
/// audited), but only the six defined flags are interpreted — "unknown flags
/// MUST be ignored by the receiver", including the vendor range 4096..524288.
/// Spec: RFC 4121 §4.1.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContextFlags(u32);

impl ContextFlags {
    /// The four Flags octets as a little-endian integer, unknown bits
    /// included. Spec: RFC 4121 §4.1.1 ("Four-octet context-establishment
    /// flags in little-endian order").
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// GSS_C_DELEG_FLAG. Never set in an accepted checksum.
    pub const fn deleg(self) -> bool {
        self.0 & GSS_C_DELEG_FLAG != 0
    }

    /// GSS_C_MUTUAL_FLAG. Always set in an accepted checksum.
    pub const fn mutual(self) -> bool {
        self.0 & GSS_C_MUTUAL_FLAG != 0
    }

    /// GSS_C_REPLAY_FLAG (not judged by this profile).
    pub const fn replay(self) -> bool {
        self.0 & GSS_C_REPLAY_FLAG != 0
    }

    /// GSS_C_SEQUENCE_FLAG (not judged by this profile: RFC 4752 §3.1 has the
    /// client request it only together with a security layer, and none is
    /// offered — docs/questions/Q-1110).
    pub const fn sequence(self) -> bool {
        self.0 & GSS_C_SEQUENCE_FLAG != 0
    }

    /// GSS_C_CONF_FLAG (not judged here; a Sealed Wrap token is refused
    /// whatever this says).
    pub const fn conf(self) -> bool {
        self.0 & GSS_C_CONF_FLAG != 0
    }

    /// GSS_C_INTEG_FLAG. Always set in an accepted checksum.
    pub const fn integ(self) -> bool {
        self.0 & GSS_C_INTEG_FLAG != 0
    }
}

/// The `Bnd` field: the channel binding information of the initiator, 16
/// octets, kept opaque (never all zero once accepted). `Debug` shows no
/// octets (docs/60 §7: no Bnd in any log).
/// Spec: RFC 4121 §4.1.1, §4.1.1.2.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Bnd([u8; BND_LEN]);

impl Bnd {
    /// The 16 octets, for keyd's constant-time comparison with the
    /// channel-binding digest (docs/60 §3.4 step 4, §4.3).
    pub const fn octets(&self) -> &[u8; BND_LEN] {
        &self.0
    }
}

impl fmt::Debug for Bnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bnd(<16 octets>)")
    }
}

/// An Authenticator's checksum and sequence number that passed every check of
/// RFC 4121 §4.1.1 and of the docs/60 profile.
///
/// Spec: RFC 4121 §4.1.1, §4.1.1.1, §4.1.1.2; docs/60 §3.4 step 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatorChecksum {
    bnd: Bnd,
    flags: ContextFlags,
    initiator_seq_number: u32,
}

impl AuthenticatorChecksum {
    /// Check the `cksum` and `seq-number` fields of a decoded Authenticator.
    ///
    /// Refusals, in order: no `cksum` ([`Error::MissingChecksum`]); no
    /// `seq-number` ([`Error::MissingSequenceNumber`]); `cksumtype` ≠ 0x8003
    /// ([`Error::WrongChecksumType`]); more octets than a token can hold
    /// ([`Error::ChecksumTooLong`]); fewer than 24 ([`Error::ChecksumTooShort`]);
    /// `Lgth` ≠ 16 ([`Error::LgthNot16`]); GSS_C_DELEG_FLAG set
    /// ([`Error::DelegationRefused`]); GSS_C_INTEG_FLAG clear
    /// ([`Error::IntegFlagMissing`]); GSS_C_MUTUAL_FLAG clear
    /// ([`Error::MutualFlagMissing`]); `Bnd` all zero
    /// ([`Error::NoChannelBindings`]). Octets 24 and later (Exts) are not
    /// read.
    ///
    /// Spec: RFC 4121 §4.1.1 ("MUST include the optional sequence number and
    /// the checksum field"; type 0x8003; layout; "at least 24 octets"; "MUST
    /// ignore any octets past ... the Flags field"), §4.1.1.1 (flag values;
    /// unknown flags ignored), §4.1.1.2 (3) (16 zero octets = no bindings);
    /// RFC 4120 §5.5.1; RFC 4752 §3.1; docs/60 R60-1, §3.4 step 4, §10.1;
    /// Q-1093 items 1, 2, 3, 5.
    pub fn from_authenticator(
        cksum: Option<ChecksumField<'_>>,
        seq_number: Option<u32>,
    ) -> Result<Self> {
        let cksum = cksum.ok_or(Error::MissingChecksum)?;
        let initiator_seq_number = seq_number.ok_or(Error::MissingSequenceNumber)?;
        if cksum.cksumtype != GSS_CHECKSUM_TYPE {
            return Err(Error::WrongChecksumType);
        }
        if cksum.checksum.len() > MAX_CONTEXT_TOKEN_LEN {
            return Err(Error::ChecksumTooLong);
        }
        // The fixed 24 octets; anything after them is DlgOpt/Dlgth/Deleg
        // (only with GSS_C_DELEG_FLAG, refused below) or Exts (ignored).
        let Some((fixed, _exts)) = cksum
            .checksum
            .split_first_chunk::<AUTHENTICATOR_CHECKSUM_MIN_LEN>()
        else {
            return Err(Error::ChecksumTooShort);
        };
        let (lgth, rest) = split4(fixed);
        let (bnd, flags) = split_bnd(rest);
        if lgth != LGTH {
            return Err(Error::LgthNot16);
        }
        let flags = ContextFlags(u32::from_le_bytes(flags));
        if flags.deleg() {
            return Err(Error::DelegationRefused);
        }
        if !flags.integ() {
            return Err(Error::IntegFlagMissing);
        }
        if !flags.mutual() {
            return Err(Error::MutualFlagMissing);
        }
        if bnd == [0u8; BND_LEN] {
            return Err(Error::NoChannelBindings);
        }
        Ok(AuthenticatorChecksum {
            bnd: Bnd(bnd),
            flags,
            initiator_seq_number,
        })
    }

    /// `Bnd`, never all zero. Spec: RFC 4121 §4.1.1.2.
    pub const fn bnd(&self) -> &Bnd {
        &self.bnd
    }

    /// The Flags as received (DELEG clear, INTEG and MUTUAL set).
    /// Spec: RFC 4121 §4.1.1.1.
    pub const fn flags(&self) -> ContextFlags {
        self.flags
    }

    /// The Authenticator's `seq-number`: the initial sequence number for
    /// messages from the initiator to the acceptor — the SND_SEQ keyd expects
    /// in the client's first Wrap token (docs/60 §3.4; Q-1093 item 7).
    /// Spec: RFC 4120 §5.5.1; RFC 4121 §4.1.1, §4.2.1.
    pub const fn initiator_seq_number(&self) -> u32 {
        self.initiator_seq_number
    }
}

/// Split the 24 fixed octets into `Lgth` (octets 0..3) and the rest.
fn split4(fixed: &[u8; AUTHENTICATOR_CHECKSUM_MIN_LEN]) -> ([u8; 4], [u8; 20]) {
    let [l0, l1, l2, l3, rest @ ..] = *fixed;
    ([l0, l1, l2, l3], rest)
}

/// Split octets 4..23 into `Bnd` (4..19) and `Flags` (20..23).
fn split_bnd(rest: [u8; 20]) -> ([u8; BND_LEN], [u8; 4]) {
    let [b @ .., f0, f1, f2, f3] = rest;
    (b, [f0, f1, f2, f3])
}
