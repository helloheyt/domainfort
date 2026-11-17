//! Wrap tokens of the Kerberos V5 mechanism, in the form without
//! confidentiality — the only form this profile has.
//!
//! ```text
//! Octet   Name     Description
//! 0..1    TOK_ID   05 04
//! 2       Flags    bit 0 SentByAcceptor, bit 1 Sealed, bit 2 AcceptorSubkey
//! 3       Filler   FF
//! 4..5    EC       big-endian; without confidentiality: the checksum length
//! 6..7    RRC      big-endian right rotation count
//! 8..15   SND_SEQ  big-endian sequence number
//! 16..    Data     plaintext-data | checksum, rotated right by RRC
//! ```
//!
//! Three layers, one parser:
//!
//! * [`WrapHeader::read`] — the structural reading of the 16-octet header
//!   (TOK_ID, Filler; first octet 0x60 refused as the framed format). It
//!   judges no flag and exposes no octet range to MAC; an interop test uses it
//!   to read observed (sealed) Windows tokens.
//! * [`ReceivedWrapToken::parse`] — the profile: the same structural reading,
//!   then Sealed refused, the direction (SentByAcceptor) and AcceptorSubkey
//!   compared with the caller's [`WrapExpectation`], EC equal to the caller's
//!   checksum length, the size bound, and the RRC rotation undone (any value,
//!   including values beyond the length). It lays out the octets keyd must
//!   MAC — `plaintext-data | header with EC = RRC = 0` — and the checksum;
//!   the plaintext is released only through
//!   [`ReceivedWrapToken::into_verified_plaintext`], after the caller's
//!   verification of that checksum.
//! * [`OutgoingWrapToken`] — the sending side: header with Sealed clear,
//!   unknown bits clear, RRC = 0 (docs/60 §3.4 step 6: no rotation on send),
//!   EC = the checksum length; the caller MACs the laid-out input and hands
//!   the checksum back to finish the token.
//!
//! No checksum is computed here (docs/60 §3.3: the wrap and unwrap run in
//! keyd, which holds the key). There is no code path that produces or accepts
//! confidentiality.
//!
//! Spec: RFC 4121 §2, §4.2.1–§4.2.6.2, §4.4, §6; RFC 4752 §3.1–§3.3;
//! docs/60 §3.3, §3.4, §9 K4/K12/K13, §10.1; Q-1093 items 4, 6, 7.

use crate::error::{Error, Result};
use crate::limits::{MAX_WRAP_TOKEN_LEN, WRAP_HEADER_LEN};
use core::fmt;
use core::num::NonZeroU16;

/// The Wrap TOK_ID: "Tokens emitted by GSS_Wrap() contain the hex value 05 04
/// expressed in big-endian order". Spec: RFC 4121 §4.2.6.2.
pub const WRAP_TOK_ID: [u8; 2] = [0x05, 0x04];

/// The Filler octet: "Contains the hex value FF". Spec: RFC 4121 §4.2.6.2.
pub const WRAP_FILLER: u8 = 0xFF;

/// The first octet of a token in the generic GSS-API framing; never the first
/// octet of a TOK_ID of this format. Spec: RFC 4121 §4.4, §6.
const FRAMED_TOKEN_FIRST_OCTET: u8 = 0x60;

/// Flags bit 0, SentByAcceptor. Spec: RFC 4121 §4.2.2.
pub const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
/// Flags bit 1, Sealed. Spec: RFC 4121 §4.2.2.
pub const FLAG_SEALED: u8 = 0x02;
/// Flags bit 2, AcceptorSubkey. Spec: RFC 4121 §4.2.2.
pub const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// Who sent a token — the meaning of the SentByAcceptor flag ("When not set,
/// it indicates the sender is the context initiator").
/// Spec: RFC 4121 §4.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sender {
    /// The context initiator (SentByAcceptor clear) — the client.
    Initiator,
    /// The context acceptor (SentByAcceptor set) — keyd, for the server.
    Acceptor,
}

/// The 16-octet header of a Wrap token, as read.
///
/// The Flags octet is kept whole: the profile interprets only the three
/// defined bits ("The receiver MUST ignore unknown flags"), and the octets
/// keyd MACs reproduce the received header exactly.
/// Spec: RFC 4121 §4.2.2, §4.2.6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WrapHeader {
    flags: u8,
    ec: u16,
    rrc: u16,
    snd_seq: u64,
}

impl WrapHeader {
    /// Read the header of a Wrap token — structure only: at least 16 octets
    /// ([`Error::Truncated`]); first octet not 0x60 ([`Error::FramedToken`]);
    /// TOK_ID 05 04 ([`Error::NotWrapToken`]); Filler FF
    /// ([`Error::BadFiller`]). No flag is judged, the octets after the header
    /// are not read, nothing is allocated. Profile decisions are
    /// [`ReceivedWrapToken::parse`]'s, which starts with this same reading.
    ///
    /// Spec: RFC 4121 §4.2.6.2, §4.4, §6.
    pub fn read(token: &[u8]) -> Result<Self> {
        let Some((header, _data)) = token.split_first_chunk::<WRAP_HEADER_LEN>() else {
            return Err(Error::Truncated);
        };
        let [t0, t1, flags, filler, e0, e1, r0, r1, s0, s1, s2, s3, s4, s5, s6, s7] = *header;
        if t0 == FRAMED_TOKEN_FIRST_OCTET {
            return Err(Error::FramedToken);
        }
        if [t0, t1] != WRAP_TOK_ID {
            return Err(Error::NotWrapToken);
        }
        if filler != WRAP_FILLER {
            return Err(Error::BadFiller);
        }
        Ok(WrapHeader {
            flags,
            ec: u16::from_be_bytes([e0, e1]),
            rrc: u16::from_be_bytes([r0, r1]),
            snd_seq: u64::from_be_bytes([s0, s1, s2, s3, s4, s5, s6, s7]),
        })
    }

    /// The Flags octet as received, unknown bits included.
    /// Spec: RFC 4121 §4.2.2.
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// The sender the SentByAcceptor flag names. Spec: RFC 4121 §4.2.2.
    pub const fn sender(&self) -> Sender {
        if self.flags & FLAG_SENT_BY_ACCEPTOR != 0 {
            Sender::Acceptor
        } else {
            Sender::Initiator
        }
    }

    /// The Sealed flag ("confidentiality is provided for").
    /// Spec: RFC 4121 §4.2.2.
    pub const fn sealed(&self) -> bool {
        self.flags & FLAG_SEALED != 0
    }

    /// The AcceptorSubkey flag ("A subkey asserted by the context acceptor is
    /// used to protect the message"). Spec: RFC 4121 §2, §4.2.2.
    pub const fn acceptor_subkey(&self) -> bool {
        self.flags & FLAG_ACCEPTOR_SUBKEY != 0
    }

    /// EC, the "extra count". Spec: RFC 4121 §4.2.3.
    pub const fn ec(&self) -> u16 {
        self.ec
    }

    /// RRC, the "right rotation count". Spec: RFC 4121 §4.2.5.
    pub const fn rrc(&self) -> u16 {
        self.rrc
    }

    /// SND_SEQ, the sender's sequence number. Spec: RFC 4121 §4.2.1,
    /// §4.2.6.2.
    pub const fn snd_seq(&self) -> u64 {
        self.snd_seq
    }

    /// The 16 header octets with EC and RRC filled with zeroes — the header
    /// as it enters the checksum: "Both the EC field and the RRC field in the
    /// token header SHALL be filled with zeroes for the purpose of calculating
    /// the checksum."
    /// Spec: RFC 4121 §4.2.4, §4.2.6.2.
    pub fn checksum_header(&self) -> [u8; WRAP_HEADER_LEN] {
        header_octets(self.flags, 0, 0, self.snd_seq)
    }

    /// The 16 header octets as they go on the wire (EC and RRC included).
    /// Spec: RFC 4121 §4.2.6.2.
    pub fn octets(&self) -> [u8; WRAP_HEADER_LEN] {
        header_octets(self.flags, self.ec, self.rrc, self.snd_seq)
    }
}

/// Lay out the 16 header octets: TOK_ID, Flags, Filler, EC, RRC, SND_SEQ —
/// every multi-octet field big-endian.
/// Spec: RFC 4121 §4.2.6.2.
fn header_octets(flags: u8, ec: u16, rrc: u16, snd_seq: u64) -> [u8; WRAP_HEADER_LEN] {
    let [t0, t1] = WRAP_TOK_ID;
    let [e0, e1] = ec.to_be_bytes();
    let [r0, r1] = rrc.to_be_bytes();
    let [s0, s1, s2, s3, s4, s5, s6, s7] = snd_seq.to_be_bytes();
    [
        t0,
        t1,
        flags,
        WRAP_FILLER,
        e0,
        e1,
        r0,
        r1,
        s0,
        s1,
        s2,
        s3,
        s4,
        s5,
        s6,
        s7,
    ]
}

/// What the receiver of a Wrap token knows from its own context, compared
/// with the header (the caller supplies it — this crate holds no context).
///
/// Spec: RFC 4121 §2 (AcceptorSubkey when the acceptor asserted a subkey),
/// §4.2.2 (the direction indicator), §4.2.3 (EC = the checksum length without
/// confidentiality); docs/60 §3.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapExpectation {
    /// The peer the token must come from: keyd expects
    /// [`Sender::Initiator`] for the client's selection (docs/60 §3.4).
    pub sender: Sender,
    /// Whether the acceptor asserted a subkey in its AP-REP; the token's
    /// AcceptorSubkey flag must say the same (keyd always asserts one —
    /// docs/60 §3.4, Q-1093 item 4).
    pub acceptor_subkey: bool,
    /// The checksum length of the base key's encryption type, which EC must
    /// equal. Never zero: a Wrap token without confidentiality and without a
    /// checksum would carry no protection, so it cannot be described.
    pub checksum_len: NonZeroU16,
}

/// A received Wrap token without confidentiality, its rotation undone, laid
/// out for the caller's checksum verification.
///
/// Holds one buffer `plaintext-data | checksum_header | checksum` (≤
/// [`MAX_WRAP_TOKEN_LEN`] octets), so the checksum input is one contiguous
/// slice. `Debug` shows the header and lengths only, never data octets.
///
/// Spec: RFC 4121 §4.2.4, §4.2.5, §4.2.6.2.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedWrapToken {
    header: WrapHeader,
    buffer: Vec<u8>,
    plaintext_len: usize,
}

impl ReceivedWrapToken {
    /// Parse a received Wrap token by the profile.
    ///
    /// Checks, in order: the structural reading of [`WrapHeader::read`];
    /// Sealed clear ([`Error::Sealed`]); SentByAcceptor names
    /// `expected.sender` ([`Error::DirectionMismatch`]); AcceptorSubkey equals
    /// `expected.acceptor_subkey` ([`Error::AcceptorSubkeyMismatch`]); EC
    /// equals `expected.checksum_len` ([`Error::EcMismatch`]); the token is at
    /// most [`MAX_WRAP_TOKEN_LEN`] octets ([`Error::WrapTokenTooLong`]); the
    /// data holds at least EC octets ([`Error::WrapBodyTooShort`]). Then the
    /// data is rotated left by RRC modulo its length — undoing the sender's
    /// right rotation for every RRC value — and split into plaintext-data and
    /// the trailing EC-octet checksum. Unknown Flags bits are ignored.
    /// SND_SEQ is returned for the caller to compare (keyd holds the sequence
    /// state — docs/60 §3.4, Q-1093 item 7).
    ///
    /// Spec: RFC 4121 §4.2.2, §4.2.3, §4.2.4, §4.2.5 ("The receiver MUST be
    /// able to interpret all possible rotation count values, including
    /// rotation counts greater than the length of the token"), §4.2.6.2;
    /// RFC 4752 §3.1 (the selection is wrapped with conf_flag FALSE);
    /// docs/60 §3.4, R60-11; Q-1093 item 6.
    pub fn parse(token: &[u8], expected: WrapExpectation) -> Result<Self> {
        let header = WrapHeader::read(token)?;
        if header.sealed() {
            return Err(Error::Sealed);
        }
        if header.sender() != expected.sender {
            return Err(Error::DirectionMismatch);
        }
        if header.acceptor_subkey() != expected.acceptor_subkey {
            return Err(Error::AcceptorSubkeyMismatch);
        }
        if header.ec() != expected.checksum_len.get() {
            return Err(Error::EcMismatch);
        }
        if token.len() > MAX_WRAP_TOKEN_LEN {
            return Err(Error::WrapTokenTooLong);
        }
        let (_, data) = token.split_at(WRAP_HEADER_LEN.min(token.len()));
        let checksum_len = usize::from(header.ec());
        let plaintext_len = data
            .len()
            .checked_sub(checksum_len)
            .ok_or(Error::WrapBodyTooShort)?;
        let unrotated = rotate_left(data, header.rrc());
        let (plaintext, checksum) = unrotated.split_at(plaintext_len);
        let mut buffer = Vec::with_capacity(data.len() + WRAP_HEADER_LEN);
        buffer.extend_from_slice(plaintext);
        buffer.extend_from_slice(&header.checksum_header());
        buffer.extend_from_slice(checksum);
        Ok(ReceivedWrapToken {
            header,
            buffer,
            plaintext_len,
        })
    }

    /// The header as received. Spec: RFC 4121 §4.2.6.2.
    pub fn header(&self) -> &WrapHeader {
        &self.header
    }

    /// SND_SEQ. Spec: RFC 4121 §4.2.1.
    pub fn snd_seq(&self) -> u64 {
        self.header.snd_seq()
    }

    /// The octets the checksum covers, in order: the plaintext-data, then the
    /// header with EC and RRC zeroed. Spec: RFC 4121 §4.2.4 ("calculated first
    /// over the to-be-signed plaintext data, and then over the first 16 octets
    /// of the Wrap token").
    pub fn checksum_input(&self) -> &[u8] {
        let (input, _) = self.split_checksum();
        input
    }

    /// The trailing checksum (EC octets). Spec: RFC 4121 §4.2.4, §4.2.6.2.
    pub fn checksum(&self) -> &[u8] {
        let (_, checksum) = self.split_checksum();
        checksum
    }

    /// Release the plaintext-data only if `verify(checksum_input, checksum)`
    /// says the checksum is correct (keyd computes the checksum with the base
    /// key and the sender's usage and compares in constant time — docs/60
    /// §3.4). Otherwise [`Error::ChecksumMismatch`]; the token is consumed
    /// either way, so a second verification attempt needs a new parse.
    ///
    /// Spec: RFC 4121 §4.2.4; RFC 4752 §3, §3.3 (a GSS_Unwrap failure is
    /// fatal).
    pub fn into_verified_plaintext<F>(self, verify: F) -> Result<Vec<u8>>
    where
        F: FnOnce(&[u8], &[u8]) -> bool,
    {
        let verified = {
            let (input, checksum) = self.split_checksum();
            verify(input, checksum)
        };
        if !verified {
            return Err(Error::ChecksumMismatch);
        }
        let mut plaintext = self.buffer;
        plaintext.truncate(self.plaintext_len);
        Ok(plaintext)
    }

    /// (`plaintext-data | checksum_header`, `checksum`).
    fn split_checksum(&self) -> (&[u8], &[u8]) {
        let input_len = (self.plaintext_len + WRAP_HEADER_LEN).min(self.buffer.len());
        self.buffer.split_at(input_len)
    }
}

impl fmt::Debug for ReceivedWrapToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedWrapToken")
            .field("header", &self.header)
            .field("plaintext_len", &self.plaintext_len)
            .finish()
    }
}

/// A Wrap token without confidentiality being built: the header is fixed, the
/// checksum input laid out; [`Self::finish`] takes the caller's checksum.
///
/// Spec: RFC 4121 §4.2.4, §4.2.6.2; docs/60 §3.4 step 6.
#[derive(Clone, PartialEq, Eq)]
pub struct OutgoingWrapToken {
    header: WrapHeader,
    /// `plaintext-data | checksum_header`.
    checksum_input: Vec<u8>,
    plaintext_len: usize,
}

impl OutgoingWrapToken {
    /// Start a Wrap token from `sender` carrying `plaintext`, with Flags =
    /// SentByAcceptor (for [`Sender::Acceptor`]) | AcceptorSubkey (if
    /// `acceptor_subkey`), Sealed and every reserved bit clear, Filler FF,
    /// EC = `checksum_len`, RRC = 0 and SND_SEQ = `snd_seq`. Refused when the
    /// finished token would exceed [`MAX_WRAP_TOKEN_LEN`]
    /// ([`Error::WrapTokenTooLong`]).
    ///
    /// Spec: RFC 4121 §2 (AcceptorSubkey), §4.2.2 ("The rest of available
    /// bits are reserved for future use and MUST be cleared"), §4.2.3,
    /// §4.2.5 (the rotation count is the sender's choice; docs/60 §3.4 step 6
    /// sends RRC = 0), §4.2.6.2; RFC 4752 §3.2 (conf_flag FALSE).
    pub fn new(
        sender: Sender,
        acceptor_subkey: bool,
        snd_seq: u64,
        plaintext: &[u8],
        checksum_len: NonZeroU16,
    ) -> Result<Self> {
        let total = WRAP_HEADER_LEN
            .checked_add(plaintext.len())
            .and_then(|n| n.checked_add(usize::from(checksum_len.get())))
            .filter(|&n| n <= MAX_WRAP_TOKEN_LEN)
            .ok_or(Error::WrapTokenTooLong)?;
        let mut flags = 0;
        if sender == Sender::Acceptor {
            flags |= FLAG_SENT_BY_ACCEPTOR;
        }
        if acceptor_subkey {
            flags |= FLAG_ACCEPTOR_SUBKEY;
        }
        let header = WrapHeader {
            flags,
            ec: checksum_len.get(),
            rrc: 0,
            snd_seq,
        };
        let mut checksum_input = Vec::with_capacity(total);
        checksum_input.extend_from_slice(plaintext);
        checksum_input.extend_from_slice(&header.checksum_header());
        Ok(OutgoingWrapToken {
            header,
            checksum_input,
            plaintext_len: plaintext.len(),
        })
    }

    /// The header the token will carry. Spec: RFC 4121 §4.2.6.2.
    pub fn header(&self) -> &WrapHeader {
        &self.header
    }

    /// The octets the caller's checksum must cover: the plaintext-data, then
    /// the header with EC and RRC zeroed. Spec: RFC 4121 §4.2.4.
    pub fn checksum_input(&self) -> &[u8] {
        &self.checksum_input
    }

    /// Finish the token: `header | plaintext-data | checksum`, with `checksum`
    /// exactly EC octets ([`Error::ChecksumLengthMismatch`]). RRC is 0, so
    /// nothing is rotated.
    ///
    /// Spec: RFC 4121 §4.2.4 ("The resulting Wrap token is {"header" |
    /// plaintext-data | get_mic(plaintext-data | "header")}"), §4.2.6.2.
    pub fn finish(self, checksum: &[u8]) -> Result<Vec<u8>> {
        if checksum.len() != usize::from(self.header.ec()) {
            return Err(Error::ChecksumLengthMismatch);
        }
        let (plaintext, _) = self
            .checksum_input
            .split_at(self.plaintext_len.min(self.checksum_input.len()));
        let mut token = Vec::with_capacity(WRAP_HEADER_LEN + plaintext.len() + checksum.len());
        token.extend_from_slice(&self.header.octets());
        token.extend_from_slice(plaintext);
        token.extend_from_slice(checksum);
        Ok(token)
    }
}

impl fmt::Debug for OutgoingWrapToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingWrapToken")
            .field("header", &self.header)
            .field("plaintext_len", &self.plaintext_len)
            .finish()
    }
}

/// Undo a right rotation by `rrc`: rotate `data` left by `rrc` modulo its
/// length (a count equal to the length is no rotation; empty data is
/// unchanged). Allocates `data.len()` octets — bounded by the caller.
///
/// RFC 4121 §4.2.5: the token after the 16 header octets is "rotated to the
/// right by "RRC" octets", so that "RRC" trailing octets move toward the
/// header; the receiver "MUST be able to interpret all possible rotation count
/// values, including rotation counts greater than the length of the token".
///
/// Spec: RFC 4121 §4.2.5.
fn rotate_left(data: &[u8], rrc: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let shift = usize::from(rrc).checked_rem(data.len()).unwrap_or(0);
    let (front, back) = data.split_at(shift);
    out.extend_from_slice(back);
    out.extend_from_slice(front);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example of RFC 4121 §4.2.5: with RRC = 3, {aa bb cc dd ee ff gg
    /// hh} is sent as {ff gg hh aa bb cc dd ee}; undoing the rotation restores
    /// the order. Octet values stand for the section's letters.
    #[test]
    fn rfc4121_4_2_5_rotation_example_is_undone() {
        let (aa, bb, cc, dd, ee, ff, gg, hh) = (0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x99, 0x88);
        let rotated = [ff, gg, hh, aa, bb, cc, dd, ee];
        assert_eq!(
            rotate_left(&rotated, 3),
            vec![aa, bb, cc, dd, ee, ff, gg, hh]
        );
    }

    /// "including rotation counts greater than the length of the token":
    /// counts are taken modulo the length; empty data is left as is.
    /// Spec: RFC 4121 §4.2.5.
    #[test]
    fn rotation_counts_beyond_the_length_wrap_around() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(rotate_left(&data, 8), data.to_vec());
        assert_eq!(rotate_left(&data, 11), rotate_left(&data, 3));
        assert_eq!(rotate_left(&data, u16::MAX), rotate_left(&data, 65_535 % 8));
        assert_eq!(rotate_left(&[], 5), Vec::<u8>::new());
    }
}
