//! The wire → canonical relay, without I/O: the client's cleartext LDAP
//! octets are gathered in a [`WireBuffer`]; [`take_message`] cuts the first
//! LDAPMessage with dird's framing state, decodes it with parse-ldap's
//! **wire** profile and re-encodes it in the **canonical** form that dird's
//! engine accepts (docs/49 R49-16; docs/50 §4.2).
//!
//! # Framing (docs/50 §4.2)
//!
//! `parse_ldap::frame_length(buffer, auth)` "compares the announced size with
//! the bound for the session's authentication state **before any allocation
//! or wait for contents**"; `auth` is the framing state dird reported last
//! (`Opened`, `Done`, `TlsAccepted` — start: `Unauthenticated`). A
//! compromised front that ignored it would still meet the engine's own check
//! (crates/ldap: "larger than the session's bound | close, no response").
//!
//! # Wire → canonical (docs/49 R49-16; A-52)
//!
//! "The front decodes with `Profile::Wire` and encodes with
//! `encode_message`; the engine decodes with `Profile::Canonical` only"
//! (docs/50 §4.2). A simple-bind password is never retained by the decoder
//! (A-52: a placeholder takes its place), so it never reaches dird; the
//! octets it arrived in are wiped from the buffer as soon as the message is
//! cut (below).
//!
//! # What the caller does with a failure
//!
//! | [`FrameFailure`] | the front | anchor |
//! |---|---|---|
//! | `TooLarge` | close, no response | [MS-ADTS] 3.1.1.3.4.6 as crates/parse-ldap and crates/ldap cite it ("drop the connection") |
//! | `NotLdap`, `NotDecodable`, `NotEncodable` | Notice of Disconnection (protocolError), close | RFC 4511 §4.1.1 ("the server SHOULD return the Notice of Disconnection … with the resultCode set to protocolError, and MUST immediately terminate the LDAP session") |
//!
//! # The buffer holds client octets (a password may be among them)
//!
//! [`WireBuffer`] never reallocates in place: growing it copies into a new
//! buffer and wipes the old one, and cutting a message moves the rest to the
//! front and wipes the vacated tail (zeroize 1.9.1 documents that `Vec`
//! zeroization "cannot ensure that previous reallocations did not leave
//! values on the heap" — so no reallocation is left to `Vec`). Its `Debug`
//! output shows only the length (docs/50 §8.2).
//!
//! Spec: RFC 4511 §4.1.1, §4.14.1, §5.2; docs/49 R49-16, §2.4, §11; docs/50
//! R50-10, §4.2, §4.3 step 1, §8.2; A-45; A-52.

use core::fmt;
use parse_ldap::{
    decode_message, encode_message, frame_length, AuthState, DecodeOptions, Error, Frame,
    LdapMessage, ProtocolOp, START_TLS_OID,
};
use zeroize::{Zeroize, Zeroizing};

/// The most octets the buffer may hold: the largest message of any framing
/// state plus one read. Reads are made only while the first message is
/// incomplete, so this is never reached by a well-behaved peer; reaching it
/// closes the connection (a defensive bound, AGENTS.md §6).
/// Spec: docs/49 §2.4; AGENTS.md §6 (bounded parsers).
pub const MAX_BUFFERED_OCTETS: usize = parse_ldap::MAX_AUTH_MESSAGE_OCTETS + READ_CHUNK;

/// Octets read from the client socket per read call at most. Project
/// choice.
pub const READ_CHUNK: usize = 16 * 1024;

/// The client's cleartext LDAP octets not yet cut into messages (module
/// documentation: wiped on every move).
/// Spec: docs/50 §4.3 step 3 ("destroy the cleartext buffer"); AGENTS.md
/// §6.
pub struct WireBuffer {
    octets: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for WireBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireBuffer")
            .field("len", &self.octets.len())
            .finish()
    }
}

impl Default for WireBuffer {
    fn default() -> Self {
        WireBuffer::new()
    }
}

/// Appending would exceed [`MAX_BUFFERED_OCTETS`].
/// Spec: AGENTS.md §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferFull;

impl WireBuffer {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> WireBuffer {
        WireBuffer {
            octets: Zeroizing::new(Vec::new()),
        }
    }

    /// The buffered octets.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.octets
    }

    /// How many octets are buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.octets.len()
    }

    /// Whether nothing is buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.octets.is_empty()
    }

    /// Append `input`; grows by copying into a new buffer and wiping the old
    /// one (module documentation).
    ///
    /// # Errors
    /// [`BufferFull`] beyond [`MAX_BUFFERED_OCTETS`]; nothing is appended.
    ///
    /// Spec: AGENTS.md §6 (no unbounded allocation).
    pub fn extend(&mut self, input: &[u8]) -> Result<(), BufferFull> {
        let wanted = self
            .octets
            .len()
            .checked_add(input.len())
            .filter(|&len| len <= MAX_BUFFERED_OCTETS)
            .ok_or(BufferFull)?;
        if wanted > self.octets.capacity() {
            let capacity = wanted
                .max(self.octets.capacity().saturating_mul(2))
                .clamp(READ_CHUNK, MAX_BUFFERED_OCTETS);
            let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
            grown.extend_from_slice(&self.octets);
            // The old buffer is wiped (capacity included) when it drops here.
            self.octets = grown;
        }
        self.octets.extend_from_slice(input);
        Ok(())
    }

    /// Remove the first `count` octets: the rest moves to the front and the
    /// vacated tail is wiped.
    /// Spec: module documentation.
    fn consume(&mut self, count: usize) {
        let len = self.octets.len();
        let count = count.min(len);
        self.octets.copy_within(count.., 0);
        let rest = len - count;
        if let Some(tail) = self.octets.get_mut(rest..) {
            tail.zeroize();
        }
        self.octets.truncate(rest);
    }

    /// Wipe and empty the buffer (docs/50 §4.3 step 3: "destroys the
    /// cleartext buffer").
    pub fn wipe(&mut self) {
        self.octets.zeroize();
        self.octets = Zeroizing::new(Vec::new());
    }
}

/// Why a message could not be relayed (module documentation).
/// Spec: RFC 4511 §4.1.1; [MS-ADTS] 3.1.1.3.4.6 as cited by crates/parse-ldap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameFailure {
    /// The announced size is over the framing state's bound.
    TooLarge,
    /// The stream is not LDAP (the envelope's tag or length is wrong).
    NotLdap,
    /// The message did not decode under the wire profile.
    NotDecodable,
    /// The decoded message could not be re-encoded canonically.
    NotEncodable,
}

/// One message cut from the buffer, re-encoded.
/// Spec: docs/50 §4.2, §4.3 step 1.
pub struct Framed {
    /// The canonical LDAPMessage for dird.
    pub canonical: Zeroizing<Vec<u8>>,
    /// The message is a StartTLS request (RFC 4511 §4.14.1:
    /// requestName "1.3.6.1.4.1.1466.20037").
    pub start_tls: bool,
    /// Octets follow the message in the buffer (docs/50 §4.3 step 1:
    /// `input_pending`).
    pub input_pending: bool,
}

impl fmt::Debug for Framed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Framed")
            .field("canonical_len", &self.canonical.len())
            .field("start_tls", &self.start_tls)
            .field("input_pending", &self.input_pending)
            .finish()
    }
}

/// Whether `message` is a StartTLS request.
/// Spec: RFC 4511 §4.14.1 ("The requestName is "1.3.6.1.4.1.1466.20037"").
fn is_start_tls(message: &LdapMessage) -> bool {
    matches!(
        &message.protocol_op,
        ProtocolOp::ExtendedRequest(request) if request.request_name == START_TLS_OID
    )
}

/// Cut the first LDAPMessage from `buffer` under `framing`, decode it with
/// the wire profile and re-encode it canonically (module documentation).
/// Returns `None` while the message is incomplete (read more).
///
/// # Errors
/// [`FrameFailure`] — final for the connection.
///
/// Spec: RFC 4511 §4.1.1, §5.2; docs/49 R49-16, §2.4; docs/50 §4.2, §4.3
/// step 1; A-45; A-52.
pub fn take_message(
    buffer: &mut WireBuffer,
    framing: AuthState,
) -> Result<Option<Framed>, FrameFailure> {
    let length = match frame_length(buffer.as_slice(), framing) {
        Ok(Frame::Complete { length }) => length,
        Ok(Frame::NeedMore) => return Ok(None),
        Err(Error::MessageTooLarge) => return Err(FrameFailure::TooLarge),
        Err(_) => return Err(FrameFailure::NotLdap),
    };
    let decoded = {
        let octets = buffer
            .as_slice()
            .get(..length)
            .ok_or(FrameFailure::NotLdap)?;
        decode_message(octets, &DecodeOptions::request(framing))
    };
    // The message's octets leave the buffer (and are wiped) whatever the
    // decoder said.
    buffer.consume(length);
    let message = match decoded {
        Ok(message) => message,
        Err(Error::MessageTooLarge) => return Err(FrameFailure::TooLarge),
        Err(_) => return Err(FrameFailure::NotDecodable),
    };
    let canonical = encode_message(&message).map_err(|_| FrameFailure::NotEncodable)?;
    Ok(Some(Framed {
        canonical: Zeroizing::new(canonical),
        start_tls: is_start_tls(&message),
        input_pending: !buffer.is_empty(),
    }))
}
