//! TCP stream framing: find where one LDAPMessage ends.
//!
//! "The encoded LDAPMessage PDUs are mapped directly onto the TCP bytestream"
//! (RFC 4511 §5.2): each message is one SEQUENCE element, and the next begins
//! immediately after it. The framer reads only the identifier and length
//! octets of the outer LDAPMessage, compares the announced size with the bound
//! for the session's authentication state **before any allocation or wait for
//! contents** (docs/49 §2.4; AGENTS.md §6), and only then reports whether the
//! whole message is present.
//!
//! Lengths follow the wire profile (A-45): definite only, at most
//! [`crate::MAX_LENGTH_OCTETS`] long-form octets, non-minimal accepted.

use crate::ber::{check_identifier, parse_length, tag_of, LengthOctets, Profile, SEQUENCE};
use crate::error::{Error, Result};
use crate::limits::AuthState;

/// What the framer found at the start of the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    /// One whole LDAPMessage occupies the first `length` octets.
    Complete { length: usize },
    /// The buffer holds the start of a message (possibly nothing); read more.
    NeedMore,
}

/// Locate the first LDAPMessage in `buffer`.
///
/// Errors are final for the connection: [`Error::MessageTooLarge`] means drop
/// it ([MS-ADTS] 3.1.1.3.4.6); any other error means the stream is not LDAP
/// (RFC 4511 §4.1.1: "the LDAPMessage SEQUENCE tag cannot be recognized ... or
/// the encoding structures or lengths ... are found to be incorrect").
///
/// Spec: RFC 4511 §4.1.1, §5.1, §5.2; X.690 8.1.2–8.1.3; A-45; docs/49 §2.4.
pub fn frame_length(buffer: &[u8], auth: AuthState) -> Result<Frame> {
    let Some((&identifier, rest)) = buffer.split_first() else {
        return Ok(Frame::NeedMore);
    };
    check_identifier(identifier)?;
    // "LDAPMessage ::= SEQUENCE". Spec: RFC 4511 §4.1.1; X.690 8.9.1.
    if identifier != SEQUENCE {
        return Err(if tag_of(identifier) == tag_of(SEQUENCE) {
            Error::PrimitiveConstructedMismatch
        } else {
            Error::UnexpectedTag
        });
    }
    let (length, octets) = match parse_length(rest, Profile::Wire)? {
        LengthOctets::Complete { length, octets } => (length, octets),
        LengthOctets::Incomplete => return Ok(Frame::NeedMore),
    };
    let total = length
        .checked_add(octets)
        .and_then(|n| n.checked_add(1))
        .ok_or(Error::MessageTooLarge)?;
    // The bound applies to the announced size, before waiting for contents.
    if total > auth.max_message_octets() {
        return Err(Error::MessageTooLarge);
    }
    if buffer.len() >= total {
        Ok(Frame::Complete { length: total })
    } else {
        Ok(Frame::NeedMore)
    }
}
