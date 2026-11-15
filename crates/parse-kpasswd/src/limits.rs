//! Sizes and bounds of the RFC 3244 framing.
//!
//! Every bound comes from the message layout itself — the 16-bit `message
//! length` field — or from docs/53 §5.1; none is a project guess
//! (docs/questions/Q-620 records the reading).

/// Octets of the TCP header: "a 4 octet header in network byte order that
/// precedes the message and specifies the length of the message".
/// Spec: RFC 3244 §2.
pub const TCP_HEADER_LEN: usize = 4;

/// Octets of the fixed message header: `message length` (16 bits), `protocol
/// version number` (16 bits) and `AP_REQ length` / `AP_REP length` (16 bits).
/// No message is shorter (docs/53 §5.1: "message length ≥ 6").
/// Spec: RFC 3244 §2 (request and reply message diagrams).
pub const MESSAGE_HEADER_LEN: usize = 6;

/// Largest message: the `message length` field is 16 bits and "contains the
/// number of bytes in the message including this field", so no message can be
/// longer than 65,535 octets. A TCP header announcing more is refused before
/// any allocation (docs/53 §5.1: "value 0 or > 65,535 ⇒ close before
/// allocation"; §5.9 "≤ 65,535").
/// Spec: RFC 3244 §2; docs/53 §5.1, §5.9; AGENTS.md §6.
pub const MAX_MESSAGE_LEN: usize = u16::MAX as usize;
