//! Sizes and bounds of the tokens this crate reads and writes.
//!
//! Fixed sizes come from the token layouts themselves (RFC 4121 §4.1.1,
//! §4.2.6.2). The two upper bounds are project choices recorded in docs/60
//! R60-11 (AGENTS.md §6: every parser is bounded; the specifications set no
//! maximum — RFC 4121 §5.2 only sets minimum buffer sizes an implementation
//! must accept for per-message calls).

/// Largest context-establishment token, framing included, that this crate
/// decodes or encodes: 64 KiB.
///
/// docs/60 R60-11: the initial context token is at most `MAX_PREAUTH_PDU`
/// (64 KiB) — the bound of an LDAP message on an unauthenticated session
/// (docs/49 §2.4, anchored on [MS-ADTS] 3.1.1.3.4.6 MaxPreAuthReceiveBuffer,
/// stricter), inside which the token arrives as the SASL credentials of one
/// BindRequest ("SASL credentials within `MAX_PREAUTH_PDU`", docs/49 §2.4).
/// The whole token is bounded, so the inner token (TOK_ID and Kerberos
/// message) is shorter still. Checked before any other octet is read; a token
/// this crate encodes never exceeds it either.
///
/// Spec: docs/60 R60-11, §3.3; docs/49 §2.4; AGENTS.md §6.
pub const MAX_CONTEXT_TOKEN_LEN: usize = 64 * 1024;

/// Largest Wrap token this crate parses or builds: 1 KiB.
///
/// docs/60 R60-11: the client's selection token is at most 1 KiB (it carries
/// the 4-octet selection and an authorization identity of at most 256 octets,
/// plus the 16-octet header and the checksum); the server's offer (16-octet
/// header, 4 octets of data, the checksum) is far smaller. Checked before the
/// rotation is undone, so the one allocation of a received token is bounded by
/// it.
///
/// Spec: docs/60 R60-11, §3.4; RFC 4752 §3.2, §3.3; AGENTS.md §6.
pub const MAX_WRAP_TOKEN_LEN: usize = 1024;

/// Octets of the Wrap token header: octets 0..15 (TOK_ID, Flags, Filler, EC,
/// RRC, SND_SEQ). Spec: RFC 4121 §4.2.6.2.
pub const WRAP_HEADER_LEN: usize = 16;

/// Smallest authenticator checksum field: "at least 24 octets when
/// GSS_C_DELEG_FLAG is not set" (Lgth 4 + Bnd 16 + Flags 4). Delegation is
/// refused (docs/60 §3.4 step 4), so this is the only minimum that applies.
/// Spec: RFC 4121 §4.1.1.
pub const AUTHENTICATOR_CHECKSUM_MIN_LEN: usize = 24;

/// Octets of the `Bnd` field: the `Lgth` field "Currently contains hex value
/// 10 00 00 00 (16)". Spec: RFC 4121 §4.1.1.
pub const BND_LEN: usize = 16;
