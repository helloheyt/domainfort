#![forbid(unsafe_code)]
//! `gss-token`: the token framing of the Kerberos V5 GSS-API mechanism for
//! the LDAP SASL GSSAPI bind — strict, bounded, and without cryptography
//! (docs/60 §3.3, §3.4, §10 task LG1; decision A-193; docs/questions/Q-1093,
//! Q-1098 item 3).
//!
//! keyd links this crate (task LK1) to read the client's initial context
//! token and selection Wrap token and to frame its AP-REP token and offer Wrap
//! token; every key, checksum and comparison stays in keyd. This crate has no
//! dependency at all (`tests/no_crypto_dependency.rs`).
//!
//! # Scope
//!
//! * [`ContextEstablishmentToken`] — RFC 2743 §3.1 framing (0x60, minimum-
//!   octet lengths, OID tag 0x06, the exact Kerberos V5 mechanism OID of
//!   [MS-KILE] 1.9.1, no trailing octets) with the RFC 4121 §4.1 [`TokId`]
//!   (KRB_AP_REQ 01 00, KRB_AP_REP 02 00; KRB_ERROR is never produced —
//!   docs/60 R60-8). Strict decode and canonical encode.
//! * [`AuthenticatorChecksum`] — the RFC 4121 §4.1.1 checksum (type 0x8003):
//!   `Lgth` = 16, the 16-octet [`Bnd`] kept opaque, the [`ContextFlags`]
//!   judged by the profile, Exts skipped; plus the Authenticator's mandatory
//!   `seq-number`.
//! * [`WrapHeader`], [`ReceivedWrapToken`], [`OutgoingWrapToken`] — the RFC
//!   4121 §4.2.6.2 Wrap token without confidentiality (Sealed refused, never
//!   produced), the direction flag and AcceptorSubkey checked against the
//!   caller's [`WrapExpectation`], the §4.2.5 rotation undone on receipt, and
//!   the octet ranges the caller must MAC laid out.
//!
//! # Strictness (fail closed)
//!
//! Every refusal is a distinct [`Error`] that carries no input octet;
//! nothing panics. Sizes are bounded before any work: a context token by
//! [`MAX_CONTEXT_TOKEN_LEN`] (64 KiB — docs/60 R60-11, `MAX_PREAUTH_PDU`), a
//! Wrap token by [`MAX_WRAP_TOKEN_LEN`] (1 KiB — docs/60 R60-11). Decoding a
//! context token borrows and allocates nothing; a received Wrap token
//! allocates one buffer of at most its own length plus 16 octets. The profile
//! choices are the strict defaults of Q-1093 (A-193): each refuses in doubt.
//!
//! # Provenance
//!
//! Written only from the allowed specifications, opened in this session from
//! the pinned cache with their SHA-256 checked against
//! `tools/spec-pin/manifest.json` (AGENTS.md §1-3):
//!
//! * RFC 2743 (`59ca50ca…494f3600`) §1.1.6, §3.1;
//! * RFC 4121 (`2bdacc59…086fbe8f`) read in full — cited §2, §4.1, §4.1.1,
//!   §4.1.1.1, §4.1.1.2, §4.2.1–§4.2.6.2, §4.4, §5.2, §6;
//! * RFC 4752 (`3a53db51…c71bd48d`) §3, §3.1, §3.2, §3.3;
//! * RFC 4120 (`368d3cd1…6463f75b`) §5.5.1 (the Authenticator's `cksum` and
//!   `seq-number`);
//! * [MS-KILE] v20261110 (`58b84892…d3a4e3c7`) 1.9.1, 3.1.1.7, 3.4.5.4.1;
//!
//! and the project's docs/60 (§3, §9, §10, §10.1), docs/49 §2.4 and
//! docs/questions/Q-1093 / Q-1098 (A-193). No other implementation was
//! consulted or recalled. The specifications carry no token test vectors
//! (docs/60 §10.1): the tests build tokens from the layouts, use the rotation
//! example of RFC 4121 §4.2.5, and read observed Wrap headers from the lab
//! capture `interop/captures/L1L2-join.pcapng`.
//!
//! Spec: RFC 2743 §3.1; RFC 4121 §4.1, §4.1.1, §4.2.6.2; docs/60 §10 LG1.

mod checksum;
mod error;
mod framing;
pub mod limits;
mod oid;
mod wrap;

pub use checksum::{
    AuthenticatorChecksum, Bnd, ChecksumField, ContextFlags, GSS_CHECKSUM_TYPE, GSS_C_CONF_FLAG,
    GSS_C_DELEG_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG,
};
pub use error::{Error, Result};
pub use framing::{ContextEstablishmentToken, TokId, OID_TAG, TOKEN_TAG};
pub use limits::{
    AUTHENTICATOR_CHECKSUM_MIN_LEN, BND_LEN, MAX_CONTEXT_TOKEN_LEN, MAX_WRAP_TOKEN_LEN,
    WRAP_HEADER_LEN,
};
pub use oid::{
    KERBEROS_V5_MECHANISM_ARCS, KERBEROS_V5_MECHANISM_OID_OCTETS, TRUNCATED_KERBEROS_OID_ARCS,
    TRUNCATED_KERBEROS_OID_OCTETS,
};
pub use wrap::{
    OutgoingWrapToken, ReceivedWrapToken, Sender, WrapExpectation, WrapHeader,
    FLAG_ACCEPTOR_SUBKEY, FLAG_SEALED, FLAG_SENT_BY_ACCEPTOR, WRAP_FILLER, WRAP_TOK_ID,
};
