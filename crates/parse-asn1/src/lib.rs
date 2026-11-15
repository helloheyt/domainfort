#![forbid(unsafe_code)]
//! `parse-asn1`: a strict DER decoder and a canonical DER encoder for the ASN.1
//! subset that Kerberos uses.
//!
//! # Scope
//!
//! Only the types RFC 4120 §5 relies on are implemented (docs/45 §3): BOOLEAN,
//! INTEGER, ENUMERATED, BIT STRING, OCTET STRING, OBJECT IDENTIFIER,
//! GeneralString, GeneralizedTime, SEQUENCE / SEQUENCE OF, SET OF, explicit
//! context tags `[n]`, and explicit `[APPLICATION n]` tags. Kerberos uses
//! `DEFINITIONS EXPLICIT TAGS` (RFC 4120 §5), so context and application tags
//! are always the constructed, explicit form.
//!
//! # Strictness
//!
//! Decoding accepts the Distinguished Encoding Rules form only and nothing else:
//! definite lengths encoded in the minimum octets, primitive encodings where DER
//! requires them, BOOLEAN TRUE as `0xFF`, canonical SET OF ordering, minimal
//! INTEGER / OBJECT IDENTIFIER / tag-number encodings, and no trailing data.
//! Every deviation is a distinct [`Error`] — the decoder never panics, never
//! loops unbounded, and never allocates from an attacker-controlled length
//! without first bounding it against the input (docs/CLEAN-ROOM.md; docs/32 §8).
//! Nesting is capped at [`MAX_DEPTH`]. The encoder refuses to emit a
//! non-canonical value, so `encode(decode(x)) == x` for canonical input and
//! `decode(encode(v)) == v`.
//!
//! # Element level
//!
//! [`split_element`] and [`encode_element`] work one level below the value
//! model: one tag-length-value unit with strict DER identifier and length
//! octets, its contents left to the caller. They exist for structures the
//! Kerberos value model does not cover — the X.509 certificate of RFC 5280
//! (crates/parse-x509), with its implicit tags, UTCTime and character
//! string types — so that every DER header in the workspace is read and
//! written by the one implementation here. They add no behaviour to
//! [`decode`] / [`encode`].
//!
//! # Provenance
//!
//! Written only from the allowed specifications, opened in-session (docs/CLEAN-ROOM.md
//! §1-3): ITU-T X.690 (02/2021) — BER/CER/DER encoding rules; ITU-T X.680
//! (02/2021) — ASN.1 types and the universal class tag assignments; and
//! RFC 4120 §5 — the Kerberos ASN.1 module (the subset to implement). No other
//! implementation was consulted or recalled.
//!
//! Spec: X.690 (02/2021) clauses 8, 10, 11; X.680 (02/2021) Table 1, 46.3;
//! RFC 4120 §5.

mod decode;
mod encode;
mod error;
mod types;

pub use decode::{decode, split_element, Element};
pub use encode::{encode, encode_element};
pub use error::{Error, Result};
pub use types::{Tag, TagClass, Value, MAX_DEPTH};
