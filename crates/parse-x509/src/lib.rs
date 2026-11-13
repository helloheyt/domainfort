#![forbid(unsafe_code)]
//! `parse-x509`: a strict, bounded reader of the X.509 v3 certificate of
//! RFC 5280 §4.1 (docs/questions/Q-320; Q-285 items 1 and 3; A-71).
//!
//! # What it reads
//!
//! [`parse_certificate`] walks `Certificate` → `tbsCertificate`,
//! `signatureAlgorithm`, `signatureValue`, and inside `tbsCertificate`:
//! `version` (v3 only), `serialNumber`, `signature`, `issuer`, `validity`,
//! `subject`, `subjectPublicKeyInfo`, the optional unique identifiers and
//! `extensions`. It returns the [`AlgorithmIdentifier`]s, the SPKI and the
//! signed `tbsCertificate` as **octets** — this crate interprets no
//! algorithm and verifies no signature; the caller compares the octets with
//! constants it trusts (ldap-front uses rustls-pki-types' documented
//! `alg_id` constants) — and the validity as [`Time`] values.
//!
//! # Strictness (fail closed, AGENTS.md §6)
//!
//! * DER only: every identifier and length is read by parse-asn1's
//!   `split_element` (definite, minimal); INTEGER, OBJECT IDENTIFIER,
//!   BOOLEAN, BIT STRING and GeneralizedTime contents by its value decoder
//!   (X.690 8, 10, 11); a DEFAULT component encoded with its default value
//!   is refused (X.690 11.5); SET OF order is checked in names (X.690 11.6).
//! * The RFC 5280 profile where it is exact: v3 only (§4.1.2.1 — what this
//!   project issues and accepts), a non-empty issuer (§4.1.2.4), a
//!   serialNumber of at most 20 octets (§4.1.2.2), Time in exactly
//!   `YYMMDDHHMMSSZ` / `YYYYMMDDHHMMSSZ` (§4.1.2.5.1, §4.1.2.5.2, with
//!   GeneralizedTime only from 2050), at least one extension when the field
//!   is present and none twice (§4.1, §4.2).
//! * Bounded: [`MAX_CERTIFICATE_OCTETS`] of input, [`MAX_EXTENSIONS`],
//!   [`MAX_NAME_RDNS`], [`MAX_RDN_ATTRIBUTES`]; no recursion (the structure
//!   is walked field by field); no allocation from an attacker-supplied
//!   length.
//! * Errors ([`Error`]) name a field and a rule, never input octets.
//!
//! # Not here (callers' or later work)
//!
//! Signature verification, path validation (RFC 5280 §6), name
//! comparison, and the meaning of each extension (§4.2.1): the extensions
//! are returned uninterpreted, with their `critical` flag.
//!
//! # Provenance
//!
//! Written only from the allowed specifications, opened in-session from
//! tools/spec-pin/cache with their SHA-256 verified against
//! tools/spec-pin/manifest.json: RFC 5280 (a2f2628c…345d) §4.1, §4.1.1.1-
//! §4.1.1.3, §4.1.2.1-§4.1.2.9, §4.2, §4.2.1.1-§4.2.1.3, §4.2.1.6, §4.2.1.9,
//! §4.2.1.12, Appendix A.1 / A.2; ITU-T X.690 02/2021 (6ac799a2…bd6c) 8.1,
//! 8.6, 8.14, 10.1, 10.2, 11.1, 11.2, 11.5-11.8; ITU-T X.680 02/2021
//! (b69dc475…ee14) Table 1, Table 8, 46, 47 — and the public API of this
//! workspace's parse-asn1. No other implementation consulted or recalled
//! (AGENTS.md §1-3).
//!
//! Spec: RFC 5280 4.1, 4.1.1, 4.1.2, 4.2; X.690 8, 10, 11; X.680 Table 1.

mod certificate;
mod error;
mod time;

pub use certificate::{
    parse_certificate, AlgorithmIdentifier, Certificate, Extension, SubjectPublicKeyInfo,
    TbsCertificate, Validity, MAX_CERTIFICATE_OCTETS, MAX_EXTENSIONS, MAX_NAME_RDNS,
    MAX_RDN_ATTRIBUTES, MAX_SERIAL_NUMBER_OCTETS,
};
pub use error::{Error, Field};
pub use time::Time;
