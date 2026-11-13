#![forbid(unsafe_code)]
//! `krb-proto`: typed Kerberos V5 messages (RFC 4120 §5) with strict DER
//! decoding and canonical DER encoding, built on this project's `parse-asn1`
//! value model.
//!
//! # Scope
//!
//! The core AS, TGS and AP exchanges and the error message:
//!
//! - basic types (RFC 4120 5.2): [`KerberosString`] / [`Realm`],
//!   [`PrincipalName`], [`KerberosTime`], [`Microseconds`] (Int32 / UInt32 are
//!   `i32` / `u32` with range checks), [`HostAddress`] / [`HostAddresses`],
//!   [`AuthorizationData`], [`PaData`], [`KerberosFlags`] with its uses
//!   [`TicketFlags`] / [`KdcOptions`] / [`ApOptions`], [`EncryptedData`],
//!   [`EncryptionKey`], [`Checksum`];
//! - AS pre-authentication (5.2.7.2, 5.2.7.5): [`PaEncTimestamp`],
//!   [`PaEncTsEnc`], [`EtypeInfo2`], [`EtypeInfo2Entry`];
//! - tickets (5.3): [`Ticket`], [`EncTicketPart`], [`TransitedEncoding`];
//! - KDC exchange (5.4): [`AsReq`], [`TgsReq`], [`KdcRequest`], [`KdcReq`],
//!   [`KdcReqBody`], [`AsRep`], [`TgsRep`], [`KdcRep`], [`EncAsRepPart`],
//!   [`EncTgsRepPart`], [`EncKdcRepPart`], [`LastReq`];
//! - AP exchange (5.5): [`ApReq`], [`Authenticator`], [`ApRep`],
//!   [`EncApRepPart`];
//! - [`KrbError`] and [`MethodData`] (5.9.1);
//! - FAST (RFC 6113 5.4): [`PaFxFastRequest`], [`KrbFastArmoredReq`],
//!   [`KrbFastArmor`], [`KrbFastReq`], [`FastOptions`], [`PaFxFastReply`],
//!   [`KrbFastArmoredRep`], [`KrbFastResponse`], [`KrbFastFinished`],
//!   [`EncryptedChallenge`]. The FAST types carry RFC 6113 extension markers
//!   but undefined components are still rejected (docs/questions/Q-032).
//!
//! Not here (later tasks): KRB-SAFE / KRB-PRIV / KRB-CRED,
//! the AD-* authorization containers, TYPED-DATA. Weak or excluded mechanisms
//! have no code path: PA-PW-SALT / ETYPE-INFO are not implemented, and no
//! encryption-type numbers are defined here (etype policy is the crypto
//! layer's). Encrypted parts stay opaque: this crate never encrypts or
//! decrypts — that is keyd's job via krb-crypto (docs/10, docs/30).
//!
//! # Strictness (fail closed)
//!
//! Every type has `decode(&[u8])` and `encode()`. Decoding accepts DER only
//! (RFC 4120 5.1.1; the BER leniency is not taken) and checks every constraint
//! RFC 4120 §5 states: the `[APPLICATION n]` tags of 5.10, explicit context
//! tags in definition order, required vs OPTIONAL components, `pvno` = 5,
//! `msg-type` consistent with the application tag, Int32 / UInt32 /
//! Microseconds ranges (5.2.4), KerberosString content (5.2.1), KerberosTime
//! with no fractional seconds and a valid UTC calendar date-time (5.2.3), and
//! KerberosFlags of exactly 32 bits (5.2.8). Each violation is a distinct
//! [`Error`]; decoding never panics. Input size and every attacker-sized
//! SEQUENCE OF are bounded ([`limits`]). Encoding refuses values this crate
//! would not decode, and decoding is lossless, so
//! `decode(encode(x)) == x` and `encode(decode(b)) == b`.
//!
//! # Extensibility and unknown elements
//!
//! - **Typed holes are preserved, never rejected.** RFC 4120 1.5 defines
//!   extension as "defining a new type to insert into an existing typed hole",
//!   and 1.5.1 says recipients "SHOULD preserve the encoding of the extension"
//!   and "MUST NOT decline a request simply because an extension is present".
//!   So padata-type / padata-value, ad-type / ad-data, etype, addr-type,
//!   tr-type, name-type, error-code and e-data are carried as raw integers and
//!   octets, whatever their value.
//! - **Unknown authorization data is preserved for the consumer to judge.**
//!   The 1.5.1 / 5.2.6 rule that an application server MUST fail on an unknown
//!   ad-type (and a TGS must reject unknown types in AD-MANDATORY-FOR-KDC)
//!   needs knowledge of which types are understood; it belongs to the AP / TGS
//!   logic, not to this codec.
//! - **Unknown fields are rejected.** 1.5 states that "extension" does not mean
//!   adding fields to ASN.1 types, 1.5.1 that message formats "cannot readily
//!   be extended by adding fields", and the Appendix A module has no extension
//!   marker. A context tag a type does not define is [`Error::UnknownField`];
//!   an unrecognized application tag (including numbers above 30) is
//!   [`Error::UnexpectedApplicationTag`] — 5.1.4 / 5.1.5 ask for an error to be
//!   returned.
//! - **Empty OPTIONAL SEQUENCE OF (5.1.3)** is accepted, as the RFC asks, and
//!   preserved as `Some(empty)` so re-encoding is exact; consumers treat it
//!   the same as absent.
//! - Where RFC 4120 offers leniency ("MAY accept"), it is not taken: BER
//!   (5.1.1), non-IA5 GeneralString characters (5.2.1, 5.2.7.5), fewer than
//!   32 flag bits (5.2.8), negative sequence numbers (5.5.1), and the relaxed
//!   EncASRepPart / EncTGSRepPart tag check (5.4.2).
//!
//! # Secrets
//!
//! [`EncryptionKey`]`.keyvalue` is a [`KeyValue`]: held in a RustCrypto
//! `zeroize::Zeroizing` buffer (wiped on drop), redacted in `Debug`, never put
//! in an error (no [`Error`] variant carries input content). Types that carry
//! a key ([`EncryptionKey`], [`EncTicketPart`], [`EncAsRepPart`],
//! [`EncTgsRepPart`], [`Authenticator`], [`EncApRepPart`],
//! [`KrbFastResponse`]) scrub the
//! intermediate `parse-asn1` value tree on decode and encode, and return their
//! encoding in a `Zeroizing<Vec<u8>>`. Residual: transient buffers allocated
//! inside `parse-asn1` while encoding (and the caller's own input buffer) are
//! outside this crate's control.
//!
//! # Naming
//!
//! Types and fields use RFC 4120's names (AGENTS.md §4.4), transliterated to
//! Rust: hyphens are dropped from type names, which are written in CamelCase
//! (`KDC-REQ-BODY` → `KdcReqBody`, `EncASRepPart` → `EncAsRepPart`,
//! `PA-DATA` → `PaData`), and become underscores in field names
//! (`renew-till` → `renew_till`). The inner SEQUENCE of AuthorizationData is
//! named [`AuthorizationElement`] after RFC 4120 5.2.6's "authorization
//! element"; the anonymous LastReq element is [`LastReqEntry`].
//!
//! # Provenance
//!
//! Written only from the allowed specifications, opened in-session
//! (AGENTS.md §1-3): RFC 4120 (§1.5, §5, §6.2, §7.5, Appendix A), ITU-T X.680
//! (02/2021) clauses 22 and 46 and Table 8, ITU-T X.690 (02/2021) clauses
//! 8.6, 8.9, 8.10, 8.13, 8.14 and 11.7, and RFC 6113 (§5.2, §5.4, §6, §7,
//! Appendix B) for FAST. No other implementation was consulted or recalled.
//!
//! Spec: RFC 4120 §5, Appendix A; RFC 6113 §5.4, Appendix B.

#[macro_use]
mod macros;

mod ap;
mod basic;
pub mod constants;
mod der;
mod error;
mod fast;
mod flags;
mod kdc;
mod krb_error;
pub mod limits;
mod preauth;
mod ticket;

pub use ap::{ApRep, ApReq, Authenticator, EncApRepPart};
pub use basic::{
    AuthorizationData, AuthorizationElement, Checksum, EncryptedData, EncryptionKey, HostAddress,
    HostAddresses, KerberosString, KerberosTime, KeyValue, Microseconds, PaData, PrincipalName,
    Realm,
};
pub use error::{Error, Result};
pub use fast::{
    EncryptedChallenge, KrbFastArmor, KrbFastArmoredRep, KrbFastArmoredReq, KrbFastFinished,
    KrbFastReq, KrbFastResponse, PaFxFastReply, PaFxFastRequest,
};
pub use flags::{ApOptions, FastOptions, KdcOptions, KerberosFlags, TicketFlags};
pub use kdc::{
    AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcRep, KdcReq, KdcReqBody,
    KdcRequest, LastReq, LastReqEntry, TgsRep, TgsReq,
};
pub use krb_error::{KrbError, MethodData};
pub use preauth::{EtypeInfo2, EtypeInfo2Entry, PaEncTimestamp, PaEncTsEnc};
pub use ticket::{EncTicketPart, Ticket, TransitedEncoding};
