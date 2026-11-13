//! Pre-authentication data types used by the AS exchange.
//!
//! Spec: RFC 4120 5.2.7.2 (PA-ENC-TIMESTAMP / PA-ENC-TS-ENC), 5.2.7.5
//! (ETYPE-INFO2 / ETYPE-INFO2-ENTRY); Appendix A ("preauth stuff").
//! PA-PW-SALT and ETYPE-INFO (5.2.7.3, 5.2.7.4) are deliberately not
//! implemented: a KDC "MUST NOT send" them when the AS-REQ includes a "newer"
//! etype (RFC 4120 5.2.7.4, 5.2.7.5), and this project's KDC is AES-only.

use crate::basic::{EncryptedData, KerberosString, KerberosTime, Microseconds};
use crate::der::{self, ctx, octet_string, octets, Fields};
use crate::error::{Error, Result};
use crate::limits::MAX_ETYPE_INFO2_ENTRIES;
use parse_asn1::Value;

/// `PA-ENC-TIMESTAMP ::= EncryptedData -- PA-ENC-TS-ENC`.
///
/// The cipher is the encryption (key usage 1, client's key) of a DER-encoded
/// [`PaEncTsEnc`]; this crate never decrypts it.
///
/// Spec: RFC 4120 5.2.7.2, 7.5.1 (key usage 1); Appendix A.
pub type PaEncTimestamp = EncryptedData;

/// ```text
/// PA-ENC-TS-ENC           ::= SEQUENCE {
///         patimestamp     [0] KerberosTime -- client's time --,
///         pausec          [1] Microseconds OPTIONAL
/// }
/// ```
///
/// Spec: RFC 4120 5.2.7.2; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaEncTsEnc {
    /// `patimestamp [0] KerberosTime`.
    pub patimestamp: KerberosTime,
    /// `pausec [1] Microseconds OPTIONAL`.
    pub pausec: Option<Microseconds>,
}

impl PaEncTsEnc {
    const TAGS: &'static [u32] = &[0, 1];

    /// Spec: RFC 4120 5.2.7.2.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let patimestamp = KerberosTime::from_value(f.required(0)?)?;
        let pausec = f.optional(1).map(der::microseconds).transpose()?;
        f.finish()?;
        Ok(PaEncTsEnc {
            patimestamp,
            pausec,
        })
    }

    /// Spec: RFC 4120 5.2.7.2.
    pub(crate) fn to_value(&self) -> Result<Value> {
        let mut items = vec![ctx(0, self.patimestamp.to_value())];
        if let Some(pausec) = self.pausec {
            items.push(ctx(1, pausec.to_value()));
        }
        Ok(Value::Sequence(items))
    }
}

der_codec!(PaEncTsEnc, "PA-ENC-TS-ENC");

/// ```text
/// ETYPE-INFO2-ENTRY       ::= SEQUENCE {
///         etype           [0] Int32,
///         salt            [1] KerberosString OPTIONAL,
///         s2kparams       [2] OCTET STRING OPTIONAL
/// }
/// ```
///
/// `salt` is a KerberosString; the 5.2.7.5 option to handle locale-specific
/// (non-IA5) salt characters is not taken (fail closed, see
/// [`KerberosString`]). `s2kparams` is opaque here (its meaning is defined by
/// the etype's cryptosystem).
///
/// Spec: RFC 4120 5.2.7.5; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EtypeInfo2Entry {
    /// `etype [0] Int32`.
    pub etype: i32,
    /// `salt [1] KerberosString OPTIONAL`.
    pub salt: Option<KerberosString>,
    /// `s2kparams [2] OCTET STRING OPTIONAL`.
    pub s2kparams: Option<Vec<u8>>,
}

impl EtypeInfo2Entry {
    const TAGS: &'static [u32] = &[0, 1, 2];

    /// Spec: RFC 4120 5.2.7.5.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let etype = der::int32(f.required(0)?)?;
        let salt = f.optional(1).map(KerberosString::from_value).transpose()?;
        let s2kparams = f
            .optional(2)
            .map(|v| octet_string(v).map(<[u8]>::to_vec))
            .transpose()?;
        f.finish()?;
        Ok(EtypeInfo2Entry {
            etype,
            salt,
            s2kparams,
        })
    }

    /// Spec: RFC 4120 5.2.7.5.
    pub(crate) fn to_value(&self) -> Result<Value> {
        let mut items = vec![ctx(0, der::int(self.etype.into()))];
        if let Some(salt) = &self.salt {
            items.push(ctx(1, salt.to_value()));
        }
        if let Some(s2kparams) = &self.s2kparams {
            items.push(ctx(2, octets(s2kparams)));
        }
        Ok(Value::Sequence(items))
    }
}

der_codec!(EtypeInfo2Entry, "ETYPE-INFO2-ENTRY");

/// `ETYPE-INFO2 ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY`.
///
/// Must hold at least one entry ([`Error::EmptySequenceOf`] otherwise) and at
/// most [`crate::limits::MAX_ETYPE_INFO2_ENTRIES`]. (When sent in an AS-REP
/// there "shall be exactly one" entry matching the enc-part etype — a check for
/// the AS exchange logic, which knows the context.)
///
/// Spec: RFC 4120 5.2.7.5; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EtypeInfo2(pub Vec<EtypeInfo2Entry>);

impl EtypeInfo2 {
    /// Spec: RFC 4120 5.2.7.5 (`SIZE (1..MAX)`).
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let entries =
            der::decode_sequence_of(value, MAX_ETYPE_INFO2_ENTRIES, EtypeInfo2Entry::from_value)?;
        if entries.is_empty() {
            return Err(Error::EmptySequenceOf);
        }
        Ok(EtypeInfo2(entries))
    }

    /// Spec: RFC 4120 5.2.7.5 (`SIZE (1..MAX)`).
    pub(crate) fn to_value(&self) -> Result<Value> {
        if self.0.is_empty() {
            return Err(Error::EmptySequenceOf);
        }
        der::encode_sequence_of(&self.0, MAX_ETYPE_INFO2_ENTRIES, EtypeInfo2Entry::to_value)
    }
}

der_codec!(EtypeInfo2, "ETYPE-INFO2");
