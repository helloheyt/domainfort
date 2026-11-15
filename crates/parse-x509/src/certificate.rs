//! The certificate reader: RFC 5280 §4.1, walked field by field over
//! parse-asn1's strict DER element reader.
//!
//! The structure is fixed, so the walk is not recursive: Certificate →
//! TBSCertificate → Name → RelativeDistinguishedName → AttributeTypeAndValue
//! is the deepest path, and parse-asn1's value decoder is only ever handed
//! one primitive element (INTEGER, OBJECT IDENTIFIER, BOOLEAN, BIT STRING,
//! GeneralizedTime). Every length is bounded against the input by
//! `split_element` before it is used; the only allocations are the
//! extension list (at most [`MAX_EXTENSIONS`] entries) and the bounded
//! copies parse-asn1's decoder makes of a primitive's contents.

use crate::error::{Error, Field};
use crate::time::Time;
use core::cmp::Ordering;
use parse_asn1::{decode, encode_element, split_element, Element, Tag, TagClass, Value};

/// Most octets a certificate may have. Resource bound (docs/CLEAN-ROOM.md), the
/// same value as ldap-front's certificate-file bound (one DER certificate is
/// a few hundred octets to a few KiB). Project choice.
pub const MAX_CERTIFICATE_OCTETS: usize = 64 * 1024;

/// Most contents octets of `serialNumber`.
/// Spec: RFC 5280 4.1.2.2 ("Conforming CAs MUST NOT use serialNumber values
/// longer than 20 octets").
pub const MAX_SERIAL_NUMBER_OCTETS: usize = 20;

/// Most extensions. Resource bound (project choice): RFC 5280 §4.2.1 defines
/// sixteen certificate extensions and forbids repeating one (§4.2).
pub const MAX_EXTENSIONS: usize = 32;

/// Most RelativeDistinguishedNames in one Name. Resource bound (project
/// choice; RFC 5280 §4.1.2.4 lists fourteen standard attribute types).
pub const MAX_NAME_RDNS: usize = 32;

/// Most AttributeTypeAndValue in one RelativeDistinguishedName. Resource
/// bound (project choice).
pub const MAX_RDN_ATTRIBUTES: usize = 8;

// Universal class tag numbers. Spec: X.680 Table 1.
/// BOOLEAN. Spec: X.680 Table 1 (UNIVERSAL 1).
const BOOLEAN: u32 = 1;
/// INTEGER. Spec: X.680 Table 1 (UNIVERSAL 2).
const INTEGER: u32 = 2;
/// BIT STRING. Spec: X.680 Table 1 (UNIVERSAL 3).
const BIT_STRING: u32 = 3;
/// OCTET STRING. Spec: X.680 Table 1 (UNIVERSAL 4).
const OCTET_STRING: u32 = 4;
/// OBJECT IDENTIFIER. Spec: X.680 Table 1 (UNIVERSAL 6).
const OBJECT_IDENTIFIER: u32 = 6;
/// SEQUENCE / SEQUENCE OF. Spec: X.680 Table 1 (UNIVERSAL 16).
const SEQUENCE: u32 = 16;
/// SET / SET OF. Spec: X.680 Table 1 (UNIVERSAL 17).
const SET: u32 = 17;
/// UTCTime. Spec: X.680 Table 1 (UNIVERSAL 23), 47.3.
const UTC_TIME: u32 = 23;
/// GeneralizedTime. Spec: X.680 Table 1 (UNIVERSAL 24), 46.3.
const GENERALIZED_TIME: u32 = 24;

// The context-specific tags of TBSCertificate. Spec: RFC 5280 4.1.
/// `version [0] EXPLICIT`. Spec: RFC 5280 4.1.
const VERSION: u32 = 0;
/// `issuerUniqueID [1] IMPLICIT`. Spec: RFC 5280 4.1.
const ISSUER_UNIQUE_ID: u32 = 1;
/// `subjectUniqueID [2] IMPLICIT`. Spec: RFC 5280 4.1.
const SUBJECT_UNIQUE_ID: u32 = 2;
/// `extensions [3] EXPLICIT`. Spec: RFC 5280 4.1.
const EXTENSIONS: u32 = 3;

/// The Version value v3. Spec: RFC 5280 4.1 (`Version ::= INTEGER { v1(0),
/// v2(1), v3(2) }`), 4.1.2.1 ("When extensions are used … version MUST be
/// 3 (value is 2)").
const VERSION_V3: i64 = 2;

/// A universal-class tag. Primitive types are primitive in DER (X.690 10.2,
/// 8.1.2.5); SEQUENCE and SET are constructed (X.690 8.9.1, 8.11.1).
const fn universal(number: u32, constructed: bool) -> Tag {
    Tag {
        class: TagClass::Universal,
        constructed,
        number,
    }
}

/// A context-specific tag: constructed when EXPLICIT (X.690 8.14.3), the
/// base encoding's form when IMPLICIT (X.690 8.14.4).
const fn context(number: u32, constructed: bool) -> Tag {
    Tag {
        class: TagClass::ContextSpecific,
        constructed,
        number,
    }
}

/// An `AlgorithmIdentifier`, as octets (its meaning is the caller's).
/// Spec: RFC 5280 4.1.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmIdentifier<'a> {
    /// The complete DER encoding, the SEQUENCE header included.
    pub encoding: &'a [u8],
    /// The contents of the SEQUENCE: the `algorithm` OBJECT IDENTIFIER's
    /// encoding followed by the `parameters` encoding, if any.
    pub contents: &'a [u8],
    /// The `algorithm` OBJECT IDENTIFIER's complete encoding.
    pub algorithm: &'a [u8],
    /// The `parameters` element's complete encoding, if present.
    pub parameters: Option<&'a [u8]>,
}

/// `SubjectPublicKeyInfo`. Spec: RFC 5280 4.1, 4.1.2.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubjectPublicKeyInfo<'a> {
    /// The complete DER encoding.
    pub encoding: &'a [u8],
    /// `algorithm`.
    pub algorithm: AlgorithmIdentifier<'a>,
    /// `subjectPublicKey`: the BIT STRING's data octets (no unused bits).
    pub subject_public_key: &'a [u8],
}

/// `Validity`. Spec: RFC 5280 4.1.2.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// `notBefore`.
    pub not_before: Time,
    /// `notAfter`.
    pub not_after: Time,
}

impl Validity {
    /// Whether the instant `unix_seconds` lies in the validity period.
    /// Spec: RFC 5280 4.1.2.5 ("the period of time from notBefore through
    /// notAfter, inclusive").
    #[must_use]
    pub fn contains(&self, unix_seconds: i64) -> bool {
        self.not_before.unix_seconds() <= unix_seconds
            && unix_seconds <= self.not_after.unix_seconds()
    }
}

/// One `Extension`, uninterpreted. Spec: RFC 5280 4.1, 4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extension<'a> {
    /// `extnID`: the OBJECT IDENTIFIER's complete encoding.
    pub extn_id: &'a [u8],
    /// `critical` (FALSE when absent, its DEFAULT).
    pub critical: bool,
    /// `extnValue`: the OCTET STRING's contents (the DER encoding of the
    /// extension's own value).
    pub extn_value: &'a [u8],
}

/// `TBSCertificate`, version 3. Spec: RFC 5280 4.1, 4.1.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TbsCertificate<'a> {
    /// The complete DER encoding — the octets the signature covers
    /// (RFC 5280 4.1.1.3).
    pub encoding: &'a [u8],
    /// `serialNumber`: the INTEGER's contents octets.
    pub serial_number: &'a [u8],
    /// `signature`.
    pub signature: AlgorithmIdentifier<'a>,
    /// `issuer`: the Name's complete encoding (structure checked, never
    /// empty).
    pub issuer: &'a [u8],
    /// `validity`.
    pub validity: Validity,
    /// `subject`: the Name's complete encoding (structure checked; may be
    /// the empty sequence, RFC 5280 4.1.2.6).
    pub subject: &'a [u8],
    /// `subjectPublicKeyInfo`.
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    /// `extensions`, in certificate order (empty when absent).
    pub extensions: Vec<Extension<'a>>,
}

/// A parsed `Certificate`. Spec: RFC 5280 4.1, 4.1.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate<'a> {
    /// The complete DER encoding (the whole input).
    pub encoding: &'a [u8],
    /// `tbsCertificate`.
    pub tbs_certificate: TbsCertificate<'a>,
    /// `signatureAlgorithm` (outer).
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    /// `signatureValue`: the BIT STRING's data octets (no unused bits).
    pub signature_value: &'a [u8],
}

/// Read exactly one X.509 v3 certificate from `input` (no trailing octet).
/// Nothing is verified cryptographically and no algorithm is interpreted
/// (the caller compares [`AlgorithmIdentifier`] octets with what it trusts).
///
/// # Errors
/// [`Error`] — the first rule broken.
///
/// Spec: RFC 5280 4.1, 4.1.1.1-4.1.1.3, 4.1.2.1-4.1.2.9, 4.2; X.690 8, 10,
/// 11.
pub fn parse_certificate(input: &[u8]) -> Result<Certificate<'_>, Error> {
    if input.len() > MAX_CERTIFICATE_OCTETS {
        return Err(Error::TooLarge);
    }
    let (outer, rest) = split_element(input).map_err(|e| Error::Der(Field::Certificate, e))?;
    expect(&outer, universal(SEQUENCE, true), Field::Certificate)?;
    if !rest.is_empty() {
        return Err(Error::TrailingData(Field::Certificate));
    }
    // Spec: RFC 5280 4.1 (`Certificate ::= SEQUENCE { tbsCertificate,
    // signatureAlgorithm, signatureValue }`), 4.1.1.
    let mut fields = Components::of(&outer, Field::Certificate);
    let tbs_certificate = read_tbs_certificate(&fields.next(Field::TbsCertificate)?)?;
    let signature_algorithm = read_algorithm_identifier(
        &fields.next(Field::SignatureAlgorithm)?,
        Field::SignatureAlgorithm,
    )?;
    let signature_value =
        read_octet_aligned_bit_string(&fields.next(Field::SignatureValue)?, Field::SignatureValue)?;
    fields.finish()?;
    Ok(Certificate {
        encoding: outer.encoding,
        tbs_certificate,
        signature_algorithm,
        signature_value,
    })
}

/// The components of one constructed element, read in order.
struct Components<'a> {
    rest: &'a [u8],
    field: Field,
}

impl<'a> Components<'a> {
    fn of(element: &Element<'a>, field: Field) -> Components<'a> {
        Components {
            rest: element.contents,
            field,
        }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The next (required) component, read as `field`.
    fn next(&mut self, field: Field) -> Result<Element<'a>, Error> {
        if self.rest.is_empty() {
            return Err(Error::UnexpectedElement(field));
        }
        let (element, rest) = split_element(self.rest).map_err(|e| Error::Der(field, e))?;
        self.rest = rest;
        Ok(element)
    }

    /// The next component if it carries `tag` (an OPTIONAL or DEFAULT
    /// component); otherwise nothing is consumed.
    fn optional(&mut self, tag: Tag) -> Result<Option<Element<'a>>, Error> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let (element, rest) = split_element(self.rest).map_err(|e| Error::Der(self.field, e))?;
        if element.tag != tag {
            return Ok(None);
        }
        self.rest = rest;
        Ok(Some(element))
    }

    /// No component may follow the last one.
    fn finish(&self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingData(self.field))
        }
    }
}

/// `element` must carry `tag`.
fn expect(element: &Element<'_>, tag: Tag, field: Field) -> Result<(), Error> {
    if element.tag == tag {
        Ok(())
    } else {
        Err(Error::UnexpectedElement(field))
    }
}

/// `TBSCertificate`, v3 only.
/// Spec: RFC 5280 4.1 (the TBSCertificate SEQUENCE and its tags, in the
/// explicitly tagged module A.1 for [0] / [3] and IMPLICIT for [1] / [2]),
/// 4.1.2.1-4.1.2.9.
fn read_tbs_certificate<'a>(element: &Element<'a>) -> Result<TbsCertificate<'a>, Error> {
    expect(element, universal(SEQUENCE, true), Field::TbsCertificate)?;
    let mut fields = Components::of(element, Field::TbsCertificate);
    // `version [0] EXPLICIT Version DEFAULT v1`: absent means v1, so a v3
    // certificate always carries it. Spec: RFC 5280 4.1, 4.1.2.1.
    let Some(version) = fields.optional(context(VERSION, true))? else {
        return Err(Error::VersionNotV3);
    };
    read_version(&version)?;
    // Spec: RFC 5280 4.1.2.2.
    let serial_number = read_integer(&fields.next(Field::SerialNumber)?, Field::SerialNumber)?;
    if serial_number.len() > MAX_SERIAL_NUMBER_OCTETS {
        return Err(Error::SerialNumberTooLong);
    }
    // Spec: RFC 5280 4.1.2.3.
    let signature = read_algorithm_identifier(&fields.next(Field::Signature)?, Field::Signature)?;
    // Spec: RFC 5280 4.1.2.4 ("MUST contain a non-empty distinguished name").
    let issuer = fields.next(Field::Issuer)?;
    if read_name(&issuer, Field::Issuer)? == 0 {
        return Err(Error::EmptyIssuer);
    }
    // Spec: RFC 5280 4.1.2.5.
    let validity = read_validity(&fields.next(Field::Validity)?)?;
    // Spec: RFC 5280 4.1.2.6 (the subject may be an empty sequence).
    let subject = fields.next(Field::Subject)?;
    read_name(&subject, Field::Subject)?;
    // Spec: RFC 5280 4.1.2.7.
    let subject_public_key_info =
        read_subject_public_key_info(&fields.next(Field::SubjectPublicKeyInfo)?)?;
    // `issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL`,
    // `subjectUniqueID [2] IMPLICIT …`: BIT STRING, primitive in DER, so
    // the implicit tag is primitive (X.690 10.2, 8.14.4). Read and checked,
    // not kept. Spec: RFC 5280 4.1.2.8 ("Applications conforming to this
    // profile SHOULD be capable of parsing certificates that include unique
    // identifiers, but there are no processing requirements").
    if let Some(id) = fields.optional(context(ISSUER_UNIQUE_ID, false))? {
        read_unique_identifier(&id, Field::IssuerUniqueId)?;
    }
    if let Some(id) = fields.optional(context(SUBJECT_UNIQUE_ID, false))? {
        read_unique_identifier(&id, Field::SubjectUniqueId)?;
    }
    // Spec: RFC 5280 4.1.2.9.
    let extensions = match fields.optional(context(EXTENSIONS, true))? {
        Some(extensions) => read_extensions(&extensions)?,
        None => Vec::new(),
    };
    fields.finish()?;
    Ok(TbsCertificate {
        encoding: element.encoding,
        serial_number,
        signature,
        issuer: issuer.encoding,
        validity,
        subject: subject.encoding,
        subject_public_key_info,
        extensions,
    })
}

/// The contents of `[0] EXPLICIT Version`: exactly one INTEGER, value v3.
/// Spec: RFC 5280 4.1, 4.1.2.1; X.690 8.14.3 (the contents are exactly the
/// complete base encoding).
fn read_version(element: &Element<'_>) -> Result<(), Error> {
    let mut inner = Components::of(element, Field::Version);
    let integer = read_integer(&inner.next(Field::Version)?, Field::Version)?;
    inner.finish()?;
    match Value::Integer(integer.to_vec()).as_i64() {
        Ok(VERSION_V3) => Ok(()),
        _ => Err(Error::VersionNotV3),
    }
}

/// An INTEGER's contents octets, minimal two's complement checked.
/// Spec: X.690 8.3.1, 8.3.2.
fn read_integer<'a>(element: &Element<'a>, field: Field) -> Result<&'a [u8], Error> {
    expect(element, universal(INTEGER, false), field)?;
    decode(element.encoding).map_err(|e| Error::Der(field, e))?;
    Ok(element.contents)
}

/// An OBJECT IDENTIFIER's complete encoding, its subidentifiers checked.
/// Spec: X.690 8.19.
fn read_object_identifier<'a>(element: &Element<'a>, field: Field) -> Result<&'a [u8], Error> {
    expect(element, universal(OBJECT_IDENTIFIER, false), field)?;
    decode(element.encoding).map_err(|e| Error::Der(field, e))?;
    Ok(element.encoding)
}

/// A BIT STRING whose value is whole octets: its data octets (the initial
/// unused-bits octet must be 0). Spec: X.690 8.6.2, 10.2, 11.2.1; RFC 5280
/// 4.1, 4.1.1.3 (the signature), 4.1.2.7 (the public key) — octet-aligned
/// in this profile (project choice, docs/questions/Q-320).
fn read_octet_aligned_bit_string<'a>(
    element: &Element<'a>,
    field: Field,
) -> Result<&'a [u8], Error> {
    expect(element, universal(BIT_STRING, false), field)?;
    match decode(element.encoding).map_err(|e| Error::Der(field, e))? {
        Value::BitString { unused_bits: 0, .. } => match element.contents.split_first() {
            Some((_, data)) => Ok(data),
            None => Err(Error::Der(field, parse_asn1::Error::BitStringEmpty)),
        },
        Value::BitString { .. } => Err(Error::PartialOctet(field)),
        _ => Err(Error::UnexpectedElement(field)),
    }
}

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
/// parameters ANY DEFINED BY algorithm OPTIONAL }` — the parameters are one
/// element whose header is checked and whose contents are not interpreted.
/// Spec: RFC 5280 4.1.1.2.
fn read_algorithm_identifier<'a>(
    element: &Element<'a>,
    field: Field,
) -> Result<AlgorithmIdentifier<'a>, Error> {
    expect(element, universal(SEQUENCE, true), field)?;
    let mut components = Components::of(element, field);
    let algorithm = read_object_identifier(&components.next(field)?, field)?;
    let parameters = if components.is_empty() {
        None
    } else {
        Some(components.next(field)?.encoding)
    };
    components.finish()?;
    Ok(AlgorithmIdentifier {
        encoding: element.encoding,
        contents: element.contents,
        algorithm,
        parameters,
    })
}

/// `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`.
/// Spec: RFC 5280 4.1, 4.1.2.5.
fn read_validity(element: &Element<'_>) -> Result<Validity, Error> {
    expect(element, universal(SEQUENCE, true), Field::Validity)?;
    let mut components = Components::of(element, Field::Validity);
    let not_before = read_time(&components.next(Field::NotBefore)?, Field::NotBefore)?;
    let not_after = read_time(&components.next(Field::NotAfter)?, Field::NotAfter)?;
    components.finish()?;
    Ok(Validity {
        not_before,
        not_after,
    })
}

/// `Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }`, in
/// the profile forms of crate::time. Both are primitive in DER (X.690 10.2:
/// restricted character string types; X.680 46.3, 47.3: VisibleString).
/// Spec: RFC 5280 4.1, 4.1.2.5.1, 4.1.2.5.2; X.690 11.7, 11.8.
fn read_time(element: &Element<'_>, field: Field) -> Result<Time, Error> {
    if element.tag == universal(UTC_TIME, false) {
        Time::from_utc_time(element.contents).ok_or(Error::InvalidTime(field))
    } else if element.tag == universal(GENERALIZED_TIME, false) {
        decode(element.encoding).map_err(|e| Error::Der(field, e))?;
        Time::from_generalized_time(element.contents).ok_or(Error::InvalidTime(field))
    } else {
        Err(Error::UnexpectedElement(field))
    }
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
/// subjectPublicKey BIT STRING }`. Spec: RFC 5280 4.1, 4.1.2.7.
fn read_subject_public_key_info<'a>(
    element: &Element<'a>,
) -> Result<SubjectPublicKeyInfo<'a>, Error> {
    expect(
        element,
        universal(SEQUENCE, true),
        Field::SubjectPublicKeyInfo,
    )?;
    let mut components = Components::of(element, Field::SubjectPublicKeyInfo);
    let algorithm = read_algorithm_identifier(
        &components.next(Field::SubjectPublicKeyInfo)?,
        Field::SubjectPublicKeyInfo,
    )?;
    let subject_public_key = read_octet_aligned_bit_string(
        &components.next(Field::SubjectPublicKey)?,
        Field::SubjectPublicKey,
    )?;
    components.finish()?;
    Ok(SubjectPublicKeyInfo {
        encoding: element.encoding,
        algorithm,
        subject_public_key,
    })
}

/// An implicitly tagged `UniqueIdentifier ::= BIT STRING`: its contents
/// must be those of a DER BIT STRING (checked by re-reading them under the
/// universal tag; the copy is bounded by the input).
/// Spec: RFC 5280 4.1; X.690 8.6.2, 8.14.4, 11.2.1.
fn read_unique_identifier(element: &Element<'_>, field: Field) -> Result<(), Error> {
    let as_bit_string = encode_element(universal(BIT_STRING, false), element.contents);
    decode(&as_bit_string).map_err(|e| Error::Der(field, e))?;
    Ok(())
}

/// `Name ::= CHOICE { rdnSequence RDNSequence }`, `RDNSequence ::= SEQUENCE
/// OF RelativeDistinguishedName`, `RelativeDistinguishedName ::= SET SIZE
/// (1..MAX) OF AttributeTypeAndValue`, `AttributeTypeAndValue ::= SEQUENCE
/// { type OBJECT IDENTIFIER, value ANY }` — the structure only; the
/// attribute values are one element each, header checked, contents not
/// interpreted. Returns the number of RDNs.
/// Spec: RFC 5280 4.1.2.4, A.1; X.690 11.6 (SET OF order).
fn read_name(element: &Element<'_>, field: Field) -> Result<usize, Error> {
    expect(element, universal(SEQUENCE, true), field)?;
    let mut rdns = Components::of(element, field);
    let mut count = 0usize;
    while !rdns.is_empty() {
        count += 1;
        if count > MAX_NAME_RDNS {
            return Err(Error::TooManyComponents(field));
        }
        let rdn = rdns.next(field)?;
        if rdn.tag != universal(SET, true) {
            return Err(Error::MalformedName(field));
        }
        read_relative_distinguished_name(&rdn, field)?;
    }
    Ok(count)
}

/// One `RelativeDistinguishedName` (see [`read_name`]).
/// Spec: RFC 5280 4.1.2.4, A.1; X.690 11.6.
fn read_relative_distinguished_name(rdn: &Element<'_>, field: Field) -> Result<(), Error> {
    // SET SIZE (1..MAX).
    if rdn.contents.is_empty() {
        return Err(Error::MalformedName(field));
    }
    let mut attributes = Components::of(rdn, field);
    let mut previous: Option<&[u8]> = None;
    let mut count = 0usize;
    while !attributes.is_empty() {
        count += 1;
        if count > MAX_RDN_ATTRIBUTES {
            return Err(Error::TooManyComponents(field));
        }
        let attribute = attributes.next(field)?;
        if attribute.tag != universal(SEQUENCE, true) {
            return Err(Error::MalformedName(field));
        }
        // X.690 11.6: ascending order of the encodings.
        if let Some(before) = previous {
            if set_of_order(before, attribute.encoding) == Ordering::Greater {
                return Err(Error::MalformedName(field));
            }
        }
        previous = Some(attribute.encoding);
        let mut parts = Components::of(&attribute, field);
        let attribute_type = parts.next(field)?;
        if attribute_type.tag != universal(OBJECT_IDENTIFIER, false) {
            return Err(Error::MalformedName(field));
        }
        read_object_identifier(&attribute_type, field)?;
        let _value = parts.next(field)?;
        if !parts.is_empty() {
            return Err(Error::MalformedName(field));
        }
    }
    Ok(())
}

/// The X.690 11.6 order of two SET OF component encodings: compared as
/// octet strings, the shorter padded at its trailing end with 0-octets.
/// Spec: X.690 11.6.
fn set_of_order(a: &[u8], b: &[u8]) -> Ordering {
    let length = a.len().max(b.len());
    (0..length)
        .map(|i| {
            let x = a.get(i).copied().unwrap_or(0);
            let y = b.get(i).copied().unwrap_or(0);
            x.cmp(&y)
        })
        .find(|order| *order != Ordering::Equal)
        .unwrap_or(Ordering::Equal)
}

/// `[3] EXPLICIT Extensions`, `Extensions ::= SEQUENCE SIZE (1..MAX) OF
/// Extension`, no extnID twice.
/// Spec: RFC 5280 4.1, 4.1.2.9, 4.2 ("A certificate MUST NOT include more
/// than one instance of a particular extension"); X.690 8.14.3.
fn read_extensions<'a>(element: &Element<'a>) -> Result<Vec<Extension<'a>>, Error> {
    let mut outer = Components::of(element, Field::Extensions);
    let sequence = outer.next(Field::Extensions)?;
    outer.finish()?;
    expect(&sequence, universal(SEQUENCE, true), Field::Extensions)?;
    if sequence.contents.is_empty() {
        return Err(Error::EmptyExtensions);
    }
    let mut items = Components::of(&sequence, Field::Extensions);
    let mut extensions: Vec<Extension<'a>> = Vec::new();
    while !items.is_empty() {
        if extensions.len() >= MAX_EXTENSIONS {
            return Err(Error::TooManyComponents(Field::Extensions));
        }
        let extension = read_extension(&items.next(Field::Extension)?)?;
        // DER encodings are unique, so equal OIDs have equal encodings.
        if extensions.iter().any(|e| e.extn_id == extension.extn_id) {
            return Err(Error::DuplicateExtension);
        }
        extensions.push(extension);
    }
    Ok(extensions)
}

/// `Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN
/// DEFAULT FALSE, extnValue OCTET STRING }` — a present `critical` must be
/// TRUE (DER omits a component equal to its default).
/// Spec: RFC 5280 4.1; X.690 11.1, 11.5.
fn read_extension<'a>(element: &Element<'a>) -> Result<Extension<'a>, Error> {
    expect(element, universal(SEQUENCE, true), Field::Extension)?;
    let mut parts = Components::of(element, Field::Extension);
    let extn_id = read_object_identifier(&parts.next(Field::Extension)?, Field::Extension)?;
    let critical = match parts.optional(universal(BOOLEAN, false))? {
        None => false,
        Some(boolean) => {
            match decode(boolean.encoding).map_err(|e| Error::Der(Field::Extension, e))? {
                Value::Boolean(true) => true,
                Value::Boolean(false) => return Err(Error::DefaultEncoded),
                _ => return Err(Error::UnexpectedElement(Field::Extension)),
            }
        }
    };
    let value = parts.next(Field::Extension)?;
    expect(&value, universal(OCTET_STRING, false), Field::Extension)?;
    parts.finish()?;
    Ok(Extension {
        extn_id,
        critical,
        extn_value: value.contents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// X.690 11.6: shorter-padded comparison.
    #[test]
    fn set_of_order_pads_with_zero_octets() {
        assert_eq!(set_of_order(&[1, 2], &[1, 2]), Ordering::Equal);
        assert_eq!(set_of_order(&[1, 2], &[1, 3]), Ordering::Less);
        assert_eq!(set_of_order(&[1, 2, 0], &[1, 2]), Ordering::Equal);
        assert_eq!(set_of_order(&[1, 2, 1], &[1, 2]), Ordering::Greater);
        assert_eq!(set_of_order(&[2], &[1, 9, 9]), Ordering::Greater);
    }
}
