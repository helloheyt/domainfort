//! Basic Kerberos types.
//!
//! Spec: RFC 4120 5.2 (5.2.1 KerberosString, 5.2.2 Realm / PrincipalName,
//! 5.2.3 KerberosTime, 5.2.4 constrained integers, 5.2.5 HostAddress(es),
//! 5.2.6 AuthorizationData, 5.2.7 PA-DATA, 5.2.9 EncryptedData /
//! EncryptionKey / Checksum) and Appendix A. KerberosFlags (5.2.8) lives in
//! [`crate::flags`].

use crate::der::{self, ctx, int, octet_string, octets, Fields};
use crate::error::{Error, Result};
use crate::limits::{MAX_AUTHORIZATION_ELEMENTS, MAX_HOST_ADDRESSES, MAX_NAME_COMPONENTS};
use core::fmt;
use parse_asn1::Value;

// ===========================================================================
// KerberosString / Realm — RFC 4120 5.2.1, 5.2.2
// ===========================================================================

/// `KerberosString ::= GeneralString (IA5String)`.
///
/// Accepted content (checked on construction and on decode):
/// - only octets of the IA5String repertoire, i.e. < 0x80 — the 5.2.1 option
///   to accept other GeneralString characters is not taken (fail closed);
/// - no US-ASCII control characters (0x00-0x1F, 0x7F). RFC 4120 says they
///   "should not be used" in KerberosString and "SHOULD NOT be used in
///   principal names or realm names", and realms "shall not contain" NUL; this
///   crate rejects them in every KerberosString (fail closed). This also
///   excludes ISO 2022 escape sequences (ESC is 0x1B), so the content is always
///   plain US-ASCII in the default G0 set.
///
/// The interop impact of these choices (e.g. clients that send UTF-8 names,
/// which RFC 4120 5.2.1 says at least one major implementation does) is an open
/// owner / lab question: docs/questions/Q-031.
///
/// Spec: RFC 4120 5.2.1, 5.2.2; X.680 (02/2021) Table 8 (IA5String).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KerberosString(String);

/// `Realm ::= KerberosString`. Spec: RFC 4120 5.2.2.
pub type Realm = KerberosString;

impl KerberosString {
    /// Build from text, enforcing the KerberosString content rules.
    /// Spec: RFC 4120 5.2.1.
    pub fn new(text: &str) -> Result<Self> {
        Self::from_bytes(text.as_bytes())
    }

    /// Build from GeneralString content octets, enforcing the content rules.
    /// Spec: RFC 4120 5.2.1.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_kerberos_string(bytes)?;
        // Every octet is < 0x80, so the content is valid UTF-8 (US-ASCII).
        match core::str::from_utf8(bytes) {
            Ok(text) => Ok(KerberosString(text.to_owned())),
            Err(_) => Err(Error::NonIa5Character),
        }
    }

    /// The string as text (always US-ASCII).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The GeneralString content octets.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Spec: RFC 4120 5.2.1 (GeneralString, UNIVERSAL 27 — X.680 Table 8).
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::GeneralString(bytes) => Self::from_bytes(bytes),
            _ => Err(Error::ExpectedGeneralString),
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::GeneralString(self.0.as_bytes().to_vec())
    }
}

impl fmt::Display for KerberosString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Check KerberosString content octets. Spec: RFC 4120 5.2.1, 5.2.2.
fn check_kerberos_string(bytes: &[u8]) -> Result<()> {
    for &octet in bytes {
        // IA5String repertoire: register entries 1 (C0) and 6 (G0) + SPACE +
        // DELETE, all below 0x80. Spec: X.680 Table 8; RFC 4120 5.2.1.
        if octet >= 0x80 {
            return Err(Error::NonIa5Character);
        }
        // C0 controls and DELETE. Spec: RFC 4120 5.2.1 ("SHOULD NOT"), 5.2.2
        // (no NUL in realms); fail closed.
        if octet < 0x20 || octet == 0x7F {
            return Err(Error::ControlCharacter);
        }
    }
    Ok(())
}

// ===========================================================================
// PrincipalName — RFC 4120 5.2.2
// ===========================================================================

/// ```text
/// PrincipalName   ::= SEQUENCE {
///         name-type       [0] Int32,
///         name-string     [1] SEQUENCE OF KerberosString
/// }
/// ```
///
/// `name-type` is a hint (RFC 4120 5.2.2, 6.2) and is carried as the raw
/// Int32, so unregistered values are preserved (RFC 4120 1.5.1); see the
/// `KRB_NT_*` constants in [`crate::constants`]. `name-string` is bounded by
/// [`crate::limits::MAX_NAME_COMPONENTS`].
///
/// Spec: RFC 4120 5.2.2, 6.2, 7.5.8; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrincipalName {
    /// `name-type [0] Int32`.
    pub name_type: i32,
    /// `name-string [1] SEQUENCE OF KerberosString`.
    pub name_string: Vec<KerberosString>,
}

impl PrincipalName {
    const TAGS: &'static [u32] = &[0, 1];

    /// Spec: RFC 4120 5.2.2.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let name_type = der::int32(f.required(0)?)?;
        let name_string = der::decode_sequence_of(
            f.required(1)?,
            MAX_NAME_COMPONENTS,
            KerberosString::from_value,
        )?;
        f.finish()?;
        Ok(PrincipalName {
            name_type,
            name_string,
        })
    }

    /// Spec: RFC 4120 5.2.2.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![
            ctx(0, int(self.name_type.into())),
            ctx(
                1,
                der::encode_sequence_of(&self.name_string, MAX_NAME_COMPONENTS, |s| {
                    Ok(s.to_value())
                })?,
            ),
        ]))
    }
}

der_codec!(PrincipalName, "PrincipalName");

// ===========================================================================
// KerberosTime — RFC 4120 5.2.3
// ===========================================================================

/// `KerberosTime ::= GeneralizedTime -- with no fractional seconds`.
///
/// The only accepted form is `YYYYMMDDHHMMSSZ` (RFC 4120 5.2.3: no fractional
/// seconds, no separators, UTC "Z"), and the fields must form a valid calendar
/// date and UTC time of day: month 01-12, day within the month (Gregorian leap
/// years), hour 00-23 (midnight at the end of a day is not representable,
/// X.680 46.2 / X.690 11.7.5), minute 00-59, second 00-59. A leap second (60)
/// is rejected — the allowed sources do not define it; see
/// docs/questions/Q-030.
///
/// Field order makes the derived `Ord` chronological.
///
/// Spec: RFC 4120 5.2.3; X.680 (02/2021) 46.2, 46.3; X.690 (02/2021) 11.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KerberosTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl KerberosTime {
    /// Build from calendar fields (UTC), validating them.
    /// Spec: RFC 4120 5.2.3; X.680 46.2, 46.3 (four-digit year, calendar date,
    /// time of day excluding midnight at the end of a day).
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Result<Self> {
        let valid = year <= 9999
            && (1..=12).contains(&month)
            && day >= 1
            && day <= days_in_month(year, month)
            && hour <= 23
            && minute <= 59
            && second <= 59;
        if !valid {
            return Err(Error::InvalidKerberosTime);
        }
        Ok(KerberosTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        })
    }

    /// Year (0000-9999).
    pub fn year(&self) -> u16 {
        self.year
    }
    /// Month (1-12).
    pub fn month(&self) -> u8 {
        self.month
    }
    /// Day of month (1-31).
    pub fn day(&self) -> u8 {
        self.day
    }
    /// Hour (0-23).
    pub fn hour(&self) -> u8 {
        self.hour
    }
    /// Minute (0-59).
    pub fn minute(&self) -> u8 {
        self.minute
    }
    /// Second (0-59).
    pub fn second(&self) -> u8 {
        self.second
    }

    /// Spec: RFC 4120 5.2.3 (GeneralizedTime, UNIVERSAL 24).
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::GeneralizedTime(text) => Self::from_generalized_time(text),
            _ => Err(Error::ExpectedGeneralizedTime),
        }
    }

    /// Parse `YYYYMMDDHHMMSSZ`. `parse-asn1` has already enforced the X.690
    /// 11.7 DER form (14 digits, optional fraction without trailing zeros, "Z"),
    /// so any encoding longer than 15 octets carries fractional seconds.
    /// Spec: RFC 4120 5.2.3; X.690 11.7.
    fn from_generalized_time(text: &[u8]) -> Result<Self> {
        if text.len() > 15 {
            return Err(Error::FractionalKerberosTime);
        }
        let (digits_text, zone) = match text.split_at_checked(14) {
            Some(parts) => parts,
            None => return Err(Error::InvalidKerberosTime),
        };
        if zone != b"Z" {
            return Err(Error::InvalidKerberosTime);
        }
        let mut digits = [0u8; 14];
        for (digit, &c) in digits.iter_mut().zip(digits_text) {
            if !c.is_ascii_digit() {
                return Err(Error::InvalidKerberosTime);
            }
            *digit = c - b'0';
        }
        let year = u16::from(digits[0]) * 1000
            + u16::from(digits[1]) * 100
            + u16::from(digits[2]) * 10
            + u16::from(digits[3]);
        let pair = |i: usize| digits[i] * 10 + digits[i + 1];
        Self::new(year, pair(4), pair(6), pair(8), pair(10), pair(12))
    }

    /// Spec: RFC 4120 5.2.3 (e.g. `19851106210627Z`).
    pub(crate) fn to_value(self) -> Value {
        let text = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        );
        Value::GeneralizedTime(text.into_bytes())
    }
}

/// Gregorian leap-year rule (every fourth year, except century years not
/// divisible by 400) — the calendar of X.680 46.2's "calendar date". The
/// crate's one calendar: [`KerberosTime::new`] validates with it and the
/// time scale (crate::time) counts with it.
fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Days in `month` of `year` (0 for an invalid month).
pub(crate) fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

// ===========================================================================
// Microseconds — RFC 4120 5.2.4
// ===========================================================================

/// `Microseconds ::= INTEGER (0..999999)`.
///
/// Spec: RFC 4120 5.2.4 (also 5.5.1 cusec "ranges from 0 to 999999").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Microseconds(u32);

impl Microseconds {
    /// Largest permitted value. Spec: RFC 4120 5.2.4.
    pub const MAX: u32 = 999_999;

    /// Build, rejecting values above [`Microseconds::MAX`].
    /// Spec: RFC 4120 5.2.4.
    pub fn new(value: u32) -> Result<Self> {
        if value > Self::MAX {
            Err(Error::MicrosecondsOutOfRange)
        } else {
            Ok(Microseconds(value))
        }
    }

    /// The value (0..=999999).
    pub fn get(self) -> u32 {
        self.0
    }

    pub(crate) fn to_value(self) -> Value {
        int(self.0.into())
    }
}

// ===========================================================================
// HostAddress / HostAddresses — RFC 4120 5.2.5
// ===========================================================================

/// ```text
/// HostAddress     ::= SEQUENCE  {
///         addr-type       [0] Int32,
///         address         [1] OCTET STRING
/// }
/// ```
///
/// `addr-type` is a typed hole and is carried raw (RFC 4120 1.5.1).
///
/// Spec: RFC 4120 5.2.5, 7.5.3; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostAddress {
    /// `addr-type [0] Int32`.
    pub addr_type: i32,
    /// `address [1] OCTET STRING`.
    pub address: Vec<u8>,
}

impl HostAddress {
    const TAGS: &'static [u32] = &[0, 1];

    /// Spec: RFC 4120 5.2.5.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let addr_type = der::int32(f.required(0)?)?;
        let address = octet_string(f.required(1)?)?.to_vec();
        f.finish()?;
        Ok(HostAddress { addr_type, address })
    }

    /// Spec: RFC 4120 5.2.5.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![
            ctx(0, int(self.addr_type.into())),
            ctx(1, octets(&self.address)),
        ]))
    }
}

der_codec!(HostAddress, "HostAddress");

/// `HostAddresses ::= SEQUENCE OF HostAddress`, bounded by
/// [`crate::limits::MAX_HOST_ADDRESSES`].
///
/// RFC 4120 notes it "should not be empty" when present; per RFC 4120 5.1.3 an
/// empty encoding is accepted and preserved (so re-encoding is exact), and
/// consumers treat it as equivalent to the field being absent.
///
/// Spec: RFC 4120 5.2.5, 5.1.3; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct HostAddresses(pub Vec<HostAddress>);

impl HostAddresses {
    /// Spec: RFC 4120 5.2.5.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        der::decode_sequence_of(value, MAX_HOST_ADDRESSES, HostAddress::from_value)
            .map(HostAddresses)
    }

    /// Spec: RFC 4120 5.2.5.
    pub(crate) fn to_value(&self) -> Result<Value> {
        der::encode_sequence_of(&self.0, MAX_HOST_ADDRESSES, HostAddress::to_value)
    }
}

der_codec!(HostAddresses, "HostAddresses");

// ===========================================================================
// AuthorizationData — RFC 4120 5.2.6
// ===========================================================================

/// One element of AuthorizationData (RFC 4120 5.2.6 calls each
/// "sequence of type and data" an *authorization element*):
///
/// ```text
/// SEQUENCE {
///         ad-type         [0] Int32,
///         ad-data         [1] OCTET STRING
/// }
/// ```
///
/// `ad-type` / `ad-data` form a typed hole and are carried raw, so unknown
/// types are preserved byte-for-byte (RFC 4120 1.5.1). **This layer does not
/// apply the criticality rules**: an application server that receives an
/// unknown ad-type in an AP-REQ or its ticket MUST fail authentication, and a
/// TGS MUST reject unknown types inside AD-MANDATORY-FOR-KDC (RFC 4120 1.5.1,
/// 5.2.6, 5.2.6.4). That decision belongs to the consumer that knows which
/// types it understands.
///
/// Spec: RFC 4120 5.2.6, 7.5.4; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorizationElement {
    /// `ad-type [0] Int32`.
    pub ad_type: i32,
    /// `ad-data [1] OCTET STRING`.
    pub ad_data: Vec<u8>,
}

impl AuthorizationElement {
    const TAGS: &'static [u32] = &[0, 1];

    /// Spec: RFC 4120 5.2.6.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let ad_type = der::int32(f.required(0)?)?;
        let ad_data = octet_string(f.required(1)?)?.to_vec();
        f.finish()?;
        Ok(AuthorizationElement { ad_type, ad_data })
    }

    /// Spec: RFC 4120 5.2.6.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![
            ctx(0, int(self.ad_type.into())),
            ctx(1, octets(&self.ad_data)),
        ]))
    }
}

/// `AuthorizationData ::= SEQUENCE OF SEQUENCE { ad-type, ad-data }`, bounded
/// by [`crate::limits::MAX_AUTHORIZATION_ELEMENTS`].
///
/// It "should not be empty" when present; per RFC 4120 5.1.3 an empty
/// encoding is accepted, preserved, and means the same as absent. The standalone
/// `decode` serves nested containers whose ad-data is itself AuthorizationData
/// (e.g. AD-IF-RELEVANT, RFC 4120 5.2.6.1).
///
/// Spec: RFC 4120 5.2.6, 5.1.3; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct AuthorizationData(pub Vec<AuthorizationElement>);

impl AuthorizationData {
    /// Spec: RFC 4120 5.2.6.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        der::decode_sequence_of(
            value,
            MAX_AUTHORIZATION_ELEMENTS,
            AuthorizationElement::from_value,
        )
        .map(AuthorizationData)
    }

    /// Spec: RFC 4120 5.2.6.
    pub(crate) fn to_value(&self) -> Result<Value> {
        der::encode_sequence_of(
            &self.0,
            MAX_AUTHORIZATION_ELEMENTS,
            AuthorizationElement::to_value,
        )
    }
}

der_codec!(AuthorizationData, "AuthorizationData");

// ===========================================================================
// PA-DATA — RFC 4120 5.2.7
// ===========================================================================

/// ```text
/// PA-DATA         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         padata-type     [1] Int32,
///         padata-value    [2] OCTET STRING -- might be encoded AP-REQ
/// }
/// ```
///
/// A typed hole: unknown `padata-type` values are preserved byte-for-byte and
/// never cause a decode failure here (RFC 4120 1.5.1, "MUST NOT decline a
/// request simply because an extension is present"). See the `PA_*` constants
/// in [`crate::constants`].
///
/// Spec: RFC 4120 5.2.7, 7.5.2; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaData {
    /// `padata-type [1] Int32`.
    pub padata_type: i32,
    /// `padata-value [2] OCTET STRING`.
    pub padata_value: Vec<u8>,
}

impl PaData {
    // Spec: RFC 4120 5.2.7 — "first tag is [1], not [0]".
    const TAGS: &'static [u32] = &[1, 2];

    /// Spec: RFC 4120 5.2.7.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let padata_type = der::int32(f.required(1)?)?;
        let padata_value = octet_string(f.required(2)?)?.to_vec();
        f.finish()?;
        Ok(PaData {
            padata_type,
            padata_value,
        })
    }

    /// Spec: RFC 4120 5.2.7.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![
            ctx(1, int(self.padata_type.into())),
            ctx(2, octets(&self.padata_value)),
        ]))
    }
}

der_codec!(PaData, "PA-DATA");

// ===========================================================================
// EncryptedData — RFC 4120 5.2.9
// ===========================================================================

/// ```text
/// EncryptedData   ::= SEQUENCE {
///         etype   [0] Int32 -- EncryptionType --,
///         kvno    [1] UInt32 OPTIONAL,
///         cipher  [2] OCTET STRING -- ciphertext
/// }
/// ```
///
/// Opaque here: this crate never encrypts or decrypts (keyd / krb-crypto do).
/// `etype` is carried as the raw Int32; which encryption types are acceptable
/// is a policy decision of the crypto layer, not of this codec.
///
/// Spec: RFC 4120 5.2.9; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncryptedData {
    /// `etype [0] Int32`.
    pub etype: i32,
    /// `kvno [1] UInt32 OPTIONAL`.
    pub kvno: Option<u32>,
    /// `cipher [2] OCTET STRING`.
    pub cipher: Vec<u8>,
}

impl EncryptedData {
    const TAGS: &'static [u32] = &[0, 1, 2];

    /// Spec: RFC 4120 5.2.9.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let etype = der::int32(f.required(0)?)?;
        let kvno = f.optional(1).map(der::uint32).transpose()?;
        let cipher = octet_string(f.required(2)?)?.to_vec();
        f.finish()?;
        Ok(EncryptedData {
            etype,
            kvno,
            cipher,
        })
    }

    /// Spec: RFC 4120 5.2.9.
    pub(crate) fn to_value(&self) -> Result<Value> {
        let mut items = vec![ctx(0, int(self.etype.into()))];
        if let Some(kvno) = self.kvno {
            items.push(ctx(1, int(kvno.into())));
        }
        items.push(ctx(2, octets(&self.cipher)));
        Ok(Value::Sequence(items))
    }
}

der_codec!(EncryptedData, "EncryptedData");

// ===========================================================================
// EncryptionKey — RFC 4120 5.2.9
// ===========================================================================

secret_octets! {
    /// The `keyvalue` octets of an EncryptionKey — key material.
    ///
    /// Held in a RustCrypto `Zeroizing` buffer, wiped on drop. `Debug` never
    /// prints the octets. Equality compares every octet without an early exit
    /// on the first difference; it is meant for bookkeeping and tests, not as
    /// a verified constant-time primitive — authentication decisions must
    /// never be made by comparing keys. (Defined by the crate's one
    /// secret-octets definition, shared with [`crate::UserData`] and
    /// [`crate::NewPasswd`].)
    ///
    /// Spec: RFC 4120 5.2.9 ("This field contains the key itself");
    /// docs/CLEAN-ROOM.md
    KeyValue
}

/// ```text
/// EncryptionKey   ::= SEQUENCE {
///         keytype         [0] Int32 -- actually encryption type --,
///         keyvalue        [1] OCTET STRING
/// }
/// ```
///
/// `keyvalue` is a [`KeyValue`]: zeroized on drop, redacted in `Debug`, never
/// placed in an error. `encode` returns a `Zeroizing` buffer.
///
/// Spec: RFC 4120 5.2.9; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionKey {
    /// `keytype [0] Int32` (an encryption type number).
    pub keytype: i32,
    /// `keyvalue [1] OCTET STRING`.
    pub keyvalue: KeyValue,
}

impl EncryptionKey {
    const TAGS: &'static [u32] = &[0, 1];

    /// Spec: RFC 4120 5.2.9.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let keytype = der::int32(f.required(0)?)?;
        let keyvalue = KeyValue::from_slice(octet_string(f.required(1)?)?);
        f.finish()?;
        Ok(EncryptionKey { keytype, keyvalue })
    }

    /// Spec: RFC 4120 5.2.9. The returned value holds a copy of the key; every
    /// caller hands it to `der::encode_secret` / `SecretFields`, which scrub it.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![
            ctx(0, int(self.keytype.into())),
            ctx(1, octets(self.keyvalue.as_bytes())),
        ]))
    }
}

der_codec_secret!(EncryptionKey, "EncryptionKey");

// ===========================================================================
// Checksum — RFC 4120 5.2.9
// ===========================================================================

/// ```text
/// Checksum        ::= SEQUENCE {
///         cksumtype       [0] Int32,
///         checksum        [1] OCTET STRING
/// }
/// ```
///
/// Spec: RFC 4120 5.2.9; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Checksum {
    /// `cksumtype [0] Int32`.
    pub cksumtype: i32,
    /// `checksum [1] OCTET STRING`.
    pub checksum: Vec<u8>,
}

impl Checksum {
    const TAGS: &'static [u32] = &[0, 1];

    /// Spec: RFC 4120 5.2.9.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let cksumtype = der::int32(f.required(0)?)?;
        let checksum = octet_string(f.required(1)?)?.to_vec();
        f.finish()?;
        Ok(Checksum {
            cksumtype,
            checksum,
        })
    }

    /// Spec: RFC 4120 5.2.9.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![
            ctx(0, int(self.cksumtype.into())),
            ctx(1, octets(&self.checksum)),
        ]))
    }
}

der_codec!(Checksum, "Checksum");

// ===========================================================================
// Shared helpers for optional / repeated fields used by several messages.
// ===========================================================================

/// Decode `SEQUENCE OF PA-DATA` (KDC-REQ / KDC-REP `padata`, METHOD-DATA),
/// bounded by [`crate::limits::MAX_PADATA`]. Spec: RFC 4120 5.4.1, 5.4.2, 5.9.1.
pub(crate) fn padata_from_value(value: &Value) -> Result<Vec<PaData>> {
    der::decode_sequence_of(value, crate::limits::MAX_PADATA, PaData::from_value)
}

/// Encode `SEQUENCE OF PA-DATA`. Spec: RFC 4120 5.4.1, 5.4.2, 5.9.1.
pub(crate) fn padata_to_value(items: &[PaData]) -> Result<Value> {
    der::encode_sequence_of(items, crate::limits::MAX_PADATA, PaData::to_value)
}
