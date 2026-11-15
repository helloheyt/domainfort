//! RFC 3244 change-password user data: ChangePasswdData (the plaintext
//! `user-data` of a request's KRB-PRIV) and the result data (the `user-data`
//! of a reply's KRB-PRIV, or the `e-data` of a reply's KRB-ERROR).
//!
//! The message framing (message length, protocol version number, AP_REQ /
//! AP_REP length) is the `parse-kpasswd` crate's; this module holds only the
//! structures keyd opens and seals (docs/53 §5.9).
//!
//! # Phase-1 scope: change only (docs/53 R53-1; docs/questions/Q-600)
//!
//! A ChangePasswdData that carries `targname` or `targrealm` is "a request to
//! set a password" ([MS-KILE] 3.1.5.12). It is still decoded strictly, so keyd
//! can answer it with KRB5_KPASSWD_ACCESSDENIED without looking the target up
//! (docs/53 §5.4 item 4, §5.7). Its components are not reachable:
//! [`ChangePasswdData::request`] reports [`PasswordRequest::Set`], which
//! carries nothing — neither the target nor the new password — so no code
//! path can route a set request to a password operation. The only
//! constructor, [`ChangePasswdData::change`], builds the change form. The
//! target fields are retained privately only so that re-encoding a decoded
//! value is exact (`encode(decode(b)) == b`).
//!
//! # Encoding rules and tagging
//!
//! RFC 3244 §2 gives the ASN.1 type outside any module, so no TagDefault
//! applies: an empty TagDefault is taken as EXPLICIT TAGS (X.680 13.2,
//! 31.2.7 b)) — the same mode as the RFC 4120 module whose PrincipalName and
//! Realm it uses. RFC 3244 states no encoding rules for the structure; it is
//! read as DER like every Kerberos value (RFC 4120 5.1.1) and decoded under
//! this crate's strict DER (docs/53 §5.4 item 4). Fields after `targrealm` are
//! refused ([`crate::Error::UnknownField`]) — the SHOULD-level "prepared to
//! ignore fields after targrealm" is not taken (docs/questions/Q-603 item 6).
//! See docs/questions/Q-620 for these readings.
//!
//! Spec: RFC 3244 §2; [MS-KILE] v20261110 3.1.5.12; RFC 4120 5.1.1, 5.2.2;
//! X.680 (02/2021) 13.2, 31.2.7; docs/53 §5.4, §5.7.

use crate::basic::{PrincipalName, Realm};
use crate::constants::{
    KRB5_KPASSWD_ACCESSDENIED, KRB5_KPASSWD_AUTHERROR, KRB5_KPASSWD_BAD_VERSION,
    KRB5_KPASSWD_HARDERROR, KRB5_KPASSWD_INITIAL_FLAG_NEEDED, KRB5_KPASSWD_MALFORMED,
    KRB5_KPASSWD_SOFTERROR, KRB5_KPASSWD_SUCCESS,
};
use crate::der::{ctx, octet_string, octets, Fields, SecretFields};
use crate::error::{Error, Result};
use crate::limits::MAX_NEWPASSWD_LEN;
use parse_asn1::Value;

// ===========================================================================
// ChangePasswdData — RFC 3244 §2
// ===========================================================================

secret_octets! {
    /// The `newpasswd` octets of a ChangePasswdData — "the cleartext
    /// password" (RFC 3244 §2). Zeroized on drop, redacted in `Debug`, never
    /// placed in an error.
    ///
    /// Any octets are accepted here (up to
    /// [`crate::limits::MAX_NEWPASSWD_LEN`]): whether they are valid UTF-8
    /// (RFC 3961 §3 string-to-key needs UTF-8) and whether they meet the
    /// password policy are keyd's checks, answered with the PasswordRefused
    /// verdict (SOFTERROR) — docs/53 §5.4 items 5–6, docs/questions/Q-603
    /// item 7.
    ///
    /// Spec: RFC 3244 §2; AGENTS.md §6.
    NewPasswd
}

/// ```text
/// ChangePasswdData ::=  SEQUENCE {
///                     newpasswd[0]   OCTET STRING,
///                     targname[1]    PrincipalName OPTIONAL,
///                     targrealm[2]   Realm OPTIONAL
///                     }
/// ```
///
/// The plaintext carried as the `user-data` of the request's EncKrbPrivPart.
/// Holds a password, so it is decoded / encoded on the secret path.
///
/// The fields are private: the new password is reachable only through
/// [`ChangePasswdData::request`], and only for the change form (see the module
/// documentation). `targname` / `targrealm` (a set request) are kept only for
/// exact re-encoding and have no accessor.
///
/// Spec: RFC 3244 §2; [MS-KILE] 3.1.5.12; docs/53 §5.4 item 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePasswdData {
    /// `newpasswd [0] OCTET STRING`.
    newpasswd: NewPasswd,
    /// `targname [1] PrincipalName OPTIONAL` — no accessor (Q-600).
    targname: Option<PrincipalName>,
    /// `targrealm [2] Realm OPTIONAL` — no accessor (Q-600).
    targrealm: Option<Realm>,
}

/// What a ChangePasswdData asks for, as far as this project acts on it.
///
/// Spec: [MS-KILE] 3.1.5.12 ("If the fields are present, then this is a
/// request to set a password ... If the fields are absent, then this is a
/// password change"); docs/53 §5.4 item 4 (either field present ⇒ set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordRequest<'a> {
    /// `targname` and `targrealm` both absent: a change of the ticket
    /// client's own password to `newpasswd`.
    Change {
        /// The requested new password.
        newpasswd: &'a NewPasswd,
    },
    /// `targname` or `targrealm` present: a request to set a password. Not
    /// supported in phase 1 — answered with KRB5_KPASSWD_ACCESSDENIED without
    /// looking the target up (docs/53 R53-1, §5.7; Q-600 item 2). Carries no
    /// content by design.
    Set,
}

impl ChangePasswdData {
    const TAGS: &'static [u32] = &[0, 1, 2];

    /// A password change: `newpasswd` only, `targname` and `targrealm`
    /// absent. The only form this crate builds (docs/53 R53-1). `encode`
    /// refuses a `newpasswd` over [`crate::limits::MAX_NEWPASSWD_LEN`].
    ///
    /// Spec: RFC 3244 §2; [MS-KILE] 3.1.5.12.
    pub fn change(newpasswd: NewPasswd) -> Self {
        ChangePasswdData {
            newpasswd,
            targname: None,
            targrealm: None,
        }
    }

    /// Classify the request: [`PasswordRequest::Change`] (with the new
    /// password) only when both target fields are absent; otherwise
    /// [`PasswordRequest::Set`], with nothing in it.
    ///
    /// Spec: [MS-KILE] 3.1.5.12; docs/53 §5.4 item 4.
    pub fn request(&self) -> PasswordRequest<'_> {
        if self.targname.is_none() && self.targrealm.is_none() {
            PasswordRequest::Change {
                newpasswd: &self.newpasswd,
            }
        } else {
            PasswordRequest::Set
        }
    }

    /// Spec: RFC 3244 §2 (explicit tags per X.680 13.2, 31.2.7 b)).
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let newpasswd = newpasswd_from(octet_string(f.required(0)?)?)?;
        let targname = f.optional(1).map(PrincipalName::from_value).transpose()?;
        let targrealm = f.optional(2).map(Realm::from_value).transpose()?;
        f.finish()?;
        Ok(ChangePasswdData {
            newpasswd,
            targname,
            targrealm,
        })
    }

    /// Spec: RFC 3244 §2. The `newpasswd` copy in the value tree is scrubbed
    /// by `SecretFields` / `der::encode_secret`.
    pub(crate) fn to_value(&self) -> Result<Value> {
        if self.newpasswd.len() > MAX_NEWPASSWD_LEN {
            return Err(Error::NewPasswdTooLong);
        }
        let mut f = SecretFields::new();
        f.push(ctx(0, octets(self.newpasswd.as_bytes())));
        if let Some(targname) = &self.targname {
            f.push(ctx(1, targname.to_value()?));
        }
        if let Some(targrealm) = &self.targrealm {
            f.push(ctx(2, targrealm.to_value()));
        }
        Ok(f.into_sequence())
    }
}

/// Bound the password before copying it into its zeroizing buffer, so an
/// oversized value is never copied. Spec: docs/53 §5.4 item 4, §5.9.
fn newpasswd_from(bytes: &[u8]) -> Result<NewPasswd> {
    if bytes.len() > MAX_NEWPASSWD_LEN {
        return Err(Error::NewPasswdTooLong);
    }
    Ok(NewPasswd::from_slice(bytes))
}

der_codec_secret!(ChangePasswdData, "ChangePasswdData", "RFC 3244 §2");

// ===========================================================================
// Result codes and result data — RFC 3244 §2
// ===========================================================================

/// A failure result code: every RFC 3244 §2 code except KRB5_KPASSWD_SUCCESS.
///
/// The only code type a KRB-ERROR (or keyd's sealed error reply) can carry, so
/// "0 in a KRB-ERROR" is unrepresentable (RFC 3244 §2: SUCCESS "is not allowed
/// in a KRB-ERROR message"; docs/53 §4.5, §2.4). 0xFFFF ("some other reason")
/// is not a variant: this project never sends it (docs/questions/Q-604
/// item 4).
///
/// Spec: RFC 3244 §2; docs/53 §5.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NonZeroResultCode {
    /// KRB5_KPASSWD_MALFORMED (1): "request fails due to being malformed".
    Malformed = KRB5_KPASSWD_MALFORMED,
    /// KRB5_KPASSWD_HARDERROR (2): a "hard" error in processing.
    HardError = KRB5_KPASSWD_HARDERROR,
    /// KRB5_KPASSWD_AUTHERROR (3): an error in authentication processing.
    AuthError = KRB5_KPASSWD_AUTHERROR,
    /// KRB5_KPASSWD_SOFTERROR (4): a "soft" error in processing.
    SoftError = KRB5_KPASSWD_SOFTERROR,
    /// KRB5_KPASSWD_ACCESSDENIED (5): "requestor not authorized".
    AccessDenied = KRB5_KPASSWD_ACCESSDENIED,
    /// KRB5_KPASSWD_BAD_VERSION (6): "protocol version unsupported".
    BadVersion = KRB5_KPASSWD_BAD_VERSION,
    /// KRB5_KPASSWD_INITIAL_FLAG_NEEDED (7): "initial flag required".
    InitialFlagNeeded = KRB5_KPASSWD_INITIAL_FLAG_NEEDED,
}

impl NonZeroResultCode {
    /// The 16-bit result code value. Spec: RFC 3244 §2.
    pub const fn value(self) -> u16 {
        self as u16
    }

    /// The failure code with this value: 0 ⇒ [`Error::SuccessNotAllowed`];
    /// any value RFC 3244 §2 does not define (including 0xFFFF) ⇒
    /// [`Error::UnknownResultCode`].
    ///
    /// Spec: RFC 3244 §2.
    pub fn from_value(value: u16) -> Result<Self> {
        match value {
            KRB5_KPASSWD_SUCCESS => Err(Error::SuccessNotAllowed),
            KRB5_KPASSWD_MALFORMED => Ok(NonZeroResultCode::Malformed),
            KRB5_KPASSWD_HARDERROR => Ok(NonZeroResultCode::HardError),
            KRB5_KPASSWD_AUTHERROR => Ok(NonZeroResultCode::AuthError),
            KRB5_KPASSWD_SOFTERROR => Ok(NonZeroResultCode::SoftError),
            KRB5_KPASSWD_ACCESSDENIED => Ok(NonZeroResultCode::AccessDenied),
            KRB5_KPASSWD_BAD_VERSION => Ok(NonZeroResultCode::BadVersion),
            KRB5_KPASSWD_INITIAL_FLAG_NEEDED => Ok(NonZeroResultCode::InitialFlagNeeded),
            _ => Err(Error::UnknownResultCode),
        }
    }

    /// The result data for this code: the 16-bit result code, big-endian,
    /// with the result string omitted — the `e-data` of a KRB-ERROR reply or
    /// the `user-data` of a sealed error reply.
    ///
    /// Spec: RFC 3244 §2 ("result code (16 bits)", "big-endian integer";
    /// the result string "may be omitted"); docs/questions/Q-604 items 1, 5.
    pub const fn result_data(self) -> [u8; 2] {
        self.value().to_be_bytes()
    }

    /// Decode result data that must carry a failure code (a KRB-ERROR's
    /// `e-data`): exactly two octets ([`Error::ResultDataLength`]), a defined
    /// code, never 0.
    ///
    /// Spec: RFC 3244 §2; docs/questions/Q-604 item 5.
    pub fn from_result_data(data: &[u8]) -> Result<Self> {
        Self::from_value(result_code_value(data)?)
    }
}

/// An RFC 3244 §2 result code: success, or a [`NonZeroResultCode`].
///
/// Spec: RFC 3244 §2 ("The result code must have one of the following
/// values"); docs/53 §5.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultCode {
    /// KRB5_KPASSWD_SUCCESS (0): "request succeeds". Only in a KRB-PRIV
    /// reply, which keyd seals only after the password is installed (docs/53
    /// §5.5).
    Success,
    /// Any failure code.
    Failure(NonZeroResultCode),
}

impl ResultCode {
    /// The 16-bit result code value. Spec: RFC 3244 §2.
    pub const fn value(self) -> u16 {
        match self {
            ResultCode::Success => KRB5_KPASSWD_SUCCESS,
            ResultCode::Failure(code) => code.value(),
        }
    }

    /// The code with this value; a value RFC 3244 §2 does not define
    /// (including 0xFFFF) ⇒ [`Error::UnknownResultCode`].
    ///
    /// Spec: RFC 3244 §2.
    pub fn from_value(value: u16) -> Result<Self> {
        match value {
            KRB5_KPASSWD_SUCCESS => Ok(ResultCode::Success),
            other => NonZeroResultCode::from_value(other).map(ResultCode::Failure),
        }
    }

    /// The result data for this code (the `user-data` of a reply's
    /// EncKrbPrivPart): the 16-bit result code, big-endian, result string
    /// omitted.
    ///
    /// Spec: RFC 3244 §2; docs/questions/Q-604 items 2, 5.
    pub const fn result_data(self) -> [u8; 2] {
        self.value().to_be_bytes()
    }

    /// Decode a reply KRB-PRIV's result data: exactly two octets
    /// ([`Error::ResultDataLength`]), a defined code.
    ///
    /// Spec: RFC 3244 §2; docs/questions/Q-604 item 5.
    pub fn from_result_data(data: &[u8]) -> Result<Self> {
        Self::from_value(result_code_value(data)?)
    }
}

impl From<NonZeroResultCode> for ResultCode {
    fn from(code: NonZeroResultCode) -> Self {
        ResultCode::Failure(code)
    }
}

/// Read result data that is exactly one big-endian 16-bit result code (no
/// result string — this project never sends one, Q-604 item 5).
/// Spec: RFC 3244 §2.
fn result_code_value(data: &[u8]) -> Result<u16> {
    match <[u8; 2]>::try_from(data) {
        Ok(octets) => Ok(u16::from_be_bytes(octets)),
        Err(_) => Err(Error::ResultDataLength),
    }
}
