//! The client/server (AP) exchange: AP-REQ, Authenticator, AP-REP,
//! EncAPRepPart.
//!
//! Spec: RFC 4120 5.5.1, 5.5.2; 5.10 (application tags 2, 14, 15, 27);
//! Appendix A.

use crate::basic::{
    AuthorizationData, Checksum, EncryptedData, EncryptionKey, KerberosTime, Microseconds,
    PrincipalName, Realm,
};
use crate::constants::{
    APP_AP_REP, APP_AP_REQ, APP_AUTHENTICATOR, APP_ENC_AP_REP_PART, KRB_AP_REP, KRB_AP_REQ, PVNO,
};
use crate::der::{self, app, ctx, int, Fields, SecretFields};
use crate::error::Result;
use crate::flags::ApOptions;
use crate::ticket::Ticket;
use parse_asn1::Value;

// ===========================================================================
// AP-REQ — RFC 4120 5.5.1
// ===========================================================================

/// ```text
/// AP-REQ          ::= [APPLICATION 14] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (14),
///         ap-options      [2] APOptions,
///         ticket          [3] Ticket,
///         authenticator   [4] EncryptedData -- Authenticator
/// }
/// ```
///
/// `pvno` and `msg-type` are fixed by the type: checked, written, not stored.
/// `authenticator` stays opaque (key usage 11, or 7 inside PA-TGS-REQ).
///
/// Spec: RFC 4120 5.5.1, 5.10; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApReq {
    /// `ap-options [2] APOptions`.
    pub ap_options: ApOptions,
    /// `ticket [3] Ticket`.
    pub ticket: Ticket,
    /// `authenticator [4] EncryptedData`.
    pub authenticator: EncryptedData,
}

impl ApReq {
    const TAGS: &'static [u32] = &[0, 1, 2, 3, 4];

    /// Spec: RFC 4120 5.5.1, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let inner = der::application(value, APP_AP_REQ)?;
        let mut f = Fields::new(inner, Self::TAGS)?;
        der::pvno(f.required(0)?)?;
        der::msg_type(f.required(1)?, &[KRB_AP_REQ], KRB_AP_REQ)?;
        let ap_options = ApOptions::from_value(f.required(2)?)?;
        let ticket = Ticket::from_value(f.required(3)?)?;
        let authenticator = EncryptedData::from_value(f.required(4)?)?;
        f.finish()?;
        Ok(ApReq {
            ap_options,
            ticket,
            authenticator,
        })
    }

    /// Spec: RFC 4120 5.5.1, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(app(
            APP_AP_REQ,
            Value::Sequence(vec![
                ctx(0, int(PVNO)),
                ctx(1, int(KRB_AP_REQ)),
                ctx(2, self.ap_options.to_value()),
                ctx(3, self.ticket.to_value()?),
                ctx(4, self.authenticator.to_value()?),
            ]),
        ))
    }
}

der_codec!(ApReq, "AP-REQ");

// ===========================================================================
// Authenticator — RFC 4120 5.5.1
// ===========================================================================

/// ```text
/// Authenticator   ::= [APPLICATION 2] SEQUENCE  {
///         authenticator-vno       [0] INTEGER (5),
///         crealm                  [1] Realm,
///         cname                   [2] PrincipalName,
///         cksum                   [3] Checksum OPTIONAL,
///         cusec                   [4] Microseconds,
///         ctime                   [5] KerberosTime,
///         subkey                  [6] EncryptionKey OPTIONAL,
///         seq-number              [7] UInt32 OPTIONAL,
///         authorization-data      [8] AuthorizationData OPTIONAL
/// }
/// ```
///
/// The plaintext of an AP-REQ `authenticator`. `authenticator-vno` is fixed at
/// 5 (checked, written, not stored). May carry a `subkey`, so it is
/// decoded/encoded on the secret path. `seq-number` is a UInt32: negative
/// values are rejected (the 5.5.1 "MAY accept the equivalent negative number"
/// option is not taken); an omitted value is preserved as `None` (the
/// "omitted means zero" reading of 5.1.2 / 5.5.1 is the consumer's choice).
///
/// Spec: RFC 4120 5.5.1, 5.10; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticator {
    /// `crealm [1] Realm`.
    pub crealm: Realm,
    /// `cname [2] PrincipalName`.
    pub cname: PrincipalName,
    /// `cksum [3] Checksum OPTIONAL`.
    pub cksum: Option<Checksum>,
    /// `cusec [4] Microseconds`.
    pub cusec: Microseconds,
    /// `ctime [5] KerberosTime`.
    pub ctime: KerberosTime,
    /// `subkey [6] EncryptionKey OPTIONAL`.
    pub subkey: Option<EncryptionKey>,
    /// `seq-number [7] UInt32 OPTIONAL`.
    pub seq_number: Option<u32>,
    /// `authorization-data [8] AuthorizationData OPTIONAL`.
    pub authorization_data: Option<AuthorizationData>,
}

impl Authenticator {
    const TAGS: &'static [u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8];

    /// Spec: RFC 4120 5.5.1, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let inner = der::application(value, APP_AUTHENTICATOR)?;
        let mut f = Fields::new(inner, Self::TAGS)?;
        der::pvno(f.required(0)?)?;
        let crealm = Realm::from_value(f.required(1)?)?;
        let cname = PrincipalName::from_value(f.required(2)?)?;
        let cksum = f.optional(3).map(Checksum::from_value).transpose()?;
        let cusec = der::microseconds(f.required(4)?)?;
        let ctime = KerberosTime::from_value(f.required(5)?)?;
        let subkey = f.optional(6).map(EncryptionKey::from_value).transpose()?;
        let seq_number = f.optional(7).map(der::uint32).transpose()?;
        let authorization_data = f
            .optional(8)
            .map(AuthorizationData::from_value)
            .transpose()?;
        f.finish()?;
        Ok(Authenticator {
            crealm,
            cname,
            cksum,
            cusec,
            ctime,
            subkey,
            seq_number,
            authorization_data,
        })
    }

    /// Spec: RFC 4120 5.5.1, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        let mut f = SecretFields::new();
        f.push(ctx(0, int(PVNO)));
        f.push(ctx(1, self.crealm.to_value()));
        f.push(ctx(2, self.cname.to_value()?));
        if let Some(cksum) = &self.cksum {
            f.push(ctx(3, cksum.to_value()?));
        }
        f.push(ctx(4, self.cusec.to_value()));
        f.push(ctx(5, self.ctime.to_value()));
        if let Some(subkey) = &self.subkey {
            f.push(ctx(6, subkey.to_value()?));
        }
        if let Some(seq_number) = self.seq_number {
            f.push(ctx(7, int(seq_number.into())));
        }
        if let Some(authorization_data) = &self.authorization_data {
            f.push(ctx(8, authorization_data.to_value()?));
        }
        Ok(app(APP_AUTHENTICATOR, f.into_sequence()))
    }
}

der_codec_secret!(Authenticator, "Authenticator");

// ===========================================================================
// AP-REP — RFC 4120 5.5.2
// ===========================================================================

/// ```text
/// AP-REP          ::= [APPLICATION 15] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (15),
///         enc-part        [2] EncryptedData -- EncAPRepPart
/// }
/// ```
///
/// `pvno` and `msg-type` are fixed by the type. `enc-part` stays opaque
/// (key usage 12).
///
/// Spec: RFC 4120 5.5.2, 5.10; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApRep {
    /// `enc-part [2] EncryptedData`.
    pub enc_part: EncryptedData,
}

impl ApRep {
    const TAGS: &'static [u32] = &[0, 1, 2];

    /// Spec: RFC 4120 5.5.2, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let inner = der::application(value, APP_AP_REP)?;
        let mut f = Fields::new(inner, Self::TAGS)?;
        der::pvno(f.required(0)?)?;
        der::msg_type(f.required(1)?, &[KRB_AP_REP], KRB_AP_REP)?;
        let enc_part = EncryptedData::from_value(f.required(2)?)?;
        f.finish()?;
        Ok(ApRep { enc_part })
    }

    /// Spec: RFC 4120 5.5.2, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(app(
            APP_AP_REP,
            Value::Sequence(vec![
                ctx(0, int(PVNO)),
                ctx(1, int(KRB_AP_REP)),
                ctx(2, self.enc_part.to_value()?),
            ]),
        ))
    }
}

der_codec!(ApRep, "AP-REP");

// ===========================================================================
// EncAPRepPart — RFC 4120 5.5.2
// ===========================================================================

/// ```text
/// EncAPRepPart    ::= [APPLICATION 27] SEQUENCE {
///         ctime           [0] KerberosTime,
///         cusec           [1] Microseconds,
///         subkey          [2] EncryptionKey OPTIONAL,
///         seq-number      [3] UInt32 OPTIONAL
/// }
/// ```
///
/// May carry a `subkey`: decoded/encoded on the secret path.
///
/// Spec: RFC 4120 5.5.2, 5.10; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncApRepPart {
    /// `ctime [0] KerberosTime`.
    pub ctime: KerberosTime,
    /// `cusec [1] Microseconds`.
    pub cusec: Microseconds,
    /// `subkey [2] EncryptionKey OPTIONAL`.
    pub subkey: Option<EncryptionKey>,
    /// `seq-number [3] UInt32 OPTIONAL`.
    pub seq_number: Option<u32>,
}

impl EncApRepPart {
    const TAGS: &'static [u32] = &[0, 1, 2, 3];

    /// Spec: RFC 4120 5.5.2, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let inner = der::application(value, APP_ENC_AP_REP_PART)?;
        let mut f = Fields::new(inner, Self::TAGS)?;
        let ctime = KerberosTime::from_value(f.required(0)?)?;
        let cusec = der::microseconds(f.required(1)?)?;
        let subkey = f.optional(2).map(EncryptionKey::from_value).transpose()?;
        let seq_number = f.optional(3).map(der::uint32).transpose()?;
        f.finish()?;
        Ok(EncApRepPart {
            ctime,
            cusec,
            subkey,
            seq_number,
        })
    }

    /// Spec: RFC 4120 5.5.2, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        let mut f = SecretFields::new();
        f.push(ctx(0, self.ctime.to_value()));
        f.push(ctx(1, self.cusec.to_value()));
        if let Some(subkey) = &self.subkey {
            f.push(ctx(2, subkey.to_value()?));
        }
        if let Some(seq_number) = self.seq_number {
            f.push(ctx(3, int(seq_number.into())));
        }
        Ok(app(APP_ENC_AP_REP_PART, f.into_sequence()))
    }
}

der_codec_secret!(EncApRepPart, "EncAPRepPart");
