//! Tickets: Ticket, EncTicketPart, TransitedEncoding.
//!
//! Spec: RFC 4120 5.3; 5.10 (application tags 1 and 3); Appendix A.

use crate::basic::{
    AuthorizationData, EncryptedData, EncryptionKey, HostAddresses, KerberosTime, PrincipalName,
    Realm,
};
use crate::constants::{APP_ENC_TICKET_PART, APP_TICKET};
use crate::der::{self, app, ctx, int, octet_string, octets, Fields, SecretFields};
use crate::error::Result;
use crate::flags::TicketFlags;
use parse_asn1::Value;

/// ```text
/// Ticket          ::= [APPLICATION 1] SEQUENCE {
///         tkt-vno         [0] INTEGER (5),
///         realm           [1] Realm,
///         sname           [2] PrincipalName,
///         enc-part        [3] EncryptedData -- EncTicketPart
/// }
/// ```
///
/// `tkt-vno` is fixed at 5: it is checked on decode, written on encode, and
/// not stored. `enc-part` stays opaque (encrypted under the server's key with
/// key usage 2; this crate never decrypts).
///
/// Spec: RFC 4120 5.3, 5.2.4, 7.5.1; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ticket {
    /// `realm [1] Realm`.
    pub realm: Realm,
    /// `sname [2] PrincipalName`.
    pub sname: PrincipalName,
    /// `enc-part [3] EncryptedData`.
    pub enc_part: EncryptedData,
}

impl Ticket {
    const TAGS: &'static [u32] = &[0, 1, 2, 3];

    /// Spec: RFC 4120 5.3, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let inner = der::application(value, APP_TICKET)?;
        let mut f = Fields::new(inner, Self::TAGS)?;
        der::pvno(f.required(0)?)?;
        let realm = Realm::from_value(f.required(1)?)?;
        let sname = PrincipalName::from_value(f.required(2)?)?;
        let enc_part = EncryptedData::from_value(f.required(3)?)?;
        f.finish()?;
        Ok(Ticket {
            realm,
            sname,
            enc_part,
        })
    }

    /// Spec: RFC 4120 5.3, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(app(
            APP_TICKET,
            Value::Sequence(vec![
                ctx(0, int(crate::constants::PVNO)),
                ctx(1, self.realm.to_value()),
                ctx(2, self.sname.to_value()?),
                ctx(3, self.enc_part.to_value()?),
            ]),
        ))
    }
}

der_codec!(Ticket, "Ticket");

/// ```text
/// TransitedEncoding       ::= SEQUENCE {
///         tr-type         [0] Int32 -- must be registered --,
///         contents        [1] OCTET STRING
/// }
/// ```
///
/// `contents` is opaque here; its interpretation (e.g. DOMAIN-X500-COMPRESS,
/// RFC 4120 3.3.3.2) belongs to the transited-policy logic.
///
/// Spec: RFC 4120 5.3, 3.3.3.2, 7.5.5; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransitedEncoding {
    /// `tr-type [0] Int32`.
    pub tr_type: i32,
    /// `contents [1] OCTET STRING`.
    pub contents: Vec<u8>,
}

impl TransitedEncoding {
    const TAGS: &'static [u32] = &[0, 1];

    /// Spec: RFC 4120 5.3.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let tr_type = der::int32(f.required(0)?)?;
        let contents = octet_string(f.required(1)?)?.to_vec();
        f.finish()?;
        Ok(TransitedEncoding { tr_type, contents })
    }

    /// Spec: RFC 4120 5.3.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![
            ctx(0, int(self.tr_type.into())),
            ctx(1, octets(&self.contents)),
        ]))
    }
}

der_codec!(TransitedEncoding, "TransitedEncoding");

/// ```text
/// EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
///         flags                   [0] TicketFlags,
///         key                     [1] EncryptionKey,
///         crealm                  [2] Realm,
///         cname                   [3] PrincipalName,
///         transited               [4] TransitedEncoding,
///         authtime                [5] KerberosTime,
///         starttime               [6] KerberosTime OPTIONAL,
///         endtime                 [7] KerberosTime,
///         renew-till              [8] KerberosTime OPTIONAL,
///         caddr                   [9] HostAddresses OPTIONAL,
///         authorization-data      [10] AuthorizationData OPTIONAL
/// }
/// ```
///
/// The plaintext of a Ticket's `enc-part`. It carries the session key, so it is
/// decoded/encoded on the secret path (intermediate trees zeroized; `encode`
/// returns a `Zeroizing` buffer). An empty `caddr` / `authorization-data`
/// encoding is accepted and preserved (RFC 4120 5.1.3: equivalent to absent).
///
/// Spec: RFC 4120 5.3, 5.10; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncTicketPart {
    /// `flags [0] TicketFlags`.
    pub flags: TicketFlags,
    /// `key [1] EncryptionKey` — the session key.
    pub key: EncryptionKey,
    /// `crealm [2] Realm`.
    pub crealm: Realm,
    /// `cname [3] PrincipalName`.
    pub cname: PrincipalName,
    /// `transited [4] TransitedEncoding`.
    pub transited: TransitedEncoding,
    /// `authtime [5] KerberosTime`.
    pub authtime: KerberosTime,
    /// `starttime [6] KerberosTime OPTIONAL`.
    pub starttime: Option<KerberosTime>,
    /// `endtime [7] KerberosTime`.
    pub endtime: KerberosTime,
    /// `renew-till [8] KerberosTime OPTIONAL`.
    pub renew_till: Option<KerberosTime>,
    /// `caddr [9] HostAddresses OPTIONAL`.
    pub caddr: Option<HostAddresses>,
    /// `authorization-data [10] AuthorizationData OPTIONAL`.
    pub authorization_data: Option<AuthorizationData>,
}

impl EncTicketPart {
    const TAGS: &'static [u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    /// Spec: RFC 4120 5.3, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let inner = der::application(value, APP_ENC_TICKET_PART)?;
        let mut f = Fields::new(inner, Self::TAGS)?;
        let flags = TicketFlags::from_value(f.required(0)?)?;
        let key = EncryptionKey::from_value(f.required(1)?)?;
        let crealm = Realm::from_value(f.required(2)?)?;
        let cname = PrincipalName::from_value(f.required(3)?)?;
        let transited = TransitedEncoding::from_value(f.required(4)?)?;
        let authtime = KerberosTime::from_value(f.required(5)?)?;
        let starttime = f.optional(6).map(KerberosTime::from_value).transpose()?;
        let endtime = KerberosTime::from_value(f.required(7)?)?;
        let renew_till = f.optional(8).map(KerberosTime::from_value).transpose()?;
        let caddr = f.optional(9).map(HostAddresses::from_value).transpose()?;
        let authorization_data = f
            .optional(10)
            .map(AuthorizationData::from_value)
            .transpose()?;
        f.finish()?;
        Ok(EncTicketPart {
            flags,
            key,
            crealm,
            cname,
            transited,
            authtime,
            starttime,
            endtime,
            renew_till,
            caddr,
            authorization_data,
        })
    }

    /// Spec: RFC 4120 5.3, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        let mut f = SecretFields::new();
        f.push(ctx(0, self.flags.to_value()));
        f.push(ctx(1, self.key.to_value()?));
        f.push(ctx(2, self.crealm.to_value()));
        f.push(ctx(3, self.cname.to_value()?));
        f.push(ctx(4, self.transited.to_value()?));
        f.push(ctx(5, self.authtime.to_value()));
        if let Some(starttime) = &self.starttime {
            f.push(ctx(6, starttime.to_value()));
        }
        f.push(ctx(7, self.endtime.to_value()));
        if let Some(renew_till) = &self.renew_till {
            f.push(ctx(8, renew_till.to_value()));
        }
        if let Some(caddr) = &self.caddr {
            f.push(ctx(9, caddr.to_value()?));
        }
        if let Some(authorization_data) = &self.authorization_data {
            f.push(ctx(10, authorization_data.to_value()?));
        }
        Ok(app(APP_ENC_TICKET_PART, f.into_sequence()))
    }
}

der_codec_secret!(EncTicketPart, "EncTicketPart");
