//! The AS and TGS exchanges: KDC-REQ (AS-REQ, TGS-REQ), KDC-REQ-BODY, KDC-REP
//! (AS-REP, TGS-REP), EncKDCRepPart (EncASRepPart, EncTGSRepPart), LastReq.
//!
//! Spec: RFC 4120 5.4.1, 5.4.2; 5.10 (application tags 10-13, 25, 26);
//! Appendix A.
//!
//! Scope boundary: this module enforces the wire format (tags, order,
//! presence, value constraints). The protocol-processing rules that depend on
//! the exchange — e.g. `cname` "Used only in AS-REQ", `enc-authorization-data`
//! only in TGS-REQ, `sname` absent only with ENC-TKT-IN-SKEY, a TGS-REQ MUST
//! carry PA-TGS-REQ (RFC 4120 5.4.1) — are the KDC's checks, made on the typed
//! values decoded here.

use crate::basic::{
    padata_from_value, padata_to_value, EncryptedData, EncryptionKey, HostAddresses, KerberosTime,
    PaData, PrincipalName, Realm,
};
use crate::constants::{
    APP_AS_REP, APP_AS_REQ, APP_ENC_AS_REP_PART, APP_ENC_TGS_REP_PART, APP_TGS_REP, APP_TGS_REQ,
    KRB_AS_REP, KRB_AS_REQ, KRB_TGS_REP, KRB_TGS_REQ, PVNO,
};
use crate::der::{self, app, ctx, int, Fields, SecretFields};
use crate::error::{Error, Result};
use crate::flags::{KdcOptions, TicketFlags};
use crate::limits::{MAX_ADDITIONAL_TICKETS, MAX_ETYPES, MAX_LAST_REQ};
use crate::ticket::Ticket;
use parse_asn1::Value;

// ===========================================================================
// KDC-REQ-BODY — RFC 4120 5.4.1
// ===========================================================================

/// ```text
/// KDC-REQ-BODY    ::= SEQUENCE {
///         kdc-options             [0] KDCOptions,
///         cname                   [1] PrincipalName OPTIONAL
///                                     -- Used only in AS-REQ --,
///         realm                   [2] Realm
///                                     -- Server's realm
///                                     -- Also client's in AS-REQ --,
///         sname                   [3] PrincipalName OPTIONAL,
///         from                    [4] KerberosTime OPTIONAL,
///         till                    [5] KerberosTime,
///         rtime                   [6] KerberosTime OPTIONAL,
///         nonce                   [7] UInt32,
///         etype                   [8] SEQUENCE OF Int32 -- EncryptionType
///                                     -- in preference order --,
///         addresses               [9] HostAddresses OPTIONAL,
///         enc-authorization-data  [10] EncryptedData OPTIONAL
///                                     -- AuthorizationData --,
///         additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
///                                         -- NOTE: not empty
/// }
/// ```
///
/// Decoding is lossless (every accepted encoding re-encodes to the identical
/// octets), so `encode()` of a decoded body reproduces exactly the
/// KDC-REQ-BODY octets a checksum over the request is computed on
/// (RFC 4120 5.4.1 "req-body", 5.2.7.1). An empty `additional-tickets` or
/// `addresses` encoding is accepted and preserved (RFC 4120 5.1.3: equivalent
/// to absent). `etype` entries are raw Int32s in the client's preference
/// order; selecting an acceptable one is the KDC's policy.
///
/// Spec: RFC 4120 5.4.1; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KdcReqBody {
    /// `kdc-options [0] KDCOptions`.
    pub kdc_options: KdcOptions,
    /// `cname [1] PrincipalName OPTIONAL`.
    pub cname: Option<PrincipalName>,
    /// `realm [2] Realm`.
    pub realm: Realm,
    /// `sname [3] PrincipalName OPTIONAL`.
    pub sname: Option<PrincipalName>,
    /// `from [4] KerberosTime OPTIONAL`.
    pub from: Option<KerberosTime>,
    /// `till [5] KerberosTime`.
    pub till: KerberosTime,
    /// `rtime [6] KerberosTime OPTIONAL`.
    pub rtime: Option<KerberosTime>,
    /// `nonce [7] UInt32`.
    pub nonce: u32,
    /// `etype [8] SEQUENCE OF Int32`, bounded by
    /// [`crate::limits::MAX_ETYPES`].
    pub etype: Vec<i32>,
    /// `addresses [9] HostAddresses OPTIONAL`.
    pub addresses: Option<HostAddresses>,
    /// `enc-authorization-data [10] EncryptedData OPTIONAL`.
    pub enc_authorization_data: Option<EncryptedData>,
    /// `additional-tickets [11] SEQUENCE OF Ticket OPTIONAL`, bounded by
    /// [`crate::limits::MAX_ADDITIONAL_TICKETS`].
    pub additional_tickets: Option<Vec<Ticket>>,
}

impl KdcReqBody {
    const TAGS: &'static [u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    /// Spec: RFC 4120 5.4.1.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let kdc_options = KdcOptions::from_value(f.required(0)?)?;
        let cname = f.optional(1).map(PrincipalName::from_value).transpose()?;
        let realm = Realm::from_value(f.required(2)?)?;
        let sname = f.optional(3).map(PrincipalName::from_value).transpose()?;
        let from = f.optional(4).map(KerberosTime::from_value).transpose()?;
        let till = KerberosTime::from_value(f.required(5)?)?;
        let rtime = f.optional(6).map(KerberosTime::from_value).transpose()?;
        let nonce = der::uint32(f.required(7)?)?;
        let etype = der::decode_sequence_of(f.required(8)?, MAX_ETYPES, der::int32)?;
        let addresses = f.optional(9).map(HostAddresses::from_value).transpose()?;
        let enc_authorization_data = f.optional(10).map(EncryptedData::from_value).transpose()?;
        let additional_tickets = f
            .optional(11)
            .map(|v| der::decode_sequence_of(v, MAX_ADDITIONAL_TICKETS, Ticket::from_value))
            .transpose()?;
        f.finish()?;
        Ok(KdcReqBody {
            kdc_options,
            cname,
            realm,
            sname,
            from,
            till,
            rtime,
            nonce,
            etype,
            addresses,
            enc_authorization_data,
            additional_tickets,
        })
    }

    /// Spec: RFC 4120 5.4.1.
    pub(crate) fn to_value(&self) -> Result<Value> {
        let mut items = vec![ctx(0, self.kdc_options.to_value())];
        if let Some(cname) = &self.cname {
            items.push(ctx(1, cname.to_value()?));
        }
        items.push(ctx(2, self.realm.to_value()));
        if let Some(sname) = &self.sname {
            items.push(ctx(3, sname.to_value()?));
        }
        if let Some(from) = &self.from {
            items.push(ctx(4, from.to_value()));
        }
        items.push(ctx(5, self.till.to_value()));
        if let Some(rtime) = &self.rtime {
            items.push(ctx(6, rtime.to_value()));
        }
        items.push(ctx(7, int(self.nonce.into())));
        items.push(ctx(
            8,
            der::encode_sequence_of(&self.etype, MAX_ETYPES, |e| Ok(int((*e).into())))?,
        ));
        if let Some(addresses) = &self.addresses {
            items.push(ctx(9, addresses.to_value()?));
        }
        if let Some(enc) = &self.enc_authorization_data {
            items.push(ctx(10, enc.to_value()?));
        }
        if let Some(tickets) = &self.additional_tickets {
            items.push(ctx(
                11,
                der::encode_sequence_of(tickets, MAX_ADDITIONAL_TICKETS, Ticket::to_value)?,
            ));
        }
        Ok(Value::Sequence(items))
    }
}

der_codec!(KdcReqBody, "KDC-REQ-BODY");

// ===========================================================================
// KDC-REQ, AS-REQ, TGS-REQ — RFC 4120 5.4.1
// ===========================================================================

/// ```text
/// KDC-REQ         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         pvno            [1] INTEGER (5) ,
///         msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
///         padata          [3] SEQUENCE OF PA-DATA OPTIONAL
///                             -- NOTE: not empty --,
///         req-body        [4] KDC-REQ-BODY
/// }
/// ```
///
/// KDC-REQ has no application tag of its own; it is always carried as
/// [`AsReq`] (`[APPLICATION 10]`) or [`TgsReq`] (`[APPLICATION 12]`), which fix
/// `msg-type`. `pvno` and `msg-type` are therefore checked on decode, written
/// on encode, and not stored. `padata` is bounded by
/// [`crate::limits::MAX_PADATA`]; unknown padata-types are preserved
/// (RFC 4120 1.5.1); an empty encoding is accepted and preserved (5.1.3).
///
/// Spec: RFC 4120 5.4.1; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KdcReq {
    /// `padata [3] SEQUENCE OF PA-DATA OPTIONAL`.
    pub padata: Option<Vec<PaData>>,
    /// `req-body [4] KDC-REQ-BODY`.
    pub req_body: KdcReqBody,
}

impl KdcReq {
    // Spec: RFC 4120 5.4.1 — "first tag is [1], not [0]".
    const TAGS: &'static [u32] = &[1, 2, 3, 4];

    /// Decode the KDC-REQ SEQUENCE inside an application tag whose number
    /// implies `msg_type`. Spec: RFC 4120 5.4.1.
    fn from_value(value: &Value, msg_type: i64) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        der::pvno(f.required(1)?)?;
        der::msg_type(f.required(2)?, &[KRB_AS_REQ, KRB_TGS_REQ], msg_type)?;
        let padata = f.optional(3).map(padata_from_value).transpose()?;
        let req_body = KdcReqBody::from_value(f.required(4)?)?;
        f.finish()?;
        Ok(KdcReq { padata, req_body })
    }

    /// Spec: RFC 4120 5.4.1.
    fn to_value(&self, msg_type: i64) -> Result<Value> {
        let mut items = vec![ctx(1, int(PVNO)), ctx(2, int(msg_type))];
        if let Some(padata) = &self.padata {
            items.push(ctx(3, padata_to_value(padata)?));
        }
        items.push(ctx(4, self.req_body.to_value()?));
        Ok(Value::Sequence(items))
    }
}

/// `AS-REQ ::= [APPLICATION 10] KDC-REQ` (msg-type 10, KRB_AS_REQ).
///
/// Spec: RFC 4120 5.4.1, 5.10, 7.5.7; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AsReq(pub KdcReq);

impl AsReq {
    /// Spec: RFC 4120 5.4.1, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        KdcReq::from_value(der::application(value, APP_AS_REQ)?, KRB_AS_REQ).map(AsReq)
    }

    /// Spec: RFC 4120 5.4.1, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(app(APP_AS_REQ, self.0.to_value(KRB_AS_REQ)?))
    }
}

der_codec!(AsReq, "AS-REQ");

/// `TGS-REQ ::= [APPLICATION 12] KDC-REQ` (msg-type 12, KRB_TGS_REQ).
///
/// Spec: RFC 4120 5.4.1, 5.10, 7.5.7; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TgsReq(pub KdcReq);

impl TgsReq {
    /// Spec: RFC 4120 5.4.1, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        KdcReq::from_value(der::application(value, APP_TGS_REQ)?, KRB_TGS_REQ).map(TgsReq)
    }

    /// Spec: RFC 4120 5.4.1, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(app(APP_TGS_REQ, self.0.to_value(KRB_TGS_REQ)?))
    }
}

der_codec!(TgsReq, "TGS-REQ");

/// A request received by a KDC: either an AS-REQ or a TGS-REQ.
///
/// [`KdcRequest::decode`] dispatches on the application tag. Any other tag
/// (another Kerberos message, an unassigned number, or a number above 30) is
/// [`Error::UnexpectedApplicationTag`], so the KDC can answer
/// KRB_AP_ERR_MSG_TYPE over TCP or stay silent over UDP as RFC 4120 5.1.4
/// recommends; a non-application value is [`Error::ExpectedApplicationTag`].
///
/// Spec: RFC 4120 5.1.4, 5.1.5, 5.4.1, 5.10.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KdcRequest {
    /// `AS-REQ` (`[APPLICATION 10]`).
    As(AsReq),
    /// `TGS-REQ` (`[APPLICATION 12]`).
    Tgs(TgsReq),
}

impl KdcRequest {
    /// Spec: RFC 4120 5.1.4, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Application {
                number: APP_AS_REQ, ..
            } => AsReq::from_value(value).map(KdcRequest::As),
            Value::Application {
                number: APP_TGS_REQ,
                ..
            } => TgsReq::from_value(value).map(KdcRequest::Tgs),
            Value::Application { .. } => Err(Error::UnexpectedApplicationTag),
            _ => Err(Error::ExpectedApplicationTag),
        }
    }

    /// Spec: RFC 4120 5.4.1, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        match self {
            KdcRequest::As(req) => req.to_value(),
            KdcRequest::Tgs(req) => req.to_value(),
        }
    }
}

der_codec!(KdcRequest, "AS-REQ | TGS-REQ");

// ===========================================================================
// KDC-REP, AS-REP, TGS-REP — RFC 4120 5.4.2
// ===========================================================================

/// ```text
/// KDC-REP         ::= SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
///         padata          [2] SEQUENCE OF PA-DATA OPTIONAL
///                                 -- NOTE: not empty --,
///         crealm          [3] Realm,
///         cname           [4] PrincipalName,
///         ticket          [5] Ticket,
///         enc-part        [6] EncryptedData
///                                 -- EncASRepPart or EncTGSRepPart,
///                                 -- as appropriate
/// }
/// ```
///
/// Always carried as [`AsRep`] (`[APPLICATION 11]`) or [`TgsRep`]
/// (`[APPLICATION 13]`), which fix `msg-type`; `pvno` / `msg-type` are checked,
/// written, and not stored. `enc-part` stays opaque.
///
/// Spec: RFC 4120 5.4.2; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KdcRep {
    /// `padata [2] SEQUENCE OF PA-DATA OPTIONAL`.
    pub padata: Option<Vec<PaData>>,
    /// `crealm [3] Realm`.
    pub crealm: Realm,
    /// `cname [4] PrincipalName`.
    pub cname: PrincipalName,
    /// `ticket [5] Ticket`.
    pub ticket: Ticket,
    /// `enc-part [6] EncryptedData`.
    pub enc_part: EncryptedData,
}

impl KdcRep {
    const TAGS: &'static [u32] = &[0, 1, 2, 3, 4, 5, 6];

    /// Spec: RFC 4120 5.4.2.
    fn from_value(value: &Value, msg_type: i64) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        der::pvno(f.required(0)?)?;
        der::msg_type(f.required(1)?, &[KRB_AS_REP, KRB_TGS_REP], msg_type)?;
        let padata = f.optional(2).map(padata_from_value).transpose()?;
        let crealm = Realm::from_value(f.required(3)?)?;
        let cname = PrincipalName::from_value(f.required(4)?)?;
        let ticket = Ticket::from_value(f.required(5)?)?;
        let enc_part = EncryptedData::from_value(f.required(6)?)?;
        f.finish()?;
        Ok(KdcRep {
            padata,
            crealm,
            cname,
            ticket,
            enc_part,
        })
    }

    /// Spec: RFC 4120 5.4.2.
    fn to_value(&self, msg_type: i64) -> Result<Value> {
        let mut items = vec![ctx(0, int(PVNO)), ctx(1, int(msg_type))];
        if let Some(padata) = &self.padata {
            items.push(ctx(2, padata_to_value(padata)?));
        }
        items.push(ctx(3, self.crealm.to_value()));
        items.push(ctx(4, self.cname.to_value()?));
        items.push(ctx(5, self.ticket.to_value()?));
        items.push(ctx(6, self.enc_part.to_value()?));
        Ok(Value::Sequence(items))
    }
}

/// `AS-REP ::= [APPLICATION 11] KDC-REP` (msg-type 11, KRB_AS_REP).
///
/// Spec: RFC 4120 5.4.2, 5.10, 7.5.7; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AsRep(pub KdcRep);

impl AsRep {
    /// Spec: RFC 4120 5.4.2, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        KdcRep::from_value(der::application(value, APP_AS_REP)?, KRB_AS_REP).map(AsRep)
    }

    /// Spec: RFC 4120 5.4.2, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(app(APP_AS_REP, self.0.to_value(KRB_AS_REP)?))
    }
}

der_codec!(AsRep, "AS-REP");

/// `TGS-REP ::= [APPLICATION 13] KDC-REP` (msg-type 13, KRB_TGS_REP).
///
/// Spec: RFC 4120 5.4.2, 5.10, 7.5.7; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TgsRep(pub KdcRep);

impl TgsRep {
    /// Spec: RFC 4120 5.4.2, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        KdcRep::from_value(der::application(value, APP_TGS_REP)?, KRB_TGS_REP).map(TgsRep)
    }

    /// Spec: RFC 4120 5.4.2, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(app(APP_TGS_REP, self.0.to_value(KRB_TGS_REP)?))
    }
}

der_codec!(TgsRep, "TGS-REP");

// ===========================================================================
// LastReq — RFC 4120 5.4.2
// ===========================================================================

/// One element of LastReq (anonymous in RFC 4120):
///
/// ```text
/// SEQUENCE {
///         lr-type         [0] Int32,
///         lr-value        [1] KerberosTime
/// }
/// ```
///
/// Spec: RFC 4120 5.4.2; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LastReqEntry {
    /// `lr-type [0] Int32`.
    pub lr_type: i32,
    /// `lr-value [1] KerberosTime`.
    pub lr_value: KerberosTime,
}

impl LastReqEntry {
    const TAGS: &'static [u32] = &[0, 1];

    /// Spec: RFC 4120 5.4.2.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let lr_type = der::int32(f.required(0)?)?;
        let lr_value = KerberosTime::from_value(f.required(1)?)?;
        f.finish()?;
        Ok(LastReqEntry { lr_type, lr_value })
    }

    /// Spec: RFC 4120 5.4.2.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![
            ctx(0, int(self.lr_type.into())),
            ctx(1, self.lr_value.to_value()),
        ]))
    }
}

/// `LastReq ::= SEQUENCE OF SEQUENCE { lr-type, lr-value }`, bounded by
/// [`crate::limits::MAX_LAST_REQ`]. Required (not OPTIONAL) in EncKDCRepPart;
/// RFC 4120 places no minimum size on it, so an empty value is valid.
///
/// Spec: RFC 4120 5.4.2; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct LastReq(pub Vec<LastReqEntry>);

impl LastReq {
    /// Spec: RFC 4120 5.4.2.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        der::decode_sequence_of(value, MAX_LAST_REQ, LastReqEntry::from_value).map(LastReq)
    }

    /// Spec: RFC 4120 5.4.2.
    pub(crate) fn to_value(&self) -> Result<Value> {
        der::encode_sequence_of(&self.0, MAX_LAST_REQ, LastReqEntry::to_value)
    }
}

der_codec!(LastReq, "LastReq");

// ===========================================================================
// EncKDCRepPart, EncASRepPart, EncTGSRepPart — RFC 4120 5.4.2
// ===========================================================================

/// ```text
/// EncKDCRepPart   ::= SEQUENCE {
///         key             [0] EncryptionKey,
///         last-req        [1] LastReq,
///         nonce           [2] UInt32,
///         key-expiration  [3] KerberosTime OPTIONAL,
///         flags           [4] TicketFlags,
///         authtime        [5] KerberosTime,
///         starttime       [6] KerberosTime OPTIONAL,
///         endtime         [7] KerberosTime,
///         renew-till      [8] KerberosTime OPTIONAL,
///         srealm          [9] Realm,
///         sname           [10] PrincipalName,
///         caddr           [11] HostAddresses OPTIONAL
/// }
/// ```
///
/// Carried as [`EncAsRepPart`] (`[APPLICATION 25]`) or [`EncTgsRepPart`]
/// (`[APPLICATION 26]`). Holds the session key: decoded/encoded on the secret
/// path.
///
/// Spec: RFC 4120 5.4.2; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncKdcRepPart {
    /// `key [0] EncryptionKey` — the session key.
    pub key: EncryptionKey,
    /// `last-req [1] LastReq`.
    pub last_req: LastReq,
    /// `nonce [2] UInt32`.
    pub nonce: u32,
    /// `key-expiration [3] KerberosTime OPTIONAL`.
    pub key_expiration: Option<KerberosTime>,
    /// `flags [4] TicketFlags`.
    pub flags: TicketFlags,
    /// `authtime [5] KerberosTime`.
    pub authtime: KerberosTime,
    /// `starttime [6] KerberosTime OPTIONAL`.
    pub starttime: Option<KerberosTime>,
    /// `endtime [7] KerberosTime`.
    pub endtime: KerberosTime,
    /// `renew-till [8] KerberosTime OPTIONAL`.
    pub renew_till: Option<KerberosTime>,
    /// `srealm [9] Realm`.
    pub srealm: Realm,
    /// `sname [10] PrincipalName`.
    pub sname: PrincipalName,
    /// `caddr [11] HostAddresses OPTIONAL`.
    pub caddr: Option<HostAddresses>,
}

impl EncKdcRepPart {
    const TAGS: &'static [u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    /// Spec: RFC 4120 5.4.2.
    fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let key = EncryptionKey::from_value(f.required(0)?)?;
        let last_req = LastReq::from_value(f.required(1)?)?;
        let nonce = der::uint32(f.required(2)?)?;
        let key_expiration = f.optional(3).map(KerberosTime::from_value).transpose()?;
        let flags = TicketFlags::from_value(f.required(4)?)?;
        let authtime = KerberosTime::from_value(f.required(5)?)?;
        let starttime = f.optional(6).map(KerberosTime::from_value).transpose()?;
        let endtime = KerberosTime::from_value(f.required(7)?)?;
        let renew_till = f.optional(8).map(KerberosTime::from_value).transpose()?;
        let srealm = Realm::from_value(f.required(9)?)?;
        let sname = PrincipalName::from_value(f.required(10)?)?;
        let caddr = f.optional(11).map(HostAddresses::from_value).transpose()?;
        f.finish()?;
        Ok(EncKdcRepPart {
            key,
            last_req,
            nonce,
            key_expiration,
            flags,
            authtime,
            starttime,
            endtime,
            renew_till,
            srealm,
            sname,
            caddr,
        })
    }

    /// Spec: RFC 4120 5.4.2.
    fn to_value(&self) -> Result<Value> {
        let mut f = SecretFields::new();
        f.push(ctx(0, self.key.to_value()?));
        f.push(ctx(1, self.last_req.to_value()?));
        f.push(ctx(2, int(self.nonce.into())));
        if let Some(key_expiration) = &self.key_expiration {
            f.push(ctx(3, key_expiration.to_value()));
        }
        f.push(ctx(4, self.flags.to_value()));
        f.push(ctx(5, self.authtime.to_value()));
        if let Some(starttime) = &self.starttime {
            f.push(ctx(6, starttime.to_value()));
        }
        f.push(ctx(7, self.endtime.to_value()));
        if let Some(renew_till) = &self.renew_till {
            f.push(ctx(8, renew_till.to_value()));
        }
        f.push(ctx(9, self.srealm.to_value()));
        f.push(ctx(10, self.sname.to_value()?));
        if let Some(caddr) = &self.caddr {
            f.push(ctx(11, caddr.to_value()?));
        }
        Ok(f.into_sequence())
    }
}

/// `EncASRepPart ::= [APPLICATION 25] EncKDCRepPart`.
///
/// Decode requires tag 25 exactly: the RFC 4120 5.4.2 compatibility option to
/// "relax the check on the tag number" (accepting 26 here) is not taken.
///
/// Spec: RFC 4120 5.4.2, 5.10; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncAsRepPart(pub EncKdcRepPart);

impl EncAsRepPart {
    /// Spec: RFC 4120 5.4.2, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        EncKdcRepPart::from_value(der::application(value, APP_ENC_AS_REP_PART)?).map(EncAsRepPart)
    }

    /// Spec: RFC 4120 5.4.2, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(app(APP_ENC_AS_REP_PART, self.0.to_value()?))
    }
}

der_codec_secret!(EncAsRepPart, "EncASRepPart");

/// `EncTGSRepPart ::= [APPLICATION 26] EncKDCRepPart`.
///
/// Decode requires tag 26 exactly (see [`EncAsRepPart`]).
///
/// Spec: RFC 4120 5.4.2, 5.10; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncTgsRepPart(pub EncKdcRepPart);

impl EncTgsRepPart {
    /// Spec: RFC 4120 5.4.2, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        EncKdcRepPart::from_value(der::application(value, APP_ENC_TGS_REP_PART)?).map(EncTgsRepPart)
    }

    /// Spec: RFC 4120 5.4.2, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(app(APP_ENC_TGS_REP_PART, self.0.to_value()?))
    }
}

der_codec_secret!(EncTgsRepPart, "EncTGSRepPart");
