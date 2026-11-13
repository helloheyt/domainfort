//! Kerberos FAST: the armored request and reply wrappers carried in PA-FX-FAST
//! padata, the armor, the inner request and response, KrbFastFinished, and the
//! encrypted challenge FAST factor.
//!
//! Spec: RFC 6113 5.2 (PA-FX-COOKIE), 5.4 (FAST padata), 5.4.1 / 5.4.1.1
//! (KrbFastArmor), 5.4.2 (PA-FX-FAST-REQUEST, KrbFastArmoredReq, KrbFastReq,
//! FastOptions), 5.4.3 (PA-FX-FAST-REPLY, KrbFastArmoredRep, KrbFastResponse,
//! KrbFastFinished), 5.4.4 (PA-FX-ERROR), 5.4.6 (EncryptedChallenge),
//! Appendix B (module `KerberosPreauthFramework`, "DEFINITIONS EXPLICIT
//! TAGS", importing the basic types from RFC 4120).
//!
//! # How FAST embeds in the RFC 4120 messages
//!
//! - In a KDC-REQ, a PA-DATA of type [`crate::constants::PA_FX_FAST`] carries
//!   the DER encoding of [`PaFxFastRequest`] (RFC 6113 5.4.2).
//! - In a KDC-REP, and in the METHOD-DATA of a KRB-ERROR `e-data`, a PA-DATA
//!   of the same type carries the DER encoding of [`PaFxFastReply`]
//!   (5.4.3, 5.4.4). When the KDC only advertises FAST, the pa-value is empty
//!   (5.4.2).
//! - The ciphertexts stay opaque here: `enc-fast-req` is a [`KrbFastReq`] and
//!   `enc-fast-rep` a [`KrbFastResponse`], encrypted in the armor key with key
//!   usages KEY_USAGE_FAST_ENC / KEY_USAGE_FAST_REP (6.2). This crate never
//!   encrypts, decrypts or computes checksums or the armor key; it decodes the
//!   plaintext types after keyd has decrypted them (docs/10, docs/30 §5).
//!
//! Two FAST padata values have no ASN.1 type of their own, so no type is
//! defined for them: the PA-FX-COOKIE value is "an opaque token" whose content
//! "is a local matter of the KDC" (5.2) and is carried as a [`PaData`]; the
//! PA-FX-ERROR value is the DER encoding of a KRB-ERROR (5.4.4) and is decoded
//! with [`crate::KrbError`].
//!
//! Not here: PA-AUTHENTICATION-SET / PA-AUTH-SET-SELECTED (5.3), the
//! AD-authentication-strength element (5.5) and the AD-fx-fast-armor /
//! AD-fx-fast-used authorization data (5.4.1.1, 5.4.2). An armored AS / TGS
//! exchange does not need them to be decoded here.
//!
//! # Strictness and extensibility
//!
//! The wire rules are those of the rest of the crate: strict DER (RFC 6113
//! asks for "the DER encoding" of each padata value, 5.4.1.1, 5.4.2, 5.4.3,
//! 5.4.6), explicit context tags in definition order, required vs OPTIONAL
//! components, Int32 / UInt32 / Microseconds ranges, bounded SEQUENCE OF.
//!
//! Every SEQUENCE and CHOICE in RFC 6113 Appendix B ends in an extension
//! marker (`...`), unlike the RFC 4120 module. This crate nevertheless rejects
//! an undefined component ([`Error::UnknownField`]) or CHOICE alternative
//! ([`Error::UnknownChoiceAlternative`]) — fail closed, as for every other
//! type here — pending docs/questions/Q-032. Typed holes are preserved: the
//! padata lists, armor-type / armor-value, and all 32 FastOptions bits.
//!
//! Scope boundary (as for KDC-REQ / KDC-REP): the processing rules that depend
//! on the exchange are made by the KDC / client on the decoded values, not
//! here — e.g. `armor` MUST be present in an AS request (5.4.2); an unknown
//! armor type is answered with KDC_ERR_PREAUTH_FAILED (5.4.1); the armor AP-REQ
//! MUST carry a subkey (5.4.1.1); an unsupported critical FastOptions bit is
//! answered with KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS (5.4.2);
//! `strengthen-key` MUST be present in a TGS reply and absent in an error, and
//! `finished` is present in an AS / TGS reply and absent in an error (5.4.3);
//! the reply `nonce` must match the request (5.4.3); the PA-FX-ERROR KRB-ERROR
//! has no e-data (5.4.4).

use crate::basic::{
    padata_from_value, padata_to_value, Checksum, EncryptedData, EncryptionKey, KerberosTime,
    Microseconds, PaData, PrincipalName, Realm,
};
use crate::der::{self, ctx, int, octet_string, octets, Fields, SecretFields};
use crate::error::{Error, Result};
use crate::flags::FastOptions;
use crate::kdc::KdcReqBody;
use parse_asn1::Value;

/// Context tag of `armored-data`, the only alternative of PA-FX-FAST-REQUEST
/// and of PA-FX-FAST-REPLY. Spec: RFC 6113 5.4.2, 5.4.3, Appendix B.
const ARMORED_DATA: u32 = 0;

/// Select the `armored-data [0]` alternative of a FAST CHOICE.
///
/// Under EXPLICIT TAGS the alternative is encoded as a constructed `[0]` whose
/// contents are the complete encoding of the chosen type, and a choice value
/// is encoded as its chosen alternative. Anything else — another class, or
/// another context tag number — selects no defined alternative.
/// Spec: RFC 6113 Appendix B; X.690 8.13, 8.14.3.
fn armored_data(value: &Value) -> Result<&Value> {
    match value {
        Value::ContextTag {
            number: ARMORED_DATA,
            inner,
        } => Ok(inner),
        _ => Err(Error::UnknownChoiceAlternative),
    }
}

// ===========================================================================
// KrbFastArmor — RFC 6113 5.4.1
// ===========================================================================

/// ```text
/// KrbFastArmor ::= SEQUENCE {
///     armor-type   [0] Int32,
///         -- Type of the armor.
///     armor-value  [1] OCTET STRING,
///         -- Value of the armor.
///     ...
/// }
/// ```
///
/// `armor-type` / `armor-value` are carried raw, so an unknown armor type is
/// preserved for the KDC to answer with KDC_ERR_PREAUTH_FAILED (RFC 6113
/// 5.4.1). For [`crate::constants::FX_FAST_ARMOR_AP_REQUEST`], `armor-value`
/// is the DER encoding of an AP-REQ (5.4.1.1); decode it with
/// [`crate::ApReq::decode`].
///
/// Spec: RFC 6113 5.4.1, 5.4.1.1, 7.2; Appendix B.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KrbFastArmor {
    /// `armor-type [0] Int32`.
    pub armor_type: i32,
    /// `armor-value [1] OCTET STRING`.
    pub armor_value: Vec<u8>,
}

impl KrbFastArmor {
    const TAGS: &'static [u32] = &[0, 1];

    /// Spec: RFC 6113 5.4.1.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let armor_type = der::int32(f.required(0)?)?;
        let armor_value = octet_string(f.required(1)?)?.to_vec();
        f.finish()?;
        Ok(KrbFastArmor {
            armor_type,
            armor_value,
        })
    }

    /// Spec: RFC 6113 5.4.1.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![
            ctx(0, int(self.armor_type.into())),
            ctx(1, octets(&self.armor_value)),
        ]))
    }
}

der_codec!(KrbFastArmor, "KrbFastArmor", "RFC 6113 Appendix B");

// ===========================================================================
// PA-FX-FAST-REQUEST, KrbFastArmoredReq — RFC 6113 5.4.2
// ===========================================================================

/// ```text
/// PA-FX-FAST-REQUEST ::= CHOICE {
///     armored-data [0] KrbFastArmoredReq,
///     ...
/// }
/// ```
///
/// The padata-value of a PA-FX-FAST padata in a KDC request. Any alternative
/// other than `armored-data [0]` is [`Error::UnknownChoiceAlternative`].
///
/// Spec: RFC 6113 5.4.2; Appendix B.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PaFxFastRequest {
    /// `armored-data [0] KrbFastArmoredReq`.
    ArmoredData(KrbFastArmoredReq),
}

impl PaFxFastRequest {
    /// Spec: RFC 6113 5.4.2.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        KrbFastArmoredReq::from_value(armored_data(value)?).map(PaFxFastRequest::ArmoredData)
    }

    /// Spec: RFC 6113 5.4.2.
    pub(crate) fn to_value(&self) -> Result<Value> {
        match self {
            PaFxFastRequest::ArmoredData(req) => Ok(ctx(ARMORED_DATA, req.to_value()?)),
        }
    }
}

der_codec!(PaFxFastRequest, "PA-FX-FAST-REQUEST", "RFC 6113 Appendix B");

/// ```text
/// KrbFastArmoredReq ::= SEQUENCE {
///     armor        [0] KrbFastArmor OPTIONAL,
///         -- Contains the armor that identifies the armor key.
///         -- MUST be present in AS-REQ.
///     req-checksum [1] Checksum,
///     enc-fast-req [2] EncryptedData, -- KrbFastReq --
///     ...
/// }
/// ```
///
/// `armor` is OPTIONAL on the wire (a TGS request normally omits it and uses
/// implicit armor, 5.4.2); "MUST be present in AS-REQ" is the KDC's check.
/// `req-checksum` and `enc-fast-req` are opaque here (armor key; key usages
/// KEY_USAGE_FAST_REQ_CHKSUM and KEY_USAGE_FAST_ENC, 6.2).
///
/// Spec: RFC 6113 5.4.2; Appendix B.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KrbFastArmoredReq {
    /// `armor [0] KrbFastArmor OPTIONAL`.
    pub armor: Option<KrbFastArmor>,
    /// `req-checksum [1] Checksum`.
    pub req_checksum: Checksum,
    /// `enc-fast-req [2] EncryptedData` — an encrypted [`KrbFastReq`].
    pub enc_fast_req: EncryptedData,
}

impl KrbFastArmoredReq {
    const TAGS: &'static [u32] = &[0, 1, 2];

    /// Spec: RFC 6113 5.4.2.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let armor = f.optional(0).map(KrbFastArmor::from_value).transpose()?;
        let req_checksum = Checksum::from_value(f.required(1)?)?;
        let enc_fast_req = EncryptedData::from_value(f.required(2)?)?;
        f.finish()?;
        Ok(KrbFastArmoredReq {
            armor,
            req_checksum,
            enc_fast_req,
        })
    }

    /// Spec: RFC 6113 5.4.2.
    pub(crate) fn to_value(&self) -> Result<Value> {
        let mut items = Vec::new();
        if let Some(armor) = &self.armor {
            items.push(ctx(0, armor.to_value()?));
        }
        items.push(ctx(1, self.req_checksum.to_value()?));
        items.push(ctx(2, self.enc_fast_req.to_value()?));
        Ok(Value::Sequence(items))
    }
}

der_codec!(
    KrbFastArmoredReq,
    "KrbFastArmoredReq",
    "RFC 6113 Appendix B"
);

// ===========================================================================
// KrbFastReq — RFC 6113 5.4.2
// ===========================================================================

/// ```text
/// KrbFastReq ::= SEQUENCE {
///     fast-options [0] FastOptions,
///         -- Additional options.
///     padata       [1] SEQUENCE OF PA-DATA,
///         -- padata typed holes.
///     req-body     [2] KDC-REQ-BODY,
///         -- Contains the KDC request body as defined in Section
///         -- 5.4.1 of [RFC4120].
///         -- This req-body field is preferred over the outer field
///         -- in the KDC request.
///      ...
/// }
/// ```
///
/// The plaintext of `enc-fast-req`. `padata` is not OPTIONAL and has no size
/// constraint, so an empty list is valid; it is bounded by
/// [`crate::limits::MAX_PADATA`] and unknown padata-types are preserved.
/// Decoding is lossless, so `req_body.encode()` reproduces the exact
/// KDC-REQ-BODY octets that checksums over the inner body are computed on
/// (5.4.2).
///
/// Spec: RFC 6113 5.4.2; Appendix B; RFC 4120 5.2.7, 5.4.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KrbFastReq {
    /// `fast-options [0] FastOptions`.
    pub fast_options: FastOptions,
    /// `padata [1] SEQUENCE OF PA-DATA`.
    pub padata: Vec<PaData>,
    /// `req-body [2] KDC-REQ-BODY`.
    pub req_body: KdcReqBody,
}

impl KrbFastReq {
    const TAGS: &'static [u32] = &[0, 1, 2];

    /// Spec: RFC 6113 5.4.2.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let fast_options = FastOptions::from_value(f.required(0)?)?;
        let padata = padata_from_value(f.required(1)?)?;
        let req_body = KdcReqBody::from_value(f.required(2)?)?;
        f.finish()?;
        Ok(KrbFastReq {
            fast_options,
            padata,
            req_body,
        })
    }

    /// Spec: RFC 6113 5.4.2.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![
            ctx(0, self.fast_options.to_value()),
            ctx(1, padata_to_value(&self.padata)?),
            ctx(2, self.req_body.to_value()?),
        ]))
    }
}

der_codec!(KrbFastReq, "KrbFastReq", "RFC 6113 Appendix B");

// ===========================================================================
// PA-FX-FAST-REPLY, KrbFastArmoredRep — RFC 6113 5.4.3
// ===========================================================================

/// ```text
/// PA-FX-FAST-REPLY ::= CHOICE {
///     armored-data [0] KrbFastArmoredRep,
///     ...
/// }
/// ```
///
/// The padata-value of a PA-FX-FAST padata in a KDC reply or in the
/// METHOD-DATA of a KRB-ERROR. Any alternative other than `armored-data [0]`
/// is [`Error::UnknownChoiceAlternative`].
///
/// Spec: RFC 6113 5.4.3, 5.4.4; Appendix B.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PaFxFastReply {
    /// `armored-data [0] KrbFastArmoredRep`.
    ArmoredData(KrbFastArmoredRep),
}

impl PaFxFastReply {
    /// Spec: RFC 6113 5.4.3.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        KrbFastArmoredRep::from_value(armored_data(value)?).map(PaFxFastReply::ArmoredData)
    }

    /// Spec: RFC 6113 5.4.3.
    pub(crate) fn to_value(&self) -> Result<Value> {
        match self {
            PaFxFastReply::ArmoredData(rep) => Ok(ctx(ARMORED_DATA, rep.to_value()?)),
        }
    }
}

der_codec!(PaFxFastReply, "PA-FX-FAST-REPLY", "RFC 6113 Appendix B");

/// ```text
/// KrbFastArmoredRep ::= SEQUENCE {
///     enc-fast-rep      [0] EncryptedData, -- KrbFastResponse --
///     ...
/// }
/// ```
///
/// `enc-fast-rep` is opaque here (armor key of the request; key usage
/// KEY_USAGE_FAST_REP, 6.2).
///
/// Spec: RFC 6113 5.4.3; Appendix B.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KrbFastArmoredRep {
    /// `enc-fast-rep [0] EncryptedData` — an encrypted [`KrbFastResponse`].
    pub enc_fast_rep: EncryptedData,
}

impl KrbFastArmoredRep {
    const TAGS: &'static [u32] = &[0];

    /// Spec: RFC 6113 5.4.3.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let enc_fast_rep = EncryptedData::from_value(f.required(0)?)?;
        f.finish()?;
        Ok(KrbFastArmoredRep { enc_fast_rep })
    }

    /// Spec: RFC 6113 5.4.3.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![ctx(0, self.enc_fast_rep.to_value()?)]))
    }
}

der_codec!(
    KrbFastArmoredRep,
    "KrbFastArmoredRep",
    "RFC 6113 Appendix B"
);

// ===========================================================================
// KrbFastResponse — RFC 6113 5.4.3
// ===========================================================================

/// ```text
/// KrbFastResponse ::= SEQUENCE {
///     padata         [0] SEQUENCE OF PA-DATA,
///         -- padata typed holes.
///     strengthen-key [1] EncryptionKey OPTIONAL,
///         -- This, if present, strengthens the reply key for AS and
///         -- TGS. MUST be present for TGS.
///         -- MUST be absent in KRB-ERROR.
///     finished       [2] KrbFastFinished OPTIONAL,
///         -- Present in AS or TGS reply; absent otherwise.
///     nonce          [3] UInt32,
///         -- Nonce from the client request.
///     ...
/// }
/// ```
///
/// The plaintext of `enc-fast-rep`. It may carry `strengthen-key`, a random
/// key that is combined into the reply key (5.4.3), so it is decoded / encoded
/// on the secret path: the intermediate value trees are zeroized, `encode`
/// returns a `Zeroizing` buffer, and `Debug` redacts the key octets. `padata`
/// (which in an error carries PA-FX-ERROR, the cookie and PA-ETYPE-INFO2,
/// 5.4.4) is bounded by [`crate::limits::MAX_PADATA`]; unknown padata-types
/// are preserved.
///
/// Spec: RFC 6113 5.4.3, 5.4.4; Appendix B; RFC 4120 5.2.9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrbFastResponse {
    /// `padata [0] SEQUENCE OF PA-DATA`.
    pub padata: Vec<PaData>,
    /// `strengthen-key [1] EncryptionKey OPTIONAL` — key material.
    pub strengthen_key: Option<EncryptionKey>,
    /// `finished [2] KrbFastFinished OPTIONAL`.
    pub finished: Option<KrbFastFinished>,
    /// `nonce [3] UInt32`.
    pub nonce: u32,
}

impl KrbFastResponse {
    const TAGS: &'static [u32] = &[0, 1, 2, 3];

    /// Spec: RFC 6113 5.4.3.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let padata = padata_from_value(f.required(0)?)?;
        let strengthen_key = f.optional(1).map(EncryptionKey::from_value).transpose()?;
        let finished = f.optional(2).map(KrbFastFinished::from_value).transpose()?;
        let nonce = der::uint32(f.required(3)?)?;
        f.finish()?;
        Ok(KrbFastResponse {
            padata,
            strengthen_key,
            finished,
            nonce,
        })
    }

    /// Spec: RFC 6113 5.4.3. Built in [`SecretFields`] (the strengthen-key
    /// copy is scrubbed on every path); `encode` scrubs the finished tree.
    pub(crate) fn to_value(&self) -> Result<Value> {
        let mut f = SecretFields::new();
        f.push(ctx(0, padata_to_value(&self.padata)?));
        if let Some(strengthen_key) = &self.strengthen_key {
            f.push(ctx(1, strengthen_key.to_value()?));
        }
        if let Some(finished) = &self.finished {
            f.push(ctx(2, finished.to_value()?));
        }
        f.push(ctx(3, int(self.nonce.into())));
        Ok(f.into_sequence())
    }
}

der_codec_secret!(KrbFastResponse, "KrbFastResponse", "RFC 6113 Appendix B");

// ===========================================================================
// KrbFastFinished — RFC 6113 5.4.3
// ===========================================================================

/// ```text
/// KrbFastFinished ::= SEQUENCE {
///     timestamp       [0] KerberosTime,
///     usec            [1] Microseconds,
///         -- timestamp and usec represent the time on the KDC when
///         -- the reply was generated.
///     crealm          [2] Realm,
///     cname           [3] PrincipalName,
///         -- Contains the client realm and the client name.
///     ticket-checksum [4] Checksum,
///         -- checksum of the ticket in the KDC-REP using the armor
///         -- and the key usage is KEY_USAGE_FAST_FINISH.
///         -- The checksum type is the required checksum type
///         -- of the armor key.
///     ...
/// }
/// ```
///
/// `ticket-checksum` is opaque here (armor key; key usage
/// KEY_USAGE_FAST_FINISHED, 5.4.3 / 6.2).
///
/// Spec: RFC 6113 5.4.3; Appendix B; RFC 4120 5.2.3, 5.2.4, 5.6.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KrbFastFinished {
    /// `timestamp [0] KerberosTime`.
    pub timestamp: KerberosTime,
    /// `usec [1] Microseconds`.
    pub usec: Microseconds,
    /// `crealm [2] Realm`.
    pub crealm: Realm,
    /// `cname [3] PrincipalName`.
    pub cname: PrincipalName,
    /// `ticket-checksum [4] Checksum`.
    pub ticket_checksum: Checksum,
}

impl KrbFastFinished {
    const TAGS: &'static [u32] = &[0, 1, 2, 3, 4];

    /// Spec: RFC 6113 5.4.3.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let mut f = Fields::new(value, Self::TAGS)?;
        let timestamp = KerberosTime::from_value(f.required(0)?)?;
        let usec = der::microseconds(f.required(1)?)?;
        let crealm = Realm::from_value(f.required(2)?)?;
        let cname = PrincipalName::from_value(f.required(3)?)?;
        let ticket_checksum = Checksum::from_value(f.required(4)?)?;
        f.finish()?;
        Ok(KrbFastFinished {
            timestamp,
            usec,
            crealm,
            cname,
            ticket_checksum,
        })
    }

    /// Spec: RFC 6113 5.4.3.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(Value::Sequence(vec![
            ctx(0, self.timestamp.to_value()),
            ctx(1, self.usec.to_value()),
            ctx(2, self.crealm.to_value()),
            ctx(3, self.cname.to_value()?),
            ctx(4, self.ticket_checksum.to_value()?),
        ]))
    }
}

der_codec!(KrbFastFinished, "KrbFastFinished", "RFC 6113 Appendix B");

// ===========================================================================
// EncryptedChallenge — RFC 6113 5.4.6
// ===========================================================================

/// ```text
/// EncryptedChallenge ::= EncryptedData
///         -- Encrypted PA-ENC-TS-ENC, encrypted in the challenge key
///         -- using key usage KEY_USAGE_ENC_CHALLENGE_CLIENT for the
///         -- client and KEY_USAGE_ENC_CHALLENGE_KDC for the KDC.
/// ```
///
/// The padata-value of a PA-ENCRYPTED-CHALLENGE FAST factor, sent inside
/// KrbFastReq / KrbFastResponse `padata`. The plaintext is a
/// [`crate::PaEncTsEnc`] (RFC 4120 5.2.7.2); this crate never derives the
/// challenge key or decrypts.
///
/// Spec: RFC 6113 5.4.6, 6.2; Appendix B.
pub type EncryptedChallenge = EncryptedData;
