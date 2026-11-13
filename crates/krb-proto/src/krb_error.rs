//! KRB-ERROR and METHOD-DATA.
//!
//! Spec: RFC 4120 5.9.1; 5.10 (application tag 30); Appendix A.

use crate::basic::{
    padata_from_value, padata_to_value, KerberosString, KerberosTime, Microseconds, PaData,
    PrincipalName, Realm,
};
use crate::constants::{APP_KRB_ERROR, KRB_ERROR, PVNO};
use crate::der::{self, app, ctx, int, octet_string, octets, Fields};
use crate::error::Result;
use parse_asn1::Value;

/// ```text
/// KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (30),
///         ctime           [2] KerberosTime OPTIONAL,
///         cusec           [3] Microseconds OPTIONAL,
///         stime           [4] KerberosTime,
///         susec           [5] Microseconds,
///         error-code      [6] Int32,
///         crealm          [7] Realm OPTIONAL,
///         cname           [8] PrincipalName OPTIONAL,
///         realm           [9] Realm -- service realm --,
///         sname           [10] PrincipalName -- service name --,
///         e-text          [11] KerberosString OPTIONAL,
///         e-data          [12] OCTET STRING OPTIONAL
/// }
/// ```
///
/// `pvno` and `msg-type` are fixed by the type (checked, written, not stored).
/// `e-data` is carried raw: for KDC_ERR_PREAUTH_REQUIRED it holds a
/// DER-encoded [`MethodData`] (decode it with [`MethodData::decode`]); for
/// other codes its format is implementation-defined (RFC 4120 5.9.1).
/// KRB-ERROR is not integrity protected; its fields must not be used for
/// security-critical decisions (RFC 4120 5.9).
///
/// Spec: RFC 4120 5.9, 5.9.1, 5.10, 7.5.9; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KrbError {
    /// `ctime [2] KerberosTime OPTIONAL`.
    pub ctime: Option<KerberosTime>,
    /// `cusec [3] Microseconds OPTIONAL`.
    pub cusec: Option<Microseconds>,
    /// `stime [4] KerberosTime`.
    pub stime: KerberosTime,
    /// `susec [5] Microseconds`.
    pub susec: Microseconds,
    /// `error-code [6] Int32` (see the error constants in
    /// [`crate::constants`]).
    pub error_code: i32,
    /// `crealm [7] Realm OPTIONAL`.
    pub crealm: Option<Realm>,
    /// `cname [8] PrincipalName OPTIONAL`.
    pub cname: Option<PrincipalName>,
    /// `realm [9] Realm` — service realm.
    pub realm: Realm,
    /// `sname [10] PrincipalName` — service name.
    pub sname: PrincipalName,
    /// `e-text [11] KerberosString OPTIONAL`.
    pub e_text: Option<KerberosString>,
    /// `e-data [12] OCTET STRING OPTIONAL`.
    pub e_data: Option<Vec<u8>>,
}

impl KrbError {
    const TAGS: &'static [u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    /// Spec: RFC 4120 5.9.1, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let inner = der::application(value, APP_KRB_ERROR)?;
        let mut f = Fields::new(inner, Self::TAGS)?;
        der::pvno(f.required(0)?)?;
        der::msg_type(f.required(1)?, &[KRB_ERROR], KRB_ERROR)?;
        let ctime = f.optional(2).map(KerberosTime::from_value).transpose()?;
        let cusec = f.optional(3).map(der::microseconds).transpose()?;
        let stime = KerberosTime::from_value(f.required(4)?)?;
        let susec = der::microseconds(f.required(5)?)?;
        let error_code = der::int32(f.required(6)?)?;
        let crealm = f.optional(7).map(Realm::from_value).transpose()?;
        let cname = f.optional(8).map(PrincipalName::from_value).transpose()?;
        let realm = Realm::from_value(f.required(9)?)?;
        let sname = PrincipalName::from_value(f.required(10)?)?;
        let e_text = f.optional(11).map(KerberosString::from_value).transpose()?;
        let e_data = f
            .optional(12)
            .map(|v| octet_string(v).map(<[u8]>::to_vec))
            .transpose()?;
        f.finish()?;
        Ok(KrbError {
            ctime,
            cusec,
            stime,
            susec,
            error_code,
            crealm,
            cname,
            realm,
            sname,
            e_text,
            e_data,
        })
    }

    /// Spec: RFC 4120 5.9.1, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        let mut items = vec![ctx(0, int(PVNO)), ctx(1, int(KRB_ERROR))];
        if let Some(ctime) = &self.ctime {
            items.push(ctx(2, ctime.to_value()));
        }
        if let Some(cusec) = self.cusec {
            items.push(ctx(3, cusec.to_value()));
        }
        items.push(ctx(4, self.stime.to_value()));
        items.push(ctx(5, self.susec.to_value()));
        items.push(ctx(6, int(self.error_code.into())));
        if let Some(crealm) = &self.crealm {
            items.push(ctx(7, crealm.to_value()));
        }
        if let Some(cname) = &self.cname {
            items.push(ctx(8, cname.to_value()?));
        }
        items.push(ctx(9, self.realm.to_value()));
        items.push(ctx(10, self.sname.to_value()?));
        if let Some(e_text) = &self.e_text {
            items.push(ctx(11, e_text.to_value()));
        }
        if let Some(e_data) = &self.e_data {
            items.push(ctx(12, octets(e_data)));
        }
        Ok(app(APP_KRB_ERROR, Value::Sequence(items)))
    }
}

der_codec!(KrbError, "KRB-ERROR");

/// `METHOD-DATA ::= SEQUENCE OF PA-DATA`, bounded by
/// [`crate::limits::MAX_PADATA`].
///
/// Carried in KRB-ERROR `e-data` when the error code is
/// KDC_ERR_PREAUTH_REQUIRED: one PA-DATA per acceptable pre-authentication
/// method. Unknown padata-types are preserved (RFC 4120 1.5.1).
///
/// Spec: RFC 4120 5.9.1; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct MethodData(pub Vec<PaData>);

impl MethodData {
    /// Spec: RFC 4120 5.9.1.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        padata_from_value(value).map(MethodData)
    }

    /// Spec: RFC 4120 5.9.1.
    pub(crate) fn to_value(&self) -> Result<Value> {
        padata_to_value(&self.0)
    }
}

der_codec!(MethodData, "METHOD-DATA");
