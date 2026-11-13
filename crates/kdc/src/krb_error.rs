//! Building the KRB-ERROR replies.
//!
//! Every KRB-ERROR the KDC sends (main-session decision 11):
//! - has NO e-text and no internal detail (docs/10 §9, docs/11 §8: the reason
//!   goes to audit only); e-data is present only for KDC_ERR_PREAUTH_REQUIRED,
//!   where RFC 4120 5.9.1 defines it as METHOD-DATA;
//! - takes stime from the caller's `now`; susec is 0, because `now` is a
//!   KerberosTime, which has whole seconds only (RFC 4120 5.2.3);
//! - carries realm / sname from the request when it decoded, otherwise the
//!   KDC's own realm and TGS name (RFC 4120 5.9.1 makes both fields mandatory
//!   but defines no value for "unknown"; this is the project's choice);
//! - carries crealm / cname only when the KDC knows them (5.9.1: "If the
//!   values are not known, the crealm and cname fields SHOULD be omitted");
//! - omits ctime / cusec: the KDC never sees the client's time in clear (it
//!   is inside PA-ENC-TIMESTAMP or the authenticator, which only keyd opens;
//!   5.9.1: "If the values are not available, these fields can be omitted").
//!
//! Spec: RFC 4120 5.9.1, 3.1.3, 3.1.4, 5.2.7.5, 7.5.9; main-session decision 11.

use crate::names::tgs_name;
use krb_proto::constants::{PA_ENC_TIMESTAMP, PA_ETYPE_INFO2};
use krb_proto::{
    EtypeInfo2, EtypeInfo2Entry, KerberosTime, KrbError, MethodData, Microseconds, PaData,
    PrincipalName, Realm,
};

/// The request-derived fields of a KRB-ERROR. Not secret.
/// Spec: RFC 4120 5.9.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ErrorContext {
    /// `realm [9]` — service realm.
    pub(crate) realm: Realm,
    /// `sname [10]` — service name.
    pub(crate) sname: PrincipalName,
    /// `crealm [7]`, when known.
    pub(crate) crealm: Option<Realm>,
    /// `cname [8]`, when known.
    pub(crate) cname: Option<PrincipalName>,
}

impl ErrorContext {
    /// The KDC's own realm and TGS name, no client: for requests whose names
    /// are not known. Spec: RFC 4120 5.9.1, 7.3.
    pub(crate) fn local(realm: &Realm) -> Option<Self> {
        Some(ErrorContext {
            realm: realm.clone(),
            sname: tgs_name(realm)?,
            crealm: None,
            cname: None,
        })
    }
}

/// Encode a KRB-ERROR with `code`. `None` only if encoding fails (the caller
/// then falls back to [`ErrorContext::local`]).
/// Spec: RFC 4120 5.9.1; main-session decision 11.
pub(crate) fn krb_error(
    code: i32,
    ctx: &ErrorContext,
    now: KerberosTime,
    e_data: Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    KrbError {
        ctime: None,
        cusec: None,
        stime: now,
        susec: Microseconds::default(),
        error_code: code,
        crealm: ctx.crealm.clone(),
        cname: ctx.cname.clone(),
        realm: ctx.realm.clone(),
        sname: ctx.sname.clone(),
        e_text: None,
        e_data,
    }
    .encode()
    .ok()
}

/// The e-data of KDC_ERR_PREAUTH_REQUIRED: METHOD-DATA advertising
/// PA-ENC-TIMESTAMP (the only method, with no data) and PA-ETYPE-INFO2 with
/// one entry per acceptable enctype, in the client's preference order.
///
/// PA-ETYPE-INFO and PA-PW-SALT are never sent: the client's list holds at
/// least one "newer" (AES) enctype whenever any entry exists, and then "it
/// MUST use PA-ETYPE-INFO2, not PA-ETYPE-INFO" (3.1.3) and "a KDC MUST NOT
/// send PA-PW-SALT" (5.2.7.3).
///
/// Spec: RFC 4120 3.1.3, 5.2.7.2-5.2.7.5, 5.9.1 (METHOD-DATA).
pub(crate) fn preauth_required_e_data(entries: Vec<EtypeInfo2Entry>) -> Option<Vec<u8>> {
    let etype_info2 = EtypeInfo2(entries).encode().ok()?;
    MethodData(vec![
        PaData {
            padata_type: PA_ENC_TIMESTAMP,
            padata_value: Vec::new(),
        },
        PaData {
            padata_type: PA_ETYPE_INFO2,
            padata_value: etype_info2,
        },
    ])
    .encode()
    .ok()
}
