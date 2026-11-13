//! Building the KRB-ERROR replies.
//!
//! Every KRB-ERROR the KDC sends (main-session decision 11):
//! - has NO e-text and no internal detail (docs/10 §9, docs/11 §8: the reason
//!   goes to audit only); e-data is present only for KDC_ERR_PREAUTH_REQUIRED,
//!   where RFC 4120 5.9.1 defines it as METHOD-DATA, and for an armored
//!   error, whose e-data is METHOD-DATA with the PA-FX-FAST (RFC 6113 5.4.4,
//!   module `fast`);
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
//! Spec: RFC 4120 5.9.1, 3.1.3, 3.1.4, 5.2.7.5, 7.5.9; RFC 6113 5.2, 5.4.2,
//! 5.4.4; main-session decision 11.

use crate::fast::cookie_padata;
use crate::names::tgs_name;
use krb_proto::constants::{PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_FX_FAST};
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

/// The KRB-ERROR with `code` (the rules of the module docs). The same value,
/// without e-data, is what keyd seals as the PA-FX-ERROR of an armored error
/// ("All other fields should be the same as the outer KRB-ERROR", RFC 6113
/// 5.4.4).
/// Spec: RFC 4120 5.9.1; RFC 6113 5.4.4; main-session decision 11.
pub(crate) fn error_message(
    code: i32,
    ctx: &ErrorContext,
    now: KerberosTime,
    e_data: Option<Vec<u8>>,
) -> KrbError {
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
    error_message(code, ctx, now, e_data).encode().ok()
}

/// A padata with an empty value: the advertisement of a mechanism in
/// KDC_ERR_PREAUTH_REQUIRED. Spec: RFC 4120 5.9.1 ("each corresponding to an
/// acceptable pre-authentication method and optionally containing data for
/// the method"); RFC 6113 5.4.2 ("KDCs MUST send the advertisement of
/// PA-FX-FAST with an empty pa-value").
pub(crate) fn advertise(padata_type: i32) -> PaData {
    PaData {
        padata_type,
        padata_value: Vec::new(),
    }
}

/// PA-ETYPE-INFO2 with `entries`. `None` if `entries` is empty (ETYPE-INFO2
/// is SIZE (1..MAX)) or encoding fails. Spec: RFC 4120 5.2.7.5.
pub(crate) fn etype_info2(entries: Vec<EtypeInfo2Entry>) -> Option<PaData> {
    Some(PaData {
        padata_type: PA_ETYPE_INFO2,
        padata_value: EtypeInfo2(entries).encode().ok()?,
    })
}

/// The e-data of the unarmored KDC_ERR_PREAUTH_REQUIRED of a principal that
/// may bootstrap (a computer account, docs/48 §7.3): METHOD-DATA advertising
/// PA-FX-FAST (empty, RFC 6113 5.4.2 MUST), PA-ENC-TIMESTAMP (no data),
/// PA-ETYPE-INFO2 with one entry per acceptable enctype in the client's
/// preference order, and the PA-FX-COOKIE (RFC 6113 5.2: "a KDC MUST include
/// a cookie in a KDC_ERR_PREAUTH_REQUIRED").
///
/// PA-ETYPE-INFO and PA-PW-SALT are never sent: the client's list holds at
/// least one "newer" (AES) enctype whenever any entry exists, and then "it
/// MUST use PA-ETYPE-INFO2, not PA-ETYPE-INFO" (3.1.3) and "a KDC MUST NOT
/// send PA-PW-SALT" (5.2.7.3).
///
/// Spec: RFC 4120 3.1.3, 5.2.7.2-5.2.7.5, 5.9.1 (METHOD-DATA); RFC 6113
/// 5.2, 5.4.2; docs/48 §6.4, §7.3.
pub(crate) fn preauth_required_e_data(entries: Vec<EtypeInfo2Entry>) -> Option<Vec<u8>> {
    MethodData(vec![
        advertise(PA_FX_FAST),
        advertise(PA_ENC_TIMESTAMP),
        etype_info2(entries)?,
        cookie_padata(),
    ])
    .encode()
    .ok()
}

/// The e-data of a KDC_ERR_PREAUTH_REQUIRED that only points the client at
/// FAST: METHOD-DATA with PA-FX-FAST (empty) and the PA-FX-COOKIE — nothing
/// a passive observer could attack offline, and no PA-ENC-TIMESTAMP offered.
/// Sent to an unarmored AS request for a principal that must use FAST (the
/// layer-1 gate, docs/48 §7.2), and as the unarmored fallback of an armored
/// PREAUTH_REQUIRED that keyd could not seal (Q-125 item 10).
/// Spec: RFC 6113 5.2, 5.4.2, 5.4 (FAST against offline dictionary
/// attacks); docs/48 §7.2 ("advertising ONLY PA-FX-FAST (empty value) and
/// PA-FX-COOKIE").
pub(crate) fn fast_required_e_data() -> Option<Vec<u8>> {
    MethodData(vec![advertise(PA_FX_FAST), cookie_padata()])
        .encode()
        .ok()
}
