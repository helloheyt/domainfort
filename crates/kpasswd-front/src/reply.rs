//! The front's replies: the RFC 3244 reply message, framed for TCP — keyd's
//! sealed reply relayed unchanged, or the front's one KRB-ERROR.
//!
//! # The KRB-ERROR (docs/53 §5.7; docs/questions/Q-604 items 1, 5)
//!
//! One encoder for every KRB-ERROR the front sends — its own framing
//! answers (MALFORMED, BAD_VERSION), dird's unsealed codes (AUTHERROR,
//! HARDERROR) and HARDERROR when dird does not serve:
//!
//! | field (RFC 4120 §5.9.1) | value |
//! |---|---|
//! | `ctime`, `cusec`, `crealm`, `cname`, `e-text` | absent — the front decodes nothing of the request (docs/53 §5.1) and sends no text |
//! | `stime`, `susec` | the front's clock (crate::clock) |
//! | `error-code` | KRB_ERR_GENERIC (60) for all of them — RFC 3244 names none (RFC 4120 §7.5.9: "60 Generic error") |
//! | `realm` | the configured realm |
//! | `sname` | `kadmin/changepw`, name-type NT-SRV-INST (RFC 4120 §6.2: "the first component … identifies a service and the remaining components identify an instance") |
//! | `e-data` | the result data: the 2-octet result code, big-endian, **no result string** (RFC 3244 §2: "It may be omitted"; Q-604 item 5) |
//!
//! It goes in the reply message with `AP_REP length` 0 (RFC 3244 §2: "If the
//! length is zero, then the last field contains a KRB-ERROR message"; the
//! reading kept while docs/questions/Q-831 is open — parse-kpasswd's
//! `ReplyMessage::krb_error`).
//!
//! **Never result code 0.** RFC 3244 §2: SUCCESS "is not allowed in a
//! KRB-ERROR message". [`ReplyEncoder::krb_error`] takes a
//! [`NonZeroResultCode`], which cannot hold it (A-121; docs/questions/Q-620
//! item 6) — "success in an unauthenticated message" (the observed Windows
//! version-1 reply, docs/research/r3-e §3.2) has no code path here (A-142:
//! replies are always authenticated).
//!
//! **One copy of the service name (C14 residual).** keyd-types holds the
//! name keyd binds (`CHANGE_PASSWORD_SERVICE_NAME`); the front links no keyd
//! crate, so it writes the RFC 3244 §2 name once more here; a test pins the
//! two equal (docs/questions/Q-955 item 5). The KRB-ERROR's `sname` is
//! informational only (RFC 4120 §5.9: not integrity protected).
//!
//! Spec: RFC 3244 §2; RFC 4120 §5.9, §5.9.1, §6.2, §7.5.9; docs/53 §5.7;
//! docs/questions Q-604, Q-620, Q-831; A-121; A-142.

use crate::clock::ServerTime;
use core::fmt;
use ipc_kpasswd::{SealedReply, UnsealedCode};
use krb_proto::constants::{KRB_ERR_GENERIC, KRB_NT_SRV_INST};
use krb_proto::{KerberosString, KrbError, NonZeroResultCode, PrincipalName, Realm};
use parse_kpasswd::ReplyMessage;

/// The change-password service principal's name components (`kadmin`,
/// `changepw`).
/// Spec: RFC 3244 §2 ("the service principal kadmin/changepw@REALM").
pub const CHANGE_PASSWORD_SERVICE: [&str; 2] = ["kadmin", "changepw"];

/// dird's unsealed code as the RFC 3244 result code of the front's
/// KRB-ERROR.
/// Spec: RFC 3244 §2; docs/53 §5.7.
#[must_use]
pub const fn result_code_of(code: UnsealedCode) -> NonZeroResultCode {
    match code {
        UnsealedCode::HardError => NonZeroResultCode::HardError,
        UnsealedCode::AuthError => NonZeroResultCode::AuthError,
    }
}

// The channel's codes are RFC 3244's values (crates/ipc-kpasswd defines them
// without linking krb-proto; this crate links both and pins them).
const _: () = assert!(UnsealedCode::HardError.value() == NonZeroResultCode::HardError.value());
const _: () = assert!(UnsealedCode::AuthError.value() == NonZeroResultCode::AuthError.value());

/// The realm could not be used in a KRB-ERROR.
/// Spec: RFC 4120 §5.2.1, §5.2.2 (KerberosString / Realm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRealm;

impl fmt::Display for InvalidRealm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("realm is not a valid Kerberos realm")
    }
}

impl std::error::Error for InvalidRealm {}

/// The front's KRB-ERROR encoder: the realm and the service name, fixed at
/// start (module documentation).
/// Spec: docs/53 §5.7; RFC 4120 §5.9.1.
#[derive(Debug, Clone)]
pub struct ReplyEncoder {
    realm: Realm,
    sname: PrincipalName,
}

impl ReplyEncoder {
    /// The encoder for `realm` (re-validated as a KerberosString).
    ///
    /// # Errors
    /// [`InvalidRealm`].
    ///
    /// Spec: RFC 4120 §5.2.1, §5.2.2, §6.2; RFC 3244 §2.
    pub fn new(realm: &str) -> Result<ReplyEncoder, InvalidRealm> {
        if realm.is_empty() {
            return Err(InvalidRealm);
        }
        let realm = KerberosString::new(realm).map_err(|_| InvalidRealm)?;
        let mut name_string = Vec::with_capacity(CHANGE_PASSWORD_SERVICE.len());
        for component in CHANGE_PASSWORD_SERVICE {
            name_string.push(KerberosString::new(component).map_err(|_| InvalidRealm)?);
        }
        Ok(ReplyEncoder {
            realm,
            sname: PrincipalName {
                name_type: KRB_NT_SRV_INST,
                name_string,
            },
        })
    }

    /// The KRB-ERROR (module documentation) carrying `code`, at `time`.
    /// `None` only if the encoder refuses the value (cannot happen with the
    /// validated realm) — the caller then closes without a reply.
    /// Spec: RFC 3244 §2; RFC 4120 §5.9.1; docs/53 §5.7.
    #[must_use]
    pub fn krb_error_message(&self, code: NonZeroResultCode, time: ServerTime) -> Option<Vec<u8>> {
        KrbError {
            ctime: None,
            cusec: None,
            stime: time.stime,
            susec: time.susec,
            error_code: KRB_ERR_GENERIC,
            crealm: None,
            cname: None,
            realm: self.realm.clone(),
            sname: self.sname.clone(),
            e_text: None,
            e_data: Some(code.result_data().to_vec()),
        }
        .encode()
        .ok()
    }

    /// The TCP frame of the RFC 3244 reply carrying the KRB-ERROR of `code`
    /// (`AP_REP length` 0).
    ///
    /// SUCCESS cannot be asked for — the code type has no such value (RFC
    /// 3244 §2: "not allowed in a KRB-ERROR message"; A-121):
    ///
    /// ```compile_fail,E0308
    /// use kpasswd_front::reply::ReplyEncoder;
    /// let encoder = ReplyEncoder::new("EXAMPLE.TEST").unwrap();
    /// let time = kpasswd_front::clock::server_time_now().unwrap();
    /// let _ = encoder.krb_error(krb_proto::ResultCode::Success, time);
    /// ```
    ///
    /// A failure code builds:
    ///
    /// ```
    /// use kpasswd_front::reply::ReplyEncoder;
    /// let encoder = ReplyEncoder::new("EXAMPLE.TEST").unwrap();
    /// let time = kpasswd_front::clock::server_time_now().unwrap();
    /// let _ = encoder.krb_error(krb_proto::NonZeroResultCode::HardError, time);
    /// ```
    ///
    /// Spec: RFC 3244 §2 (reply message; TCP 4-octet header); docs/53 §5.7.
    #[must_use]
    pub fn krb_error(&self, code: NonZeroResultCode, time: ServerTime) -> Option<Vec<u8>> {
        let krb_error = self.krb_error_message(code, time)?;
        ReplyMessage::krb_error(&krb_error)
            .ok()
            .map(|reply| reply.encode_tcp())
    }
}

/// The TCP frame of the RFC 3244 reply carrying keyd's sealed reply — the
/// AP-REP and the KRB-PRIV unchanged (the front cannot read or alter what
/// they say: only the client holds the keys).
/// Spec: RFC 3244 §2 (reply message); docs/53 §5.5 ("`SealedReply { ap_rep,
/// krb_priv }` — the front frames it").
#[must_use]
pub fn sealed_reply(sealed: &SealedReply) -> Option<Vec<u8>> {
    ReplyMessage::ap_rep(sealed.ap_rep().as_bytes(), sealed.krb_priv().as_bytes())
        .ok()
        .map(|reply| reply.encode_tcp())
}
