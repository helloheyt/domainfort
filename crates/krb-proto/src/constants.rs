//! Protocol constants, transcribed from the RFC 4120, RFC 6113 and RFC 3244
//! tables opened in-session.
//!
//! Names are the RFC's own labels with hyphens written as underscores
//! (docs/CLEAN-ROOM.md). Only the constants the in-scope messages (AS / TGS / AP /
//! KRB-PRIV / KRB-ERROR, FAST armoring of AS / TGS, and the RFC 3244 change
//! password user data) use are defined; values for out-of-scope or excluded
//! mechanisms (e.g. PA-PW-SALT, PA-ETYPE-INFO, KRB-SAFE / KRB-CRED, the
//! RFC 6113 5.3 authentication sets) are deliberately absent. Key usage
//! numbers (RFC 4120 7.5.1, RFC 6113 6.2) belong to the crypto layer and are
//! not defined here.
//!
//! Spec: RFC 4120 5.10, 7.5.2, 7.5.5, 7.5.6, 7.5.7, 7.5.8, 7.5.9; RFC 6113
//! 6.1, 6.4, 7.1, 7.2; RFC 3244 §2.

// --- Protocol version number. Spec: RFC 4120 7.5.6; 5.2.4. -------------------

/// Current Kerberos protocol version number (`pvno`, also `tkt-vno` and
/// `authenticator-vno`). Spec: RFC 4120 7.5.6, 5.2.4.
pub const PVNO: i64 = 5;

// --- Message types. Spec: RFC 4120 7.5.7 (equal to the 5.10 tag numbers). ----

/// Request for initial authentication. Spec: RFC 4120 7.5.7.
pub const KRB_AS_REQ: i64 = 10;
/// Response to KRB_AS_REQ request. Spec: RFC 4120 7.5.7.
pub const KRB_AS_REP: i64 = 11;
/// Request for authentication based on TGT. Spec: RFC 4120 7.5.7.
pub const KRB_TGS_REQ: i64 = 12;
/// Response to KRB_TGS_REQ request. Spec: RFC 4120 7.5.7.
pub const KRB_TGS_REP: i64 = 13;
/// Application request to server. Spec: RFC 4120 7.5.7.
pub const KRB_AP_REQ: i64 = 14;
/// Response to KRB_AP_REQ_MUTUAL. Spec: RFC 4120 7.5.7.
pub const KRB_AP_REP: i64 = 15;
/// Private (encrypted) application message. Spec: RFC 4120 7.5.7.
pub const KRB_PRIV: i64 = 21;
/// Error response. Spec: RFC 4120 7.5.7.
pub const KRB_ERROR: i64 = 30;

// --- Application tag numbers of the in-scope types. Spec: RFC 4120 5.10. -----

/// `Ticket ::= [APPLICATION 1]`. Spec: RFC 4120 5.10, 5.3.
pub(crate) const APP_TICKET: u32 = 1;
/// `Authenticator ::= [APPLICATION 2]`. Spec: RFC 4120 5.10, 5.5.1.
pub(crate) const APP_AUTHENTICATOR: u32 = 2;
/// `EncTicketPart ::= [APPLICATION 3]`. Spec: RFC 4120 5.10, 5.3.
pub(crate) const APP_ENC_TICKET_PART: u32 = 3;
/// `AS-REQ ::= [APPLICATION 10]`. Spec: RFC 4120 5.10, 5.4.1.
pub(crate) const APP_AS_REQ: u32 = 10;
/// `AS-REP ::= [APPLICATION 11]`. Spec: RFC 4120 5.10, 5.4.2.
pub(crate) const APP_AS_REP: u32 = 11;
/// `TGS-REQ ::= [APPLICATION 12]`. Spec: RFC 4120 5.10, 5.4.1.
pub(crate) const APP_TGS_REQ: u32 = 12;
/// `TGS-REP ::= [APPLICATION 13]`. Spec: RFC 4120 5.10, 5.4.2.
pub(crate) const APP_TGS_REP: u32 = 13;
/// `AP-REQ ::= [APPLICATION 14]`. Spec: RFC 4120 5.10, 5.5.1.
pub(crate) const APP_AP_REQ: u32 = 14;
/// `AP-REP ::= [APPLICATION 15]`. Spec: RFC 4120 5.10, 5.5.2.
pub(crate) const APP_AP_REP: u32 = 15;
/// `EncASRepPart ::= [APPLICATION 25]`. Spec: RFC 4120 5.10, 5.4.2.
pub(crate) const APP_ENC_AS_REP_PART: u32 = 25;
/// `EncTGSRepPart ::= [APPLICATION 26]`. Spec: RFC 4120 5.10, 5.4.2.
pub(crate) const APP_ENC_TGS_REP_PART: u32 = 26;
/// `EncAPRepPart ::= [APPLICATION 27]`. Spec: RFC 4120 5.10, 5.5.2.
pub(crate) const APP_ENC_AP_REP_PART: u32 = 27;
/// `KRB-PRIV ::= [APPLICATION 21]`. Spec: RFC 4120 5.10, 5.7.1.
pub(crate) const APP_KRB_PRIV: u32 = 21;
/// `EncKrbPrivPart ::= [APPLICATION 28]`. Spec: RFC 4120 5.10, 5.7.1.
pub(crate) const APP_ENC_KRB_PRIV_PART: u32 = 28;
/// `KRB-ERROR ::= [APPLICATION 30]`. Spec: RFC 4120 5.10, 5.9.1.
pub(crate) const APP_KRB_ERROR: u32 = 30;

// --- Name types. Spec: RFC 4120 7.5.8 (also 6.2). ----------------------------

/// Name type not known. Spec: RFC 4120 7.5.8.
pub const KRB_NT_UNKNOWN: i32 = 0;
/// Just the name of the principal as in DCE, or for users. Spec: RFC 4120 7.5.8.
pub const KRB_NT_PRINCIPAL: i32 = 1;
/// Service and other unique instance (krbtgt). Spec: RFC 4120 7.5.8.
pub const KRB_NT_SRV_INST: i32 = 2;
/// Service with host name as instance. Spec: RFC 4120 7.5.8.
pub const KRB_NT_SRV_HST: i32 = 3;
/// Service with host as remaining components. Spec: RFC 4120 7.5.8.
pub const KRB_NT_SRV_XHST: i32 = 4;
/// Unique ID. Spec: RFC 4120 7.5.8.
pub const KRB_NT_UID: i32 = 5;
/// Encoded X.509 Distinguished name. Spec: RFC 4120 7.5.8.
pub const KRB_NT_X500_PRINCIPAL: i32 = 6;
/// Name in form of SMTP email name. Spec: RFC 4120 7.5.8.
pub const KRB_NT_SMTP_NAME: i32 = 7;
/// Enterprise name; may be mapped to principal name. Spec: RFC 4120 7.5.8.
pub const KRB_NT_ENTERPRISE: i32 = 10;

// --- Pre-authentication data types used by the in-scope exchanges. ----------
// Spec: RFC 4120 7.5.2, 5.2.7.

/// padata-value is the DER encoding of an AP-REQ. Spec: RFC 4120 7.5.2, 5.2.7.1.
pub const PA_TGS_REQ: i32 = 1;
/// padata-value is the DER encoding of PA-ENC-TIMESTAMP.
/// Spec: RFC 4120 7.5.2, 5.2.7.2.
pub const PA_ENC_TIMESTAMP: i32 = 2;
/// padata-value is the DER encoding of ETYPE-INFO2. Spec: RFC 4120 7.5.2, 5.2.7.5.
pub const PA_ETYPE_INFO2: i32 = 19;

// --- FAST pre-authentication data types. Spec: RFC 6113 6.4 (also 7.1). -----

/// Stateless cookie: padata-value is an opaque token the KDC issues and the
/// client copies unchanged into its next message (no ASN.1 type).
/// Spec: RFC 6113 5.2 ("PA-FX-COOKIE 133"), 6.4, 7.1.
pub const PA_FX_COOKIE: i32 = 133;
/// Kerberos FAST: padata-value is the DER encoding of PA-FX-FAST-REQUEST in a
/// request and of PA-FX-FAST-REPLY in a reply or KRB-ERROR METHOD-DATA; empty
/// when the KDC advertises FAST.
/// Spec: RFC 6113 5.4.2 ("PA-FX-FAST 136"), 5.4.3, 5.4.4, 6.4, 7.1.
pub const PA_FX_FAST: i32 = 136;
/// padata-value is the DER encoding of a KRB-ERROR (with e-data absent),
/// carried inside KrbFastResponse. Spec: RFC 6113 5.4.4 ("PA-FX-ERROR 137"),
/// 6.4, 7.1.
pub const PA_FX_ERROR: i32 = 137;
/// padata-value is the DER encoding of EncryptedChallenge.
/// Spec: RFC 6113 5.4.6 ("PA-ENCRYPTED-CHALLENGE 138"), 6.4, 7.1.
pub const PA_ENCRYPTED_CHALLENGE: i32 = 138;

// --- FAST armor types. Spec: RFC 6113 7.2 (also 5.4.1). ----------------------

/// Ticket-based armor: armor-value is the DER encoding of an AP-REQ.
/// Spec: RFC 6113 5.4.1 ("FX_FAST_ARMOR_AP_REQUEST 1"), 5.4.1.1, 7.2.
pub const FX_FAST_ARMOR_AP_REQUEST: i32 = 1;

// --- Transited encoding types. Spec: RFC 4120 7.5.5, 3.3.3.2. -----------------

/// The DOMAIN-X500-COMPRESS transited encoding. Spec: RFC 4120 7.5.5.
pub const DOMAIN_X500_COMPRESS: i32 = 1;

// --- Error codes. Spec: RFC 4120 7.5.9 (the complete table). -----------------

/// No error. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_NONE: i32 = 0;
/// Client's entry in database has expired. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_NAME_EXP: i32 = 1;
/// Server's entry in database has expired. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_SERVICE_EXP: i32 = 2;
/// Requested protocol version number not supported. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_BAD_PVNO: i32 = 3;
/// Client's key encrypted in old master key. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_C_OLD_MAST_KVNO: i32 = 4;
/// Server's key encrypted in old master key. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_S_OLD_MAST_KVNO: i32 = 5;
/// Client not found in Kerberos database. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;
/// Server not found in Kerberos database. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;
/// Multiple principal entries in database. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE: i32 = 8;
/// The client or server has a null key. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_NULL_KEY: i32 = 9;
/// Ticket not eligible for postdating. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_CANNOT_POSTDATE: i32 = 10;
/// Requested starttime is later than end time. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_NEVER_VALID: i32 = 11;
/// KDC policy rejects request. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_POLICY: i32 = 12;
/// KDC cannot accommodate requested option. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_BADOPTION: i32 = 13;
/// KDC has no support for encryption type. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_ETYPE_NOSUPP: i32 = 14;
/// KDC has no support for checksum type. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_SUMTYPE_NOSUPP: i32 = 15;
/// KDC has no support for padata type. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_PADATA_TYPE_NOSUPP: i32 = 16;
/// KDC has no support for transited type. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_TRTYPE_NOSUPP: i32 = 17;
/// Clients credentials have been revoked. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_CLIENT_REVOKED: i32 = 18;
/// Credentials for server have been revoked. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_SERVICE_REVOKED: i32 = 19;
/// TGT has been revoked. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_TGT_REVOKED: i32 = 20;
/// Client not yet valid; try again later. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_CLIENT_NOTYET: i32 = 21;
/// Server not yet valid; try again later. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_SERVICE_NOTYET: i32 = 22;
/// Password has expired; change password to reset. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_KEY_EXPIRED: i32 = 23;
/// Pre-authentication information was invalid. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
/// Additional pre-authentication required. Spec: RFC 4120 7.5.9, 5.9.1.
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
/// Requested server and ticket don't match. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_SERVER_NOMATCH: i32 = 26;
/// Server principal valid for user2user only. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_MUST_USE_USER2USER: i32 = 27;
/// KDC Policy rejects transited path. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_PATH_NOT_ACCEPTED: i32 = 28;
/// A service is not available. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_SVC_UNAVAILABLE: i32 = 29;
/// Integrity check on decrypted field failed. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_BAD_INTEGRITY: i32 = 31;
/// Ticket expired. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_TKT_EXPIRED: i32 = 32;
/// Ticket not yet valid. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_TKT_NYV: i32 = 33;
/// Request is a replay. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_REPEAT: i32 = 34;
/// The ticket isn't for us. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_NOT_US: i32 = 35;
/// Ticket and authenticator don't match. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_BADMATCH: i32 = 36;
/// Clock skew too great. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_SKEW: i32 = 37;
/// Incorrect net address. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_BADADDR: i32 = 38;
/// Protocol version mismatch. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_BADVERSION: i32 = 39;
/// Invalid msg type. Spec: RFC 4120 7.5.9, 5.1.4.
pub const KRB_AP_ERR_MSG_TYPE: i32 = 40;
/// Message stream modified. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_MODIFIED: i32 = 41;
/// Message out of order. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_BADORDER: i32 = 42;
/// Specified version of key is not available. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_BADKEYVER: i32 = 44;
/// Service key not available. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_NOKEY: i32 = 45;
/// Mutual authentication failed. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_MUT_FAIL: i32 = 46;
/// Incorrect message direction. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_BADDIRECTION: i32 = 47;
/// Alternative authentication method required. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_METHOD: i32 = 48;
/// Incorrect sequence number in message. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_BADSEQ: i32 = 49;
/// Inappropriate type of checksum in message. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_INAPP_CKSUM: i32 = 50;
/// Policy rejects transited path. Spec: RFC 4120 7.5.9.
pub const KRB_AP_PATH_NOT_ACCEPTED: i32 = 51;
/// Response too big for UDP; retry with TCP. Spec: RFC 4120 7.5.9.
pub const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;
/// Generic error (description in e-text). Spec: RFC 4120 7.5.9.
pub const KRB_ERR_GENERIC: i32 = 60;
/// Field is too long for this implementation. Spec: RFC 4120 7.5.9.
pub const KRB_ERR_FIELD_TOOLONG: i32 = 61;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERROR_CLIENT_NOT_TRUSTED: i32 = 62;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERROR_KDC_NOT_TRUSTED: i32 = 63;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERROR_INVALID_SIG: i32 = 64;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_KEY_TOO_WEAK: i32 = 65;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_CERTIFICATE_MISMATCH: i32 = 66;
/// No TGT available to validate USER-TO-USER. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_NO_TGT: i32 = 67;
/// Reserved for future use. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_WRONG_REALM: i32 = 68;
/// Ticket must be for USER-TO-USER. Spec: RFC 4120 7.5.9.
pub const KRB_AP_ERR_USER_TO_USER_REQUIRED: i32 = 69;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_CANT_VERIFY_CERTIFICATE: i32 = 70;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_INVALID_CERTIFICATE: i32 = 71;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_REVOKED_CERTIFICATE: i32 = 72;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_REVOCATION_STATUS_UNKNOWN: i32 = 73;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_REVOCATION_STATUS_UNAVAILABLE: i32 = 74;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_CLIENT_NAME_MISMATCH: i32 = 75;
/// Reserved for PKINIT. Spec: RFC 4120 7.5.9.
pub const KDC_ERR_KDC_NAME_MISMATCH: i32 = 76;

// --- FAST / pre-authentication framework error codes. Spec: RFC 6113 6.1 (the
// complete table). ------------------------------------------------------------

/// The conversation is too old and must restart. Spec: RFC 6113 5.2, 6.1.
pub const KDC_ERR_PREAUTH_EXPIRED: i32 = 90;
/// At least one more pre-authentication message is expected (sent with a
/// PA-FX-COOKIE). Spec: RFC 6113 5.2, 6.1.
pub const KDC_ERR_MORE_PREAUTH_DATA_REQUIRED: i32 = 91;
/// The PA-AUTH-SET-SELECTED does not match an offered authentication set.
/// Spec: RFC 6113 5.3, 6.1.
pub const KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET: i32 = 92;
/// The KDC does not support a critical FastOptions bit.
/// Spec: RFC 6113 5.4.2, 6.1.
pub const KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS: i32 = 93;

// --- Change-password result codes. Spec: RFC 3244 §2 (the table of defined
// codes; 0xFFFF "if the request fails for some other reason" is not defined
// here — this project never sends it, docs/questions/Q-604 item 4). ----------

/// Request succeeds; not allowed in a KRB-ERROR message. Spec: RFC 3244 §2.
pub const KRB5_KPASSWD_SUCCESS: u16 = 0;
/// Request fails due to being malformed. Spec: RFC 3244 §2.
pub const KRB5_KPASSWD_MALFORMED: u16 = 1;
/// Request fails due to a "hard" error in processing it. Spec: RFC 3244 §2.
pub const KRB5_KPASSWD_HARDERROR: u16 = 2;
/// Request fails due to an error in authentication processing.
/// Spec: RFC 3244 §2.
pub const KRB5_KPASSWD_AUTHERROR: u16 = 3;
/// Request fails due to a "soft" error in processing it. Spec: RFC 3244 §2.
pub const KRB5_KPASSWD_SOFTERROR: u16 = 4;
/// Requestor not authorized. Spec: RFC 3244 §2.
pub const KRB5_KPASSWD_ACCESSDENIED: u16 = 5;
/// Protocol version unsupported. Spec: RFC 3244 §2.
pub const KRB5_KPASSWD_BAD_VERSION: u16 = 6;
/// Initial flag required. Spec: RFC 3244 §2.
pub const KRB5_KPASSWD_INITIAL_FLAG_NEEDED: u16 = 7;
