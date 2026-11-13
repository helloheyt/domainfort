//! Flag values used by the phase-1 tables and their value constraints.
//!
//! Only the bits the phase-1 tables use, plus the ones a rule refers to, are
//! defined; names are the spec's symbolic names.
//!
//! Spec: [MS-ADTS] v20261026 2.2.9 (searchFlags), 2.2.10 (systemFlags),
//! 2.2.12 (Group Type Flags), 2.2.16 (userAccountControl Bits); docs/46 §5.3,
//! §8.2 (R46-6, A-29).

/// searchFlags bits. Spec: [MS-ADTS] 2.2.9.
pub mod search_flags {
    /// fATTINDEX (IX). Spec: [MS-ADTS] 2.2.9.
    pub const F_ATTINDEX: u32 = 0x0000_0001;
    /// fANR (AR). Spec: [MS-ADTS] 2.2.9.
    pub const F_ANR: u32 = 0x0000_0004;
    /// fPRESERVEONDELETE (PR). Spec: [MS-ADTS] 2.2.9.
    pub const F_PRESERVEONDELETE: u32 = 0x0000_0008;
    /// fCOPY (CP). Spec: [MS-ADTS] 2.2.9.
    pub const F_COPY: u32 = 0x0000_0010;
    /// fCONFIDENTIAL (CF): "the attribute is confidential. An extended access
    /// check (section 3.1.1.4.4) is required" — the bit that makes an
    /// attribute `AttrClass::Sensitive` (docs/46 §6). No phase-1 attribute
    /// has it. Spec: [MS-ADTS] 2.2.9.
    pub const F_CONFIDENTIAL: u32 = 0x0000_0080;
}

/// systemFlags bits on attributeSchema objects. Spec: [MS-ADTS] 2.2.10.
pub mod system_flags {
    /// FLAG_ATTR_NOT_REPLICATED (NR). Spec: [MS-ADTS] 2.2.10.
    pub const FLAG_ATTR_NOT_REPLICATED: u32 = 0x0000_0001;
    /// FLAG_ATTR_REQ_PARTIAL_SET_MEMBER (PS). Spec: [MS-ADTS] 2.2.10.
    pub const FLAG_ATTR_REQ_PARTIAL_SET_MEMBER: u32 = 0x0000_0002;
    /// FLAG_ATTR_IS_OPERATIONAL (OP). Spec: [MS-ADTS] 2.2.10.
    pub const FLAG_ATTR_IS_OPERATIONAL: u32 = 0x0000_0008;
    /// FLAG_SCHEMA_BASE_OBJECT (BS). Spec: [MS-ADTS] 2.2.10.
    pub const FLAG_SCHEMA_BASE_OBJECT: u32 = 0x0000_0010;
}

/// The two's-complement `i32` with the same 32 bits as `bits` (groupType is
/// stored as Integer32, docs/46 §5.4).
const fn as_i32(bits: u32) -> i32 {
    i32::from_be_bytes(bits.to_be_bytes())
}

/// groupType values. Spec: [MS-ADTS] 2.2.12.
pub mod group_type {
    /// GROUP_TYPE_BUILTIN_LOCAL_GROUP — "cannot be set by clients".
    /// Spec: [MS-ADTS] 2.2.12.
    pub const GROUP_TYPE_BUILTIN_LOCAL_GROUP: u32 = 0x0000_0001;
    /// GROUP_TYPE_ACCOUNT_GROUP (global group). Spec: [MS-ADTS] 2.2.12.
    pub const GROUP_TYPE_ACCOUNT_GROUP: u32 = 0x0000_0002;
    /// GROUP_TYPE_RESOURCE_GROUP (domain local group). Spec: [MS-ADTS] 2.2.12.
    pub const GROUP_TYPE_RESOURCE_GROUP: u32 = 0x0000_0004;
    /// GROUP_TYPE_UNIVERSAL_GROUP. Spec: [MS-ADTS] 2.2.12.
    pub const GROUP_TYPE_UNIVERSAL_GROUP: u32 = 0x0000_0008;
    /// GROUP_TYPE_APP_BASIC_GROUP — "not used by Active Directory".
    /// Spec: [MS-ADTS] 2.2.12.
    pub const GROUP_TYPE_APP_BASIC_GROUP: u32 = 0x0000_0010;
    /// GROUP_TYPE_APP_QUERY_GROUP — "not used by Active Directory".
    /// Spec: [MS-ADTS] 2.2.12.
    pub const GROUP_TYPE_APP_QUERY_GROUP: u32 = 0x0000_0020;
    /// GROUP_TYPE_SECURITY_ENABLED. Spec: [MS-ADTS] 2.2.12.
    pub const GROUP_TYPE_SECURITY_ENABLED: u32 = 0x8000_0000;

    /// The six groupType values phase 1 accepts: exactly one of ACCOUNT /
    /// RESOURCE / UNIVERSAL ("mutually exclusive, and only one value MUST be
    /// set"), optionally OR SECURITY_ENABLED. BUILTIN_LOCAL ("cannot be set
    /// by clients"; builtinDomain is outside phase 1) and APP_BASIC /
    /// APP_QUERY ("not used by Active Directory") are refused.
    /// Spec: [MS-ADTS] 2.2.12; docs/46 §8.2 (R46-6, A-29).
    pub const ALLOWED_VALUES: [i32; 6] = [
        super::as_i32(GROUP_TYPE_ACCOUNT_GROUP),
        super::as_i32(GROUP_TYPE_RESOURCE_GROUP),
        super::as_i32(GROUP_TYPE_UNIVERSAL_GROUP),
        super::as_i32(GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_ACCOUNT_GROUP),
        super::as_i32(GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_RESOURCE_GROUP),
        super::as_i32(GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_UNIVERSAL_GROUP),
    ];
}

/// userAccountControl bits. Spec: [MS-ADTS] 2.2.16.
pub mod user_account_control {
    /// D — ADS_UF_ACCOUNT_DISABLE. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_ACCOUNT_DISABLE: u32 = 0x0000_0002;
    /// HR — ADS_UF_HOMEDIR_REQUIRED. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_HOMEDIR_REQUIRED: u32 = 0x0000_0008;
    /// L — ADS_UF_LOCKOUT. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_LOCKOUT: u32 = 0x0000_0010;
    /// NR — ADS_UF_PASSWD_NOTREQD. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_PASSWD_NOTREQD: u32 = 0x0000_0020;
    /// CC — ADS_UF_PASSWD_CANT_CHANGE. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_PASSWD_CANT_CHANGE: u32 = 0x0000_0040;
    /// ET — ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED: u32 = 0x0000_0080;
    /// N — ADS_UF_NORMAL_ACCOUNT. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_NORMAL_ACCOUNT: u32 = 0x0000_0200;
    /// ID — ADS_UF_INTERDOMAIN_TRUST_ACCOUNT. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_INTERDOMAIN_TRUST_ACCOUNT: u32 = 0x0000_0800;
    /// WT — ADS_UF_WORKSTATION_TRUST_ACCOUNT. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_WORKSTATION_TRUST_ACCOUNT: u32 = 0x0000_1000;
    /// ST — ADS_UF_SERVER_TRUST_ACCOUNT. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_SERVER_TRUST_ACCOUNT: u32 = 0x0000_2000;
    /// DP — ADS_UF_DONT_EXPIRE_PASSWD. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_DONT_EXPIRE_PASSWD: u32 = 0x0001_0000;
    /// SR — ADS_UF_SMARTCARD_REQUIRED. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_SMARTCARD_REQUIRED: u32 = 0x0004_0000;
    /// TD — ADS_UF_TRUSTED_FOR_DELEGATION. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_TRUSTED_FOR_DELEGATION: u32 = 0x0008_0000;
    /// ND — ADS_UF_NOT_DELEGATED. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_NOT_DELEGATED: u32 = 0x0010_0000;
    /// DK — ADS_UF_USE_DES_KEY_ONLY. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_USE_DES_KEY_ONLY: u32 = 0x0020_0000;
    /// DR — ADS_UF_DONT_REQUIRE_PREAUTH. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_DONT_REQUIRE_PREAUTH: u32 = 0x0040_0000;
    /// PE — ADS_UF_PASSWORD_EXPIRED. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_PASSWORD_EXPIRED: u32 = 0x0080_0000;
    /// TA — ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION.
    /// Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: u32 = 0x0100_0000;
    /// NA — ADS_UF_NO_AUTH_DATA_REQUIRED. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_NO_AUTH_DATA_REQUIRED: u32 = 0x0200_0000;
    /// PS — ADS_UF_PARTIAL_SECRETS_ACCOUNT. Spec: [MS-ADTS] 2.2.16.
    pub const ADS_UF_PARTIAL_SECRETS_ACCOUNT: u32 = 0x0400_0000;

    /// The bits phase 1 accepts in userAccountControl: D, HR, CC, N, WT, ST,
    /// DP, SR, ND, PE. Every other bit — the ten refused ones in
    /// [`REFUSED`] and the "X: Unused. Must be zero" bits — is refused
    /// (who may set ST is a PDP policy rule, not a dirstore one).
    /// Spec: [MS-ADTS] 2.2.16; docs/46 §8.2 (R46-6; A-29: ND allowed).
    pub const ALLOWED: u32 = ADS_UF_ACCOUNT_DISABLE
        | ADS_UF_HOMEDIR_REQUIRED
        | ADS_UF_PASSWD_CANT_CHANGE
        | ADS_UF_NORMAL_ACCOUNT
        | ADS_UF_WORKSTATION_TRUST_ACCOUNT
        | ADS_UF_SERVER_TRUST_ACCOUNT
        | ADS_UF_DONT_EXPIRE_PASSWD
        | ADS_UF_SMARTCARD_REQUIRED
        | ADS_UF_NOT_DELEGATED
        | ADS_UF_PASSWORD_EXPIRED;

    /// The ten defined bits phase 1 refuses, each enabling an option with no
    /// code path: NR (no password), ET (cleartext password), DK (DES), DR
    /// (no preauthentication), TD (unconstrained delegation), TA (S4U2self
    /// forwardable, phase 3), NA (no PAC), ID (trust, OD-10), PS (RODC), L
    /// (lockout, not in phase 1). Spec: [MS-ADTS] 2.2.16; docs/46 §8.2
    /// (R46-6, A-29).
    pub const REFUSED: [u32; 10] = [
        ADS_UF_PASSWD_NOTREQD,
        ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,
        ADS_UF_USE_DES_KEY_ONLY,
        ADS_UF_DONT_REQUIRE_PREAUTH,
        ADS_UF_TRUSTED_FOR_DELEGATION,
        ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
        ADS_UF_NO_AUTH_DATA_REQUIRED,
        ADS_UF_INTERDOMAIN_TRUST_ACCOUNT,
        ADS_UF_PARTIAL_SECRETS_ACCOUNT,
        ADS_UF_LOCKOUT,
    ];
}
