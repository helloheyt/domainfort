//! The KRB_PRIV message: KRB-PRIV and its plaintext EncKrbPrivPart.
//!
//! The codec only: the `enc-part` stays opaque here (key usage 13, "encrypted
//! with a key chosen by the application" — RFC 4120 7.5.1); decrypting it and
//! checking its control information (RFC 4120 3.5.2: sender's address,
//! timestamp / usec, sequence number — "if neither ... is present, a
//! KRB_AP_ERR_MODIFIED error is generated") are the receiver's processing
//! rules, applied by keyd, not by this codec.
//!
//! Spec: RFC 4120 3.5, 5.6.1 (field descriptions), 5.7.1; 5.10 (application
//! tags 21, 28); 7.5.7 (KRB_PRIV = 21); Appendix A.

use crate::basic::{EncryptedData, HostAddress, KerberosTime, Microseconds};
use crate::constants::{APP_ENC_KRB_PRIV_PART, APP_KRB_PRIV, KRB_PRIV, PVNO};
use crate::der::{self, app, ctx, int, octet_string, octets, Fields, SecretFields};
use crate::error::Result;
use parse_asn1::Value;

// ===========================================================================
// KRB-PRIV — RFC 4120 5.7.1
// ===========================================================================

/// ```text
/// KRB-PRIV        ::= [APPLICATION 21] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (21),
///                         -- NOTE: there is no [2] tag
///         enc-part        [3] EncryptedData -- EncKrbPrivPart
/// }
/// ```
///
/// `pvno` and `msg-type` are fixed by the type: checked, written, not stored
/// (a mismatch is the RFC 4120 3.5.2 KRB_AP_ERR_BADVERSION / MSG_TYPE case).
/// A component tagged `[2]` is undefined and rejected
/// ([`crate::Error::UnknownField`]). `enc-part` stays opaque (key usage 13).
///
/// Spec: RFC 4120 5.7.1, 5.10, 3.5.2; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KrbPriv {
    /// `enc-part [3] EncryptedData` — the encrypted EncKrbPrivPart.
    pub enc_part: EncryptedData,
}

impl KrbPriv {
    // Spec: RFC 4120 5.7.1 — "NOTE: there is no [2] tag".
    const TAGS: &'static [u32] = &[0, 1, 3];

    /// Spec: RFC 4120 5.7.1, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let inner = der::application(value, APP_KRB_PRIV)?;
        let mut f = Fields::new(inner, Self::TAGS)?;
        der::pvno(f.required(0)?)?;
        der::msg_type(f.required(1)?, &[KRB_PRIV], KRB_PRIV)?;
        let enc_part = EncryptedData::from_value(f.required(3)?)?;
        f.finish()?;
        Ok(KrbPriv { enc_part })
    }

    /// Spec: RFC 4120 5.7.1, 5.10.
    pub(crate) fn to_value(&self) -> Result<Value> {
        Ok(app(
            APP_KRB_PRIV,
            Value::Sequence(vec![
                ctx(0, int(PVNO)),
                ctx(1, int(KRB_PRIV)),
                ctx(3, self.enc_part.to_value()?),
            ]),
        ))
    }
}

der_codec!(KrbPriv, "KRB-PRIV");

// ===========================================================================
// EncKrbPrivPart — RFC 4120 5.7.1
// ===========================================================================

secret_octets! {
    /// The `user-data` octets of an EncKrbPrivPart — the application data a
    /// KRB_PRIV message exists to keep private (RFC 4120 3.5: for "clients
    /// requiring confidentiality"). In an RFC 3244 request it is the DER of a
    /// ChangePasswdData, i.e. a cleartext password, so it is always handled as
    /// a secret: zeroized on drop, redacted in `Debug`.
    ///
    /// Spec: RFC 4120 5.6.1 (user-data "contains the application-specific
    /// data that is being passed from the sender to the recipient"), 5.7.1;
    /// RFC 3244 §2; docs/CLEAN-ROOM.md
    UserData
}

/// ```text
/// EncKrbPrivPart  ::= [APPLICATION 28] SEQUENCE {
///         user-data       [0] OCTET STRING,
///         timestamp       [1] KerberosTime OPTIONAL,
///         usec            [2] Microseconds OPTIONAL,
///         seq-number      [3] UInt32 OPTIONAL,
///         s-address       [4] HostAddress -- sender's addr --,
///         r-address       [5] HostAddress OPTIONAL -- recip's addr
/// }
/// ```
///
/// The plaintext of a KRB-PRIV `enc-part`. `user-data` is a [`UserData`]
/// (secret), so the type is decoded / encoded on the secret path: the
/// intermediate value tree is scrubbed and `encode` returns a `Zeroizing`
/// buffer. `s-address` is required (it is not OPTIONAL in the module; RFC 4120
/// 3.5.2: "The sender's address MUST be included"). `seq-number` is a UInt32:
/// negative values are rejected (the 5.5.1 negative-number leniency is not
/// taken). Which control fields must be present, and their values, are
/// checked by the receiver (RFC 4120 3.5.2; RFC 3244 §2), not here.
///
/// Spec: RFC 4120 5.7.1, 5.6.1, 5.10, 3.5.1, 3.5.2; Appendix A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncKrbPrivPart {
    /// `user-data [0] OCTET STRING`.
    pub user_data: UserData,
    /// `timestamp [1] KerberosTime OPTIONAL`.
    pub timestamp: Option<KerberosTime>,
    /// `usec [2] Microseconds OPTIONAL`.
    pub usec: Option<Microseconds>,
    /// `seq-number [3] UInt32 OPTIONAL`.
    pub seq_number: Option<u32>,
    /// `s-address [4] HostAddress` — sender's address.
    pub s_address: HostAddress,
    /// `r-address [5] HostAddress OPTIONAL` — recipient's address.
    pub r_address: Option<HostAddress>,
}

impl EncKrbPrivPart {
    const TAGS: &'static [u32] = &[0, 1, 2, 3, 4, 5];

    /// Spec: RFC 4120 5.7.1, 5.10.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let inner = der::application(value, APP_ENC_KRB_PRIV_PART)?;
        let mut f = Fields::new(inner, Self::TAGS)?;
        let user_data = UserData::from_slice(octet_string(f.required(0)?)?);
        let timestamp = f.optional(1).map(KerberosTime::from_value).transpose()?;
        let usec = f.optional(2).map(der::microseconds).transpose()?;
        let seq_number = f.optional(3).map(der::uint32).transpose()?;
        let s_address = HostAddress::from_value(f.required(4)?)?;
        let r_address = f.optional(5).map(HostAddress::from_value).transpose()?;
        f.finish()?;
        Ok(EncKrbPrivPart {
            user_data,
            timestamp,
            usec,
            seq_number,
            s_address,
            r_address,
        })
    }

    /// Spec: RFC 4120 5.7.1, 5.10. The `user-data` copy in the value tree is
    /// scrubbed by `SecretFields` / `der::encode_secret`.
    pub(crate) fn to_value(&self) -> Result<Value> {
        let mut f = SecretFields::new();
        f.push(ctx(0, octets(self.user_data.as_bytes())));
        if let Some(timestamp) = &self.timestamp {
            f.push(ctx(1, timestamp.to_value()));
        }
        if let Some(usec) = self.usec {
            f.push(ctx(2, usec.to_value()));
        }
        if let Some(seq_number) = self.seq_number {
            f.push(ctx(3, int(seq_number.into())));
        }
        f.push(ctx(4, self.s_address.to_value()?));
        if let Some(r_address) = &self.r_address {
            f.push(ctx(5, r_address.to_value()?));
        }
        Ok(app(APP_ENC_KRB_PRIV_PART, f.into_sequence()))
    }
}

der_codec_secret!(EncKrbPrivPart, "EncKrbPrivPart");
