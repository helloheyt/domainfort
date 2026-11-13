//! The argument and result types of keyd's FAST armor core
//! (`open_fast_armor`, `seal_fast_error`; role `Kdc`). The armor key, the
//! challenge keys, the strengthen key and the reply key never leave keyd
//! (docs/48 §2, A-33); these types carry none of them (moved unchanged from
//! keyd: D182; decision A-63).
//!
//! Spec: RFC 6113 5.2, 5.4.1.1, 5.4.2, 5.4.4; docs/48 §2.3, §5, §6.

use crate::tokens::{ArmorId, CtxId};
use krb_proto::{KerberosTime, KrbFastReq, PrincipalName, Realm};

/// Upper bound on a PA-FX-COOKIE value keyd seals into an armored error. The
/// cookie's content "is a local matter of the KDC" (RFC 6113 5.2); phase 1's
/// cookie is a short constant token (docs/questions/Q-126, A-32), so this
/// project bound only keeps the sealed reply small. Not taken from any other
/// source.
pub const MAX_FX_COOKIE_LENGTH: usize = 64;

/// The result of `open_fast_armor`: the one-time armor token, the armor
/// ticket's client (non-secret; the KDC re-evaluates it as an account, D126 /
/// D53) and the decrypted inner request. No key of any kind (docs/48 §9.1
/// I1).
///
/// Spec: docs/48 §2.3 (`struct FastArmor`); RFC 6113 5.4.1.1, 5.4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastArmor {
    /// The one-time armor token (docs/48 §2.3, D36).
    pub armor_id: ArmorId,
    /// Client realm of the armor ticket.
    pub armor_crealm: Realm,
    /// Client name of the armor ticket.
    pub armor_cname: PrincipalName,
    /// Authentication time of the armor ticket (for the KDC's
    /// `revoked_before` hot-list check, docs/48 §3.1).
    pub armor_authtime: KerberosTime,
    /// The decrypted KrbFastReq: fast-options, padata, inner req-body.
    pub fast_req: KrbFastReq,
}

/// Which armored conversation `seal_fast_error` answers.
///
/// Spec: docs/48 §2.3 (`enum FastConversation { As(ArmorId), Tgs(CtxId) }`),
/// §5, §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastConversation {
    /// The AS conversation opened by `open_fast_armor`.
    As(ArmorId),
    /// The TGS conversation opened by an armored `open_and_verify_tgt`
    /// (implicit armor, RFC 6113 5.4.2); a context opened without FAST has
    /// no armor key and is refused.
    Tgs(CtxId),
}
