//! The argument and result types of keyd's AS exchange (`verify_preauth`,
//! `issue_as_rep`; role `Kdc`). The operations themselves — the state
//! machine `verify_preauth ──(AuthnProof)──► issue_as_rep`, the sealing,
//! the session key drawn inside keyd — are keyd's; these types carry no key
//! and no plaintext (moved unchanged from keyd: D182; decision A-63).
//!
//! Spec: RFC 4120 3.1.3, 5.3, 5.4.2; RFC 6113 5.4.3; docs/10 §4, §8;
//! docs/48 §2.3.

use crate::enctype::EncTypeId;
use crate::model::PrincipalId;
use crate::tokens::ExchangeId;
use krb_proto::{EncryptedData, KerberosTime, PrincipalName, Realm, Ticket, TicketFlags};

/// Proof that pre-authentication succeeded, returned by `verify_preauth`
/// and consumed by `issue_as_rep`. It binds the issuance to this exchange,
/// this caller and this client; it is short-lived and single-use. It carries
/// no decrypted plaintext (no decryption oracle, docs/10 §4).
///
/// The expiry is tracked inside keyd (docs/10 `expires: Instant`).
///
/// Spec: docs/10 §4 (`struct AuthnProof`), §8, D36.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnProof {
    /// The one-time exchange token.
    pub exchange_id: ExchangeId,
    /// The pre-authenticated principal.
    pub client: PrincipalId,
    /// The authentication time (the caller's `now` at pre-authentication;
    /// RFC 4120 5.3 authtime of an AS ticket is the KDC's current time).
    pub authtime: KerberosTime,
}

/// The KDC's request for a TGT. keyd fills in the session key, the realm,
/// authtime, transited and the INITIAL / PRE-AUTHENT flags itself.
///
/// Spec: docs/10 §4 (`struct TicketTemplate`); RFC 4120 5.3, 5.4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsTicketTemplate {
    /// The client; must be the principal the proof is bound to.
    pub client: PrincipalId,
    /// Client realm; must be the configured realm (single realm, phase 1).
    pub crealm: Realm,
    /// Client name (RFC 4120 5.3 cname). Must identify the principal name
    /// the client key set is bound to (realm + name-string, RFC 4120 6.2;
    /// docs/questions/Q-040, A-19) — otherwise `Denied`. Canonicalization
    /// (case, aliases, enterprise names) is the KDC's job before the call.
    pub cname: PrincipalName,
    /// Server name; must be this realm's TGS name, NT-SRV-INST ("krbtgt",
    /// realm), because the ticket is sealed under the krbtgt key
    /// (RFC 4120 7.3).
    pub sname: PrincipalName,
    /// Requested starttime; must be within the clock skew of now (no
    /// postdating). `None` = authtime is the start (RFC 4120 5.3).
    pub starttime: Option<KerberosTime>,
    /// Expiration time.
    pub endtime: KerberosTime,
    /// Renew-till; present exactly when RENEWABLE is requested.
    pub renew_till: Option<KerberosTime>,
    /// Requested flags; must lie in the configured allowed mask.
    pub flags: TicketFlags,
    /// Session-key encryption type; must be configured (I5). A crypto-free
    /// identifier (D182; A-63).
    pub session_enctype: EncTypeId,
    /// The AS-REQ nonce, echoed in EncASRepPart (RFC 4120 5.4.2).
    pub nonce: u32,
}

/// The sealed AS-REP parts: the ticket (sealed under krbtgt), the enc-part
/// (sealed under the client key, or under the strengthened reply key when
/// armored) and, when armored, the enc-fast-rep. The KDC assembles the
/// AS-REP (and, when armored, its PA-FX-FAST padata around `fast_rep`).
///
/// Spec: docs/10 §4 (`struct AsRep { ticket: Sealed, enc_part: Sealed }`);
/// docs/48 §2.3 (`fast_rep: Option<Sealed>`), §4.1 A14; RFC 4120 5.4.2; RFC
/// 6113 5.4.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsRepParts {
    /// `ticket [5] Ticket`.
    pub ticket: Ticket,
    /// `enc-part [6] EncryptedData` (EncASRepPart, key usage 3, client
    /// kvno).
    pub enc_part: EncryptedData,
    /// `enc-fast-rep` of the KrbFastArmoredRep (the KrbFastResponse sealed
    /// in the armor key, key usage 52): `Some` exactly when the issuance was
    /// armored. Spec: RFC 6113 5.4.3; docs/48 §2.3.
    pub fast_rep: Option<EncryptedData>,
}
