//! The argument and result types of keyd's AS exchange (`verify_preauth`,
//! `issue_as_rep`; role `Kdc`). The operations themselves — the state
//! machine `verify_preauth ──(AuthnProof)──► issue_as_rep`, the sealing,
//! the session key drawn inside keyd — are keyd's; these types carry no key
//! and no plaintext (moved unchanged from keyd: D182; decision A-63).
//!
//! Task K3b adds the closed set of servers an AS ticket can be issued for
//! ([`AsServer`]: this realm's TGS, or the change-password service — armored
//! only) and the change-password ticket's longest life
//! ([`CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS`], the one definition keyd
//! enforces and the KDC plans with).
//!
//! # Each key set named once (task PN11b; docs/questions/Q-1067)
//!
//! **The class (docs/CLEAN-ROOM.md):** "one request states one fact twice" —
//! until PN11b the KDC handed `issue_as_rep` the client's key handle (and,
//! for `kadmin/changepw`, the service's) **beside** dird's attested name
//! resolution that already names that key set (`principal`, `key_purpose`
//! — docs/59 §7.1), and the template named the client a third time; keyd
//! refused a disagreement, but the disagreement was representable. **The
//! root-level change:** the request names a resolved key set only through
//! its resolution. `issue_as_rep` takes the client's resolution and no
//! client handle; the server is an [`AsServerKeySet`] — this realm's krbtgt
//! by its handle (it has no resolution: docs/59 §7.2), or the
//! change-password service by its resolution alone; [`AsTicketTemplate`]
//! has no `client`. keyd looks each resolved set up by the resolution it
//! verified, so there is nothing left to compare.
//!
//! Spec: RFC 4120 2.1, 3.1.3, 5.3, 5.4.2; RFC 6113 5.4, 5.4.3; RFC 3244 §2;
//! docs/10 §4, §8; docs/48 §2.3; docs/53 R53-6, §5.2; docs/questions/Q-915
//! (A-151); docs/59 §7.1, §7.2; docs/questions/Q-1067 (task PN11b).

use crate::enctype::EncTypeId;
use crate::model::{KeyHandle, KeyPurpose, PrincipalId};
use crate::name_resolution::AttestedNameResolution;
use crate::tokens::ExchangeId;
use krb_proto::{EncryptedData, KerberosTime, PrincipalName, Realm, Ticket, TicketFlags};

/// The longest life, in seconds, of a ticket for the change-password service
/// (`kadmin/changepw`, RFC 3244 §2): 300 — the project's choice for that
/// service's ticket profile (any value at least the round trip works;
/// shorter is a smaller window for a stolen INITIAL ticket and its session
/// key, docs/53 §8). It is a limit "associated with the server principal"
/// in the sense of RFC 4120 3.1.3: the endtime of such a ticket is at most
/// its start plus this value, and the realm's minimum lifetime still applies
/// below it (KDC_ERR_NEVER_VALID) — so keyd refuses at start a realm minimum
/// above it ([`crate::KeydConfig::validate`], which would otherwise make
/// every change-password AS fail).
///
/// The **one** definition: keyd enforces it in `issue_as_rep` for
/// [`AsServer::ChangePasswordService`]; the KDC plans its endtime cap with
/// the same constant (docs/questions/Q-915 item 2 — "one rule, two
/// definitions" closed by the crate both link).
///
/// Spec: docs/53 R53-6, §5.2 ("lifetime ≤ 300 s"); docs/questions/Q-601
/// item 3, Q-915 items 2, 5 (A-117, A-151); RFC 4120 3.1.3, §8.2.
pub const CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS: u32 = 300;

/// The server of an AS issuance (`issue_as_rep`) — a closed set of two
/// (docs/53 §5.2: "Krbtgt **or** ChangePasswordService, no other purpose
/// expressible"):
///
/// - [`AsServer::LocalTgt`]: this realm's TGS — the ticket is a TGT sealed
///   under the realm's Krbtgt key set (RFC 4120 7.3); armored or not (the
///   unarmored computer bootstrap, docs/48 §7.3);
/// - [`AsServer::ChangePasswordService`]: the change-password service
///   `kadmin/changepw` — sealed under its ChangePasswordService key set,
///   **armored only** (A-142: an unarmored AS for it would let a passive
///   observer guess the old password offline and read the new one; RFC 6113
///   5.4) and under the service's ticket profile (INITIAL, at most
///   [`CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS`], never renewable,
///   forwardable, proxiable or postdated).
///
/// [`AsServer::of`] is the one classification of a server key set: the
/// capability table's two `issue_as_rep` server slots are defined by it
/// (`authz::purpose_permitted`), and keyd builds its issuance from it, so a
/// third server — or an unarmored change-password issuance — has no value.
///
/// Spec: docs/53 R53-6, §5.2; docs/questions/Q-915 items 1, 3 (A-151); A-117,
/// A-142; RFC 4120 2.1, 3.1.3, 7.3; RFC 6113 5.4; docs/52 C24.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsServer {
    /// This realm's ticket-granting service (a TGT). Spec: RFC 4120 7.3.
    LocalTgt,
    /// The change-password service `kadmin/changepw` — armored only, under
    /// its profile. Spec: RFC 3244 §2; docs/53 §5.2.
    ChangePasswordService,
}

impl AsServer {
    /// Both servers.
    pub const ALL: [AsServer; 2] = [AsServer::LocalTgt, AsServer::ChangePasswordService];

    /// The server whose key set has `purpose`, for an issuance that is
    /// `armored` — or `None`: no other purpose is a server of an AS ticket,
    /// and the change-password service is one only under FAST armor.
    /// Spec: docs/53 §5.2; docs/questions/Q-915 items 1, 3; A-142.
    #[must_use]
    pub const fn of(purpose: KeyPurpose, armored: bool) -> Option<AsServer> {
        match purpose {
            KeyPurpose::Krbtgt => Some(AsServer::LocalTgt),
            KeyPurpose::ChangePasswordService if armored => Some(AsServer::ChangePasswordService),
            _ => None,
        }
    }

    /// The purpose of the key set the ticket is sealed under.
    /// Spec: RFC 4120 3.1.3 ("the encryption key extracted from the server
    /// principal's record"); docs/53 §5.2.
    #[must_use]
    pub const fn key_purpose(self) -> KeyPurpose {
        match self {
            AsServer::LocalTgt => KeyPurpose::Krbtgt,
            AsServer::ChangePasswordService => KeyPurpose::ChangePasswordService,
        }
    }

    /// `true` if an issuance for this server must be FAST-armored.
    /// Spec: A-142; docs/53 §5.2.
    #[must_use]
    pub const fn requires_armor(self) -> bool {
        matches!(self, AsServer::ChangePasswordService)
    }
}

/// The server key set of one `issue_as_rep`, as the KDC names it to keyd —
/// one of the closed set [`AsServer`], each named **once** (task PN11b;
/// docs/questions/Q-1067):
///
/// - [`AsServerKeySet::LocalTgt`]: a TGT — this realm's krbtgt key set by
///   its handle. The krbtgt has no name resolution: the KDC always writes
///   the canonical TGS name `krbtgt/<REALM>`, and keyd reaches the set's
///   keys only by its exact stored binding to that name ([MS-KILE]
///   3.3.5.1.2; RFC 4120 §7.3; docs/59 §7.2);
/// - [`AsServerKeySet::ChangePasswordService`]: a ticket for
///   `kadmin/changepw` (armored only — keyd refuses it unarmored, A-142) —
///   by dird's attested resolution of the service object's name alone (the
///   record carried it, task PN11). No handle travels beside it: keyd looks
///   the key set up by the resolution it verified, so the server's key set
///   cannot be stated twice (docs/59 §7.1, §7.2).
///
/// Borrowed and `Copy`: one value per call, nothing kept.
///
/// Spec: docs/53 §5.2; docs/59 §7.1, §7.2; docs/questions/Q-915 items 1, 3
/// (A-151), Q-1011 item 8 (A-173), Q-1067; RFC 3244 §2; [MS-KILE] 3.3.5.1.2;
/// RFC 4120 §7.3; docs/CLEAN-ROOM.md.
#[derive(Debug, Clone, Copy)]
pub enum AsServerKeySet<'a> {
    /// This realm's krbtgt key set (a TGT), by its handle.
    /// Spec: RFC 4120 §7.3; docs/59 §7.2.
    LocalTgt(&'a KeyHandle),
    /// The change-password service's key set, by dird's attested
    /// resolution of `kadmin/changepw`. Spec: RFC 3244 §2; docs/53 §5.2;
    /// docs/59 §7.2.
    ChangePasswordService(&'a AttestedNameResolution),
}

impl AsServerKeySet<'_> {
    /// The server of the closed set this names.
    /// Spec: docs/53 §5.2; docs/questions/Q-915 items 1, 3.
    #[must_use]
    pub const fn server(&self) -> AsServer {
        match self {
            AsServerKeySet::LocalTgt(_) => AsServer::LocalTgt,
            AsServerKeySet::ChangePasswordService(_) => AsServer::ChangePasswordService,
        }
    }
}

/// Proof that pre-authentication succeeded, returned by `verify_preauth`
/// and consumed by `issue_as_rep`. It binds the issuance to this exchange,
/// this caller and this client; it is short-lived and single-use. It carries
/// no decrypted plaintext (no decryption oracle, docs/10 §4).
///
/// The client it binds is keyd's own record of the key set that
/// pre-authenticated; `issue_as_rep` requires it to be the key set of the
/// client's attested name resolution keyd verified (task PN11b) — two
/// statements keyd made or checked itself, never the KDC's.
///
/// The expiry is tracked inside keyd (docs/10 `expires: Instant`).
///
/// Spec: docs/10 §4 (`struct AuthnProof`; `issue_as_rep` step 1: the proof
/// is valid and bound to the client), §8, D36; docs/questions/Q-1067 open
/// point 1.
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

/// The KDC's request for an AS ticket — a TGT, or (armored) a
/// change-password service ticket. keyd fills in the session key, the
/// realm, authtime, transited and the INITIAL / PRE-AUTHENT flags itself.
///
/// It names no client principal (task PN11b): the ticket's client is the
/// key set of the client's attested name resolution keyd verified, which
/// must be the one the proof is bound to (docs/10 §4 step 1; docs/59 §7.1)
/// — docs/10 §4's `TicketTemplate.client` would state it a second time.
///
/// Spec: docs/10 §4 (`struct TicketTemplate`); RFC 4120 5.3, 5.4.2;
/// docs/53 §5.2; docs/questions/Q-1067.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsTicketTemplate {
    /// Client realm; must be the configured realm (single realm, phase 1).
    pub crealm: Realm,
    /// Client name (RFC 4120 5.3 cname). Together with `crealm` it must be
    /// one of the two (realm, name) pairs of the client's attested name
    /// resolution (`issue_as_rep`'s `client`) — as the request sent it, or
    /// canonical — exactly (task PN11; docs/59 §7.2 step 5); keyd looks the
    /// client key set up by that resolution (task PN11b) — otherwise
    /// `Denied`. keyd never canonicalises: dird chose the names (docs/59
    /// §4.5).
    pub cname: PrincipalName,
    /// Server name. For [`AsServer::LocalTgt`]: this realm's TGS name,
    /// NT-SRV-INST ("krbtgt", realm), exactly — the canonical TGS name the
    /// KDC always writes ([MS-KILE] 3.3.5.1.2; RFC 4120 7.3), checked against
    /// the krbtgt key set's stored binding without any resolution. For
    /// [`AsServer::ChangePasswordService`]: `kadmin/changepw` (RFC 3244 §2;
    /// never canonicalised, [MS-KILE] 3.3.5.1.2) — one of the two names of
    /// the service's attested name resolution
    /// ([`AsServerKeySet::ChangePasswordService`], task PN11).
    pub sname: PrincipalName,
    /// Requested starttime; must be within the clock skew of now (no
    /// postdating). `None` = authtime is the start (RFC 4120 5.3). Absent
    /// for [`AsServer::ChangePasswordService`] (the profile: the ticket
    /// starts at authtime).
    pub starttime: Option<KerberosTime>,
    /// Expiration time. For [`AsServer::ChangePasswordService`]: at most
    /// authtime + [`CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS`].
    pub endtime: KerberosTime,
    /// Renew-till; present exactly when RENEWABLE is requested. Absent for
    /// [`AsServer::ChangePasswordService`].
    pub renew_till: Option<KerberosTime>,
    /// Requested flags; must lie in the configured allowed mask. Empty for
    /// [`AsServer::ChangePasswordService`] (keyd adds INITIAL and
    /// PRE-AUTHENT, nothing else).
    pub flags: TicketFlags,
    /// Session-key encryption type; must be configured (I5). A crypto-free
    /// identifier (D182; A-63).
    pub session_enctype: EncTypeId,
    /// The AS-REQ nonce, echoed in EncASRepPart (RFC 4120 5.4.2).
    pub nonce: u32,
}

/// The sealed AS-REP parts: the ticket (sealed under the server's key set —
/// krbtgt, or the change-password service's), the enc-part
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
