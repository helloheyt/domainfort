//! The arguments and the result type of keyd's service-ticket verification
//! (`open_and_verify_service_ticket`, task L6a; role `Ldap`). keyd runs RFC
//! 4120 3.2.3 under the service key and returns only non-secret facts; the
//! session key and subkey stay in keyd (docs/49 §3.3, R49-5; decision A-46).
//! The result type moved unchanged from keyd (D182; decision A-63).
//!
//! # The application binding (R2; docs/52 §3.2, §5; decision A-102)
//!
//! RFC 4120 5.5.1: the Authenticator's `cksum` "contains a checksum of the
//! application data that accompanies the KRB_AP_REQ, computed using a key
//! usage value of 10 in normal application exchanges"; 7.5.1 item 10: "AP-REQ
//! Authenticator cksum, keyed with the application session key". RFC 4120
//! §4: checksums use the RFC 3961 `get_mic` operation with that key usage;
//! RFC 3961 §3 / §4: the checksum mechanism is the encryption type's
//! "required checksum mechanism" (RFC 3962 §7: sumtypes 15 / 16 for etypes
//! 17 / 18; RFC 8009 §6, §7: 19 / 20 for 19 / 20).
//!
//! [`AppBinding`] says what application data a caller requires the AP-REQ
//! to be bound to, and — structurally — **which key set may open it**:
//! [`AppBinding::key_purpose`]. The service key set is named by its
//! principal alone; its purpose is derived from the binding. So an admin
//! service ticket ([`KeyPurpose::AdminService`]) cannot be asked for
//! without an [`OperationDigest`], and an operation digest cannot be
//! verified under any other key set: neither pairing can be expressed (in
//! this type, in keyd's API, or on the keyd channel).
//!
//! Spec: RFC 4120 §4, 3.2.3, 5.3, 5.5.1, 7.5.1; RFC 3961 §3, §4; RFC 3962 §7;
//! RFC 8009 §6, §7; docs/10 §5ב; docs/49 §3.3; docs/52 §3.2, §5;
//! docs/questions/Q-165 (A-46), Q-463 (A-102).

use crate::model::KeyPurpose;
use crate::tokens::ServiceCtxId;
use core::fmt;
use krb_proto::{KerberosTime, PrincipalName, Realm, TicketFlags};

/// Octets of an [`OperationDigest`]: one SHA-256 output.
/// Spec: FIPS 180-4 §6.2 (a 256-bit message digest); docs/52 §5 item 1.
pub const OPERATION_DIGEST_LEN: usize = 32;

/// The digest of one admin-channel operation — the application data an
/// admin AP-REQ is bound to. The admin channel defines and computes it
/// (crate ipc-dird-admin `operation_digest`: SHA-256 over a fixed label and
/// the exact operation octets dird decodes); keyd never parses it: keyd
/// only checks that the Authenticator's `cksum` is the session key's
/// `get_mic` over these 32 octets (key usage 10).
///
/// Not secret (a hash of a request admind forwards in the clear). `Debug`
/// prints it as hex.
///
/// Spec: RFC 4120 5.5.1 ("a checksum of the application data"), 7.5.1 item
/// 10; docs/52 §5 items 1-2; docs/questions/Q-463 item 1 (A-102).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationDigest([u8; OPERATION_DIGEST_LEN]);

impl OperationDigest {
    /// Wrap a digest. Spec: docs/52 §5 item 1.
    #[must_use]
    pub const fn new(octets: [u8; OPERATION_DIGEST_LEN]) -> Self {
        OperationDigest(octets)
    }

    /// The digest octets — the message the `cksum` MIC covers.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; OPERATION_DIGEST_LEN] {
        &self.0
    }
}

impl fmt::Debug for OperationDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperationDigest(")?;
        for octet in &self.0 {
            write!(f, "{octet:02x}")?;
        }
        f.write_str(")")
    }
}

/// What application data the AP-REQ's Authenticator must be bound to, and
/// therefore which purpose of key set opens it (module documentation).
/// Spec: RFC 4120 5.5.1 (cksum), 7.5.1 item 10; docs/52 §5 item 3
/// (`AppBinding::{Unbound, OperationDigest([u8; 32])}`); docs/questions/
/// Q-463 item 3 (A-102).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppBinding {
    /// No application data: the Authenticator must carry **no** `cksum`
    /// (task L6a — keyd has nothing to verify one over, so one is refused
    /// rather than ignored; the GSS checksum of RFC 4121 is task L6b, a
    /// separate variant when it comes). Opens only a
    /// [`KeyPurpose::Service`] key set (the LDAP service key).
    /// Spec: docs/10 §5ב step 9; docs/questions/Q-180 item 3 (A-50).
    Unbound,
    /// The admin channel: the Authenticator must carry a `cksum` of the
    /// session key's required checksum type, key usage 10, whose MIC
    /// verifies over the digest's 32 octets. Opens only a
    /// [`KeyPurpose::AdminService`] key set.
    /// Spec: RFC 4120 5.5.1, 7.5.1 item 10; RFC 3961 §3, §4; docs/52 §5
    /// items 2-3.
    OperationDigest(OperationDigest),
}

impl AppBinding {
    /// The one key purpose a ticket verified with this binding is opened
    /// under. Exhaustive: a new binding does not compile until it names its
    /// purpose; the compile-time pins in crate::authz fix both rows.
    /// Spec: docs/52 §3.2 ("keyd will verify a ticket of this profile
    /// **only** with `OperationDigest`"), §5 item 3; docs/questions/Q-463
    /// item 4 (A-102).
    #[must_use]
    pub const fn key_purpose(&self) -> KeyPurpose {
        match self {
            AppBinding::Unbound => KeyPurpose::Service,
            AppBinding::OperationDigest(_) => KeyPurpose::AdminService,
        }
    }
}

/// Non-secret facts of a verified service ticket, plus the one-time context
/// id that names the session key keyd keeps for the later GSS steps.
///
/// There is no key field (docs/10 §12 I1): not the service key, not the
/// session key, not the subkey — only whether a subkey was offered.
/// `channel_bound` of a GSS channel binding (docs/49 §3.3) arrives with task
/// L6b; the admin channel's binding is [`ServiceContext::bound_operation`].
///
/// Spec: docs/49 §3.3 (`struct ServiceContext { ctx_id, client, authtime,
/// endtime, flags, … } // no key field (I1)`); docs/questions/Q-165 item 2
/// (A-46); RFC 4120 5.3 (the EncTicketPart fields), 5.5.1 (subkey, cksum).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceContext {
    /// The one-time service-context token.
    pub ctx_id: ServiceCtxId,
    /// Client realm from the ticket (equal to the authenticator's).
    pub crealm: Realm,
    /// Client name from the ticket (equal to the authenticator's).
    pub cname: PrincipalName,
    /// Time of initial authentication — for the PEP's hot-list check
    /// (docs/49 §3.2, R49-15). Spec: RFC 4120 5.3 (authtime: "the necessary
    /// information for implementation of a 'hot list' service").
    pub authtime: KerberosTime,
    /// Ticket expiration time. Spec: RFC 4120 5.3 (endtime).
    pub endtime: KerberosTime,
    /// Ticket flags (never INVALID: such a ticket is refused).
    /// Spec: RFC 4120 2.2, 5.3.
    pub flags: TicketFlags,
    /// `true` if the authenticator offered a subkey ("the client's choice
    /// for an encryption key to be used to protect this specific application
    /// session"); the subkey itself stays in keyd. Spec: RFC 4120 5.5.1.
    pub subkey_present: bool,
    /// The operation digest keyd verified the Authenticator's `cksum` over
    /// (an [`AppBinding::OperationDigest`] verification), `None` for an
    /// unbound one. Only keyd's successful answer carries it: the PEP
    /// reports the request channel-bound to the PDP only when every ticket
    /// it relies on carries the digest of the request it is deciding
    /// (docs/52 §5 item 4).
    /// Spec: RFC 4120 5.5.1; docs/52 §5 items 3-4; docs/11 §1
    /// (`channel_bound`).
    pub bound_operation: Option<OperationDigest>,
}
