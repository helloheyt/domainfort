//! The result type of keyd's service-ticket verification
//! (`open_and_verify_service_ticket`, task L6a; role `Ldap`). keyd runs RFC
//! 4120 3.2.3 under the service key and returns only non-secret facts; the
//! session key and subkey stay in keyd (docs/49 §3.3, R49-5; decision A-46).
//! Moved unchanged from keyd (D182; decision A-63).
//!
//! Spec: RFC 4120 5.3, 5.5.1; docs/10 §5ב; docs/49 §3.3;
//! docs/questions/Q-165 (A-46).

use crate::tokens::ServiceCtxId;
use krb_proto::{KerberosTime, PrincipalName, Realm, TicketFlags};

/// Non-secret facts of a verified service ticket, plus the one-time context
/// id that names the session key keyd keeps for the later GSS steps.
///
/// There is no key field (docs/10 §12 I1): not the service key, not the
/// session key, not the subkey — only whether a subkey was offered.
/// `channel_bound` (docs/49 §3.3) arrives with channel binding in task L6b.
///
/// Spec: docs/49 §3.3 (`struct ServiceContext { ctx_id, client, authtime,
/// endtime, flags, … } // no key field (I1)`); docs/questions/Q-165 item 2
/// (A-46); RFC 4120 5.3 (the EncTicketPart fields), 5.5.1 (subkey).
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
}
