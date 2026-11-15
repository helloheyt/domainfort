//! The operation digest: the application data an admin AP-REQ is bound to
//! (R2; docs/52 §3.2, §5; decision A-102).
//!
//! # Why
//!
//! An AP-REQ proves **who** asks, not **what**: as long as the octets of the
//! operation are not cryptographically bound to the Authenticator, the
//! intermediary (admind) could attach an administrator's valid AP-REQ to
//! another operation — once, within the clock skew (docs/52 §3.2, class C2;
//! docs/questions/Q-292). RFC 4120 §5.5.1 gives the Authenticator a `cksum`:
//! "a checksum of the application data that accompanies the KRB_AP_REQ,
//! computed using a key usage value of 10 in normal application exchanges";
//! §7.5.1 item 10: "AP-REQ Authenticator cksum, keyed with the application
//! session key".
//!
//! # What the application data is
//!
//! For this channel the application data is the **operation digest**, the
//! SHA-256 (FIPS 180-4, the approved RustCrypto `sha2`) of
//!
//! ```text
//! OPERATION_DIGEST_LABEL ‖ magic:u16 (0x4441) ‖ version:u8 (1) ‖ kind:u8 ‖ bound fields
//! ```
//!
//! where the bound fields are the operation's payload **after `auth`**,
//! exactly as on the wire — the octets dird decodes (the codec is
//! canonical: one encoding per value, `encode(decode(b)) == b`, docs/50
//! §3.3) — for every kind but one: for `CompletePasswordSet` they are its
//! `target` alone, because its `outcome` and `kvnos` are admind's report of
//! what keyd did, which the client cannot know when it makes the AP-REQ
//! (docs/52 §5 items 1, 5). `SetPassword` on `admin.sock` becomes two dird
//! requests (docs/51 §7.6): the client binds its `auth` AP-REQs to
//! `BeginPasswordSet {target}` and its `completion` AP-REQ to
//! `CompletePasswordSet {target, …}`; the password is in neither (dird
//! never sees it). An `Approve` binds `(kind, id, digest)` — the exact
//! approval of the pending request `id` whose operation digest the approver
//! was shown (docs/questions/Q-420 item 3, Q-882 item 1); a `Propose` binds
//! its `reason_ref` and its whole operation (kind and fields).
//!
//! # The fingerprint of an operation (docs/questions/Q-882, Q-888)
//!
//! The digest of an operation *as sent on its own* — for a proposed key
//! operation, of `KEY_OPERATION ‖ KeyOperation` — is the operation's
//! fingerprint: the value a pending request holds and shows, the value an
//! `Approve` names, the value the requester's AP-REQ is bound to when the
//! approved operation is executed, and the value every audit event of it
//! carries. One function computes it on both sides of the channel.
//!
//! The client puts `get_mic(session key, usage 10, digest)` of the session
//! key's required checksum type into the Authenticator; dird computes the
//! digest from the request it decoded and has keyd verify the `cksum` while
//! it opens the ticket (keyd `open_and_verify_service_ticket` with
//! `AppBinding::OperationDigest`). keyd never parses an admin request.
//!
//! The label separates this digest from every other digest of the project
//! (no other starts with it); the header after it has a fixed width, and
//! the bound fields are the canonical encoding of the kind it names — so
//! the input determines the operation uniquely.
//!
//! Spec: RFC 4120 §4, §5.5.1, §7.5.1 item 10; FIPS 180-4 §6.2; docs/52 §3.2,
//! §5 items 1-2, 5; docs/51 §7.1, §7.3, §7.6; docs/50 §3.3;
//! docs/questions/Q-463 item 1 (A-102), Q-420 item 3, Q-492.

use crate::channel::{ADMIN_MAGIC, ADMIN_VERSION, MAX_PAYLOAD};
use crate::typed::{ConversionError, Operation};
use crate::wire::WireOperation;
use core::fmt;
use ipc::{FrameLimit, Writer};
use keyd_types::OperationDigest;
use sha2::{Digest, Sha256};

/// The domain-separation label: the first octets of every operation digest,
/// and of no other digest of this project. Project choice.
/// Spec: docs/52 §5 item 1 ("a fixed domain-separation label").
pub const OPERATION_DIGEST_LABEL: &[u8] = b"dird-admin AP-REQ operation binding, layout 1";

/// The bound of the bound fields: the payload after `auth`.
/// Spec: docs/51 §7.5 ("payload ≤ 16 KiB").
const PAYLOAD_LIMIT: FrameLimit = match FrameLimit::new(MAX_PAYLOAD as u32) {
    Some(limit) => limit,
    None => panic!("MAX_PAYLOAD is outside the ipc FrameLimit range"),
};

/// Why an operation has no digest: it has no wire form (a typed value the
/// codec refuses), or its fields break the payload bound. Neither happens to
/// an operation dird decoded; dird refuses the request if it does.
/// Spec: docs/50 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestError {
    /// The typed operation has no wire form.
    Conversion(ConversionError),
    /// The fields could not be encoded within the payload bound.
    Encoding(ipc::Error),
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestError::Conversion(e) => write!(f, "operation has no wire form: {e}"),
            DigestError::Encoding(_) => f.write_str("operation fields could not be encoded"),
        }
    }
}

impl std::error::Error for DigestError {}

/// The bound fields of `operation` (module documentation): the payload after
/// `auth`, or `target` alone for `CompletePasswordSet`.
/// Spec: docs/52 §5 items 1, 5; docs/51 §7.3.
fn bound_fields(operation: &WireOperation) -> Result<Vec<u8>, ipc::Error> {
    let mut writer = Writer::new(PAYLOAD_LIMIT);
    match operation {
        WireOperation::CompletePasswordSet { target, .. } => writer.write_array(target)?,
        other => other.write_fields(&mut writer)?,
    }
    Ok(writer.into_payload().to_vec())
}

/// The operation digest of a wire operation (module documentation).
///
/// # Errors
/// [`DigestError::Encoding`] if the fields break the payload bound.
///
/// Spec: docs/52 §5 item 1; RFC 4120 §5.5.1; FIPS 180-4 §6.2.
pub fn wire_operation_digest(operation: &WireOperation) -> Result<OperationDigest, DigestError> {
    let fields = bound_fields(operation).map_err(DigestError::Encoding)?;
    let mut octets = Vec::with_capacity(OPERATION_DIGEST_LABEL.len() + 4 + fields.len());
    octets.extend_from_slice(OPERATION_DIGEST_LABEL);
    octets.extend_from_slice(&ADMIN_MAGIC.to_be_bytes());
    octets.push(ADMIN_VERSION);
    octets.push(operation.kind());
    octets.extend_from_slice(&fields);
    // The one-shot `Digest::digest` of the approved `sha2`, as crates
    // audit-log and directory-admin call it (docs.rs sha2 0.11.1).
    Ok(OperationDigest::new(<[u8; 32]>::from(Sha256::digest(
        &octets,
    ))))
}

/// The operation digest of a typed operation: what the client binds its
/// AP-REQs to, and what dird computes from the request it decoded.
///
/// # Errors
/// [`DigestError`].
///
/// Spec: docs/52 §5 items 1, 4; RFC 4120 §5.5.1.
pub fn operation_digest(operation: &Operation) -> Result<OperationDigest, DigestError> {
    let wire = operation.to_wire().map_err(DigestError::Conversion)?;
    wire_operation_digest(&wire)
}
