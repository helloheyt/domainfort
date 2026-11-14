//! The security descriptor of a new object.
//!
//! Spec: [MS-ADTS] v20261026 6.1.3 items 1, 4, 5, 7 (CreateSecurityDescriptor
//! inputs for a directory object; "NULL DACLs are disallowed"), 6.1.3.7
//! (OWNER: the DAG when defined, else the requester's SID), 6.1.3.8 (the DAG
//! is Domain Admins / Enterprise Admins, "Otherwise, the DAG is undefined"
//! — phase 1 has neither, D50); [MS-ADTS] 3.1.1.5.2.4 ("The
//! nTSecurityDescriptor value is computed and set on the object"); decisions
//! A-76 (Q-294 (a)) and A-84 (Q-336: the caller's inputs).

use dirstore::Object;
use dtyp::{
    create_security_descriptor, AutoInheritFlags, GenericMapping, Guid, SecurityDescriptor, Sid,
    Token,
};
use ipc_audit::{AdminFailure, AdminRefusal};

use crate::audit::Stop;
use crate::checks::malformed;
use crate::ids::Ids;
use crate::record;

/// The descriptor of a new object of the class whose schemaIDGUID is
/// `class_guid`, created under `parent` by `requester`:
///
/// - ParentDescriptor = the parent's nTSecurityDescriptor (6.1.3 item 5.1;
///   the admin plane never creates an NC root);
/// - CreatorDescriptor = NULL (A-76: no defaultSecurityDescriptor in phase
///   1);
/// - IsContainerObject = TRUE (6.1.3 item 5.3: "TRUE is always passed");
/// - ObjectTypes = the most specific structural class GUID (6.1.3 item 4;
///   phase 1 has no dynamic auxiliary class — A-84, Q-336 item 11);
/// - AutoInheritFlags = DACL_AUTO_INHERIT | SACL_AUTO_INHERIT (6.1.3 item
///   5.4; without a CreatorDescriptor they have no effect — Q-336 item 9);
/// - Token: owner and primary group = the requester's SID (6.1.3.7 with the
///   DAG undefined, 6.1.3.8; A-76), no default DACL;
/// - GenericMapping = the Active Directory table (6.1.3 item 5.6).
///
/// A result without a DACL is refused (6.1.3 item 7: "NULL DACLs are
/// disallowed"; A-84). A parent without a descriptor, or one that does not
/// decode, is an inconsistent record (nTSecurityDescriptor is a must on
/// top, docs/46 §4.4).
pub(crate) fn new_object_sd(
    ids: &Ids,
    parent: &Object,
    class_guid: Guid,
    requester: &Sid,
) -> Result<SecurityDescriptor, Stop> {
    let bytes = record::single(parent, ids.nt_security_descriptor)
        .map_err(malformed)?
        .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?;
    let parent_sd = SecurityDescriptor::decode(bytes)
        .map_err(|_| Stop::Failed(AdminFailure::IntegrityFailure))?;
    new_object_descriptor(&parent_sd, class_guid, requester).map_err(|e| match e {
        DescriptorError::Computation => Stop::Failed(AdminFailure::InternalFailure),
        DescriptorError::NoDacl => Stop::Refused(AdminRefusal::ValueInvalid),
    })
}

/// Why [`new_object_descriptor`] produced no descriptor.
/// Spec: [MS-ADTS] 6.1.3 item 7; decision A-84 (Q-336 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DescriptorError {
    /// CreateSecurityDescriptor refused its inputs (`dtyp::Error`: an
    /// unsupported inheritable ACE, an ACL over its bound, …).
    Computation,
    /// The result has no DACL ("NULL DACLs are disallowed").
    NoDacl,
}

/// The security descriptor of a new object of the class whose schemaIDGUID
/// is `class_guid`, created under a parent whose descriptor is `parent`, on
/// behalf of `owner` — the one computation of this crate's creates
/// ([`DirectoryAdmin::apply`](crate::DirectoryAdmin::apply)), public so that
/// `provision domain` (docs/51 §12 task A4) computes every provisioned
/// object's descriptor exactly as the runtime write path does (docs/51
/// §10: "provisioning and runtime agree"):
///
/// - ParentDescriptor = `parent` (6.1.3 item 5.1);
/// - CreatorDescriptor = NULL (A-76: no defaultSecurityDescriptor in phase
///   1);
/// - IsContainerObject = TRUE (6.1.3 item 5.3);
/// - ObjectTypes = `[class_guid]`, the most specific structural class
///   (6.1.3 item 4; Q-336 item 11);
/// - AutoInheritFlags = DACL_AUTO_INHERIT | SACL_AUTO_INHERIT (6.1.3 item
///   5.4; Q-336 item 9);
/// - Token: owner and primary group = `owner` (6.1.3.7 with the DAG
///   undefined, 6.1.3.8; A-76), no default DACL;
/// - GenericMapping = the Active Directory table (6.1.3 item 5.6).
///
/// A result without a DACL is refused (6.1.3 item 7).
///
/// # Errors
/// [`DescriptorError`].
///
/// Spec: [MS-ADTS] 6.1.3 items 4, 5, 7, 6.1.3.7, 6.1.3.8; [MS-DTYP]
/// 2.5.3.4; A-76; A-84.
pub fn new_object_descriptor(
    parent: &SecurityDescriptor,
    class_guid: Guid,
    owner: &Sid,
) -> Result<SecurityDescriptor, DescriptorError> {
    let token = Token {
        owner: *owner,
        primary_group: *owner,
        default_dacl: None,
    };
    let flags = AutoInheritFlags {
        dacl_auto_inherit: true,
        sacl_auto_inherit: true,
        ..AutoInheritFlags::default()
    };
    let sd = create_security_descriptor(
        Some(parent),
        None,
        true,
        Some(&[class_guid]),
        flags,
        &token,
        &GenericMapping::ACTIVE_DIRECTORY,
    )
    .map_err(|_| DescriptorError::Computation)?;
    if sd.dacl.is_none() {
        return Err(DescriptorError::NoDacl);
    }
    Ok(sd)
}
