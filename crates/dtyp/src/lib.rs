#![forbid(unsafe_code)]
//! `dtyp`: a strict, bounded parser and canonical encoder for the Windows
//! security data types that the directory and the PDP need.
//!
//! # Scope
//!
//! Data types only (docs/11 §5 needs them; the access-check algorithm of
//! [MS-DTYP] 2.5.3 is the next crate):
//!
//! - [`Guid`] — packet representation ([MS-DTYP] 2.3.4.2).
//! - [`Sid`] — packet representation and the "S-1-..." string form (decimal
//!   or hexadecimal authority, 0 to 15 SubAuthority values) ([MS-DTYP] 2.4.1,
//!   2.4.2.1, 2.4.2.2, 2.4.2.4; RFC 5234 §2.3, Appendix B.1).
//! - [`AccessMask`] — generic, standard and directory-object rights
//!   ([MS-DTYP] 2.4.3, 2.4.4.3, 2.5.1.1).
//! - [`Ace`] — ACE_HEADER and the ACCESS_ALLOWED, ACCESS_DENIED,
//!   ACCESS_ALLOWED_OBJECT, ACCESS_DENIED_OBJECT, SYSTEM_AUDIT and
//!   SYSTEM_AUDIT_OBJECT ACEs; every other defined AceType is kept whole as
//!   [`Ace::Unsupported`] so the access-check layer can fail closed on it
//!   ([MS-DTYP] 2.4.4.x).
//! - [`Acl`] — revision, AclSize / AceCount consistency, revision-versus-type
//!   and SACL / DACL type rules ([MS-DTYP] 2.4.5).
//! - [`SecurityDescriptor`] — self-relative form with every offset and size
//!   validated against the buffer ([MS-DTYP] 2.4.6).
//!
//! Out of scope: SDDL (2.5.1), the curly-braced GUID string (2.3.4.3, defined
//! via RFC 4122, not an allowed source), the RPC (IDL) representations, the
//! absolute security descriptor form, and the access-check algorithm.
//!
//! # Byte order
//!
//! Multi-byte fields are little-endian: a self-relative security descriptor
//! "is sent in little-endian format" ([MS-DTYP] 2.4.6), and the SID / ACL /
//! ACE packets here are the ones carried inside it. A protocol that carries a
//! stand-alone SID with another byte order (2.4.2.2 leaves it to "the protocol
//! in question") must not use [`Sid::decode`] without checking its own spec.
//!
//! # Strictness
//!
//! Every count, size and offset is checked against the input before it is
//! used; nothing is allocated from an attacker-controlled count without such a
//! bound; there is no recursion. Every violated rule is a distinct [`Error`]
//! (fail closed — AGENTS.md §6; docs/32 §8). Where the text needed a reading,
//! the reading is recorded in `docs/questions/` (Q-020 to Q-025, resolved).
//!
//! The encoder is canonical and refuses values the decoder would reject, so
//! `decode(encode(v)) == v` always holds and `encode(decode(b)) == b` holds for
//! canonical input. Non-canonical but valid input (components in another
//! order, padding inside AceSize that MUST be ignored) decodes, and re-encodes
//! to the canonical form.
//!
//! # Provenance
//!
//! Written only from [MS-DTYP] v20241119 (protocol revision 42.0, release
//! 2024-11-19; pinned PDF, sha256 0f4a3744…83b3 in
//! tools/spec-pin/manifest.json), opened in-session: sections 2.1, 2.3.4,
//! 2.4.1, 2.4.2, 2.4.3, 2.4.4.1-2.4.4.16, 2.4.5, 2.4.6, 2.5.1.1 (rights table)
//! and 2.5.1.4 (worked example); and RFC 5234 (STD 68, January 2008) §2.3 and
//! Appendix B.1, which [MS-DTYP] 2.4.2.1 cites for its grammar, read from
//! www.rfc-editor.org. No other implementation was consulted or recalled
//! (AGENTS.md §1-3).
//!
//! Spec: [MS-DTYP] 2.3.4, 2.4.1-2.4.6; RFC 5234 §2.3, Appendix B.1.

mod access_mask;
mod ace;
mod acl;
mod error;
mod guid;
mod reader;
mod security_descriptor;
mod sid;

pub use access_mask::AccessMask;
pub use ace::{
    ace_flags, ace_type, is_supported_ace_type, Ace, AceHeader, MaskSidAce, ObjectAce,
    UnsupportedAce, ACE_HEADER_LEN, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT,
    MAX_ACE_SIZE,
};
pub use acl::{
    acl_revision_permits, is_valid_sacl_ace_type, Acl, ACL_HEADER_LEN, ACL_REVISION,
    ACL_REVISION_DS, MAX_ACL_SIZE,
};
pub use error::{Error, Result};
pub use guid::{Guid, GUID_PACKET_LEN};
pub use security_descriptor::{
    Control, SecurityDescriptor, SD_FIXED_LEN, SECURITY_DESCRIPTOR_REVISION,
};
pub use sid::{
    Sid, CREATOR_SID_AUTHORITY, LOCAL_SID_AUTHORITY, NON_UNIQUE_AUTHORITY, NULL_SID_AUTHORITY,
    SECURITY_APP_PACKAGE_AUTHORITY, SECURITY_AUTHENTICATION_AUTHORITY,
    SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_NT_AUTHORITY, SECURITY_SCOPED_POLICY_ID_AUTHORITY,
    SID_MAX_SUB_AUTHORITIES, SID_REVISION, WORLD_SID_AUTHORITY,
};
