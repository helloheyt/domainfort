//! Errors. None carries a name, a key or any directory value (AGENTS.md §6:
//! no secret, and nothing an attacker could use as an oracle, in errors).
//!
//! Every lookup failure inside a view is a [`Fault`]; the trait boundaries
//! map it to `kdc::AccountSourceError` (the request fails closed,
//! KRB_ERR_GENERIC — Q-070 item 10) or to `pdp::PipError` (Deny — D40).
//!
//! Spec: AGENTS.md §6 ("fail closed"; "secrets never appear in ... error
//! messages"); docs/47 §5.3 item 3, §8; D40.

use pdp::PipError;

/// Building a [`crate::DirectoryContext`] or a [`crate::DirectoryView`]
/// failed. Fail closed: no view, no answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ViewError {
    /// keyd's configuration is invalid (`KeydConfig::validate`).
    KeydConfig,
    /// The realm is not the domain's DNS name in upper case: it is empty or
    /// holds an a-z letter (docs/47 §3.3 item 3; [MS-KILE] 3.1.1.2 "DNS of
    /// the realm, converted to uppercase"; RFC 4120 §6.1).
    RealmNotUppercase,
    /// An attribute or class this crate needs is missing from the schema, or
    /// has an unexpected definition (unique / single-valued / link role).
    Schema,
    /// The store was opened with a different schema than the context's.
    SchemaMismatch,
    /// The store could not hand out a snapshot.
    Store,
    /// The tier map is malformed (an empty subtree DN).
    TierMap,
    /// The naming context is malformed (no label, too many, a label that is
    /// empty, not printable ASCII, holds "." or is too long), or its DNS
    /// name in upper case is not the realm (A-53; [MS-ADTS] 3.1.1.1.5;
    /// docs/47 §3.3 item 3).
    NamingContext,
}

impl core::fmt::Display for ViewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ViewError::KeydConfig => "keyd configuration is invalid",
            ViewError::RealmNotUppercase => "realm is not an upper-case DNS name",
            ViewError::Schema => "schema lacks a required definition",
            ViewError::SchemaMismatch => "store schema differs from the context schema",
            ViewError::Store => "store snapshot failed",
            ViewError::TierMap => "tier map is malformed",
            ViewError::NamingContext => "naming context is malformed or does not name the realm",
        })
    }
}

impl std::error::Error for ViewError {}

/// Why a lookup inside a view produced no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Fault {
    /// The item does not exist in the snapshot.
    NotFound,
    /// The store failed, a record is inconsistent with the rules of
    /// docs/47, or a bound was exceeded.
    Unavailable,
}

impl From<dirstore::Error> for Fault {
    /// Any store error (tamper, inconsistency, I/O, refused input) is
    /// "cannot tell". Spec: AGENTS.md §6 (fail closed).
    fn from(_: dirstore::Error) -> Fault {
        Fault::Unavailable
    }
}

impl From<Fault> for PipError {
    /// Spec: pdp `PipError` (NotFound / Unavailable; both Deny, D40).
    fn from(fault: Fault) -> PipError {
        match fault {
            Fault::NotFound => PipError::NotFound,
            Fault::Unavailable => PipError::Unavailable,
        }
    }
}

impl From<Fault> for kdc::AccountSourceError {
    /// Spec: kdc `AccountSource` ("`Err` means cannot tell and always refuses
    /// the request").
    fn from(_: Fault) -> kdc::AccountSourceError {
        kdc::AccountSourceError
    }
}
