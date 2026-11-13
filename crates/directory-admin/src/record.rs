//! Reading and encoding attribute values in their dirstore canonical forms.
//!
//! Spec: docs/46 §8.1 (Integer32 = 4 bytes big-endian two's complement;
//! DsTime = 8 bytes big-endian seconds since 1601; ObjectRef = the 16-byte
//! GUID packet), §5.4 (which attribute has which syntax; single-valued
//! attributes); [MS-DTYP] 2.3.4.2 (GUID packet), 2.4.2.2 (SID).
//!
//! Every malformed stored value is an error: the record was authenticated
//! by dirstore, so a value that does not decode is an inconsistent record
//! and the operation fails closed (AGENTS.md §6).

use dirstore::{AttrId, Object};
use dtyp::{Guid, Sid, GUID_PACKET_LEN};

/// A stored value did not have its syntax's form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// The single stored value of `id`, or `None` if absent; more than one
/// value is an inconsistent record (every attribute read here is
/// single-valued, docs/46 §5.4).
pub(crate) fn single(obj: &Object, id: AttrId) -> Result<Option<&[u8]>, Malformed> {
    match obj.attribute(id) {
        None => Ok(None),
        Some(attr) => match attr.values.as_slice() {
            [only] => Ok(Some(only.value.as_slice())),
            _ => Err(Malformed),
        },
    }
}

/// A 32-bit flag word stored as Integer32 (userAccountControl, groupType),
/// as its bit pattern. Spec: docs/46 §8.1; [MS-ADTS] 2.2.12, 2.2.16 (as
/// cited in docs/46).
pub(crate) fn flags(obj: &Object, id: AttrId) -> Result<Option<u32>, Malformed> {
    single(obj, id)?
        .map(|v| {
            <[u8; 4]>::try_from(v)
                .map(u32::from_be_bytes)
                .map_err(|_| Malformed)
        })
        .transpose()
}

/// A SID value. Spec: [MS-DTYP] 2.4.2.2; docs/46 §1.
pub(crate) fn sid(obj: &Object, id: AttrId) -> Result<Option<Sid>, Malformed> {
    single(obj, id)?
        .map(|v| Sid::decode(v).map_err(|_| Malformed))
        .transpose()
}

/// A Utf8String value. Spec: docs/46 §1.
pub(crate) fn text(obj: &Object, id: AttrId) -> Result<Option<&str>, Malformed> {
    single(obj, id)?
        .map(|v| core::str::from_utf8(v).map_err(|_| Malformed))
        .transpose()
}

/// Every GUID of a multi-valued ObjectRef attribute (`member`), in stored
/// order. Spec: docs/46 §2.3 item 1, §8.1.
pub(crate) fn refs(obj: &Object, id: AttrId) -> Result<Vec<Guid>, Malformed> {
    match obj.attribute(id) {
        None => Ok(Vec::new()),
        Some(attr) => attr
            .values
            .iter()
            .map(|v| {
                <&[u8; GUID_PACKET_LEN]>::try_from(v.value.as_slice())
                    .map(Guid::from_packet)
                    .map_err(|_| Malformed)
            })
            .collect(),
    }
}

/// The Integer32 form of a 32-bit flag word. Spec: docs/46 §8.1.
pub(crate) fn encode_flags(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// The Integer / DsTime form of a 64-bit value. Spec: docs/46 §8.1.
pub(crate) fn encode_int64(value: i64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// The ObjectRef form of a GUID. Spec: docs/46 §8.1; [MS-DTYP] 2.3.4.2.
pub(crate) fn encode_ref(guid: Guid) -> Vec<u8> {
    guid.to_packet().to_vec()
}
