//! The schema identifiers this crate reads, and typed readers for the stored
//! values of one object.
//!
//! Identifiers are resolved once, by lDAPDisplayName, from the phase-1
//! schema (docs/46 §7: AttrId / ClassId by lDAPDisplayName), and checked
//! against the definitions docs/47 relies on: the three lookup attributes
//! are `unique` and single-valued (docs/46 §8.5; R47-13 for
//! servicePrincipalName), memberOf is a back link (docs/46 §2.3 item 3).
//! A schema that differs fails closed when the context is built.
//!
//! Value forms are dirstore's canonical ones (docs/46 §1, §8.1): Integer32 =
//! 4 bytes and Integer / DsTime = 8 bytes, two's complement big-endian; Sid
//! = the [MS-DTYP] 2.4.2.2 packet; Utf8String = UTF-8 text.
//!
//! Spec: docs/46 §1, §2.3, §5.4, §7, §8.1, §8.5; docs/47 §1.3, §4, §5.3,
//! R47-13.

use crate::error::{Fault, ViewError};
use ad_schema::Phase1Schema;
use dirstore::{AttrId, ClassId, Link, Multiplicity, Object, Storage};
use dtyp::Sid;

/// The schema identifiers of the attributes and classes docs/47 reads.
/// Spec: docs/47 §1.3, §4, §5.3, §8.2; docs/46 §5.2, §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ids {
    pub(crate) sam_account_name: AttrId,
    pub(crate) object_sid: AttrId,
    pub(crate) service_principal_name: AttrId,
    pub(crate) user_account_control: AttrId,
    pub(crate) account_expires: AttrId,
    pub(crate) pwd_last_set: AttrId,
    pub(crate) when_created: AttrId,
    pub(crate) member_of: AttrId,
    /// The forward link memberOf is the back link of (task MA3: the
    /// downward walk of an effect plan, crate::groups `member_closure`).
    pub(crate) member: AttrId,
    pub(crate) group_type: AttrId,
    pub(crate) nt_security_descriptor: AttrId,
    /// The RDN attribute of every component of the naming context's DN
    /// (A-53; [MS-ADTS] 3.1.1.1.5, 3.1.1.3.1.2.2).
    pub(crate) dc: AttrId,
    pub(crate) user: ClassId,
    pub(crate) computer: ClassId,
    pub(crate) group: ClassId,
    pub(crate) domain_dns: ClassId,
}

impl Ids {
    /// Resolve and check every identifier (module docs). Fail closed.
    /// Spec: docs/46 §7, §8.5, §2.3; R47-13.
    pub(crate) fn resolve(p1: &Phase1Schema) -> Result<Ids, ViewError> {
        let attr = |n: &str| p1.attribute_by_name(n).ok_or(ViewError::Schema);
        let class = |n: &str| p1.class_by_name(n).ok_or(ViewError::Schema);
        let ids = Ids {
            sam_account_name: attr("sAMAccountName")?,
            object_sid: attr("objectSid")?,
            service_principal_name: attr("servicePrincipalName")?,
            user_account_control: attr("userAccountControl")?,
            account_expires: attr("accountExpires")?,
            pwd_last_set: attr("pwdLastSet")?,
            when_created: attr("whenCreated")?,
            member_of: attr("memberOf")?,
            member: attr("member")?,
            group_type: attr("groupType")?,
            nt_security_descriptor: attr("nTSecurityDescriptor")?,
            dc: attr(crate::naming::NC_RDN_ATTRIBUTE)?,
            user: class("user")?,
            computer: class("computer")?,
            group: class("group")?,
            domain_dns: class("domainDNS")?,
        };
        let schema = p1.schema();
        // The exact-match lookups need a unique, single-valued index.
        for id in [
            ids.sam_account_name,
            ids.object_sid,
            ids.service_principal_name,
        ] {
            let def = schema.attribute(id).ok_or(ViewError::Schema)?;
            if !def.unique
                || def.multiplicity != Multiplicity::SingleValued
                || def.storage != Storage::Stored
            {
                return Err(ViewError::Schema);
            }
        }
        // memberOf is answered from the reverse-link index.
        let member_of = schema.attribute(ids.member_of).ok_or(ViewError::Schema)?;
        if !matches!(member_of.link, Some(Link::Back { .. })) {
            return Err(ViewError::Schema);
        }
        // member is the forward link (its values are objectGUID packets).
        let member = schema.attribute(ids.member).ok_or(ViewError::Schema)?;
        if !matches!(member.link, Some(Link::Forward { .. })) {
            return Err(ViewError::Schema);
        }
        // The NC root is a domainDNS object named by dc ([MS-ADTS]
        // 3.1.1.3.1.2.2: "The rDNAttID for the domainDNS class is dc").
        let domain_dns = schema.class(ids.domain_dns).ok_or(ViewError::Schema)?;
        if domain_dns.rdn_attr != ids.dc {
            return Err(ViewError::Schema);
        }
        Ok(ids)
    }
}

/// The single stored value of `id`, or `None` if absent. More than one value
/// is an inconsistent record (every attribute read here is single-valued).
/// Spec: docs/46 §5.4 (Single); AGENTS.md §6 (fail closed).
pub(crate) fn single(obj: &Object, id: AttrId) -> Result<Option<&[u8]>, Fault> {
    match obj.attribute(id) {
        None => Ok(None),
        Some(attr) => match attr.values.as_slice() {
            [only] => Ok(Some(only.value.as_slice())),
            _ => Err(Fault::Unavailable),
        },
    }
}

/// An Integer32 value. Spec: docs/46 §8.1 (4 bytes, big-endian).
pub(crate) fn int32(obj: &Object, id: AttrId) -> Result<Option<i32>, Fault> {
    single(obj, id)?
        .map(|v| {
            <[u8; 4]>::try_from(v)
                .map(i32::from_be_bytes)
                .map_err(|_| Fault::Unavailable)
        })
        .transpose()
}

/// A 32-bit flag word stored as Integer32 (userAccountControl, groupType),
/// as its bit pattern. Spec: docs/46 §5.4; [MS-ADTS] 2.2.12, 2.2.16.
pub(crate) fn flags(obj: &Object, id: AttrId) -> Result<Option<u32>, Fault> {
    Ok(int32(obj, id)?.map(|v| u32::from_be_bytes(v.to_be_bytes())))
}

/// An Integer (LargeInteger) or DsTime value. Spec: docs/46 §8.1 (8 bytes,
/// big-endian).
pub(crate) fn int64(obj: &Object, id: AttrId) -> Result<Option<i64>, Fault> {
    single(obj, id)?
        .map(|v| {
            <[u8; 8]>::try_from(v)
                .map(i64::from_be_bytes)
                .map_err(|_| Fault::Unavailable)
        })
        .transpose()
}

/// A SID value. Spec: [MS-DTYP] 2.4.2.2; docs/46 §1 (String(Sid) → Sid).
pub(crate) fn sid(obj: &Object, id: AttrId) -> Result<Option<Sid>, Fault> {
    single(obj, id)?
        .map(|v| Sid::decode(v).map_err(|_| Fault::Unavailable))
        .transpose()
}

/// A Utf8String value. Spec: docs/46 §1 (String(Unicode) → Utf8String).
pub(crate) fn text(obj: &Object, id: AttrId) -> Result<Option<&str>, Fault> {
    single(obj, id)?
        .map(|v| core::str::from_utf8(v).map_err(|_| Fault::Unavailable))
        .transpose()
}

/// The objectGUIDs of a link attribute's values (ObjectRef: the 16-octet
/// objectGUID packet, docs/46 §8.1). A value of another length is an
/// inconsistent record.
/// Spec: docs/46 §8.1; [MS-DTYP] 2.3.4.2.
pub(crate) fn refs(obj: &Object, id: AttrId) -> Result<Vec<dtyp::Guid>, Fault> {
    match obj.attribute(id) {
        None => Ok(Vec::new()),
        Some(attr) => attr
            .values
            .iter()
            .map(|v| {
                <&[u8; 16]>::try_from(v.value.as_slice())
                    .map(dtyp::Guid::from_packet)
                    .map_err(|_| Fault::Unavailable)
            })
            .collect(),
    }
}
