//! The schema identifiers provisioning writes, resolved once from the
//! phase-1 schema (fail closed if one is missing), and the value encodings
//! of the attributes it writes.
//!
//! Spec: docs/46 §4.4 (the classes, their musts, possSuperiors), §5.4 (the
//! stored attributes and their syntaxes), §8.1 (the canonical value forms);
//! [MS-ADTS] 5.1.3.3.3 (an attribute / class is named in an ACE by its
//! schemaIDGUID), 6.1.3 item 4 (the most specific structural class GUID).

use ad_schema::Phase1Schema;
use dirstore::{AttrId, ClassId};
use dtyp::Guid;

/// One class provisioning creates objects of, or names in an ACE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClassIds {
    /// The class id.
    pub(crate) id: ClassId,
    /// Its schemaIDGUID.
    pub(crate) guid: Guid,
    /// Its full objectClass chain (`NewObject.classes`, docs/46 §8.3 item
    /// 1).
    pub(crate) chain: Vec<ClassId>,
}

/// The resolved identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SchemaIds {
    pub(crate) dc: AttrId,
    pub(crate) ou: AttrId,
    pub(crate) cn: AttrId,
    pub(crate) sam_account_name: AttrId,
    pub(crate) object_sid: AttrId,
    pub(crate) user_account_control: AttrId,
    pub(crate) account_expires: AttrId,
    pub(crate) pwd_last_set: AttrId,
    pub(crate) when_created: AttrId,
    pub(crate) when_changed: AttrId,
    pub(crate) nt_security_descriptor: AttrId,
    pub(crate) member: AttrId,
    pub(crate) group_type: AttrId,
    pub(crate) service_principal_name: AttrId,
    pub(crate) dns_host_name: AttrId,
    /// schemaIDGUID of userAccountControl (the root's WP grant).
    pub(crate) uac_guid: Guid,
    /// schemaIDGUID of accountExpires (the root's WP grant).
    pub(crate) account_expires_guid: Guid,
    /// schemaIDGUID of member (the root's WP grant).
    pub(crate) member_guid: Guid,
    pub(crate) domain_dns: ClassIds,
    pub(crate) organizational_unit: ClassIds,
    pub(crate) container: ClassIds,
    pub(crate) user: ClassIds,
    pub(crate) computer: ClassIds,
    pub(crate) group: ClassIds,
}

/// A name the phase-1 schema lacks (an internal inconsistency).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SchemaMissing;

impl SchemaIds {
    /// Resolve every identifier by lDAPDisplayName. Spec: docs/46 §4.4,
    /// §5.4.
    pub(crate) fn resolve(p1: &Phase1Schema) -> Result<SchemaIds, SchemaMissing> {
        let attr = |n: &str| p1.attribute_by_name(n).ok_or(SchemaMissing);
        let attr_guid = |id: AttrId| p1.attribute_schema_id_guid(id).map_err(|_| SchemaMissing);
        let class = |n: &str| -> Result<ClassIds, SchemaMissing> {
            let id = p1.class_by_name(n).ok_or(SchemaMissing)?;
            let info = p1.class(id).ok_or(SchemaMissing)?;
            Ok(ClassIds {
                id,
                guid: info.schema_id_guid,
                chain: info.object_class.clone(),
            })
        };
        let user_account_control = attr("userAccountControl")?;
        let account_expires = attr("accountExpires")?;
        let member = attr("member")?;
        Ok(SchemaIds {
            dc: attr("dc")?,
            ou: attr("ou")?,
            cn: attr("cn")?,
            sam_account_name: attr("sAMAccountName")?,
            object_sid: attr("objectSid")?,
            user_account_control,
            account_expires,
            pwd_last_set: attr("pwdLastSet")?,
            when_created: attr("whenCreated")?,
            when_changed: attr("whenChanged")?,
            nt_security_descriptor: attr("nTSecurityDescriptor")?,
            member,
            group_type: attr("groupType")?,
            service_principal_name: attr("servicePrincipalName")?,
            dns_host_name: attr("dNSHostName")?,
            uac_guid: attr_guid(user_account_control)?,
            account_expires_guid: attr_guid(account_expires)?,
            member_guid: attr_guid(member)?,
            domain_dns: class("domainDNS")?,
            organizational_unit: class("organizationalUnit")?,
            container: class("container")?,
            user: class("user")?,
            computer: class("computer")?,
            group: class("group")?,
        })
    }
}

/// The Integer32 form of a 32-bit flag word (userAccountControl,
/// groupType): 4 octets, big-endian two's complement of the bit pattern.
/// Spec: docs/46 §8.1. (The same encoding as crates/directory-admin's
/// private `record::encode_flags`.)
pub(crate) fn integer32(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// The Integer / DsTime form of a 64-bit value (accountExpires, pwdLastSet,
/// whenCreated, whenChanged): 8 octets, big-endian.
/// Spec: docs/46 §8.1.
pub(crate) fn integer64(value: i64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// The ObjectRef form of a GUID (member): the 16-octet [MS-DTYP] 2.3.4.2
/// packet. Spec: docs/46 §8.1.
pub(crate) fn object_ref(guid: Guid) -> Vec<u8> {
    guid.to_packet().to_vec()
}

/// The Utf8String form of a name (ASCII here, P-6). Spec: docs/46 §1, §8.1.
pub(crate) fn text(value: &str) -> Vec<u8> {
    value.as_bytes().to_vec()
}
