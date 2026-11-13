//! The schema identifiers the write PEP uses, resolved once from the
//! phase-1 schema (fail closed if one is missing).
//!
//! Spec: docs/46 §4.4 (the classes and their musts), §5.4 (the stored
//! attributes); [MS-ADTS] 5.1.3.3.3 (an attribute / class is named in an ACE
//! by its schemaIDGUID), 6.1.3 item 4 (the most specific structural class
//! GUID is the ObjectTypes input of CreateSecurityDescriptor).

use ad_schema::Phase1Schema;
use dirstore::{AttrId, ClassId};
use dtyp::Guid;

use crate::config::ConfigError;

/// One class the admin plane creates or reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClassIds {
    /// The class id.
    pub(crate) id: ClassId,
    /// Its schemaIDGUID (`DirAddChild(class)`, CreateSecurityDescriptor
    /// ObjectTypes).
    pub(crate) guid: Guid,
    /// Its full objectClass chain (`NewObject.classes`, docs/46 §8.3 item
    /// 1).
    pub(crate) chain: Vec<ClassId>,
    /// Its lDAPDisplayName (the `Lookup` reply).
    pub(crate) name: &'static str,
}

/// The resolved identifiers. Spec: docs/46 §4.4, §5.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ids {
    pub(crate) cn: AttrId,
    pub(crate) ou: AttrId,
    pub(crate) sam_account_name: AttrId,
    pub(crate) object_sid: AttrId,
    pub(crate) user_account_control: AttrId,
    pub(crate) account_expires: AttrId,
    pub(crate) pwd_last_set: AttrId,
    pub(crate) when_created: AttrId,
    pub(crate) when_changed: AttrId,
    pub(crate) nt_security_descriptor: AttrId,
    pub(crate) member: AttrId,
    /// memberOf, the back link of member (the groups holding an object;
    /// docs/46 §2.3 item 3).
    pub(crate) member_of: AttrId,
    pub(crate) group_type: AttrId,
    pub(crate) user_principal_name: AttrId,
    pub(crate) service_principal_name: AttrId,
    pub(crate) dns_host_name: AttrId,
    pub(crate) description: AttrId,
    /// schemaIDGUID of userAccountControl (`DirWrite(userAccountControl)`).
    pub(crate) uac_guid: Guid,
    /// schemaIDGUID of accountExpires (`DirWrite(accountExpires)`).
    pub(crate) account_expires_guid: Guid,
    /// schemaIDGUID of member (`DirWrite(member)`).
    pub(crate) member_guid: Guid,
    pub(crate) user: ClassIds,
    pub(crate) computer: ClassIds,
    pub(crate) group: ClassIds,
    pub(crate) organizational_unit: ClassIds,
    pub(crate) container: ClassIds,
    pub(crate) domain_dns: ClassIds,
}

impl Ids {
    /// Resolve every identifier. Spec: docs/46 §4.4, §5.4.
    pub(crate) fn resolve(p1: &Phase1Schema) -> Result<Ids, ConfigError> {
        let attr = |n: &str| p1.attribute_by_name(n).ok_or(ConfigError::Schema);
        let attr_guid = |id: AttrId| {
            p1.attribute_schema_id_guid(id)
                .map_err(|_| ConfigError::Schema)
        };
        let class = |n: &str| -> Result<ClassIds, ConfigError> {
            let id = p1.class_by_name(n).ok_or(ConfigError::Schema)?;
            let info = p1.class(id).ok_or(ConfigError::Schema)?;
            Ok(ClassIds {
                id,
                guid: info.schema_id_guid,
                chain: info.object_class.clone(),
                name: info.entry.ldap_display_name,
            })
        };
        let user_account_control = attr("userAccountControl")?;
        let account_expires = attr("accountExpires")?;
        let member = attr("member")?;
        Ok(Ids {
            cn: attr("cn")?,
            ou: attr("ou")?,
            sam_account_name: attr("sAMAccountName")?,
            object_sid: attr("objectSid")?,
            user_account_control,
            account_expires,
            pwd_last_set: attr("pwdLastSet")?,
            when_created: attr("whenCreated")?,
            when_changed: attr("whenChanged")?,
            nt_security_descriptor: attr("nTSecurityDescriptor")?,
            member,
            member_of: attr("memberOf")?,
            group_type: attr("groupType")?,
            user_principal_name: attr("userPrincipalName")?,
            service_principal_name: attr("servicePrincipalName")?,
            dns_host_name: attr("dNSHostName")?,
            description: attr("description")?,
            uac_guid: attr_guid(user_account_control)?,
            account_expires_guid: attr_guid(account_expires)?,
            member_guid: attr_guid(member)?,
            user: class("user")?,
            computer: class("computer")?,
            group: class("group")?,
            organizational_unit: class("organizationalUnit")?,
            container: class("container")?,
            domain_dns: class("domainDNS")?,
        })
    }

    /// The class record of a class id this crate knows.
    pub(crate) fn class(&self, id: ClassId) -> Option<&ClassIds> {
        [
            &self.user,
            &self.computer,
            &self.group,
            &self.organizational_unit,
            &self.container,
            &self.domain_dns,
        ]
        .into_iter()
        .find(|c| c.id == id)
    }
}
