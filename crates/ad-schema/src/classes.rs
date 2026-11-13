//! The 10 phase-1 class definitions: 6 instantiable (domainDNS as NC root
//! only, organizationalUnit, container, user, computer, group) and 4 that
//! only appear in chains (top, domain, person, organizationalPerson).
//!
//! Each row carries the classSchema values of its [MS-ADSC] entry (named in
//! `source`), the dirstore class definition decided in docs/46 §4.4
//! (`must`, `may`, `poss_superiors`, `nc_root`) and `spec_attributes`: the
//! entry's own mustContain / systemMustContain / mayContain /
//! systemMayContain together with those of its statically linked auxiliary
//! classes (folded, docs/46 §4.3), cut to the 35 phase-1 attributes — the
//! per-class input of CLASSATTS ([MS-ADTS] 3.1.1.4.2) for the object type
//! tree (docs/46 §7). The ClassId is computed from `governs_id` with
//! [`crate::make_attid`] (R46-3); `instantiable` from objectClassCategory.
//!
//! All names here are lDAPDisplayNames resolved against the tables when the
//! schema is built (an unknown name fails closed).
//!
//! Spec: docs/46 §4.1-§4.4, §7 (decided, A-29: R46-8, R46-9); [MS-ADSC]
//! v20240423 (the entry in each row's `source`; auxiliary classes 2.85,
//! 2.134, 2.244, 2.245, 2.249, 2.67, 2.224, 2.225, 2.256); [MS-ADTS]
//! v20261026 3.1.1.2.4.6 (static auxiliary classes), 3.1.1.4.2 (SUPCLASSES,
//! AUXCLASSES, POSSSUPERIORS, CLASSATTS).

/// One phase-1 class. Spec: [MS-ADTS] 3.1.1.2.4.8 (classSchema); docs/46 §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassEntry {
    /// lDAPDisplayName.
    pub ldap_display_name: &'static str,
    /// cn of the classSchema object.
    pub cn: &'static str,
    /// governsID (OID).
    pub governs_id: &'static str,
    /// schemaIDGUID, as printed.
    pub schema_id_guid: &'static str,
    /// objectClassCategory: 0 = 88 class, 1 = structural, 2 = abstract,
    /// 3 = auxiliary ([MS-ADTS] 3.1.1.2.4.8). Phase 1 instantiates only
    /// structural classes (docs/46 §4.1, D104).
    pub object_class_category: u32,
    /// subClassOf (lDAPDisplayName; `top` names itself).
    pub sub_class_of: &'static str,
    /// rDNAttID (lDAPDisplayName).
    pub rdn_att_id: &'static str,
    /// defaultObjectCategory, as the cn of the class it names (the entry
    /// prints `CN=<cn>,<SchemaNCDN>`).
    pub default_object_category: &'static str,
    /// systemOnly.
    pub system_only: bool,
    /// The entry the values were read from.
    pub source: &'static str,
    /// dirstore must-attributes (stored only). Spec: docs/46 §4.4.
    pub must: &'static [&'static str],
    /// dirstore may-attributes (stored, plus the Secret ones [MS-ADSC]
    /// allows). Spec: docs/46 §4.4.
    pub may: &'static [&'static str],
    /// Flattened possible superiors, cut to phase-1 instantiable classes.
    /// Spec: docs/46 §4.4; [MS-ADTS] 3.1.1.4.2 (POSSSUPERIORS).
    pub poss_superiors: &'static [&'static str],
    /// The root of a naming context (no parent). Spec: docs/46 §8.3.
    pub nc_root: bool,
    /// (own ∪ statically linked auxiliary) attributes ∩ the 35 phase-1
    /// attributes. Spec: [MS-ADTS] 3.1.1.4.2 (CLASSATTS); docs/46 §7.
    pub spec_attributes: &'static [&'static str],
}

/// The 10 phase-1 classes, in docs/46 §4.2 order.
pub static CLASSES: [ClassEntry; 10] = [
    // Spec: [MS-ADSC] 2.266 top. systemMustContain objectClass,
    // objectCategory, nTSecurityDescriptor, instanceType; of its
    // systemMayContain, whenCreated, whenChanged, name, objectGUID,
    // distinguishedName, memberOf, description and cn are phase-1
    // attributes. docs/46 §4.4: derived attributes are not in `must`.
    ClassEntry {
        ldap_display_name: "top",
        cn: "Top",
        governs_id: "2.5.6.0",
        schema_id_guid: "bf967ab7-0de6-11d0-a285-00aa003049e2",
        object_class_category: 2,
        sub_class_of: "top",
        rdn_att_id: "cn",
        default_object_category: "Top",
        system_only: true,
        source: "[MS-ADSC] 2.266",
        must: &["nTSecurityDescriptor"],
        may: &["description", "cn", "whenCreated", "whenChanged"],
        poss_superiors: &[],
        nc_root: false,
        spec_attributes: &[
            "objectClass",
            "objectCategory",
            "nTSecurityDescriptor",
            "instanceType",
            "whenCreated",
            "whenChanged",
            "name",
            "objectGUID",
            "distinguishedName",
            "memberOf",
            "description",
            "cn",
        ],
    },
    // Spec: [MS-ADSC] 2.43 domain (systemMustContain dc).
    ClassEntry {
        ldap_display_name: "domain",
        cn: "Domain",
        governs_id: "1.2.840.113556.1.5.66",
        schema_id_guid: "19195a5a-6da0-11d0-afd3-00c04fd930c9",
        object_class_category: 2,
        sub_class_of: "top",
        rdn_att_id: "dc",
        default_object_category: "Domain-DNS",
        system_only: false,
        source: "[MS-ADSC] 2.43",
        must: &["dc"],
        may: &[],
        poss_superiors: &[],
        nc_root: false,
        spec_attributes: &["dc"],
    },
    // Spec: [MS-ADSC] 2.44 domainDNS (systemAuxiliaryClass samDomain, 2.244:
    // description; its systemAuxiliaryClass samDomainBase, 2.245: objectSid,
    // nTSecurityDescriptor). docs/46 §4.4: NC root only (domainDNS →
    // domainDNS, a child domain, is outside phase 1).
    ClassEntry {
        ldap_display_name: "domainDNS",
        cn: "Domain-DNS",
        governs_id: "1.2.840.113556.1.5.67",
        schema_id_guid: "19195a5b-6da0-11d0-afd3-00c04fd930c9",
        object_class_category: 1,
        sub_class_of: "domain",
        rdn_att_id: "dc",
        default_object_category: "Domain-DNS",
        system_only: false,
        source: "[MS-ADSC] 2.44",
        must: &[],
        may: &["objectSid"],
        poss_superiors: &[],
        nc_root: true,
        spec_attributes: &["description", "objectSid", "nTSecurityDescriptor"],
    },
    // Spec: [MS-ADSC] 2.218 organizationalUnit (systemMustContain ou;
    // systemPossSuperiors country, organization, organizationalUnit,
    // domainDNS).
    ClassEntry {
        ldap_display_name: "organizationalUnit",
        cn: "Organizational-Unit",
        governs_id: "2.5.6.5",
        schema_id_guid: "bf967aa5-0de6-11d0-a285-00aa003049e2",
        object_class_category: 1,
        sub_class_of: "top",
        rdn_att_id: "ou",
        default_object_category: "Organizational-Unit",
        system_only: false,
        source: "[MS-ADSC] 2.218",
        must: &["ou"],
        may: &[],
        poss_superiors: &["organizationalUnit", "domainDNS"],
        nc_root: false,
        spec_attributes: &["ou"],
    },
    // Spec: [MS-ADSC] 2.25 container (systemMustContain cn).
    ClassEntry {
        ldap_display_name: "container",
        cn: "Container",
        governs_id: "1.2.840.113556.1.3.23",
        schema_id_guid: "bf967a8b-0de6-11d0-a285-00aa003049e2",
        object_class_category: 1,
        sub_class_of: "top",
        rdn_att_id: "cn",
        default_object_category: "Container",
        system_only: false,
        source: "[MS-ADSC] 2.25",
        must: &["cn"],
        may: &[],
        poss_superiors: &["domainDNS", "container", "organizationalUnit"],
        nc_root: false,
        spec_attributes: &["cn"],
    },
    // Spec: [MS-ADSC] 2.220 person (88 class; systemMustContain cn).
    ClassEntry {
        ldap_display_name: "person",
        cn: "Person",
        governs_id: "2.5.6.6",
        schema_id_guid: "bf967aa7-0de6-11d0-a285-00aa003049e2",
        object_class_category: 0,
        sub_class_of: "top",
        rdn_att_id: "cn",
        default_object_category: "Person",
        system_only: false,
        source: "[MS-ADSC] 2.220",
        must: &["cn"],
        may: &[],
        poss_superiors: &[],
        nc_root: false,
        spec_attributes: &["cn"],
    },
    // Spec: [MS-ADSC] 2.216 organizationalPerson (88 class; ou is in its
    // systemMayContain). docs/46 §4.4 / R46-8: ou is left out of the
    // dirstore definition in phase 1; CLASSATTS keeps it (docs/46 §7: the
    // full lists, cut to the 35 definitions).
    ClassEntry {
        ldap_display_name: "organizationalPerson",
        cn: "Organizational-Person",
        governs_id: "2.5.6.7",
        schema_id_guid: "bf967aa4-0de6-11d0-a285-00aa003049e2",
        object_class_category: 0,
        sub_class_of: "person",
        rdn_att_id: "cn",
        default_object_category: "Person",
        system_only: false,
        source: "[MS-ADSC] 2.216",
        must: &[],
        may: &[],
        poss_superiors: &[],
        nc_root: false,
        spec_attributes: &["ou"],
    },
    // Spec: [MS-ADSC] 2.269 user. Own systemMayContain: userPrincipalName,
    // userAccountControl, unicodePwd, servicePrincipalName, pwdLastSet,
    // ntPwdHistory, lmPwdHistory, dBCSPwd, accountExpires.
    // systemAuxiliaryClass securityPrincipal (2.249: sAMAccountName,
    // objectSid; supplementalCredentials, nTSecurityDescriptor),
    // mailRecipient (2.85: cn), msDS-CloudExtensions (2.134: none);
    // auxiliaryClass shadowAccount (2.256: description), posixAccount
    // (2.224: cn, description).
    ClassEntry {
        ldap_display_name: "user",
        cn: "User",
        governs_id: "1.2.840.113556.1.5.9",
        schema_id_guid: "bf967aba-0de6-11d0-a285-00aa003049e2",
        object_class_category: 1,
        sub_class_of: "organizationalPerson",
        rdn_att_id: "cn",
        default_object_category: "Person",
        system_only: false,
        source: "[MS-ADSC] 2.269",
        must: &["cn", "sAMAccountName", "objectSid"],
        may: &[
            "userPrincipalName",
            "servicePrincipalName",
            "userAccountControl",
            "accountExpires",
            "pwdLastSet",
            "unicodePwd",
            "ntPwdHistory",
            "lmPwdHistory",
            "dBCSPwd",
            "supplementalCredentials",
        ],
        poss_superiors: &["organizationalUnit", "domainDNS", "container"],
        nc_root: false,
        spec_attributes: &[
            "userPrincipalName",
            "userAccountControl",
            "unicodePwd",
            "servicePrincipalName",
            "pwdLastSet",
            "ntPwdHistory",
            "lmPwdHistory",
            "dBCSPwd",
            "accountExpires",
            "sAMAccountName",
            "objectSid",
            "supplementalCredentials",
            "nTSecurityDescriptor",
            "cn",
            "description",
        ],
    },
    // Spec: [MS-ADSC] 2.21 computer. Own systemMayContain: dNSHostName, cn;
    // auxiliaryClass ipHost (2.67: cn, description).
    ClassEntry {
        ldap_display_name: "computer",
        cn: "Computer",
        governs_id: "1.2.840.113556.1.3.30",
        schema_id_guid: "bf967a86-0de6-11d0-a285-00aa003049e2",
        object_class_category: 1,
        sub_class_of: "user",
        rdn_att_id: "cn",
        default_object_category: "Computer",
        system_only: false,
        source: "[MS-ADSC] 2.21",
        must: &[],
        may: &["dNSHostName"],
        poss_superiors: &["container", "organizationalUnit", "domainDNS"],
        nc_root: false,
        spec_attributes: &["dNSHostName", "cn", "description"],
    },
    // Spec: [MS-ADSC] 2.55 group. systemMustContain groupType; own
    // systemMayContain: member. systemAuxiliaryClass mailRecipient (2.85:
    // cn), securityPrincipal (2.249: sAMAccountName, objectSid;
    // supplementalCredentials, nTSecurityDescriptor); auxiliaryClass
    // posixGroup (2.225: cn, description).
    ClassEntry {
        ldap_display_name: "group",
        cn: "Group",
        governs_id: "1.2.840.113556.1.5.8",
        schema_id_guid: "bf967a9c-0de6-11d0-a285-00aa003049e2",
        object_class_category: 1,
        sub_class_of: "top",
        rdn_att_id: "cn",
        default_object_category: "Group",
        system_only: false,
        source: "[MS-ADSC] 2.55",
        must: &["groupType", "cn", "sAMAccountName", "objectSid"],
        may: &["member", "supplementalCredentials"],
        poss_superiors: &["container", "organizationalUnit", "domainDNS"],
        nc_root: false,
        spec_attributes: &[
            "groupType",
            "member",
            "cn",
            "sAMAccountName",
            "objectSid",
            "supplementalCredentials",
            "nTSecurityDescriptor",
            "description",
        ],
    },
];

/// objectClassCategory of a structural class ("1: Structural class") — the
/// only category phase 1 instantiates. 88 classes (0) may be instantiated
/// per [MS-ADTS] 3.1.1.5.2.2 but are blocked in phase 1 (D104); abstract (2)
/// and auxiliary (3) classes never are. Spec: [MS-ADTS] v20261026
/// 3.1.1.2.4.8 (objectClassCategory encoding), 3.1.1.5.2.2; docs/46 §4.1.
pub const STRUCTURAL_CLASS: u32 = 1;
