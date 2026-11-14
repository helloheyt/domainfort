//! The SearchResultEntry of a matching candidate: which attributes, which
//! values, in which LDAP representation.
//!
//! # Which attributes (RFC 4511 §4.5.1.8; docs/49 §6.3)
//!
//! - "All user attributes" (an empty list or "*") = the attributes of
//!   CLASSATTS of the object's most specific class (ad-schema's
//!   `class_attributes`, [MS-ADTS] 3.1.1.4.2) that are not constructed in
//!   the sense of [MS-ADTS] 3.1.1.4.5 — memberOf (a back link) is returned
//!   only when named (Q-168 item 1, A-48).
//! - Named attributes are added, each once.
//! - Never returned, even when named, even if the ACL would allow it: the
//!   Secret attributes and nTSecurityDescriptor (R49-9; [MS-ADTS] 3.1.1.4.4;
//!   docs/49 §6.5) — the PDP is not asked (docs/11 P6); and objectCategory,
//!   which has no DN to return without a schema NC (Q-168 item 3 — it is
//!   still evaluated in filters).
//! - Each remaining attribute needs `DirRead(attr)` on the object (one PDP
//!   decision per returned attribute, docs/49 §6.1 item 6; a Sensitive
//!   attribute also needs its control right — pdp layer 5, [MS-ADTS]
//!   3.1.1.4.4); an attribute with no (visible) value is not returned.
//! - typesOnly: the descriptions with no values (RFC 4511 §4.5.1.6).
//! - The description is the lDAPDisplayName (RFC 4511 §4.5.2: "the server
//!   SHOULD use one of those names"); attributes come in ascending ATTRTYP
//!   order (deterministic).
//!
//! # DN values (docs/49 §6.5)
//!
//! member and memberOf values, and the objectName / distinguishedName of
//! the entry, are DNs: the directory's canonical DN (`dn_of`) written as an
//! RFC 4514 string (parse-ldap `Dn::from_directory_rdns(..).encode()`,
//! Q-195 item 8). A member / memberOf value names another object, so only
//! the targets the requester can see ([MS-ADTS] 5.1.3.3.6: `DirList` on the
//! target's parent) are returned — a subset, never more; each costs one
//! visibility decision (cached per container) within the search's DN-value
//! bound.
//!
//! Spec: RFC 4511 §4.5.1.6, §4.5.1.8, §4.5.2; RFC 4514 §2; [MS-ADTS]
//! v20261026 3.1.1.2.2.2, 3.1.1.4.2-3.1.1.4.5, 5.1.3.3.6; docs/46 §5.4;
//! docs/49 §6.3-§6.5; Q-168 items 1, 3.

use std::collections::BTreeMap;

use directory_pip::Visibility;
use dirstore::{AttrId, Object, ValueSyntax};
use dtyp::Guid;
use parse_ldap::dn::Dn as LdapDn;
use parse_ldap::{PartialAttribute, ResultCode, SearchResultEntry};
use pdp::Dn;

use super::attrs::{attr, Attr, Kind};
use super::filter::instance_type;
use super::limits::MAX_VALUES_PER_RETURNED_ATTRIBUTE;
use super::syntax::{render_boolean, render_dstime, render_integer};
use super::{Candidate, Search, Stop};
use crate::audit::AuditReason;

/// The RFC 4514 string of a canonical DN; `None` if it cannot be written
/// within the LDAPDN bound. Spec: RFC 4514 §2; Q-195 item 8; docs/49 §2.4.
pub(super) fn encode_dn(dn: &Dn) -> Option<String> {
    LdapDn::from_directory_rdns(dn.rdns())
        .ok()
        .map(|d| d.encode())
}

/// A stored value without its canonical form: cannot happen (dirstore
/// re-validates every record) — fail closed.
fn malformed() -> Stop {
    Stop::Fail(AuditReason::DirectoryUnavailable)
}

impl<'r> Search<'r> {
    /// The value of the object's RDN attribute ([MS-ADTS] 3.1.1.1.4: "An
    /// object's value of name equals the value of the object's RDN
    /// attribute"). Spec: docs/46 §5.4 (name).
    pub(super) fn rdn_value<'o>(&self, obj: &'o Object) -> Result<&'o [u8], Stop> {
        let class = self.class_of(obj)?;
        let rdn_attr = self
            .p1
            .schema()
            .class(class.id)
            .ok_or_else(malformed)?
            .rdn_attr;
        match obj.attribute(rdn_attr).map(|a| a.values.as_slice()) {
            Some([only]) => Ok(only.value.as_slice()),
            _ => Err(malformed()),
        }
    }

    /// The canonical DN of `target` if it is a live object of the NC that
    /// the requester can see (the visibility gate's verdict), else `None` —
    /// absent and hidden alike; within the DN-value bound.
    /// Spec: docs/49 §6.5; [MS-ADTS] 5.1.3.3.6; docs/52 R10.
    pub(super) fn visible_ref(&mut self, target: Guid) -> Result<Option<Dn>, Stop> {
        self.count_dn_value()?;
        match self.gate.visible(target) {
            Ok(Visibility::Visible { object, .. }) => Ok(Some(object.dn().clone())),
            Ok(Visibility::NotFound(_) | Visibility::Refused(_)) => Ok(None),
            Err(_) => Err(Stop::Fail(AuditReason::DirectoryUnavailable)),
        }
    }

    /// The RFC 4514 strings of the visible targets among `targets`.
    fn visible_dns(
        &mut self,
        targets: impl IntoIterator<Item = Guid>,
    ) -> Result<Vec<Vec<u8>>, Stop> {
        let mut out = Vec::new();
        for target in targets {
            if let Some(dn) = self.visible_ref(target)? {
                if let Some(text) = encode_dn(&dn) {
                    out.push(text.into_bytes());
                }
            }
        }
        Ok(out)
    }

    /// The entry of a matching candidate (module documentation).
    /// Spec: RFC 4511 §4.5.2.
    pub(super) fn entry(&mut self, cand: &mut Candidate<'r>) -> Result<SearchResultEntry, Stop> {
        let object_name = encode_dn(cand.dn()).ok_or(Stop::Fail(AuditReason::UnrepresentableDn))?;
        let class = self.class_of(cand.obj())?;
        let mut wanted: BTreeMap<AttrId, Attr> = BTreeMap::new();
        if self.selection.all_user {
            for id in &class.class_attributes {
                if let Some(info) = self.p1.attribute(*id) {
                    let a = attr(info, &self.known);
                    if !matches!(a.kind, Kind::MemberOf) {
                        wanted.insert(a.id, a);
                    }
                }
            }
        }
        for a in &self.selection.named {
            wanted.insert(a.id, *a);
        }
        let mut attributes = Vec::new();
        for a in wanted.into_values() {
            // Never returned. Spec: R49-9; docs/49 §6.5; Q-168 item 3.
            if matches!(a.kind, Kind::Never | Kind::ObjectCategory) {
                continue;
            }
            if !self.readable(cand, &a) {
                continue;
            }
            let vals = self.returned_values(cand, &a, &object_name)?;
            if vals.is_empty() {
                continue;
            }
            if vals.len() > MAX_VALUES_PER_RETURNED_ATTRIBUTE {
                return Err(Stop::Limit(
                    ResultCode::AdminLimitExceeded,
                    AuditReason::ValueBudgetExceeded,
                ));
            }
            attributes.push(PartialAttribute {
                r#type: a.name.to_owned(),
                vals: if self.request.types_only {
                    Vec::new()
                } else {
                    vals
                },
            });
        }
        Ok(SearchResultEntry {
            object_name,
            attributes,
        })
    }

    /// The LDAP values of a readable attribute (crate::search::syntax
    /// table). A value that has no LDAP form (a DsTime after year 9999) is
    /// not returned. Spec: [MS-ADTS] 3.1.1.2.2.2; docs/46 §5.4; docs/49
    /// §6.4.
    fn returned_values(
        &mut self,
        cand: &Candidate<'_>,
        a: &Attr,
        object_name: &str,
    ) -> Result<Vec<Vec<u8>>, Stop> {
        let stored: Vec<&[u8]> = cand
            .obj()
            .attribute(a.id)
            .map(|x| x.values.iter().map(|v| v.value.as_slice()).collect())
            .unwrap_or_default();
        Ok(match a.kind {
            // String(Unicode): UTF-8 as stored; String(Octet), GUID: the
            // octets; String(Sid): the binary SID ([MS-ADTS] 3.1.1.2.2.2.7).
            Kind::Stored(
                ValueSyntax::Utf8String
                | ValueSyntax::OctetString
                | ValueSyntax::Guid
                | ValueSyntax::Sid,
            ) => stored.iter().map(|v| v.to_vec()).collect(),
            // Integer: signed decimal. Spec: RFC 4517 §3.3.16; [MS-DRSR]
            // 5.16.3.2.
            Kind::Stored(ValueSyntax::Integer32) => stored
                .iter()
                .map(|v| {
                    <[u8; 4]>::try_from(*v)
                        .map(|b| render_integer(i64::from(i32::from_be_bytes(b))))
                        .map_err(|_| malformed())
                })
                .collect::<Result<_, _>>()?,
            // LargeInteger: signed decimal. Spec: RFC 4517 §3.3.16;
            // [MS-DRSR] 5.16.3.3.
            Kind::Stored(ValueSyntax::Integer) => stored
                .iter()
                .map(|v| {
                    <[u8; 8]>::try_from(*v)
                        .map(|b| render_integer(i64::from_be_bytes(b)))
                        .map_err(|_| malformed())
                })
                .collect::<Result<_, _>>()?,
            // Generalized Time. Spec: RFC 4517 §3.3.13; [MS-DRSR] 5.16.3.9.
            Kind::Stored(ValueSyntax::DsTime) => {
                let mut out = Vec::new();
                for v in stored {
                    let seconds = <[u8; 8]>::try_from(v)
                        .map(i64::from_be_bytes)
                        .map_err(|_| malformed())?;
                    if let Some(text) = render_dstime(seconds) {
                        out.push(text);
                    }
                }
                out
            }
            // Boolean. Spec: RFC 4517 §3.3.3; [MS-DRSR] 5.16.3.1.
            Kind::Stored(ValueSyntax::Boolean) => stored
                .iter()
                .map(|v| match v {
                    [0x00] => Ok(render_boolean(false)),
                    [0x01] => Ok(render_boolean(true)),
                    _ => Err(malformed()),
                })
                .collect::<Result<_, _>>()?,
            // Object(DS-DN): the visible targets' DNs. Spec: docs/49 §6.5.
            Kind::Stored(ValueSyntax::ObjectRef) => {
                let targets = stored
                    .iter()
                    .map(|v| Guid::decode(v).map_err(|_| malformed()))
                    .collect::<Result<Vec<_>, _>>()?;
                self.visible_dns(targets)?
            }
            // objectClass: the chain's lDAPDisplayNames, top first, the most
            // specific class last. Spec: [MS-ADTS] 3.1.1.2.4.3, 3.1.1.2.2.2
            // note ††† rule 3; docs/46 §5.4.
            Kind::ObjectClass => self
                .class_of(cand.obj())?
                .object_class
                .iter()
                .filter_map(|c| self.p1.class(*c))
                .map(|c| c.entry.ldap_display_name.as_bytes().to_vec())
                .collect(),
            // instanceType 4 / 5. Spec: docs/46 §5.4.
            Kind::InstanceType => vec![render_integer(instance_type(cand))],
            // objectGUID: the 16 octets of the record key ([MS-DTYP] 2.3.4.2
            // packet). Spec: docs/46 §5.4; [MS-ADTS] 3.1.1.1.3.
            Kind::ObjectGuid => vec![cand.obj().guid.to_packet().to_vec()],
            // name: the RDN attribute's value. Spec: [MS-ADTS] 3.1.1.1.4.
            Kind::Name => vec![self.rdn_value(cand.obj())?.to_vec()],
            // distinguishedName: the object's DN. Spec: [MS-ADTS] 3.1.1.1.4.
            Kind::DistinguishedName => vec![object_name.as_bytes().to_vec()],
            // memberOf: the back link, filtered to visible groups.
            // Spec: docs/46 R46-2; docs/49 §6.4, §6.5.
            Kind::MemberOf => {
                let groups = self
                    .view
                    .snapshot()
                    .back_links(cand.obj().guid, a.id)
                    .map_err(|_| Stop::Fail(AuditReason::DirectoryUnavailable))?;
                self.visible_dns(groups)?
            }
            // Never returned (filtered by the caller).
            Kind::Never | Kind::ObjectCategory | Kind::Stored(ValueSyntax::SecurityDescriptor) => {
                Vec::new()
            }
        })
    }
}
