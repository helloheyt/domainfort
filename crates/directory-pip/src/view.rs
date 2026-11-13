//! The per-request directory view: ONE dirstore snapshot, the phase-1
//! schema and the request's tier map, implementing both `kdc::AccountSource`
//! and `pdp::Pip` (docs/47 §8.1, R47-11), so the groups, tier and state the
//! KDC reads and the answers the PDP gets come from one consistent picture
//! (docs/11 §6 snapshot semantics, P9).
//!
//! [`DirectoryContext`] is built once (schema identifiers, the reverse
//! schemaIDGUID map, keyd's realm / enctypes / s2kparams); a
//! [`DirectoryView`] is taken from it for each request.
//!
//! Spec: docs/47 §1-§8 (R47-1..R47-11); docs/11 §6; kdc `accounts.rs`;
//! pdp `pip.rs`.

use crate::error::{Fault, ViewError};
use crate::groups;
use crate::names::{
    client_search_key, is_krbtgt_sid, service_search_key, DOMAIN_USER_RID_KRBTGT, KRBTGT,
};
use crate::record::{self, Ids};
use crate::salt::{account_salt, AccountKind};
use crate::state;
use crate::tier::{most_privileged, TierMap};
use ad_schema::Phase1Schema;
use dirstore::{ClassId, Object, Snapshot, Store};
use dtyp::{Guid, SecurityDescriptor, Sid};
use kdc::{
    AccountKind as KdcAccountKind, AccountSource, AccountSourceError, AccountState, ArmorPolicy,
    ClientAccount, ServiceAccount,
};
use keyd::{KeyHandle, KeyPurpose, KeydConfig, PrincipalId};
use krb_proto::{EtypeInfo2Entry, PrincipalName, Realm};
use pdp::{
    AttrClass, ControlRightId, Dn, ObjClass, ObjClassChain, Pip, PipError, PropertySet, Resource,
    Tier,
};
use std::collections::{BTreeMap, BTreeSet};

/// Most RDN components of a DN this crate resolves or produces (project
/// choice; bounds the walk up and down the tree — dirstore fixes no tree
/// depth). Spec: AGENTS.md §6 (bounded work on input); docs/47 §8.2.
pub const MAX_DN_DEPTH: usize = 64;

/// The separator of an RDN component, `att=value`, in the directory's own
/// canonical DN form (see [`DirectoryView::dn_of`]). Spec: [MS-ADTS]
/// 3.1.1.1.4 (RDN = "att=val"); docs/47 §8.2.
const RDN_SEPARATOR: char = '=';

/// The long-lived part: the phase-1 schema, the identifiers docs/47 reads,
/// the schemaIDGUID → AttrId map, and keyd's realm, enctypes and s2kparams
/// (one configuration shared with keyd, docs/47 §7.3 R47-10).
///
/// Spec: docs/47 §7.3, §8.1, §8.2.
pub struct DirectoryContext {
    pub(crate) schema: Phase1Schema,
    pub(crate) ids: Ids,
    /// schemaIDGUID → AttrId, built once from the schema (docs/47 §8.2
    /// `attr_class`: "reverse map built once from attributes()").
    attr_by_guid: BTreeMap<Guid, dirstore::AttrId>,
    realm: Realm,
    /// `KeydConfig.enctypes`, in keyd's order (R47-10).
    enctypes: Vec<i32>,
    /// `KeydConfig.s2k_params` (R47-10).
    s2kparams: Option<Vec<u8>>,
    /// Longest stored sAMAccountName / servicePrincipalName value: a longer
    /// name cannot match (checked before the index is asked).
    sam_max_len: usize,
    spn_max_len: usize,
}

impl DirectoryContext {
    /// Build the context from the phase-1 schema and keyd's configuration.
    /// Fails closed if keyd's configuration is invalid, if the realm is not
    /// an upper-case DNS name (the salt's "DNS of the realm, converted to
    /// uppercase" must be the Kerberos realm, docs/47 §3.3 item 3), or if the
    /// schema lacks what docs/47 reads.
    ///
    /// Spec: docs/47 §3.3 item 3, §7.3 (R47-10), §8.2; [MS-KILE] 3.1.1.2;
    /// RFC 4120 §6.1.
    pub fn new(schema: Phase1Schema, keyd: &KeydConfig) -> Result<DirectoryContext, ViewError> {
        keyd.validate().map_err(|_| ViewError::KeydConfig)?;
        let realm = keyd.realm.clone();
        if realm.as_bytes().is_empty() || realm.as_bytes().iter().any(u8::is_ascii_lowercase) {
            return Err(ViewError::RealmNotUppercase);
        }
        let ids = Ids::resolve(&schema)?;
        let mut attr_by_guid = BTreeMap::new();
        for a in schema.attributes() {
            if attr_by_guid.insert(a.schema_id_guid, a.id).is_some() {
                return Err(ViewError::Schema);
            }
        }
        let max_len = |id| {
            schema
                .schema()
                .attribute(id)
                .map(|d| d.max_value_len)
                .ok_or(ViewError::Schema)
        };
        let sam_max_len = max_len(ids.sam_account_name)?;
        let spn_max_len = max_len(ids.service_principal_name)?;
        Ok(DirectoryContext {
            ids,
            attr_by_guid,
            realm,
            enctypes: keyd.enctypes.iter().map(|e| e.number()).collect(),
            s2kparams: keyd.s2k_params.map(|p| p.to_vec()),
            sam_max_len,
            spn_max_len,
            schema,
        })
    }

    /// The realm (keyd's).
    #[must_use]
    pub fn realm(&self) -> &Realm {
        &self.realm
    }

    /// The phase-1 schema.
    #[must_use]
    pub fn schema(&self) -> &Phase1Schema {
        &self.schema
    }

    /// Take the view of one request: a snapshot of `store` and the tier map
    /// of the request's policy version. The store must have been opened
    /// with this context's schema (fail closed otherwise).
    /// Spec: docs/47 §8.1 (R47-11); docs/32 §6 (D39 snapshots).
    pub fn view<'a>(
        &'a self,
        store: &'a Store,
        tiers: &'a TierMap,
    ) -> Result<DirectoryView<'a>, ViewError> {
        if store.schema() != self.schema.schema() {
            return Err(ViewError::SchemaMismatch);
        }
        let snapshot = store.snapshot().map_err(|_| ViewError::Store)?;
        Ok(DirectoryView {
            ctx: self,
            snapshot,
            tiers,
        })
    }
}

/// One request's view of the directory (module docs). Implements
/// [`AccountSource`] and [`Pip`] over the same snapshot.
/// Spec: docs/47 §8.1 (R47-11).
pub struct DirectoryView<'a> {
    pub(crate) ctx: &'a DirectoryContext,
    pub(crate) snapshot: Snapshot<'a>,
    tiers: &'a TierMap,
}

/// A user or computer object, read and checked (docs/47 §1.3, §4.1).
struct Account<'o> {
    kind: AccountKind,
    sid: Sid,
    sam_account_name: &'o str,
    /// userAccountControl, checked by [`state::checked_uac`].
    uac: Option<u32>,
}

/// keyd's principal identifier of an object: its objectGUID, in the 16-octet
/// packet form that is also the dirstore key. Spec: docs/47 §2.3 (R47-3);
/// docs/10 §1 (`PrincipalId = Guid`); [MS-ADTS] 3.1.1.1.3.
fn principal_id(guid: Guid) -> PrincipalId {
    PrincipalId::from_bytes(guid.to_packet())
}

/// The KDC's account kind and armor policy of a user / computer object, from
/// its most specific class (objectClass — authoritative directory data, never
/// client-claimed, like the tier, docs/11 P3): a computer object is a
/// computer account that may bootstrap — make the one unarmored AS request
/// for its TGT that it needs before it can armor anything; every other
/// account must use FAST.
/// Spec: docs/48 §3.1 (armor ticket of a computer account only, D126), §7.2
/// ("derived by the AccountSource from authoritative data: objectClass
/// computer → BootstrapAllowed; everything else → Required"), §7.3;
/// docs/questions/Q-127 interim decision ((ב) = `kind` from objectClass;
/// P-10).
fn armor_facts(kind: AccountKind) -> (KdcAccountKind, ArmorPolicy) {
    match kind {
        AccountKind::Computer => (KdcAccountKind::Computer, ArmorPolicy::BootstrapAllowed),
        AccountKind::User => (KdcAccountKind::User, ArmorPolicy::Required),
    }
}

/// `true` if `s` is non-empty printable ASCII. Spec: P-6, Q-080.
fn printable_ascii(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

impl DirectoryView<'_> {
    /// The most specific class of a stored object. Spec: docs/46 §8.3 item
    /// 1; [MS-ADTS] 3.1.1.2.4.3.
    pub(crate) fn most_specific_class(&self, obj: &Object) -> Result<ClassId, Fault> {
        self.ctx
            .schema
            .schema()
            .most_specific_class(&obj.classes)
            .ok_or(Fault::Unavailable)
    }

    /// The salt rule of an object's class: user → User, computer →
    /// Computer, anything else → `None` (not an account). Spec: docs/47
    /// §1.3 step 5, §3.3.
    fn account_kind(&self, obj: &Object) -> Result<Option<AccountKind>, Fault> {
        let class = self.most_specific_class(obj)?;
        Ok(if class == self.ctx.ids.user {
            Some(AccountKind::User)
        } else if class == self.ctx.ids.computer {
            Some(AccountKind::Computer)
        } else {
            None
        })
    }

    /// Read a user / computer object: sAMAccountName and objectSid (musts,
    /// docs/46 §4.4) and the checked userAccountControl. `Ok(None)` if the
    /// object is not an account; `Err` if it is inconsistent.
    /// Spec: docs/47 §1.3 steps 5-7, §4.1.
    fn account<'o>(&self, obj: &'o Object) -> Result<Option<Account<'o>>, Fault> {
        let Some(kind) = self.account_kind(obj)? else {
            return Ok(None);
        };
        let ids = self.ctx.ids;
        let sam_account_name =
            record::text(obj, ids.sam_account_name)?.ok_or(Fault::Unavailable)?;
        let sid = record::sid(obj, ids.object_sid)?.ok_or(Fault::Unavailable)?;
        let uac = state::checked_uac(
            kind,
            record::flags(obj, ids.user_account_control)?,
            sam_account_name,
        )?;
        Ok(Some(Account {
            kind,
            sid,
            sam_account_name,
            uac,
        }))
    }

    /// The account state of a checked account. Spec: docs/47 §4 (R47-5,
    /// R47-6, R47-7).
    fn state_of(&self, obj: &Object, account: &Account<'_>) -> Result<AccountState, Fault> {
        let ids = self.ctx.ids;
        state::account_state(
            account.kind,
            account.uac,
            record::int64(obj, ids.account_expires)?,
            record::int64(obj, ids.pwd_last_set)?,
            record::int64(obj, ids.when_created)?,
        )
    }

    /// `Pip::tier_of`, and `ClientAccount.tier` (the same function, so the
    /// PDP's P3 check holds by construction): the most privileged map tier
    /// of `{p} ∪ g`, and Tier0 if `p` is a DC's computer account (ST); no
    /// value ⇒ `Untiered`. A `p` that is not a directory object has no ST.
    /// Spec: docs/47 §6.3 (R47-9), §8.2; [MS-ADTS] 2.2.16 (ST); docs/11 §1.
    fn subject_tier(&self, p: &Sid, g: &BTreeSet<Sid>) -> Result<Tier, Fault> {
        let mut tier = self
            .tiers
            .principal_tier(core::iter::once(p).chain(g.iter()));
        if let Some(guid) = self
            .snapshot
            .lookup_unique(self.ctx.ids.object_sid, &p.encode())?
        {
            let obj = self.snapshot.get_object(guid)?.ok_or(Fault::Unavailable)?;
            if let Some(account) = self.account(&obj)? {
                if state::is_dc_account(account.uac) {
                    tier = most_privileged(tier, Some(Tier::Tier0));
                }
            }
        }
        Ok(tier.unwrap_or(Tier::Untiered))
    }

    /// The RDN attribute's lDAPDisplayName and stored value of an object.
    /// Spec: docs/46 §8.3 item 3 (the RDN attribute of the most specific
    /// class); [MS-ADTS] 3.1.1.1.4.
    fn rdn_of<'o>(&self, obj: &'o Object) -> Result<(&'static str, &'o [u8]), Fault> {
        let class = self.most_specific_class(obj)?;
        let rdn_attr = self
            .ctx
            .schema
            .schema()
            .class(class)
            .ok_or(Fault::Unavailable)?
            .rdn_attr;
        let name = self
            .ctx
            .schema
            .attribute(rdn_attr)
            .ok_or(Fault::Unavailable)?
            .entry
            .ldap_display_name;
        let value = record::single(obj, rdn_attr)?.ok_or(Fault::Unavailable)?;
        Ok((name, value))
    }

    /// Resolve a DN in the directory's own canonical form (see
    /// [`DirectoryView::dn_of`]): from the root down, `lookup_child` per
    /// component, then the component must name the RDN attribute of the
    /// found object's most specific class and equal its stored value octet
    /// for octet (one spelling per object — the PDP compares DNs exactly).
    /// Anything else is `NotFound`.
    ///
    /// The textual syntax of a DN component belongs to the LDAP layer
    /// (RFC 4514, not opened — docs/47 §8.2 ⚠); until it exists this view
    /// accepts only DNs the directory itself produced.
    ///
    /// Spec: docs/47 §8.2 (DN resolution); docs/46 §8.3; pdp `Dn`.
    fn resolve(&self, dn: &Dn) -> Result<Object, Fault> {
        let rdns = dn.rdns();
        if rdns.is_empty() || rdns.len() > MAX_DN_DEPTH {
            return Err(Fault::NotFound);
        }
        let mut parent: Option<Guid> = None;
        let mut found = None;
        for component in rdns.iter().rev() {
            let (att, value) = component.split_once(RDN_SEPARATOR).ok_or(Fault::NotFound)?;
            if !printable_ascii(value) {
                return Err(Fault::NotFound);
            }
            let guid = self
                .snapshot
                .lookup_child(parent, value.as_bytes())?
                .ok_or(Fault::NotFound)?;
            let obj = self.snapshot.get_object(guid)?.ok_or(Fault::NotFound)?;
            let (name, stored) = self.rdn_of(&obj)?;
            if name != att || stored != value.as_bytes() {
                return Err(Fault::NotFound);
            }
            parent = Some(guid);
            found = Some(obj);
        }
        found.ok_or(Fault::NotFound)
    }

    /// The DN of a live object in the directory's own canonical form: leaf
    /// first, each component `<lDAPDisplayName of the RDN attribute>=<stored
    /// RDN value>`, up to the naming-context root (which has no parent).
    /// `Ok(None)` if no live object has this GUID. These are the DNs this
    /// view resolves, and the form of the tier map's subtree entries.
    /// Spec: docs/47 §8.2; [MS-ADTS] 3.1.1.1.4 (RDN "att=val"); pdp `Dn`
    /// (leaf first, naming-context root last).
    pub fn dn_of(&self, guid: Guid) -> Result<Option<Dn>, PipError> {
        let Some(mut obj) = self.snapshot.get_object(guid).map_err(Fault::from)? else {
            return Ok(None);
        };
        let mut rdns = Vec::new();
        loop {
            if rdns.len() >= MAX_DN_DEPTH {
                return Err(PipError::Unavailable);
            }
            let (name, value) = self.rdn_of(&obj)?;
            let value = core::str::from_utf8(value).map_err(|_| PipError::Unavailable)?;
            let mut component = String::with_capacity(name.len() + 1 + value.len());
            component.push_str(name);
            component.push(RDN_SEPARATOR);
            component.push_str(value);
            rdns.push(component);
            match obj.parent {
                None => break,
                Some(parent) => {
                    obj = self
                        .snapshot
                        .get_object(parent)
                        .map_err(Fault::from)?
                        .ok_or(PipError::Unavailable)?;
                }
            }
        }
        Ok(Some(Dn::new(rdns)))
    }

    /// keyd's handle of the krbtgt key set (`KdcConfig.krbtgt`, docs/47
    /// §1.4 R47-2): the user object whose objectSid is `domain_sid ‖ 502`
    /// and whose sAMAccountName is "krbtgt"; purpose `Krbtgt`.
    /// Spec: docs/47 §1.4 (R47-2); [MS-SAMR] 2.2.1.14, 3.1.1.6 item 14
    /// ("sAMAccountName MUST be the value "krbtgt" ... if the RID of the
    /// objectSid attribute is DOMAIN_USER_RID_KRBTGT"); [MS-DTYP] 2.4.2.4;
    /// [MS-KILE] 3.3.3.
    pub fn krbtgt_handle(&self, domain_sid: &Sid) -> Result<KeyHandle, AccountSourceError> {
        let mut sub = domain_sid.sub_authority().to_vec();
        sub.push(DOMAIN_USER_RID_KRBTGT);
        let sid =
            Sid::new(domain_sid.identifier_authority(), &sub).map_err(|_| AccountSourceError)?;
        let ids = self.ctx.ids;
        let guid = self
            .snapshot
            .lookup_unique(ids.object_sid, &sid.encode())
            .map_err(|_| AccountSourceError)?
            .ok_or(AccountSourceError)?;
        let obj = self
            .snapshot
            .get_object(guid)
            .map_err(|_| AccountSourceError)?
            .ok_or(AccountSourceError)?;
        if self.most_specific_class(&obj)? != ids.user
            || record::text(&obj, ids.sam_account_name)? != Some(KRBTGT)
        {
            return Err(AccountSourceError);
        }
        Ok(KeyHandle::new(principal_id(guid), KeyPurpose::Krbtgt))
    }

    /// [`AccountSource::client`] with internal faults (docs/47 §1.3 AS).
    fn client_account(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ClientAccount>, Fault> {
        let ids = self.ctx.ids;
        // 1. The configured realm, octet for octet.
        if realm.as_bytes() != self.ctx.realm.as_bytes() {
            return Ok(None);
        }
        // 2. One printable component, not "krbtgt".
        let Some(key) = client_search_key(name) else {
            return Ok(None);
        };
        if key.len() > self.ctx.sam_max_len {
            return Ok(None);
        }
        // 3. The unique index (ASCII, A–Z folded — Q-080).
        let Some(guid) = self
            .snapshot
            .lookup_unique(ids.sam_account_name, key.as_bytes())?
        else {
            return Ok(None);
        };
        let Some(obj) = self.snapshot.get_object(guid)? else {
            return Ok(None);
        };
        // 4. The stored value equals the component octet for octet (A-27).
        let stored = record::text(&obj, ids.sam_account_name)?.ok_or(Fault::Unavailable)?;
        if stored.as_bytes() != key.as_bytes() {
            return Ok(None);
        }
        // 5-7. user / computer; not krbtgt; userAccountControl consistent.
        let Some(account) = self.account(&obj)? else {
            return Ok(None);
        };
        if is_krbtgt_sid(&account.sid) {
            return Ok(None);
        }
        let groups = groups::expand(self, &obj)?;
        let tier = self.subject_tier(&account.sid, &groups)?;
        let state = self.state_of(&obj, &account)?;
        let salt = account_salt(&self.ctx.realm, account.kind, account.sam_account_name)
            .map_err(|_| Fault::Unavailable)?;
        let etype_info = self
            .ctx
            .enctypes
            .iter()
            .map(|etype| EtypeInfo2Entry {
                etype: *etype,
                salt: Some(salt.clone()),
                s2kparams: self.ctx.s2kparams.clone(),
            })
            .collect();
        // 8. The key set (objectGUID, PrincipalLongterm).
        // 9. The account kind and the armor policy (docs/48 §3.1, §7.2).
        let (kind, armor_policy) = armor_facts(account.kind);
        Ok(Some(ClientAccount {
            key: KeyHandle::new(principal_id(guid), KeyPurpose::PrincipalLongterm),
            sid: account.sid,
            groups,
            tier,
            state,
            etype_info,
            kind,
            armor_policy,
        }))
    }

    /// [`AccountSource::service`] with internal faults (docs/47 §1.3 TGS).
    fn service_account(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ServiceAccount>, Fault> {
        let ids = self.ctx.ids;
        // 1. The configured realm.
        if realm.as_bytes() != self.ctx.realm.as_bytes() {
            return Ok(None);
        }
        // 2. Two or more components, joined with "/".
        let Some(spn) = service_search_key(name) else {
            return Ok(None);
        };
        if spn.len() > self.ctx.spn_max_len {
            return Ok(None);
        }
        // 3. The unique index, then the stored value octet for octet.
        let Some(guid) = self
            .snapshot
            .lookup_unique(ids.service_principal_name, spn.as_bytes())?
        else {
            return Ok(None);
        };
        let Some(obj) = self.snapshot.get_object(guid)? else {
            return Ok(None);
        };
        let stored = record::text(&obj, ids.service_principal_name)?.ok_or(Fault::Unavailable)?;
        if stored.as_bytes() != spn.as_bytes() {
            return Ok(None);
        }
        // 4. computer only (R47-13); not krbtgt.
        if self.most_specific_class(&obj)? != ids.computer {
            return Ok(None);
        }
        let account = self.account(&obj)?.ok_or(Fault::Unavailable)?;
        if is_krbtgt_sid(&account.sid) {
            return Ok(None);
        }
        let state = self.state_of(&obj, &account)?;
        // 5. The key set (objectGUID, Service).
        Ok(Some(ServiceAccount {
            key: KeyHandle::new(principal_id(guid), KeyPurpose::Service),
            state,
            enctypes: self.ctx.enctypes.clone(),
        }))
    }

    /// `object_tier` of a directory object (docs/47 §6.3; A-36): the most
    /// privileged of every classification that applies — the subtree
    /// entries containing it; for an account or group, the map tier of its
    /// objectSid and expanded groups; Tier0 for the naming-context root, the
    /// krbtgt account and a DC account (ST). No classification ⇒ Tier0 (an
    /// unclassified resource is Tier0 for writes, A-36).
    fn dir_object_tier(&self, dn: &Dn) -> Result<Tier, Fault> {
        let ids = self.ctx.ids;
        let obj = self.resolve(dn)?;
        let class = self.most_specific_class(&obj)?;
        let mut tier = self.tiers.subtree_tier(dn);
        if obj.parent.is_none() || class == ids.domain_dns {
            tier = most_privileged(tier, Some(Tier::Tier0));
        }
        let sid = if let Some(account) = self.account(&obj)? {
            if is_krbtgt_sid(&account.sid) || state::is_dc_account(account.uac) {
                tier = most_privileged(tier, Some(Tier::Tier0));
            }
            Some(account.sid)
        } else if class == ids.group {
            Some(record::sid(&obj, ids.object_sid)?.ok_or(Fault::Unavailable)?)
        } else {
            None
        };
        if let Some(sid) = sid {
            let groups = groups::expand(self, &obj)?;
            let mapped = self
                .tiers
                .principal_tier(core::iter::once(&sid).chain(groups.iter()));
            tier = most_privileged(tier, mapped);
        }
        Ok(tier.unwrap_or(Tier::Tier0))
    }

    /// The AttrId of a pdp attribute identifier (its schemaIDGUID).
    /// Spec: docs/47 §8.2 (`attr_class`, `property_set`).
    fn attr_id(&self, a: &pdp::AttrId) -> Result<dirstore::AttrId, Fault> {
        self.ctx
            .attr_by_guid
            .get(&a.0)
            .copied()
            .ok_or(Fault::NotFound)
    }
}

impl AccountSource for DirectoryView<'_> {
    /// Spec: docs/47 §1.3 AS (R47-1), §2 (R47-3), §3 (R47-4), §4 (R47-5,
    /// R47-7), §5 (R47-8), §6 (R47-9), §7 (R47-10).
    fn client(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ClientAccount>, AccountSourceError> {
        self.client_account(realm, name)
            .map_err(AccountSourceError::from)
    }

    /// Spec: docs/47 §1.3 TGS (R47-1), §2 (R47-3), §4 (R47-5), §7 (R47-10),
    /// R47-13.
    fn service(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ServiceAccount>, AccountSourceError> {
        self.service_account(realm, name)
            .map_err(AccountSourceError::from)
    }
}

impl Pip for DirectoryView<'_> {
    /// `lookup_unique(objectSid, p)` → the closure of docs/47 §5.3.
    /// Spec: docs/47 §8.2, §5.3 (R47-8).
    fn expand_groups(&self, p: &Sid) -> Result<BTreeSet<Sid>, PipError> {
        let guid = self
            .snapshot
            .lookup_unique(self.ctx.ids.object_sid, &p.encode())
            .map_err(Fault::from)?
            .ok_or(PipError::NotFound)?;
        let obj = self
            .snapshot
            .get_object(guid)
            .map_err(Fault::from)?
            .ok_or(PipError::NotFound)?;
        Ok(groups::expand(self, &obj)?)
    }

    /// Spec: docs/47 §8.2, §6.3 (R47-9).
    fn tier_of(&self, p: &Sid, g: &BTreeSet<Sid>) -> Result<Tier, PipError> {
        Ok(self.subject_tier(p, g)?)
    }

    /// `object_tier` is asked only for writes (pdp `decide`, layer 4), so
    /// every resource kind the map cannot classify is Tier0: a policy scope
    /// (docs/06 §9), and RPC / file / DNS / Kerberos resources until the map
    /// has rows for them (A-36: an unclassified resource is Tier0 for
    /// writes). The rootDSE is never written (pdp admits only `DirRead` on
    /// it; [MS-ADTS] 3.1.1.3.2: its attributes "are read-only"), so it is
    /// never asked; if it were, Tier0 (A-36).
    /// Spec: docs/47 §6.3, §8.2; docs/06 §9; docs/49 §5.2 (R49-10); A-36.
    fn object_tier(&self, r: &Resource) -> Result<Tier, PipError> {
        match r {
            Resource::DirObject { dn, .. } => Ok(self.dir_object_tier(dn)?),
            Resource::Policy { .. }
            | Resource::RpcMethod { .. }
            | Resource::File { .. }
            | Resource::Dns { .. }
            | Resource::Kerberos { .. }
            | Resource::RootDse => Ok(Tier::Tier0),
        }
    }

    /// The stored nTSecurityDescriptor; absent ⇒ `NotFound` (Deny, D40;
    /// A-13). Spec: docs/47 §8.2; [MS-ADTS] 5.1.3.1.
    fn security_descriptor(&self, dn: &Dn) -> Result<SecurityDescriptor, PipError> {
        let obj = self.resolve(dn)?;
        let bytes =
            record::single(&obj, self.ctx.ids.nt_security_descriptor)?.ok_or(PipError::NotFound)?;
        SecurityDescriptor::decode(bytes).map_err(|_| PipError::Unavailable)
    }

    /// schemaIDGUID → AttrId → the attribute's class; Sensitive names the
    /// attribute's own schemaIDGUID as its control access right; an unknown
    /// GUID is `NotFound`. Spec: docs/47 §8.2; docs/46 §6; Q-052 item 2;
    /// [MS-ADTS] 3.1.1.4.4.
    fn attr_class(&self, a: &pdp::AttrId) -> Result<AttrClass, PipError> {
        let id = self.attr_id(a)?;
        match self
            .ctx
            .schema
            .attr_class(id)
            .map_err(|_| PipError::NotFound)?
        {
            dirstore::AttrClass::Normal => Ok(AttrClass::Normal),
            dirstore::AttrClass::Secret => Ok(AttrClass::Secret),
            dirstore::AttrClass::Sensitive => Ok(AttrClass::Sensitive {
                control_access_right: ControlRightId(a.0),
            }),
        }
    }

    /// The object's classes → `class_chain` → schemaIDGUIDs, most specific
    /// first. Spec: docs/47 §8.2; A-28; [MS-ADTS] 3.1.1.2.4.3.
    fn object_classes(&self, dn: &Dn) -> Result<ObjClassChain, PipError> {
        let obj = self.resolve(dn)?;
        let chain = self
            .ctx
            .schema
            .class_chain(&obj.classes)
            .map_err(|_| PipError::Unavailable)?;
        Ok(ObjClassChain {
            most_specific: ObjClass(chain.most_specific.schema_id_guid),
            superclasses: chain
                .superclasses
                .iter()
                .map(|c| ObjClass(c.schema_id_guid))
                .collect(),
        })
    }

    /// The objectSid, or `None`. Spec: docs/47 §8.2; [MS-ADTS] 5.1.3.3
    /// (PRINCIPAL_SELF).
    fn object_sid(&self, dn: &Dn) -> Result<Option<Sid>, PipError> {
        let obj = self.resolve(dn)?;
        Ok(record::sid(&obj, self.ctx.ids.object_sid)?)
    }

    /// `Phase1Schema::property_set` (with A-28's `is_attribute_guid`); an
    /// unknown GUID is `NotFound`. Spec: docs/47 §8.2; A-28; [MS-ADTS]
    /// 3.1.1.2.3.3.
    fn property_set(&self, a: &pdp::AttrId) -> Result<Option<PropertySet>, PipError> {
        let id = self.attr_id(a)?;
        let set = self
            .ctx
            .schema
            .property_set(id)
            .map_err(|_| PipError::NotFound)?;
        Ok(set.map(|s| PropertySet {
            guid: s.guid,
            is_attribute_guid: s.is_attribute_guid,
        }))
    }
}
