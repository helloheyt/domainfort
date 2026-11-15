//! The request / decision model.
//!
//! Spec: docs/11 §1 (the request: `AccessRequest`, `Subject`, `AuthContext`,
//! `Tier`, `Resource`, `Action`, `Context`) and §1b (the answer: `Decision`,
//! `Effect`, `Obligation`, reason). Conceptual model: docs/06 §2-§4.
//!
//! Provenance invariant P3 (docs/11 §1 note, §10): no `Subject` field is
//! claimed by the client. `principal` / `groups` / `claims` come from the PAC
//! that keyd signed and the KDC / PEP verified; `tier` is computed by the PIP
//! and is re-checked against the PIP inside [`crate::decide`].
//!
//! Deliberately absent (docs/11 §1 note; docs/06 §3; docs/05 §4): there is no
//! `Action` that reads secret material (no `SecretRead`). Such a request cannot
//! even be expressed.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use dtyp::{Guid, Sid};

/// A principal identifier: a SID ([MS-DTYP] 2.4.2). docs/11 §1 allows
/// "SID/GUID"; this crate uses the SID, which is what the access check of
/// [MS-DTYP] 2.5.3.2 compares (`Token.Sids[]`, 2.5.2).
pub type PrincipalId = Sid;

/// "A GUID, also known as a UUID" — Spec: [MS-DTYP] 2.3.4. Used for RPC
/// interface identifiers (docs/11 §1 `RpcMethod { iface: Uuid, .. }`).
pub type Uuid = Guid;

// ---------------------------------------------------------------------------
// The request — docs/11 §1.
// ---------------------------------------------------------------------------

/// The canonical request every PEP builds from the wire and the authenticated
/// identity only. Spec: docs/11 §1, §2; docs/06 §2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    /// Who asks. Spec: docs/11 §1.
    pub subject: Subject,
    /// On what. Spec: docs/11 §1.
    pub resource: Resource,
    /// To do what. Spec: docs/11 §1.
    pub action: Action,
    /// Under which observed conditions. Spec: docs/11 §1.
    pub context: Context,
}

/// The authenticated requester. Spec: docs/11 §1 (P3: no field is
/// client-claimed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// The account SID; always part of the token (Spec: [MS-DTYP] 2.5.2,
    /// "The Sids[] array always contains at least the SID of the account").
    pub principal: PrincipalId,
    /// Expanded (nested) group SIDs from the verified PAC — not reloaded.
    /// Spec: docs/11 §1.
    pub groups: BTreeSet<PrincipalId>,
    /// Claims from the verified PAC. Spec: docs/11 §1.
    pub claims: BTreeMap<ClaimId, ClaimValue>,
    /// How the identity was established. Spec: docs/11 §1.
    pub auth: AuthContext,
    /// Administrative tier, derived by the PIP from membership — not claimed.
    /// Spec: docs/11 §1; docs/06 §10. Re-checked against `Pip::tier_of`.
    pub tier: Tier,
}

/// A claim identifier. Spec: docs/11 §1 (`Map<ClaimId, ClaimValue>`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimId(pub String);

/// A claim value (project model; matched exactly by rules). Spec: docs/11 §1.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimValue {
    /// A signed integer value.
    Integer(i64),
    /// A text value.
    Text(String),
    /// A boolean value.
    Boolean(bool),
}

/// Authentication context. Spec: docs/11 §1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthContext {
    /// Strength of the authentication. Spec: docs/11 §1.
    pub strength: AuthStrength,
    /// FAST armoring was used. Set by the PEP only after keyd verified the
    /// armor (docs/48 §4.2, R48-10; P3); rules match it through
    /// `Match.auth` (docs/48 §7.2). Spec: docs/11 §1.
    pub armored: bool,
    /// Age of the ticket, as supplied by the PEP (no clock is read here).
    /// Spec: docs/11 §1.
    pub ticket_age: Duration,
    /// The identity was established from a ticket that keyd / the KDC
    /// verified. Spec: docs/11 §1.
    pub ticket_verified: bool,
}

/// Authentication strength. Spec: docs/11 §1 (`Unauth | Kerberos |
/// KerberosFast | Pkinit`); docs/06 §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthStrength {
    /// Unauthenticated.
    Unauth,
    /// Kerberos.
    Kerberos,
    /// Kerberos with FAST.
    KerberosFast,
    /// PKINIT.
    Pkinit,
}

/// Administrative tier. Spec: docs/11 §1; docs/06 §10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Tier 0: control of the directory, the KDC, keyd and the policy.
    Tier0,
    /// Tier 1: servers.
    Tier1,
    /// Tier 2: endpoints.
    Tier2,
    /// Not assigned to a tier.
    Untiered,
}

/// A distinguished name, as an already-canonicalised sequence of RDN
/// components in LDAP string order (leaf first, naming-context root last).
///
/// The PDP does not parse or canonicalise DNs: the directory supplies them in
/// canonical form and the PDP compares components exactly (fail closed — two
/// spellings of one DN simply do not match). Spec: docs/11 §1, §3
/// (`ResourceMatch`: "subtree of DN").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dn {
    rdns: Vec<String>,
}

impl Dn {
    /// Build a DN from canonical RDN components, leaf first.
    #[must_use]
    pub fn new(rdns: Vec<String>) -> Dn {
        Dn { rdns }
    }

    /// The RDN components, leaf first.
    #[must_use]
    pub fn rdns(&self) -> &[String] {
        &self.rdns
    }

    /// `true` if this DN equals `base` or lies in the subtree below it, i.e.
    /// `base`'s components are a suffix of this DN's components.
    ///
    /// An empty `base` is a suffix of every DN, so it contains everything.
    /// No policy rule can carry one: a rule's subtree is a
    /// [`crate::SubtreeBase`], which refuses the empty DN (Q-164 item 2,
    /// A-48). Spec: docs/11 §3 (`ResourceMatch` "subtree of DN").
    #[must_use]
    pub fn is_within(&self, base: &Dn) -> bool {
        self.rdns.ends_with(&base.rdns)
    }
}

/// An attribute, identified by its schemaIDGUID — the GUID that labels the
/// attribute node of the object type tree and that object ACEs carry in
/// ObjectType. Spec: [MS-ADTS] 5.1.3.3.3 ("set Guid(ai) to ai!schemaIDGUID");
/// [MS-DTYP] 2.4.4.3 (ObjectType identifies "a property set or property").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttrId(pub Guid);

impl AttrId {
    /// The nTSecurityDescriptor attribute: its schemaIDGUID.
    ///
    /// Spec: [MS-ADA3] v20180912 2.37 ("ldapDisplayName:
    /// nTSecurityDescriptor"; "schemaIdGuid:
    /// bf9679e3-0de6-11d0-a285-00aa003049e2"). The printed groups map to the
    /// members as the project decided for every schema GUID (A-31, Q-100:
    /// group 1 = Data1, group 2 = Data2, group 3 = Data3, groups 4-5 = the
    /// eight Data4 bytes in array order; [MS-DTYP] 2.3.4.1, 2.3.4.2).
    ///
    /// Reading it needs the rights of [MS-ADTS] 3.1.1.4.4, not
    /// RIGHT_DS_READ_PROPERTY (see `desired_right` in decide.rs; Q-164, A-48).
    /// The PDP recognises it by this identifier itself, so the stricter rule
    /// holds whatever class the PIP reports for the attribute.
    pub const NT_SECURITY_DESCRIPTOR: AttrId = AttrId(Guid {
        data1: 0xbf96_79e3,
        data2: 0x0de6,
        data3: 0x11d0,
        data4: [0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2],
    });
}

/// An object class, identified by its schemaIDGUID. Spec: [MS-ADTS] 5.1.3.2
/// (CC: "The ObjectType member of an ACE can contain a GUID that identifies
/// the objectClass of child object"), 5.1.3.3.3 ("Guid(c) to c!schemaIDGUID").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjClass(pub Guid);

/// Every class a directory object is an instance of: the schemaIDGUIDs of
/// its objectClass values.
///
/// Spec: [MS-ADTS] 3.1.1.2.4.3 (objectClass: "The first element is always
/// class top. The last element is the name of the structural class ...
/// (referred to as the most specific class). The rest of the classes in the
/// superclass chain are listed in between"); 5.1.3.3.3 ("Let O be an object
/// of class c"; "Add c to V as the root node of the tree"); A-28 (Q-081):
/// `c` is the most specific class, an allow object ACE matches the root only
/// for it, and a deny object ACE naming any class of the chain applies at
/// the root.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjClassChain {
    /// The most specific class (the last objectClass value): `c`, the root of
    /// the object type tree.
    pub most_specific: ObjClass,
    /// The other classes of the superclass chain (`top` up to the direct
    /// superclass of `most_specific`), in any order. Auxiliary classes are
    /// not listed (they are not objectClass values, [MS-ADTS] 3.1.1.2.4.6).
    pub superclasses: Vec<ObjClass>,
}

/// The property set an attribute is a member of.
///
/// Spec: [MS-ADTS] 3.1.1.2.3.3 ("the property set is identified by the
/// property set GUID, which is the attributeSecurityGUID value"); 5.1.3.3.3
/// ("Guid(pi) = ai.attributeSecurityGUID"); A-28 (Q-081) item 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PropertySet {
    /// The property set GUID (the attribute's attributeSecurityGUID).
    pub guid: Guid,
    /// `true` if `guid` is also the schemaIDGUID of an attribute — of any
    /// attribute in the schema, not only of the classes the object can hold.
    /// The GUID then labels two nodes of the object type tree (in the pinned
    /// schema: the "DNS Host Name Attributes" set, [MS-ADTS] 3.1.1.2.3.3, and
    /// the dNSHostName attribute, [MS-ADA1] 2.185 — recorded in Q-081), and
    /// A-28 lets an allow object ACE with that ObjectType apply only at the
    /// attribute node, never at this property set node. When unsure, `true`:
    /// it can only remove grants.
    pub is_attribute_guid: bool,
}

/// A control access right, identified by its rightsGuid. Spec: [MS-ADTS]
/// 5.1.3.2.1 ("each control access right is identified by a GUID";
/// "rightsGuid: The GUID that is used to identify the control access right in
/// an ACE").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlRightId(pub Guid);

/// A file share name. Spec: docs/11 §1 (`File { share, path }`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShareId(pub String);

/// A path inside a share, as canonical components. Spec: docs/11 §1.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilePath(pub Vec<String>);

/// A DNS zone. Spec: docs/11 §1 (`Dns { zone, record }`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZoneId(pub String);

/// A DNS record key inside a zone. Spec: docs/11 §1.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordKey(pub String);

/// A service principal name, compared exactly. Spec: docs/11 §1 ("target
/// SPN").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Spn(pub String);

/// What a Kerberos request is about. Spec: docs/11 §1 (`Kerberos { kind:
/// KerbResKind }` — "target SPN / operation kind").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KerbResKind {
    /// A ticket-granting ticket.
    Tgt,
    /// A service ticket for the named SPN.
    Service(Spn),
    /// A ticket for the change-password service (`kadmin/changepw`, RFC
    /// 3244 §2) — an operation kind of its own, not a `Service` SPN: the
    /// KDC decides that a request names this service with the one name
    /// rule keyd binds that service's key set with (crates/kdc `names.rs`,
    /// task K5), and the PDP never compares the name again — so a rule
    /// cannot match the service through a second, string-compared path
    /// (A-139: one name space, one canonicalisation function), and a
    /// `Service(Spn("kadmin/changepw"))` rule never applies to it. The KDC
    /// asks about it only in the armored AS (docs/53 §5.2).
    /// Spec: docs/11 §1 ("operation kind"); docs/53 R53-6, §5.2; RFC 3244
    /// §2; A-117, A-139.
    ChangePassword,
}

/// A policy scope. Spec: docs/11 §1 (`Policy { scope }`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyScope(pub String);

/// The resource of a request. Spec: docs/11 §1; docs/06 §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resource {
    /// A directory object; `attr` is `None` for a whole-object operation.
    DirObject {
        /// The object.
        dn: Dn,
        /// The attribute, if the operation is on one attribute.
        attr: Option<AttrId>,
    },
    /// An RPC method; the interface UUID and the opnum.
    RpcMethod {
        /// Interface UUID.
        iface: Uuid,
        /// Operation number.
        opnum: u16,
    },
    /// A file in a share.
    File {
        /// The share.
        share: ShareId,
        /// The path inside the share.
        path: FilePath,
    },
    /// A DNS zone or record.
    Dns {
        /// The zone.
        zone: ZoneId,
        /// The record, if any.
        record: Option<RecordKey>,
    },
    /// A Kerberos issuance target.
    Kerberos {
        /// What is requested.
        kind: KerbResKind,
    },
    /// A policy scope.
    Policy {
        /// The scope.
        scope: PolicyScope,
    },
    /// The rootDSE of the LDAP server.
    ///
    /// "The rootDSE (empty DN) is a mechanism for clients of an LDAP server
    /// to interact with the server itself, rather than with particular
    /// objects contained by the server" — it is not a directory object, has
    /// no nTSecurityDescriptor, and so has no layer 5 (no ACL, no attribute
    /// class). Its attributes "are not described by the schema" and "are
    /// read-only", so the resource names no attribute (an [`AttrId`] is a
    /// schemaIDGUID) and the only well-formed action on it is
    /// [`Action::DirRead`]; which rootDSE attributes are returned is the
    /// PEP's choice (docs/49 §5.2). An unauthenticated read is admitted only
    /// through an anonymous-allowlist entry naming it and the request's
    /// source network (docs/15 §6). Spec: [MS-ADTS] v20261026 3.1.1.3,
    /// 3.1.1.3.2; docs/49 §5.2 (R49-10); Q-164 item 1 (A-48).
    RootDse,
}

/// The abstract action taxonomy. Spec: docs/11 §1; docs/06 §3 (D14).
///
/// Deliberately absent: any action that reads secret material (docs/11 §1
/// note, docs/06 §3, docs/05 §4) — there is no `SecretRead`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// Read an attribute, or the whole object. (LDAP Search / Compare.)
    DirRead,
    /// Write an attribute, or the whole object. (LDAP Modify.)
    DirWrite,
    /// Add a child of the given class. (LDAP Add.)
    DirAddChild(ObjClass),
    /// Delete the object. (LDAP Delete.)
    DirDelete,
    /// List a container. (LDAP Search scope.)
    DirList,
    /// Exercise a control access right ("extended right").
    DirControlRight(ControlRightId),
    /// Call an RPC method (the resource carries iface + opnum).
    RpcCall,
    /// Read a file.
    FileRead,
    /// Write a file.
    FileWrite,
    /// Update a DNS zone / record.
    ///
    /// PEP contract (A-22; docs/40 §2, D166): an authenticated `Subject` for
    /// this action may come only from a verified GSS-TSIG signature over that
    /// update message. GSS-TSIG signs but cannot encrypt, so this action has
    /// no transport floor (`required_sec`); an unauthenticated `DnsUpdate` is
    /// always denied (the anonymous allowlist never applies to it).
    DnsUpdate,
    /// Transfer a DNS zone. (Read floor: `{encrypted}`.)
    DnsXfer,
    /// KDC: AS exchange.
    ///
    /// For all four `Kdc*` actions (A-22): no transport floor — Kerberos
    /// messages carry their own protection, verified inside keyd
    /// (pre-authentication; TGT + authenticator + req-body checksum). FAST is
    /// reported separately in `AuthContext.armored` and is NOT mapped to
    /// `TransportSec.encrypted`; policy rules require it (`Match.auth`, D126;
    /// docs/48 §7.2 — see [`crate::mandatory_fast`]).
    KdcAs,
    /// KDC: TGS exchange. (No transport floor — see `KdcAs`.)
    KdcTgs,
    /// KDC: S4U2Self. (No transport floor — see `KdcAs`.)
    KdcS4u2Self,
    /// KDC: S4U2Proxy. (No transport floor — see `KdcAs`.)
    KdcS4u2Proxy,
    /// Change policy — the most privileged action (docs/06 §9).
    PolicyAdmin,
}

/// The protocol family of an action, used by `ActionMatch::Class` and by the
/// rate-limit key. Spec: docs/11 §3 (`ActionMatch`: "Exact | AnyOf | Class"),
/// §8 (rate-limit key derived from the request).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActionClass {
    /// `Dir*`.
    Directory,
    /// `RpcCall`.
    Rpc,
    /// `File*`.
    File,
    /// `Dns*`.
    Dns,
    /// `Kdc*`.
    Kerberos,
    /// `PolicyAdmin`.
    Policy,
}

impl Action {
    /// The protocol family of this action. Spec: docs/06 §3 table.
    #[must_use]
    pub fn class(&self) -> ActionClass {
        match self {
            Action::DirRead
            | Action::DirWrite
            | Action::DirAddChild(_)
            | Action::DirDelete
            | Action::DirList
            | Action::DirControlRight(_) => ActionClass::Directory,
            Action::RpcCall => ActionClass::Rpc,
            Action::FileRead | Action::FileWrite => ActionClass::File,
            Action::DnsUpdate | Action::DnsXfer => ActionClass::Dns,
            Action::KdcAs | Action::KdcTgs | Action::KdcS4u2Self | Action::KdcS4u2Proxy => {
                ActionClass::Kerberos
            }
            Action::PolicyAdmin => ActionClass::Policy,
        }
    }
}

/// Observed request context. Spec: docs/11 §1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// Network zone of the source, as observed by the PEP. Matched by rules
    /// (`ContextMatch.src_net`) and by every anonymous-allowlist entry
    /// (`AnonymousGrant`: docs/15 §6, "from the internal network").
    /// Spec: docs/11 §1.
    pub src_net: IpScope,
    /// Explicit time, supplied by the PEP. The PDP never reads a clock
    /// (P9). Spec: docs/11 §1, §10.
    pub time: Instant,
    /// The transport the request arrived on. Spec: docs/11 §1.
    pub transport: Transport,
    /// Security properties of that transport, as observed by the PEP.
    /// Spec: docs/11 §1.
    pub transport_sec: TransportSec,
}

/// Network zone of the request source. Spec: docs/11 §1 ("internal zone?
/// network class").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpScope {
    /// An internal network zone.
    Internal,
    /// Anything else.
    External,
}

/// An explicit point in time: seconds since 1970-01-01T00:00:00Z, as supplied
/// by the PEP. Not related to any clock (P9). Spec: docs/11 §1 (`time:
/// Instant`), §10 P9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(pub u64);

/// The transport a request arrived on. Spec: docs/11 §1 (`Ldaps | SmbEnc |
/// NcacnIpTcpPrivacy | Cldap | ...`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transport {
    /// LDAP with no TLS layer: the cleartext listener before any StartTLS
    /// (docs/49 §4.3 names `Ldaps` for 636 and for 389 after StartTLS, and
    /// nothing for 389 before it). Recorded so the LDAP PEP reports the
    /// transport truthfully; the security state it carries is
    /// `Context.transport_sec`, which is what [`crate::decide`] reads;
    /// `decide` acts on no `Context.transport` value (since R2, A-102,
    /// [`crate::required_sec_on`] is the same floor on every transport), so
    /// this variant changes no decision. Spec: docs/49 §4.3, §4.4;
    /// docs/questions/Q-190 item 2 (A-54).
    Ldap,
    /// LDAP over TLS.
    Ldaps,
    /// LDAP with a SASL security layer.
    LdapSasl,
    /// Connectionless LDAP (UDP).
    Cldap,
    /// SMB with encryption.
    SmbEnc,
    /// ncacn_ip_tcp at the privacy authentication level.
    NcacnIpTcpPrivacy,
    /// DNS.
    Dns,
    /// Kerberos (KDC).
    Kerberos,
    /// A Unix-domain socket on the DC host itself: the admin plane's
    /// `dird-admin.sock` channel (admind → dird), whose peer is identified
    /// by its peer credentials and whose bytes never leave the host's
    /// kernel, with no encryption layer of its own (A-57 / Q-214). Its PEP
    /// reports `{encrypted: true, sealed: true}` and `channel_bound: true`
    /// only when keyd verified that every AP-REQ the request carries is
    /// bound to that very operation — the Authenticator's `cksum`, "a
    /// checksum of the application data that accompanies the KRB_AP_REQ"
    /// (RFC 4120 §5.5.1, key usage 10), over the operation digest (R2,
    /// docs/52 §5 item 4).
    ///
    /// Its floor is the floor of every transport ([`crate::required_sec_on`]):
    /// a write needs `channel_bound`. The A-74 exemption (Q-292 option (a))
    /// was removed with R2 (A-102).
    ///
    /// Spec: docs/51 §5.4 (R51-9), §7.1; docs/52 §3.2, §5 item 4;
    /// docs/questions/Q-463 (A-102; superseding Q-292 / A-74 option (a));
    /// A-57 / Q-214 (the local channel); RFC 4120 §5.5.1.
    LocalIpc,
}

/// Security properties of the transport. Spec: docs/11 §1 (`{ encrypted,
/// sealed, channel_bound: bool }`), §4 (`required_sec`).
///
/// `encrypted`: confidentiality; `sealed`: message protection bound to the
/// authenticated security context (e.g. RPC PKT_PRIVACY, docs/06 §5);
/// `channel_bound`: the authentication is bound to the channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TransportSec {
    /// Confidentiality is provided.
    pub encrypted: bool,
    /// Messages are sealed under the authenticated context.
    pub sealed: bool,
    /// The authentication is channel-bound.
    pub channel_bound: bool,
}

impl TransportSec {
    /// No protection at all.
    pub const NONE: TransportSec = TransportSec {
        encrypted: false,
        sealed: false,
        channel_bound: false,
    };

    /// `true` if every property `required` asks for is present.
    /// Spec: docs/11 §4 (`meets(transport_sec, required_sec(action))`).
    #[must_use]
    pub fn meets(self, required: TransportSec) -> bool {
        (self.encrypted || !required.encrypted)
            && (self.sealed || !required.sealed)
            && (self.channel_bound || !required.channel_bound)
    }

    /// The union of two requirements (each property required by either).
    #[must_use]
    pub fn union(self, other: TransportSec) -> TransportSec {
        TransportSec {
            encrypted: self.encrypted || other.encrypted,
            sealed: self.sealed || other.sealed,
            channel_bound: self.channel_bound || other.channel_bound,
        }
    }
}

// ---------------------------------------------------------------------------
// The answer — docs/11 §1b.
// ---------------------------------------------------------------------------

/// The decision. Spec: docs/11 §1b.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Allow or deny.
    pub effect: Effect,
    /// What the PEP must do with the decision; always exactly one
    /// [`Obligation::Audit`] (P7). Spec: docs/11 §1b, §8.
    pub obligations: Vec<Obligation>,
    /// Internal reason, for the audit record only. The client receives a
    /// uniform error (docs/11 §1b, §8; docs/05 §6; D13).
    pub reason: ReasonCode,
}

/// The effect of a decision. Spec: docs/11 §1b.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    /// The request may proceed.
    Allow,
    /// The request is refused.
    Deny,
}

/// An obligation the PEP must honour. Spec: docs/11 §1b, §2 ("the PEP must
/// honour obligations"), §8.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Obligation {
    /// Record the decision. Emitted exactly once on every decision (P7).
    Audit,
    /// Apply rate limiting under the given key.
    RateLimit(RlKey),
    /// Apply a constraint (e.g. a page-size cap).
    Constrain(Constraint),
}

/// A rate-limit key derived from the request. Spec: docs/11 §8 ("RateLimit
/// with a request-derived key").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RlKey {
    /// The requesting principal.
    pub principal: PrincipalId,
    /// The protocol family of the action.
    pub class: ActionClass,
}

/// A constraint the PEP must enforce. Spec: docs/11 §8 ("Constrain (e.g. a
/// page size cap)").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Constraint {
    /// At most this many entries per result page.
    MaxPageSize(u32),
}

/// Identifier of a global rule. Spec: docs/11 §3 (`Rule { id: RuleId, .. }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(pub u32);

/// Internal reason code, for audit only. Spec: docs/11 §1b, §4 (the deny
/// reasons named in the pseudocode), §8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReasonCode {
    /// Every layer allowed the request.
    Allowed,
    /// The request is malformed (action and resource do not belong together,
    /// or a whole-object action carries an attribute). Fail closed (P1, D40).
    InvalidRequest,
    /// Layer 1: unauthenticated and not on the anonymous allowlist.
    Unauthenticated,
    /// Layer 2: the transport does not meet `required_sec(action)`.
    WeakTransport,
    /// A PIP lookup failed or was absent (D40).
    PipFailure,
    /// `Subject.tier` disagrees with the PIP (P3).
    SubjectMismatch,
    /// Layer 3: an explicit Deny rule matched.
    CoarseDeny(RuleId),
    /// Layer 3: no Allow rule matched (deny by default).
    NoGrant,
    /// Layer 4: a write to a Tier-0 object by a non-Tier-0 subject (P5).
    TierViolation,
    /// Layer 5: the object ACL does not grant the right.
    Acl,
    /// Layer 5: the attribute is Secret — unreachable (P6).
    NoSuchPath,
    /// Layer 5: the attribute is Sensitive and its control right is not
    /// granted.
    Sensitive,
}
