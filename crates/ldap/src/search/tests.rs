//! Search over the directory (task L8), end to end through `Engine::handle`.
//!
//! Unit tests of the crate because a bound session can only be built inside
//! it until task L7 (`Session::bound_for_test`). The directory is a real
//! dirstore opened with the phase-1 schema (ad-schema) under a temporary
//! directory, viewed through directory-pip with the naming context
//! dc=example,dc=test (realm EXAMPLE.TEST, A-53):
//!
//! ```text
//! dc=example,dc=test            domainDNS (NC root)
//! ├─ ou=Staff                    alice (the requester), bob (description unreadable),
//! │                              carol, ws01$ (computer), staff (global security: alice),
//! │                              allstaff (universal security: staff)
//! ├─ ou=Bulk                     cn=item00 … cn=item69 (containers)
//! └─ ou=Vault                    readable but not listable by the requester
//!    └─ ou=Hidden                (invisible) hiddenuser, hiddengroup (global security: alice)
//! ```
//!
//! Every descriptor grants the group staff RIGHT_DS_LIST_CONTENTS and
//! RIGHT_DS_READ_PROPERTY ([MS-ADTS] 5.1.3.2), except ou=Vault (read only,
//! so its children are invisible — [MS-ADTS] 5.1.3.3.6), bob (a deny object
//! ACE on description) and alice (GENERIC_ALL, to show what is never
//! returned whatever the ACL says). The policy allows DirRead and DirList on
//! the NC subtree (docs/11 §3). The SID layout S-1-5-21-1-2-3-<RID> follows
//! the [MS-DTYP] 2.4.2.4 example; names, RIDs and times are this project's
//! own test data, every time derived by hand in a comment. No vector or
//! fixture comes from any other implementation.
//!
//! The store is written through dirstore directly — beneath the one checker
//! — so it holds what the checker would have written (task PN4b; docs/59
//! §5.1, §5.5; docs/questions/Q-1031): the `principal-namespace` marker and
//! every principal's namespace keys (`PRINCIPAL_NAME_KEY`), through
//! crates/directory-pip's one fixture helper ([`namespace`], reused by
//! `#[path]`). LDAP never names that attribute (it has no lDAPDisplayName —
//! docs/59 §4.6, §6.4), so the keys change no answer here.
//!
//! Sources (each test names its own): RFC 4511 §4.5.1-§4.5.2, A.2; RFC 4517
//! §3.3.13, §3.3.16; RFC 4514 §2; [MS-ADTS] v20261026 3.1.1.1.4, 3.1.1.1.5,
//! 3.1.1.2.2.2, 3.1.1.2.2.2.7, 3.1.1.2.2.4, 3.1.1.3.1.2.4, 3.1.1.3.1.3.1,
//! 3.1.1.3.1.3.5, 3.1.1.3.4.6, 3.1.1.4.3, 3.1.1.4.4, 5.1.3.3.6; [MS-DRSR]
//! 5.16.3.9; docs/49 R49-9, R49-11, R49-13, R49-14, §6; A-48, A-53, A-54;
//! Q-168, Q-169.

/// The principal namespace of a store written beneath the one checker
/// (module documentation).
#[path = "../../../directory-pip/tests/common/namespace.rs"]
mod namespace;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::path::PathBuf;

use ad_schema::flags::user_account_control as uac;
use ad_schema::{phase1, Phase1Schema};
use directory_pip::{dstime_of, time_of_dstime, DirectoryContext, NamingContext, TierMap};
use dirstore::{AttrId, IntegrityKey, NewObject, NodeId, Origin, Store, Timestamp};
use dtyp::{
    AccessMask, Ace, Acl, Control, Guid, MaskSidAce, ObjectAce, SecurityDescriptor, Sid,
    ACL_REVISION_DS, SECURITY_NT_AUTHORITY,
};
use kdc::NamedPrincipal;
use keyd_types::KeydConfig;
use krb_proto::{KerberosTime, Realm};
use parse_ldap::{
    decode_message, encode_message, AttributeValueAssertion, DecodeOptions, DerefAliases,
    Direction, Filter, LdapMessage, MatchingRuleAssertion, MessageId, Profile, ProtocolOp,
    ResultCode, Scope, SearchRequest, SearchResultEntry, Substring, SubstringFilter,
    MAX_AUTH_MESSAGE_OCTETS,
};
use pdp::access_check::rights::{
    RIGHT_DS_LIST_CONTENTS, RIGHT_DS_READ_PROPERTY, RIGHT_GENERIC_ALL,
};
use pdp::{
    Action, ActionMatch, AuthMatch, Constraint, ContextMatch, Effect, IpScope, Match, Obligation,
    PolicySnapshot, PolicyVersion, ResourceMatch, RlKey, Rule, RuleId, SubjectMatch, SubtreeBase,
};

use super::limits::SearchLimits;
use crate::session::BoundIdentity;
use crate::{
    AuditReason, AuditTarget, DirectoryInputs, Engine, EngineConfig, Listener, Outcome,
    RateLimiter, RequestInputs, RootDseConfig, SearchClock, Session, TransportReport,
};

// ---------------------------------------------------------------- constants --

const REALM: &str = "EXAMPLE.TEST";

const ROOT: u32 = 1;
const STAFF_OU: u32 = 2;
const BULK_OU: u32 = 3;
const VAULT: u32 = 4;
const HIDDEN_OU: u32 = 5;
const ALICE: u32 = 10;
const BOB: u32 = 11;
const CAROL: u32 = 12;
const WS01: u32 = 20;
const STAFF: u32 = 30;
const ALLSTAFF: u32 = 31;
const HIDDEN_USER: u32 = 40;
const HIDDEN_GROUP: u32 = 41;
const BULK_FIRST: u32 = 100;
const BULK_COUNT: u32 = 70;

/// whenCreated 2026-11-01T00:00:00Z as DSTIME (seconds since 1601-01-01,
/// [MS-DRSR] 5.51): 1601→1970 = 134 774 days = 11 644 473 600 s; 1970→2026
/// = 20 454 days; January..October 2026 = 304 days; 20 758 days =
/// 1 793 491 200 s; total 13 437 964 800.
const WHEN_CREATED: i64 = 13_437_964_800;

/// pwdLastSet 2026-11-05T12:00:00Z as FILETIME (100-ns intervals since
/// 1601, [MS-DTYP] 2.3.3): 13 437 964 800 + 4 days 12 h (388 800 s) =
/// 13 438 353 600 s; × 10^7.
const PWD_LAST_SET: i64 = 134_383_536_000_000_000;

/// groupType, global security: GROUP_TYPE_SECURITY_ENABLED | GLOBAL
/// ([MS-ADTS] 2.2.12), as the stored Integer32: -2147483646.
const GLOBAL_SECURITY: i32 = i32::MIN | 0x2;
/// groupType, universal security ([MS-ADTS] 2.2.12).
const UNIVERSAL_SECURITY: i32 = i32::MIN | 0x8;

// ------------------------------------------------------------------- values --

fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0x0108,
        data3: 0x0008,
        data4: [8, 1, 8, 1, 8, 1, 8, 1],
    }
}

fn domain_sid() -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3]).expect("SID")
}

fn sid_of(id: u32) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 1000 + id]).expect("SID")
}

fn time(h: u8, m: u8, s: u8) -> KerberosTime {
    KerberosTime::new(2026, 11, 13, h, m, s).expect("time")
}

fn now() -> KerberosTime {
    time(10, 0, 0)
}

fn int32(v: i32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn int64(v: i64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn bits(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// A self-relative descriptor with the given DACL ([MS-DTYP] 2.4.6: SR set;
/// DP; no group, so GD).
fn sd(aces: Vec<Ace>) -> Vec<u8> {
    SecurityDescriptor {
        sbz1: 0,
        control: Control(Control::SELF_RELATIVE | Control::DACL_PRESENT | Control::GROUP_DEFAULTED),
        owner_sid: Some(Sid::new(SECURITY_NT_AUTHORITY, &[18]).expect("SID")),
        group_sid: None,
        sacl: None,
        dacl: Some(Acl {
            acl_revision: ACL_REVISION_DS,
            aces,
        }),
    }
    .encode()
    .expect("canonical descriptor")
}

/// ACCESS_ALLOWED_ACE ([MS-DTYP] 2.4.4.2).
fn allow(mask: u32, sid: Sid) -> Ace {
    Ace::AccessAllowed(MaskSidAce {
        ace_flags: 0,
        mask: AccessMask(mask),
        sid,
    })
}

/// ACCESS_DENIED_OBJECT_ACE for one attribute ([MS-DTYP] 2.4.4.5).
fn deny_attribute(mask: u32, attribute: Guid, sid: Sid) -> Ace {
    Ace::AccessDeniedObject(ObjectAce {
        ace_flags: 0,
        mask: AccessMask(mask),
        object_type: Some(attribute),
        inherited_object_type: None,
        sid,
    })
}

/// Staff may list and read. Spec: [MS-ADTS] 5.1.3.2 (LC, RP).
fn open_sd() -> Vec<u8> {
    sd(vec![allow(
        RIGHT_DS_LIST_CONTENTS | RIGHT_DS_READ_PROPERTY,
        sid_of(STAFF),
    )])
}

// ---------------------------------------------------------------- directory --

/// A per-test directory under the system temporary directory.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!("ldap-search-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn naming_context() -> NamingContext {
    NamingContext::new(&["example", "test"]).expect("naming context")
}

struct Dir {
    p1: Phase1Schema,
    store: Store,
    ctx: DirectoryContext,
    tiers: TierMap,
    seq: Cell<u64>,
    _dir: TempDir,
}

impl Dir {
    fn new(name: &str) -> Dir {
        let p1 = phase1().expect("schema");
        let dir = TempDir::new(name);
        let store = Store::open(
            dir.0.join("store.redb"),
            IntegrityKey::from_bytes(&[0x18; 32]),
            p1.schema().clone(),
        )
        .expect("store");
        let ctx = DirectoryContext::new(
            p1.clone(),
            &KeydConfig::new(Realm::new(REALM).expect("realm")),
            naming_context(),
        )
        .expect("context");
        let mut txn = store.begin_write().expect("write");
        namespace::create_namespace_marker(&mut txn);
        txn.commit().expect("commit");
        Dir {
            p1,
            store,
            ctx,
            tiers: TierMap::empty(),
            seq: Cell::new(0),
            _dir: dir,
        }
    }

    fn attr(&self, name: &str) -> AttrId {
        self.p1.attribute_by_name(name).expect(name)
    }

    fn attr_guid(&self, name: &str) -> Guid {
        self.p1
            .attribute_schema_id_guid(self.attr(name))
            .expect(name)
    }

    fn object(
        &self,
        id: u32,
        parent: Option<u32>,
        class: &str,
        sd_value: Vec<u8>,
        attrs: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        let mut attributes: Vec<(AttrId, Vec<Vec<u8>>)> = attrs
            .iter()
            .map(|(n, v)| (self.attr(n), v.clone()))
            .collect();
        attributes.push((self.attr("nTSecurityDescriptor"), vec![sd_value]));
        let class = self.p1.class_by_name(class).expect(class);
        NewObject {
            guid: guid(id),
            parent: parent.map(guid),
            classes: self.p1.class(class).expect("class").object_class.clone(),
            attributes,
        }
    }

    fn principal(
        &self,
        class: &str,
        id: u32,
        parent: u32,
        sam: &str,
        sd_value: Vec<u8>,
        extra: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        let mut attrs = vec![
            ("cn", vec![sam.as_bytes().to_vec()]),
            ("sAMAccountName", vec![sam.as_bytes().to_vec()]),
            ("objectSid", vec![sid_of(id).encode()]),
        ];
        attrs.extend(extra.iter().cloned());
        self.object(id, Some(parent), class, sd_value, &attrs)
    }

    fn user(
        &self,
        id: u32,
        parent: u32,
        sam: &str,
        sd_value: Vec<u8>,
        extra: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        let mut attrs = vec![
            ("userAccountControl", vec![bits(uac::ADS_UF_NORMAL_ACCOUNT)]),
            ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
            ("whenCreated", vec![int64(WHEN_CREATED)]),
        ];
        attrs.extend(extra.iter().cloned());
        self.principal("user", id, parent, sam, sd_value, &attrs)
    }

    fn group(
        &self,
        id: u32,
        parent: u32,
        sam: &str,
        group_type: i32,
        members: &[u32],
    ) -> NewObject {
        let mut extra = vec![("groupType", vec![int32(group_type)])];
        if !members.is_empty() {
            extra.push((
                "member",
                members
                    .iter()
                    .map(|m| guid(*m).to_packet().to_vec())
                    .collect(),
            ));
        }
        self.principal("group", id, parent, sam, open_sd(), &extra)
    }

    /// Create every object in one committed transaction, each principal with
    /// its namespace keys as the one checker writes them (module
    /// [`namespace`]).
    fn create_all(&self, objects: Vec<NewObject>) {
        let mut txn = self.store.begin_write().expect("write");
        let mut created = Vec::with_capacity(objects.len());
        for obj in objects {
            let seq = self.seq.get() + 1;
            self.seq.set(seq);
            let origin = Origin {
                wall_clock: Timestamp(1000 + seq),
                origin_node: NodeId([0x18; 16]),
                origin_seq: seq,
            };
            created.push((obj.guid, origin));
            txn.create_object(obj, &origin).expect("create");
        }
        namespace::write_namespace_keys(&self.store, &mut txn, &self.ctx, &created);
        txn.commit().expect("commit");
    }

    /// The directory of the module documentation.
    fn standard(name: &str) -> Dir {
        let d = Dir::new(name);
        let description = d.attr_guid("description");
        let mut objects = vec![
            d.object(
                ROOT,
                None,
                "domainDNS",
                open_sd(),
                &[
                    ("dc", vec![b"example".to_vec()]),
                    ("objectSid", vec![domain_sid().encode()]),
                ],
            ),
            d.object(
                STAFF_OU,
                Some(ROOT),
                "organizationalUnit",
                open_sd(),
                &[("ou", vec![b"Staff".to_vec()])],
            ),
            d.object(
                BULK_OU,
                Some(ROOT),
                "organizationalUnit",
                open_sd(),
                &[("ou", vec![b"Bulk".to_vec()])],
            ),
            d.object(
                VAULT,
                Some(ROOT),
                "organizationalUnit",
                sd(vec![allow(RIGHT_DS_READ_PROPERTY, sid_of(STAFF))]),
                &[("ou", vec![b"Vault".to_vec()])],
            ),
            // Not listable either: an object is visible by its parent's
            // RIGHT_DS_LIST_CONTENTS alone ([MS-ADTS] 5.1.3.3.6), so the
            // children of ou=Hidden are hidden by ou=Hidden's descriptor.
            d.object(
                HIDDEN_OU,
                Some(VAULT),
                "organizationalUnit",
                sd(vec![allow(RIGHT_DS_READ_PROPERTY, sid_of(STAFF))]),
                &[("ou", vec![b"Hidden".to_vec()])],
            ),
            d.user(
                ALICE,
                STAFF_OU,
                "alice",
                sd(vec![allow(RIGHT_GENERIC_ALL, sid_of(STAFF))]),
                &[
                    ("userPrincipalName", vec![b"alice@example.test".to_vec()]),
                    ("description", vec![b"Team lead".to_vec()]),
                ],
            ),
            d.user(
                BOB,
                STAFF_OU,
                "bob",
                sd(vec![
                    deny_attribute(RIGHT_DS_READ_PROPERTY, description, sid_of(STAFF)),
                    allow(
                        RIGHT_DS_LIST_CONTENTS | RIGHT_DS_READ_PROPERTY,
                        sid_of(STAFF),
                    ),
                ]),
                &[("description", vec![b"Secret description".to_vec()])],
            ),
            d.user(CAROL, STAFF_OU, "carol", open_sd(), &[]),
            d.principal(
                "computer",
                WS01,
                STAFF_OU,
                "ws01$",
                open_sd(),
                &[
                    (
                        "userAccountControl",
                        vec![bits(uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT)],
                    ),
                    ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
                    ("whenCreated", vec![int64(WHEN_CREATED)]),
                    ("dNSHostName", vec![b"ws01.example.test".to_vec()]),
                    (
                        "servicePrincipalName",
                        vec![b"host/ws01.example.test".to_vec()],
                    ),
                ],
            ),
            d.group(STAFF, STAFF_OU, "staff", GLOBAL_SECURITY, &[ALICE]),
            d.group(ALLSTAFF, STAFF_OU, "allstaff", UNIVERSAL_SECURITY, &[STAFF]),
            d.user(HIDDEN_USER, HIDDEN_OU, "hiddenuser", open_sd(), &[]),
            d.group(
                HIDDEN_GROUP,
                HIDDEN_OU,
                "hiddengroup",
                GLOBAL_SECURITY,
                &[ALICE],
            ),
        ];
        for i in 0..BULK_COUNT {
            objects.push(d.object(
                BULK_FIRST + i,
                Some(BULK_OU),
                "container",
                open_sd(),
                &[("cn", vec![format!("item{i:02}").into_bytes()])],
            ));
        }
        d.create_all(objects);
        d
    }
}

// ------------------------------------------------------------ the requester --

struct AdmitAll {
    calls: u32,
}

impl RateLimiter for AdmitAll {
    fn admit(&mut self, _key: &RlKey, _now: &KerberosTime) -> bool {
        self.calls += 1;
        true
    }
}

/// A clock that starts at `now()` and advances `step` seconds per reading.
struct StepClock {
    step: i64,
    reads: Cell<i64>,
}

impl StepClock {
    fn fixed() -> StepClock {
        StepClock {
            step: 0,
            reads: Cell::new(0),
        }
    }
}

impl SearchClock for StepClock {
    fn now(&self) -> KerberosTime {
        let reads = self.reads.get();
        self.reads.set(reads + 1);
        let start = dstime_of(&now()).expect("dstime");
        time_of_dstime(start + reads * self.step).expect("time")
    }
}

/// The policy: Allow DirRead and DirList on the NC subtree, with
/// `obligations` (docs/11 §3).
fn policy(obligations: Vec<Obligation>) -> PolicySnapshot {
    PolicySnapshot::new(
        PolicyVersion(1),
        vec![Rule {
            id: RuleId(1),
            effect: Effect::Allow,
            when: Match {
                action: ActionMatch::AnyOf(vec![Action::DirRead, Action::DirList]),
                resource: ResourceMatch::DirSubtree {
                    base: SubtreeBase::new(naming_context().dn().clone()).expect("subtree"),
                },
                subject: SubjectMatch::Any,
                context: ContextMatch::ANY,
                auth: AuthMatch::ANY,
            },
            obligations,
        }],
        vec![],
    )
}

/// alice, bound over LDAPS with a keyd-verified channel binding (the L7
/// seam): authtime 08:00, endtime 18:00.
fn alice_session() -> Session {
    Session::bound_for_test(
        9,
        Listener::Ldaps,
        BoundIdentity {
            principal: NamedPrincipal::from_text(REALM, 1, &["alice"]).expect("name"),
            sid: sid_of(ALICE),
            authtime: time(8, 0, 0),
            endtime: time(18, 0, 0),
            channel_bound: true,
        },
    )
}

fn engine_for(nc: NamingContext) -> Engine {
    Engine::new(EngineConfig {
        root_dse: RootDseConfig {
            naming_context: nc,
            dns_host_name: "dc1.example.test".to_owned(),
        },
    })
    .expect("engine")
}

fn engine() -> Engine {
    engine_for(naming_context())
}

fn tls() -> TransportReport {
    TransportReport {
        src_net: IpScope::Internal,
        tls_established: true,
        input_pending: false,
    }
}

fn request(base: &str, scope: Scope, filter: Filter, attributes: &[&str]) -> SearchRequest {
    SearchRequest {
        base_object: base.to_owned(),
        scope,
        deref_aliases: DerefAliases::NeverDerefAliases,
        size_limit: 0,
        time_limit: 0,
        types_only: false,
        filter,
        attributes: attributes.iter().map(|a| (*a).to_owned()).collect(),
    }
}

fn present(attr: &str) -> Filter {
    Filter::Present(attr.to_owned())
}

fn eq(attr: &str, value: &[u8]) -> Filter {
    Filter::EqualityMatch(AttributeValueAssertion {
        attribute_desc: attr.to_owned(),
        assertion_value: value.to_vec(),
    })
}

fn ge(attr: &str, value: &[u8]) -> Filter {
    Filter::GreaterOrEqual(AttributeValueAssertion {
        attribute_desc: attr.to_owned(),
        assertion_value: value.to_vec(),
    })
}

fn le(attr: &str, value: &[u8]) -> Filter {
    Filter::LessOrEqual(AttributeValueAssertion {
        attribute_desc: attr.to_owned(),
        assertion_value: value.to_vec(),
    })
}

fn substrings(attr: &str, pieces: Vec<Substring>) -> Filter {
    Filter::Substrings(SubstringFilter {
        r#type: attr.to_owned(),
        substrings: pieces,
    })
}

fn not(f: Filter) -> Filter {
    Filter::Not(Box::new(f))
}

const STAFF_DN: &str = "ou=Staff,dc=example,dc=test";
const NC_DN: &str = "dc=example,dc=test";

/// What a search returned, decoded.
struct Got {
    entries: Vec<SearchResultEntry>,
    code: ResultCode,
    outcome: Outcome,
}

impl Got {
    fn names(&self) -> Vec<&str> {
        self.entries
            .iter()
            .map(|e| e.object_name.as_str())
            .collect()
    }

    fn sorted_names(&self) -> Vec<&str> {
        let mut n = self.names();
        n.sort_unstable();
        n
    }

    fn only(&self) -> &SearchResultEntry {
        assert_eq!(self.entries.len(), 1, "{:?}", self.names());
        &self.entries[0]
    }
}

fn values<'e>(entry: &'e SearchResultEntry, name: &str) -> Option<&'e [Vec<u8>]> {
    entry
        .attributes
        .iter()
        .find(|a| a.r#type == name)
        .map(|a| a.vals.as_slice())
}

fn decode(octets: &[u8]) -> LdapMessage {
    decode_message(
        octets,
        &DecodeOptions {
            direction: Direction::Response,
            profile: Profile::Canonical,
            max_message_octets: MAX_AUTH_MESSAGE_OCTETS,
        },
    )
    .expect("canonical response")
}

/// Run one search as `session` against `d` (module documentation).
struct Run<'a> {
    d: &'a Dir,
    engine: Engine,
    policy: PolicySnapshot,
    clock: StepClock,
}

impl<'a> Run<'a> {
    fn new(d: &'a Dir) -> Run<'a> {
        Run {
            d,
            engine: engine(),
            policy: policy(vec![]),
            clock: StepClock::fixed(),
        }
    }

    fn as_session(&self, session: &mut Session, req: SearchRequest) -> Got {
        let view = self.d.ctx.view(&self.d.store, &self.d.tiers).expect("view");
        let mut rate = AdmitAll { calls: 0 };
        let msg = LdapMessage {
            message_id: MessageId::new(7).expect("id"),
            protocol_op: ProtocolOp::SearchRequest(req),
            controls: None,
        };
        let octets = encode_message(&msg).expect("canonical");
        let outcome = self.engine.handle(
            session,
            &octets,
            RequestInputs {
                snapshot: &self.policy,
                pip: &view,
                accounts: &view,
                rate: &mut rate,
                now: now(),
                transport: tls(),
                directory: Some(DirectoryInputs {
                    view: directory_pip::PepView::new(&view),
                    clock: &self.clock,
                }),
            },
        );
        let (last, entries) = outcome.responses.split_last().expect("a SearchResultDone");
        let code = match decode(last).protocol_op {
            ProtocolOp::SearchResultDone(r) => {
                assert!(r.matched_dn.is_empty() && r.diagnostic_message.is_empty());
                r.result_code
            }
            other => panic!("not a SearchResultDone: {other:?}"),
        };
        let entries = entries
            .iter()
            .map(|o| match decode(o).protocol_op {
                ProtocolOp::SearchResultEntry(e) => e,
                other => panic!("not an entry: {other:?}"),
            })
            .collect();
        Got {
            entries,
            code,
            outcome,
        }
    }

    fn search(&self, req: SearchRequest) -> Got {
        self.as_session(&mut alice_session(), req)
    }
}

// --------------------------------------------------------------------- tests --

/// A-53 ([MS-ADTS] 3.1.1.1.4: the root's DN is the assigned naming context)
/// and docs/49 §7 (the client may spell the case differently; the suffix is
/// compared by its case-folded key): a base resolves case-insensitively; a
/// base outside the NC is noSuchObject (R49-17); `<GUID=hex>` resolves
/// through get_object ([MS-ADTS] 3.1.1.3.1.2.4); a syntax error is
/// invalidDNSyntax and a value no phase-1 object can carry noSuchObject
/// (Q-195 item 4).
#[test]
fn dn_resolution() {
    let d = Dir::standard("dn");
    let r = Run::new(&d);
    let got = r.search(request(
        "OU=STAFF,DC=EXAMPLE,DC=TEST",
        Scope::BaseObject,
        present("objectClass"),
        &["1.1"],
    ));
    assert_eq!(got.code, ResultCode::Success);
    assert_eq!(got.names(), [STAFF_DN]);
    assert_eq!(
        got.outcome.audit.target,
        Some(AuditTarget::DirObject(guid(STAFF_OU)))
    );

    let root = r.search(request(
        NC_DN,
        Scope::BaseObject,
        present("objectClass"),
        &["distinguishedName"],
    ));
    assert_eq!(root.names(), [NC_DN]);
    assert_eq!(
        values(root.only(), "distinguishedName"),
        Some(&[NC_DN.as_bytes().to_vec()][..])
    );

    for wrong in [
        "ou=Staff,dc=example,dc=com",
        "ou=Staff,dc=example",
        "ou=Staff",
        "ou=Staff,dc=example,dc=test,dc=extra",
        "ou=Nope,dc=example,dc=test",
        "cn=Staff,dc=example,dc=test",
        "ou=Staff,dc=exampl\\c3\\a9,dc=test",
    ] {
        let got = r.search(request(
            wrong,
            Scope::BaseObject,
            present("objectClass"),
            &[],
        ));
        assert_eq!(got.code, ResultCode::NoSuchObject, "{wrong}");
        assert!(got.entries.is_empty());
    }
    for bad in [
        "ou=Staff,,dc=example,dc=test",
        "ou=Staff+cn=x,dc=example,dc=test",
        "<SID=S-1-5>",
    ] {
        let got = r.search(request(bad, Scope::BaseObject, present("objectClass"), &[]));
        assert_eq!(got.code, ResultCode::InvalidDnSyntax, "{bad}");
        assert_eq!(got.outcome.audit.reason, AuditReason::BaseDnSyntax);
    }
    let hex: String = guid(ALICE)
        .to_packet()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let by_guid = r.search(request(
        &format!("<GUID={hex}>"),
        Scope::BaseObject,
        present("objectClass"),
        &["1.1"],
    ));
    assert_eq!(by_guid.names(), ["cn=alice,ou=Staff,dc=example,dc=test"]);
    let unknown: String = guid(9999)
        .to_packet()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let none = r.search(request(
        &format!("<GUID={unknown}>"),
        Scope::BaseObject,
        present("objectClass"),
        &[],
    ));
    assert_eq!(none.code, ResultCode::NoSuchObject);
}

/// RFC 4511 §4.5.1.2: baseObject, singleLevel and wholeSubtree; [MS-ADTS]
/// 5.1.3.3.6 / docs/49 §6.1 item 3: the invisible subtree (ou=Vault's
/// children) is pruned and counted.
#[test]
fn scopes() {
    let d = Dir::standard("scopes");
    let r = Run::new(&d);
    let base = r.search(request(
        STAFF_DN,
        Scope::BaseObject,
        present("objectClass"),
        &["1.1"],
    ));
    assert_eq!(base.names(), [STAFF_DN]);

    let one = r.search(request(
        STAFF_DN,
        Scope::SingleLevel,
        present("objectClass"),
        &["1.1"],
    ));
    assert_eq!(one.code, ResultCode::Success);
    assert_eq!(
        one.sorted_names(),
        [
            "cn=alice,ou=Staff,dc=example,dc=test",
            "cn=allstaff,ou=Staff,dc=example,dc=test",
            "cn=bob,ou=Staff,dc=example,dc=test",
            "cn=carol,ou=Staff,dc=example,dc=test",
            "cn=staff,ou=Staff,dc=example,dc=test",
            "cn=ws01$,ou=Staff,dc=example,dc=test",
        ]
    );

    let all = r.search(request(
        NC_DN,
        Scope::WholeSubtree,
        present("objectClass"),
        &["1.1"],
    ));
    assert_eq!(all.code, ResultCode::Success);
    // root, Staff + 6, Bulk + 70, Vault.
    assert_eq!(all.entries.len(), 1 + 1 + 6 + 1 + 70 + 1);
    assert_eq!(all.names()[0], NC_DN);
    let audit = all.outcome.audit.search.clone().expect("search facts");
    assert_eq!(audit.entries_returned, 80);
    assert_eq!(audit.candidates_visited, 80);
    assert_eq!(audit.pruned_subtrees, 1, "ou=Vault is not listable");
    for name in all.names() {
        assert!(!name.to_ascii_lowercase().contains("hidden"), "{name}");
    }
}

/// docs/49 §6.1 item 3 (`children` with paging; A-49): a one-level search
/// of more children than one page (CHILD_PAGE_SIZE = 64) returns every
/// child once, in name-index order.
#[test]
fn one_level_pages_across_more_than_a_page() {
    let d = Dir::standard("paging");
    let r = Run::new(&d);
    let got = r.search(request(
        "ou=Bulk,dc=example,dc=test",
        Scope::SingleLevel,
        present("objectClass"),
        &["cn"],
    ));
    assert_eq!(got.code, ResultCode::Success);
    assert_eq!(got.entries.len(), 70);
    const { assert!(BULK_COUNT as usize > super::limits::CHILD_PAGE_SIZE) };
    let expected: Vec<String> = (0..BULK_COUNT)
        .map(|i| format!("cn=item{i:02},ou=Bulk,dc=example,dc=test"))
        .collect();
    assert_eq!(
        got.names(),
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );
}

/// The users of ou=Staff matched by `filter`, sorted by cn.
fn staff_matching(r: &Run<'_>, filter: Filter) -> Vec<String> {
    let got = r.search(request(STAFF_DN, Scope::SingleLevel, filter, &["cn"]));
    assert_eq!(got.code, ResultCode::Success);
    let mut cns: Vec<String> = got
        .entries
        .iter()
        .map(|e| String::from_utf8(values(e, "cn").expect("cn")[0].clone()).expect("UTF-8"))
        .collect();
    cns.sort_unstable();
    cns
}

/// RFC 4511 §4.5.1.7 (three-valued logic; and / or / not) and the
/// comparison rules of [MS-ADTS] 3.1.1.2.2.4: equality (UnicodeString,
/// interim A–Z fold — Q-080), presence, substrings (RFC 4517 §4.2.6), ge /
/// le on Integer (signed — .2; RFC 4517 §3.3.16) and Time (.14; RFC 4517
/// §3.3.13), objectClass (OID rule, .10) and objectCategory ([MS-ADTS]
/// 3.1.1.3.1.3.5).
#[test]
fn filters() {
    let d = Dir::standard("filters");
    let r = Run::new(&d);
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        staff_matching(&r, eq("sAMAccountName", b"ALICE")),
        s(&["alice"])
    );
    assert_eq!(
        staff_matching(&r, eq("samaccountname", b"alice")),
        s(&["alice"])
    );
    // The attributeID OID names the attribute ([MS-ADTS] 3.1.1.3.1.3.6).
    assert_eq!(
        staff_matching(&r, eq("1.2.840.113556.1.4.221", b"bob")),
        s(&["bob"])
    );
    assert_eq!(
        staff_matching(&r, substrings("cn", vec![Substring::Any(b"O".to_vec())])),
        s(&["bob", "carol"])
    );
    assert_eq!(
        staff_matching(
            &r,
            substrings("cn", vec![Substring::Initial(b"a".to_vec())])
        ),
        s(&["alice", "allstaff"])
    );
    assert_eq!(
        staff_matching(
            &r,
            substrings(
                "cn",
                vec![
                    Substring::Initial(b"a".to_vec()),
                    Substring::Final(b"f".to_vec())
                ]
            )
        ),
        s(&["allstaff"])
    );
    assert_eq!(
        staff_matching(
            &r,
            Filter::And(vec![
                eq("objectClass", b"user"),
                not(eq("objectClass", b"computer"))
            ])
        ),
        s(&["alice", "bob", "carol"])
    );
    assert_eq!(
        staff_matching(&r, Filter::Or(vec![eq("cn", b"carol"), eq("cn", b"ws01$")])),
        s(&["carol", "ws01$"])
    );
    // userAccountControl: ws01$ is WT (0x1000 = 4096), the users NORMAL (512).
    assert_eq!(
        staff_matching(&r, ge("userAccountControl", b"4096")),
        s(&["ws01$"])
    );
    assert_eq!(
        staff_matching(&r, le("userAccountControl", b"512")),
        s(&["alice", "bob", "carol"])
    );
    // groupType is signed: -2147483646 (global) < -2147483640 (universal).
    assert_eq!(
        staff_matching(&r, le("groupType", b"-2147483646")),
        s(&["staff"])
    );
    assert_eq!(
        staff_matching(&r, ge("groupType", b"-2147483646")),
        s(&["allstaff", "staff"])
    );
    // whenCreated 2026-11-01T00:00:00Z.
    assert_eq!(
        staff_matching(&r, ge("whenCreated", b"20261101000000Z")),
        s(&["alice", "bob", "carol", "ws01$"])
    );
    assert_eq!(
        staff_matching(&r, le("whenCreated", b"20261031235959Z")),
        s(&[])
    );
    assert_eq!(
        staff_matching(&r, eq("whenCreated", b"202611010100+0100")),
        s(&["alice", "bob", "carol", "ws01$"])
    );
    // objectCategory=user means the defaultObjectCategory of user (Person):
    // users, not the computer (Computer) — [MS-ADTS] 3.1.1.3.1.3.5.
    assert_eq!(
        staff_matching(&r, eq("objectCategory", b"user")),
        s(&["alice", "bob", "carol"])
    );
    assert_eq!(
        staff_matching(&r, eq("objectCategory", b"computer")),
        s(&["ws01$"])
    );
    // approxMatch = equality ([MS-ADTS] 3.1.1.3.1.3.1); an extensibleMatch
    // with no rule = equality on its type (RFC 4511 §4.5.1.7.7).
    assert_eq!(
        staff_matching(
            &r,
            Filter::ApproxMatch(AttributeValueAssertion {
                attribute_desc: "cn".to_owned(),
                assertion_value: b"BOB".to_vec(),
            })
        ),
        s(&["bob"])
    );
    assert_eq!(
        staff_matching(
            &r,
            Filter::ExtensibleMatch(MatchingRuleAssertion {
                matching_rule: None,
                r#type: Some("cn".to_owned()),
                match_value: b"carol".to_vec(),
                dn_attributes: true,
            })
        ),
        s(&["carol"])
    );
    // member is a DN: equal when it names the same object ([MS-ADTS]
    // 3.1.1.2.2.4.5), whatever the spelling.
    assert_eq!(
        staff_matching(&r, eq("member", b"CN=ALICE,OU=staff,DC=Example,DC=Test")),
        s(&["staff"])
    );
}

/// RFC 4511 §4.5.1.7: an unrecognised attribute, an invalid assertion, an
/// unsupported matching rule, memberOf in a filter (constructed — Q-168
/// item 2), and a DN or OID assertion with no ordering rule are Undefined —
/// excluded both as themselves and under 'not', TRUE only through 'or'.
#[test]
fn undefined_items() {
    let d = Dir::standard("undefined");
    let r = Run::new(&d);
    let none: Vec<String> = Vec::new();
    for undefined in [
        eq("shoeSize", b"12"),
        present("shoeSize"),
        eq("cn;binary", b"alice"),
        eq("userAccountControl", b"0512"),
        eq("whenCreated", b"20261101000000"),
        eq("cn", "al\u{e9}".as_bytes()),
        ge("member", b"cn=alice,ou=Staff,dc=example,dc=test"),
        substrings("objectClass", vec![Substring::Any(b"user".to_vec())]),
        eq(
            "objectCategory",
            b"CN=Person,CN=Schema,CN=Configuration,DC=example,DC=test",
        ),
        eq("member", b"not a dn"),
        present("memberOf"),
        eq("memberOf", b"cn=staff,ou=Staff,dc=example,dc=test"),
        Filter::ExtensibleMatch(MatchingRuleAssertion {
            matching_rule: Some("1.2.840.113556.1.4.803".to_owned()),
            r#type: Some("userAccountControl".to_owned()),
            match_value: b"2".to_vec(),
            dn_attributes: false,
        }),
        // No type: Undefined ([MS-ADTS] 3.1.1.3.1.3.1).
        Filter::ExtensibleMatch(MatchingRuleAssertion {
            matching_rule: Some("2.5.13.2".to_owned()),
            r#type: None,
            match_value: b"x".to_vec(),
            dn_attributes: false,
        }),
        Filter::Unrecognized { tag_number: 12 },
    ] {
        assert_eq!(staff_matching(&r, undefined.clone()), none, "{undefined:?}");
        assert_eq!(
            staff_matching(&r, not(undefined.clone())),
            none,
            "not {undefined:?}"
        );
        assert_eq!(
            staff_matching(&r, Filter::Or(vec![undefined.clone(), eq("cn", b"alice")])),
            vec!["alice".to_owned()],
            "or {undefined:?}"
        );
    }
}

/// [MS-ADTS] 3.1.1.4.3: an attribute the requester may not read is treated
/// as "does not exist" in the filter — bob's description (a deny object
/// ACE) neither matches nor is present, exactly like carol's absent one.
#[test]
fn an_unreadable_attribute_behaves_as_absent() {
    let d = Dir::standard("unreadable");
    let r = Run::new(&d);
    assert_eq!(
        staff_matching(&r, present("description")),
        vec!["alice".to_owned()]
    );
    assert_eq!(
        staff_matching(
            &r,
            substrings("description", vec![Substring::Initial(b"Secret".to_vec())])
        ),
        Vec::<String>::new()
    );
    let without = staff_matching(&r, not(present("description")));
    assert!(without.contains(&"bob".to_owned()) && without.contains(&"carol".to_owned()));
    assert!(!without.contains(&"alice".to_owned()));
    let bob = r.search(request(
        "cn=bob,ou=Staff,dc=example,dc=test",
        Scope::BaseObject,
        present("objectClass"),
        &["description", "cn"],
    ));
    assert_eq!(values(bob.only(), "description"), None);
    assert!(values(bob.only(), "cn").is_some());
}

/// docs/49 §6.1 item 3: the unique-index fast path returns exactly the
/// entries the full walk returns — for the unique attributes, in every
/// scope, inside and outside the scope, and for an object in an invisible
/// subtree.
#[test]
fn the_unique_fast_path_returns_the_slow_path_result() {
    let d = Dir::standard("fast-path");
    let fast = Run::new(&d);
    let mut slow = Run::new(&d);
    let mut limits = SearchLimits::PHASE1;
    limits.unique_index = false;
    slow.engine = engine().with_limits(limits);
    let alice_sid = sid_of(ALICE).encode();
    let filters = [
        eq("sAMAccountName", b"bob"),
        eq("sAMAccountName", b"hiddenuser"),
        eq("sAMAccountName", b"nobody"),
        eq("userPrincipalName", b"ALICE@EXAMPLE.TEST"),
        eq("servicePrincipalName", b"host/ws01.example.test"),
        Filter::And(vec![
            eq("objectSid", &alice_sid),
            eq("objectClass", b"user"),
        ]),
        Filter::And(vec![
            eq("objectSid", &alice_sid),
            eq("objectClass", b"group"),
        ]),
        eq("sAMAccountName", "b\u{f6}b".as_bytes()),
    ];
    let bases = [
        (NC_DN, Scope::WholeSubtree),
        (STAFF_DN, Scope::SingleLevel),
        (STAFF_DN, Scope::WholeSubtree),
        ("cn=bob,ou=Staff,dc=example,dc=test", Scope::BaseObject),
        ("ou=Bulk,dc=example,dc=test", Scope::WholeSubtree),
        (NC_DN, Scope::SingleLevel),
    ];
    let mut matched = 0usize;
    for filter in &filters {
        for (base, scope) in bases {
            let a = fast.search(request(base, scope, filter.clone(), &["*"]));
            let b = slow.search(request(base, scope, filter.clone(), &["*"]));
            assert_eq!(a.code, b.code, "{base} {scope:?} {filter:?}");
            assert_eq!(a.entries, b.entries, "{base} {scope:?} {filter:?}");
            matched += a.entries.len();
            assert!(
                a.outcome
                    .audit
                    .search
                    .as_ref()
                    .expect("facts")
                    .candidates_visited
                    <= 1
            );
        }
    }
    assert!(matched >= 8, "{matched}");
}

/// R49-13 / A-48 ([MS-ADTS] 5.1.3.3.6): the hidden OU and its children are
/// never returned; a base in the invisible subtree is noSuchObject, with
/// exactly the octets of a base that does not exist.
#[test]
fn an_invisible_base_is_identical_to_a_nonexistent_one() {
    let d = Dir::standard("invisible");
    let r = Run::new(&d);
    let hidden = "ou=Hidden,ou=Vault,dc=example,dc=test";
    for scope in [Scope::BaseObject, Scope::SingleLevel, Scope::WholeSubtree] {
        let invisible = r.search(request(hidden, scope, present("objectClass"), &[]));
        let missing = r.search(request(
            "ou=Missing,ou=Vault,dc=example,dc=test",
            scope,
            present("objectClass"),
            &[],
        ));
        assert_eq!(invisible.code, ResultCode::NoSuchObject);
        assert_eq!(invisible.outcome.responses, missing.outcome.responses);
        assert_eq!(invisible.outcome.audit.reason, AuditReason::BaseNotVisible);
        assert_eq!(missing.outcome.audit.reason, AuditReason::BaseNotFound);
    }
    let user = r.search(request(
        "cn=hiddenuser,ou=Hidden,ou=Vault,dc=example,dc=test",
        Scope::BaseObject,
        present("objectClass"),
        &[],
    ));
    assert_eq!(user.code, ResultCode::NoSuchObject);
    let hex: String = guid(HIDDEN_USER)
        .to_packet()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let by_guid = r.search(request(
        &format!("<GUID={hex}>"),
        Scope::BaseObject,
        present("objectClass"),
        &[],
    ));
    assert_eq!(by_guid.code, ResultCode::NoSuchObject);
    // ou=Vault itself is visible and readable, but not listable: its
    // children are not enumerated.
    let vault = r.search(request(
        "ou=Vault,dc=example,dc=test",
        Scope::SingleLevel,
        present("objectClass"),
        &[],
    ));
    assert_eq!(vault.code, ResultCode::Success);
    assert!(vault.entries.is_empty());
    let sub = r.search(request(
        "ou=Vault,dc=example,dc=test",
        Scope::WholeSubtree,
        present("objectClass"),
        &["1.1"],
    ));
    assert_eq!(sub.names(), ["ou=Vault,dc=example,dc=test"]);
}

/// R49-9; [MS-ADTS] 3.1.1.4.4 ("Access is never granted"); docs/49 §6.5:
/// unicodePwd (Secret) and nTSecurityDescriptor are never returned — not
/// with "*", not when named, not on alice whose descriptor grants
/// GENERIC_ALL — and "do not exist" in a filter.
#[test]
fn secret_attributes_and_the_descriptor_are_never_returned() {
    let d = Dir::standard("never");
    let r = Run::new(&d);
    for selection in [
        &["*"][..],
        &["unicodePwd", "nTSecurityDescriptor"],
        &[
            "*",
            "unicodePwd",
            "ntsecuritydescriptor",
            "supplementalCredentials",
        ],
    ] {
        let got = r.search(request(
            "cn=alice,ou=Staff,dc=example,dc=test",
            Scope::BaseObject,
            present("objectClass"),
            selection,
        ));
        let names: Vec<&str> = got
            .only()
            .attributes
            .iter()
            .map(|a| a.r#type.as_str())
            .collect();
        for never in [
            "unicodePwd",
            "nTSecurityDescriptor",
            "supplementalCredentials",
            "objectCategory",
        ] {
            assert!(!names.contains(&never), "{selection:?}: {names:?}");
        }
    }
    assert!(staff_matching(&r, present("nTSecurityDescriptor")).is_empty());
    assert!(staff_matching(&r, present("unicodePwd")).is_empty());
    assert_eq!(staff_matching(&r, not(present("unicodePwd"))).len(), 6);
}

/// docs/49 §6.4, §6.5: memberOf is computed from the back links and lists
/// only the groups the requester can see — alice is a direct member of
/// staff and of hiddengroup (invisible); "*" does not return it (Q-168
/// item 1).
#[test]
fn member_of_hides_invisible_groups() {
    let d = Dir::standard("member-of");
    let r = Run::new(&d);
    let alice = "cn=alice,ou=Staff,dc=example,dc=test";
    let got = r.search(request(
        alice,
        Scope::BaseObject,
        present("objectClass"),
        &["memberOf"],
    ));
    assert_eq!(
        values(got.only(), "memberOf"),
        Some(&[b"cn=staff,ou=Staff,dc=example,dc=test".to_vec()][..])
    );
    let star = r.search(request(
        alice,
        Scope::BaseObject,
        present("objectClass"),
        &["*"],
    ));
    assert_eq!(values(star.only(), "memberOf"), None);
    let allstaff = r.search(request(
        "cn=allstaff,ou=Staff,dc=example,dc=test",
        Scope::BaseObject,
        present("objectClass"),
        &["member"],
    ));
    assert_eq!(
        values(allstaff.only(), "member"),
        Some(&[b"cn=staff,ou=Staff,dc=example,dc=test".to_vec()][..])
    );
    // The hidden group's members are not even reachable: it is invisible.
    let hidden_group = r.search(request(
        "cn=hiddengroup,ou=Hidden,ou=Vault,dc=example,dc=test",
        Scope::BaseObject,
        present("objectClass"),
        &["member"],
    ));
    assert_eq!(hidden_group.code, ResultCode::NoSuchObject);
}

/// The LDAP representation of each phase-1 syntax ([MS-ADTS] 3.1.1.2.2.2
/// via RFC 4517; crate::search::syntax table): Integer and LargeInteger as
/// signed decimals (RFC 4517 §3.3.16), Generalized Time as
/// `YYYYMMDDHHMMSS.0Z` ([MS-DRSR] 5.16.3.9), String(Sid) as the binary SID
/// ([MS-ADTS] 3.1.1.2.2.2.7), String(Octet) objectGUID as the 16 octets,
/// String(Unicode) as UTF-8, Object(DS-DN) as the RFC 4514 DN,
/// String(Object-Identifier) objectClass as lDAPDisplayNames top first;
/// instanceType 4 / 5 (docs/46 §5.4); typesOnly without values (RFC 4511
/// §4.5.1.6).
#[test]
fn value_representations() {
    let d = Dir::standard("values");
    let r = Run::new(&d);
    let alice = r.search(request(
        "cn=alice,ou=Staff,dc=example,dc=test",
        Scope::BaseObject,
        present("objectClass"),
        &[
            "objectClass",
            "objectGUID",
            "objectSid",
            "name",
            "distinguishedName",
            "instanceType",
            "userAccountControl",
            "pwdLastSet",
            "whenCreated",
            "description",
            "sAMAccountName",
            "userPrincipalName",
        ],
    ));
    let e = alice.only();
    let one = |name: &str| values(e, name).expect(name).to_vec();
    assert_eq!(
        one("objectClass"),
        [
            b"top".to_vec(),
            b"person".to_vec(),
            b"organizationalPerson".to_vec(),
            b"user".to_vec()
        ]
    );
    assert_eq!(one("objectGUID"), [guid(ALICE).to_packet().to_vec()]);
    assert_eq!(one("objectSid"), [sid_of(ALICE).encode()]);
    assert_eq!(one("name"), [b"alice".to_vec()]);
    assert_eq!(
        one("distinguishedName"),
        [b"cn=alice,ou=Staff,dc=example,dc=test".to_vec()]
    );
    assert_eq!(one("instanceType"), [b"4".to_vec()]);
    assert_eq!(one("userAccountControl"), [b"512".to_vec()]);
    assert_eq!(one("pwdLastSet"), [b"134383536000000000".to_vec()]);
    assert_eq!(one("whenCreated"), [b"20261101000000.0Z".to_vec()]);
    assert_eq!(one("description"), [b"Team lead".to_vec()]);
    assert_eq!(one("sAMAccountName"), [b"alice".to_vec()]);
    assert_eq!(one("userPrincipalName"), [b"alice@example.test".to_vec()]);
    // Attributes in ascending ATTRTYP order, objectClass (0) first.
    assert_eq!(e.attributes[0].r#type, "objectClass");

    let staff = r.search(request(
        "cn=staff,ou=Staff,dc=example,dc=test",
        Scope::BaseObject,
        present("objectClass"),
        &["groupType"],
    ));
    assert_eq!(
        values(staff.only(), "groupType"),
        Some(&[b"-2147483646".to_vec()][..])
    );
    let root = r.search(request(
        NC_DN,
        Scope::BaseObject,
        present("objectClass"),
        &["instanceType", "objectSid"],
    ));
    assert_eq!(
        values(root.only(), "instanceType"),
        Some(&[b"5".to_vec()][..])
    );
    assert_eq!(
        values(root.only(), "objectSid"),
        Some(&[domain_sid().encode()][..])
    );

    let mut types_only = request(
        "cn=alice,ou=Staff,dc=example,dc=test",
        Scope::BaseObject,
        present("objectClass"),
        &["*"],
    );
    types_only.types_only = true;
    let got = r.search(types_only);
    assert!(got.only().attributes.len() > 5);
    assert!(got.only().attributes.iter().all(|a| a.vals.is_empty()));
}

/// RFC 4511 §4.5.1.4 (sizeLimit → sizeLimitExceeded, the entries returned
/// standing); [MS-ADTS] 3.1.1.3.4.6 / docs/49 §6.1 item 7 (the server's page
/// bound and the PDP's MaxPageSize → adminLimitExceeded); docs/49 §6.1 item
/// 3 (the visit budget → adminLimitExceeded); the response octet bound.
#[test]
fn size_page_visit_and_octet_limits() {
    let d = Dir::standard("limits");
    let r = Run::new(&d);
    let mut sized = request(
        STAFF_DN,
        Scope::SingleLevel,
        present("objectClass"),
        &["1.1"],
    );
    sized.size_limit = 2;
    let got = r.search(sized.clone());
    assert_eq!(got.code, ResultCode::SizeLimitExceeded);
    assert_eq!(got.entries.len(), 2);
    assert_eq!(got.outcome.audit.reason, AuditReason::SizeLimitExceeded);
    sized.size_limit = 6;
    assert_eq!(r.search(sized.clone()).code, ResultCode::Success);

    let mut capped = Run::new(&d);
    capped.policy = policy(vec![Obligation::Constrain(Constraint::MaxPageSize(3))]);
    let got = capped.search(request(
        STAFF_DN,
        Scope::SingleLevel,
        present("objectClass"),
        &["1.1"],
    ));
    assert_eq!(got.code, ResultCode::AdminLimitExceeded);
    assert_eq!(got.entries.len(), 3);
    assert_eq!(got.outcome.audit.reason, AuditReason::PageLimitExceeded);
    // The client's smaller limit names the client's code.
    sized.size_limit = 2;
    assert_eq!(capped.search(sized).code, ResultCode::SizeLimitExceeded);

    let mut budget = Run::new(&d);
    let mut limits = SearchLimits::PHASE1;
    limits.visit_budget = 5;
    budget.engine = engine().with_limits(limits);
    let got = budget.search(request(
        NC_DN,
        Scope::WholeSubtree,
        present("objectClass"),
        &["1.1"],
    ));
    assert_eq!(got.code, ResultCode::AdminLimitExceeded);
    assert_eq!(got.entries.len(), 5);
    assert_eq!(got.outcome.audit.reason, AuditReason::VisitBudgetExceeded);
    assert_eq!(
        got.outcome
            .audit
            .search
            .as_ref()
            .expect("facts")
            .candidates_visited,
        5
    );
    // The same budget with a filter that matches little still stops.
    let got = budget.search(request(
        NC_DN,
        Scope::WholeSubtree,
        eq("cn", b"carol"),
        &["1.1"],
    ));
    assert_eq!(got.code, ResultCode::AdminLimitExceeded);

    let mut octets = Run::new(&d);
    let mut limits = SearchLimits::PHASE1;
    limits.max_response_octets = 400;
    octets.engine = engine().with_limits(limits);
    let got = octets.search(request(
        STAFF_DN,
        Scope::SingleLevel,
        present("objectClass"),
        &["*"],
    ));
    assert_eq!(got.code, ResultCode::AdminLimitExceeded);
    assert_eq!(got.outcome.audit.reason, AuditReason::ResponseTooLarge);
    let sent: usize = got
        .outcome
        .responses
        .iter()
        .rev()
        .skip(1)
        .map(Vec::len)
        .sum();
    assert!(sent <= 400);
}

/// RFC 4511 §4.5.1.5 (timeLimit, in seconds) and [MS-ADTS] 3.1.1.3.4.6
/// (MaxQueryDuration → timeLimitExceeded), measured on the caller's clock
/// (docs/49 §11: the engine reads none): a clock that advances one second
/// per reading stops a search with timeLimit 3 after three visits.
#[test]
fn time_limits_use_the_callers_clock() {
    let d = Dir::standard("time");
    let mut r = Run::new(&d);
    r.clock = StepClock {
        step: 1,
        reads: Cell::new(0),
    };
    let mut timed = request(NC_DN, Scope::WholeSubtree, present("objectClass"), &["1.1"]);
    timed.time_limit = 3;
    let got = r.search(timed);
    assert_eq!(got.code, ResultCode::TimeLimitExceeded);
    assert_eq!(got.outcome.audit.reason, AuditReason::TimeLimitExceeded);
    // Readings 0, 1, 2, 3 s pass; the fifth (4 s) exceeds 3 s.
    assert_eq!(got.entries.len(), 4);

    let mut server = Run::new(&d);
    server.clock = StepClock {
        step: 30,
        reads: Cell::new(0),
    };
    let got = server.search(request(
        NC_DN,
        Scope::WholeSubtree,
        present("objectClass"),
        &["1.1"],
    ));
    assert_eq!(got.code, ResultCode::TimeLimitExceeded);
    assert_eq!(got.outcome.audit.reason, AuditReason::QueryDurationExceeded);
    // 0, 30, 60 s pass (the limit is 60 s); 90 s does not.
    assert_eq!(got.entries.len(), 3);

    // A fixed clock never stops a search.
    let fixed = Run::new(&d);
    let mut timed = request(NC_DN, Scope::WholeSubtree, present("objectClass"), &["1.1"]);
    timed.time_limit = 1;
    assert_eq!(fixed.search(timed).code, ResultCode::Success);
}

/// docs/49 §10.1 (R49-14): one audit event per search operation, with the
/// counts and the filter's attribute names — never an assertion value, a
/// returned value or the client's DN string.
#[test]
fn one_audit_event_with_counts_and_no_values() {
    let d = Dir::standard("audit");
    let r = Run::new(&d);
    let marker = b"MARKER-VALUE-5e1a";
    let got = r.search(request(
        "OU=Staff,DC=EXAMPLE,DC=TEST",
        Scope::SingleLevel,
        Filter::Or(vec![
            eq("sAMAccountName", marker),
            present("cn"),
            eq("shoeSize", marker),
        ]),
        &["description"],
    ));
    assert_eq!(got.code, ResultCode::Success);
    let audit = &got.outcome.audit;
    let facts = audit.search.as_ref().expect("search facts");
    assert_eq!(facts.entries_returned, 6);
    assert_eq!(facts.candidates_visited, 6);
    assert_eq!(facts.pruned_subtrees, 0);
    assert_eq!(facts.filter_attrs, ["cn", "sAMAccountName"]);
    assert_eq!(audit.target, Some(AuditTarget::DirObject(guid(STAFF_OU))));
    assert_eq!(audit.reason, AuditReason::SearchCompleted);
    assert_eq!(audit.result_code, Some(ResultCode::Success));
    let debug = format!("{audit:?}");
    for leaked in ["MARKER", "Team lead", "OU=Staff", "shoeSize"] {
        assert!(!debug.contains(leaked), "{leaked} in {debug}");
    }
}

/// Q-169 item 3 (an anonymous operation other than the rootDSE →
/// operationsError, "not dependent on the DN") and docs/49 §6.1: the refusal
/// comes before the base is looked at, so an existing and a nonexistent
/// base give the same octets — no existence oracle.
#[test]
fn an_anonymous_search_is_operations_error_whatever_the_base() {
    let d = Dir::standard("anonymous");
    let r = Run::new(&d);
    let mut results = Vec::new();
    for base in [
        NC_DN,
        STAFF_DN,
        "ou=Missing,dc=example,dc=test",
        "ou=Hidden,ou=Vault,dc=example,dc=test",
    ] {
        let mut session = Session::new(3, Listener::Ldaps);
        let got = r.as_session(
            &mut session,
            request(base, Scope::WholeSubtree, present("objectClass"), &[]),
        );
        assert_eq!(got.code, ResultCode::OperationsError, "{base}");
        assert!(got.entries.is_empty());
        assert_eq!(got.outcome.audit.target, None);
        results.push(got.outcome.responses);
    }
    assert!(results.windows(2).all(|w| w[0] == w[1]));
}

/// A-53 (one source of truth): an engine configured with another naming
/// context refuses to search the view (other), and a view of this naming
/// context serves the rootDSE's DN unchanged.
#[test]
fn the_naming_context_is_one_source_of_truth() {
    let d = Dir::standard("one-nc");
    let mut r = Run::new(&d);
    r.engine = engine_for(NamingContext::new(&["example", "org"]).expect("nc"));
    let got = r.search(request(
        NC_DN,
        Scope::BaseObject,
        present("objectClass"),
        &[],
    ));
    assert_eq!(got.code, ResultCode::Other);
    assert_eq!(got.outcome.audit.reason, AuditReason::NamingContextMismatch);
    assert_eq!(
        crate::config::naming_context_string(&naming_context()).as_deref(),
        Some(NC_DN)
    );
}

/// RFC 4511 §4.5.1.8: "1.1" alone returns no attribute; unrecognised
/// descriptions are ignored; each attribute once; "*" plus a named
/// operational attribute returns both.
#[test]
fn attribute_selection() {
    let d = Dir::standard("selection");
    let r = Run::new(&d);
    let alice = "cn=alice,ou=Staff,dc=example,dc=test";
    let names = |sel: &[&str]| -> BTreeSet<String> {
        r.search(request(
            alice,
            Scope::BaseObject,
            present("objectClass"),
            sel,
        ))
        .only()
        .attributes
        .iter()
        .map(|a| a.r#type.clone())
        .collect()
    };
    assert!(names(&["1.1"]).is_empty());
    assert_eq!(
        names(&["CN", "cn", "noSuchThing", "cn;range=0-1"]),
        ["cn".to_owned()].into()
    );
    let star = names(&["*"]);
    assert!(star.contains("cn") && star.contains("objectClass") && star.contains("whenCreated"));
    assert!(!star.contains("memberOf"));
    let both = names(&["*", "memberOf"]);
    assert!(both.contains("memberOf") && both.contains("cn"));
    assert_eq!(names(&[]), star);
}
