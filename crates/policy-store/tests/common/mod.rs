//! Shared test data for the policy-store tests: SIDs, a sample policy with
//! every rule type, and a hand-written raw layout (the format of the crate
//! documentation, octet by octet) for files the encoder would refuse to
//! write.
//!
//! Sources: crates/policy-store crate documentation (the format); [MS-DTYP]
//! 2.4.2.2 (SID packets); docs/11 §1, §3 (the rule model); docs/48 §7
//! (mandatory FAST); docs/15 §6, A-51 (anonymous grants). Every value is
//! hand-made for these tests; no vector comes from any other implementation.

#![allow(dead_code)] // each test binary uses a different subset

use dtyp::{Guid, Sid, SECURITY_NT_AUTHORITY};
use pdp::{
    Action, ActionClass, ActionMatch, AnonymousGrant, AuthMatch, ClaimId, ClaimValue, Constraint,
    ContextMatch, ControlRightId, Dn, Effect, Instant, IpScope, KerbResKind, Match, ObjClass,
    Obligation, PolicyScope, PolicyVersion, ResourceMatch, RlKey, Rule, RuleId, ShareId, Spn,
    SubjectMatch, SubtreeBase, Tier, TimeWindow, TransportSec, ZoneId,
};
use policy_store::{DevelopmentPolicy, MandatoryFast, FORMAT, MARKER};

/// S-1-5-21-7-8-9-`rid` ([MS-DTYP] 2.4.2.4 layout; hand-made).
pub fn sid(rid: u32) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 7, 8, 9, rid]).unwrap()
}

/// A hand-made GUID.
pub fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0x00AB,
        data3: 0x00CD,
        data4: [1, 2, 3, 4, 5, 6, 7, 8],
    }
}

pub fn dn(rdns: &[&str]) -> Dn {
    Dn::new(rdns.iter().map(|s| String::from(*s)).collect())
}

/// The bootstrap group of the samples (hand-made RID).
pub fn bootstrap() -> Sid {
    sid(1500)
}

pub fn fast() -> MandatoryFast {
    MandatoryFast {
        bootstrap_group: bootstrap(),
        first_rule_id: RuleId(100),
    }
}

fn rule(id: u32, effect: Effect, when: Match, obligations: Vec<Obligation>) -> Rule {
    Rule {
        id: RuleId(id),
        effect,
        when,
        obligations,
    }
}

fn any_match() -> Match {
    Match {
        action: ActionMatch::Any,
        resource: ResourceMatch::Any,
        subject: SubjectMatch::Any,
        context: ContextMatch::ANY,
        auth: AuthMatch::ANY,
    }
}

/// One rule per variant of every matcher, both effects, every obligation —
/// docs/11 §3 (ActionMatch, ResourceMatch, SubjectMatch, ContextMatch),
/// docs/48 §7.2 (AuthMatch, NotMemberOf), docs/49 §5.2 (RootDse), docs/11 §8
/// (obligations).
pub fn every_rule_type() -> Vec<Rule> {
    let window = TimeWindow::new(Instant(1_700_000_000), Instant(1_800_000_000)).unwrap();
    vec![
        rule(1, Effect::Allow, any_match(), Vec::new()),
        rule(
            2,
            Effect::Deny,
            Match {
                action: ActionMatch::Exact(Action::DirWrite),
                resource: ResourceMatch::DirSubtree {
                    base: SubtreeBase::new(dn(&["ou=Servers", "dc=example", "dc=org"])).unwrap(),
                },
                subject: SubjectMatch::NotMemberOf(sid(512)),
                ..any_match()
            },
            Vec::new(),
        ),
        rule(
            3,
            Effect::Allow,
            Match {
                action: ActionMatch::AnyOf(vec![
                    Action::DirRead,
                    Action::DirWrite,
                    Action::DirAddChild(ObjClass(guid(1))),
                    Action::DirDelete,
                    Action::DirList,
                    Action::DirControlRight(ControlRightId(guid(2))),
                    Action::RpcCall,
                    Action::FileRead,
                    Action::FileWrite,
                    Action::DnsUpdate,
                    Action::DnsXfer,
                    Action::KdcAs,
                    Action::KdcTgs,
                    Action::KdcS4u2Self,
                    Action::KdcS4u2Proxy,
                    Action::PolicyAdmin,
                ]),
                resource: ResourceMatch::RootDse,
                subject: SubjectMatch::Principal(sid(1101)),
                context: ContextMatch {
                    min_transport: TransportSec {
                        encrypted: true,
                        sealed: false,
                        channel_bound: true,
                    },
                    src_net: Some(IpScope::Internal),
                    time_window: Some(window),
                },
                auth: AuthMatch::ARMORED,
            },
            vec![
                Obligation::Audit,
                Obligation::RateLimit(RlKey {
                    principal: sid(1101),
                    class: ActionClass::Kerberos,
                }),
                Obligation::Constrain(Constraint::MaxPageSize(500)),
            ],
        ),
        rule(
            4,
            Effect::Allow,
            Match {
                action: ActionMatch::Class(ActionClass::Rpc),
                resource: ResourceMatch::RpcMethod {
                    iface: guid(3),
                    opnum: Some(7),
                },
                subject: SubjectMatch::MemberOf(sid(513)),
                auth: AuthMatch::UNARMORED,
                ..any_match()
            },
            Vec::new(),
        ),
        rule(
            5,
            Effect::Deny,
            Match {
                action: ActionMatch::Class(ActionClass::File),
                resource: ResourceMatch::RpcMethod {
                    iface: guid(4),
                    opnum: None,
                },
                subject: SubjectMatch::Tier(Tier::Tier2),
                context: ContextMatch {
                    src_net: Some(IpScope::External),
                    ..ContextMatch::ANY
                },
                ..any_match()
            },
            Vec::new(),
        ),
        rule(
            6,
            Effect::Allow,
            Match {
                action: ActionMatch::Class(ActionClass::File),
                resource: ResourceMatch::File {
                    share: ShareId(String::from("SYSVOL")),
                },
                subject: SubjectMatch::Claim(
                    ClaimId(String::from("department")),
                    ClaimValue::Text(String::from("ops")),
                ),
                ..any_match()
            },
            Vec::new(),
        ),
        rule(
            7,
            Effect::Allow,
            Match {
                action: ActionMatch::Class(ActionClass::Dns),
                resource: ResourceMatch::Dns {
                    zone: ZoneId(String::from("example.org")),
                },
                subject: SubjectMatch::Claim(
                    ClaimId(String::from("clearance")),
                    ClaimValue::Integer(-42),
                ),
                ..any_match()
            },
            Vec::new(),
        ),
        rule(
            8,
            Effect::Allow,
            Match {
                action: ActionMatch::Class(ActionClass::Kerberos),
                resource: ResourceMatch::Kerberos {
                    kind: Some(KerbResKind::Service(Spn(String::from(
                        "host/files.example.org",
                    )))),
                },
                subject: SubjectMatch::Claim(
                    ClaimId(String::from("enrolled")),
                    ClaimValue::Boolean(true),
                ),
                ..any_match()
            },
            Vec::new(),
        ),
        rule(
            9,
            Effect::Allow,
            Match {
                action: ActionMatch::Exact(Action::KdcAs),
                resource: ResourceMatch::Kerberos {
                    kind: Some(KerbResKind::Tgt),
                },
                ..any_match()
            },
            Vec::new(),
        ),
        rule(
            10,
            Effect::Deny,
            Match {
                action: ActionMatch::AnyOf(Vec::new()),
                resource: ResourceMatch::Kerberos { kind: None },
                ..any_match()
            },
            Vec::new(),
        ),
        rule(
            11,
            Effect::Deny,
            Match {
                action: ActionMatch::Exact(Action::PolicyAdmin),
                resource: ResourceMatch::Policy {
                    scope: Some(PolicyScope(String::from("tier0"))),
                },
                ..any_match()
            },
            Vec::new(),
        ),
        rule(
            12,
            Effect::Deny,
            Match {
                action: ActionMatch::Exact(Action::PolicyAdmin),
                resource: ResourceMatch::Policy { scope: None },
                ..any_match()
            },
            Vec::new(),
        ),
        // The change-password service's resource kind (docs/53 §5.2, task
        // K5).
        rule(
            13,
            Effect::Deny,
            Match {
                action: ActionMatch::Exact(Action::KdcAs),
                resource: ResourceMatch::Kerberos {
                    kind: Some(KerbResKind::ChangePassword),
                },
                auth: AuthMatch::UNARMORED,
                ..any_match()
            },
            Vec::new(),
        ),
    ]
}

/// The rootDSE read from the internal network — the anonymous allowlist of
/// docs/15 §6 (A-51: Internal only).
pub fn root_dse_grant() -> AnonymousGrant {
    AnonymousGrant::new(
        ActionMatch::Exact(Action::DirRead),
        ResourceMatch::RootDse,
        TransportSec::NONE,
        IpScope::Internal,
    )
    .unwrap()
}

/// A policy with a tier map, the mandatory-FAST entry, every rule type and
/// one anonymous grant.
pub fn sample_policy() -> DevelopmentPolicy {
    DevelopmentPolicy {
        version: PolicyVersion(42),
        principals: [
            (sid(512), Tier::Tier0),
            (sid(1030), Tier::Tier2),
            (sid(1101), Tier::Tier1),
        ]
        .into_iter()
        .collect(),
        subtrees: vec![
            (dn(&["ou=Servers", "dc=example", "dc=org"]), Tier::Tier1),
            (dn(&["ou=Staff", "dc=example", "dc=org"]), Tier::Tier2),
        ],
        mandatory_fast: fast(),
        rules: every_rule_type(),
        anonymous: vec![root_dse_grant()],
    }
}

/// A policy with nothing but the mandatory-FAST entry.
pub fn minimal_policy(version: u64) -> DevelopmentPolicy {
    DevelopmentPolicy {
        version: PolicyVersion(version),
        principals: Default::default(),
        subtrees: Vec::new(),
        mandatory_fast: fast(),
        rules: Vec::new(),
        anonymous: Vec::new(),
    }
}

// ---- the raw layout, octet by octet (crate documentation) -------------------------

/// A raw file writer.
#[derive(Default)]
pub struct Raw(pub Vec<u8>);

impl Raw {
    pub fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
    pub fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn bytes(self, v: &[u8]) -> Self {
        let mut s = self.u32(u32::try_from(v.len()).unwrap());
        s.0.extend_from_slice(v);
        s
    }
    pub fn raw(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
    pub fn dn(self, components: &[&str]) -> Self {
        let mut s = self.u32(u32::try_from(components.len()).unwrap());
        for c in components {
            s = s.bytes(c.as_bytes());
        }
        s
    }
}

/// marker ‖ format ‖ version ‖ principals ‖ subtrees (format 1's layout,
/// with format 2's number), each entry `(sid packet, tier)` / `(dn, tier)`.
pub fn raw_head(principals: &[(Vec<u8>, u8)], subtrees: &[(Vec<&str>, u8)]) -> Raw {
    let mut out = Raw(MARKER.to_vec()).u8(FORMAT).u64(7);
    out = out.u32(u32::try_from(principals.len()).unwrap());
    for (packet, tier) in principals {
        out = out.bytes(packet).u8(*tier);
    }
    out = out.u32(u32::try_from(subtrees.len()).unwrap());
    for (components, tier) in subtrees {
        out = out.dn(components).u8(*tier);
    }
    out
}

/// A whole file: the head, the mandatory-FAST entry (bootstrap packet,
/// first id), then `rules` raw rule encodings and `grants` raw grant
/// encodings.
pub fn raw_file(
    principals: &[(Vec<u8>, u8)],
    subtrees: &[(Vec<&str>, u8)],
    bootstrap_packet: &[u8],
    first_id: u32,
    rules: &[Vec<u8>],
    grants: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = raw_head(principals, subtrees)
        .bytes(bootstrap_packet)
        .u32(first_id)
        .u32(u32::try_from(rules.len()).unwrap());
    for r in rules {
        out = out.raw(r);
    }
    out = out.u32(u32::try_from(grants.len()).unwrap());
    for g in grants {
        out = out.raw(g);
    }
    out.0
}

/// A raw rule: `id`, Allow, ActionMatch::Any, the given raw resource
/// matcher, SubjectMatch::Any, ContextMatch::ANY, AuthMatch::ANY, no
/// obligation.
pub fn raw_rule(id: u32, resource: &[u8]) -> Vec<u8> {
    Raw::default()
        .u32(id)
        .u8(0) // Allow
        .u8(0) // ActionMatch::Any
        .raw(resource)
        .u8(0) // SubjectMatch::Any
        .u8(0)
        .u8(0)
        .u8(0) // min_transport: three false
        .u8(0) // src_net: absent
        .u8(0) // time_window: absent
        .u8(0) // armored: absent
        .u32(0) // no obligation
        .0
}

/// A raw anonymous grant: Exact(DirRead), the given raw resource matcher,
/// TransportSec::NONE, the given network code.
pub fn raw_grant(resource: &[u8], network: u8) -> Vec<u8> {
    Raw::default()
        .u8(1) // ActionMatch::Exact
        .u8(0) // DirRead
        .raw(resource)
        .u8(0)
        .u8(0)
        .u8(0)
        .u8(network)
        .0
}
