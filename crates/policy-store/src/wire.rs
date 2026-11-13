//! Reading and writing each piece of the policy file with ipc's bounded
//! primitives and the closed code tables of [`crate::codes`].
//!
//! The reader checks each value as it reads it — a SID through
//! `dtyp::Sid::decode`, a DN component and a text by their rules, a rule
//! subtree through `pdp::SubtreeBase::new`, a time window through
//! `pdp::TimeWindow::new`, an anonymous grant through
//! `pdp::AnonymousGrant::new` — so a decoded value is always a valid `pdp`
//! value. A content fault is noted in [`Content`] and stops the read (the
//! reader returns a placeholder structure error, which the decoder replaces
//! by the noted fault); the first fault found is the one reported.
//!
//! ```text
//! action_match   := 0 Any | 1 Exact action | 2 AnyOf seq<action, 64> | 3 Class class:u8
//! action         := kind:u8 [‖ guid[16] for DirAddChild / DirControlRight]
//! resource_match := 0 Any | 1 DirSubtree dn | 2 RootDse
//!                 | 3 RpcMethod iface:guid[16] ‖ opnum:Option<u16>
//!                 | 4 File share:text | 5 Dns zone:text
//!                 | 6 Kerberos kind:Option<0 Tgt | 1 Service spn:text>
//!                 | 7 Policy scope:Option<text>
//! subject_match  := 0 Any | 1 Principal sid | 2 MemberOf sid | 3 NotMemberOf sid
//!                 | 4 Tier tier | 5 Claim id:text ‖ value
//! value          := 0 Integer u64 (two's complement) | 1 Text text | 2 Boolean bool
//! context_match  := min_transport ‖ src_net:Option<scope:u8>
//!                 ‖ time_window:Option<not_before:u64 ‖ not_after:u64>
//! min_transport  := encrypted:bool ‖ sealed:bool ‖ channel_bound:bool
//! auth_match     := armored:Option<bool>
//! obligation     := 0 Audit | 1 RateLimit principal:sid ‖ class:u8
//!                 | 2 Constrain (0 MaxPageSize u32)
//! text           := bytes<1024>                   ; printable ASCII, not empty
//! ```
//!
//! Spec: docs/50 §3.3; docs/11 §1, §1b, §3, §8; docs/48 §7.2 (`AuthMatch`,
//! `NotMemberOf`); docs/49 §5.2 (`RootDse`); A-48; A-51.

use crate::codes::{self, action_match, claim_value, constraint, kerberos_kind, obligation};
use crate::codes::{resource_match, subject_match};
use crate::policy::{
    valid_component, valid_text, PolicyError, MAX_ACTIONS, MAX_COMPONENT, MAX_DN_COMPONENTS,
    MAX_OBLIGATIONS, MAX_SID, MAX_TEXT,
};
use core::cell::Cell;
use dtyp::{Guid, Sid};
use ipc::{Reader, Writer};
use pdp::{
    Action, ActionMatch, AnonymousGrant, AuthMatch, ClaimId, ClaimValue, Constraint, ContextMatch,
    ControlRightId, Dn, Instant, KerbResKind, Match, ObjClass, Obligation, PolicyScope,
    ResourceMatch, RlKey, Rule, RuleId, ShareId, Spn, SubjectMatch, SubtreeBase, TimeWindow,
    TransportSec, ZoneId,
};

/// The first content fault met while reading.
/// Spec: crate documentation ("anything else refuses the whole file").
#[derive(Debug, Default)]
pub(crate) struct Content(Cell<Option<PolicyError>>);

impl Content {
    pub(crate) fn new() -> Content {
        Content::default()
    }

    /// Note `error` (the first one is kept) and stop the read.
    pub(crate) fn refuse<T>(&self, error: PolicyError) -> ipc::Result<T> {
        if self.0.get().is_none() {
            self.0.set(Some(error));
        }
        Err(ipc::Error::UnknownCode)
    }

    /// The noted fault, if any.
    pub(crate) fn take(&self) -> Option<PolicyError> {
        self.0.take()
    }
}

// ---- SIDs, DNs, texts ------------------------------------------------------------

/// A SID packet, decoded strictly ([MS-DTYP] 2.4.2.2); a fault is `error`.
pub(crate) fn read_sid(r: &mut Reader<'_>, c: &Content, error: PolicyError) -> ipc::Result<Sid> {
    let packet = r.read_bytes(MAX_SID)?;
    match Sid::decode(packet) {
        Ok(sid) => Ok(sid),
        Err(_) => c.refuse(error),
    }
}

/// Spec: [MS-DTYP] 2.4.2.2.
pub(crate) fn write_sid(w: &mut Writer, sid: &Sid) -> ipc::Result<()> {
    w.write_bytes(&sid.encode(), MAX_SID)
}

/// A DN, leaf first; each component must be printable `att=value`, else
/// `error`. An empty DN is read (the caller's rule decides).
pub(crate) fn read_dn(r: &mut Reader<'_>, c: &Content, error: PolicyError) -> ipc::Result<Dn> {
    let rdns = r.read_seq(MAX_DN_COMPONENTS, |r| {
        let octets = r.read_bytes(MAX_COMPONENT)?;
        if !valid_component(octets) {
            return c.refuse(error);
        }
        match core::str::from_utf8(octets) {
            Ok(text) => Ok(text.to_owned()),
            Err(_) => c.refuse(error),
        }
    })?;
    Ok(Dn::new(rdns))
}

/// Spec: format 1.
pub(crate) fn write_dn(w: &mut Writer, dn: &Dn) -> ipc::Result<()> {
    w.write_seq(dn.rdns(), MAX_DN_COMPONENTS, |w, component| {
        w.write_bytes(component.as_bytes(), MAX_COMPONENT)
    })
}

/// A text field (1 ..= 1024 printable ASCII octets), else `RuleValue`.
fn read_text(r: &mut Reader<'_>, c: &Content) -> ipc::Result<String> {
    let octets = r.read_bytes(MAX_TEXT)?;
    if !valid_text(octets) {
        return c.refuse(PolicyError::RuleValue);
    }
    match core::str::from_utf8(octets) {
        Ok(text) => Ok(text.to_owned()),
        Err(_) => c.refuse(PolicyError::RuleValue),
    }
}

fn write_text(w: &mut Writer, text: &str) -> ipc::Result<()> {
    w.write_bytes(text.as_bytes(), MAX_TEXT)
}

fn read_guid(r: &mut Reader<'_>) -> ipc::Result<Guid> {
    r.read_array::<{ dtyp::GUID_PACKET_LEN }>()
        .map(|packet| Guid::from_packet(&packet))
}

fn write_guid(w: &mut Writer, guid: &Guid) -> ipc::Result<()> {
    w.write_array(&guid.to_packet())
}

// ---- actions ------------------------------------------------------------------

/// Spec: docs/11 §1; crates/pdp model.rs (`Action`).
fn read_action(r: &mut Reader<'_>) -> ipc::Result<Action> {
    match r.read_u8()? {
        codes::ACTION_DIR_ADD_CHILD => read_guid(r).map(|g| Action::DirAddChild(ObjClass(g))),
        codes::ACTION_DIR_CONTROL_RIGHT => {
            read_guid(r).map(|g| Action::DirControlRight(ControlRightId(g)))
        }
        code => codes::simple_action_from(code).ok_or(ipc::Error::UnknownCode),
    }
}

fn write_action(w: &mut Writer, action: &Action) -> ipc::Result<()> {
    w.write_enum(codes::action(action))?;
    match action {
        Action::DirAddChild(class) => write_guid(w, &class.0),
        Action::DirControlRight(right) => write_guid(w, &right.0),
        _ => Ok(()),
    }
}

/// Spec: docs/11 §3 (`ActionMatch`).
fn read_action_match(r: &mut Reader<'_>) -> ipc::Result<ActionMatch> {
    match r.read_u8()? {
        action_match::ANY => Ok(ActionMatch::Any),
        action_match::EXACT => read_action(r).map(ActionMatch::Exact),
        action_match::ANY_OF => r.read_seq(MAX_ACTIONS, read_action).map(ActionMatch::AnyOf),
        action_match::CLASS => r
            .read_enum(codes::action_class_from)
            .map(ActionMatch::Class),
        _ => Err(ipc::Error::UnknownCode),
    }
}

fn write_action_match(w: &mut Writer, matcher: &ActionMatch) -> ipc::Result<()> {
    match matcher {
        ActionMatch::Any => w.write_enum(action_match::ANY),
        ActionMatch::Exact(action) => {
            w.write_enum(action_match::EXACT)?;
            write_action(w, action)
        }
        ActionMatch::AnyOf(actions) => {
            w.write_enum(action_match::ANY_OF)?;
            w.write_seq(actions, MAX_ACTIONS, write_action)
        }
        ActionMatch::Class(class) => {
            w.write_enum(action_match::CLASS)?;
            w.write_enum(codes::action_class(*class))
        }
    }
}

// ---- resources ----------------------------------------------------------------

/// Spec: docs/11 §3 (`ResourceMatch`); A-48 (`SubtreeBase`, `RootDse`).
fn read_resource_match(r: &mut Reader<'_>, c: &Content) -> ipc::Result<ResourceMatch> {
    match r.read_u8()? {
        resource_match::ANY => Ok(ResourceMatch::Any),
        resource_match::DIR_SUBTREE => {
            let dn = read_dn(r, c, PolicyError::RuleValue)?;
            // A-48 / A-51: the empty base would contain every object; the
            // refusal fails the whole load (crates/pdp policy.rs).
            match SubtreeBase::new(dn) {
                Ok(base) => Ok(ResourceMatch::DirSubtree { base }),
                Err(error) => c.refuse(PolicyError::Rule(error)),
            }
        }
        resource_match::ROOT_DSE => Ok(ResourceMatch::RootDse),
        resource_match::RPC_METHOD => {
            let iface = read_guid(r)?;
            let opnum = r.read_option(|r| r.read_u16())?;
            Ok(ResourceMatch::RpcMethod { iface, opnum })
        }
        resource_match::FILE => Ok(ResourceMatch::File {
            share: ShareId(read_text(r, c)?),
        }),
        resource_match::DNS => Ok(ResourceMatch::Dns {
            zone: ZoneId(read_text(r, c)?),
        }),
        resource_match::KERBEROS => {
            let kind = r.read_option(|r| match r.read_u8()? {
                kerberos_kind::TGT => Ok(KerbResKind::Tgt),
                kerberos_kind::SERVICE => read_text(r, c).map(|spn| KerbResKind::Service(Spn(spn))),
                _ => Err(ipc::Error::UnknownCode),
            })?;
            Ok(ResourceMatch::Kerberos { kind })
        }
        resource_match::POLICY => {
            let scope = r.read_option(|r| read_text(r, c).map(PolicyScope))?;
            Ok(ResourceMatch::Policy { scope })
        }
        _ => Err(ipc::Error::UnknownCode),
    }
}

fn write_resource_match(w: &mut Writer, matcher: &ResourceMatch) -> ipc::Result<()> {
    match matcher {
        ResourceMatch::Any => w.write_enum(resource_match::ANY),
        ResourceMatch::DirSubtree { base } => {
            w.write_enum(resource_match::DIR_SUBTREE)?;
            write_dn(w, base.dn())
        }
        ResourceMatch::RootDse => w.write_enum(resource_match::ROOT_DSE),
        ResourceMatch::RpcMethod { iface, opnum } => {
            w.write_enum(resource_match::RPC_METHOD)?;
            write_guid(w, iface)?;
            w.write_option(opnum.as_ref(), |w, opnum| w.write_u16(*opnum))
        }
        ResourceMatch::File { share } => {
            w.write_enum(resource_match::FILE)?;
            write_text(w, &share.0)
        }
        ResourceMatch::Dns { zone } => {
            w.write_enum(resource_match::DNS)?;
            write_text(w, &zone.0)
        }
        ResourceMatch::Kerberos { kind } => {
            w.write_enum(resource_match::KERBEROS)?;
            w.write_option(kind.as_ref(), |w, kind| match kind {
                KerbResKind::Tgt => w.write_enum(kerberos_kind::TGT),
                KerbResKind::Service(spn) => {
                    w.write_enum(kerberos_kind::SERVICE)?;
                    write_text(w, &spn.0)
                }
            })
        }
        ResourceMatch::Policy { scope } => {
            w.write_enum(resource_match::POLICY)?;
            w.write_option(scope.as_ref(), |w, scope| write_text(w, &scope.0))
        }
    }
}

// ---- subjects -----------------------------------------------------------------

/// Spec: docs/11 §3 (`SubjectMatch`); docs/48 §7.2 (`NotMemberOf`).
fn read_subject_match(r: &mut Reader<'_>, c: &Content) -> ipc::Result<SubjectMatch> {
    match r.read_u8()? {
        subject_match::ANY => Ok(SubjectMatch::Any),
        subject_match::PRINCIPAL => {
            read_sid(r, c, PolicyError::RuleValue).map(SubjectMatch::Principal)
        }
        subject_match::MEMBER_OF => {
            read_sid(r, c, PolicyError::RuleValue).map(SubjectMatch::MemberOf)
        }
        subject_match::NOT_MEMBER_OF => {
            read_sid(r, c, PolicyError::RuleValue).map(SubjectMatch::NotMemberOf)
        }
        subject_match::TIER => r.read_enum(codes::tier_from).map(SubjectMatch::Tier),
        subject_match::CLAIM => {
            let id = ClaimId(read_text(r, c)?);
            let value = match r.read_u8()? {
                claim_value::INTEGER => {
                    ClaimValue::Integer(i64::from_be_bytes(r.read_u64()?.to_be_bytes()))
                }
                claim_value::TEXT => ClaimValue::Text(read_text(r, c)?),
                claim_value::BOOLEAN => ClaimValue::Boolean(r.read_bool()?),
                _ => return Err(ipc::Error::UnknownCode),
            };
            Ok(SubjectMatch::Claim(id, value))
        }
        _ => Err(ipc::Error::UnknownCode),
    }
}

fn write_subject_match(w: &mut Writer, matcher: &SubjectMatch) -> ipc::Result<()> {
    match matcher {
        SubjectMatch::Any => w.write_enum(subject_match::ANY),
        SubjectMatch::Principal(sid) => {
            w.write_enum(subject_match::PRINCIPAL)?;
            write_sid(w, sid)
        }
        SubjectMatch::MemberOf(sid) => {
            w.write_enum(subject_match::MEMBER_OF)?;
            write_sid(w, sid)
        }
        SubjectMatch::NotMemberOf(sid) => {
            w.write_enum(subject_match::NOT_MEMBER_OF)?;
            write_sid(w, sid)
        }
        SubjectMatch::Tier(tier) => {
            w.write_enum(subject_match::TIER)?;
            w.write_enum(codes::tier(*tier))
        }
        SubjectMatch::Claim(id, value) => {
            w.write_enum(subject_match::CLAIM)?;
            write_text(w, &id.0)?;
            match value {
                ClaimValue::Integer(n) => {
                    w.write_enum(claim_value::INTEGER)?;
                    w.write_u64(u64::from_be_bytes(n.to_be_bytes()))
                }
                ClaimValue::Text(text) => {
                    w.write_enum(claim_value::TEXT)?;
                    write_text(w, text)
                }
                ClaimValue::Boolean(b) => {
                    w.write_enum(claim_value::BOOLEAN)?;
                    w.write_bool(*b)
                }
            }
        }
    }
}

// ---- context and authentication -------------------------------------------------

/// Spec: docs/11 §1 (`TransportSec { encrypted, sealed, channel_bound }`).
fn read_transport_sec(r: &mut Reader<'_>) -> ipc::Result<TransportSec> {
    Ok(TransportSec {
        encrypted: r.read_bool()?,
        sealed: r.read_bool()?,
        channel_bound: r.read_bool()?,
    })
}

fn write_transport_sec(w: &mut Writer, sec: &TransportSec) -> ipc::Result<()> {
    w.write_bool(sec.encrypted)?;
    w.write_bool(sec.sealed)?;
    w.write_bool(sec.channel_bound)
}

/// Spec: docs/11 §3 (`ContextMatch`), §10 P9 (`TimeWindow`).
fn read_context_match(r: &mut Reader<'_>, c: &Content) -> ipc::Result<ContextMatch> {
    let min_transport = read_transport_sec(r)?;
    let src_net = r.read_option(|r| r.read_enum(codes::ip_scope_from))?;
    let window = r.read_option(|r| Ok((r.read_u64()?, r.read_u64()?)))?;
    let time_window = match window {
        None => None,
        Some((not_before, not_after)) => {
            match TimeWindow::new(Instant(not_before), Instant(not_after)) {
                Some(window) => Some(window),
                None => return c.refuse(PolicyError::RuleValue),
            }
        }
    };
    Ok(ContextMatch {
        min_transport,
        src_net,
        time_window,
    })
}

fn write_context_match(w: &mut Writer, context: &ContextMatch) -> ipc::Result<()> {
    write_transport_sec(w, &context.min_transport)?;
    w.write_option(context.src_net.as_ref(), |w, scope| {
        w.write_enum(codes::ip_scope(*scope))
    })?;
    w.write_option(context.time_window.as_ref(), |w, window| {
        w.write_u64(window.not_before().0)?;
        w.write_u64(window.not_after().0)
    })
}

/// Spec: docs/48 §7.2 option (i) (`AuthMatch { armored: Option<bool> }`).
fn read_auth_match(r: &mut Reader<'_>) -> ipc::Result<AuthMatch> {
    Ok(AuthMatch {
        armored: r.read_option(|r| r.read_bool())?,
    })
}

fn write_auth_match(w: &mut Writer, auth: &AuthMatch) -> ipc::Result<()> {
    w.write_option(auth.armored.as_ref(), |w, armored| w.write_bool(*armored))
}

// ---- obligations, rules, grants --------------------------------------------------

/// Spec: docs/11 §1b, §8 (`Obligation`, `RlKey`, `Constraint`).
fn read_obligation(r: &mut Reader<'_>, c: &Content) -> ipc::Result<Obligation> {
    match r.read_u8()? {
        obligation::AUDIT => Ok(Obligation::Audit),
        obligation::RATE_LIMIT => {
            let principal = read_sid(r, c, PolicyError::RuleValue)?;
            let class = r.read_enum(codes::action_class_from)?;
            Ok(Obligation::RateLimit(RlKey { principal, class }))
        }
        obligation::CONSTRAIN => match r.read_u8()? {
            constraint::MAX_PAGE_SIZE => Ok(Obligation::Constrain(Constraint::MaxPageSize(
                r.read_u32()?,
            ))),
            _ => Err(ipc::Error::UnknownCode),
        },
        _ => Err(ipc::Error::UnknownCode),
    }
}

fn write_obligation(w: &mut Writer, value: &Obligation) -> ipc::Result<()> {
    match value {
        Obligation::Audit => w.write_enum(obligation::AUDIT),
        Obligation::RateLimit(key) => {
            w.write_enum(obligation::RATE_LIMIT)?;
            write_sid(w, &key.principal)?;
            w.write_enum(codes::action_class(key.class))
        }
        Obligation::Constrain(Constraint::MaxPageSize(size)) => {
            w.write_enum(obligation::CONSTRAIN)?;
            w.write_enum(constraint::MAX_PAGE_SIZE)?;
            w.write_u32(*size)
        }
    }
}

/// One rule. Spec: docs/11 §3 (`Rule { id, effect, when, obligations }`).
pub(crate) fn read_rule(r: &mut Reader<'_>, c: &Content) -> ipc::Result<Rule> {
    let id = RuleId(r.read_u32()?);
    let effect = r.read_enum(codes::effect_from)?;
    let action = read_action_match(r)?;
    let resource = read_resource_match(r, c)?;
    let subject = read_subject_match(r, c)?;
    let context = read_context_match(r, c)?;
    let auth = read_auth_match(r)?;
    let obligations = r.read_seq(MAX_OBLIGATIONS, |r| read_obligation(r, c))?;
    Ok(Rule {
        id,
        effect,
        when: Match {
            action,
            resource,
            subject,
            context,
            auth,
        },
        obligations,
    })
}

pub(crate) fn write_rule(w: &mut Writer, rule: &Rule) -> ipc::Result<()> {
    w.write_u32(rule.id.0)?;
    w.write_enum(codes::effect(rule.effect))?;
    write_action_match(w, &rule.when.action)?;
    write_resource_match(w, &rule.when.resource)?;
    write_subject_match(w, &rule.when.subject)?;
    write_context_match(w, &rule.when.context)?;
    write_auth_match(w, &rule.when.auth)?;
    w.write_seq(&rule.obligations, MAX_OBLIGATIONS, write_obligation)
}

/// One anonymous-allowlist entry, built through `pdp::AnonymousGrant::new`:
/// an entry for External or over every resource refuses the whole load
/// (A-51; docs/15 §6).
pub(crate) fn read_grant(r: &mut Reader<'_>, c: &Content) -> ipc::Result<AnonymousGrant> {
    let action = read_action_match(r)?;
    let resource = read_resource_match(r, c)?;
    let min_transport = read_transport_sec(r)?;
    let src_net = r.read_enum(codes::ip_scope_from)?;
    match AnonymousGrant::new(action, resource, min_transport, src_net) {
        Ok(grant) => Ok(grant),
        Err(error) => c.refuse(PolicyError::Rule(error)),
    }
}

pub(crate) fn write_grant(w: &mut Writer, grant: &AnonymousGrant) -> ipc::Result<()> {
    write_action_match(w, grant.action())?;
    write_resource_match(w, grant.resource())?;
    write_transport_sec(w, &grant.min_transport())?;
    w.write_enum(codes::ip_scope(grant.src_net()))
}
