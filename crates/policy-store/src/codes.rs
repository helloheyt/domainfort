//! The closed code tables of the policy file: one `u8` table per `pdp`
//! enumeration the file carries, variant for variant (docs/50 §3.3: "enum =
//! `u8` from a closed table"). A code outside a table is a structure error
//! (`ipc::Error::UnknownCode`). Every match is exhaustive, so a variant
//! added to a `pdp` enumeration does not compile until it has a code here.
//!
//! The tier codes are format 1's (the directory channel's,
//! crates/ipc-directory `codes::tier`) — unchanged by A-68. The other tables
//! are new in format 2; their values are this project's choice (no document
//! assigns them).
//!
//! Spec: docs/50 §3.3; crates/pdp model.rs, policy.rs (the enumerations);
//! docs/questions/Q-270 item 2 (format 1), A-68.

use pdp::{Action, ActionClass, Effect, IpScope, Tier};

/// The kind of an action that carries a GUID payload: it is followed by the
/// 16-octet GUID packet ([MS-DTYP] 2.3.4).
pub const ACTION_DIR_ADD_CHILD: u8 = 2;
/// See [`ACTION_DIR_ADD_CHILD`].
pub const ACTION_DIR_CONTROL_RIGHT: u8 = 5;

/// `Tier` → code. Spec: format 1 (crates/ipc-directory `codes::tier`).
#[must_use]
pub const fn tier(tier: Tier) -> u8 {
    match tier {
        Tier::Tier0 => 0x00,
        Tier::Tier1 => 0x01,
        Tier::Tier2 => 0x02,
        Tier::Untiered => 0x03,
    }
}

/// Code → `Tier`. Spec: format 1.
#[must_use]
pub const fn tier_from(code: u8) -> Option<Tier> {
    match code {
        0x00 => Some(Tier::Tier0),
        0x01 => Some(Tier::Tier1),
        0x02 => Some(Tier::Tier2),
        0x03 => Some(Tier::Untiered),
        _ => None,
    }
}

/// `Effect` → code. Spec: docs/11 §3 (`effect: Allow | Deny`).
#[must_use]
pub const fn effect(effect: Effect) -> u8 {
    match effect {
        Effect::Allow => 0,
        Effect::Deny => 1,
    }
}

/// Code → `Effect`.
#[must_use]
pub const fn effect_from(code: u8) -> Option<Effect> {
    match code {
        0 => Some(Effect::Allow),
        1 => Some(Effect::Deny),
        _ => None,
    }
}

/// `IpScope` → code. Spec: docs/11 §1 (`src_net`).
#[must_use]
pub const fn ip_scope(scope: IpScope) -> u8 {
    match scope {
        IpScope::Internal => 0,
        IpScope::External => 1,
    }
}

/// Code → `IpScope`. Both decode; an anonymous grant for `External` is then
/// refused by `pdp::AnonymousGrant::new` (A-51), not here.
#[must_use]
pub const fn ip_scope_from(code: u8) -> Option<IpScope> {
    match code {
        0 => Some(IpScope::Internal),
        1 => Some(IpScope::External),
        _ => None,
    }
}

/// `ActionClass` → code. Spec: docs/11 §3 (`ActionMatch::Class`).
#[must_use]
pub const fn action_class(class: ActionClass) -> u8 {
    match class {
        ActionClass::Directory => 0,
        ActionClass::Rpc => 1,
        ActionClass::File => 2,
        ActionClass::Dns => 3,
        ActionClass::Kerberos => 4,
        ActionClass::Policy => 5,
    }
}

/// Code → `ActionClass`.
#[must_use]
pub const fn action_class_from(code: u8) -> Option<ActionClass> {
    match code {
        0 => Some(ActionClass::Directory),
        1 => Some(ActionClass::Rpc),
        2 => Some(ActionClass::File),
        3 => Some(ActionClass::Dns),
        4 => Some(ActionClass::Kerberos),
        5 => Some(ActionClass::Policy),
        _ => None,
    }
}

/// `Action` → its kind code (the GUID payload of
/// [`ACTION_DIR_ADD_CHILD`] / [`ACTION_DIR_CONTROL_RIGHT`] follows it on
/// the wire). Spec: docs/11 §1 (the action taxonomy); crates/pdp model.rs.
#[must_use]
pub const fn action(action: &Action) -> u8 {
    match action {
        Action::DirRead => 0,
        Action::DirWrite => 1,
        Action::DirAddChild(_) => ACTION_DIR_ADD_CHILD,
        Action::DirDelete => 3,
        Action::DirList => 4,
        Action::DirControlRight(_) => ACTION_DIR_CONTROL_RIGHT,
        Action::RpcCall => 6,
        Action::FileRead => 7,
        Action::FileWrite => 8,
        Action::DnsUpdate => 9,
        Action::DnsXfer => 10,
        Action::KdcAs => 11,
        Action::KdcTgs => 12,
        Action::KdcS4u2Self => 13,
        Action::KdcS4u2Proxy => 14,
        Action::PolicyAdmin => 15,
    }
}

/// Code → an action without a payload, or `None` for the two payload
/// kinds and unknown codes (the reader handles the payload kinds first).
#[must_use]
pub const fn simple_action_from(code: u8) -> Option<Action> {
    match code {
        0 => Some(Action::DirRead),
        1 => Some(Action::DirWrite),
        3 => Some(Action::DirDelete),
        4 => Some(Action::DirList),
        6 => Some(Action::RpcCall),
        7 => Some(Action::FileRead),
        8 => Some(Action::FileWrite),
        9 => Some(Action::DnsUpdate),
        10 => Some(Action::DnsXfer),
        11 => Some(Action::KdcAs),
        12 => Some(Action::KdcTgs),
        13 => Some(Action::KdcS4u2Self),
        14 => Some(Action::KdcS4u2Proxy),
        15 => Some(Action::PolicyAdmin),
        _ => None,
    }
}

/// The kinds of `ActionMatch`. Spec: docs/11 §3 ("Exact | AnyOf | Class").
pub mod action_match {
    /// `ActionMatch::Any`.
    pub const ANY: u8 = 0;
    /// `ActionMatch::Exact(action)`.
    pub const EXACT: u8 = 1;
    /// `ActionMatch::AnyOf(seq<action>)`.
    pub const ANY_OF: u8 = 2;
    /// `ActionMatch::Class(class)`.
    pub const CLASS: u8 = 3;
}

/// The kinds of `ResourceMatch`. Spec: docs/11 §3; docs/49 §5.2 (RootDse).
pub mod resource_match {
    /// `ResourceMatch::Any`.
    pub const ANY: u8 = 0;
    /// `ResourceMatch::DirSubtree { base: dn }`.
    pub const DIR_SUBTREE: u8 = 1;
    /// `ResourceMatch::RootDse`.
    pub const ROOT_DSE: u8 = 2;
    /// `ResourceMatch::RpcMethod { iface: guid, opnum: Option<u16> }`.
    pub const RPC_METHOD: u8 = 3;
    /// `ResourceMatch::File { share: text }`.
    pub const FILE: u8 = 4;
    /// `ResourceMatch::Dns { zone: text }`.
    pub const DNS: u8 = 5;
    /// `ResourceMatch::Kerberos { kind: Option<kerberos_kind> }`.
    pub const KERBEROS: u8 = 6;
    /// `ResourceMatch::Policy { scope: Option<text> }`.
    pub const POLICY: u8 = 7;
}

/// The kinds of `KerbResKind`. Spec: docs/11 §1.
pub mod kerberos_kind {
    /// `KerbResKind::Tgt`.
    pub const TGT: u8 = 0;
    /// `KerbResKind::Service(spn: text)`.
    pub const SERVICE: u8 = 1;
    /// `KerbResKind::ChangePassword` (no payload). Spec: docs/53 §5.2 (task
    /// K5); crates/pdp model.rs.
    pub const CHANGE_PASSWORD: u8 = 2;
}

/// The kinds of `SubjectMatch`. Spec: docs/11 §3; docs/48 §7.2 (NotMemberOf).
pub mod subject_match {
    /// `SubjectMatch::Any`.
    pub const ANY: u8 = 0;
    /// `SubjectMatch::Principal(sid)`.
    pub const PRINCIPAL: u8 = 1;
    /// `SubjectMatch::MemberOf(sid)`.
    pub const MEMBER_OF: u8 = 2;
    /// `SubjectMatch::NotMemberOf(sid)` (takes effect in Deny rules only,
    /// crates/pdp `Rule::applies`).
    pub const NOT_MEMBER_OF: u8 = 3;
    /// `SubjectMatch::Tier(tier)`.
    pub const TIER: u8 = 4;
    /// `SubjectMatch::Claim(text, claim_value)`.
    pub const CLAIM: u8 = 5;
}

/// The kinds of `ClaimValue`. Spec: docs/11 §1.
pub mod claim_value {
    /// `ClaimValue::Integer(i64)` — the `u64` of its two's-complement
    /// big-endian octets.
    pub const INTEGER: u8 = 0;
    /// `ClaimValue::Text(text)`.
    pub const TEXT: u8 = 1;
    /// `ClaimValue::Boolean(bool)`.
    pub const BOOLEAN: u8 = 2;
}

/// The kinds of `Obligation`. Spec: docs/11 §1b, §8.
pub mod obligation {
    /// `Obligation::Audit`.
    pub const AUDIT: u8 = 0;
    /// `Obligation::RateLimit(RlKey { principal: sid, class })`.
    pub const RATE_LIMIT: u8 = 1;
    /// `Obligation::Constrain(constraint)`.
    pub const CONSTRAIN: u8 = 2;
}

/// The kinds of `Constraint`. Spec: docs/11 §8.
pub mod constraint {
    /// `Constraint::MaxPageSize(u32)`.
    pub const MAX_PAGE_SIZE: u8 = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use pdp::{ControlRightId, ObjClass};

    /// Format 1 (crates/ipc-directory `codes::tier`, docs/questions/Q-270
    /// item 2): the tier codes are unchanged by A-68.
    #[test]
    fn tier_codes_are_format_1s() {
        for (tier_value, code) in [
            (Tier::Tier0, 0u8),
            (Tier::Tier1, 1),
            (Tier::Tier2, 2),
            (Tier::Untiered, 3),
        ] {
            assert_eq!(tier(tier_value), code);
            assert_eq!(tier_from(code), Some(tier_value));
        }
        assert_eq!(tier_from(4), None);
    }

    /// docs/50 §3.3 ("closed table"): every table maps each variant to one
    /// code and back, and nothing else decodes.
    #[test]
    fn every_table_round_trips_and_is_closed() {
        for code in 0..=u8::MAX {
            if let Some(value) = effect_from(code) {
                assert_eq!(effect(value), code);
            }
            if let Some(value) = ip_scope_from(code) {
                assert_eq!(ip_scope(value), code);
            }
            if let Some(value) = action_class_from(code) {
                assert_eq!(action_class(value), code);
            }
            if let Some(value) = simple_action_from(code) {
                assert_eq!(action(&value), code);
            }
        }
        assert_eq!((0..=u8::MAX).filter_map(effect_from).count(), 2);
        assert_eq!((0..=u8::MAX).filter_map(ip_scope_from).count(), 2);
        assert_eq!((0..=u8::MAX).filter_map(action_class_from).count(), 6);
        assert_eq!((0..=u8::MAX).filter_map(simple_action_from).count(), 14);
        let guid = dtyp::Guid {
            data1: 1,
            data2: 2,
            data3: 3,
            data4: [4; 8],
        };
        assert_eq!(
            action(&Action::DirAddChild(ObjClass(guid))),
            ACTION_DIR_ADD_CHILD
        );
        assert_eq!(
            action(&Action::DirControlRight(ControlRightId(guid))),
            ACTION_DIR_CONTROL_RIGHT
        );
        assert_eq!(simple_action_from(ACTION_DIR_ADD_CHILD), None);
        assert_eq!(simple_action_from(ACTION_DIR_CONTROL_RIGHT), None);
    }
}
