//! The policy value, its bounds and errors, the content rules, the file's
//! decoder and encoder, and the snapshot (crate documentation).
//!
//! Spec: docs/50 §3.3, §7.2; docs/11 §3, §6; docs/48 §7; A-36; A-39; A-51;
//! A-57; A-68; docs/questions/Q-270 item 2.

use crate::codes;
use crate::wire::{self, Content};
use core::fmt;
use core::ops::RangeInclusive;
use dtyp::Sid;
use ipc::{FrameLimit, Reader, Writer};
use pdp::{
    mandatory_fast_rules, AnonymousGrant, ClaimValue, Dn, KerbResKind, PolicySnapshot,
    PolicyVersion, ResourceMatch, Rule, RuleError, RuleId, SubjectMatch, Tier,
    MANDATORY_FAST_RULE_COUNT,
};
use std::collections::{BTreeMap, BTreeSet};

/// The marker that opens every development policy file: a file without it
/// is not an unsigned development policy and is refused. Unchanged from
/// format 1 (A-68: "the marker stays").
/// Spec: docs/questions/Q-270 item 2 ("clearly marked").
pub const MARKER: &[u8; 24] = b"UNSIGNED-DEV-DIRD-POLICY";

/// The one format number this build reads: 2 (the tier map, the rule set,
/// the anonymous allowlist and the mandatory-FAST bootstrap group).
/// Spec: docs/50 §3.3 ("exact version … no negotiation"); A-68.
pub const FORMAT: u8 = 2;

/// Format 1 (dird's tier-map-only file, task P8): refused with
/// [`PolicyError::Superseded`], never migrated (crate documentation).
/// Spec: A-68; docs/questions/Q-275 item 1.
pub const SUPERSEDED_FORMAT: u8 = 1;

/// Largest policy file: 1 MiB. Project choice (AGENTS.md §6: bounded);
/// unchanged from format 1.
pub const MAX_POLICY_FILE: u32 = 1024 * 1024;

/// Most `SID → tier` entries. Project choice (format 1).
pub const MAX_PRINCIPALS: u32 = 4096;

/// Most `subtree → tier` entries. Project choice (format 1).
pub const MAX_SUBTREES: u32 = 256;

/// Most RDN components of a DN (directory-pip `MAX_DN_DEPTH`, checked at
/// compile time in dird, which links both).
pub const MAX_DN_COMPONENTS: u32 = 64;

/// Bound of one RDN component: [MS-ADTS] 3.1.1.5.1.2 "The RDN size MUST be
/// less than 255 characters" (A-30: counted as `att=val`). Format 1.
pub const MAX_COMPONENT: u32 = 255;

/// Bound of a SID packet: 8 + 4 × 15 octets ([MS-DTYP] 2.4.2.2).
pub const MAX_SID: u32 = 8 + 4 * 15;

/// Most rules in the file (beside the mandatory-FAST set). Project choice.
pub const MAX_RULES: u32 = 1024;

/// Most actions of one `ActionMatch::AnyOf`. Project choice.
pub const MAX_ACTIONS: u32 = 64;

/// Most obligations of one rule. Project choice.
pub const MAX_OBLIGATIONS: u32 = 8;

/// Most anonymous-allowlist entries. Project choice (docs/15 §6 lists a
/// handful of anonymous resources).
pub const MAX_ANONYMOUS_GRANTS: u32 = 64;

/// Bound of a text field (share, zone, SPN, policy scope, claim id or
/// value). Project choice.
pub const MAX_TEXT: u32 = 1024;

/// The fixed warning both daemons print at every start (A-68: "the marker
/// stays, printed as a warning by both daemons").
/// Spec: docs/50 §7.2; docs/questions/Q-219 (A-57), Q-270 item 2.
pub const UNSIGNED_DEVELOPMENT_WARNING: &str =
    "WARNING: UNSIGNED DEVELOPMENT POLICY (docs/50 §7.2, Q-219, A-68): the policy store's \
     signature is NOT verified; its tier map, rule set and anonymous allowlist are trusted \
     as written. Not for deployment.";

/// The writer's bound for a whole file.
const FILE_LIMIT: FrameLimit = match FrameLimit::new(MAX_POLICY_FILE) {
    Some(limit) => limit,
    None => panic!("MAX_POLICY_FILE is outside the ipc FrameLimit range"),
};

const _: () = assert!(MAX_SID as usize == 8 + 4 * dtyp::SID_MAX_SUB_AUTHORITIES);
const _: () = assert!(MANDATORY_FAST_RULE_COUNT >= 1);

/// Why a policy file (or a policy value to be encoded) was refused. Carries
/// no file content (docs/50 §8.2).
/// Spec: docs/50 §7.2 ("invalid … ⇒ do not start"); crates/pdp policy.rs (a
/// `RuleError` fails the whole load).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// The file is longer than [`MAX_POLICY_FILE`].
    TooLarge,
    /// The file does not start with [`MARKER`].
    NotMarked,
    /// The format number is neither [`FORMAT`] nor [`SUPERSEDED_FORMAT`].
    Format,
    /// The file is format 1 (tier map only): refused, not migrated.
    Superseded,
    /// The structure did not decode (truncated, over a bound, trailing
    /// octets, an unknown code).
    Structure(ipc::Error),
    /// A tier-map SID did not decode, or the SIDs are not strictly
    /// ascending.
    Principal,
    /// A tier-map subtree DN is empty, a component is not printable
    /// `att=value`, or a DN appears twice.
    Subtree,
    /// A tier-map entry classifies as Untiered (no classification).
    Untiered,
    /// The mandatory-FAST bootstrap group SID did not decode, or its rule
    /// ids do not fit in `u32`.
    Bootstrap,
    /// Two rules share an id, or a rule id lies in the mandatory-FAST range.
    RuleId,
    /// A SID, text or DN component inside a rule or grant is invalid, or a
    /// time window is reversed.
    RuleValue,
    /// A construction refusal of the rule model (A-51): an empty subtree
    /// base, an anonymous grant for a network other than Internal or over
    /// every resource. The whole load fails.
    Rule(RuleError),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::TooLarge => f.write_str("policy file too large"),
            PolicyError::NotMarked => {
                f.write_str("policy file is not marked as an unsigned development policy")
            }
            PolicyError::Format => f.write_str("policy file format number not supported"),
            PolicyError::Superseded => f.write_str(
                "policy file is format 1 (tier map only), superseded by format 2: re-encode it with its rule set",
            ),
            PolicyError::Structure(error) => write!(f, "policy file malformed: {error}"),
            PolicyError::Principal => f.write_str("policy file principal entries invalid"),
            PolicyError::Subtree => f.write_str("policy file subtree entries invalid"),
            PolicyError::Untiered => f.write_str("policy file entry classifies as Untiered"),
            PolicyError::Bootstrap => {
                f.write_str("policy file mandatory-FAST bootstrap entry invalid")
            }
            PolicyError::RuleId => f.write_str("policy file rule ids repeat or overlap"),
            PolicyError::RuleValue => f.write_str("policy file rule value invalid"),
            PolicyError::Rule(error) => write!(f, "policy file rule refused: {error:?}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// The mandatory-FAST entry of the file: the bootstrap group whose expanded
/// members may make the one unarmored exchange (an AS for a TGT, docs/48
/// §7.3), and the first of the [`MANDATORY_FAST_RULE_COUNT`] consecutive
/// rule ids the set takes. Which SID a deployment names is a deployment
/// datum (Q-130 → A-39, with P-10); the file carries it.
/// Spec: docs/48 §7.1-§7.3; crates/pdp mandatory_fast.rs; A-39; P-10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MandatoryFast {
    /// The bootstrap-allowed group SID.
    pub bootstrap_group: Sid,
    /// The id of the first rule of the set.
    pub first_rule_id: RuleId,
}

impl MandatoryFast {
    /// The rule ids the set takes, or `None` if they do not fit in `u32`.
    /// Spec: crates/pdp `mandatory_fast_rules` ("`None` if the ids would
    /// overflow").
    #[must_use]
    pub fn rule_ids(&self) -> Option<RangeInclusive<u32>> {
        let last = self
            .first_rule_id
            .0
            .checked_add(MANDATORY_FAST_RULE_COUNT - 1)?;
        Some(self.first_rule_id.0..=last)
    }

    /// The rule set (`pdp::mandatory_fast_rules`), or `None` on overflow.
    /// Spec: docs/48 §7.2.
    #[must_use]
    pub fn rules(&self) -> Option<Vec<Rule>> {
        mandatory_fast_rules(self.bootstrap_group, self.first_rule_id)
    }
}

/// The unsigned development policy: its version, its tier map entries
/// (A-36), the mandatory-FAST bootstrap group (A-39), the file's rules and
/// the anonymous allowlist (crate documentation).
///
/// Every `Rule` and `AnonymousGrant` already passed its construction checks
/// (`pdp::SubtreeBase::new`, `pdp::AnonymousGrant::new`,
/// `pdp::TimeWindow::new`); [`DevelopmentPolicy::validate`] checks the rest.
///
/// Spec: docs/50 §3.4, §7.2; docs/11 §3, §6; A-36; A-39; A-51; A-68.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevelopmentPolicy {
    /// The policy version every view carries (R50-2) and the snapshot has.
    pub version: PolicyVersion,
    /// `SID → tier`.
    pub principals: BTreeMap<Sid, Tier>,
    /// `DN subtree → tier`, in file order.
    pub subtrees: Vec<(Dn, Tier)>,
    /// The mandatory-FAST bootstrap group and rule ids.
    pub mandatory_fast: MandatoryFast,
    /// The file's rules, in file order.
    pub rules: Vec<Rule>,
    /// The anonymous allowlist (internal network only, A-51).
    pub anonymous: Vec<AnonymousGrant>,
}

/// An RDN component of the directory's canonical form: at most
/// [`MAX_COMPONENT`] octets of printable ASCII, `att=value` with both sides
/// non-empty.
/// Spec: [MS-ADTS] 3.1.1.1.4 (RDN "att=val"); docs/47 §8.2; directory-pip
/// `DirectoryView::dn_of`; format 1's rule.
pub(crate) fn valid_component(octets: &[u8]) -> bool {
    if octets.len() > MAX_COMPONENT as usize || !octets.iter().all(|b| (0x20..=0x7E).contains(b)) {
        return false;
    }
    match octets.iter().position(|b| *b == b'=') {
        Some(at) => at > 0 && at + 1 < octets.len(),
        None => false,
    }
}

/// A text field: 1 ..= [`MAX_TEXT`] octets of printable ASCII. KDC names
/// the PDP compares are KerberosStrings, which krb-proto restricts to
/// printable ASCII (crates/kdc audit.rs), so a rule text outside it could
/// never match; refusing it keeps the file canonical (Q-275 item 4).
pub(crate) fn valid_text(octets: &[u8]) -> bool {
    !octets.is_empty()
        && octets.len() <= MAX_TEXT as usize
        && octets.iter().all(|b| (0x20..=0x7E).contains(b))
}

/// Every DN component of `dn` is valid.
fn valid_dn(dn: &Dn) -> bool {
    dn.rdns().iter().all(|c| valid_component(c.as_bytes()))
}

/// The texts and DN components of a resource matcher are valid.
fn valid_resource(resource: &ResourceMatch) -> bool {
    match resource {
        ResourceMatch::Any | ResourceMatch::RootDse | ResourceMatch::RpcMethod { .. } => true,
        ResourceMatch::DirSubtree { base } => valid_dn(base.dn()),
        ResourceMatch::File { share } => valid_text(share.0.as_bytes()),
        ResourceMatch::Dns { zone } => valid_text(zone.0.as_bytes()),
        ResourceMatch::Kerberos { kind } => match kind {
            None | Some(KerbResKind::Tgt) => true,
            Some(KerbResKind::Service(spn)) => valid_text(spn.0.as_bytes()),
        },
        ResourceMatch::Policy { scope } => scope
            .as_ref()
            .is_none_or(|scope| valid_text(scope.0.as_bytes())),
    }
}

/// The texts of a subject matcher are valid (SIDs are valid by type).
fn valid_subject(subject: &SubjectMatch) -> bool {
    match subject {
        SubjectMatch::Any
        | SubjectMatch::Principal(_)
        | SubjectMatch::MemberOf(_)
        | SubjectMatch::NotMemberOf(_)
        | SubjectMatch::Tier(_) => true,
        SubjectMatch::Claim(id, value) => {
            valid_text(id.0.as_bytes())
                && match value {
                    ClaimValue::Integer(_) | ClaimValue::Boolean(_) => true,
                    ClaimValue::Text(text) => valid_text(text.as_bytes()),
                }
        }
    }
}

impl DevelopmentPolicy {
    /// Check the content rules (crate documentation) on a value: what the
    /// decoder refuses, the encoder refuses too.
    ///
    /// # Errors
    /// [`PolicyError::Untiered`], [`PolicyError::Subtree`],
    /// [`PolicyError::Bootstrap`], [`PolicyError::RuleValue`],
    /// [`PolicyError::RuleId`].
    ///
    /// Spec: crate documentation; format 1 (Untiered first, then the
    /// subtrees); A-39; A-51.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self
            .principals
            .values()
            .chain(self.subtrees.iter().map(|(_, tier)| tier))
            .any(|tier| *tier == Tier::Untiered)
        {
            return Err(PolicyError::Untiered);
        }
        let mut seen = BTreeSet::new();
        for (dn, _) in &self.subtrees {
            if dn.rdns().is_empty() || !valid_dn(dn) || !seen.insert(dn) {
                return Err(PolicyError::Subtree);
            }
        }
        let fast = self
            .mandatory_fast
            .rule_ids()
            .ok_or(PolicyError::Bootstrap)?;
        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            if !valid_resource(&rule.when.resource) || !valid_subject(&rule.when.subject) {
                return Err(PolicyError::RuleValue);
            }
            if fast.contains(&rule.id.0) || !ids.insert(rule.id) {
                return Err(PolicyError::RuleId);
            }
        }
        if self
            .anonymous
            .iter()
            .any(|grant| !valid_resource(grant.resource()))
        {
            return Err(PolicyError::RuleValue);
        }
        Ok(())
    }

    /// Decode a whole policy file (crate documentation): the size bound,
    /// the marker, the format number, the structure (each value checked as
    /// it is read — the first fault found is reported), no trailing octet,
    /// then [`DevelopmentPolicy::validate`].
    ///
    /// # Errors
    /// [`PolicyError`].
    ///
    /// Spec: crate documentation; docs/50 §3.3, §7.2; crates/pdp policy.rs
    /// (a `RuleError` fails the whole load).
    pub fn decode(file: &[u8]) -> Result<DevelopmentPolicy, PolicyError> {
        if file.len() > MAX_POLICY_FILE as usize {
            return Err(PolicyError::TooLarge);
        }
        if file.get(..MARKER.len()) != Some(MARKER.as_slice()) {
            return Err(PolicyError::NotMarked);
        }
        let mut reader = Reader::new(file);
        let _marker = reader.read_array::<24>().map_err(PolicyError::Structure)?;
        // The format number before anything else: a format-1 file must be
        // reported as superseded, not as a structure error of format 2.
        match reader.read_u8().map_err(PolicyError::Structure)? {
            FORMAT => {}
            SUPERSEDED_FORMAT => return Err(PolicyError::Superseded),
            _ => return Err(PolicyError::Format),
        }
        let content = Content::new();
        let policy = read_body(&mut reader, &content)
            .map_err(|error| content.take().unwrap_or(PolicyError::Structure(error)))?;
        reader.finish().map_err(PolicyError::Structure)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Encode the policy as a file (for the development tooling and tests).
    ///
    /// # Errors
    /// [`PolicyError`] when an entry breaks a content rule
    /// ([`DevelopmentPolicy::validate`]), `Structure` when a bound is
    /// exceeded.
    ///
    /// Spec: crate documentation.
    pub fn encode(&self) -> Result<Vec<u8>, PolicyError> {
        self.validate()?;
        let mut writer = Writer::new(FILE_LIMIT);
        self.write(&mut writer).map_err(PolicyError::Structure)?;
        Ok(writer.into_payload().to_vec())
    }

    /// The fields in file order. Spec: crate documentation.
    fn write(&self, w: &mut Writer) -> ipc::Result<()> {
        w.write_array(MARKER)?;
        w.write_u8(FORMAT)?;
        w.write_u64(self.version.0)?;
        let principals: Vec<(&Sid, &Tier)> = self.principals.iter().collect();
        w.write_seq(&principals, MAX_PRINCIPALS, |w, (sid, tier)| {
            wire::write_sid(w, sid)?;
            w.write_enum(codes::tier(**tier))
        })?;
        w.write_seq(&self.subtrees, MAX_SUBTREES, |w, (dn, tier)| {
            wire::write_dn(w, dn)?;
            w.write_enum(codes::tier(*tier))
        })?;
        wire::write_sid(w, &self.mandatory_fast.bootstrap_group)?;
        w.write_u32(self.mandatory_fast.first_rule_id.0)?;
        w.write_seq(&self.rules, MAX_RULES, wire::write_rule)?;
        w.write_seq(&self.anonymous, MAX_ANONYMOUS_GRANTS, wire::write_grant)
    }

    /// The `pdp::PolicySnapshot` of this policy: the mandatory-FAST rule set
    /// of the bootstrap group first, then the file's rules in order, the
    /// anonymous allowlist, the file's version (crate documentation).
    ///
    /// # Errors
    /// [`PolicyError`] from [`DevelopmentPolicy::validate`] (a policy that
    /// decoded always validates).
    ///
    /// Spec: docs/11 §3, §6 (P9, D39); docs/48 §7.2; A-39; A-51.
    pub fn snapshot(&self) -> Result<PolicySnapshot, PolicyError> {
        self.validate()?;
        let mut rules = self.mandatory_fast.rules().ok_or(PolicyError::Bootstrap)?;
        rules.extend(self.rules.iter().cloned());
        Ok(PolicySnapshot::new(
            self.version,
            rules,
            self.anonymous.clone(),
        ))
    }
}

/// Everything after the format number. Content faults are noted in
/// `content` (crate::wire). Spec: crate documentation.
fn read_body(r: &mut Reader<'_>, content: &Content) -> ipc::Result<DevelopmentPolicy> {
    let version = PolicyVersion(r.read_u64()?);
    let mut last: Option<Sid> = None;
    let entries = r.read_seq(MAX_PRINCIPALS, |r| {
        let sid = wire::read_sid(r, content, PolicyError::Principal)?;
        // Strictly ascending: one encoding per map (format 1).
        if last.is_some_and(|previous| previous >= sid) {
            return content.refuse(PolicyError::Principal);
        }
        last = Some(sid);
        let tier = r.read_enum(codes::tier_from)?;
        Ok((sid, tier))
    })?;
    let subtrees = r.read_seq(MAX_SUBTREES, |r| {
        let dn = wire::read_dn(r, content, PolicyError::Subtree)?;
        let tier = r.read_enum(codes::tier_from)?;
        Ok((dn, tier))
    })?;
    let bootstrap_group = wire::read_sid(r, content, PolicyError::Bootstrap)?;
    let first_rule_id = RuleId(r.read_u32()?);
    let rules = r.read_seq(MAX_RULES, |r| wire::read_rule(r, content))?;
    let anonymous = r.read_seq(MAX_ANONYMOUS_GRANTS, |r| wire::read_grant(r, content))?;
    Ok(DevelopmentPolicy {
        version,
        principals: entries.into_iter().collect(),
        subtrees,
        mandatory_fast: MandatoryFast {
            bootstrap_group,
            first_rule_id,
        },
        rules,
        anonymous,
    })
}
