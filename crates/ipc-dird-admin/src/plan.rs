//! The **effect plan** (task MA2; docs/research/r5-a-admin-model.md §3.3,
//! §11 MA2; docs/questions/Q-874, Q-980, Q-981): what an admin operation
//! will do beyond its direct target, computed by dird with the functions
//! that enforce it, in one canonical encoding whose digest is bound — inside
//! the operation digest — by the requester's AP-REQ at the commit and by
//! every approver's `Approve`.
//!
//! # Why a plan (class C46)
//!
//! An approval of "AddMember(H, G)" where H has forty members and G is a
//! Tier-0 group raises forty people to Tier 0 while the approver sees one
//! line (PENDING-OWNER A-147, the finding of r5-a U4). The decision covers
//! the request, not its effect closure. The plan names the closure; its
//! digest is part of what is signed; dird recomputes it at the execution and
//! refuses any difference — so "approved X, executed X + Y" has no path.
//!
//! # Canonical layout (layout 1)
//!
//! ```text
//! EffectPlan  := layout:u8 (1) ‖ principals:seq<Principal, 256> ‖ effects:seq<Effect, 64>
//! Principal   := sid:bytes<68> ‖ guid:[16] ‖ kind:u8 {1 User, 2 Computer, 3 Group}
//!                ‖ name:bytes<256>                       (sAMAccountName, printable ASCII)
//! Effect      := tag:u8 ‖ parameters ‖ principals:seq<bytes<68>, 256>
//!   1 MembershipDelta    gained:seq<sid, 256> ‖ lost:seq<sid, 256>
//!   2 TierDelta          subject_from:u8 ‖ subject_to:u8 ‖ object_from:u8 ‖ object_to:u8
//!   3 PolicyReference    reference:u8 {1 TierMap, 2 PolicyPrincipal} ‖ tier:u8
//!   4 TicketsRevoked     kind:u8 {1 PasswordSet, 2 AccountUnusable}
//!   5 ProtectedDataLoss  (none)
//!   6 KeyDestruction     kvno:Option<u32>
//!   7 NamesReleased      names:seq<bytes<2048>, 36>       (appended, task PN7)
//! tier        := 0 Tier0 | 1 Tier1 | 2 Tier2 | 3 none (Untiered / unclassified)
//! ```
//!
//! One encoding per plan (docs/50 §3.3), checked by the decoder:
//! `principals` strictly ascending by SID octets; every SID an effect names
//! (in `gained`, `lost`, `principals`) is in `principals`, and every entry of
//! `principals` is named by some effect; each effect's `principals` is
//! non-empty and strictly ascending, as are `gained` and `lost`, which are
//! disjoint and not both empty; a `TierDelta` changes at least one tier;
//! `PolicyReference` pairs `TierMap` with a tier 0-2 and `PolicyPrincipal`
//! with 3; a `NamesReleased` names exactly one principal and a non-empty set
//! of names, strictly ascending by octets, each a namespace key's form
//! (printable ASCII without `A`-`Z` — the fold of docs/59 §4.2), and no
//! principal or name is in two of them (a key has one holder, docs/59 §4.4
//! N1); effects strictly ascending by their head (`tag ‖ parameters`) — so
//! two effects never share a head; the whole encoding at most [`MAX_PLAN`]
//! octets. `encode(decode(b)) == b` for every `b` that decodes.
//!
//! Tag 7 is appended to the closed table under layout 1 (no code reused or
//! renumbered, every earlier plan keeps its octets and digest): a decoder
//! that does not know it refuses the plan — fail closed (docs/questions/
//! Q-1037).
//!
//! The effects group principals that share the same change: "these 41
//! principals gain {G, P}" is one `MembershipDelta`, "these 40 go from
//! Untiered to Tier0" one `TierDelta` — the per-principal facts of r5-a §3.3
//! (`MembershipDelta {principal, gained, lost}`, `TierDelta {object, from,
//! to}`), grouped so that a plan stays within one reply.
//!
//! # The digest
//!
//! [`plan_digest`] = SHA-256 (FIPS 180-4, the approved RustCrypto `sha2`)
//! over [`PLAN_DIGEST_LABEL`] ‖ the canonical encoding. It is a field of the
//! `Commit` operation (crate::wire), so the operation digest an AP-REQ binds
//! (crate::digest; RFC 4120 §5.5.1) covers it.
//!
//! Spec: docs/research/r5-a-admin-model.md §3.3, §8.1 U4, U18, §8.3 (C46);
//! docs/questions/Q-874 items 1-3, 7; docs/50 §3.3; FIPS 180-4 §6.2;
//! PENDING-OWNER A-147.

use crate::channel::{
    codes, MAX_NAME, MAX_PLAN, MAX_PLAN_EFFECTS, MAX_PLAN_PRINCIPALS, MAX_PLAN_RELEASED_NAME,
    MAX_PLAN_RELEASED_NAMES, MAX_SID,
};
use core::fmt;
use dtyp::{Guid, Sid};
use ipc::{FrameLimit, Reader, Writer};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// The domain-separation label of a plan digest: the first octets of every
/// plan digest and of no other digest of this project. Project choice.
/// Spec: docs/52 §5 item 1 (the precedent: "a fixed domain-separation
/// label").
pub const PLAN_DIGEST_LABEL: &[u8] = b"dird-admin effect plan, layout 1";

/// The layout octet this build encodes and accepts.
/// Spec: docs/50 §3.3 (exact versions, no negotiation).
pub const PLAN_LAYOUT: u8 = 1;

/// The writer's bound: the plan bound.
const PLAN_LIMIT: FrameLimit = match FrameLimit::new(MAX_PLAN as u32) {
    Some(limit) => limit,
    None => panic!("MAX_PLAN is outside the ipc FrameLimit range"),
};

/// Why a plan does not encode or decode. Carries no octet.
/// Spec: docs/50 §3.3, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanError {
    /// A bound is exceeded (more than [`MAX_PLAN`] octets, more principals
    /// or effects than the layout admits): the closure cannot be shown.
    TooLarge,
    /// The octets do not follow the layout, or the plan breaks a canonical
    /// rule (module documentation).
    Malformed,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PlanError::TooLarge => "effect plan exceeds its bounds",
            PlanError::Malformed => "effect plan is not canonical",
        })
    }
}

impl std::error::Error for PlanError {}

/// The kind of a principal a plan names.
/// Spec: docs/46 §4; module documentation (`kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PlanPrincipalKind {
    /// A user account.
    User,
    /// A computer account.
    Computer,
    /// A group.
    Group,
}

impl PlanPrincipalKind {
    fn code(self) -> u8 {
        match self {
            PlanPrincipalKind::User => codes::PLAN_KIND_USER,
            PlanPrincipalKind::Computer => codes::PLAN_KIND_COMPUTER,
            PlanPrincipalKind::Group => codes::PLAN_KIND_GROUP,
        }
    }

    fn from_code(code: u8) -> Option<PlanPrincipalKind> {
        match code {
            codes::PLAN_KIND_USER => Some(PlanPrincipalKind::User),
            codes::PLAN_KIND_COMPUTER => Some(PlanPrincipalKind::Computer),
            codes::PLAN_KIND_GROUP => Some(PlanPrincipalKind::Group),
            _ => None,
        }
    }
}

/// One principal a plan names: its identity as dird resolved it — SID and
/// canonical ASCII name, the GUID for the directory (r5-a R5A-10: "identity
/// in the plan = SID + canonical name").
/// Spec: docs/research/r5-a-admin-model.md §8.2 (R5A-10); P-6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanPrincipal {
    /// The objectSid.
    pub sid: Sid,
    /// The objectGUID.
    pub guid: Guid,
    /// User, computer or group.
    pub kind: PlanPrincipalKind,
    /// The sAMAccountName (printable ASCII, 1 to 256 characters).
    pub name: String,
}

/// A tier in a plan: the three tiers, or none (`Untiered` as a Subject; no
/// explicit classification as an object — Tier0 for writes by A-36).
/// Spec: docs/47 §6.3; A-36; P-22.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PlanTier {
    /// Tier 0.
    Tier0,
    /// Tier 1.
    Tier1,
    /// Tier 2.
    Tier2,
    /// No tier.
    None,
}

impl PlanTier {
    fn code(self) -> u8 {
        match self {
            PlanTier::Tier0 => codes::TIER_0,
            PlanTier::Tier1 => codes::TIER_1,
            PlanTier::Tier2 => codes::TIER_2,
            PlanTier::None => codes::FACT_UNCLASSIFIED,
        }
    }

    fn from_code(code: u8) -> Option<PlanTier> {
        match code {
            codes::TIER_0 => Some(PlanTier::Tier0),
            codes::TIER_1 => Some(PlanTier::Tier1),
            codes::TIER_2 => Some(PlanTier::Tier2),
            codes::FACT_UNCLASSIFIED => Some(PlanTier::None),
            _ => None,
        }
    }
}

/// How the policy names a group a membership change reaches.
/// Spec: docs/research/r5-a-admin-model.md §3.3 (`PolicyReference {object,
/// referenced_by}`), §8.2 ("AddMember to a group the tier map / … / the
/// bootstrap group references").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyReferenceKind {
    /// A tier-map row `SID → tier` (never `PlanTier::None`).
    TierMap(PlanTier),
    /// A policy principal (the bootstrap group, A-39 / A-44).
    PolicyPrincipal,
}

/// Which tickets a change revokes.
/// Spec: docs/research/r5-a-admin-model.md §3.3 (`TicketsRevoked`); docs/47
/// §4.5 (R47-7); A-162; D53.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RevocationKind {
    /// A password set: every ticket first authenticated at or before the
    /// commit is refused from its next use at the DC, for good
    /// (`revoked_before`, A-162).
    PasswordSet,
    /// The account becomes unusable (disabled, expired, deleted): its
    /// tickets are refused from their next use at the DC while it stays so
    /// (D53: at the next TGS — not at once).
    AccountUnusable,
}

/// One effect of a plan (module documentation, the layout).
/// Spec: docs/research/r5-a-admin-model.md §3.3 (`Effect`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// These principals' expansion gains `gained` and loses `lost`.
    MembershipDelta {
        /// Groups gained.
        gained: BTreeSet<Sid>,
        /// Groups lost.
        lost: BTreeSet<Sid>,
        /// The principals.
        principals: BTreeSet<Sid>,
    },
    /// These principals' subject tier goes `subject.0 → subject.1` and their
    /// object tier `object.0 → object.1`.
    TierDelta {
        /// The subject tier, before and after.
        subject: (PlanTier, PlanTier),
        /// The object tier, before and after.
        object: (PlanTier, PlanTier),
        /// The principals.
        principals: BTreeSet<Sid>,
    },
    /// The policy names these groups, which the change reaches.
    PolicyReference {
        /// How the policy names them.
        reference: PolicyReferenceKind,
        /// The groups.
        principals: BTreeSet<Sid>,
    },
    /// These principals' tickets are revoked.
    TicketsRevoked {
        /// Which tickets, and how long.
        kind: RevocationKind,
        /// The accounts.
        principals: BTreeSet<Sid>,
    },
    /// These users lose the secrets protected under their password (an
    /// administrator's reset, P-68).
    ProtectedDataLoss {
        /// The users.
        principals: BTreeSet<Sid>,
    },
    /// Key material of these accounts is destroyed: every key set (`None` —
    /// a `Delete`, by dird's destroy decision, A-105) or one key version.
    KeyDestruction {
        /// The key version, or every key set.
        kvno: Option<u32>,
        /// The accounts.
        principals: BTreeSet<Sid>,
    },
    /// The principal-namespace keys this principal holds are released (task
    /// PN7): the object is deleted, so every name it held — in every form
    /// (sAMAccountName, a computer's base name, a userPrincipalName's local
    /// part, an SPN, a host name) — is free for another object to take. A
    /// ticket authenticated under one of them before stays refused for an
    /// object that later takes the name (`revoked_before`; docs/59 §2, §9
    /// S7).
    NamesReleased {
        /// The keys, as the namespace stores them: folded (docs/59 §4.2).
        names: BTreeSet<String>,
        /// The one principal that held them.
        principals: BTreeSet<Sid>,
    },
}

/// Whether `name` has a namespace key's form: non-empty printable ASCII
/// without `A`-`Z` (docs/59 §4.2: printable octets 0x20-0x7E only, `A`-`Z`
/// folded to `a`-`z`). Its length is the field's bound
/// ([`MAX_PLAN_RELEASED_NAME`]).
/// Spec: docs/59 §4.2, §4.6; docs/questions/Q-080 items 1-2.
fn released_name_ok(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|b| (0x20..=0x7E).contains(b) && !b.is_ascii_uppercase())
}

impl Effect {
    /// The principals the effect applies to.
    #[must_use]
    pub fn principals(&self) -> &BTreeSet<Sid> {
        match self {
            Effect::MembershipDelta { principals, .. }
            | Effect::TierDelta { principals, .. }
            | Effect::PolicyReference { principals, .. }
            | Effect::TicketsRevoked { principals, .. }
            | Effect::ProtectedDataLoss { principals }
            | Effect::KeyDestruction { principals, .. }
            | Effect::NamesReleased { principals, .. } => principals,
        }
    }

    /// Every SID the effect names (its principals and, for a membership
    /// delta, the groups).
    fn sids(&self) -> impl Iterator<Item = &Sid> {
        let groups: Box<dyn Iterator<Item = &Sid>> = match self {
            Effect::MembershipDelta { gained, lost, .. } => Box::new(gained.iter().chain(lost)),
            _ => Box::new(core::iter::empty()),
        };
        self.principals().iter().chain(groups)
    }

    /// The head: `tag ‖ parameters` (module documentation).
    fn write_head(&self, writer: &mut Writer) -> Result<(), PlanError> {
        let enc = |e: ipc::Error| map_ipc(&e);
        match self {
            Effect::MembershipDelta { gained, lost, .. } => {
                writer
                    .write_enum(codes::EFFECT_MEMBERSHIP_DELTA)
                    .map_err(enc)?;
                write_sids(writer, gained)?;
                write_sids(writer, lost)
            }
            Effect::TierDelta {
                subject, object, ..
            } => {
                writer.write_enum(codes::EFFECT_TIER_DELTA).map_err(enc)?;
                for tier in [subject.0, subject.1, object.0, object.1] {
                    writer.write_enum(tier.code()).map_err(enc)?;
                }
                Ok(())
            }
            Effect::PolicyReference { reference, .. } => {
                writer
                    .write_enum(codes::EFFECT_POLICY_REFERENCE)
                    .map_err(enc)?;
                let (kind, tier) = match reference {
                    PolicyReferenceKind::TierMap(tier) => (codes::REFERENCE_TIER_MAP, *tier),
                    PolicyReferenceKind::PolicyPrincipal => {
                        (codes::REFERENCE_POLICY_PRINCIPAL, PlanTier::None)
                    }
                };
                writer.write_enum(kind).map_err(enc)?;
                writer.write_enum(tier.code()).map_err(enc)
            }
            Effect::TicketsRevoked { kind, .. } => {
                writer
                    .write_enum(codes::EFFECT_TICKETS_REVOKED)
                    .map_err(enc)?;
                writer
                    .write_enum(match kind {
                        RevocationKind::PasswordSet => codes::REVOKED_BY_PASSWORD_SET,
                        RevocationKind::AccountUnusable => codes::REVOKED_ACCOUNT_UNUSABLE,
                    })
                    .map_err(enc)
            }
            Effect::ProtectedDataLoss { .. } => writer
                .write_enum(codes::EFFECT_PROTECTED_DATA_LOSS)
                .map_err(enc),
            Effect::KeyDestruction { kvno, .. } => {
                writer
                    .write_enum(codes::EFFECT_KEY_DESTRUCTION)
                    .map_err(enc)?;
                writer
                    .write_option(kvno.as_ref(), |w, k| w.write_u32(*k))
                    .map_err(enc)
            }
            Effect::NamesReleased { names, .. } => {
                writer
                    .write_enum(codes::EFFECT_NAMES_RELEASED)
                    .map_err(enc)?;
                // A `BTreeSet<String>` iterates in ascending octet order.
                let names: Vec<&String> = names.iter().collect();
                writer
                    .write_seq(&names, MAX_PLAN_RELEASED_NAMES, |w, n| {
                        w.write_bytes(n.as_bytes(), MAX_PLAN_RELEASED_NAME)
                    })
                    .map_err(enc)
            }
        }
    }

    /// The head's octets: the canonical order key of effects.
    fn head(&self) -> Result<Vec<u8>, PlanError> {
        let mut writer = Writer::new(PLAN_LIMIT);
        self.write_head(&mut writer)?;
        Ok(writer.into_payload().to_vec())
    }

    /// The canonical rules of one effect (module documentation).
    fn check(&self) -> Result<(), PlanError> {
        if self.principals().is_empty() {
            return Err(PlanError::Malformed);
        }
        match self {
            Effect::MembershipDelta { gained, lost, .. } => {
                if (gained.is_empty() && lost.is_empty()) || !gained.is_disjoint(lost) {
                    return Err(PlanError::Malformed);
                }
            }
            Effect::TierDelta {
                subject, object, ..
            } => {
                if subject.0 == subject.1 && object.0 == object.1 {
                    return Err(PlanError::Malformed);
                }
            }
            Effect::PolicyReference { reference, .. } => {
                if *reference == PolicyReferenceKind::TierMap(PlanTier::None) {
                    return Err(PlanError::Malformed);
                }
            }
            Effect::NamesReleased { names, principals } => {
                // One holder per key (docs/59 §4.4 N1): the names of one
                // principal, never a set shared by several.
                if principals.len() != 1
                    || names.is_empty()
                    || names.iter().any(|n| !released_name_ok(n.as_bytes()))
                {
                    return Err(PlanError::Malformed);
                }
            }
            Effect::TicketsRevoked { .. }
            | Effect::ProtectedDataLoss { .. }
            | Effect::KeyDestruction { .. } => {}
        }
        Ok(())
    }

    /// Read one effect: its head, then its principals.
    fn read(reader: &mut Reader<'_>) -> Result<Effect, PlanError> {
        let dec = |e: ipc::Error| map_ipc(&e);
        let tag = reader
            .read_enum(|c| {
                matches!(
                    c,
                    codes::EFFECT_MEMBERSHIP_DELTA
                        | codes::EFFECT_TIER_DELTA
                        | codes::EFFECT_POLICY_REFERENCE
                        | codes::EFFECT_TICKETS_REVOKED
                        | codes::EFFECT_PROTECTED_DATA_LOSS
                        | codes::EFFECT_KEY_DESTRUCTION
                        | codes::EFFECT_NAMES_RELEASED
                )
                .then_some(c)
            })
            .map_err(dec)?;
        let tier = |r: &mut Reader<'_>| r.read_enum(PlanTier::from_code).map_err(dec);
        let effect = match tag {
            codes::EFFECT_MEMBERSHIP_DELTA => {
                let gained = read_sids(reader)?;
                let lost = read_sids(reader)?;
                Effect::MembershipDelta {
                    gained,
                    lost,
                    principals: read_sids(reader)?,
                }
            }
            codes::EFFECT_TIER_DELTA => {
                let subject = (tier(reader)?, tier(reader)?);
                let object = (tier(reader)?, tier(reader)?);
                Effect::TierDelta {
                    subject,
                    object,
                    principals: read_sids(reader)?,
                }
            }
            codes::EFFECT_POLICY_REFERENCE => {
                let kind = reader
                    .read_enum(|c| {
                        matches!(
                            c,
                            codes::REFERENCE_TIER_MAP | codes::REFERENCE_POLICY_PRINCIPAL
                        )
                        .then_some(c)
                    })
                    .map_err(dec)?;
                let level = tier(reader)?;
                let reference = match (kind, level) {
                    (codes::REFERENCE_POLICY_PRINCIPAL, PlanTier::None) => {
                        PolicyReferenceKind::PolicyPrincipal
                    }
                    (codes::REFERENCE_TIER_MAP, level) if level != PlanTier::None => {
                        PolicyReferenceKind::TierMap(level)
                    }
                    _ => return Err(PlanError::Malformed),
                };
                Effect::PolicyReference {
                    reference,
                    principals: read_sids(reader)?,
                }
            }
            codes::EFFECT_TICKETS_REVOKED => {
                let kind = reader
                    .read_enum(|c| match c {
                        codes::REVOKED_BY_PASSWORD_SET => Some(RevocationKind::PasswordSet),
                        codes::REVOKED_ACCOUNT_UNUSABLE => Some(RevocationKind::AccountUnusable),
                        _ => None,
                    })
                    .map_err(dec)?;
                Effect::TicketsRevoked {
                    kind,
                    principals: read_sids(reader)?,
                }
            }
            codes::EFFECT_PROTECTED_DATA_LOSS => Effect::ProtectedDataLoss {
                principals: read_sids(reader)?,
            },
            codes::EFFECT_NAMES_RELEASED => {
                let names = read_released_names(reader)?;
                Effect::NamesReleased {
                    names,
                    principals: read_sids(reader)?,
                }
            }
            _ => {
                let kvno = reader.read_option(Reader::read_u32).map_err(dec)?;
                Effect::KeyDestruction {
                    kvno,
                    principals: read_sids(reader)?,
                }
            }
        };
        effect.check()?;
        Ok(effect)
    }
}

/// A plan (module documentation). Build it with [`EffectPlan::new`], which
/// puts it in canonical order and checks every rule; decode it with
/// [`EffectPlan::decode`].
/// Spec: docs/research/r5-a-admin-model.md §3.3 (`EffectPlan`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectPlan {
    principals: Vec<PlanPrincipal>,
    effects: Vec<Effect>,
}

/// The canonical order key of a SID: its packet ([MS-DTYP] 2.4.2.2).
fn sid_key(sid: &Sid) -> Vec<u8> {
    sid.encode()
}

/// Write a set of SIDs in ascending packet order.
fn write_sids(writer: &mut Writer, sids: &BTreeSet<Sid>) -> Result<(), PlanError> {
    let mut packets: Vec<Vec<u8>> = sids.iter().map(sid_key).collect();
    packets.sort();
    writer
        .write_seq(&packets, MAX_PLAN_PRINCIPALS, |w, p| {
            w.write_bytes(p, MAX_SID)
        })
        .map_err(|e| map_ipc(&e))
}

/// Read a set of SIDs, strictly ascending by packet.
fn read_sids(reader: &mut Reader<'_>) -> Result<BTreeSet<Sid>, PlanError> {
    let packets = reader
        .read_seq(MAX_PLAN_PRINCIPALS, |r| {
            r.read_bytes(MAX_SID).map(<[u8]>::to_vec)
        })
        .map_err(|e| map_ipc(&e))?;
    if packets.windows(2).any(|w| w[0] >= w[1]) {
        return Err(PlanError::Malformed);
    }
    packets
        .iter()
        .map(|p| Sid::decode(p).map_err(|_| PlanError::Malformed))
        .collect()
}

/// Read the names of a `NamesReleased`: at most [`MAX_PLAN_RELEASED_NAMES`],
/// each at most [`MAX_PLAN_RELEASED_NAME`] octets of a key's form, strictly
/// ascending by octets (module documentation).
/// Spec: docs/50 §3.3 (one encoding per value); docs/59 §4.2, §4.6.
fn read_released_names(reader: &mut Reader<'_>) -> Result<BTreeSet<String>, PlanError> {
    let names = reader
        .read_seq(MAX_PLAN_RELEASED_NAMES, |r| {
            r.read_bytes(MAX_PLAN_RELEASED_NAME).map(<[u8]>::to_vec)
        })
        .map_err(|e| map_ipc(&e))?;
    if names.windows(2).any(|w| w[0] >= w[1]) || names.iter().any(|n| !released_name_ok(n)) {
        return Err(PlanError::Malformed);
    }
    names
        .into_iter()
        .map(|n| String::from_utf8(n).map_err(|_| PlanError::Malformed))
        .collect()
}

/// An `ipc` error of the plan's codec: a bound exceeded is `TooLarge`, any
/// other `Malformed`.
fn map_ipc(error: &ipc::Error) -> PlanError {
    match error {
        ipc::Error::LengthOverBound
        | ipc::Error::CountOverBound
        | ipc::Error::BodyOverBound
        | ipc::Error::FrameTooLarge => PlanError::TooLarge,
        _ => PlanError::Malformed,
    }
}

/// Whether `name` is a canonical principal name: printable ASCII, 1 to
/// [`MAX_NAME`] characters (P-6).
fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME as usize
        && name.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

impl EffectPlan {
    /// The empty plan: the operation has no effect beyond its direct target.
    #[must_use]
    pub fn empty() -> EffectPlan {
        EffectPlan {
            principals: Vec::new(),
            effects: Vec::new(),
        }
    }

    /// A plan of `effects` over `principals`, in canonical order: the
    /// principals the effects name are kept (others dropped), each effect
    /// checked, the whole encoding bounded.
    ///
    /// # Errors
    /// [`PlanError::Malformed`] when an effect breaks a canonical rule, two
    /// effects share a head, two principals share a SID, an effect names a
    /// SID without a principal, or two `NamesReleased` effects share a
    /// principal or a name; [`PlanError::TooLarge`] beyond the bounds.
    ///
    /// Spec: module documentation.
    pub fn new(
        principals: impl IntoIterator<Item = PlanPrincipal>,
        effects: impl IntoIterator<Item = Effect>,
    ) -> Result<EffectPlan, PlanError> {
        let mut keyed = Vec::new();
        for effect in effects {
            effect.check()?;
            keyed.push((effect.head()?, effect));
        }
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(PlanError::Malformed);
        }
        let effects: Vec<Effect> = keyed.into_iter().map(|(_, e)| e).collect();
        if effects.len() > MAX_PLAN_EFFECTS as usize {
            return Err(PlanError::TooLarge);
        }
        // A key has one holder (docs/59 §4.4 N1): no principal and no name
        // in two `NamesReleased` effects — so each released name has one
        // spelling in the plan, beside the one principal that held it.
        let mut holders: BTreeSet<&Sid> = BTreeSet::new();
        let mut released: BTreeSet<&String> = BTreeSet::new();
        for effect in &effects {
            if let Effect::NamesReleased { names, principals } = effect {
                if !principals.iter().all(|p| holders.insert(p))
                    || !names.iter().all(|n| released.insert(n))
                {
                    return Err(PlanError::Malformed);
                }
            }
        }
        let named: BTreeSet<&Sid> = effects.iter().flat_map(Effect::sids).collect();
        let mut kept: Vec<(Vec<u8>, PlanPrincipal)> = Vec::new();
        for principal in principals {
            if named.contains(&principal.sid) {
                kept.push((sid_key(&principal.sid), principal));
            }
        }
        kept.sort_by(|a, b| a.0.cmp(&b.0));
        if kept.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(PlanError::Malformed);
        }
        if kept.len() != named.len() || kept.iter().any(|(_, p)| !name_ok(&p.name)) {
            return Err(PlanError::Malformed);
        }
        if kept.len() > MAX_PLAN_PRINCIPALS as usize {
            return Err(PlanError::TooLarge);
        }
        let plan = EffectPlan {
            principals: kept.into_iter().map(|(_, p)| p).collect(),
            effects,
        };
        // The whole encoding must fit its bound.
        plan.encode()?;
        Ok(plan)
    }

    /// The principals, ascending by SID packet.
    #[must_use]
    pub fn principals(&self) -> &[PlanPrincipal] {
        &self.principals
    }

    /// The effects, in canonical order.
    #[must_use]
    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }

    /// The principal of `sid`, if the plan names it.
    #[must_use]
    pub fn principal(&self, sid: &Sid) -> Option<&PlanPrincipal> {
        self.principals.iter().find(|p| p.sid == *sid)
    }

    /// The canonical encoding (module documentation).
    ///
    /// # Errors
    /// [`PlanError::TooLarge`] beyond [`MAX_PLAN`] octets.
    pub fn encode(&self) -> Result<Vec<u8>, PlanError> {
        let enc = |e: ipc::Error| map_ipc(&e);
        let mut writer = Writer::new(PLAN_LIMIT);
        writer.write_u8(PLAN_LAYOUT).map_err(enc)?;
        writer
            .write_seq(&self.principals, MAX_PLAN_PRINCIPALS, |w, p| {
                w.write_bytes(&p.sid.encode(), MAX_SID)?;
                w.write_array(&p.guid.to_packet())?;
                w.write_enum(p.kind.code())?;
                w.write_bytes(p.name.as_bytes(), MAX_NAME)
            })
            .map_err(enc)?;
        writer
            .write_u32(u32::try_from(self.effects.len()).map_err(|_| PlanError::TooLarge)?)
            .map_err(enc)?;
        for effect in &self.effects {
            effect.write_head(&mut writer)?;
            write_sids(&mut writer, effect.principals())?;
        }
        Ok(writer.into_payload().to_vec())
    }

    /// Decode a plan, checking every canonical rule (module documentation).
    ///
    /// # Errors
    /// [`PlanError`].
    pub fn decode(octets: &[u8]) -> Result<EffectPlan, PlanError> {
        if octets.len() > MAX_PLAN {
            return Err(PlanError::TooLarge);
        }
        let dec = |e: ipc::Error| map_ipc(&e);
        let mut reader = Reader::new(octets);
        if reader.read_u8().map_err(dec)? != PLAN_LAYOUT {
            return Err(PlanError::Malformed);
        }
        let principals = reader
            .read_seq(MAX_PLAN_PRINCIPALS, |r| {
                let sid = r.read_bytes(MAX_SID)?.to_vec();
                let guid = r.read_array::<16>()?;
                let kind = r.read_enum(PlanPrincipalKind::from_code)?;
                let name = r.read_bytes(MAX_NAME)?.to_vec();
                Ok((sid, guid, kind, name))
            })
            .map_err(dec)?;
        if principals.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(PlanError::Malformed);
        }
        let principals = principals
            .into_iter()
            .map(|(sid, guid, kind, name)| {
                Ok(PlanPrincipal {
                    sid: Sid::decode(&sid).map_err(|_| PlanError::Malformed)?,
                    guid: Guid::from_packet(&guid),
                    kind,
                    name: String::from_utf8(name).map_err(|_| PlanError::Malformed)?,
                })
            })
            .collect::<Result<Vec<_>, PlanError>>()?;
        let effects = reader
            .read_seq(MAX_PLAN_EFFECTS, |r| {
                Effect::read(r).map_err(|_| ipc::Error::UnknownCode)
            })
            .map_err(dec)?;
        reader.finish().map_err(|_| PlanError::Malformed)?;
        let plan = EffectPlan::new(principals.clone(), effects)?;
        // Canonical: nothing dropped, nothing reordered.
        if plan.principals != principals || plan.encode()? != octets {
            return Err(PlanError::Malformed);
        }
        Ok(plan)
    }

    /// The plan's digest (module documentation).
    ///
    /// # Errors
    /// [`PlanError::TooLarge`] beyond [`MAX_PLAN`] octets.
    pub fn digest(&self) -> Result<[u8; 32], PlanError> {
        Ok(plan_digest(&self.encode()?))
    }
}

/// The digest of a plan's canonical encoding `octets`: SHA-256 over
/// [`PLAN_DIGEST_LABEL`] ‖ `octets` (module documentation).
/// Spec: FIPS 180-4 §6.2 (via the approved `sha2`, its one-shot
/// `Digest::digest` as crate::digest calls it); docs/52 §5 item 1 (label).
#[must_use]
pub fn plan_digest(octets: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(PLAN_DIGEST_LABEL.len() + octets.len());
    input.extend_from_slice(PLAN_DIGEST_LABEL);
    input.extend_from_slice(octets);
    <[u8; 32]>::from(Sha256::digest(&input))
}
