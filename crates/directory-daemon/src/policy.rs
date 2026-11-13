//! The policy store dird loads at start: for now ONLY the clearly marked,
//! UNSIGNED development format.
//!
//! The signed policy store is decided in principle (Q-219 → A-57: "a
//! hand-defined format with the same discipline as the IPC codec + fuzz
//! target; signature with a tier-0 key"), but its format, signature
//! algorithm, key custody and reload semantics are not defined anywhere yet
//! (docs/50 §7.2: "not found in any document"). Until they are, dird loads a
//! development file that **says** what it is — its first octets are the
//! marker [`MARKER`] — and only when the configuration names the format
//! explicitly (`policy_store_format = unsigned-development`, crates/config);
//! the daemon prints a fixed WARNING at every start. No signature is
//! verified and nothing here may be trusted in production
//! (docs/questions/Q-270 item 2).
//!
//! # Format (the discipline of the IPC codec, docs/50 §3.3; A-57)
//!
//! ```text
//! file      := marker[24] ‖ format:u8 ‖ policy_version:u64
//!              ‖ principals: seq<principal, 4096> ‖ subtrees: seq<subtree, 256>
//! marker    := "UNSIGNED-DEV-DIRD-POLICY" (24 ASCII octets)
//! format    := 1
//! principal := sid: bytes<68> ‖ tier: u8           ; strictly ascending SID order
//! subtree   := dn: seq<bytes<255>, 64> ‖ tier: u8  ; RDN components leaf first
//! tier      := 0x00 Tier0 | 0x01 Tier1 | 0x02 Tier2 ; (Untiered is no classification)
//! ```
//!
//! Every primitive is ipc's (fixed-width big-endian integers, `u32`-counted
//! sequences and byte strings under a bound, no trailing octet); the file is
//! at most [`MAX_POLICY_FILE`] octets and is bounded before it is read
//! whole. The content rules: each SID decodes strictly ([MS-DTYP] 2.4.2.2)
//! and appears once, in ascending order (so the map has one encoding); each
//! subtree DN has at least one component (a DN with none would classify the
//! whole directory — directory-pip `TierMap::new` refuses it too), each
//! component is printable ASCII of the form `att=value` (the directory's own
//! canonical DN form, directory-pip `DirectoryView::dn_of`), and no DN
//! appears twice. Anything else refuses the file — dird does not start
//! (fail closed).
//!
//! The kdc's `PolicySnapshot` rules are **not** in this format: the kdc
//! daemon (P9) needs them from "the same file" (docs/50 §7.2) — part of the
//! Q-219 gap (docs/questions/Q-270 item 2).
//!
//! Spec: docs/50 §3.3, §3.4 (policy version per view), §7.2, §9
//! (`policy_store` fuzz target); docs/06 §9; docs/47 §6.3 (R47-9); A-36
//! (SID → tier and subtree → tier in the policy store); docs/questions/Q-219
//! (A-57), Q-270.

use core::fmt;
use directory_pip::TierMap;
use dtyp::Sid;
use ipc::{decode_payload, encode_payload, FrameLimit, Payload, Reader, Writer};
use pdp::{Dn, PolicyVersion, Tier};
use std::collections::{BTreeMap, BTreeSet};

/// The marker that opens every development policy file: a file without it is
/// not an unsigned development policy and is refused.
/// Spec: docs/questions/Q-270 item 2 ("clearly marked").
pub const MARKER: &[u8; 24] = b"UNSIGNED-DEV-DIRD-POLICY";

/// The one format number this build reads.
/// Spec: docs/50 §3.3 ("exact version … no negotiation").
pub const FORMAT: u8 = 1;

/// Largest policy file: 1 MiB. Project choice (AGENTS.md §6: bounded).
pub const MAX_POLICY_FILE: u32 = 1024 * 1024;

/// Most `SID → tier` entries. Project choice.
pub const MAX_PRINCIPALS: u32 = 4096;

/// Most `subtree → tier` entries. Project choice.
pub const MAX_SUBTREES: u32 = 256;

/// Most RDN components of a subtree DN (directory-pip `MAX_DN_DEPTH`).
pub const MAX_DN_COMPONENTS: u32 = 64;

/// Bound of one RDN component: [MS-ADTS] 3.1.1.5.1.2 "The RDN size MUST be
/// less than 255 characters" (A-30: counted as `att=val`).
pub const MAX_COMPONENT: u32 = 255;

/// Bound of a SID packet: 8 + 4 × 15 octets ([MS-DTYP] 2.4.2.2).
const MAX_SID: u32 = 8 + 4 * 15;

/// The writer's bound for a whole file.
const FILE_LIMIT: FrameLimit = match FrameLimit::new(MAX_POLICY_FILE) {
    Some(limit) => limit,
    None => panic!("MAX_POLICY_FILE is outside the ipc FrameLimit range"),
};

const _: () = assert!(MAX_DN_COMPONENTS as usize == directory_pip::MAX_DN_DEPTH);
const _: () = assert!(MAX_SID as usize == 8 + 4 * dtyp::SID_MAX_SUB_AUTHORITIES);

/// Why a policy file was refused. Carries no file content (docs/50 §8.2).
/// Spec: docs/50 §7.2 ("invalid … ⇒ do not start").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// The file is longer than [`MAX_POLICY_FILE`].
    TooLarge,
    /// The file does not start with [`MARKER`].
    NotMarked,
    /// The format number is not [`FORMAT`].
    Format,
    /// The structure did not decode (truncated, over a bound, trailing
    /// octets, an unknown tier code).
    Structure(ipc::Error),
    /// A SID did not decode, or the SIDs are not strictly ascending.
    Principal,
    /// A subtree DN is empty, a component is not printable `att=value`, or a
    /// DN appears twice.
    Subtree,
    /// An entry classifies as Untiered (no classification).
    Untiered,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::TooLarge => f.write_str("policy file too large"),
            PolicyError::NotMarked => {
                f.write_str("policy file is not marked as an unsigned development policy")
            }
            PolicyError::Format => f.write_str("policy file format number not supported"),
            PolicyError::Structure(error) => write!(f, "policy file malformed: {error}"),
            PolicyError::Principal => f.write_str("policy file principal entries invalid"),
            PolicyError::Subtree => f.write_str("policy file subtree entries invalid"),
            PolicyError::Untiered => f.write_str("policy file entry classifies as Untiered"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// A tier code of the file. Spec: crates/ipc-directory code table (the same
/// codes); A-36.
const fn tier_code(tier: Tier) -> u8 {
    ipc_directory::channel::codes::tier(tier)
}

/// The file's raw fields.
struct RawPolicy {
    format: u8,
    version: u64,
    principals: Vec<(Vec<u8>, Tier)>,
    subtrees: Vec<(Vec<Vec<u8>>, Tier)>,
}

impl Payload for RawPolicy {
    /// Spec: module docs; docs/50 §3.3.
    fn write_fields(&self, writer: &mut Writer) -> ipc::Result<()> {
        writer.write_array(MARKER)?;
        writer.write_u8(self.format)?;
        writer.write_u64(self.version)?;
        writer.write_seq(&self.principals, MAX_PRINCIPALS, |w, (sid, tier)| {
            w.write_bytes(sid, MAX_SID)?;
            w.write_enum(tier_code(*tier))
        })?;
        writer.write_seq(&self.subtrees, MAX_SUBTREES, |w, (dn, tier)| {
            w.write_seq(dn, MAX_DN_COMPONENTS, |w, c| {
                w.write_bytes(c, MAX_COMPONENT)
            })?;
            w.write_enum(tier_code(*tier))
        })
    }

    /// Spec: module docs; docs/50 §3.3.
    fn read_fields(reader: &mut Reader<'_>) -> ipc::Result<RawPolicy> {
        let marker = reader.read_array::<24>()?;
        if &marker != MARKER {
            // Reported as `NotMarked` by `decode` (checked first there).
            return Err(ipc::Error::UnknownCode);
        }
        let format = reader.read_u8()?;
        let version = reader.read_u64()?;
        let principals = reader.read_seq(MAX_PRINCIPALS, |r| {
            let sid = r.read_bytes(MAX_SID)?.to_vec();
            let tier = r.read_enum(ipc_directory::channel::codes::tier_from)?;
            Ok((sid, tier))
        })?;
        let subtrees = reader.read_seq(MAX_SUBTREES, |r| {
            let dn = r.read_seq(MAX_DN_COMPONENTS, |r| {
                Ok(r.read_bytes(MAX_COMPONENT)?.to_vec())
            })?;
            let tier = r.read_enum(ipc_directory::channel::codes::tier_from)?;
            Ok((dn, tier))
        })?;
        Ok(RawPolicy {
            format,
            version,
            principals,
            subtrees,
        })
    }
}

/// An RDN component of the directory's canonical form: printable ASCII,
/// `att=value` with both sides non-empty.
/// Spec: [MS-ADTS] 3.1.1.1.4 (RDN "att=val"); docs/47 §8.2; directory-pip
/// `DirectoryView::dn_of`.
fn component(octets: &[u8]) -> Result<String, PolicyError> {
    if !octets.iter().all(|b| (0x20..=0x7E).contains(b)) {
        return Err(PolicyError::Subtree);
    }
    let text = core::str::from_utf8(octets).map_err(|_| PolicyError::Subtree)?;
    match text.split_once('=') {
        Some((att, value)) if !att.is_empty() && !value.is_empty() => Ok(text.to_owned()),
        _ => Err(PolicyError::Subtree),
    }
}

/// The unsigned development policy: its version and its tier map entries.
/// Spec: docs/50 §3.4, §7.2; A-36; Q-270 item 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevelopmentPolicy {
    /// The policy version every view carries (R50-2).
    pub version: PolicyVersion,
    /// `SID → tier`.
    pub principals: BTreeMap<Sid, Tier>,
    /// `DN subtree → tier`, in file order.
    pub subtrees: Vec<(Dn, Tier)>,
}

impl DevelopmentPolicy {
    /// Decode a whole policy file (module docs).
    ///
    /// # Errors
    /// [`PolicyError`].
    ///
    /// Spec: module docs; docs/50 §3.3, §7.2.
    pub fn decode(file: &[u8]) -> Result<DevelopmentPolicy, PolicyError> {
        if file.len() > MAX_POLICY_FILE as usize {
            return Err(PolicyError::TooLarge);
        }
        if file.get(..MARKER.len()) != Some(MARKER.as_slice()) {
            return Err(PolicyError::NotMarked);
        }
        let raw: RawPolicy = decode_payload(file).map_err(PolicyError::Structure)?;
        if raw.format != FORMAT {
            return Err(PolicyError::Format);
        }
        let mut principals = BTreeMap::new();
        let mut last: Option<Sid> = None;
        for (packet, tier) in &raw.principals {
            let sid = Sid::decode(packet).map_err(|_| PolicyError::Principal)?;
            if last.is_some_and(|previous| previous >= sid) {
                return Err(PolicyError::Principal);
            }
            if *tier == Tier::Untiered {
                return Err(PolicyError::Untiered);
            }
            principals.insert(sid, *tier);
            last = Some(sid);
        }
        let mut seen = BTreeSet::new();
        let mut subtrees = Vec::with_capacity(raw.subtrees.len());
        for (components, tier) in &raw.subtrees {
            if components.is_empty() {
                return Err(PolicyError::Subtree);
            }
            let rdns = components
                .iter()
                .map(|c| component(c))
                .collect::<Result<Vec<_>, _>>()?;
            if !seen.insert(rdns.clone()) {
                return Err(PolicyError::Subtree);
            }
            if *tier == Tier::Untiered {
                return Err(PolicyError::Untiered);
            }
            subtrees.push((Dn::new(rdns), *tier));
        }
        Ok(DevelopmentPolicy {
            version: PolicyVersion(raw.version),
            principals,
            subtrees,
        })
    }

    /// Encode the policy as a file (for the development tooling and tests).
    ///
    /// # Errors
    /// `ipc::Error` when a bound is exceeded; [`PolicyError`] when an entry
    /// breaks a content rule (an Untiered entry, an empty DN).
    ///
    /// Spec: module docs.
    pub fn encode(&self) -> Result<Vec<u8>, PolicyError> {
        if self
            .principals
            .values()
            .chain(self.subtrees.iter().map(|(_, tier)| tier))
            .any(|tier| *tier == Tier::Untiered)
        {
            return Err(PolicyError::Untiered);
        }
        if self.subtrees.iter().any(|(dn, _)| dn.rdns().is_empty()) {
            return Err(PolicyError::Subtree);
        }
        let raw = RawPolicy {
            format: FORMAT,
            version: self.version.0,
            principals: self
                .principals
                .iter()
                .map(|(sid, tier)| (sid.encode(), *tier))
                .collect(),
            subtrees: self
                .subtrees
                .iter()
                .map(|(dn, tier)| {
                    (
                        dn.rdns().iter().map(|c| c.as_bytes().to_vec()).collect(),
                        *tier,
                    )
                })
                .collect(),
        };
        encode_payload(&raw, FILE_LIMIT)
            .map(|octets| octets.to_vec())
            .map_err(PolicyError::Structure)
    }

    /// The tier map the views carry.
    ///
    /// # Errors
    /// [`PolicyError::Subtree`] if directory-pip refuses the map (an empty
    /// DN — already refused by [`DevelopmentPolicy::decode`]).
    ///
    /// Spec: docs/47 §6.3 (R47-9); A-36.
    pub fn tier_map(&self) -> Result<TierMap, PolicyError> {
        TierMap::new(self.principals.clone(), self.subtrees.clone())
            .map_err(|_| PolicyError::Subtree)
    }
}
