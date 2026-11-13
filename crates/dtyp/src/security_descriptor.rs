//! SECURITY_DESCRIPTOR in self-relative form.
//!
//! Spec: [MS-DTYP] 2.4.6. Fixed portion (20 bytes): Revision (1, MUST be 1),
//! Sbz1 (1), Control (2), OffsetOwner, OffsetGroup, OffsetSacl, OffsetDacl
//! (4 each), then the pointer target fields OwnerSid, GroupSid, Sacl, Dacl at
//! those offsets, in any order. A self-relative descriptor "is sent in
//! little-endian format and requires no padding".
//!
//! Decoding validates every offset and size against the input before use:
//! each non-zero offset must lie after the fixed portion and inside the input,
//! each component is parsed bounded by the input, the present flags and
//! offsets must agree (SP/OffsetSacl, DP/OffsetDacl), the SACL / DACL ACE-type
//! rules of 2.4.5 are applied, and the components must neither overlap nor
//! leave unreferenced bytes (project strictness, Q-024).
//!
//! Encoding is canonical: the fixed portion, then Sacl, Dacl, OwnerSid,
//! GroupSid, back to back. That is the order of the worked example in
//! [MS-DTYP] 2.5.1.4 and the order product note <72> to 2.4.6 says Windows
//! typically presents.
//!
//! What a descriptor *means* — e.g. that an absent DACL (DP clear) grants all
//! access while an empty DACL grants none (2.5.3.2) — is the access-check
//! layer's concern; this type only carries the structure faithfully.

use crate::acl::Acl;
use crate::error::{Error, Result};
use crate::reader::Reader;
use crate::sid::Sid;

/// Size of the fixed portion. Spec: [MS-DTYP] 2.4.6.
pub const SD_FIXED_LEN: usize = 20;

/// The only valid SECURITY_DESCRIPTOR revision. Spec: [MS-DTYP] 2.4.6
/// ("This field MUST be set to one").
pub const SECURITY_DESCRIPTOR_REVISION: u8 = 1;

/// The 16-bit Control field. Spec: [MS-DTYP] 2.4.6.
///
/// Bit values: the 2.4.6 Control figure lists the bits from position 0 (the
/// most significant, per the packet convention of 2.1) as SR RM PS PD SI DI
/// SC DC SS DT SD SP DD DP GD OD; the worked example in 2.5.1.4 confirms it
/// (Control 0xB014 = SR, PS, PD, SP, DP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Control(pub u16);

impl Control {
    /// SR — Self-Relative. MUST be set in self-relative form.
    pub const SELF_RELATIVE: u16 = 0x8000;
    /// RM — RM Control Valid (Sbz1 holds resource manager control bits).
    pub const RM_CONTROL_VALID: u16 = 0x4000;
    /// PS — SACL Protected.
    pub const SACL_PROTECTED: u16 = 0x2000;
    /// PD — DACL Protected.
    pub const DACL_PROTECTED: u16 = 0x1000;
    /// SI — SACL Auto-Inherited.
    pub const SACL_AUTO_INHERITED: u16 = 0x0800;
    /// DI — DACL Auto-Inherited.
    pub const DACL_AUTO_INHERITED: u16 = 0x0400;
    /// SC — SACL Computed Inheritance Required.
    pub const SACL_COMPUTED_INHERITANCE_REQUIRED: u16 = 0x0200;
    /// DC — DACL Computed Inheritance Required.
    pub const DACL_COMPUTED_INHERITANCE_REQUIRED: u16 = 0x0100;
    /// SS — Server Security.
    pub const SERVER_SECURITY: u16 = 0x0080;
    /// DT — DACL Trusted.
    pub const DACL_TRUSTED: u16 = 0x0040;
    /// SD — SACL Defaulted.
    pub const SACL_DEFAULTED: u16 = 0x0020;
    /// SP — SACL Present.
    pub const SACL_PRESENT: u16 = 0x0010;
    /// DD — DACL Defaulted.
    pub const DACL_DEFAULTED: u16 = 0x0008;
    /// DP — DACL Present.
    pub const DACL_PRESENT: u16 = 0x0004;
    /// GD — Group Defaulted.
    pub const GROUP_DEFAULTED: u16 = 0x0002;
    /// OD — Owner Defaulted.
    pub const OWNER_DEFAULTED: u16 = 0x0001;

    /// `true` if every bit of `bits` is set.
    #[must_use]
    pub fn contains(self, bits: u16) -> bool {
        self.0 & bits == bits
    }
}

/// A security descriptor (self-relative form on the wire).
///
/// Spec: [MS-DTYP] 2.4.6. `None` for a component means its offset is zero and
/// the field is not present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptor {
    /// Sbz1: resource manager control bits when RM is set, otherwise without
    /// meaning; carried unchanged. Spec: [MS-DTYP] 2.4.6.
    pub sbz1: u8,
    /// Control. Spec: [MS-DTYP] 2.4.6.
    pub control: Control,
    /// OwnerSid. Spec: [MS-DTYP] 2.4.6.
    pub owner_sid: Option<Sid>,
    /// GroupSid. Spec: [MS-DTYP] 2.4.6.
    pub group_sid: Option<Sid>,
    /// Sacl; present iff SP is set. Spec: [MS-DTYP] 2.4.6.
    pub sacl: Option<Acl>,
    /// Dacl; present iff DP is set. Spec: [MS-DTYP] 2.4.6.
    pub dacl: Option<Acl>,
}

impl SecurityDescriptor {
    /// Decode a self-relative security descriptor occupying all of `input`.
    ///
    /// Spec: [MS-DTYP] 2.4.6, 2.4.5; layout strictness per Q-024.
    pub fn decode(input: &[u8]) -> Result<SecurityDescriptor> {
        let mut r = Reader::new(input);
        let revision = r.u8(Error::SdTruncated)?;
        let sbz1 = r.u8(Error::SdTruncated)?;
        let control = Control(r.u16_le(Error::SdTruncated)?);
        let offset_owner = r.u32_le(Error::SdTruncated)?;
        let offset_group = r.u32_le(Error::SdTruncated)?;
        let offset_sacl = r.u32_le(Error::SdTruncated)?;
        let offset_dacl = r.u32_le(Error::SdTruncated)?;

        // Revision MUST be one. Spec: [MS-DTYP] 2.4.6.
        if revision != SECURITY_DESCRIPTOR_REVISION {
            return Err(Error::SdRevision);
        }
        check_flags(
            control,
            offset_owner != 0,
            offset_group != 0,
            offset_sacl != 0,
            offset_dacl != 0,
        )?;

        let mut layout = Layout::default();
        let owner_sid = match offset_owner {
            0 => None,
            offset => Some(layout.sid_at(input, offset)?),
        };
        let group_sid = match offset_group {
            0 => None,
            offset => Some(layout.sid_at(input, offset)?),
        };
        let sacl = match offset_sacl {
            0 => None,
            offset => {
                let acl = layout.acl_at(input, offset)?;
                acl.check_sacl()?;
                Some(acl)
            }
        };
        let dacl = match offset_dacl {
            0 => None,
            offset => {
                let acl = layout.acl_at(input, offset)?;
                acl.check_dacl()?;
                Some(acl)
            }
        };
        layout.check_cover(input.len())?;

        Ok(SecurityDescriptor {
            sbz1,
            control,
            owner_sid,
            group_sid,
            sacl,
            dacl,
        })
    }

    /// Check that this value can be encoded: the same rules the decoder
    /// applies to the flags and to the SACL / DACL contents.
    ///
    /// Spec: [MS-DTYP] 2.4.6, 2.4.5, 2.4.3.
    pub fn validate(&self) -> Result<()> {
        check_flags(
            self.control,
            self.owner_sid.is_some(),
            self.group_sid.is_some(),
            self.sacl.is_some(),
            self.dacl.is_some(),
        )?;
        if let Some(sacl) = &self.sacl {
            sacl.check_sacl()?;
        }
        if let Some(dacl) = &self.dacl {
            dacl.check_dacl()?;
        }
        Ok(())
    }

    /// Length of the canonical encoding. Spec: [MS-DTYP] 2.4.6.
    pub fn encoded_len(&self) -> Result<usize> {
        self.validate()?;
        let mut size = SD_FIXED_LEN;
        if let Some(sacl) = &self.sacl {
            size += sacl.encoded_len()?;
        }
        if let Some(dacl) = &self.dacl {
            size += dacl.encoded_len()?;
        }
        if let Some(sid) = &self.owner_sid {
            size += sid.encoded_len();
        }
        if let Some(sid) = &self.group_sid {
            size += sid.encoded_len();
        }
        Ok(size)
    }

    /// The canonical self-relative encoding: fixed portion, then Sacl, Dacl,
    /// OwnerSid, GroupSid, with no gaps.
    ///
    /// Spec: [MS-DTYP] 2.4.6; order as in the 2.5.1.4 example and note <72>.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let total = self.encoded_len()?;
        // Component sizes, in canonical order. All bounded: an ACL is at most
        // 65535 bytes and a SID at most 68, so every offset fits 32 bits.
        let sacl = match &self.sacl {
            Some(acl) => Some(acl.encode()?),
            None => None,
        };
        let dacl = match &self.dacl {
            Some(acl) => Some(acl.encode()?),
            None => None,
        };
        let owner = self.owner_sid.as_ref().map(Sid::encode);
        let group = self.group_sid.as_ref().map(Sid::encode);

        let mut next = SD_FIXED_LEN;
        let mut place = |part: &Option<Vec<u8>>| -> Result<u32> {
            match part {
                None => Ok(0),
                Some(bytes) => {
                    let offset = u32::try_from(next).map_err(|_| Error::OffsetOutOfRange)?;
                    next += bytes.len();
                    Ok(offset)
                }
            }
        };
        let offset_sacl = place(&sacl)?;
        let offset_dacl = place(&dacl)?;
        let offset_owner = place(&owner)?;
        let offset_group = place(&group)?;

        let mut out = Vec::with_capacity(total);
        out.push(SECURITY_DESCRIPTOR_REVISION);
        out.push(self.sbz1);
        out.extend_from_slice(&self.control.0.to_le_bytes());
        out.extend_from_slice(&offset_owner.to_le_bytes());
        out.extend_from_slice(&offset_group.to_le_bytes());
        out.extend_from_slice(&offset_sacl.to_le_bytes());
        out.extend_from_slice(&offset_dacl.to_le_bytes());
        for bytes in [&sacl, &dacl, &owner, &group].into_iter().flatten() {
            out.extend_from_slice(bytes);
        }
        Ok(out)
    }
}

/// The Control-versus-offset rules of [MS-DTYP] 2.4.6, shared by the decoder
/// (from offsets) and the encoder (from which components are present).
fn check_flags(
    control: Control,
    has_owner: bool,
    has_group: bool,
    has_sacl: bool,
    has_dacl: bool,
) -> Result<()> {
    // "The Self Relative (SR) bit MUST be set". Spec: [MS-DTYP] 2.4.6.
    if !control.contains(Control::SELF_RELATIVE) {
        return Err(Error::SdNotSelfRelative);
    }
    // OffsetSacl: valid if SP is set; "if the SP flag is not set, this field
    // MUST be set to zero"; Sacl "MUST be present if the SP flag is set".
    match (control.contains(Control::SACL_PRESENT), has_sacl) {
        (false, true) => return Err(Error::SaclOffsetWithoutPresentFlag),
        (true, false) => return Err(Error::SaclPresentWithoutOffset),
        _ => {}
    }
    // OffsetDacl: the same rules with DP. Spec: [MS-DTYP] 2.4.6.
    match (control.contains(Control::DACL_PRESENT), has_dacl) {
        (false, true) => return Err(Error::DaclOffsetWithoutPresentFlag),
        (true, false) => return Err(Error::DaclPresentWithoutOffset),
        _ => {}
    }
    // Spec: [MS-DTYP] 2.4.6 — OffsetOwner / OffsetGroup "must be a valid
    // offset if the OD / GD flag is not set", so a zero offset with OD / GD
    // clear is rejected (Q-023, resolved). Partial descriptors sent with the
    // LDAP SD_FLAGS control are a directory-layer case, to be defined later
    // from [MS-ADTS] — not accepted here.
    if !has_owner && !control.contains(Control::OWNER_DEFAULTED) {
        return Err(Error::OwnerAbsentNotDefaulted);
    }
    if !has_group && !control.contains(Control::GROUP_DEFAULTED) {
        return Err(Error::GroupAbsentNotDefaulted);
    }
    Ok(())
}

/// The byte ranges `[start, end)` the components occupy, for the overlap and
/// coverage checks (at most four components).
#[derive(Default)]
struct Layout {
    ranges: [(usize, usize); 4],
    count: usize,
}

impl Layout {
    /// Validate a non-zero offset against the input. Spec: [MS-DTYP] 2.4.6.
    fn start(input: &[u8], offset: u32) -> Result<usize> {
        let start = usize::try_from(offset).map_err(|_| Error::OffsetOutOfRange)?;
        // Offsets locate pointer target fields after the fixed portion.
        if start < SD_FIXED_LEN {
            return Err(Error::OffsetIntoHeader);
        }
        // "must be a valid offset": inside the input.
        if start >= input.len() {
            return Err(Error::OffsetOutOfRange);
        }
        Ok(start)
    }

    fn record(&mut self, start: usize, len: usize) {
        // At most four components call this (owner, group, SACL, DACL).
        self.ranges[self.count] = (start, start + len);
        self.count += 1;
    }

    /// Decode the SID at `offset`, bounded by the input. Spec: [MS-DTYP] 2.4.6.
    fn sid_at(&mut self, input: &[u8], offset: u32) -> Result<Sid> {
        let start = Layout::start(input, offset)?;
        let (sid, len) = Sid::decode_prefix(&input[start..])?;
        self.record(start, len);
        Ok(sid)
    }

    /// Decode the ACL at `offset`, bounded by the input. Spec: [MS-DTYP] 2.4.6.
    fn acl_at(&mut self, input: &[u8], offset: u32) -> Result<Acl> {
        let start = Layout::start(input, offset)?;
        let (acl, len) = Acl::decode_prefix(&input[start..])?;
        self.record(start, len);
        Ok(acl)
    }

    /// Require the components to tile the bytes after the fixed portion
    /// exactly: no overlap, no gap, no trailing data. Project strictness on
    /// top of [MS-DTYP] 2.4.6 ("requires no padding") — Q-024.
    fn check_cover(&mut self, total_len: usize) -> Result<()> {
        let ranges = &mut self.ranges[..self.count];
        ranges.sort_unstable();
        let mut expected = SD_FIXED_LEN;
        for &(start, end) in ranges.iter() {
            if start < expected {
                return Err(Error::ComponentsOverlap);
            }
            if start > expected {
                return Err(Error::UnreferencedBytes);
            }
            expected = end;
        }
        if expected != total_len {
            return Err(Error::UnreferencedBytes);
        }
        Ok(())
    }
}
