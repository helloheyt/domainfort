//! ACCESS_MASK and the bit definitions the directory needs.
//!
//! Spec: [MS-DTYP] 2.4.3 (ACCESS_MASK is a 32-bit set of flags; Figure 2
//! "Access mask bitmap table" and the value table that follows it).
//!
//! Bit positions in Figure 2 use the packet convention of [MS-DTYP] 2.1:
//! position 0 is the most significant bit. Figure 2 places GR, GW, GX, GA at
//! positions 0-3, MA at 6, AS at 7, SY at 11, WO at 12, WD at 13, RC at 14 and
//! DE at 15; positions 16-31 ("X") are object-specific.
//!
//! Note on GENERIC_WRITE: the 2.4.3 value table prints "0x4000000L" (seven hex
//! digits), which would be bit position 5 — a position Figure 2 marks
//! reserved. Figure 2 (position 1) and the SDDL table in 2.5.1.1 ("GW" Generic
//! Write 0x40000000) both give 0x40000000, which is used here.
//!
//! The directory-object rights are the ones [MS-DTYP] itself defines:
//! the six ADS_RIGHT_DS_* values of 2.4.4.3, and the three further
//! "Directory Object" rights of the 2.5.1.1 object-specific-rights table.
//! Mapping of generic rights and the meaning of rights in an access check are
//! the access-check layer's concern (2.5.3), not this crate's.

/// A 32-bit ACCESS_MASK. Spec: [MS-DTYP] 2.4.3 (`typedef DWORD ACCESS_MASK`).
///
/// In a self-relative security descriptor it is carried little-endian
/// (Spec: [MS-DTYP] 2.4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AccessMask(pub u32);

impl AccessMask {
    // ---- Generic rights (positions 0-3). Spec: [MS-DTYP] 2.4.3. ----

    /// GR — GENERIC_READ. Spec: [MS-DTYP] 2.4.3.
    pub const GENERIC_READ: u32 = 0x8000_0000;
    /// GW — GENERIC_WRITE. Spec: [MS-DTYP] 2.4.3 Figure 2 (position 1);
    /// 2.5.1.1 (see the module note on the table's typo).
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    /// GX — GENERIC_EXECUTE. Spec: [MS-DTYP] 2.4.3.
    pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
    /// GA — GENERIC_ALL. Spec: [MS-DTYP] 2.4.3.
    pub const GENERIC_ALL: u32 = 0x1000_0000;

    // ---- Positions 6 and 7. Spec: [MS-DTYP] 2.4.3. ----

    /// MA — MAXIMUM_ALLOWED. Only requested, never meaningful in an ACE.
    /// Spec: [MS-DTYP] 2.4.3.
    pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    /// AS — ACCESS_SYSTEM_SECURITY. MUST NOT be set in a DACL ACE.
    /// Spec: [MS-DTYP] 2.4.3.
    pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;

    // ---- Standard rights (positions 11-15). Spec: [MS-DTYP] 2.4.3. ----

    /// SY — SYNCHRONIZE. Spec: [MS-DTYP] 2.4.3.
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
    /// WO — WRITE_OWNER. Spec: [MS-DTYP] 2.4.3.
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    /// WD — WRITE_DACL. Spec: [MS-DTYP] 2.4.3.
    pub const WRITE_DACL: u32 = 0x0004_0000;
    /// RC — READ_CONTROL. Spec: [MS-DTYP] 2.4.3.
    pub const READ_CONTROL: u32 = 0x0002_0000;
    /// DE — DELETE. Spec: [MS-DTYP] 2.4.3.
    pub const DELETE: u32 = 0x0001_0000;

    // ---- Directory-object rights (object-specific, low 16 bits). ----

    /// ADS_RIGHT_DS_CREATE_CHILD. Spec: [MS-DTYP] 2.4.4.3; 2.5.1.1 ("CC").
    pub const ADS_RIGHT_DS_CREATE_CHILD: u32 = 0x0000_0001;
    /// ADS_RIGHT_DS_DELETE_CHILD. Spec: [MS-DTYP] 2.4.4.3; 2.5.1.1 ("DC").
    pub const ADS_RIGHT_DS_DELETE_CHILD: u32 = 0x0000_0002;
    /// Directory Object "List Children". Spec: [MS-DTYP] 2.5.1.1 ("LC").
    pub const DIRECTORY_OBJECT_LIST_CHILDREN: u32 = 0x0000_0004;
    /// ADS_RIGHT_DS_SELF (validated write). Spec: [MS-DTYP] 2.4.4.3; 2.5.1.1 ("SW").
    pub const ADS_RIGHT_DS_SELF: u32 = 0x0000_0008;
    /// ADS_RIGHT_DS_READ_PROP. Spec: [MS-DTYP] 2.4.4.3; 2.5.1.1 ("RP").
    pub const ADS_RIGHT_DS_READ_PROP: u32 = 0x0000_0010;
    /// ADS_RIGHT_DS_WRITE_PROP. Spec: [MS-DTYP] 2.4.4.3; 2.5.1.1 ("WP").
    pub const ADS_RIGHT_DS_WRITE_PROP: u32 = 0x0000_0020;
    /// Directory Object "Delete Tree". Spec: [MS-DTYP] 2.5.1.1 ("DT").
    pub const DIRECTORY_OBJECT_DELETE_TREE: u32 = 0x0000_0040;
    /// Directory Object "List Object". Spec: [MS-DTYP] 2.5.1.1 ("LO").
    pub const DIRECTORY_OBJECT_LIST_OBJECT: u32 = 0x0000_0080;
    /// ADS_RIGHT_DS_CONTROL_ACCESS (extended right). Spec: [MS-DTYP] 2.4.4.3;
    /// 2.5.1.1 ("CR").
    pub const ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x0000_0100;

    /// `true` if every bit of `bits` is set in this mask.
    #[must_use]
    pub fn contains(self, bits: u32) -> bool {
        self.0 & bits == bits
    }
}
