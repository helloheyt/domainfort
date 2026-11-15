//! The persisted format of keyd's sealed key store (task KL1): one **key
//! record** per key set and one **store header**, with a hand-written,
//! strict, bounded codec.
//!
//! # What is where (r4-c §3.3)
//!
//! A key record is `associated data ‖ sealed body`:
//!
//! * the **associated data** ([`KeyRecordAad`]) is authenticated but not
//!   secret: the format version, the sealing suite (`alg_id`), the store id,
//!   the handle (principal id + purpose), the principal binding, and for each
//!   kept version (current, then the previous one if kept) its kvno, its
//!   **key source** and its encryption types;
//! * the **sealed body** is opaque to this module: the output of the
//!   suite's sealing of the plaintext body under the store wrapping key
//!   (SWK), with the associated data as the AEAD's associated data. Sealing
//!   and opening are keyd's (task KL3) — this crate links no crypto (D182).
//! * the **plaintext body** is the key material only: for each version in
//!   the order of the associated data, for each of its encryption types in
//!   order, the key octets. Every length in it follows from the associated
//!   data, so it carries no length field at all ([`parse_body`],
//!   [`encode_body_into`]).
//!
//! The store header is `header fields ‖ sealed tail`: the format version,
//! the suite, the store id, the generation **G**, the ceremony state, the
//! number of records and the **root digest** over the list of (handle,
//! record digest) of every record ([`root_digest_input`]); the sealed tail
//! is the suite's sealing of an empty plaintext with the header fields as
//! associated data (the header is authenticated, not secret). G is in the
//! header only: a record's associated data does not carry it, so a commit
//! does not reseal every record (r4-c §3.3).
//!
//! # Why each field is authenticated (classes C39, C5, C21; r4-c §9.1)
//!
//! Every property a type proves in memory is bound into the authenticated
//! bytes, so that a loaded record cannot enjoy a property no one proved
//! again: the key source (a password-derived version can never be read back
//! as keyd-drawn — only keyd-drawn versions open service tickets, Q-180
//! item 4), the binding (A-19), the handle and purpose (a record moved to
//! another handle or purpose fails its AEAD), the store id (a record of
//! another store fails), the format version and the suite (a downgrade is
//! refused, r4-c §8.3). Each object type begins with its own magic, so the
//! associated data of a header can never be taken for a record's, nor
//! either for the root-digest list (one key, separated purposes — the same
//! principle as RFC 3961 §2 key usage, applied to the associated data).
//!
//! # The suite registry is not chosen here (docs/questions/Q-906)
//!
//! The codec carries the suite as a code and refuses every code its
//! registry does not know (the floor, docs/38 §2; r4-c §8.3). The registry
//! itself — which AEAD and which digest a code names — is the crate that
//! links those primitives (keyd, task KL3), behind the [`SealingSuite`]
//! trait: no AEAD is approved for keyd yet (docs/research/r4-a §4 G1,
//! docs/questions/Q-840), so this module assigns no code.
//!
//! # Strictness (docs/CLEAN-ROOM.md)
//!
//! Every parser here checks the whole input against a fixed bound before it
//! reads a field, checks each length against its own bound **and** against
//! the remaining input before it takes any octet, allocates only after both
//! checks (and never for key material: the body is returned as views into
//! the caller's buffer), refuses every unknown code (format version, suite,
//! purpose, key source, encryption type, ceremony state), every
//! non-canonical encoding (a flag other than 0 or 1, a repeated encryption
//! type, a previous kvno not below the current one, a zero generation,
//! unordered digest entries) and every trailing octet. The encoders apply
//! the same rules, so anything encoded here also parses. Errors carry no
//! data ([`FormatError`]); nothing secret can reach one.
//!
//! # Not in this format (open)
//!
//! * The key source `MachineGenerated` of r4-c §3.3 has no code: its
//!   parameters are not fixed (a Windows machine password needs a salt,
//!   r4-c §4.1 K7; a Linux machine key does not, K8) and no installer
//!   produces it yet — docs/questions/Q-905. A record naming it is refused.
//! * Executed decision results (R4C-4) are persisted by KL3 in the same
//!   commit; their record format is KL3's (a new magic).
//!
//! Spec: docs/research/r4-c-key-lifecycle.md §3.3, §3.6, §3.7, §8.1, §8.3,
//! §9.1; PENDING-OWNER A-143; docs/10 §1; RFC 4120 §5.2.2, §5.2.9, §6.2;
//! RFC 3961 §8; RFC 3962 §4, §6, §7; RFC 8009 §2, §5, §7; docs/38 §1, §2
//! (D159); docs/CLEAN-ROOM.md

use crate::decision::CeremonyState;
use crate::enctype::EncTypeId;
use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalBinding, PrincipalId};
use core::fmt;
use krb_proto::limits::MAX_NAME_COMPONENTS;
use krb_proto::{KerberosString, PrincipalName};

/// The one format version this codec reads and writes. Every other value is
/// refused — a lower one is a downgrade, a higher one unknown (the floor;
/// fail closed).
/// Spec: r4-c §3.3 (`format_version` in the associated data: "a format
/// downgrade is refused (floor)"), §8.3.
pub const FORMAT_VERSION: u16 = 1;

/// The first four octets of every key record. A project constant: no
/// specification names this format.
/// Spec: r4-c §3.3; this module's documentation (one magic per object type).
pub const KEY_RECORD_MAGIC: [u8; 4] = *b"KYDR";

/// The first four octets of the store header. A project constant.
/// Spec: r4-c §3.3.
pub const STORE_HEADER_MAGIC: [u8; 4] = *b"KYDH";

/// The first four octets of the root-digest list ([`root_digest_input`]). A
/// project constant.
/// Spec: r4-c §3.3 ("root digest over the list of (handle, record digest)").
pub const ROOT_DIGEST_MAGIC: [u8; 4] = *b"KYDL";

/// Octets of a store id. Spec: r4-c §3.3 ("`store_id` (16 random bytes, set
/// in the ceremony)").
pub const STORE_ID_LEN: usize = 16;

/// Bound on the realm and on each name component of a binding, in octets.
/// Not an RFC 4120 rule (§5.2.1 bounds no KerberosString); a project choice
/// equal to the bound on a salt — docs/questions/Q-905 item 2.
/// Spec: RFC 4120 §5.2.1, §5.2.2; docs/CLEAN-ROOM.md
pub const MAX_NAME_OCTETS: usize = 1024;

/// Bound on a string-to-key salt, in octets: the bound the keyd channel puts
/// on the salt of `set_secret` (docs/50 §3.4; docs/questions/Q-245 item 7).
/// Spec: docs/50 §3.4; RFC 3961 §3 (salt).
pub const MAX_SALT_OCTETS: usize = 1024;

/// Octets of a string-to-key parameter block.
/// Spec: RFC 3962 §4 ("The parameter string is four octets"); RFC 8009 §4.
pub const S2K_PARAMS_LEN: usize = 4;

/// Versions a record keeps at most: the current one and the previous one.
/// Spec: docs/10 §1 ("keyd holds current + previous"); r4-c §3.3.
pub const MAX_VERSIONS: usize = 2;

/// Encryption types one version carries at most: the four AES types, each
/// at most once.
/// Spec: RFC 3962 §7; RFC 8009 §7; docs/10 §12 I5.
pub const MAX_RECORD_ENCTYPES: usize = EncTypeId::ALL.len();

/// Octets of the longest protocol key (256 bits).
/// Spec: RFC 3962 §6 ("128- or 256-bit string"); RFC 8009 §2, §5.
pub const MAX_KEY_OCTETS: usize = 32;

/// Bound on what a suite may add to a plaintext when sealing, in octets
/// (nonce, tag). A codec bound, not a cryptographic parameter: a registry
/// that declares more is refused ([`FormatError::BadSuiteParameters`]).
/// Spec: docs/CLEAN-ROOM.md (bounded); docs/questions/Q-906.
pub const MAX_SEAL_OVERHEAD: usize = 64;

/// Bound on a suite's record digest, in octets. A codec bound, like
/// [`MAX_SEAL_OVERHEAD`].
/// Spec: docs/CLEAN-ROOM.md; docs/questions/Q-906.
pub const MAX_DIGEST_OCTETS: usize = 64;

/// Bound on the number of key records of one store: the capacity of keyd's
/// development store (`keyd_daemon::startup::KEY_STORE_CAPACITY`), a
/// project choice (docs/questions/Q-230 item 12).
/// Spec: docs/CLEAN-ROOM.md; r4-c §3.3.
pub const MAX_KEY_RECORDS: usize = 4096;

/// Fixed octets at the start of a record's associated data: magic, format
/// version, suite, store id, principal id, purpose.
const RECORD_FIXED_OCTETS: usize = 4 + 2 + 2 + STORE_ID_LEN + 16 + 1;

/// Octets of the longest binding: realm length and realm, name-type,
/// component count, each component's length and octets.
const MAX_BINDING_OCTETS: usize =
    2 + MAX_NAME_OCTETS + 4 + 1 + MAX_NAME_COMPONENTS * (2 + MAX_NAME_OCTETS);

/// Octets of the longest version description: kvno, source, salt length and
/// salt, parameter flag and block, encryption-type count and numbers.
const MAX_VERSION_OCTETS: usize =
    4 + 1 + 2 + MAX_SALT_OCTETS + 1 + S2K_PARAMS_LEN + 1 + MAX_RECORD_ENCTYPES * 4;

/// Bound on a record's associated data, in octets.
/// Spec: docs/CLEAN-ROOM.md (the whole input is bounded before any field is read).
pub const MAX_RECORD_AAD_OCTETS: usize =
    RECORD_FIXED_OCTETS + MAX_BINDING_OCTETS + 1 + MAX_VERSIONS * MAX_VERSION_OCTETS;

/// Bound on a plaintext body, in octets: two versions of four 256-bit keys.
/// Spec: docs/10 §1; RFC 3962 §6; RFC 8009 §5.
pub const MAX_BODY_OCTETS: usize = MAX_VERSIONS * MAX_RECORD_ENCTYPES * MAX_KEY_OCTETS;

/// Bound on a whole key record, in octets.
/// Spec: docs/CLEAN-ROOM.md
pub const MAX_KEY_RECORD_OCTETS: usize =
    MAX_RECORD_AAD_OCTETS + MAX_BODY_OCTETS + MAX_SEAL_OVERHEAD;

/// Fixed octets of the header fields before the root digest: magic, format
/// version, suite, store id, generation, ceremony state, record count.
const HEADER_FIXED_OCTETS: usize = 4 + 2 + 2 + STORE_ID_LEN + 8 + 1 + 4;

/// Bound on the whole store header, in octets.
/// Spec: docs/CLEAN-ROOM.md
pub const MAX_STORE_HEADER_OCTETS: usize =
    HEADER_FIXED_OCTETS + MAX_DIGEST_OCTETS + MAX_SEAL_OVERHEAD;

/// The key-source code of a version keyd drew itself. Spec: r4-c §3.3
/// (`KeydDrawn`).
const SOURCE_KEYD_DRAWN: u8 = 1;
/// The key-source code of a version derived from a password. Spec: r4-c
/// §3.3 (`PasswordDerived{salt, s2k_params}`).
const SOURCE_PASSWORD_DERIVED: u8 = 2;
// No code for `MachineGenerated` (docs/questions/Q-905).

/// The ceremony code of `Provisioning`. Spec: r4-c §3.3, §3.7 step 6.
const CEREMONY_PROVISIONING: u8 = 1;
/// The ceremony code of a sealed store (`Sealed` in r4-c, read back as
/// [`CeremonyState::Operational`]). Spec: r4-c §3.3, §3.7 step 6.
const CEREMONY_SEALED: u8 = 2;

/// Why an encoding was refused. Carries no data — no field, octet or length
/// of the input reaches it (docs/CLEAN-ROOM.md: nothing secret in an error).
/// Spec: docs/CLEAN-ROOM.md; r4-c §3.7 step 5 ("every failure ⇒ keyd does not
/// start").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// The input ended before a field.
    Truncated,
    /// Octets follow the last field, or a length disagrees with what the
    /// associated data implies.
    BadLength,
    /// The input, or a field, exceeds its bound.
    TooLarge,
    /// The magic is not this object type's.
    BadMagic,
    /// The format version is not [`FORMAT_VERSION`].
    UnsupportedFormatVersion,
    /// The registry knows no suite of this code.
    UnknownSuite,
    /// The suite declares an overhead or digest length outside the codec's
    /// bounds.
    BadSuiteParameters,
    /// No [`KeyPurpose`] has this code.
    UnknownPurpose,
    /// No key source has this code (`MachineGenerated` included, Q-905).
    UnknownKeySource,
    /// The encryption type is not one of the four AES types.
    UnknownEncType,
    /// The ceremony code is unknown.
    UnknownCeremonyState,
    /// The realm or a name component is not KerberosString content, or the
    /// name has no component or too many.
    BadName,
    /// The salt is not UTF-8.
    BadSalt,
    /// A well-formed field breaks a canonical rule (a flag other than 0 / 1,
    /// a repeated encryption type, a previous kvno not below the current
    /// one, a zero generation, unordered or repeated digest entries).
    NonCanonical,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FormatError::Truncated => "truncated",
            FormatError::BadLength => "bad length",
            FormatError::TooLarge => "too large",
            FormatError::BadMagic => "bad magic",
            FormatError::UnsupportedFormatVersion => "unsupported format version",
            FormatError::UnknownSuite => "unknown suite",
            FormatError::BadSuiteParameters => "bad suite parameters",
            FormatError::UnknownPurpose => "unknown purpose",
            FormatError::UnknownKeySource => "unknown key source",
            FormatError::UnknownEncType => "unknown encryption type",
            FormatError::UnknownCeremonyState => "unknown ceremony state",
            FormatError::BadName => "bad name",
            FormatError::BadSalt => "bad salt",
            FormatError::NonCanonical => "non-canonical",
        })
    }
}

impl std::error::Error for FormatError {}

/// The registry of the store's sealing suites (D159: every persisted object
/// carries a suite id; r4-c §8.1, §8.3): what a code names — the AEAD that
/// seals the bodies and the header, and the digest of the root list — as
/// the lengths the format needs. Implemented by a **closed** type in the
/// crate that links the primitives (keyd, task KL3): `from_code` returns
/// `None` for every unregistered code, and the codec refuses it (the floor).
///
/// Spec: docs/38 §1, §2 (D159 — suite registry with a hard floor); r4-c
/// §3.3 (the AEAD's algorithm id in the associated data), §8.3;
/// docs/questions/Q-906 (no suite is registered yet).
pub trait SealingSuite: Copy + Eq + fmt::Debug {
    /// The suite registered under `code`; `None` for every other code.
    fn from_code(code: u16) -> Option<Self>;
    /// This suite's code.
    fn code(self) -> u16;
    /// Exactly how many octets sealing adds to a plaintext (≤
    /// [`MAX_SEAL_OVERHEAD`]).
    fn seal_overhead(self) -> usize;
    /// Exactly how many octets a record digest has (1 ..=
    /// [`MAX_DIGEST_OCTETS`]).
    fn digest_len(self) -> usize;
}

/// The suite of `code`, with its lengths inside the codec's bounds.
/// Spec: docs/38 §2 (floor); docs/CLEAN-ROOM.md
fn suite_of<S: SealingSuite>(code: u16) -> Result<S, FormatError> {
    let suite = S::from_code(code).ok_or(FormatError::UnknownSuite)?;
    check_suite(suite)?;
    Ok(suite)
}

/// The suite's lengths are inside the codec's bounds; the code maps back to
/// the suite. Spec: docs/CLEAN-ROOM.md
fn check_suite<S: SealingSuite>(suite: S) -> Result<(), FormatError> {
    let digest = suite.digest_len();
    let consistent = S::from_code(suite.code()) == Some(suite);
    if !consistent
        || suite.seal_overhead() > MAX_SEAL_OVERHEAD
        || digest == 0
        || digest > MAX_DIGEST_OCTETS
    {
        return Err(FormatError::BadSuiteParameters);
    }
    Ok(())
}

/// The id of one sealed key store: 16 octets drawn in the ceremony. A record
/// or header of another store carries another id and is refused (r4-c
/// §3.3). Not secret; `Debug` prints hex.
/// Spec: r4-c §3.3, §3.7 step 2.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StoreId([u8; STORE_ID_LEN]);

impl StoreId {
    /// Wrap 16 octets. Spec: r4-c §3.3.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; STORE_ID_LEN]) -> Self {
        StoreId(bytes)
    }

    /// The id octets.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; STORE_ID_LEN] {
        &self.0
    }
}

impl fmt::Debug for StoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoreId(")?;
        for octet in &self.0 {
            write!(f, "{octet:02x}")?;
        }
        f.write_str(")")
    }
}

/// Where a version's keys came from — the property r4-c §3.3 binds into the
/// associated data (class C39).
///
/// Spec: r4-c §3.3 (`KeydDrawn` / `PasswordDerived{salt, s2k_params}`),
/// §9.1 (C39); docs/10 §1 (`StoredKeySet { kvno, keys, salt, purpose }`);
/// docs/questions/Q-165 item 4 (A-46: only keyd-drawn versions open service
/// tickets); Q-905 (no `MachineGenerated` yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// keyd drew the keys itself (`create_key`, `rotate_key`,
    /// `rotate_krbtgt`); no one outside keyd knows them.
    /// Spec: docs/10 §7; RFC 3961 §3 (random-to-key).
    KeydDrawn,
    /// The keys were derived from a password with `salt` and, when given,
    /// the string-to-key parameters `s2k_params` (`set_secret`, the
    /// change-password completion).
    /// Spec: docs/10 §6; RFC 3961 §3 (string-to-key); RFC 3962 §4; RFC
    /// 8009 §4.
    PasswordDerived {
        /// The string-to-key salt (≤ [`MAX_SALT_OCTETS`] octets, UTF-8).
        salt: String,
        /// The string-to-key parameter block, when the keys were derived
        /// with explicit parameters.
        s2k_params: Option<[u8; S2K_PARAMS_LEN]>,
    },
}

/// One kept version of a key set, as the associated data describes it: no
/// key octet.
/// Spec: r4-c §3.3 ("for each version: `kvno`, source, enctypes"); RFC 4120
/// §5.2.9 (kvno UInt32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordVersion {
    /// The key version number.
    pub kvno: Kvno,
    /// Where the keys came from.
    pub source: KeySource,
    /// The version's encryption types, in preference order (the first seals
    /// tickets): 1 ..= [`MAX_RECORD_ENCTYPES`], each at most once.
    pub enctypes: Vec<EncTypeId>,
}

/// The associated data of one key record — every authenticated, non-secret
/// fact about the key set (module documentation).
///
/// Spec: r4-c §3.3 (the table of the record's fields), §9.1 (C39); A-143;
/// docs/10 §1; RFC 4120 §5.2.2 (Realm, PrincipalName), §6.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecordAad<S> {
    /// The sealing suite (`alg_id`).
    pub suite: S,
    /// The store the record belongs to.
    pub store_id: StoreId,
    /// The key set's handle: principal id and purpose.
    pub handle: KeyHandle,
    /// The principal name the key set is bound to (A-19).
    pub binding: PrincipalBinding,
    /// The current version.
    pub current: RecordVersion,
    /// The retained previous version, when kept; its kvno is below the
    /// current one's.
    pub previous: Option<RecordVersion>,
}

impl<S: SealingSuite> KeyRecordAad<S> {
    /// The associated data's octets — exactly what [`KeyRecord::parse`]
    /// reads back, and what the sealing authenticates.
    ///
    /// # Errors
    /// Any rule the parser applies ([`FormatError`]): a field over its
    /// bound, an unregistered suite, an empty or repeated encryption-type
    /// list, a previous kvno not below the current one, a name with no
    /// component.
    ///
    /// Spec: r4-c §3.3; docs/CLEAN-ROOM.md
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        check_suite(self.suite)?;
        check_versions(&self.current, self.previous.as_ref())?;
        let mut out = Writer::new();
        out.bytes(&KEY_RECORD_MAGIC);
        out.u16(FORMAT_VERSION);
        out.u16(self.suite.code());
        out.bytes(self.store_id.as_bytes());
        out.bytes(self.handle.principal.as_bytes());
        out.u8(purpose_code(self.handle.purpose));
        write_binding(&mut out, &self.binding)?;
        let count: u8 = if self.previous.is_some() { 2 } else { 1 };
        out.u8(count);
        write_version(&mut out, &self.current)?;
        if let Some(previous) = &self.previous {
            write_version(&mut out, previous)?;
        }
        let octets = out.finish();
        if octets.len() > MAX_RECORD_AAD_OCTETS {
            return Err(FormatError::TooLarge);
        }
        Ok(octets)
    }

    /// The length of the plaintext body: the key octets of every version and
    /// encryption type. Spec: RFC 3962 §6; RFC 8009 §5.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.versions()
            .flat_map(|v| v.enctypes.iter())
            .map(|e| record_key_octets(*e))
            .sum()
    }

    /// The length of the sealed body: the plaintext body plus the suite's
    /// overhead. Spec: r4-c §3.3.
    #[must_use]
    pub fn sealed_len(&self) -> usize {
        self.body_len().saturating_add(self.suite.seal_overhead())
    }

    /// The current version, then the previous one if kept.
    fn versions(&self) -> impl Iterator<Item = &RecordVersion> {
        core::iter::once(&self.current).chain(self.previous.as_ref())
    }
}

/// One parsed key record: its associated data, the exact octets that carry
/// it (what the opening authenticates) and the sealed body, both borrowed
/// from the input.
/// Spec: r4-c §3.3, §3.7 step 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord<'a, S> {
    aad: KeyRecordAad<S>,
    aad_octets: &'a [u8],
    sealed: &'a [u8],
}

impl<'a, S: SealingSuite> KeyRecord<'a, S> {
    /// Parse one whole key record. The sealed body must be exactly
    /// [`KeyRecordAad::sealed_len`] octets, and nothing may follow it.
    ///
    /// # Errors
    /// [`FormatError`] — every input this codec did not produce is refused
    /// (module documentation, "Strictness").
    ///
    /// Spec: r4-c §3.3, §3.7 step 5, §8.3; docs/CLEAN-ROOM.md
    pub fn parse(input: &'a [u8]) -> Result<Self, FormatError> {
        if input.len() > MAX_KEY_RECORD_OCTETS {
            return Err(FormatError::TooLarge);
        }
        let mut reader = Reader::new(input);
        let aad = read_record_aad::<S>(&mut reader)?;
        let aad_octets = input
            .get(..reader.position())
            .ok_or(FormatError::Truncated)?;
        let sealed = reader.rest();
        if sealed.len() != aad.sealed_len() {
            return Err(FormatError::BadLength);
        }
        Ok(KeyRecord {
            aad,
            aad_octets,
            sealed,
        })
    }

    /// The associated data. Spec: r4-c §3.3.
    #[must_use]
    pub fn aad(&self) -> &KeyRecordAad<S> {
        &self.aad
    }

    /// The associated data's octets as stored (canonical: equal to
    /// [`KeyRecordAad::encode`] of [`KeyRecord::aad`]).
    #[must_use]
    pub fn aad_octets(&self) -> &'a [u8] {
        self.aad_octets
    }

    /// The sealed body as stored.
    #[must_use]
    pub fn sealed(&self) -> &'a [u8] {
        self.sealed
    }
}

/// A whole key record: `aad ‖ sealed`.
///
/// # Errors
/// [`FormatError`] from [`KeyRecordAad::encode`]; [`FormatError::BadLength`]
/// when `sealed` is not exactly [`KeyRecordAad::sealed_len`] octets.
///
/// Spec: r4-c §3.3.
pub fn encode_record<S: SealingSuite>(
    aad: &KeyRecordAad<S>,
    sealed: &[u8],
) -> Result<Vec<u8>, FormatError> {
    if sealed.len() != aad.sealed_len() {
        return Err(FormatError::BadLength);
    }
    let mut octets = aad.encode()?;
    octets.extend_from_slice(sealed);
    Ok(octets)
}

/// The length of one protocol key of `enctype`: 16 octets for the 128-bit
/// types, 32 for the 256-bit ones. keyd's tests pin it to the crypto
/// profile's own key length (D182: this crate does not link it).
/// Spec: RFC 3962 §6 ("protocol key format: 128- or 256-bit string"), §7
/// (key size 128 / 256 for etypes 17 / 18); RFC 8009 §2, §5 ("key size (128
/// or 256 bits)"), §7 (etypes 19 / 20).
#[must_use]
pub const fn record_key_octets(enctype: EncTypeId) -> usize {
    match enctype {
        EncTypeId::Aes128CtsHmacSha196 | EncTypeId::Aes128CtsHmacSha256128 => 16,
        EncTypeId::Aes256CtsHmacSha196 | EncTypeId::Aes256CtsHmacSha384192 => 32,
    }
}

/// One key of a plaintext body: its encryption type and a view of its
/// octets in the caller's buffer. `Debug` shows the type and the length
/// only — never an octet (docs/CLEAN-ROOM.md).
/// Spec: RFC 3962 §6; RFC 8009 §2.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyOctets<'a> {
    /// The key's encryption type.
    pub enctype: EncTypeId,
    /// The key octets (borrowed from the plaintext).
    pub octets: &'a [u8],
}

impl fmt::Debug for KeyOctets<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyOctets")
            .field("enctype", &self.enctype)
            .field("len", &self.octets.len())
            .finish()
    }
}

/// The keys of one version in a plaintext body, in the order of its
/// encryption types. No allocation: at most [`MAX_RECORD_ENCTYPES`] views.
/// Spec: docs/10 §1; r4-c §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionKeys<'a> {
    keys: [Option<KeyOctets<'a>>; MAX_RECORD_ENCTYPES],
}

impl<'a> VersionKeys<'a> {
    /// The keys, in preference order.
    pub fn iter(&self) -> impl Iterator<Item = KeyOctets<'a>> + '_ {
        self.keys.iter().flatten().copied()
    }
}

/// A parsed plaintext body: views of the current version's keys and, when
/// kept, the previous version's — into the caller's buffer, which the caller
/// keeps in zeroizing memory (this crate never copies key material).
/// Spec: r4-c §3.3; docs/10 §11 (zeroize); docs/CLEAN-ROOM.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordBody<'a> {
    /// The current version's keys.
    pub current: VersionKeys<'a>,
    /// The previous version's keys, when the record keeps one.
    pub previous: Option<VersionKeys<'a>>,
}

/// Split an opened plaintext body into its keys, following `aad`: it must be
/// exactly [`KeyRecordAad::body_len`] octets.
///
/// # Errors
/// [`FormatError::BadLength`] for any other length.
///
/// Spec: r4-c §3.3 ("the key material for each enctype — inside the
/// ciphertext"); RFC 3962 §6; RFC 8009 §2.
pub fn parse_body<'a, S: SealingSuite>(
    aad: &KeyRecordAad<S>,
    plaintext: &'a [u8],
) -> Result<RecordBody<'a>, FormatError> {
    check_versions(&aad.current, aad.previous.as_ref())?;
    if plaintext.len() != aad.body_len() || plaintext.len() > MAX_BODY_OCTETS {
        return Err(FormatError::BadLength);
    }
    let mut reader = Reader::new(plaintext);
    let current = read_version_keys(&mut reader, &aad.current)?;
    let previous = match &aad.previous {
        Some(version) => Some(read_version_keys(&mut reader, version)?),
        None => None,
    };
    reader.finish()?;
    Ok(RecordBody { current, previous })
}

/// Write the plaintext body of `aad` into `out`, which must be exactly
/// [`KeyRecordAad::body_len`] octets (the caller allocates it in zeroizing
/// memory). `current` and `previous` give each version's key octets in the
/// order of its encryption types; each must have its type's length, and
/// `previous` must be given exactly when the associated data keeps one.
///
/// # Errors
/// [`FormatError::BadLength`] for a wrong buffer, key count or key length.
/// On error `out` may be partly written; the caller wipes it.
///
/// Spec: r4-c §3.3; RFC 3962 §6; RFC 8009 §2.
pub fn encode_body_into<S: SealingSuite>(
    aad: &KeyRecordAad<S>,
    current: &[&[u8]],
    previous: Option<&[&[u8]]>,
    out: &mut [u8],
) -> Result<(), FormatError> {
    check_versions(&aad.current, aad.previous.as_ref())?;
    if out.len() != aad.body_len() {
        return Err(FormatError::BadLength);
    }
    let mut at = 0usize;
    write_version_keys(out, &mut at, &aad.current, current)?;
    match (&aad.previous, previous) {
        (Some(version), Some(keys)) => write_version_keys(out, &mut at, version, keys)?,
        (None, None) => {}
        _ => return Err(FormatError::BadLength),
    }
    if at == out.len() {
        Ok(())
    } else {
        Err(FormatError::BadLength)
    }
}

/// The store header's fields (module documentation).
///
/// Spec: r4-c §3.3 ("store header: `format_version`, `store_id`, the
/// generation G, the ceremony state (`Provisioning`/`Sealed`), the root
/// digest over the list of (handle, record digest) of every record —
/// authenticated under the SWK"), §3.6, §3.7 steps 4, 6; §8.1 (the header's
/// AEAD id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreHeader<S> {
    /// The sealing suite (`alg_id`) of the header's own tail and of the
    /// root digest.
    pub suite: S,
    /// The store id.
    pub store_id: StoreId,
    /// The generation G (≥ 1): compared with the backend's monotonic anchor
    /// at start (r4-c §3.6).
    pub generation: u64,
    /// The ceremony state: `Provisioning`, or a sealed store
    /// ([`CeremonyState::Operational`]).
    pub ceremony: CeremonyState,
    /// The number of key records (≤ [`MAX_KEY_RECORDS`]).
    pub record_count: u32,
    /// The root digest: the suite's digest of [`root_digest_input`] over
    /// every record ([`SealingSuite::digest_len`] octets).
    pub root_digest: Vec<u8>,
}

impl<S: SealingSuite> StoreHeader<S> {
    /// The header fields' octets — what the header's sealing authenticates.
    ///
    /// # Errors
    /// [`FormatError`]: an unregistered suite, a zero generation, a record
    /// count over [`MAX_KEY_RECORDS`], a root digest not of the suite's
    /// digest length.
    ///
    /// Spec: r4-c §3.3; docs/CLEAN-ROOM.md
    pub fn encode_fields(&self) -> Result<Vec<u8>, FormatError> {
        check_suite(self.suite)?;
        if self.generation == 0 {
            return Err(FormatError::NonCanonical);
        }
        if usize::try_from(self.record_count).map_or(true, |n| n > MAX_KEY_RECORDS) {
            return Err(FormatError::TooLarge);
        }
        if self.root_digest.len() != self.suite.digest_len() {
            return Err(FormatError::BadLength);
        }
        let mut out = Writer::new();
        out.bytes(&STORE_HEADER_MAGIC);
        out.u16(FORMAT_VERSION);
        out.u16(self.suite.code());
        out.bytes(self.store_id.as_bytes());
        out.u64(self.generation);
        out.u8(match self.ceremony {
            CeremonyState::Provisioning => CEREMONY_PROVISIONING,
            CeremonyState::Operational => CEREMONY_SEALED,
        });
        out.u32(self.record_count);
        out.bytes(&self.root_digest);
        Ok(out.finish())
    }

    /// The length of the sealed tail: the suite's overhead over an empty
    /// plaintext. Spec: r4-c §3.3 (the header is authenticated, not
    /// secret).
    #[must_use]
    pub fn sealed_len(&self) -> usize {
        self.suite.seal_overhead()
    }
}

/// One parsed store header: its fields, their exact octets and the sealed
/// tail, both borrowed from the input.
/// Spec: r4-c §3.3, §3.7 step 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHeader<'a, S> {
    header: StoreHeader<S>,
    field_octets: &'a [u8],
    sealed: &'a [u8],
}

impl<'a, S: SealingSuite> ParsedHeader<'a, S> {
    /// Parse a whole store header: the fields, then exactly
    /// [`StoreHeader::sealed_len`] octets, and nothing after.
    ///
    /// # Errors
    /// [`FormatError`] (module documentation, "Strictness").
    ///
    /// Spec: r4-c §3.3, §3.7 step 4 ("`format_version` ≥ the floor;
    /// `store_id`; G against the anchor; the root digest"); docs/CLEAN-ROOM.md
    pub fn parse(input: &'a [u8]) -> Result<Self, FormatError> {
        if input.len() > MAX_STORE_HEADER_OCTETS {
            return Err(FormatError::TooLarge);
        }
        let mut reader = Reader::new(input);
        if reader.array::<4>()? != STORE_HEADER_MAGIC {
            return Err(FormatError::BadMagic);
        }
        if reader.u16()? != FORMAT_VERSION {
            return Err(FormatError::UnsupportedFormatVersion);
        }
        let suite = suite_of::<S>(reader.u16()?)?;
        let store_id = StoreId::from_bytes(reader.array::<STORE_ID_LEN>()?);
        let generation = reader.u64()?;
        if generation == 0 {
            return Err(FormatError::NonCanonical);
        }
        let ceremony = match reader.u8()? {
            CEREMONY_PROVISIONING => CeremonyState::Provisioning,
            CEREMONY_SEALED => CeremonyState::Operational,
            _ => return Err(FormatError::UnknownCeremonyState),
        };
        let record_count = reader.u32()?;
        if usize::try_from(record_count).map_or(true, |n| n > MAX_KEY_RECORDS) {
            return Err(FormatError::TooLarge);
        }
        let root_digest = reader.take(suite.digest_len())?.to_vec();
        let field_octets = input
            .get(..reader.position())
            .ok_or(FormatError::Truncated)?;
        let sealed = reader.rest();
        if sealed.len() != suite.seal_overhead() {
            return Err(FormatError::BadLength);
        }
        Ok(ParsedHeader {
            header: StoreHeader {
                suite,
                store_id,
                generation,
                ceremony,
                record_count,
                root_digest,
            },
            field_octets,
            sealed,
        })
    }

    /// The header fields. Spec: r4-c §3.3.
    #[must_use]
    pub fn header(&self) -> &StoreHeader<S> {
        &self.header
    }

    /// The fields' octets as stored (canonical: equal to
    /// [`StoreHeader::encode_fields`]).
    #[must_use]
    pub fn field_octets(&self) -> &'a [u8] {
        self.field_octets
    }

    /// The sealed tail as stored.
    #[must_use]
    pub fn sealed(&self) -> &'a [u8] {
        self.sealed
    }
}

/// A whole store header: `fields ‖ sealed`.
///
/// # Errors
/// [`FormatError`] from [`StoreHeader::encode_fields`];
/// [`FormatError::BadLength`] when `sealed` is not exactly
/// [`StoreHeader::sealed_len`] octets.
///
/// Spec: r4-c §3.3.
pub fn encode_header<S: SealingSuite>(
    header: &StoreHeader<S>,
    sealed: &[u8],
) -> Result<Vec<u8>, FormatError> {
    if sealed.len() != header.sealed_len() {
        return Err(FormatError::BadLength);
    }
    let mut octets = header.encode_fields()?;
    octets.extend_from_slice(sealed);
    Ok(octets)
}

/// The octets the root digest covers: the list of (handle, record digest)
/// of every record of the store, in strictly ascending order of (principal
/// id, purpose code) — so a record that is removed, added, or replaced by
/// another (an older valid record of the same handle included) changes the
/// list. A record's digest is the suite's digest of the record's whole
/// stored octets (associated data and sealed body), computed by keyd.
///
/// `ROOT_DIGEST_MAGIC ‖ format_version ‖ suite ‖ count:u32 ‖ (principal id ‖
/// purpose ‖ record digest)*`.
///
/// # Errors
/// [`FormatError`]: more than [`MAX_KEY_RECORDS`] entries, a digest not of
/// the suite's digest length, a repeated handle, an unregistered suite.
///
/// Spec: r4-c §3.3 ("rollback of a single record ⇒ the digest does not
/// match ⇒ refused"; "deletion of a record ⇒ the digest does not match ⇒
/// refused (not 'the key simply does not exist' — C28)").
pub fn root_digest_input<S: SealingSuite>(
    suite: S,
    entries: &[(KeyHandle, &[u8])],
) -> Result<Vec<u8>, FormatError> {
    check_suite(suite)?;
    if entries.len() > MAX_KEY_RECORDS {
        return Err(FormatError::TooLarge);
    }
    let count = u32::try_from(entries.len()).map_err(|_| FormatError::TooLarge)?;
    let mut sorted: Vec<(KeyHandle, &[u8])> = entries.to_vec();
    sorted.sort_by_key(|(handle, _)| handle_order(handle));
    let mut out = Writer::new();
    out.bytes(&ROOT_DIGEST_MAGIC);
    out.u16(FORMAT_VERSION);
    out.u16(suite.code());
    out.u32(count);
    let mut last: Option<([u8; 16], u8)> = None;
    for (handle, digest) in sorted {
        let key = handle_order(&handle);
        if last.is_some_and(|previous| previous >= key) {
            return Err(FormatError::NonCanonical);
        }
        last = Some(key);
        if digest.len() != suite.digest_len() {
            return Err(FormatError::BadLength);
        }
        out.bytes(handle.principal.as_bytes());
        out.u8(purpose_code(handle.purpose));
        out.bytes(digest);
    }
    Ok(out.finish())
}

/// The order of the root-digest list: principal id octets, then purpose
/// code. Spec: r4-c §3.3.
fn handle_order(handle: &KeyHandle) -> ([u8; 16], u8) {
    (*handle.principal.as_bytes(), purpose_code(handle.purpose))
}

/// The persisted code of a purpose — explicit, so that the format does not
/// depend on the enum's in-memory representation; a new purpose fails to
/// compile here until it is given a code.
/// Spec: docs/10 §1 (KeyPurpose); r4-c §3.3 (the handle in the associated
/// data).
const fn purpose_code(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::PrincipalLongterm => 0,
        KeyPurpose::Krbtgt => 1,
        KeyPurpose::Service => 2,
        KeyPurpose::AdminService => 3,
        KeyPurpose::ChangePasswordService => 4,
    }
}

/// The purpose of a persisted code; `None` for every other code.
/// Spec: docs/10 §1; r4-c §3.3.
const fn purpose_from_code(code: u8) -> Option<KeyPurpose> {
    match code {
        0 => Some(KeyPurpose::PrincipalLongterm),
        1 => Some(KeyPurpose::Krbtgt),
        2 => Some(KeyPurpose::Service),
        3 => Some(KeyPurpose::AdminService),
        4 => Some(KeyPurpose::ChangePasswordService),
        _ => None,
    }
}

/// The version rules shared by the encoder and the parser: each version's
/// encryption types and source are well-formed, and a previous version's
/// kvno is below the current one's (keyd assigns kvnos with `Kvno::next`,
/// never wrapping — so a store keyd wrote always has it).
/// Spec: docs/10 §1, §7; RFC 4120 §5.2.9; docs/questions/Q-115 (A-35).
fn check_versions(
    current: &RecordVersion,
    previous: Option<&RecordVersion>,
) -> Result<(), FormatError> {
    check_version(current)?;
    if let Some(previous) = previous {
        check_version(previous)?;
        if previous.kvno >= current.kvno {
            return Err(FormatError::NonCanonical);
        }
    }
    Ok(())
}

/// One version's own rules: 1 ..= 4 encryption types, none repeated; a
/// salt within its bound.
/// Spec: RFC 3962 §7; RFC 8009 §7; docs/50 §3.4 (salt bound).
fn check_version(version: &RecordVersion) -> Result<(), FormatError> {
    let count = version.enctypes.len();
    if count == 0 || count > MAX_RECORD_ENCTYPES {
        return Err(FormatError::BadLength);
    }
    for (i, enctype) in version.enctypes.iter().enumerate() {
        if version.enctypes.iter().skip(i + 1).any(|e| e == enctype) {
            return Err(FormatError::NonCanonical);
        }
    }
    if let KeySource::PasswordDerived { salt, .. } = &version.source {
        if salt.len() > MAX_SALT_OCTETS {
            return Err(FormatError::TooLarge);
        }
    }
    Ok(())
}

/// The binding: `realm_len:u16 ‖ realm ‖ name_type:i32 ‖ count:u8 ‖
/// (len:u16 ‖ component)*`.
/// Spec: RFC 4120 §5.2.2 (Realm ::= KerberosString; PrincipalName { name-type
/// Int32, name-string SEQUENCE OF KerberosString }), §6.2 (the name-type is
/// a hint, preserved).
fn write_binding(out: &mut Writer, binding: &PrincipalBinding) -> Result<(), FormatError> {
    let components = binding.name.name_string.len();
    if components == 0 || components > MAX_NAME_COMPONENTS {
        return Err(FormatError::BadName);
    }
    out.short_bytes(binding.realm.as_bytes(), MAX_NAME_OCTETS)?;
    out.i32(binding.name.name_type);
    out.u8(u8::try_from(components).map_err(|_| FormatError::BadName)?);
    for component in &binding.name.name_string {
        out.short_bytes(component.as_bytes(), MAX_NAME_OCTETS)?;
    }
    Ok(())
}

/// One version: `kvno:u32 ‖ source:u8 ‖ [salt_len:u16 ‖ salt ‖ s2k_flag:u8
/// ‖ s2k[4]?] ‖ count:u8 ‖ etype:i32*`.
/// Spec: r4-c §3.3; RFC 4120 §5.2.9; RFC 3961 §8 (etype numbers are signed
/// 32-bit); RFC 3962 §4.
fn write_version(out: &mut Writer, version: &RecordVersion) -> Result<(), FormatError> {
    out.u32(version.kvno.get());
    match &version.source {
        KeySource::KeydDrawn => out.u8(SOURCE_KEYD_DRAWN),
        KeySource::PasswordDerived { salt, s2k_params } => {
            out.u8(SOURCE_PASSWORD_DERIVED);
            out.short_bytes(salt.as_bytes(), MAX_SALT_OCTETS)?;
            match s2k_params {
                None => out.u8(0),
                Some(params) => {
                    out.u8(1);
                    out.bytes(params);
                }
            }
        }
    }
    out.u8(u8::try_from(version.enctypes.len()).map_err(|_| FormatError::BadLength)?);
    for enctype in &version.enctypes {
        out.i32(enctype.number());
    }
    Ok(())
}

/// Parse a record's associated data (the reader stops right after it).
/// Spec: r4-c §3.3; docs/CLEAN-ROOM.md
fn read_record_aad<S: SealingSuite>(
    reader: &mut Reader<'_>,
) -> Result<KeyRecordAad<S>, FormatError> {
    if reader.array::<4>()? != KEY_RECORD_MAGIC {
        return Err(FormatError::BadMagic);
    }
    if reader.u16()? != FORMAT_VERSION {
        return Err(FormatError::UnsupportedFormatVersion);
    }
    let suite = suite_of::<S>(reader.u16()?)?;
    let store_id = StoreId::from_bytes(reader.array::<STORE_ID_LEN>()?);
    let principal = PrincipalId::from_bytes(reader.array::<16>()?);
    let purpose = purpose_from_code(reader.u8()?).ok_or(FormatError::UnknownPurpose)?;
    let binding = read_binding(reader)?;
    let (current, previous) = match reader.u8()? {
        1 => (read_version(reader)?, None),
        2 => {
            let current = read_version(reader)?;
            let previous = read_version(reader)?;
            (current, Some(previous))
        }
        _ => return Err(FormatError::BadLength),
    };
    check_versions(&current, previous.as_ref())?;
    Ok(KeyRecordAad {
        suite,
        store_id,
        handle: KeyHandle::new(principal, purpose),
        binding,
        current,
        previous,
    })
}

/// Parse a binding (`write_binding`): KerberosString content is checked by
/// krb-proto's own rule; 1 ..= `MAX_NAME_COMPONENTS` components.
/// Spec: RFC 4120 §5.2.1, §5.2.2, §6.2.
fn read_binding(reader: &mut Reader<'_>) -> Result<PrincipalBinding, FormatError> {
    let realm = read_kerberos_string(reader)?;
    let name_type = reader.i32()?;
    let count = usize::from(reader.u8()?);
    if count == 0 || count > MAX_NAME_COMPONENTS {
        return Err(FormatError::BadName);
    }
    let mut name_string = Vec::with_capacity(count);
    for _ in 0..count {
        name_string.push(read_kerberos_string(reader)?);
    }
    Ok(PrincipalBinding::new(
        realm,
        PrincipalName {
            name_type,
            name_string,
        },
    ))
}

/// One length-prefixed KerberosString (≤ [`MAX_NAME_OCTETS`]).
/// Spec: RFC 4120 §5.2.1.
fn read_kerberos_string(reader: &mut Reader<'_>) -> Result<KerberosString, FormatError> {
    let octets = reader.short_bytes(MAX_NAME_OCTETS)?;
    KerberosString::from_bytes(octets).map_err(|_| FormatError::BadName)
}

/// Parse one version (`write_version`).
/// Spec: r4-c §3.3; RFC 4120 §5.2.9; RFC 3961 §8; RFC 3962 §4.
fn read_version(reader: &mut Reader<'_>) -> Result<RecordVersion, FormatError> {
    let kvno = Kvno::new(reader.u32()?);
    let source = match reader.u8()? {
        SOURCE_KEYD_DRAWN => KeySource::KeydDrawn,
        SOURCE_PASSWORD_DERIVED => {
            let salt = core::str::from_utf8(reader.short_bytes(MAX_SALT_OCTETS)?)
                .map_err(|_| FormatError::BadSalt)?
                .to_owned();
            let s2k_params = match reader.u8()? {
                0 => None,
                1 => Some(reader.array::<S2K_PARAMS_LEN>()?),
                _ => return Err(FormatError::NonCanonical),
            };
            KeySource::PasswordDerived { salt, s2k_params }
        }
        _ => return Err(FormatError::UnknownKeySource),
    };
    let count = usize::from(reader.u8()?);
    if count == 0 || count > MAX_RECORD_ENCTYPES {
        return Err(FormatError::BadLength);
    }
    let mut enctypes = Vec::with_capacity(count);
    for _ in 0..count {
        let enctype = EncTypeId::from_number(reader.i32()?).ok_or(FormatError::UnknownEncType)?;
        enctypes.push(enctype);
    }
    Ok(RecordVersion {
        kvno,
        source,
        enctypes,
    })
}

/// The keys of one version, as views (`parse_body`).
/// Spec: RFC 3962 §6; RFC 8009 §2.
fn read_version_keys<'a>(
    reader: &mut Reader<'a>,
    version: &RecordVersion,
) -> Result<VersionKeys<'a>, FormatError> {
    if version.enctypes.len() > MAX_RECORD_ENCTYPES {
        return Err(FormatError::BadLength);
    }
    let mut keys = [None; MAX_RECORD_ENCTYPES];
    for (slot, enctype) in keys.iter_mut().zip(version.enctypes.iter()) {
        let octets = reader.take(record_key_octets(*enctype))?;
        *slot = Some(KeyOctets {
            enctype: *enctype,
            octets,
        });
    }
    Ok(VersionKeys { keys })
}

/// Copy one version's keys into `out` at `at` (`encode_body_into`).
/// Spec: RFC 3962 §6; RFC 8009 §2.
fn write_version_keys(
    out: &mut [u8],
    at: &mut usize,
    version: &RecordVersion,
    keys: &[&[u8]],
) -> Result<(), FormatError> {
    if keys.len() != version.enctypes.len() {
        return Err(FormatError::BadLength);
    }
    for (enctype, key) in version.enctypes.iter().zip(keys) {
        let len = record_key_octets(*enctype);
        if key.len() != len {
            return Err(FormatError::BadLength);
        }
        let end = at.checked_add(len).ok_or(FormatError::BadLength)?;
        out.get_mut(*at..end)
            .ok_or(FormatError::BadLength)?
            .copy_from_slice(key);
        *at = end;
    }
    Ok(())
}

/// A bounds-checked reader over an input slice: every read checks the
/// remaining length first and never panics.
/// Spec: docs/CLEAN-ROOM.md (strict, bounded parsers).
struct Reader<'a> {
    input: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Reader { input, at: 0 }
    }

    /// The next `len` octets — only if that many remain.
    fn take(&mut self, len: usize) -> Result<&'a [u8], FormatError> {
        let end = self.at.checked_add(len).ok_or(FormatError::Truncated)?;
        let octets = self.input.get(self.at..end).ok_or(FormatError::Truncated)?;
        self.at = end;
        Ok(octets)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FormatError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, FormatError> {
        Ok(u8::from_be_bytes(self.array::<1>()?))
    }

    fn u16(&mut self) -> Result<u16, FormatError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, FormatError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, FormatError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn i32(&mut self) -> Result<i32, FormatError> {
        Ok(i32::from_be_bytes(self.array::<4>()?))
    }

    /// A `len:u16 ‖ octets` field: the length is checked against `max`
    /// before the octets are taken (and `take` checks the remaining input).
    fn short_bytes(&mut self, max: usize) -> Result<&'a [u8], FormatError> {
        let len = usize::from(self.u16()?);
        if len > max {
            return Err(FormatError::TooLarge);
        }
        self.take(len)
    }

    fn position(&self) -> usize {
        self.at
    }

    /// Everything not yet read.
    fn rest(&self) -> &'a [u8] {
        self.input.get(self.at..).unwrap_or(&[])
    }

    /// The input must be fully consumed.
    fn finish(&self) -> Result<(), FormatError> {
        if self.at == self.input.len() {
            Ok(())
        } else {
            Err(FormatError::BadLength)
        }
    }
}

/// A big-endian writer of non-secret fields (secret key octets go only
/// through [`encode_body_into`], into the caller's buffer).
/// Spec: docs/CLEAN-ROOM.md
struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Writer { out: Vec::new() }
    }

    fn bytes(&mut self, octets: &[u8]) {
        self.out.extend_from_slice(octets);
    }

    fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    fn i32(&mut self, value: i32) {
        self.bytes(&value.to_be_bytes());
    }

    /// A `len:u16 ‖ octets` field within `max`.
    fn short_bytes(&mut self, octets: &[u8], max: usize) -> Result<(), FormatError> {
        if octets.len() > max {
            return Err(FormatError::TooLarge);
        }
        self.u16(u16::try_from(octets.len()).map_err(|_| FormatError::TooLarge)?);
        self.bytes(octets);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.out
    }
}

// The bounds fit the length prefixes that carry them, and a whole record
// fits the bound checked first.
const _: () = {
    assert!(MAX_NAME_OCTETS <= u16::MAX as usize);
    assert!(MAX_SALT_OCTETS <= u16::MAX as usize);
    assert!(MAX_NAME_COMPONENTS <= u8::MAX as usize);
    assert!(MAX_RECORD_ENCTYPES <= u8::MAX as usize);
    assert!(MAX_KEY_RECORDS <= u32::MAX as usize);
    assert!(MAX_RECORD_ENCTYPES == 4);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The purpose codes round-trip and nothing else maps (docs/10 §1).
    #[test]
    fn purpose_codes_round_trip() {
        for purpose in [
            KeyPurpose::PrincipalLongterm,
            KeyPurpose::Krbtgt,
            KeyPurpose::Service,
            KeyPurpose::AdminService,
            KeyPurpose::ChangePasswordService,
        ] {
            assert_eq!(purpose_from_code(purpose_code(purpose)), Some(purpose));
        }
        for code in 5..=u8::MAX {
            assert_eq!(purpose_from_code(code), None, "{code}");
        }
    }

    /// RFC 3962 §6, §7 and RFC 8009 §5, §7: 128-bit types have 16-octet
    /// keys, 256-bit types 32.
    #[test]
    fn key_lengths_follow_the_rfc_key_sizes() {
        assert_eq!(record_key_octets(EncTypeId::Aes128CtsHmacSha196), 16);
        assert_eq!(record_key_octets(EncTypeId::Aes256CtsHmacSha196), 32);
        assert_eq!(record_key_octets(EncTypeId::Aes128CtsHmacSha256128), 16);
        assert_eq!(record_key_octets(EncTypeId::Aes256CtsHmacSha384192), 32);
        assert!(EncTypeId::ALL
            .iter()
            .all(|e| record_key_octets(*e) <= MAX_KEY_OCTETS));
    }

    /// The reader never reads past its input and refuses a length over its
    /// bound before taking octets (docs/CLEAN-ROOM.md).
    #[test]
    fn reader_is_bounded() {
        let mut r = Reader::new(&[0x00, 0x05, 1, 2]);
        assert_eq!(r.short_bytes(8), Err(FormatError::Truncated));
        let mut r = Reader::new(&[0x00, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(r.short_bytes(8), Err(FormatError::TooLarge));
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u32(), Err(FormatError::Truncated));
        assert_eq!(r.take(usize::MAX), Err(FormatError::Truncated));
        assert_eq!(r.u8(), Ok(1));
        assert_eq!(r.finish(), Err(FormatError::BadLength));
        assert_eq!(r.rest(), &[2, 3]);
    }
}
