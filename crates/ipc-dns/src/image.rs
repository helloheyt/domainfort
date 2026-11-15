//! The zone-image transfer: the canonical encoding of dns-zone's
//! `ZoneImageParts`, its division into chunks, dird's validated transfer and
//! dnsd's reassembly.
//!
//! # Encoding (a standalone `ipc` payload, fixed-order fields)
//!
//! ```text
//! image := apex:name ‖ serial:u32 (≠ 0) ‖ rname:name ‖ refresh:u32 ‖
//!          retry:u32 ‖ expire:u32 ‖ minimum:u32 ‖ infrastructure_ttl:u32 ‖
//!          dc:host ‖ hosts:seq<host, 65535> ‖ kpasswd:u8 {1 Absent, 2 Present}
//! name  := bytes<255> holding exactly one uncompressed domain name
//! host  := label:bytes<63> ‖ addresses:seq<[u8; 4], 8> ‖ ttl:u32
//! ```
//!
//! Exactly the fields of docs/54 §4.4 ("apex, SERIAL, SOA parameters, NS, SRV
//! list and host records {LDH label, ≤ 8 IPv4 addresses, TTL}") as dns-zone
//! types them — NS and SRV are synthesized from the apex and the DC's label
//! (docs/54 §5.1), so they are not inputs; nothing else of a directory object
//! can be expressed. The image is at most 8 MiB (dns-zone
//! `MAX_IMAGE_TRANSFER_OCTETS`; the worst case is checked at compile time in
//! [`crate::channel`]).
//!
//! # Chunks
//!
//! The encoded image travels as `ImageChunk { chunk, more }` replies: every
//! chunk but the last is exactly [`MAX_IMAGE_CHUNK`] octets, the last 1 ..=
//! [`MAX_IMAGE_CHUNK`] — one division per image ([`split_image`]), the
//! dird-ldap response-part rule (docs/50 "bounds of `dird-ldap.sock`",
//! Q-280 item 2).
//!
//! # Validated on both sides
//!
//! * dird sends only an [`ImageTransfer`], which is built only from parts
//!   `ZoneImage::new` accepts — dird never sends an image dnsd would refuse.
//! * dnsd's [`ImageAssembly`] bounds the reassembly (≤ 8 MiB), decodes the
//!   payload strictly (no trailing octet, closed tables), and returns only a
//!   `ZoneImage` built by `ZoneImage::new` — the same validation (docs/50
//!   §3.3: "replies are decoded with the same strictness"). Nothing partial is
//!   ever returned, so dnsd can only swap whole, valid images (docs/54 §4.4:
//!   "atomic replacement"; RFC 2136 §3.7: a query never sees a partially
//!   modified RRset).
//!
//! Spec: docs/54 §4.4, §4.6; A-124; RFC 1035 §2.3.4, §3.1, §3.4.1; RFC 2136
//! §3.7, §7.11; docs/50 §3.3.

use crate::channel::{
    codes, IMAGE_LIMIT, MAX_ADDRESSES, MAX_IMAGE_CHUNK, MAX_IMAGE_OCTETS, MAX_LABEL,
    MAX_MEMBER_HOSTS,
};
use crate::values::Serial;
use crate::wire::{read_name, read_serial, write_name, write_serial};
use core::fmt;
use dns_zone::{
    HostRecordParts, KpasswdService, SoaParameters, ZoneImage, ZoneImageError, ZoneImageParts,
};
use ipc::{Error, Reader, Result, Writer};
use std::net::Ipv4Addr;

/// [`MAX_IMAGE_CHUNK`] as a slice length.
const CHUNK: usize = MAX_IMAGE_CHUNK as usize;

/// One chunk of an encoded zone image. Invariant (checked by
/// [`ImageChunk::new`] and by the decoder): 1 ..= [`MAX_IMAGE_CHUNK`] octets,
/// and exactly [`MAX_IMAGE_CHUNK`] when `more` is set — so every image has
/// exactly one division into chunks. `Debug` shows only the length.
/// Spec: docs/54 §4.6; module documentation.
#[derive(Clone, PartialEq, Eq)]
pub struct ImageChunk {
    chunk: Vec<u8>,
    more: bool,
}

impl fmt::Debug for ImageChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageChunk")
            .field("len", &self.chunk.len())
            .field("more", &self.more)
            .finish()
    }
}

/// Whether a chunk of `len` octets with `more` keeps the invariant.
pub(crate) const fn chunk_is_valid(len: usize, more: bool) -> bool {
    if more {
        len == CHUNK
    } else {
        len >= 1 && len <= CHUNK
    }
}

impl ImageChunk {
    /// A chunk, or `None` if it breaks the invariant.
    /// Spec: module documentation.
    #[must_use]
    pub fn new(chunk: &[u8], more: bool) -> Option<ImageChunk> {
        if !chunk_is_valid(chunk.len(), more) {
            return None;
        }
        Some(ImageChunk {
            chunk: chunk.to_vec(),
            more,
        })
    }

    /// The chunk's octets.
    #[must_use]
    pub fn octets(&self) -> &[u8] {
        &self.chunk
    }

    /// Whether more chunks of the same image follow.
    #[must_use]
    pub fn more(&self) -> bool {
        self.more
    }
}

/// The one division of an encoded image into chunks: full chunks of
/// [`MAX_IMAGE_CHUNK`] octets, then the rest (if the length is a multiple of
/// the chunk size, the last full chunk ends the image). `None` for an empty
/// payload or one longer than [`MAX_IMAGE_OCTETS`].
/// Spec: module documentation.
#[must_use]
pub fn split_image(payload: &[u8]) -> Option<Vec<ImageChunk>> {
    if payload.is_empty() || payload.len() > MAX_IMAGE_OCTETS {
        return None;
    }
    let count = payload.len().div_ceil(CHUNK);
    let mut chunks = Vec::with_capacity(count);
    for (index, chunk) in payload.chunks(CHUNK).enumerate() {
        chunks.push(ImageChunk::new(chunk, index + 1 < count)?);
    }
    Some(chunks)
}

/// A host record: `label:bytes<63> ‖ addresses:seq<[u8; 4], 8> ‖ ttl:u32`.
/// Spec: docs/54 §4.4; RFC 1035 §2.3.4 (label ≤ 63), §3.4.1 (a 32-bit
/// address).
fn write_host(writer: &mut Writer, host: &HostRecordParts) -> Result<()> {
    writer.write_bytes(&host.label, MAX_LABEL)?;
    writer.write_seq(&host.addresses, MAX_ADDRESSES, |writer, address| {
        writer.write_array(&address.octets())
    })?;
    writer.write_u32(host.ttl)
}

/// Spec: docs/54 §4.4; RFC 1035 §2.3.4, §3.4.1.
fn read_host(reader: &mut Reader<'_>) -> Result<HostRecordParts> {
    let label = reader.read_bytes(MAX_LABEL)?.to_vec();
    let addresses = reader.read_seq(MAX_ADDRESSES, |reader| {
        reader.read_array::<4>().map(Ipv4Addr::from)
    })?;
    let ttl = reader.read_u32()?;
    Ok(HostRecordParts {
        label,
        addresses,
        ttl,
    })
}

/// Spec: docs/54 §3.1; dns-zone `KpasswdService`.
fn kpasswd_code(kpasswd: KpasswdService) -> u8 {
    match kpasswd {
        KpasswdService::Absent => codes::KPASSWD_ABSENT,
        KpasswdService::Present => codes::KPASSWD_PRESENT,
    }
}

/// Spec: docs/54 §3.1; dns-zone `KpasswdService`.
fn kpasswd_from(code: u8) -> Option<KpasswdService> {
    match code {
        codes::KPASSWD_ABSENT => Some(KpasswdService::Absent),
        codes::KPASSWD_PRESENT => Some(KpasswdService::Present),
        _ => None,
    }
}

/// The image fields, in order (module documentation).
/// Spec: module documentation; docs/50 §3.3.
fn write_image(writer: &mut Writer, parts: &ZoneImageParts) -> Result<()> {
    write_name(writer, &parts.apex)?;
    // A zero SERIAL has no wire form (RFC 2136 §7.11).
    let serial = Serial::new(parts.serial).ok_or(Error::UnknownCode)?;
    write_serial(writer, serial)?;
    write_name(writer, &parts.soa.rname)?;
    writer.write_u32(parts.soa.refresh)?;
    writer.write_u32(parts.soa.retry)?;
    writer.write_u32(parts.soa.expire)?;
    writer.write_u32(parts.soa.minimum)?;
    writer.write_u32(parts.infrastructure_ttl)?;
    write_host(writer, &parts.dc)?;
    writer.write_seq(&parts.hosts, MAX_MEMBER_HOSTS, write_host)?;
    writer.write_enum(kpasswd_code(parts.kpasswd))
}

/// The same fields, in the same order (one `let` per field mirrors the
/// writer line for line). Spec: module documentation; docs/50 §3.3.
fn read_image(reader: &mut Reader<'_>) -> Result<ZoneImageParts> {
    let apex = read_name(reader)?;
    let serial = read_serial(reader)?;
    let rname = read_name(reader)?;
    let refresh = reader.read_u32()?;
    let retry = reader.read_u32()?;
    let expire = reader.read_u32()?;
    let minimum = reader.read_u32()?;
    let infrastructure_ttl = reader.read_u32()?;
    let dc = read_host(reader)?;
    let hosts = reader.read_seq(MAX_MEMBER_HOSTS, read_host)?;
    let kpasswd = reader.read_enum(kpasswd_from)?;
    Ok(ZoneImageParts {
        apex,
        serial: serial.get(),
        soa: SoaParameters {
            rname,
            refresh,
            retry,
            expire,
            minimum,
        },
        infrastructure_ttl,
        dc,
        hosts,
        kpasswd,
    })
}

/// Encode `parts` as one image payload (≤ [`MAX_IMAGE_OCTETS`]).
///
/// # Errors
/// An `ipc::Error`: a zero SERIAL ([`Error::UnknownCode`]), a field over its
/// bound, or a payload over [`MAX_IMAGE_OCTETS`] ([`Error::BodyOverBound`]).
///
/// Spec: module documentation.
pub fn encode_image(parts: &ZoneImageParts) -> Result<Vec<u8>> {
    let mut writer = Writer::new(IMAGE_LIMIT);
    write_image(&mut writer, parts)?;
    // Not a secret (docs/54 §4.4: zone content is visible on the internal
    // network); the codec's zeroizing buffer is copied out once.
    Ok(writer.into_payload().to_vec())
}

/// Decode one whole image payload: its fields, then the no-trailing-octet
/// rule. The result is not yet validated as a zone — [`ImageAssembly`] passes
/// it to `ZoneImage::new`.
///
/// # Errors
/// An `ipc::Error`: over [`MAX_IMAGE_OCTETS`] ([`Error::FrameTooLarge`]),
/// truncation, an over-bound length or count, a name that is not exactly one
/// uncompressed name, a zero SERIAL or an unknown code
/// ([`Error::UnknownCode`]), or trailing octets.
///
/// Spec: module documentation; docs/50 §3.3.
pub fn decode_image(payload: &[u8]) -> Result<ZoneImageParts> {
    if payload.len() > MAX_IMAGE_OCTETS {
        return Err(Error::FrameTooLarge);
    }
    let mut reader = Reader::new(payload);
    let parts = read_image(&mut reader)?;
    reader.finish()?;
    Ok(parts)
}

/// Why an image could not be sent or rebuilt. No variant carries a name, an
/// address or a payload octet.
/// Spec: docs/54 §4.4, §4.6; docs/50 §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageError {
    /// The parts are not a valid zone (`ZoneImage::new` refused them).
    Zone(ZoneImageError),
    /// The image payload does not encode (dird's side) or decode (dnsd's).
    Payload(Error),
    /// The chunks overrun the image bound, or a chunk came after the last.
    OverBound,
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImageError::Zone(error) => write!(f, "zone image refused: {error}"),
            ImageError::Payload(error) => write!(f, "zone image payload: {error}"),
            ImageError::OverBound => f.write_str("zone image chunks over the transfer bound"),
        }
    }
}

impl std::error::Error for ImageError {}

/// dird's side: an image ready to send — its parts passed `ZoneImage::new`,
/// were encoded (≤ 8 MiB) and divided into chunks. The only way to put an
/// image on the channel ([`crate::encode_image_chunks`]), so dird can never
/// send an image dnsd would refuse.
/// Spec: docs/54 §4.4, §4.6; module documentation.
#[derive(Clone, PartialEq, Eq)]
pub struct ImageTransfer {
    serial: Serial,
    chunks: Vec<ImageChunk>,
}

impl fmt::Debug for ImageTransfer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageTransfer")
            .field("serial", &self.serial)
            .field("chunks", &self.chunks.len())
            .finish()
    }
}

impl ImageTransfer {
    /// Validate `parts` as a zone, encode and divide them.
    ///
    /// # Errors
    /// [`ImageError::Zone`] (not a valid zone), [`ImageError::Payload`] (does
    /// not encode within the bounds).
    ///
    /// Spec: docs/54 §4.4, §4.6.
    pub fn new(parts: &ZoneImageParts) -> core::result::Result<ImageTransfer, ImageError> {
        let image = ZoneImage::new(parts.clone()).map_err(ImageError::Zone)?;
        let serial =
            Serial::new(image.serial()).ok_or(ImageError::Zone(ZoneImageError::SerialZero))?;
        let payload = encode_image(parts).map_err(ImageError::Payload)?;
        let chunks = split_image(&payload).ok_or(ImageError::Payload(Error::BodyOverBound))?;
        Ok(ImageTransfer { serial, chunks })
    }

    /// The image's SERIAL.
    #[must_use]
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// The chunks, in order (1 ..= [`crate::channel::MAX_IMAGE_CHUNKS`]).
    #[must_use]
    pub fn chunks(&self) -> &[ImageChunk] {
        &self.chunks
    }
}

/// dnsd's side: the reassembly of one image from its chunks.
///
/// [`ImageAssembly::push`] appends a chunk — refusing to pass
/// [`MAX_IMAGE_OCTETS`] in all, which also bounds the count to
/// [`crate::channel::MAX_IMAGE_CHUNKS`] — and, after the last chunk, decodes
/// the payload and validates it with `ZoneImage::new`. Nothing partial is
/// ever returned.
/// Spec: docs/54 §4.4, §4.6; docs/50 §3.3; module documentation.
#[derive(Default)]
pub struct ImageAssembly {
    payload: Vec<u8>,
    finished: bool,
}

impl fmt::Debug for ImageAssembly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageAssembly")
            .field("received", &self.payload.len())
            .field("finished", &self.finished)
            .finish()
    }
}

impl ImageAssembly {
    /// An empty assembly.
    #[must_use]
    pub fn new() -> ImageAssembly {
        ImageAssembly::default()
    }

    /// Whether any chunk was received.
    #[must_use]
    pub fn is_started(&self) -> bool {
        !self.payload.is_empty() || self.finished
    }

    /// Append `chunk`; after the last chunk, the validated image.
    ///
    /// # Errors
    /// [`ImageError::OverBound`] (over [`MAX_IMAGE_OCTETS`], or a chunk after
    /// the last), [`ImageError::Payload`], [`ImageError::Zone`]. After an
    /// error the assembly is spent.
    ///
    /// Spec: docs/54 §4.4, §4.6; module documentation.
    pub fn push(
        &mut self,
        chunk: &ImageChunk,
    ) -> core::result::Result<Option<ZoneImage>, ImageError> {
        if self.finished {
            return Err(ImageError::OverBound);
        }
        let total = self
            .payload
            .len()
            .checked_add(chunk.octets().len())
            .ok_or(ImageError::OverBound)?;
        if total > MAX_IMAGE_OCTETS {
            self.finished = true;
            return Err(ImageError::OverBound);
        }
        self.payload.extend_from_slice(chunk.octets());
        if chunk.more() {
            return Ok(None);
        }
        self.finished = true;
        let parts = decode_image(&self.payload).map_err(ImageError::Payload)?;
        let image = ZoneImage::new(parts).map_err(ImageError::Zone)?;
        Ok(Some(image))
    }
}
