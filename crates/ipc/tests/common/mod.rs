//! A sample channel defined with the crate's message-definition pattern, used
//! by the integration tests.
//!
//! Source: docs/50 §3.3 (the frame / body / payload layout and the field
//! primitives), §3.4 (a request kind and a reply kind per operation), R50-4.
//! The channel, its kinds, field names and bounds are test-only choices; the
//! real channels (keyd, dird, audit) are later crates.

#![allow(dead_code)]

use ipc::{
    Channel, DerBlob, Error, FrameLimit, MessageSet, Payload, Reader, Result, Secret, Writer,
};

/// Request body bound of the sample channel.
pub const REQUEST_LIMIT: FrameLimit = match FrameLimit::new(1024) {
    Some(limit) => limit,
    None => panic!("1024 is a valid frame limit"),
};
/// Reply body bound of the sample channel.
pub const REPLY_LIMIT: FrameLimit = match FrameLimit::new(64) {
    Some(limit) => limit,
    None => panic!("64 is a valid frame limit"),
};

/// The sample channel: magic 0x7E57, version 3.
pub const SAMPLE: Channel = Channel::new(0x7E57, 3, REQUEST_LIMIT, REPLY_LIMIT);

pub const KIND_LOOKUP: u8 = 0x01;
pub const KIND_STORE: u8 = 0x02;
pub const KIND_DONE: u8 = 0x81;
pub const KIND_ACK: u8 = 0x82;

pub const MAX_PADATA: u32 = 256;
pub const MAX_PASSWORD: u32 = 64;
pub const MAX_NAMES: u32 = 4;
pub const MAX_NAME: u32 = 16;
pub const MAX_GROUPS: u32 = 8;

/// A closed enumeration field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Create,
    Replace,
}

impl Mode {
    pub fn code(self) -> u8 {
        match self {
            Mode::Create => 1,
            Mode::Replace => 2,
        }
    }

    pub fn from_code(code: u8) -> Option<Mode> {
        match code {
            1 => Some(Mode::Create),
            2 => Some(Mode::Replace),
            _ => None,
        }
    }
}

/// A small fixed-width request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub handle: [u8; 16],
    pub purpose: u8,
    pub wanted: bool,
}

impl Payload for Lookup {
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_array(&self.handle)?;
        writer.write_u8(self.purpose)?;
        writer.write_bool(self.wanted)
    }

    fn read_fields(reader: &mut Reader<'_>) -> Result<Lookup> {
        let handle = reader.read_array()?;
        let purpose = reader.read_u8()?;
        let wanted = reader.read_bool()?;
        Ok(Lookup {
            handle,
            purpose,
            wanted,
        })
    }
}

/// A request that uses every primitive.
#[derive(Debug)]
pub struct Store {
    pub handle: [u8; 16],
    pub kvno: u32,
    pub serial: u64,
    pub port: u16,
    pub enabled: bool,
    pub mode: Mode,
    pub armor: Option<[u8; 8]>,
    pub padata: DerBlob,
    pub password: Secret,
    pub names: Vec<Vec<u8>>,
    pub groups: Option<Vec<u32>>,
}

impl Payload for Store {
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_array(&self.handle)?;
        writer.write_u32(self.kvno)?;
        writer.write_u64(self.serial)?;
        writer.write_u16(self.port)?;
        writer.write_bool(self.enabled)?;
        writer.write_enum(self.mode.code())?;
        writer.write_option(self.armor.as_ref(), |w, armor| w.write_array(armor))?;
        writer.write_der(&self.padata, MAX_PADATA)?;
        writer.write_secret(&self.password, MAX_PASSWORD)?;
        writer.write_seq(&self.names, MAX_NAMES, |w, name| {
            w.write_bytes(name, MAX_NAME)
        })?;
        writer.write_option(self.groups.as_ref(), |w, groups| {
            w.write_seq(groups, MAX_GROUPS, |w, sid| w.write_u32(*sid))
        })
    }

    fn read_fields(reader: &mut Reader<'_>) -> Result<Store> {
        let handle = reader.read_array()?;
        let kvno = reader.read_u32()?;
        let serial = reader.read_u64()?;
        let port = reader.read_u16()?;
        let enabled = reader.read_bool()?;
        let mode = reader.read_enum(Mode::from_code)?;
        let armor = reader.read_option(|r| r.read_array())?;
        let padata = reader.read_der(MAX_PADATA)?;
        let password = reader.read_secret(MAX_PASSWORD)?;
        let names = reader.read_seq(MAX_NAMES, |r| r.read_bytes(MAX_NAME).map(<[u8]>::to_vec))?;
        let groups = reader.read_option(|r| r.read_seq(MAX_GROUPS, |r| r.read_u32()))?;
        Ok(Store {
            handle,
            kvno,
            serial,
            port,
            enabled,
            mode,
            armor,
            padata,
            password,
            names,
            groups,
        })
    }
}

/// The sample channel's requests.
#[derive(Debug)]
pub enum SampleRequest {
    Lookup(Lookup),
    Store(Store),
}

impl MessageSet for SampleRequest {
    const KINDS: &'static [u8] = &[KIND_LOOKUP, KIND_STORE];

    fn kind(&self) -> u8 {
        match self {
            SampleRequest::Lookup(_) => KIND_LOOKUP,
            SampleRequest::Store(_) => KIND_STORE,
        }
    }

    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            SampleRequest::Lookup(message) => message.write_fields(writer),
            SampleRequest::Store(message) => message.write_fields(writer),
        }
    }

    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<SampleRequest> {
        match kind {
            KIND_LOOKUP => Lookup::read_fields(reader).map(SampleRequest::Lookup),
            KIND_STORE => Store::read_fields(reader).map(SampleRequest::Store),
            _ => Err(Error::UnknownKind),
        }
    }
}

/// The sample channel's replies. The shared `Refused` reply is not part of
/// the set: it travels with `ipc::REFUSED_KIND` on every channel (A-59).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleReply {
    Done { kvno: u32 },
    Ack,
}

impl MessageSet for SampleReply {
    const KINDS: &'static [u8] = &[KIND_DONE, KIND_ACK];

    fn kind(&self) -> u8 {
        match self {
            SampleReply::Done { .. } => KIND_DONE,
            SampleReply::Ack => KIND_ACK,
        }
    }

    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            SampleReply::Done { kvno } => writer.write_u32(*kvno),
            SampleReply::Ack => Ok(()),
        }
    }

    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<SampleReply> {
        match kind {
            KIND_DONE => reader.read_u32().map(|kvno| SampleReply::Done { kvno }),
            KIND_ACK => Ok(SampleReply::Ack),
            _ => Err(Error::UnknownKind),
        }
    }
}

// Definition-site check that both tables leave out the reserved kind (A-59).
const _: () = assert!(ipc::kinds_exclude_refused(SampleRequest::KINDS));
const _: () = assert!(ipc::kinds_exclude_refused(SampleReply::KINDS));

/// A `Store` with every optional field present.
pub fn full_store() -> Store {
    Store {
        handle: [0x11; 16],
        kvno: 0x0102_0304,
        serial: 0x0A0B_0C0D_0E0F_1011,
        port: 0xBEEF,
        enabled: true,
        mode: Mode::Replace,
        armor: Some([0xA5; 8]),
        padata: DerBlob::from_slice(&[0x30, 0x03, 0x02, 0x01, 0x05]),
        password: Secret::from_slice(b"correct horse"),
        names: vec![b"alice".to_vec(), Vec::new(), b"bob".to_vec()],
        groups: Some(vec![513, 512, 0xFFFF_FFFF]),
    }
}

/// A `Store` with every optional field absent and every sequence empty.
pub fn sparse_store() -> Store {
    Store {
        handle: [0; 16],
        kvno: 0,
        serial: 0,
        port: 0,
        enabled: false,
        mode: Mode::Create,
        armor: None,
        padata: DerBlob::from_slice(&[]),
        password: Secret::from_slice(&[]),
        names: Vec::new(),
        groups: None,
    }
}

/// Field-by-field equality (`Secret` has no `PartialEq`, by design).
pub fn same_store(a: &Store, b: &Store) -> bool {
    a.handle == b.handle
        && a.kvno == b.kvno
        && a.serial == b.serial
        && a.port == b.port
        && a.enabled == b.enabled
        && a.mode == b.mode
        && a.armor == b.armor
        && a.padata == b.padata
        && a.password.expose() == b.password.expose()
        && a.names == b.names
        && a.groups == b.groups
}

/// A frame built by hand: `length:u32 ‖ magic ‖ version ‖ kind ‖ payload`
/// (docs/50 §3.3).
pub fn raw_frame(magic: u16, version: u8, kind: u8, payload: &[u8]) -> Vec<u8> {
    let body_len = u32::try_from(4 + payload.len()).expect("test frame fits");
    let mut frame = Vec::new();
    frame.extend_from_slice(&body_len.to_be_bytes());
    frame.extend_from_slice(&magic.to_be_bytes());
    frame.push(version);
    frame.push(kind);
    frame.extend_from_slice(payload);
    frame
}
