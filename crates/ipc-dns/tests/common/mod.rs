//! Shared fixtures of the ipc-dns tests: the zone of RFC 2782's "Fictional
//! example" as image parts, hand-made DNS message octets, large images at
//! the bounds, and a scripted in-process connection for the client.
//!
//! Sources of the values: RFC 2782, "Fictional example" (`example.com`; SOA
//! `server.example.com. root.example.com. ( 1995032001 3600 3600 604800
//! 86400 )`; hosts `server` 172.30.79.10, `old-slow-box` 172.30.79.11,
//! `sysadmins-box` 172.30.79.12, `new-fast-box` 172.30.79.13 — pinned copy,
//! SHA-256 verified this session); RFC 1035 §4.1.1 (the 12-octet header
//! layout of the hand-made messages). TTLs, IDs, uids and the large images'
//! labels and addresses are hand-made. No octet comes from any other
//! implementation or capture.

#![allow(dead_code)]

use ipc::FrameLimit;
use ipc_dns::{
    encode_refusal, encode_reply, Connection, Connector, DnsReply, HostRecordParts, KpasswdService,
    Name, SoaParameters, TransportError, ZoneImageParts,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::time::Duration;
use zeroize::Zeroizing;

/// RFC 2782 "Fictional example": SERIAL and timers.
pub const RFC2782_SERIAL: u32 = 1_995_032_001;
pub const RFC2782_REFRESH: u32 = 3600;
pub const RFC2782_RETRY: u32 = 3600;
pub const RFC2782_EXPIRE: u32 = 604_800;
pub const RFC2782_MINIMUM: u32 = 86_400;

/// Hand-made TTL of the records.
pub const TTL: u32 = 3600;

/// Hand-made uid of dird in the client tests.
pub const DIRD_UID: u32 = 61_002;

pub fn name(dotted: &str) -> Name {
    Name::from_dotted(dotted).expect("test name")
}

pub fn host(label: &[u8], addresses: &[[u8; 4]], ttl: u32) -> HostRecordParts {
    HostRecordParts {
        label: label.to_vec(),
        addresses: addresses.iter().map(|a| Ipv4Addr::from(*a)).collect(),
        ttl,
    }
}

/// The RFC 2782 example zone as image parts (the DC is `server`).
pub fn rfc2782_parts() -> ZoneImageParts {
    ZoneImageParts {
        apex: name("example.com"),
        serial: RFC2782_SERIAL,
        soa: SoaParameters {
            rname: name("root.example.com"),
            refresh: RFC2782_REFRESH,
            retry: RFC2782_RETRY,
            expire: RFC2782_EXPIRE,
            minimum: RFC2782_MINIMUM,
        },
        infrastructure_ttl: TTL,
        dc: host(b"server", &[[172, 30, 79, 10]], TTL),
        hosts: vec![
            host(b"old-slow-box", &[[172, 30, 79, 11]], TTL),
            host(b"sysadmins-box", &[[172, 30, 79, 12]], TTL),
            host(b"new-fast-box", &[[172, 30, 79, 13]], TTL),
        ],
        kpasswd: KpasswdService::Absent,
    }
}

/// A distinct 63-octet LDH label for host number `index` (hand-made: "h",
/// 54 octets "x" of padding, the index in 8 hex digits).
pub fn long_label(index: u32) -> Vec<u8> {
    let mut label = b"h".to_vec();
    label.extend_from_slice(&[b'x'; 54]);
    label.extend_from_slice(format!("{index:08x}").as_bytes());
    assert_eq!(label.len(), 63);
    label
}

/// Eight distinct private addresses for host number `index` (hand-made, in
/// 10.0.0.0/8, never loopback, unspecified or multicast).
pub fn eight_addresses(index: u32) -> Vec<[u8; 4]> {
    let [_, b, c, _] = index.to_be_bytes();
    (1..=8u8).map(|d| [10, b, c, d]).collect()
}

/// A valid image with `count` member hosts, every label 63 octets and every
/// host with eight addresses — the largest host records dns-zone admits.
pub fn large_parts(count: u32) -> ZoneImageParts {
    let mut parts = rfc2782_parts();
    parts.hosts = (0..count)
        .map(|index| host(&long_label(index), &eight_addresses(index), TTL))
        .collect();
    parts
}

/// A hand-made DNS message of `len` octets (≥ 12): an UPDATE header (RFC
/// 1035 §4.1.1 layout; RFC 2136 §2.2 opcode 5) followed by filler. The
/// channel never interprets it.
pub fn message_octets(len: usize) -> Vec<u8> {
    assert!(len >= 12);
    let mut octets = vec![0x12, 0x34, 0x28, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
    octets.resize(len, 0xA5);
    octets
}

/// The body of one encoded reply frame.
pub fn reply_body(reply: &DnsReply) -> Vec<u8> {
    encode_reply(reply).expect("reply encodes").body().to_vec()
}

/// The body of one encoded shared refusal.
pub fn refusal_body(refused: ipc::Refused) -> Vec<u8> {
    encode_refusal(refused)
        .expect("refusal encodes")
        .body()
        .to_vec()
}

// ---- scripted connection ---------------------------------------------------

/// What the scripted connections saw.
#[derive(Debug, Default)]
pub struct Log {
    /// Connections opened.
    pub connects: usize,
    /// Every frame sent, as (connection number, frame body).
    pub sent: Vec<(usize, Vec<u8>)>,
}

impl Log {
    /// The kinds of the frames sent, in order.
    pub fn kinds(&self) -> Vec<u8> {
        self.sent.iter().map(|(_, body)| body[3]).collect()
    }
}

/// One scripted connection: its peer uid, its idle-check answer, and the
/// reply bodies (or transport failures) it hands out in order.
pub struct Script {
    pub uid: Result<u32, TransportError>,
    pub idle: Result<(), TransportError>,
    pub replies: VecDeque<Result<Vec<u8>, TransportError>>,
}

impl Script {
    /// dird's uid, usable when idle, these replies.
    pub fn dird(replies: Vec<Vec<u8>>) -> Script {
        Script {
            uid: Ok(DIRD_UID),
            idle: Ok(()),
            replies: replies.into_iter().map(Ok).collect(),
        }
    }
}

pub struct ScriptedConnection {
    number: usize,
    script: Script,
    log: Rc<RefCell<Log>>,
}

impl Connection for ScriptedConnection {
    fn peer_uid(&self) -> Result<u32, TransportError> {
        self.script.uid
    }

    fn send(&mut self, frame: &[u8], deadline: Duration) -> Result<(), TransportError> {
        if deadline.is_zero() {
            return Err(TransportError::DeadlineExceeded);
        }
        self.log
            .borrow_mut()
            .sent
            .push((self.number, frame[4..].to_vec()));
        Ok(())
    }

    fn receive(
        &mut self,
        limit: FrameLimit,
        deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        if deadline.is_zero() {
            return Err(TransportError::DeadlineExceeded);
        }
        let body = self
            .script
            .replies
            .pop_front()
            .unwrap_or(Err(TransportError::Closed))?;
        // As ipc's FrameReader: the declared length against the bound.
        if body.len() > limit.max_body() as usize {
            return Err(TransportError::Framing);
        }
        Ok(Zeroizing::new(body))
    }

    fn check_idle(&mut self) -> Result<(), TransportError> {
        self.script.idle
    }
}

/// Hands out the scripted connections in order; then refuses to connect.
pub struct ScriptedConnector {
    scripts: VecDeque<Script>,
    pub log: Rc<RefCell<Log>>,
}

impl ScriptedConnector {
    pub fn new(scripts: Vec<Script>) -> ScriptedConnector {
        ScriptedConnector {
            scripts: scripts.into(),
            log: Rc::new(RefCell::new(Log::default())),
        }
    }
}

impl Connector for ScriptedConnector {
    type Connection = ScriptedConnection;

    fn connect(&mut self) -> Result<ScriptedConnection, TransportError> {
        let script = self.scripts.pop_front().ok_or(TransportError::Connect)?;
        let number = {
            let mut log = self.log.borrow_mut();
            log.connects += 1;
            log.connects
        };
        Ok(ScriptedConnection {
            number,
            script,
            log: Rc::clone(&self.log),
        })
    }
}
