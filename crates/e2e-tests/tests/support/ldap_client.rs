//! The LDAP client side of the harness, written from RFC 4511 (one PDU
//! after another over the TCP byte stream, §5.2) with this project's
//! parse-ldap codec, and the in-process reference path (the LDAP engine
//! called directly, as dird calls it — docs/50 §9).
//!
//! The helpers follow crates/ldap-front/tests/common/world.rs (this
//! project's code): the TLS client is rustls itself (docs/50 §9) with the
//! trust model of [`super::tls`].
//!
//! Sources: RFC 4511 §4.1.1, §4.2, §4.4.1, §4.5.1, §4.14.1, §5.2; RFC 4513
//! §3.1.1; docs/49 §5.2; docs/50 §4.2, §4.3, §9. Every value is made here.
#![allow(dead_code)]

use super::tls::server_name;
use core::net::SocketAddr;
use core::time::Duration;
use directory_daemon::policy::DevelopmentPolicy;
use dirstore::Store;
use krb_proto::KerberosTime;
use ldap::{
    DirectoryInputs, Engine, EngineConfig, RateLimiter, RequestInputs, RootDseConfig, SearchClock,
    Session, TransportReport,
};
use parse_ldap::{
    decode_message, encode_message, frame_length, AuthState, DecodeOptions,
    Direction as LdapDirection, Frame, LdapMessage, Profile, ProtocolOp, ResultCode,
    MAX_AUTH_MESSAGE_OCTETS,
};
use pdp::{IpScope, RlKey};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{ErrorKind, Read};
use std::net::TcpStream;
use std::sync::Arc;

/// How long a client read or write may take (every socket wait is bounded).
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Reads one LDAPMessage at a time from a stream (RFC 4511 §5.2), keeping
/// what follows it. The announced size is checked by parse-ldap's framer
/// before any wait for the contents.
#[derive(Default)]
pub struct LdapReader {
    buffer: Vec<u8>,
}

impl LdapReader {
    /// The next message, or `None` at the end of the stream, a timeout, or
    /// octets that are not an LDAPMessage.
    pub fn next<R: Read>(&mut self, stream: &mut R) -> Option<Vec<u8>> {
        loop {
            match frame_length(&self.buffer, AuthState::Authenticated) {
                Ok(Frame::Complete { length }) => {
                    return Some(self.buffer.drain(..length).collect());
                }
                Ok(Frame::NeedMore) => {}
                Err(_) => return None,
            }
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(read) => self.buffer.extend_from_slice(&chunk[..read]),
            }
        }
    }

    /// Whether nothing is left over.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

/// Whether the peer closed `stream` (end of stream, a reset, or a TLS
/// closure) within the read timeout with no further octet; `Err(octets)` if
/// octets came instead (or `"still open"` on a timeout).
pub fn closed<R: Read>(stream: &mut R) -> Result<(), Vec<u8>> {
    let mut chunk = [0u8; 1024];
    match stream.read(&mut chunk) {
        Ok(0) => Ok(()),
        Ok(read) => Err(chunk[..read].to_vec()),
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            Err(b"still open".to_vec())
        }
        Err(_) => Ok(()),
    }
}

/// A TCP connection to `address` with bounded reads and writes.
pub fn tcp(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(address).expect("connect to ldap-front");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    stream
}

/// A TLS client stream over `stream`, the handshake completed, or its
/// error. Spec: RFC 4513 §3.1; RFC 8446 §2.
pub fn tls_over(
    stream: TcpStream,
    config: &Arc<ClientConfig>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let mut connection =
        ClientConnection::new(Arc::clone(config), server_name()).map_err(|e| e.to_string())?;
    let mut stream = stream;
    while connection.is_handshaking() {
        connection
            .complete_io(&mut stream)
            .map_err(|e| e.to_string())?;
    }
    Ok(StreamOwned::new(connection, stream))
}

/// An LDAPMessage of `protocol_op` with messageID `id`, canonical.
/// Spec: RFC 4511 §4.1.1.
pub fn encoded(id: u32, protocol_op: ProtocolOp) -> Vec<u8> {
    encode_message(&LdapMessage {
        message_id: parse_ldap::MessageId::new(id).unwrap(),
        protocol_op,
        controls: None,
    })
    .unwrap()
}

/// A search of `base` with `scope` for `(objectClass=*)`, every attribute.
/// Spec: RFC 4511 §4.5.1, §4.5.1.7.5.
fn search(id: u32, base: &str, scope: parse_ldap::Scope) -> Vec<u8> {
    encoded(
        id,
        ProtocolOp::SearchRequest(parse_ldap::SearchRequest {
            base_object: base.to_owned(),
            scope,
            deref_aliases: parse_ldap::DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: parse_ldap::Filter::Present("objectClass".to_owned()),
            attributes: vec![],
        }),
    )
}

/// The rootDSE search: the empty base at baseObject (RFC 4511 §4.5.1;
/// docs/49 §5.2).
pub fn root_dse(id: u32) -> Vec<u8> {
    search(id, "", parse_ldap::Scope::BaseObject)
}

/// An anonymous search of the directory: the naming context
/// dc=example,dc=org, wholeSubtree (RFC 4511 §4.5.1.2).
pub fn directory_search(id: u32) -> Vec<u8> {
    search(id, "dc=example,dc=org", parse_ldap::Scope::WholeSubtree)
}

/// StartTLS (RFC 4511 §4.14.1: requestName 1.3.6.1.4.1.1466.20037, no
/// requestValue).
pub fn start_tls(id: u32) -> Vec<u8> {
    encoded(
        id,
        ProtocolOp::ExtendedRequest(parse_ldap::ExtendedRequest {
            request_name: parse_ldap::START_TLS_OID.to_owned(),
            request_value: None,
        }),
    )
}

/// A simple bind with a password, messageID 1: `30 16 02 01 01 60 11 02 01
/// 03 04 04 "cn=x" 80 06 "secret"` — the LDAPMessage envelope (RFC 4511
/// §4.1.1) around a BindRequest (§4.2: version 3, name, `simple [0]`), the
/// octets crates/ldap-front/tests/front.rs builds for the same refusal. The
/// canonical encoder cannot produce it: the password is never retained
/// (docs/49 §2.3, A-52).
pub fn password_bind() -> Vec<u8> {
    let mut bind = vec![
        0x30, 0x16, 0x02, 0x01, 0x01, 0x60, 0x11, 0x02, 0x01, 0x03, 0x04, 0x04,
    ];
    bind.extend_from_slice(b"cn=x");
    bind.extend_from_slice(&[0x80, 0x06]);
    bind.extend_from_slice(b"secret");
    bind
}

/// The decoded response (canonical profile, response direction).
pub fn decoded(response: &[u8]) -> LdapMessage {
    decode_message(
        response,
        &DecodeOptions {
            direction: LdapDirection::Response,
            profile: Profile::Canonical,
            max_message_octets: MAX_AUTH_MESSAGE_OCTETS,
        },
    )
    .expect("a canonical LDAP response")
}

/// The resultCode of an LDAPResult-bearing response (RFC 4511 §4.1.9).
pub fn result_code(response: &[u8]) -> ResultCode {
    match decoded(response).protocol_op {
        ProtocolOp::SearchResultDone(result) => result.result_code,
        ProtocolOp::ExtendedResponse(response) => response.result.result_code,
        ProtocolOp::BindResponse(response) => response.result.result_code,
        other => panic!("not an LDAPResult: {other:?}"),
    }
}

/// The Notice of Disconnection with `code` (RFC 4511 §4.4.1), canonical.
pub fn notice(code: ResultCode) -> Vec<u8> {
    encode_message(&LdapMessage::notice_of_disconnection(code)).unwrap()
}

/// A rate limiter that admits everything (the reference path only).
struct AdmitAll;

impl RateLimiter for AdmitAll {
    fn admit(&mut self, _key: &RlKey, _now: &KerberosTime) -> bool {
        true
    }
}

/// The reference search clock: the fixed test time.
struct FixedSearchClock(KerberosTime);

impl SearchClock for FixedSearchClock {
    fn now(&self) -> KerberosTime {
        self.0
    }
}

/// The LDAP engine called in-process over `store` with the snapshot and
/// tier map of `policy` at `now`, as dird calls it (the reference of
/// docs/50 §9; crates/ldap-front/tests/common/world.rs `direct`). The
/// requests are decided under the internal zone (dird derives it from the
/// front's peer uid — docs/52 R14).
/// Spec: docs/49 R49-16; docs/50 §4.2.
pub fn direct(
    store: &Store,
    policy: &DevelopmentPolicy,
    now: KerberosTime,
    session: &mut Session,
    message: &[u8],
    tls: bool,
    input_pending: bool,
) -> ldap::Outcome {
    let snapshot = policy.snapshot().unwrap();
    let tiers = directory_daemon::policy::tier_map(policy).unwrap();
    let ctx = super::harness::directory_context();
    let view = ctx.view(store, &tiers).unwrap();
    let engine = Engine::new(EngineConfig {
        root_dse: RootDseConfig {
            naming_context: super::harness::dird::naming_context(),
            dns_host_name: String::from(super::harness::DNS_HOST_NAME),
        },
    })
    .unwrap();
    let mut rate = AdmitAll;
    let clock = FixedSearchClock(now);
    engine.handle(
        session,
        message,
        RequestInputs {
            snapshot: &snapshot,
            pip: &view,
            subjects: &view,
            rate: &mut rate,
            now,
            transport: TransportReport {
                src_net: IpScope::Internal,
                tls_established: tls,
                input_pending,
            },
            directory: Some(DirectoryInputs {
                view: directory_pip::PepView::new(&view),
                clock: &clock,
            }),
        },
    )
}
