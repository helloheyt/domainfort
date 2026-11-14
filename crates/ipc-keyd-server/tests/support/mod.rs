//! An in-process loopback for the keyd channel: a `Connector` whose
//! connections hand each request frame to `ipc_keyd_server::dispatch` on a shared
//! keyd, with the caller identity of the "connection" and the "daemon's"
//! clock — exactly the two values the keyd-daemon will take from peer
//! credentials and from its own clock (docs/50 §3.2, R50-5).
//!
//! Switches play the transport failures and refusals a real daemon can
//! produce (docs/50 §3.6, §3.7): connect refused, unreadable or wrong peer
//! uid, deadline exceeded, a `Refused` reply, a malformed reply, a reply of
//! another operation. Every request body the "server" received is recorded,
//! so a test can show that nothing was sent.
//!
//! Source: docs/50 §3.1-§3.7, §9 tier 1 ("in-process … codecs"); docs/10 §2.
//! Test-only construction; no vector comes from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

use ipc::{decode_frame, encode_refused, FrameLimit, FrameStatus, Refused};
use ipc_keyd::{Connection, Connector, TransportError, KEYD_CHANNEL, REQUEST_LIMIT};
use ipc_keyd_server::{dispatch, Dispatch};
use keyd::{AuditSink, CallerId, EntropySource, KeyStore, Keyd};
use krb_proto::KerberosTime;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use zeroize::Zeroizing;

/// The uid the loopback's keyd "runs as" (test value).
pub const KEYD_UID: u32 = 900;

/// Failures the loopback plays.
#[derive(Debug, Default, Clone, Copy)]
pub struct Faults {
    /// `connect` fails (keyd down).
    pub refuse_connect: bool,
    /// The peer credentials cannot be read.
    pub peer_credentials_unreadable: bool,
    /// The deadline passes; the request is not delivered.
    pub deadline: bool,
    /// The server answers this transport refusal instead of serving.
    pub refuse: Option<Refused>,
    /// The server's reply gets one extra octet (not canonical / trailing).
    pub trailing_reply_octet: bool,
    /// The server answers with a `ping` reply (naming the connection's
    /// role) whatever the request.
    pub foreign_reply: bool,
    /// When set, the exchange-level faults above (deadline, refusal,
    /// trailing octet, foreign reply) apply only to requests of this kind;
    /// other requests are served.
    pub only_kind: Option<u8>,
}

/// What the loopback's "server" holds.
pub struct Server<S: KeyStore, A: AuditSink, E: EntropySource> {
    pub keyd: Keyd<S, A, E>,
    /// The keyd daemon's own clock.
    pub clock: KerberosTime,
    pub faults: Faults,
    /// Every request body that reached the server, in order.
    pub received: Vec<Vec<u8>>,
    /// Connections opened.
    pub connects: usize,
}

pub type Shared<S, A, E> = Rc<RefCell<Server<S, A, E>>>;

pub fn share<S: KeyStore, A: AuditSink, E: EntropySource>(
    keyd: Keyd<S, A, E>,
    clock: KerberosTime,
) -> Shared<S, A, E> {
    Rc::new(RefCell::new(Server {
        keyd,
        clock,
        faults: Faults::default(),
        received: Vec::new(),
        connects: 0,
    }))
}

/// Connections for one caller identity (as keyd's uid → role map would
/// assign it, docs/50 §3.2) to the shared server, which appears to run as
/// `peer_uid`.
pub struct Loopback<S: KeyStore, A: AuditSink, E: EntropySource> {
    pub server: Shared<S, A, E>,
    pub caller: CallerId,
    pub peer_uid: u32,
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Loopback<S, A, E> {
    pub fn new(server: &Shared<S, A, E>, caller: CallerId) -> Self {
        Loopback {
            server: Rc::clone(server),
            caller,
            peer_uid: KEYD_UID,
        }
    }
}

pub struct LoopbackConnection<S: KeyStore, A: AuditSink, E: EntropySource> {
    server: Shared<S, A, E>,
    caller: CallerId,
    peer_uid: u32,
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Connector for Loopback<S, A, E> {
    type Connection = LoopbackConnection<S, A, E>;

    fn connect(&mut self) -> Result<Self::Connection, TransportError> {
        let mut server = self.server.borrow_mut();
        if server.faults.refuse_connect {
            return Err(TransportError::Connect);
        }
        server.connects += 1;
        Ok(LoopbackConnection {
            server: Rc::clone(&self.server),
            caller: self.caller,
            peer_uid: self.peer_uid,
        })
    }
}

/// The body of a whole frame, checked against `limit`.
fn body_of(frame: &[u8], limit: FrameLimit) -> Result<Vec<u8>, TransportError> {
    match decode_frame(frame, limit) {
        Ok(FrameStatus::Complete { body, frame_len }) if frame_len == frame.len() => {
            Ok(body.to_vec())
        }
        _ => Err(TransportError::Framing),
    }
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Connection for LoopbackConnection<S, A, E> {
    fn peer_uid(&self) -> Result<u32, TransportError> {
        if self.server.borrow().faults.peer_credentials_unreadable {
            return Err(TransportError::PeerCredentials);
        }
        Ok(self.peer_uid)
    }

    fn exchange(
        &mut self,
        frame: &[u8],
        reply_limit: FrameLimit,
        _deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        let mut server = self.server.borrow_mut();
        let request = body_of(frame, REQUEST_LIMIT)?;
        let mut faults = server.faults;
        if faults
            .only_kind
            .is_some_and(|kind| request.get(3) != Some(&kind))
        {
            faults = Faults::default();
        }
        if faults.deadline {
            return Err(TransportError::DeadlineExceeded);
        }
        server.received.push(request.clone());
        let reply = if let Some(refused) = faults.refuse {
            encode_refused(KEYD_CHANNEL, refused).map_err(|_| TransportError::Framing)?
        } else if faults.foreign_reply {
            // A well-formed `ping` reply naming the connection's role
            // (task R9): foreign to every operation but `ping`.
            ipc::encode_frame(
                KEYD_CHANNEL,
                ipc::Direction::Reply,
                &ipc_keyd::KeydReply::Ping(self.caller.role),
            )
            .map_err(|_| TransportError::Framing)?
        } else {
            let clock = server.clock;
            match dispatch(&mut server.keyd, self.caller, clock, &request) {
                Dispatch::Reply(frame) | Dispatch::ReplyAndClose(frame) => frame,
                Dispatch::Close => return Err(TransportError::Closed),
            }
        };
        let mut body = body_of(reply.as_bytes(), reply_limit)?;
        if faults.trailing_reply_octet {
            body.push(0x00);
        }
        Ok(Zeroizing::new(body))
    }

    /// The in-process "server" lives as long as the connection and nothing
    /// is ever written to it outside an exchange: always usable (the check
    /// has no default since task R9 — this transport says so itself).
    /// Spec: docs/questions/Q-312 (A-82), Q-466 item 4.
    fn check_idle(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
