//! dird's side of the channel: decode one request body (or say how to
//! refuse it), encode the replies, and the dispatch skeleton — the zone of a
//! connection from the front's peer uid, and a pure dispatcher that asks the
//! host (dird, a later task) for the answer to each request.
//!
//! # The connection's zone (docs/52 §3.3 C3, §7 R14)
//!
//! The zone is fixed when the connection is made — [`KpasswdConnection::new`]
//! takes a [`FrontZone`], which dird derives from the **peer uid** of the
//! channel connection (the front's identity, a kernel fact: docs/50 R50-3)
//! through [`KpasswdFronts`] before any frame is read; a peer that is not
//! the front is closed without a reply. dird holds no zone table (A-114):
//! phase 1 has one kpasswd front, internal only (docs/53 §3.3). Every `Pong`
//! names that zone, so the front can refuse a dird that would treat it as
//! another front, and every request reaches the host with it.
//!
//! # Requests
//!
//! | request | host call | reply |
//! |---|---|---|
//! | `Ping` | — | `Pong { zone: the connection's zone }`; the connection stays open |
//! | `ChangePassword` | [`KpasswdHost::change_password`] with the connection's zone | `Sealed` or `Unsealed`, **then close**: one change per connection, as RFC 3244 §2 has one request and one reply per client connection |
//!
//! A request that does not decode follows docs/50 §3.3: a wrong magic, an
//! unknown kind or a body outside the envelope bounds ⇒ close without a
//! reply; another version ⇒ `Refused{VersionMismatch}` + close; a payload
//! error (a Kerberos field with the wrong identifier included) ⇒
//! `Refused{Malformed}` + close — nothing malformed reaches the host. A host
//! refusal ([`Unserved::Busy`] — dird's bounded kpasswd queue is full;
//! [`Unserved::Unavailable`]) ⇒ the shared `Refused{Busy}` /
//! `Refused{Unavailable}` + close; the front answers its client HARDERROR
//! (docs/53 §5.6 step 1, §5.7). Once closed, a connection answers nothing.
//!
//! # Why not a separate crate (as ipc-dns-server)
//!
//! ipc-dns-server, ipc-ldap-server and ipc-keyd-server are separate crates
//! because a cargo *feature* of the channel crate would be unified into the
//! client's build (A-63, A-68). This crate has **no feature**: the
//! dispatcher is an ordinary module that holds no socket, no thread, no
//! clock, no directory and no keyd client — it decodes and calls a host
//! trait. The front links it but has no host to give it (docs/questions/
//! Q-955 item 2).
//!
//! Spec: docs/53 §3.3, §4.3, §5.6, §5.7; A-114; docs/50 R50-3, R50-7, §3.2,
//! §3.3, §7.5; docs/52 §3.3, §7 R14; A-59.

use crate::channel::KPASSWD_CHANNEL;
use crate::values::{ChangePasswordRequest, FrontZone, KpasswdAnswer};
use crate::wire::{KpasswdReply, KpasswdRequest};
use core::fmt;
use ipc::{decode_body, encode_frame, encode_refused, Direction, EncodedFrame, Refused};

/// How dird answers a request body that it does not serve.
/// Spec: docs/50 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Close the connection without a reply (wrong magic, unknown kind, a
    /// body outside the envelope bounds).
    Close,
    /// Send the shared refusal, then close.
    Refuse(Refused),
}

/// Decode one request body (as cut by `ipc::FrameReader` under
/// [`crate::REQUEST_LIMIT`]).
///
/// # Errors
/// [`Rejection`] (module documentation).
///
/// Spec: docs/53 §4.3; docs/50 §3.3.
pub fn decode_request(body: &[u8]) -> Result<KpasswdRequest, Rejection> {
    decode_body::<KpasswdRequest>(KPASSWD_CHANNEL, Direction::Request, body)
        .map_err(|error| error.refusal().map_or(Rejection::Close, Rejection::Refuse))
}

/// Encode one reply as a frame.
///
/// # Errors
/// An `ipc::Error` (the reply breaks a bound — cannot happen with the value
/// types); the caller answers `Refused{Unavailable}` instead.
///
/// Spec: docs/53 §5.5–§5.7; docs/50 §3.3.
pub fn encode_reply(reply: &KpasswdReply) -> Result<EncodedFrame, ipc::Error> {
    encode_frame(KPASSWD_CHANNEL, Direction::Reply, reply)
}

/// Encode the shared refusal on this channel.
///
/// # Errors
/// An `ipc::Error` (cannot happen: every bound has room for it, A-59).
///
/// Spec: docs/50 §3.3; A-59.
pub fn encode_refusal(refused: Refused) -> Result<EncodedFrame, ipc::Error> {
    encode_refused(KPASSWD_CHANNEL, refused)
}

/// The connection a request came on, as dird numbers them (never anything
/// the peer sent) — for dird's own bookkeeping and audit records.
/// Spec: docs/50 §3.2.
pub type ConnectionId = u64;

/// The kpasswd front dird admits on `dird-kpasswd.sock`, by peer uid
/// (docs/53 §5.6 step 1: "the peer on dird-kpasswd.sock = the front's uid
/// only (R50-3)"): phase 1 has one, the internal one (A-114).
/// Spec: docs/53 §3.3, §5.6; docs/50 R50-3, §3.2; docs/52 §7 R14.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KpasswdFronts {
    internal: u32,
}

impl KpasswdFronts {
    /// The fronts of a dird whose kpasswd front runs as `front_uid` (dird's
    /// configuration, a later task).
    /// Spec: docs/53 §5.6.
    #[must_use]
    pub const fn new(front_uid: u32) -> KpasswdFronts {
        KpasswdFronts {
            internal: front_uid,
        }
    }

    /// The zone of the front whose channel connection has the peer uid
    /// `peer_uid` (read from the kernel's peer credentials, never from the
    /// peer), or `None`: not the front — the connection is closed without a
    /// reply. uid 0 is never a front (R50-3: "uid 0 is never mapped").
    /// Spec: docs/50 R50-3, §3.2; docs/53 §3.3; A-114.
    #[must_use]
    pub const fn zone_of(&self, peer_uid: u32) -> Option<FrontZone> {
        if peer_uid != 0 && peer_uid == self.internal {
            Some(FrontZone::Internal)
        } else {
            None
        }
    }
}

/// Why the host did not answer a request (module documentation).
/// Spec: docs/53 §5.6 step 1 ("full ⇒ `Busy` ⇒ the front answers
/// HARDERROR"); docs/50 R50-7, §3.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// dird's bounded kpasswd queue is full.
    Busy,
    /// A dependency the request needs (keyd, auditd, the store) is not
    /// available, and dird has no keyd context to seal an answer in.
    Unavailable,
}

/// What dird supplies for the requests of the front's connections (a later
/// task: the kpasswd thread with its bounded queue and one request in
/// flight, docs/53 §5.6).
/// Spec: docs/53 §5.6, §5.7.
pub trait KpasswdHost {
    /// Run docs/53 §5.6 steps 2–6 over one request — keyd
    /// `open_change_password_request` (with the request's two messages and
    /// addresses, keyd's own clock), the verdict, directory-admin's
    /// `ChangePassword` (the PDP on User-Change-Password on the account
    /// itself), the acknowledged intent, pwdLastSet, the `ChangePassword`
    /// decision, keyd `complete_change_password` — and return keyd's sealed
    /// reply, or the unsealed code of §5.7 when there is no context to seal
    /// in (keyd's `Denied` ⇒ AUTHERROR; `Unavailable` / an unknown outcome
    /// ⇒ HARDERROR).
    ///
    /// # Errors
    /// [`Unserved`].
    ///
    /// Spec: docs/53 §5.5–§5.7; A-126.
    fn change_password(
        &mut self,
        zone: FrontZone,
        request: &ChangePasswordRequest,
    ) -> Result<KpasswdAnswer, Unserved>;
}

/// What to send, and whether the connection then closes.
/// Spec: docs/50 §3.3 (bad prefix, wrong magic, unknown kind ⇒ close without
/// a reply; wrong version ⇒ `Refused{VersionMismatch}` + close; malformed ⇒
/// `Malformed` + close).
pub enum Dispatch {
    /// Send the frame; the connection stays open.
    Reply(EncodedFrame),
    /// Send the frame, then close the connection.
    ReplyAndClose(EncodedFrame),
    /// Close the connection without a reply.
    Close,
}

impl fmt::Debug for Dispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dispatch::Reply(frame) => f.debug_tuple("Reply").field(&frame.len()).finish(),
            Dispatch::ReplyAndClose(frame) => {
                f.debug_tuple("ReplyAndClose").field(&frame.len()).finish()
            }
            Dispatch::Close => f.write_str("Close"),
        }
    }
}

impl Dispatch {
    /// The frame to send, if any.
    #[must_use]
    pub fn frame(&self) -> Option<&EncodedFrame> {
        match self {
            Dispatch::Reply(frame) | Dispatch::ReplyAndClose(frame) => Some(frame),
            Dispatch::Close => None,
        }
    }

    /// Whether the connection closes after the frame.
    #[must_use]
    pub fn closes(&self) -> bool {
        !matches!(self, Dispatch::Reply(_))
    }
}

/// The shared refusal frame, then close; a refusal that cannot be encoded
/// (never, given ipc's minimum body bound) closes without a reply.
/// Spec: docs/50 §3.3; A-59.
#[must_use]
pub fn refuse(refused: Refused) -> Dispatch {
    match encode_refusal(refused) {
        Ok(frame) => Dispatch::ReplyAndClose(frame),
        Err(_) => Dispatch::Close,
    }
}

/// One channel connection from the kpasswd front (module documentation).
/// Spec: docs/53 §5.6; docs/52 R14.
pub struct KpasswdConnection {
    id: ConnectionId,
    /// The zone of the front this connection came from — fixed at
    /// construction, from the peer uid.
    zone: FrontZone,
    closed: bool,
}

impl fmt::Debug for KpasswdConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KpasswdConnection")
            .field("id", &self.id)
            .field("zone", &self.zone)
            .field("closed", &self.closed)
            .finish()
    }
}

impl KpasswdConnection {
    /// A new connection numbered `id` by dird, from the front of `zone`
    /// ([`KpasswdFronts::zone_of`] the connection's peer uid).
    /// Spec: docs/53 §5.6; docs/50 §3.2; docs/52 §7 R14.
    #[must_use]
    pub fn new(id: ConnectionId, zone: FrontZone) -> KpasswdConnection {
        KpasswdConnection {
            id,
            zone,
            closed: false,
        }
    }

    /// dird's number for this connection.
    #[must_use]
    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// The zone of the front this connection came from.
    #[must_use]
    pub fn zone(&self) -> FrontZone {
        self.zone
    }

    /// Whether the connection is over (nothing more is processed).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Close and send `refused`.
    fn refuse(&mut self, refused: Refused) -> Dispatch {
        self.closed = true;
        refuse(refused)
    }

    /// Handle one request body (module documentation).
    /// Spec: docs/53 §5.6, §5.7; docs/50 §3.3; A-59.
    pub fn handle(&mut self, body: &[u8], host: &mut dyn KpasswdHost) -> Dispatch {
        if self.closed {
            return Dispatch::Close;
        }
        let request = match decode_request(body) {
            Ok(request) => request,
            Err(Rejection::Close) => {
                self.closed = true;
                return Dispatch::Close;
            }
            Err(Rejection::Refuse(refused)) => return self.refuse(refused),
        };
        match request {
            KpasswdRequest::Ping => match encode_reply(&KpasswdReply::Pong { zone: self.zone }) {
                Ok(frame) => Dispatch::Reply(frame),
                Err(_) => self.refuse(Refused::Unavailable),
            },
            KpasswdRequest::ChangePassword(request) => {
                match host.change_password(self.zone, &request) {
                    Ok(answer) => {
                        let reply = match answer {
                            KpasswdAnswer::Sealed(sealed) => KpasswdReply::Sealed(sealed),
                            KpasswdAnswer::Unsealed(code) => KpasswdReply::Unsealed(code),
                        };
                        match encode_reply(&reply) {
                            Ok(frame) => {
                                // One change per connection (module
                                // documentation).
                                self.closed = true;
                                Dispatch::ReplyAndClose(frame)
                            }
                            Err(_) => self.refuse(Refused::Unavailable),
                        }
                    }
                    Err(Unserved::Busy) => self.refuse(Refused::Busy),
                    Err(Unserved::Unavailable) => self.refuse(Refused::Unavailable),
                }
            }
        }
    }
}
