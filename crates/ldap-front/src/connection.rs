//! One client connection: the transport (cleartext or rustls over the TCP
//! stream), the framer, the dird session, and the StartTLS hand-over.
//!
//! # The session (docs/50 R50-10, §4.2)
//!
//! ```text
//!  LDAP (389):  accept ─► Open{Ldap} ─► loop
//!  LDAPS (636): accept ─► TLS handshake ─► parameters checked ─► Open{Ldaps} ─► loop
//!  loop: frame (dird's framing state) ─► wire→canonical ─► Message ─► responses ─► action
//!        Continue ─► loop     Close ─► close     StartTls ─► hand-over ─► loop (TLS)
//! ```
//!
//! rustls is sans-I/O (`read_tls`, `process_new_packets`, `reader`,
//! `writer`, `write_tls`), so the front feeds it the octets it reads from
//! tokio's `TcpStream` and writes out what it produces — no adapter crate
//! (docs/50 §4.3).
//!
//! # Reading only while a message is incomplete (docs/50 §4.3 step 1)
//!
//! The socket is read only when the buffered octets do not yet hold one
//! whole message; while a request is out to dird nothing is read (each
//! message is answered before the next is cut, R50-7). So a StartTLS
//! request is followed by no read at all until dird's answer, and the
//! buffer is bounded by one message plus one read.
//!
//! # The StartTLS hand-over (docs/50 §4.3, mandatory order)
//!
//! 1. The StartTLS request goes to dird with `input_pending` = whether the
//!    cleartext buffer holds octets after it; nothing is read meanwhile.
//! 2. dird's engine refuses when `input_pending` (operationsError + close),
//!    or answers `StartTls`.
//! 3. On `StartTls`: the response is written in cleartext; the cleartext
//!    buffer must be empty (defence in depth — else close, without another
//!    cleartext octet); it is destroyed (wiped); a `ServerConnection` is
//!    created; from then on every octet read from the socket goes to
//!    `read_tls` only, and plaintext comes only from `reader()` into a new
//!    buffer. A cleartext octet injected after the response is parsed as TLS
//!    and fails ⇒ close.
//! 4. When the handshake completes, the version and the cipher suite are
//!    checked against R50-11 (crate::tls::check_negotiated) — only then is
//!    `TlsEstablished` sent and `tls_established = true` reported.
//! 5. A close_notify or any TLS error closes the session; there is no way
//!    back to cleartext (docs/49 §4.4; RFC 4511 §4.14.3: "Protocol peers MAY
//!    terminate the LDAP session after sending or receiving a TLS closure
//!    alert").
//! 6. On 636 the same path from the first octet, `Listener::Ldaps`; dird is
//!    opened only after the handshake (A-70 / Q-280 item 5).
//!
//! # When dird does not serve (docs/50 §3.7)
//!
//! Any [`ChannelFailure`] closes the client connection; first the front
//! writes the Notice of Disconnection (busy for `Refused::Busy`, otherwise
//! unavailable — ipc-ldap; RFC 4511 §4.4.1) on the current layer — never
//! between a StartTLS response and the end of the handshake, where it just
//! closes.
//!
//! # Timeouts and pools (docs/50 §4.2)
//!
//! InitRecvTimeout: the first whole message within `init_recv_timeout` of
//! the accept (the LDAPS handshake included). MaxConnIdleTime: each later
//! message within `max_conn_idle_time` of the previous answer. The TLS
//! handshake within `tls_handshake_timeout`. dird's answer within
//! `dird_deadline`. Each write to the client within [`CLIENT_WRITE_TIMEOUT`].
//! A connection holds a slot of the unauthenticated pool while dird reports
//! the framing state `Unauthenticated` (docs/50 §4.2: "a separate pool for
//! unauthenticated connections"; docs/07 §1); with no slot left when a
//! session falls back to unauthenticated, it is closed with a busy notice.
//!
//! Spec: docs/50 R50-7, R50-10, R50-11, §3.6, §3.7, §4.2, §4.3, §8.2;
//! docs/49 R49-15, R49-16, §4.3, §4.4; RFC 4511 §4.1.1, §4.4.1, §4.14,
//! §5.2, §5.3; RFC 4513 §3.1.1, §3.1.4; docs.rs rustls 0.23.46
//! `ServerConnection` (`read_tls`, `process_new_packets`, `reader`, `writer`,
//! `write_tls`, `wants_write`, `is_handshaking`, `send_close_notify`),
//! `IoState::peer_has_closed`, `Reader` (`BufRead`); tokio 1.54.1
//! `net::TcpStream`, `time::{timeout, timeout_at}`, `sync::Semaphore`.

use crate::dird::{DirdSession, Endpoint};
use crate::log::{
    CLEARTEXT_AFTER_START_TLS, DIRD_NOT_SERVING, HANDSHAKE_FAILED, NOT_LDAP, TIMED_OUT,
    TLS_PARAMETERS_REFUSED,
};
use crate::relay::{take_message, FrameFailure, WireBuffer, READ_CHUNK};
use crate::tls::check_negotiated;
use core::net::SocketAddr;
use core::time::Duration;
use ipc_ldap::{
    notice_of_disconnection, ChannelFailure, ConnectionAction, Listener, TransportFacts,
};
use parse_ldap::{encode_message, AuthState, LdapMessage, ResultCode};
use rustls::server::{ServerConfig, ServerConnection};
use std::io::{BufRead, ErrorKind, Write};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, timeout_at, Instant};
use zeroize::Zeroizing;

/// How long one write to the client may take (a response, a TLS flight).
/// Project choice (docs/50 gives no write bound; docs/questions/Q-285
/// item 6).
pub const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the closing writes (Notice of Disconnection, close_notify) may
/// take. Project choice.
const CLOSE_GRACE: Duration = Duration::from_secs(1);

/// Plaintext handed to rustls' writer per call (rustls' outgoing buffer
/// limit defaults to 64 KB; the front flushes after each piece). Project
/// choice.
const TLS_PLAINTEXT_PIECE: usize = 16 * 1024;

/// The front's timeouts.
/// Spec: docs/50 §3.6, §4.2; crates/config `LdapFrontLimits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// InitRecvTimeout.
    pub init_recv: Duration,
    /// MaxConnIdleTime.
    pub max_idle: Duration,
    /// The TLS handshake bound.
    pub tls_handshake: Duration,
    /// dird's answer to one request.
    pub dird_deadline: Duration,
    /// One write to the client.
    pub client_write: Duration,
}

/// What every connection task shares.
/// Spec: docs/50 §4.2.
#[derive(Debug)]
pub(crate) struct ConnectionContext {
    pub(crate) dird: Endpoint,
    pub(crate) timeouts: Timeouts,
    pub(crate) tls: Arc<ServerConfig>,
    pub(crate) unauthenticated: Arc<Semaphore>,
}

/// Why the transport stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// A deadline passed.
    TimedOut,
    /// The peer closed (TCP end of stream, or a TLS close_notify).
    PeerClosed,
    /// A TLS protocol failure (an alert may be queued).
    Tls,
    /// The cleartext buffer would exceed its bound.
    Overflow,
    /// Another I/O failure.
    Io,
}

/// What draining rustls' plaintext found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drained {
    /// The session goes on.
    Open,
    /// The peer closed the TLS session.
    Closed,
}

/// The client's transport: the TCP stream, the TLS layer once there is one,
/// and the cleartext LDAP buffer.
struct ClientLink {
    tcp: TcpStream,
    tls: Option<Box<ServerConnection>>,
    buffer: WireBuffer,
    chunk: Zeroizing<Vec<u8>>,
    outgoing: Vec<u8>,
    write_timeout: Duration,
}

/// Move rustls' decrypted plaintext into the LDAP buffer.
/// Spec: docs.rs rustls 0.23.46 `Reader` (`fill_buf`: no bytes ⇒
/// `WouldBlock`; clean close ⇒ end of data; unclean ⇒ `UnexpectedEof`).
fn drain(tls: &mut ServerConnection, buffer: &mut WireBuffer) -> Result<Drained, Stop> {
    loop {
        let mut reader = tls.reader();
        let taken = match reader.fill_buf() {
            Ok([]) => return Ok(Drained::Closed),
            Ok(data) => {
                buffer.extend(data).map_err(|_| Stop::Overflow)?;
                data.len()
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(Drained::Open),
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(Drained::Closed),
            Err(_) => return Err(Stop::Tls),
        };
        reader.consume(taken);
    }
}

/// Feed ciphertext octets read from the socket to rustls, process them, and
/// drain the plaintext (docs/50 §4.3 step 3: "every octet read from the
/// socket goes to `read_tls` only").
/// Spec: docs.rs rustls 0.23.46 `ConnectionCommon::{read_tls,
/// process_new_packets}` ("This function also returns Ok(0) once a
/// close_notify alert has been successfully received"), `IoState::
/// peer_has_closed`.
fn feed(
    tls: &mut ServerConnection,
    mut input: &[u8],
    buffer: &mut WireBuffer,
) -> Result<Drained, Stop> {
    while !input.is_empty() {
        let read = tls.read_tls(&mut input).map_err(|_| Stop::Tls)?;
        let state = tls.process_new_packets().map_err(|_| Stop::Tls)?;
        if drain(tls, buffer)? == Drained::Closed || state.peer_has_closed() || read == 0 {
            return Ok(Drained::Closed);
        }
    }
    Ok(Drained::Open)
}

impl ClientLink {
    fn new(tcp: TcpStream, write_timeout: Duration) -> ClientLink {
        ClientLink {
            tcp,
            tls: None,
            buffer: WireBuffer::new(),
            chunk: Zeroizing::new(vec![0u8; READ_CHUNK]),
            outgoing: Vec::new(),
            write_timeout,
        }
    }

    /// Whether a TLS layer protects the session.
    fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Read once from the socket (by `deadline`) and append the plaintext
    /// to the LDAP buffer.
    /// Spec: docs/50 §4.2, §4.3.
    async fn read_some(&mut self, deadline: Instant) -> Result<(), Stop> {
        let read = {
            let ClientLink { tcp, chunk, .. } = self;
            match timeout_at(deadline, tcp.read(chunk.as_mut_slice())).await {
                Err(_) => return Err(Stop::TimedOut),
                Ok(Err(_)) => return Err(Stop::Io),
                Ok(Ok(0)) => return Err(Stop::PeerClosed),
                Ok(Ok(read)) => read,
            }
        };
        let drained = {
            let ClientLink {
                tls, buffer, chunk, ..
            } = self;
            match (chunk.get(..read), tls.as_deref_mut()) {
                (None, _) => Err(Stop::Io),
                (Some(input), None) => buffer
                    .extend(input)
                    .map(|()| Drained::Open)
                    .map_err(|_| Stop::Overflow),
                (Some(input), Some(tls)) => feed(tls, input, buffer),
            }
        };
        match drained {
            Ok(drained) => {
                // Whatever rustls queued (a key-update answer) goes out.
                self.flush_tls(Instant::now() + self.write_timeout).await?;
                match drained {
                    Drained::Open => Ok(()),
                    Drained::Closed => Err(Stop::PeerClosed),
                }
            }
            Err(stop) => {
                // Send the alert rustls queued (if any), then give up.
                let _ = self.flush_tls(Instant::now() + CLOSE_GRACE).await;
                Err(stop)
            }
        }
    }

    /// Write out everything rustls queued, by `deadline`.
    /// Spec: docs.rs rustls 0.23.46 `ConnectionCommon::write_tls`,
    /// `CommonState::wants_write`.
    async fn flush_tls(&mut self, deadline: Instant) -> Result<(), Stop> {
        let ClientLink {
            tcp, tls, outgoing, ..
        } = self;
        let Some(tls) = tls.as_deref_mut() else {
            return Ok(());
        };
        while tls.wants_write() {
            outgoing.clear();
            tls.write_tls(outgoing).map_err(|_| Stop::Io)?;
            match timeout_at(deadline, tcp.write_all(outgoing)).await {
                Err(_) => return Err(Stop::TimedOut),
                Ok(Err(_)) => return Err(Stop::Io),
                Ok(Ok(())) => {}
            }
        }
        Ok(())
    }

    /// Write one LDAP message on the current layer.
    /// Spec: RFC 4511 §5.2; docs.rs rustls 0.23.46 `Writer`.
    async fn write_ldap(&mut self, octets: &[u8]) -> Result<(), Stop> {
        if self.tls.is_none() {
            return match timeout(self.write_timeout, self.tcp.write_all(octets)).await {
                Err(_) => Err(Stop::TimedOut),
                Ok(Err(_)) => Err(Stop::Io),
                Ok(Ok(())) => Ok(()),
            };
        }
        for piece in octets.chunks(TLS_PLAINTEXT_PIECE) {
            if let Some(tls) = self.tls.as_deref_mut() {
                tls.writer().write_all(piece).map_err(|_| Stop::Io)?;
            }
            self.flush_tls(Instant::now() + self.write_timeout).await?;
        }
        Ok(())
    }

    /// The TLS handshake as the server, by `deadline`; the plaintext that
    /// follows the client's last handshake flight lands in the (new) LDAP
    /// buffer.
    /// Spec: docs/50 §4.3 steps 3, 6; docs.rs rustls 0.23.46
    /// `ServerConnection::new`, `CommonState::is_handshaking`.
    async fn handshake(
        &mut self,
        config: &Arc<ServerConfig>,
        deadline: Instant,
    ) -> Result<(), Stop> {
        let connection = ServerConnection::new(Arc::clone(config)).map_err(|_| Stop::Tls)?;
        self.tls = Some(Box::new(connection));
        loop {
            self.flush_tls(deadline).await?;
            let handshaking = self.tls.as_deref().is_some_and(|tls| tls.is_handshaking());
            if !handshaking {
                return Ok(());
            }
            let read = {
                let ClientLink { tcp, chunk, .. } = self;
                match timeout_at(deadline, tcp.read(chunk.as_mut_slice())).await {
                    Err(_) => return Err(Stop::TimedOut),
                    Ok(Err(_)) => return Err(Stop::Io),
                    Ok(Ok(0)) => return Err(Stop::PeerClosed),
                    Ok(Ok(read)) => read,
                }
            };
            let fed = {
                let ClientLink {
                    tls, buffer, chunk, ..
                } = self;
                let input = chunk.get(..read).ok_or(Stop::Io)?;
                match tls.as_deref_mut() {
                    Some(tls) => feed(tls, input, buffer),
                    None => Err(Stop::Tls),
                }
            };
            match fed {
                Ok(Drained::Open) => {}
                Ok(Drained::Closed) => return Err(Stop::PeerClosed),
                Err(stop) => {
                    // Send the alert rustls queued, then give up.
                    let _ = self.flush_tls(Instant::now() + CLOSE_GRACE).await;
                    return Err(stop);
                }
            }
        }
    }

    /// End the transport: on TLS a close_notify first (RFC 4511 §5.3:
    /// "tearing down any TLS layer, and closing the transport connection"),
    /// then the TCP stream is shut down; both bounded.
    /// Spec: RFC 4511 §5.3; docs.rs rustls 0.23.46 `send_close_notify`.
    async fn finish(mut self) {
        if let Some(tls) = self.tls.as_deref_mut() {
            tls.send_close_notify();
        }
        let _ = self.flush_tls(Instant::now() + CLOSE_GRACE).await;
        let _ = timeout(CLOSE_GRACE, self.tcp.shutdown()).await;
    }

    /// End the transport without any further octet (the StartTLS
    /// transition, or a TLS layer that already failed).
    /// Spec: docs/50 §4.3 (no cleartext after StartTLS); RFC 4511 §5.3
    /// ("abruptly terminate the session by ceasing communication").
    async fn abort(mut self) {
        let _ = timeout(CLOSE_GRACE, self.tcp.shutdown()).await;
    }

    /// Write a Notice of Disconnection on the current layer (best effort,
    /// bounded), then finish.
    /// Spec: RFC 4511 §4.4.1, §5.3.
    async fn notice_and_finish(mut self, notice: Option<Vec<u8>>) {
        if let Some(notice) = notice {
            self.write_timeout = CLOSE_GRACE;
            let _ = self.write_ldap(&notice).await;
        }
        self.finish().await;
    }
}

/// The Notice of Disconnection with resultCode protocolError.
/// Spec: RFC 4511 §4.1.1 ("the server SHOULD return the Notice of
/// Disconnection described in Section 4.4.1, with the resultCode set to
/// protocolError"), §4.4.1.
fn protocol_error_notice() -> Option<Vec<u8>> {
    encode_message(&LdapMessage::notice_of_disconnection(
        ResultCode::ProtocolError,
    ))
    .ok()
}

/// The Notice of Disconnection with resultCode busy.
/// Spec: RFC 4511 §4.4.1, App. A (busy 51).
fn busy_notice() -> Option<Vec<u8>> {
    encode_message(&LdapMessage::notice_of_disconnection(ResultCode::Busy)).ok()
}

/// Count why a transport stopped.
fn count_stop(stop: Stop) {
    match stop {
        Stop::TimedOut => TIMED_OUT.hit(),
        Stop::Overflow => NOT_LDAP.hit(),
        Stop::PeerClosed | Stop::Tls | Stop::Io => {}
    }
}

/// The admission slots a connection holds while it lives (crate::daemon).
/// The global slot and the per-source slot are held only to be released
/// when the connection ends (drop).
pub(crate) struct Slots {
    pub(crate) _total: OwnedSemaphorePermit,
    pub(crate) _source: crate::daemon::SourceSlot,
    pub(crate) unauthenticated: Option<OwnedSemaphorePermit>,
}

/// One established session.
struct Session {
    link: ClientLink,
    dird: DirdSession,
    framing: AuthState,
    listener: Listener,
    context: Arc<ConnectionContext>,
    slots: Slots,
}

/// How a session ended (what the front still owes the client).
enum Ending {
    /// Close normally (close_notify on TLS).
    Finish,
    /// Close with this Notice of Disconnection first.
    Notice(Option<Vec<u8>>),
    /// Close without another octet.
    Abort,
}

impl Session {
    /// Keep the unauthenticated pool in step with dird's framing state
    /// (module documentation). `false` ⇒ no slot is left: close (busy).
    /// Spec: docs/50 §4.2; docs/07 §1.
    fn track_pool(&mut self) -> bool {
        match self.framing {
            AuthState::Authenticated => {
                self.slots.unauthenticated = None;
                true
            }
            AuthState::Unauthenticated => {
                if self.slots.unauthenticated.is_none() {
                    match Arc::clone(&self.context.unauthenticated).try_acquire_owned() {
                        Ok(permit) => self.slots.unauthenticated = Some(permit),
                        Err(_) => return false,
                    }
                }
                true
            }
        }
    }

    /// Serve requests until the session ends.
    /// Spec: module documentation.
    async fn serve(&mut self, first_deadline: Instant) -> Ending {
        let mut deadline = first_deadline;
        loop {
            // 1. Frame the next message (reading only while incomplete).
            let framed = loop {
                match take_message(&mut self.link.buffer, self.framing) {
                    Ok(Some(framed)) => break framed,
                    Ok(None) => {
                        if let Err(stop) = self.link.read_some(deadline).await {
                            count_stop(stop);
                            return match stop {
                                Stop::Tls => Ending::Abort,
                                _ => Ending::Finish,
                            };
                        }
                    }
                    Err(FrameFailure::TooLarge) => {
                        NOT_LDAP.hit();
                        return Ending::Finish;
                    }
                    Err(_) => {
                        NOT_LDAP.hit();
                        return Ending::Notice(protocol_error_notice());
                    }
                }
            };
            // 2. dird answers (nothing is read meanwhile).
            let facts = TransportFacts {
                tls_established: self.link.is_tls(),
                input_pending: framed.input_pending,
            };
            let exchange = match self.dird.message(&framed.canonical, facts).await {
                Ok(exchange) => exchange,
                Err(failure) => return self.dird_failed(&failure),
            };
            drop(framed);
            // 3. The responses, in order, on the current layer.
            for response in &exchange.responses {
                if let Err(stop) = self.link.write_ldap(response).await {
                    count_stop(stop);
                    return Ending::Abort;
                }
            }
            self.framing = exchange.framing;
            if !self.track_pool() {
                crate::log::CONNECTION_LIMITED.hit();
                return Ending::Notice(busy_notice());
            }
            // 4. The action.
            match exchange.action {
                ConnectionAction::Continue => {}
                ConnectionAction::Close => return Ending::Finish,
                ConnectionAction::StartTls => {
                    if let Some(ending) = self.start_tls().await {
                        return ending;
                    }
                }
            }
            deadline = Instant::now() + self.context.timeouts.max_idle;
        }
    }

    /// The StartTLS hand-over, steps 3-4 (module documentation). `None` ⇒
    /// TLS is up and dird took the report.
    /// Spec: docs/50 §4.3; docs/49 §4.4 (R49-15); RFC 4511 §4.14.1-§4.14.2;
    /// RFC 4513 §3.1.1, §3.1.4.
    async fn start_tls(&mut self) -> Option<Ending> {
        if self.listener != Listener::Ldap || self.link.is_tls() {
            // dird asked for something the channel never allows: fail closed.
            return Some(Ending::Abort);
        }
        if !self.link.buffer.is_empty() {
            CLEARTEXT_AFTER_START_TLS.hit();
            return Some(Ending::Abort);
        }
        self.link.buffer.wipe();
        let deadline = Instant::now() + self.context.timeouts.tls_handshake;
        let config = Arc::clone(&self.context.tls);
        if self.link.handshake(&config, deadline).await.is_err() {
            HANDSHAKE_FAILED.hit();
            return Some(Ending::Abort);
        }
        let refused = self
            .link
            .tls
            .as_deref()
            .is_none_or(|tls| check_negotiated(tls).is_err());
        if refused {
            TLS_PARAMETERS_REFUSED.hit();
            return Some(Ending::Finish);
        }
        match self.dird.tls_established().await {
            Ok(framing) => {
                self.framing = framing;
                if self.track_pool() {
                    None
                } else {
                    crate::log::CONNECTION_LIMITED.hit();
                    Some(Ending::Notice(busy_notice()))
                }
            }
            Err(failure) => Some(self.dird_failed(&failure)),
        }
    }

    /// dird did not serve: count, and close with the notice (on the current
    /// layer — the hand-over never reaches here between the StartTLS
    /// response and the end of the handshake).
    /// Spec: docs/50 §3.7; RFC 4511 §4.4.1.
    fn dird_failed(&mut self, failure: &ChannelFailure) -> Ending {
        DIRD_NOT_SERVING.hit();
        Ending::Notice(notice_of_disconnection(failure))
    }
}

/// Serve one accepted connection to its end (module documentation).
/// Spec: docs/50 R50-10, §4.2, §4.3.
pub(crate) async fn run(
    tcp: TcpStream,
    peer: SocketAddr,
    listener: Listener,
    context: Arc<ConnectionContext>,
    slots: Slots,
    accepted: Instant,
) {
    let timeouts = context.timeouts;
    let mut link = ClientLink::new(tcp, timeouts.client_write);
    let first_deadline = accepted + timeouts.init_recv;
    if listener == Listener::Ldaps {
        let deadline = (accepted + timeouts.tls_handshake).min(first_deadline);
        if link.handshake(&context.tls, deadline).await.is_err() {
            HANDSHAKE_FAILED.hit();
            link.abort().await;
            return;
        }
        let refused = link
            .tls
            .as_deref()
            .is_none_or(|tls| check_negotiated(tls).is_err());
        if refused {
            TLS_PARAMETERS_REFUSED.hit();
            link.finish().await;
            return;
        }
    }
    let opened =
        DirdSession::open(&context.dird, listener, peer.ip(), timeouts.dird_deadline).await;
    let (dird, framing) = match opened {
        Ok(opened) => opened,
        Err(failure) => {
            DIRD_NOT_SERVING.hit();
            link.notice_and_finish(notice_of_disconnection(&failure))
                .await;
            return;
        }
    };
    let mut session = Session {
        link,
        dird,
        framing,
        listener,
        context,
        slots,
    };
    if !session.track_pool() {
        crate::log::CONNECTION_LIMITED.hit();
        let Session { link, dird, .. } = session;
        dird.close().await;
        link.notice_and_finish(busy_notice()).await;
        return;
    }
    let ending = session.serve(first_deadline).await;
    let Session {
        link, dird, slots, ..
    } = session;
    dird.close().await;
    match ending {
        Ending::Finish => link.finish().await,
        Ending::Notice(notice) => link.notice_and_finish(notice).await,
        Ending::Abort => link.abort().await,
    }
    drop(slots);
}
