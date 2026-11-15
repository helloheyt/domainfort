//! The front's client over a real Unix socket, against a test dird that
//! answers through this crate's dispatcher (or misbehaves on purpose).
//!
//! Sources: docs/50 R50-3 (the client checks the server's uid from the
//! kernel's peer credentials before it sends anything; uid 0 is never
//! accepted), §3.3 (replies decoded strictly; the shared `Refused`), §3.6
//! (one deadline per call), §3.7 (no resend; fail closed); docs/52 §3.12
//! (C12: no client without the expected peer); docs/53 §5.6 step 1 (`Ping` →
//! the zone), §5.7 (every failure is HARDERROR at the front); A-82 (a
//! request is never sent twice). The test dird runs in this process, so its
//! uid is the test's own (read from the scratch directory's owner); as root
//! the tests skip (uid 0 is never mapped). Socket paths are in the system's
//! temporary directory (the socket-path length limit, crates/test-scratch).

#![cfg(unix)]

mod common;

use common::*;
use core::time::Duration;
use ipc::{FrameReader, Refused};
use ipc_kpasswd::{
    encode_refusal, encode_reply, ClientConfigError, ExpectedDird, FrontZone, HostUnserved,
    KpasswdAnswer, KpasswdClient, KpasswdConnection, KpasswdHost, KpasswdReply, TransportError,
    UnsealedCode, Unserved, REQUEST_LIMIT,
};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const DEADLINE: Duration = Duration::from_secs(5);

/// How the test dird behaves on each connection.
#[derive(Clone)]
enum Behaviour {
    /// Answer through the dispatcher with this host answer.
    Dispatch(Result<KpasswdAnswer, HostUnserved>),
    /// Answer `Ping` with this reply instead of `Pong`.
    PingReply(KpasswdReply),
    /// Answer `Ping` correctly, then never answer the next request.
    SilentAfterPing,
    /// Answer every frame with octets that are not a reply of this channel.
    Garbage,
}

/// A request body the test dird received, and how many frames in all.
#[derive(Default)]
struct Seen {
    frames: AtomicU32,
    bodies: Mutex<Vec<Vec<u8>>>,
}

struct Host(Result<KpasswdAnswer, HostUnserved>);

impl KpasswdHost for Host {
    fn change_password(
        &mut self,
        _zone: FrontZone,
        _request: &ipc_kpasswd::ChangePasswordRequest,
    ) -> Result<KpasswdAnswer, HostUnserved> {
        self.0.clone()
    }
}

/// A unique socket path in the temporary directory.
fn socket_path(tag: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("kpw-{tag}-{}-{n}.sock", std::process::id()))
}

/// The test's own uid (the owner of a file it created), or `None` as root
/// (uid 0 is never mapped — docs/50 R50-3).
fn own_uid() -> Option<u32> {
    let path = socket_path("uid").with_extension("probe");
    std::fs::write(&path, b"").ok()?;
    let uid = std::fs::metadata(&path).ok()?.uid();
    let _ = std::fs::remove_file(&path);
    if uid == 0 {
        eprintln!("skipped: running as root (docs/50 R50-3: uid 0 is never mapped)");
        None
    } else {
        Some(uid)
    }
}

/// Read one request frame body, or `None` at the end of the stream.
async fn read_frame(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    let mut chunk = vec![0u8; 4096];
    loop {
        if let Some(body) = reader.body() {
            return Some(body.to_vec());
        }
        let wanted = reader.wanted().min(chunk.len());
        let read = stream.read(&mut chunk[..wanted]).await.ok()?;
        if read == 0 {
            return None;
        }
        reader.push(&chunk[..read]).ok()?;
    }
}

/// Serve one connection with `behaviour`.
async fn serve_one(mut stream: UnixStream, behaviour: Behaviour, seen: Arc<Seen>) {
    let mut connection = KpasswdConnection::new(1, FrontZone::Internal);
    let mut answered_ping = false;
    while let Some(body) = read_frame(&mut stream).await {
        seen.frames.fetch_add(1, Ordering::SeqCst);
        seen.bodies.lock().unwrap().push(body.clone());
        let frame = match &behaviour {
            Behaviour::Dispatch(answer) => {
                let dispatch = connection.handle(&body, &mut Host(answer.clone()));
                let closes = dispatch.closes();
                if let Some(frame) = dispatch.frame() {
                    let _ = stream.write_all(frame.as_bytes()).await;
                }
                if closes {
                    return;
                }
                continue;
            }
            Behaviour::PingReply(reply) => encode_reply(reply).unwrap().as_bytes().to_vec(),
            Behaviour::SilentAfterPing if !answered_ping => {
                answered_ping = true;
                encode_reply(&KpasswdReply::Pong {
                    zone: FrontZone::Internal,
                })
                .unwrap()
                .as_bytes()
                .to_vec()
            }
            Behaviour::SilentAfterPing => {
                tokio::time::sleep(Duration::from_secs(30)).await;
                return;
            }
            Behaviour::Garbage => vec![0, 0, 0, 5, 0x4B, 0x50, 0x01, 0x99, 0x00],
        };
        let _ = stream.write_all(&frame).await;
    }
}

/// Run `test` against a test dird with `behaviour` on a fresh socket, in a
/// current-thread runtime.
fn with_dird<F, Fut>(tag: &str, behaviour: Behaviour, test: F)
where
    F: FnOnce(PathBuf, u32, Arc<Seen>) -> Fut,
    Fut: core::future::Future<Output = ()>,
{
    let Some(uid) = own_uid() else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let path = socket_path(tag);
    let _ = std::fs::remove_file(&path);
    runtime.block_on(async {
        let listener = UnixListener::bind(&path).unwrap();
        let seen = Arc::new(Seen::default());
        let server_seen = Arc::clone(&seen);
        let server = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_one(
                    stream,
                    behaviour.clone(),
                    Arc::clone(&server_seen),
                ));
            }
        });
        test(path.clone(), uid, seen).await;
        server.abort();
    });
    let _ = std::fs::remove_file(&path);
}

fn client(path: PathBuf, uid: u32, deadline: Duration) -> KpasswdClient {
    KpasswdClient::new(
        path,
        ExpectedDird::new(uid, FrontZone::Internal).unwrap(),
        deadline,
    )
}

/// docs/52 §3.12 (C12); docs/50 §3.2 ("uid 0 is never mapped"): there is
/// no expectation of a root dird.
#[test]
fn a_root_dird_cannot_be_expected() {
    assert_eq!(
        ExpectedDird::new(0, FrontZone::Internal),
        Err(ClientConfigError::RootServerUid)
    );
    let expected = ExpectedDird::new(4642, FrontZone::Internal).unwrap();
    assert_eq!(expected.uid(), 4642);
    assert_eq!(expected.zone(), FrontZone::Internal);
}

/// docs/50 §7.5, R50-16; docs/53 §5.6 step 1: `ping` verifies dird's uid
/// and its `Pong` naming the internal zone.
#[test]
fn ping_verifies_dird() {
    with_dird(
        "ping",
        Behaviour::Dispatch(Err(HostUnserved::Busy)),
        |path, uid, seen| async move {
            assert_eq!(client(path, uid, DEADLINE).ping().await, Ok(()));
            assert_eq!(seen.frames.load(Ordering::SeqCst), 1);
        },
    );
}

/// docs/50 R50-3 ("a process that captured the socket path receives no
/// request"): a peer whose uid is not the expected dird's receives nothing
/// — not even the `Ping`.
#[test]
fn another_uid_receives_nothing() {
    with_dird(
        "uid",
        Behaviour::Dispatch(Ok(KpasswdAnswer::Sealed(sealed()))),
        |path, uid, seen| async move {
            let wrong = client(path, uid + 1, DEADLINE);
            assert_eq!(wrong.ping().await, Err(Unserved::PeerMismatch));
            assert_eq!(
                wrong.change_password(&request()).await,
                Err(Unserved::PeerMismatch)
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(seen.frames.load(Ordering::SeqCst), 0);
        },
    );
}

/// docs/53 §4.3, §5.5: the request reaches dird exactly as built (the body
/// dird read decodes to it) and keyd's sealed reply comes back unchanged;
/// the verification `Ping` precedes it on the same connection.
#[test]
fn a_change_is_sent_once_after_the_ping_and_the_sealed_reply_returns() {
    with_dird(
        "sealed",
        Behaviour::Dispatch(Ok(KpasswdAnswer::Sealed(sealed()))),
        |path, uid, seen| async move {
            let answer = client(path, uid, DEADLINE)
                .change_password(&request())
                .await;
            assert_eq!(answer, Ok(KpasswdAnswer::Sealed(sealed())));
            let bodies = seen.bodies.lock().unwrap().clone();
            assert_eq!(bodies.len(), 2);
            assert_eq!(
                ipc_kpasswd::decode_request(&bodies[0]),
                Ok(ipc_kpasswd::KpasswdRequest::Ping)
            );
            assert_eq!(
                ipc_kpasswd::decode_request(&bodies[1]),
                Ok(ipc_kpasswd::KpasswdRequest::ChangePassword(request()))
            );
        },
    );
}

/// docs/53 §5.7: an unsealed code comes back as such.
#[test]
fn an_unsealed_code_returns() {
    with_dird(
        "unsealed",
        Behaviour::Dispatch(Ok(KpasswdAnswer::Unsealed(UnsealedCode::AuthError))),
        |path, uid, _| async move {
            assert_eq!(
                client(path, uid, DEADLINE)
                    .change_password(&request())
                    .await,
                Ok(KpasswdAnswer::Unsealed(UnsealedCode::AuthError))
            );
        },
    );
}

/// docs/53 §5.6 step 1 (`Busy`); docs/50 §3.7: dird's shared refusal is a
/// refusal at the client (the front answers HARDERROR).
#[test]
fn a_refusal_is_reported() {
    with_dird(
        "busy",
        Behaviour::Dispatch(Err(HostUnserved::Busy)),
        |path, uid, _| async move {
            assert_eq!(
                client(path, uid, DEADLINE)
                    .change_password(&request())
                    .await,
                Err(Unserved::Refused(Refused::Busy))
            );
        },
    );
}

/// docs/53 §5.6 step 1 (the `Pong` names the zone); docs/50 §3.3 (a reply
/// that does not answer the request is refused): a dird that answers the
/// verification `Ping` with anything but a `Pong` — a sealed reply, the
/// shared refusal — never receives the change request.
#[test]
fn a_wrong_answer_to_the_ping_stops_the_request() {
    with_dird(
        "pingreply",
        Behaviour::PingReply(KpasswdReply::Unsealed(UnsealedCode::HardError)),
        |path, uid, seen| async move {
            assert_eq!(
                client(path, uid, DEADLINE)
                    .change_password(&request())
                    .await,
                Err(Unserved::UnexpectedReply)
            );
            assert_eq!(seen.frames.load(Ordering::SeqCst), 1);
        },
    );
    // The shared refusal in place of the `Pong`.
    let refusal = encode_refusal(Refused::Unavailable).unwrap();
    assert_eq!(refusal.body()[3], ipc::REFUSED_KIND);
}

/// docs/50 §3.3 (replies decoded with the same strictness as requests): an
/// unknown reply kind is a malformed reply; the request is not sent.
#[test]
fn a_malformed_reply_is_refused() {
    with_dird(
        "garbage",
        Behaviour::Garbage,
        |path, uid, seen| async move {
            assert!(matches!(
                client(path, uid, DEADLINE)
                    .change_password(&request())
                    .await,
                Err(Unserved::MalformedReply(_))
            ));
            assert_eq!(seen.frames.load(Ordering::SeqCst), 1);
        },
    );
}

/// docs/50 §3.6 (one deadline per call), §3.7 / A-82 (no resend; an answer
/// that never comes after the request was written is an unknown outcome):
/// a dird that verifies and then goes silent ends the call at the deadline
/// as `OutcomeUnknown`, having received the request exactly once.
#[test]
fn a_silent_dird_after_the_request_is_an_unknown_outcome() {
    with_dird(
        "silent",
        Behaviour::SilentAfterPing,
        |path, uid, seen| async move {
            let started = std::time::Instant::now();
            assert_eq!(
                client(path, uid, Duration::from_millis(300))
                    .change_password(&request())
                    .await,
                Err(Unserved::OutcomeUnknown(TransportError::DeadlineExceeded))
            );
            assert!(started.elapsed() < Duration::from_secs(5));
            assert_eq!(seen.frames.load(Ordering::SeqCst), 2);
        },
    );
}

/// docs/50 §3.7 (dird down ⇒ not served, fail closed): no socket ⇒ a
/// connect failure, nothing sent.
#[test]
fn no_dird_is_a_connect_failure() {
    let Some(uid) = own_uid() else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let path = socket_path("absent");
    let _ = std::fs::remove_file(&path);
    runtime.block_on(async {
        assert_eq!(
            client(path, uid, DEADLINE)
                .change_password(&request())
                .await,
            Err(Unserved::Transport(TransportError::Connect))
        );
    });
}
