//! The blocking Unix stream connection (docs/50 §9 tier 2: real sockets in
//! a unique temporary directory, no root, nothing outside the test
//! process): framing and deadline over a real socket, a server thread that
//! runs `dispatch`, and the server-uid check — verified through the
//! kernel's peer credentials on Linux, failing closed elsewhere.
//!
//! Sources: docs/50 §3.1 (Unix stream sockets), §3.2 (R50-3: rustix
//! `socket_peercred` in the synchronous client; the client verifies the
//! server's uid), §3.3 (bound before allocation), §3.6 (std `UnixStream` +
//! timeout; deadline ⇒ `Unavailable`), §9 tier 2. Every value is
//! constructed by hand for these tests.
#![cfg(unix)]

#[path = "../../ipc-keyd/tests/samples/mod.rs"]
mod samples;

use ipc::{encode_frame, Direction, FrameReader};
use ipc_keyd::{
    Call, Connection, KeydClient, KeydReply, TransportError, UnixConnection, UnixConnector,
    KEYD_CHANNEL, REPLY_LIMIT, REQUEST_LIMIT,
};
use ipc_keyd_server::{dispatch, Dispatch};
use keyd::{AuditRecord, CallerId, InMemoryKeyStore, Keyd, KeydConfig, Role};
use krb_proto::KerberosTime;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Default)]
struct Records(Vec<AuditRecord>);

impl keyd::AuditSink for Records {
    fn record(&mut self, record: &AuditRecord) {
        self.0.push(record.clone());
    }
}

const KDC: CallerId = CallerId {
    uid: 100,
    role: Role::Kdc,
};

fn clock() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 12, 0, 0).unwrap()
}

/// A unique, private (0700) temporary directory for one test's socket.
fn private_dir(test: &str) -> PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let dir = std::env::temp_dir().join(format!("ipckeyd-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    dir
}

/// A keyd server on one connection: frames in, `dispatch` with `caller` and
/// the server's own clock, frames out, until the peer closes. Returns how
/// many request octets arrived in total.
fn serve(mut stream: UnixStream, caller: CallerId) -> usize {
    let mut keyd = Keyd::new(
        KeydConfig::new(samples::realm()),
        InMemoryKeyStore::new(4),
        Records::default(),
        &KerberosTime::new(2026, 11, 13, 9, 0, 0).unwrap(),
    )
    .unwrap();
    let mut received = 0usize;
    loop {
        let mut reader = FrameReader::new(REQUEST_LIMIT);
        while reader.body().is_none() {
            let mut buffer = vec![0u8; reader.wanted()];
            let read = match stream.read(&mut buffer) {
                Ok(0) | Err(_) => return received,
                Ok(read) => read,
            };
            received += read;
            if reader.push(&buffer[..read]).is_err() {
                return received;
            }
        }
        let body = reader.body().unwrap().to_vec();
        match dispatch(&mut keyd, caller, clock(), &body) {
            Dispatch::Reply(frame) => stream.write_all(frame.as_bytes()).unwrap(),
            Dispatch::ReplyAndClose(frame) => {
                stream.write_all(frame.as_bytes()).unwrap();
                return received;
            }
            Dispatch::Close => return received,
        }
    }
}

fn frame_of(call: &Call) -> Vec<u8> {
    encode_frame(KEYD_CHANNEL, Direction::Request, &call.to_wire().unwrap())
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn reply_of(body: &[u8]) -> KeydReply {
    match ipc::decode_reply::<KeydReply>(KEYD_CHANNEL, body).unwrap() {
        ipc::Reply::Message(reply) => reply,
        ipc::Reply::Refused(refused) => panic!("refused {refused:?}"),
    }
}

/// docs/50 §3.1, §3.3, §3.6, R50-7: over a real socket, each exchange sends
/// one frame and reads exactly one reply frame, which `dispatch` produced
/// with the connection's caller; the connection carries request after
/// request.
#[test]
fn exchanges_over_a_real_socket_reach_dispatch() {
    let (client_end, server_end) = UnixStream::pair().unwrap();
    let server = thread::spawn(move || serve(server_end, KDC));
    let mut connection = UnixConnection::from_stream(client_end);
    let deadline = Duration::from_secs(2);
    let reply = connection
        .exchange(&frame_of(&Call::Ping), REPLY_LIMIT, deadline)
        .unwrap();
    assert_eq!(reply_of(&reply), KeydReply::Ping);
    let reply = connection
        .exchange(&frame_of(&Call::DescribeConfig), REPLY_LIMIT, deadline)
        .unwrap();
    assert!(matches!(reply_of(&reply), KeydReply::DescribeConfig(_)));
    // A Kdc caller may not rotate keys (docs/10 §2): keyd's own Denied.
    let rotate = Call::RotateKey {
        handle: samples::KRBTGT,
    };
    let reply = connection
        .exchange(&frame_of(&rotate), REPLY_LIMIT, deadline)
        .unwrap();
    assert_eq!(reply_of(&reply), KeydReply::Failure(keyd::Error::Denied));
    drop(connection);
    assert!(server.join().unwrap() > 0);
}

/// docs/50 §3.6 ("deadline in the client — keyd: 2 s; exceeded ⇒
/// `Unavailable`"): a peer that never answers ends the exchange at the
/// deadline.
#[test]
fn the_deadline_is_enforced_on_a_real_socket() {
    let (client_end, silent_end) = UnixStream::pair().unwrap();
    let mut connection = UnixConnection::from_stream(client_end);
    let start = Instant::now();
    let result = connection.exchange(
        &frame_of(&Call::Ping),
        REPLY_LIMIT,
        Duration::from_millis(150),
    );
    assert_eq!(result, Err(TransportError::DeadlineExceeded));
    assert!(start.elapsed() < Duration::from_secs(2));
    drop(silent_end);
}

/// docs/50 §3.3 ("`length` is checked against the MAX of (channel,
/// direction) before any body byte is allocated or read"): a reply that
/// declares a body over the reply bound is refused at its prefix; a peer
/// that closes mid-reply is `Closed`.
#[test]
fn bad_replies_on_a_real_socket_are_refused() {
    let (client_end, mut peer) = UnixStream::pair().unwrap();
    let writer = thread::spawn(move || {
        let mut request = vec![0u8; frame_of(&Call::Ping).len()];
        peer.read_exact(&mut request).unwrap();
        peer.write_all(&0x7FFF_FFF0u32.to_be_bytes()).unwrap();
        peer
    });
    let mut connection = UnixConnection::from_stream(client_end);
    assert_eq!(
        connection.exchange(&frame_of(&Call::Ping), REPLY_LIMIT, Duration::from_secs(2)),
        Err(TransportError::Framing)
    );
    drop(writer.join().unwrap());

    let (client_end, mut peer) = UnixStream::pair().unwrap();
    let closer = thread::spawn(move || {
        let mut request = vec![0u8; frame_of(&Call::Ping).len()];
        peer.read_exact(&mut request).unwrap();
        // Half a reply, then close.
        peer.write_all(&[0, 0, 0, 5, 0x4B]).unwrap();
    });
    let mut connection = UnixConnection::from_stream(client_end);
    // End of stream, or — on platforms where re-arming the read timeout of
    // a socket whose peer has gone fails — an I/O error. Either way the
    // client reports `Unavailable`.
    let result = connection.exchange(&frame_of(&Call::Ping), REPLY_LIMIT, Duration::from_secs(2));
    assert!(
        matches!(result, Err(TransportError::Closed | TransportError::Io)),
        "{result:?}"
    );
    closer.join().unwrap();
}

/// A fresh socket in a private directory, with a server thread that serves
/// `connections` connections one after the other (Kdc caller) and returns
/// the request octets received over all of them.
fn socket_server(test: &str, connections: usize) -> (PathBuf, PathBuf, thread::JoinHandle<usize>) {
    let dir = private_dir(test);
    let path = dir.join("keyd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server = thread::spawn(move || {
        let mut received = 0;
        for _ in 0..connections {
            match listener.accept() {
                Ok((stream, _)) => received += serve(stream, KDC),
                Err(_) => break,
            }
        }
        received
    });
    (dir, path, server)
}

/// docs/50 R50-3 (peer credentials only from rustix `socket_peercred`,
/// "linux_kernel" only per its docs.rs page); AGENTS.md §6 (fail closed):
/// where the peer cannot be verified, the client sends nothing and reports
/// `Unavailable`.
#[cfg(not(target_os = "linux"))]
#[test]
fn without_peer_credentials_the_client_sends_nothing() {
    let (dir, path, server) = socket_server("nocred", 2);
    let mut client =
        KeydClient::new(UnixConnector::new(path), 900, Duration::from_secs(2)).unwrap();
    assert_eq!(client.ping(), Err(keyd::Error::Unavailable));
    assert_eq!(
        client.call(&Call::Ping),
        Err(ipc_keyd::Unserved::Transport(
            TransportError::PeerCredentials
        ))
    );
    drop(client);
    // The server saw connections but never a single request octet.
    assert_eq!(server.join().unwrap(), 0);
    let _ = std::fs::remove_dir_all(dir);
}

/// docs/50 R50-3, §3.2, §9 tier 2 (Linux): the kernel's peer credentials
/// give the server's uid; the client accepts the socket only when it is the
/// configured keyd uid (here: this test process's own uid, the owner of the
/// private directory), and otherwise sends nothing.
#[cfg(target_os = "linux")]
#[test]
fn peer_credentials_verify_the_server_uid() {
    use ipc_keyd::Connector;
    use std::os::unix::fs::MetadataExt;
    let (dir, path, server) = socket_server("cred", 1);
    let own_uid = std::fs::metadata(&dir).unwrap().uid();
    let mut connector = UnixConnector::new(path.clone());
    let connection = connector.connect().unwrap();
    assert_eq!(connection.peer_uid(), Ok(own_uid));
    drop(connection);
    assert_eq!(server.join().unwrap(), 0);

    let (dir2, path2, server) = socket_server("cred-ok", 1);
    if own_uid == 0 {
        // A root test process cannot play keyd: uid 0 is never accepted as
        // keyd's (docs/50 §3.2; Q-245 item 5). Release the server thread.
        assert!(
            KeydClient::new(UnixConnector::new(path2.clone()), 0, Duration::from_secs(2)).is_err()
        );
        drop(UnixStream::connect(&path2).unwrap());
        assert_eq!(server.join().unwrap(), 0);
    } else {
        let mut client =
            KeydClient::new(UnixConnector::new(path2), own_uid, Duration::from_secs(2)).unwrap();
        assert_eq!(client.ping(), Ok(()));
        assert!(client.describe_config().is_ok());
        drop(client);
        assert!(server.join().unwrap() > 0);
    }

    let (dir3, path3, server) = socket_server("cred-wrong", 1);
    let mut client = KeydClient::new(
        UnixConnector::new(path3),
        own_uid.wrapping_add(1).max(1),
        Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(
        client.call(&Call::Ping),
        Err(ipc_keyd::Unserved::PeerMismatch)
    );
    drop(client);
    assert_eq!(server.join().unwrap(), 0, "nothing was sent");
    for d in [dir, dir2, dir3] {
        let _ = std::fs::remove_dir_all(d);
    }
}
