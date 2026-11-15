//! dnsd's blocking Unix-socket connection over a connected socket pair:
//! one whole frame per `send`, exactly one frame per `receive` (the next
//! frame of a multi-frame reply stays in the socket), the reply bound
//! applied at the length prefix, the idle check without sending, and peer
//! credentials that fail closed where the kernel's are not read.
//!
//! Sources: docs/50 R50-3 (peer uid from the kernel), §3.3 (bound before
//! allocation), §3.6, §3.7; docs/54 §4.6 (chunked replies); docs/questions/
//! Q-312 (idle check: end of stream, a waiting octet). Every frame is
//! encoded by this crate from hand-made values.

#![cfg(unix)]

mod common;

use common::reply_body;
use ipc::FrameLimit;
use ipc_dns::{
    Connection, DnsReply, FrontZone, ImageChunk, Serial, TransportError, UnixConnection,
    MAX_IMAGE_CHUNK, REPLY_LIMIT,
};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(5);

fn framed(body: &[u8]) -> Vec<u8> {
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    frame
}

/// docs/54 §4.6: two reply frames written back to back are received one at
/// a time; nothing of the second is consumed by the first `receive`.
#[test]
fn receive_reads_exactly_one_frame() {
    let (client, mut dird) = UnixStream::pair().expect("pair");
    let mut connection = UnixConnection::from_stream(client);
    let first = reply_body(&DnsReply::ImageChunk(
        ImageChunk::new(&vec![0x11; MAX_IMAGE_CHUNK as usize], true).expect("chunk"),
    ));
    let second = reply_body(&DnsReply::ImageChunk(
        ImageChunk::new(&[0x22; 9], false).expect("chunk"),
    ));
    let writer = std::thread::spawn(move || {
        let mut both = framed(&first);
        both.extend_from_slice(&framed(&second));
        dird.write_all(&both).expect("write");
        dird
    });
    let got_first = connection.receive(REPLY_LIMIT, DEADLINE).expect("first");
    let got_second = connection.receive(REPLY_LIMIT, DEADLINE).expect("second");
    let _dird = writer.join().expect("writer");
    assert_eq!(got_first.len(), MAX_IMAGE_CHUNK as usize + 4 + 4 + 1);
    assert_eq!(got_second.len(), 4 + 4 + 9 + 1);
}

/// docs/50 §3.3: a declared length over the bound is refused at the prefix.
#[test]
fn an_oversized_reply_is_refused_at_the_prefix() {
    let (client, mut dird) = UnixStream::pair().expect("pair");
    let mut connection = UnixConnection::from_stream(client);
    let small = FrameLimit::new(16).expect("limit");
    dird.write_all(&framed(&[0u8; 32])).expect("write");
    assert_eq!(
        connection.receive(small, DEADLINE),
        Err(TransportError::Framing)
    );
}

/// docs/50 §3.6, §3.7: a closed peer is a transport failure (`Closed` where
/// the read sees the end of stream; some kernels already refuse to set the
/// read timeout on a disconnected socket, which is `Io` — either way the
/// call fails and the connection is dropped); a deadline is
/// `DeadlineExceeded`.
#[test]
fn closed_peers_and_deadlines_are_reported() {
    let (client, dird) = UnixStream::pair().expect("pair");
    let mut connection = UnixConnection::from_stream(client);
    drop(dird);
    assert!(matches!(
        connection.receive(REPLY_LIMIT, DEADLINE),
        Err(TransportError::Closed | TransportError::Io)
    ));

    let (client, _dird) = UnixStream::pair().expect("pair");
    let mut connection = UnixConnection::from_stream(client);
    assert_eq!(
        connection.receive(REPLY_LIMIT, Duration::from_millis(50)),
        Err(TransportError::DeadlineExceeded)
    );
    assert_eq!(
        connection.send(&[0, 0, 0, 0], Duration::ZERO),
        Err(TransportError::DeadlineExceeded)
    );
}

/// docs/questions/Q-312: the idle check sends nothing and reports a usable
/// connection, a waiting octet (`Framing`) and a closed peer (`Closed`).
#[test]
fn the_idle_check_reads_the_connection_state() {
    let (client, mut dird) = UnixStream::pair().expect("pair");
    let mut connection = UnixConnection::from_stream(client);
    assert_eq!(connection.check_idle(), Ok(()));
    // Still blocking afterwards: a full exchange works.
    let pong = reply_body(&DnsReply::Pong {
        zone: FrontZone::Internal,
    });
    dird.write_all(&framed(&pong)).expect("write");
    assert_eq!(
        connection
            .receive(REPLY_LIMIT, DEADLINE)
            .expect("pong")
            .as_slice(),
        &pong[..]
    );

    dird.write_all(&[0x00]).expect("write");
    assert_eq!(connection.check_idle(), Err(TransportError::Framing));

    let (client, dird) = UnixStream::pair().expect("pair");
    let mut connection = UnixConnection::from_stream(client);
    drop(dird);
    assert_eq!(connection.check_idle(), Err(TransportError::Closed));
}

/// docs/50 R50-3: on a platform where the kernel's peer credentials are not
/// read, the uid check fails closed (the client then sends nothing).
#[cfg(not(target_os = "linux"))]
#[test]
fn peer_credentials_fail_closed_off_linux() {
    let (client, _dird) = UnixStream::pair().expect("pair");
    let connection = UnixConnection::from_stream(client);
    assert_eq!(connection.peer_uid(), Err(TransportError::PeerCredentials));
}

/// docs/50 R50-3: on Linux the peer uid is the kernel's (here, the test's
/// own process on both ends).
#[cfg(target_os = "linux")]
#[test]
fn peer_credentials_are_read_on_linux() {
    let (client, _dird) = UnixStream::pair().expect("pair");
    let connection = UnixConnection::from_stream(client);
    assert!(connection.peer_uid().is_ok());
}

/// `send` writes the whole frame.
#[test]
fn send_writes_the_whole_frame() {
    let (client, mut dird) = UnixStream::pair().expect("pair");
    let mut connection = UnixConnection::from_stream(client);
    let body = reply_body(&DnsReply::Unchanged {
        serial: Serial::new(4).expect("serial"),
    });
    let frame = framed(&body);
    connection.send(&frame, DEADLINE).expect("send");
    let mut received = vec![0u8; frame.len()];
    std::io::Read::read_exact(&mut dird, &mut received).expect("read");
    assert_eq!(received, frame);
}
