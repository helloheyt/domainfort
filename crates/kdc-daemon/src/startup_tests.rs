//! Unit tests of the binding step (`startup.rs`), in-crate: the kdc's file
//! names port 88 only (crates/config `NonStandardPort`, task DN10c), so the
//! binding itself is exercised here on a loopback port the system picks —
//! through the crate-private `bind_addresses`, which no product path can
//! give an address that is not from the file. Moved from tests/startup.rs
//! (docs/questions/Q-1024).
//!
//! Sources: docs/50 §4.1 ("each address served on UDP and TCP"), §6.2;
//! RFC 4120 §7.2.1, §7.2.2. Hand-made values (loopback, a system-chosen
//! port — never a privileged one).

use super::*;

/// docs/50 §4.1, §6.2: one UDP socket and one TCP listener per address; an
/// address already taken refuses the start.
#[test]
fn listeners_are_bound_per_address() {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let free = std::net::TcpListener::bind(("127.0.0.1", port));
    let Ok(free) = free else {
        return; // the port was taken meanwhile: nothing to check
    };
    drop(free);
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let listeners = bind_addresses(&[address]).unwrap();
    assert_eq!((listeners.udp.len(), listeners.tcp.len()), (1, 1));
    assert_eq!(listeners.udp[0].local_addr().unwrap(), address);
    assert_eq!(listeners.tcp[0].local_addr().unwrap(), address);
    assert!(matches!(
        bind_addresses(&[address]),
        Err(StartupError::Bind(_))
    ));
}
