//! Small probes of the running deployment, from the client side only: one
//! Kerberos request over the kdc's UDP or TCP listener (RFC 4120 §7.2.1,
//! §7.2.2), one rootDSE over ldap-front (RFC 4511 §4.5.1, §5.2).
//!
//! Sources: RFC 4120 §3.1.3, §5.4.2, §7.2.1, §7.2.2, §7.5.9; RFC 4511
//! §4.4.1, §4.5.1; docs/50 §3.7 (R50-8). Every value is made here.
#![allow(dead_code)]

use super::harness::Harness;
use super::kdcd::{tcp_send, udp_send, TcpReply};
use super::ldap_client::{closed, decoded, root_dse, tcp, tls_over, LdapReader};
use crate::common::{machine_key, open_as_rep, AES256};
use core::time::Duration;
use krb_proto::{AsRep, KrbError};
use parse_ldap::ProtocolOp;
use std::io::Write;

/// How long a UDP client waits before it concludes the kdc stays silent
/// (RFC 4120 §7.2.1 has no error over UDP for an unavailable service,
/// docs/50 §3.7). The kdc answers a loopback request in milliseconds.
pub const UDP_SILENCE: Duration = Duration::from_secs(1);

/// How long a UDP client waits for a reply that must come.
pub const UDP_WAIT: Duration = Duration::from_secs(5);

/// What the kdc answered over TCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdcAnswer {
    /// A KDC-REP (an issuance), RFC 4120 §5.4.2.
    Issued,
    /// A KRB-ERROR with this code, RFC 4120 §5.9.1.
    Error(i32),
    /// The stream closed without a reply.
    Closed,
    /// Something else.
    Other,
}

/// Send `request` over TCP (a new connection, RFC 4120 §7.2.2) and
/// classify the answer.
pub fn kdc_tcp(h: &Harness, request: &[u8]) -> KdcAnswer {
    match tcp_send(h.kdcd().tcp, request) {
        TcpReply::Message(message) => classify(&message),
        TcpReply::Closed => KdcAnswer::Closed,
    }
}

/// Send `request` over UDP (RFC 4120 §7.2.1); `None` when the kdc stays
/// silent for [`UDP_SILENCE`].
pub fn kdc_udp(h: &Harness, request: &[u8]) -> Option<KdcAnswer> {
    udp_send(h.kdcd().udp, request, UDP_SILENCE).map(|reply| classify(&reply))
}

fn classify(message: &[u8]) -> KdcAnswer {
    if AsRep::decode(message).is_ok() || krb_proto::TgsRep::decode(message).is_ok() {
        KdcAnswer::Issued
    } else if let Ok(error) = KrbError::decode(message) {
        KdcAnswer::Error(error.error_code)
    } else {
        KdcAnswer::Other
    }
}

/// One TCP request whose answer is **not** looked at, sent right after keyd
/// or dird was restarted under the running kdc.
///
/// The kdc keeps its connection to keyd and to dird open between requests
/// (docs/50 §3.6: "clients hold a connection"); after the server process
/// was replaced, that idle connection is found broken only when the next
/// request uses it, and that request is answered 29 (`Unavailable`; the
/// clients reconnect at the *next* call — crates/ipc-keyd client.rs, "Any
/// failure drops the connection; the next call reconnects"). Observed in
/// this harness and recorded as docs/questions/Q-312. This probe takes that
/// one answer out of the assertions that follow, so that each of them is
/// decided by the server now running, not by the stale connection. The
/// probe is the computer's bootstrap, which reaches dird and then keyd
/// (RFC 4120 §3.1.2; docs/47 §8.1), so it meets whichever connection is
/// stale (only one server is restarted at a time in these tests).
pub fn after_restart(h: &Harness, nonce: u32) {
    let _ = kdc_tcp(h, &super::kdcd::bootstrap(nonce));
}

/// The computer's bootstrap AS-REQ with `nonce` over TCP: `true` if the
/// AS-REP came and opens with the computer's key (RFC 4120 §3.1.5).
pub fn bootstrap_issued(h: &Harness, nonce: u32) -> bool {
    match tcp_send(h.kdcd().tcp, &super::kdcd::bootstrap(nonce)) {
        TcpReply::Message(message) if AsRep::decode(&message).is_ok() => {
            let _ = open_as_rep(&message, &machine_key(AES256));
            true
        }
        _ => false,
    }
}

/// What ldap-front answered a rootDSE with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapAnswer {
    /// The search was answered (its responses).
    Served(Vec<Vec<u8>>),
    /// One message that is not a search response (a Notice of
    /// Disconnection, RFC 4511 §4.4.1), then the connection closed.
    NoticeThenClosed(Vec<u8>),
    /// Closed with no message.
    Closed,
}

/// A new LDAPS connection, one anonymous rootDSE (RFC 4511 §4.5.1).
pub fn ldaps_root_dse(h: &Harness) -> LdapAnswer {
    let Ok(mut stream) = tls_over(tcp(h.front().ldaps), &h.tls_client) else {
        return LdapAnswer::Closed;
    };
    if stream.write_all(&root_dse(1)).is_err() {
        return LdapAnswer::Closed;
    }
    let mut reader = LdapReader::default();
    let mut responses = Vec::new();
    loop {
        let Some(response) = reader.next(&mut stream) else {
            return match responses.len() {
                0 => LdapAnswer::Closed,
                _ => LdapAnswer::Served(responses),
            };
        };
        match decoded(&response).protocol_op {
            ProtocolOp::SearchResultEntry(_) => responses.push(response),
            ProtocolOp::SearchResultDone(_) => {
                responses.push(response);
                return LdapAnswer::Served(responses);
            }
            _ => {
                assert_eq!(closed(&mut stream), Ok(()), "closed after the notice");
                return LdapAnswer::NoticeThenClosed(response);
            }
        }
    }
}

/// A new cleartext LDAP connection that sends nothing: what the front says
/// first, within the read timeout (a notice and close when dird is not
/// there — docs/50 §3.7; otherwise nothing).
pub fn ldap_first_words(h: &Harness) -> Option<Vec<u8>> {
    let mut plain = tcp(h.front().ldap);
    plain
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut reader = LdapReader::default();
    reader.next(&mut plain)
}
