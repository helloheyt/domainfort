//! KDC configuration, validated once at construction (fail closed before any
//! request is handled).
//!
//! Ticket policy (allowed flags, lifetimes), the clock skew and the AES
//! encryption types are NOT configured here: they are keyd's
//! ([`keyd::KeydConfig`]), so the KDC can never plan a ticket that keyd's
//! template validation would not accept on the same terms.
//!
//! Spec: RFC 4120 §7.2 (transport), §8.2; main-session decisions 1, 3, 12.

use crate::krb_error::{krb_error, ErrorContext};
use keyd::{KeyHandle, KeyPurpose, KeydConfig};
use krb_proto::constants::KRB_ERR_RESPONSE_TOO_BIG;
use krb_proto::limits::MAX_MESSAGE_LEN;
use krb_proto::{KerberosTime, Realm};

/// Maximum length of one request message (the KDC-REQ, without the TCP length
/// prefix), in octets.
///
/// Justification (main-session decision 12): a phase-1 KDC-REQ is a few
/// hundred octets — an AS-REQ carries names, times, an etype list and one
/// PA-ENC-TIMESTAMP; a TGS-REQ adds one TGT, which in phase 1 carries no
/// authorization data (no PAC, D124 is phase 2). 64 KiB leaves more than a
/// hundredfold headroom for phase-2 PACs while bounding the memory one
/// request can make the KDC hold (AGENTS.md §6). It is a quarter of
/// krb-proto's own decoder bound (`limits::MAX_MESSAGE_LEN`, 256 KiB), so the
/// KDC's check is always the first one a request meets.
///
/// Spec: AGENTS.md §6 (bounded parsers); RFC 4120 7.2.2 (KRB_ERR_FIELD_TOOLONG
/// is the code for a length this implementation cannot take).
pub const MAX_REQUEST_LEN: usize = 64 * 1024;

/// Default largest reply sent over UDP before the KDC answers
/// KRB_ERR_RESPONSE_TOO_BIG instead (RFC 4120 7.2.1: "If the response cannot
/// be handled using UDP (for example, because it is too large)").
///
/// RFC 4120 does not fix the threshold. This project's default keeps a reply
/// within one unfragmented datagram on common 1500-octet links, with room for
/// the IP and UDP headers; the daemon should set it from the path MTU.
pub const DEFAULT_UDP_MAX_REPLY_LEN: usize = 1400;

/// Default number of replies the retransmit cache keeps (RFC 4120 3.1.2).
/// This project's choice; operators tune it.
pub const DEFAULT_RETRANSMIT_CAPACITY: usize = 4096;

/// Default bound on the octets (requests + replies) the retransmit cache
/// holds. This project's choice; operators tune it.
pub const DEFAULT_RETRANSMIT_MAX_OCTETS: usize = 8 * 1024 * 1024;

/// Upper bound for the retransmit-cache entry count (memory bound,
/// AGENTS.md §6).
pub const MAX_RETRANSMIT_CAPACITY: usize = 1 << 20;

/// Upper bound for the retransmit-cache octet budget (memory bound,
/// AGENTS.md §6).
pub const MAX_RETRANSMIT_OCTETS: usize = 256 * 1024 * 1024;

/// KDC configuration.
///
/// Spec: RFC 4120 §7.2, 3.1.2; main-session decisions 1, 3, 4, 12.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcConfig {
    /// The single realm this KDC serves (main-session decision 4). Must be
    /// keyd's realm.
    pub realm: Realm,
    /// keyd's handle of this realm's ticket-granting service key
    /// (krbtgt/REALM, RFC 4120 7.3). Must have purpose `Krbtgt`.
    pub krbtgt: KeyHandle,
    /// Largest reply sent over UDP; a larger reply is replaced by
    /// KRB_ERR_RESPONSE_TOO_BIG (RFC 4120 7.2.1).
    pub udp_max_reply_len: usize,
    /// Number of successful replies kept for retransmission (RFC 4120 3.1.2).
    pub retransmit_capacity: usize,
    /// Octet budget of the retransmit cache.
    pub retransmit_max_octets: usize,
}

impl KdcConfig {
    /// A configuration with this project's defaults for the transport and
    /// retransmit bounds. Spec: RFC 4120 §7.2, 3.1.2.
    pub fn new(realm: Realm, krbtgt: KeyHandle) -> Self {
        KdcConfig {
            realm,
            krbtgt,
            udp_max_reply_len: DEFAULT_UDP_MAX_REPLY_LEN,
            retransmit_capacity: DEFAULT_RETRANSMIT_CAPACITY,
            retransmit_max_octets: DEFAULT_RETRANSMIT_MAX_OCTETS,
        }
    }

    /// Check every field against keyd's configuration; any inconsistency is
    /// refused (fail closed).
    ///
    /// - the realm is keyd's realm (single realm, main-session decision 4);
    /// - the krbtgt handle has purpose `Krbtgt` (docs/10 §1, §4);
    /// - the UDP limit can carry the KDC's own KRB_ERR_RESPONSE_TOO_BIG
    ///   reply (otherwise RFC 4120 7.2.1 could not be obeyed) and is not above
    ///   krb-proto's message bound;
    /// - the retransmit bounds are non-zero and within the memory bounds.
    ///
    /// Spec: RFC 4120 7.2.1, 7.3; docs/10 §1; AGENTS.md §6.
    pub fn validate(&self, keyd: &KeydConfig) -> Result<(), ConfigError> {
        if self.realm.as_bytes() != keyd.realm.as_bytes() {
            return Err(ConfigError::RealmMismatch);
        }
        if self.krbtgt.purpose != KeyPurpose::Krbtgt {
            return Err(ConfigError::KrbtgtPurpose);
        }
        if self.udp_max_reply_len > MAX_MESSAGE_LEN {
            return Err(ConfigError::UdpReplyLimit);
        }
        // The smallest reply the KDC ever sends over UDP is the
        // RESPONSE_TOO_BIG error naming its own realm and TGS; any stime has
        // the same encoded length (KerberosTime is fixed-width, RFC 4120
        // 5.2.3).
        let probe_time =
            KerberosTime::new(2000, 1, 1, 0, 0, 0).map_err(|_| ConfigError::UdpReplyLimit)?;
        let fallback = ErrorContext::local(&self.realm)
            .and_then(|ctx| krb_error(KRB_ERR_RESPONSE_TOO_BIG, &ctx, probe_time, None))
            .ok_or(ConfigError::UdpReplyLimit)?;
        if fallback.len() > self.udp_max_reply_len {
            return Err(ConfigError::UdpReplyLimit);
        }
        if self.retransmit_capacity == 0
            || self.retransmit_capacity > MAX_RETRANSMIT_CAPACITY
            || self.retransmit_max_octets == 0
            || self.retransmit_max_octets > MAX_RETRANSMIT_OCTETS
        {
            return Err(ConfigError::RetransmitBounds);
        }
        Ok(())
    }
}

/// Configuration refused at construction. Carries no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// The KDC realm is not keyd's realm.
    RealmMismatch,
    /// The krbtgt handle does not have purpose `Krbtgt`.
    KrbtgtPurpose,
    /// The UDP reply limit is too small for the KDC's own errors, or larger
    /// than the message bound.
    UdpReplyLimit,
    /// A retransmit-cache bound is zero or above its memory bound.
    RetransmitBounds,
    /// The key-custody caller is not the `Kdc` role (docs/10 §2).
    CustodyRole,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ConfigError::RealmMismatch => "KDC realm differs from keyd realm",
            ConfigError::KrbtgtPurpose => "krbtgt handle does not have purpose Krbtgt",
            ConfigError::UdpReplyLimit => "invalid UDP reply limit",
            ConfigError::RetransmitBounds => "invalid retransmit cache bounds",
            ConfigError::CustodyRole => "key custody caller is not the Kdc role",
        })
    }
}

impl std::error::Error for ConfigError {}
