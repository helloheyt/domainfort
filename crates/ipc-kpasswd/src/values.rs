//! The channel's value types. Each one can hold only a value the channel
//! admits, so a value that would be refused on the wire cannot be built in
//! the first place (AGENTS.md §6.1 — unrepresentable states), and the
//! decoder and the constructors apply the same rules.
//!
//! # No password, by type
//!
//! No value here can hold a password in clear. The two messages of a
//! request are [`ApReqOctets`] and [`KrbPrivOctets`] — the client's octets,
//! uninterpreted — and a [`KrbPrivOctets`] always starts with the KRB-PRIV
//! identifier `[APPLICATION 21]`: the password is in its `enc-part`, under
//! the Authenticator's subkey (RFC 3244 §2: "This user-data field in the
//! KRB-PRIV message is encrypted using the subkey from the authenticator"),
//! which only keyd recovers (docs/53 R53-4: "only keyd decrypts the new
//! password"). The cleartext structure that would carry it — EncKrbPrivPart,
//! `[APPLICATION 28]` (RFC 4120 §5.7.1) — is refused. The crate links no
//! Kerberos crate, so no decoded or decrypted Kerberos type can appear here
//! either (crate documentation).
//!
//! Spec: docs/53 §4.3, §5.4, §5.5, R53-4; RFC 3244 §2; RFC 4120 §5.7.1,
//! §7.1; docs/50 §3.3 ("a single encoding per value").

use crate::channel::{
    codes, AP_REP_IDENTIFIER, AP_REQ_IDENTIFIER, KRB_PRIV_IDENTIFIER, MAX_REQUEST_FIELD,
    MAX_REQUEST_MESSAGES, MAX_SEALED_MESSAGES,
};
use core::fmt;
use core::net::IpAddr;
use zeroize::Zeroizing;

/// The zone of the kpasswd front, as dird derives it from the peer uid of
/// the channel connection (a kernel fact, docs/50 R50-3) and names it in
/// every `Pong`; the front refuses a dird that names another (the R14 + R9b
/// pattern). Phase 1 has one front and only the internal zone (A-114;
/// docs/53 §3.3: "`FrontZone::Internal` the only value"); an external zone
/// has no code path.
///
/// Spec: docs/53 §3.3, §5.6 step 1; docs/52 §7 R14; A-114.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrontZone {
    /// The internal front: it listens only on addresses inside
    /// `internal_networks` and serves only sources inside them.
    Internal,
}

impl FrontZone {
    /// The wire code. Spec: docs/50 §3.3.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            FrontZone::Internal => codes::ZONE_INTERNAL,
        }
    }

    /// Code → zone (closed table).
    #[must_use]
    pub const fn from_code(code: u8) -> Option<FrontZone> {
        match code {
            codes::ZONE_INTERNAL => Some(FrontZone::Internal),
            _ => None,
        }
    }
}

/// An address of the client's TCP connection as the front's kernel reported
/// it (`accept`'s peer, the socket's local address) — always the canonical
/// form: an IPv4-mapped IPv6 address is held as the IPv4 address it maps,
/// so one host has one spelling (RFC 4120 §7.1: "IPv4-mapped IPv6 addresses
/// MUST be represented as addresses of type 2"). No port: keyd compares the
/// KRB-PRIV's `s-address` (a HostAddress — no port) with the peer, and puts
/// the local address in the reply's `s-address` (docs/53 §5.4 item 3, §5.7;
/// docs/questions/Q-603 item 8, Q-604 item 2).
///
/// **Whose fact this is.** The front owns the client's socket, so these
/// addresses are its kernel-observed facts (docs/53 §4.1 last row); a
/// compromised front can report any address and so skip only the
/// `s-address` check — a documented residual (docs/53 §8, "front
/// compromised"; Q-603 item 8).
///
/// Spec: RFC 4120 §7.1; docs/53 §4.1, §5.4 item 3, §5.5 (`peer`, `local`);
/// std 1.95.0 API documentation, `IpAddr::to_canonical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObservedAddress(IpAddr);

impl ObservedAddress {
    /// The address `address`, in canonical form (an IPv4-mapped IPv6 address
    /// becomes its IPv4 address).
    /// Spec: type documentation.
    #[must_use]
    pub const fn new(address: IpAddr) -> ObservedAddress {
        ObservedAddress(address.to_canonical())
    }

    /// The address (canonical: never an IPv4-mapped IPv6 address).
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.0
    }
}

/// Copy `octets` into a zeroizing buffer of exactly their length, or `None`
/// if they are empty, longer than `max`, or do not start with `identifier`.
/// Spec: docs/53 §5.1 (each message ≥ 1 octet); X.690 8.1.2.2 (the
/// identifier octet).
fn kerberos_octets(octets: &[u8], identifier: u8, max: u32) -> Option<Zeroizing<Vec<u8>>> {
    let within = u32::try_from(octets.len()).is_ok_and(|len| len <= max);
    if !within || octets.first() != Some(&identifier) {
        return None;
    }
    let mut buffer = Zeroizing::new(Vec::with_capacity(octets.len()));
    // Within the reserved capacity: no reallocation.
    buffer.extend_from_slice(octets);
    Some(buffer)
}

/// Writes `Name { len }` — never the octets (docs/53 §9: "never … the
/// KRB-PRIV / AP-REQ octets").
fn length_only(f: &mut fmt::Formatter<'_>, name: &str, len: usize) -> fmt::Result {
    f.debug_struct(name).field("len", &len).finish()
}

/// `AP_REQ data` of an RFC 3244 request: the client's KRB_AP_REQ for
/// `kadmin/changepw@REALM`, exactly as received — at least one octet, at
/// most [`MAX_REQUEST_FIELD`], and starting with the AP-REQ identifier
/// `[APPLICATION 14]`. Uninterpreted here: keyd decodes and verifies it
/// (docs/53 §5.3). Held in a zeroizing buffer; `Debug` shows only the
/// length.
///
/// Spec: RFC 3244 §2 ("AP-REQ data"); RFC 4120 §5.5.1, §5.10; docs/53 §5.1.
#[derive(Clone, PartialEq, Eq)]
pub struct ApReqOctets(Zeroizing<Vec<u8>>);

impl ApReqOctets {
    /// The AP-REQ `octets`, or `None` (empty, over [`MAX_REQUEST_FIELD`], or
    /// not starting with `[APPLICATION 14]`).
    /// Spec: RFC 3244 §2; RFC 4120 §5.10; X.690 8.1.2.2.
    #[must_use]
    pub fn new(octets: &[u8]) -> Option<ApReqOctets> {
        kerberos_octets(octets, AP_REQ_IDENTIFIER, MAX_REQUEST_FIELD).map(ApReqOctets)
    }

    /// The octets, exactly as received.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Octets of the message.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: the message has at least its identifier.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ApReqOctets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        length_only(f, "ApReqOctets", self.0.len())
    }
}

/// A KRB-PRIV message exactly as one side sent it: in a request, the
/// client's (its `user-data` the ChangePasswdData with the new password,
/// encrypted under the Authenticator's subkey — RFC 3244 §2); in a reply,
/// keyd's (its `user-data` the result code, under the same subkey —
/// docs/53 §5.5). At least one octet, at most [`MAX_REQUEST_FIELD`], and
/// **always starting with the KRB-PRIV identifier `[APPLICATION 21]`** — so
/// never the cleartext EncKrbPrivPart (`[APPLICATION 28]`), never a bare
/// ChangePasswdData (a SEQUENCE) and never raw password octets (module
/// documentation). Held in a zeroizing buffer; `Debug` shows only the
/// length.
///
/// Spec: RFC 3244 §2; RFC 4120 §5.7.1, §5.10; X.690 8.1.2.2; docs/53 R53-4.
#[derive(Clone, PartialEq, Eq)]
pub struct KrbPrivOctets(Zeroizing<Vec<u8>>);

impl KrbPrivOctets {
    /// The KRB-PRIV `octets`, or `None` (empty, over [`MAX_REQUEST_FIELD`],
    /// or not starting with `[APPLICATION 21]`).
    /// Spec: RFC 4120 §5.7.1, §5.10; X.690 8.1.2.2.
    #[must_use]
    pub fn new(octets: &[u8]) -> Option<KrbPrivOctets> {
        kerberos_octets(octets, KRB_PRIV_IDENTIFIER, MAX_REQUEST_FIELD).map(KrbPrivOctets)
    }

    /// The octets, exactly as sent.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Octets of the message.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: the message has at least its identifier.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for KrbPrivOctets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        length_only(f, "KrbPrivOctets", self.0.len())
    }
}

/// `AP-REP data` of an RFC 3244 reply: keyd's KRB_AP_REP (ctime / cusec of
/// the Authenticator, under the ticket's session key — docs/53 §5.5), as
/// keyd sealed it — at least one octet, at most [`MAX_SEALED_MESSAGES`],
/// starting with the AP-REP identifier `[APPLICATION 15]`. `Debug` shows
/// only the length.
///
/// Spec: RFC 3244 §2 ("AP-REP data"); RFC 4120 §5.5.2, §5.10.
#[derive(Clone, PartialEq, Eq)]
pub struct ApRepOctets(Zeroizing<Vec<u8>>);

impl ApRepOctets {
    /// The AP-REP `octets`, or `None` (empty, over [`MAX_SEALED_MESSAGES`],
    /// or not starting with `[APPLICATION 15]`).
    /// Spec: RFC 4120 §5.5.2, §5.10; X.690 8.1.2.2.
    #[must_use]
    pub fn new(octets: &[u8]) -> Option<ApRepOctets> {
        kerberos_octets(octets, AP_REP_IDENTIFIER, MAX_SEALED_MESSAGES).map(ApRepOctets)
    }

    /// The octets, exactly as keyd sealed them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Octets of the message.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: the message has at least its identifier.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ApRepOctets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        length_only(f, "ApRepOctets", self.0.len())
    }
}

/// `ChangePassword`: one RFC 3244 request as the front received it — the
/// AP-REQ and the KRB-PRIV, uninterpreted, together at most
/// [`MAX_REQUEST_MESSAGES`] octets (one RFC 3244 message) — and the
/// connection's peer and local addresses. Exactly the inputs of keyd's
/// `open_change_password_request` that are the front's facts (docs/53 §5.5:
/// `ap_req_octets`, `krb_priv_octets`, `peer`, `local`); keyd's clock and
/// the service key set are keyd's and dird's.
///
/// **No field can carry a password in clear** (module documentation), and
/// nothing a client could claim about itself travels here: the subject is
/// what keyd verifies in the AP-REQ, the zone is dird's (from the front's
/// uid), the target is the ticket's client (docs/53 §4.3, R53-8).
///
/// Spec: docs/53 §4.3, §5.5, R53-4; RFC 3244 §2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePasswordRequest {
    ap_req: ApReqOctets,
    krb_priv: KrbPrivOctets,
    peer: ObservedAddress,
    local: ObservedAddress,
}

impl ChangePasswordRequest {
    /// The request, or `None` if the two messages together are longer than
    /// one RFC 3244 message can carry ([`MAX_REQUEST_MESSAGES`]).
    /// Spec: RFC 3244 §2; docs/53 §5.9 ("both fields together ≤ one
    /// message").
    #[must_use]
    pub fn new(
        ap_req: ApReqOctets,
        krb_priv: KrbPrivOctets,
        peer: ObservedAddress,
        local: ObservedAddress,
    ) -> Option<ChangePasswordRequest> {
        let total = ap_req.len().checked_add(krb_priv.len())?;
        if u32::try_from(total).is_ok_and(|total| total <= MAX_REQUEST_MESSAGES) {
            Some(ChangePasswordRequest {
                ap_req,
                krb_priv,
                peer,
                local,
            })
        } else {
            None
        }
    }

    /// The AP-REQ, exactly as received.
    #[must_use]
    pub fn ap_req(&self) -> &ApReqOctets {
        &self.ap_req
    }

    /// The KRB-PRIV, exactly as received.
    #[must_use]
    pub fn krb_priv(&self) -> &KrbPrivOctets {
        &self.krb_priv
    }

    /// The client's address, as the front's kernel reported it.
    #[must_use]
    pub fn peer(&self) -> ObservedAddress {
        self.peer
    }

    /// The connection's local address, as the front's kernel reported it.
    #[must_use]
    pub fn local(&self) -> ObservedAddress {
        self.local
    }
}

/// `Sealed`: keyd's reply to one change request — the AP-REP and the
/// KRB-PRIV, both sealed by keyd (AP-REP under the ticket's session key,
/// KRB-PRIV under the Authenticator's subkey; docs/53 §5.5 `SealedReply`),
/// together at most [`MAX_SEALED_MESSAGES`] octets. The front frames it as
/// the RFC 3244 reply without looking inside: whether it says success or a
/// sealed failure only the client can read (docs/53 §5.5: "exactly one reply
/// per context; success only after the install").
///
/// Spec: docs/53 §5.5, §5.7; RFC 3244 §2 (reply message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedReply {
    ap_rep: ApRepOctets,
    krb_priv: KrbPrivOctets,
}

impl SealedReply {
    /// The sealed reply, or `None` if the two messages together are longer
    /// than [`MAX_SEALED_MESSAGES`].
    /// Spec: docs/53 §5.5, §5.9.
    #[must_use]
    pub fn new(ap_rep: ApRepOctets, krb_priv: KrbPrivOctets) -> Option<SealedReply> {
        let total = ap_rep.len().checked_add(krb_priv.len())?;
        if u32::try_from(total).is_ok_and(|total| total <= MAX_SEALED_MESSAGES) {
            Some(SealedReply { ap_rep, krb_priv })
        } else {
            None
        }
    }

    /// The AP-REP.
    #[must_use]
    pub fn ap_rep(&self) -> &ApRepOctets {
        &self.ap_rep
    }

    /// The KRB-PRIV.
    #[must_use]
    pub fn krb_priv(&self) -> &KrbPrivOctets {
        &self.krb_priv
    }
}

/// `Unsealed.code`: the RFC 3244 result code of a reply dird cannot seal —
/// there is no keyd context to seal in — which the front sends in its
/// KRB-ERROR. A closed table of the two codes docs/53 §5.7 assigns to such
/// replies; every code keyd established after verifying the ticket
/// (ACCESSDENIED, SOFTERROR, INITIAL_FLAG_NEEDED, and dird's own decisions
/// on a verified request) is sealed instead (`Sealed`), and the front's own
/// codes (MALFORMED, BAD_VERSION) never cross this channel. SUCCESS is not
/// representable (RFC 3244 §2: not allowed in a KRB-ERROR).
///
/// **Class closed (AGENTS.md §6.1):** "an unauthenticated reply carrying a
/// code that should have been sealed" — a compromised dird answering, say,
/// ACCESSDENIED in a KRB-ERROR where keyd's sealed verdict was due; root
/// option taken: the type has no such value.
///
/// Spec: RFC 3244 §2 (codes 2, 3); docs/53 §5.7; A-26; A-126 (docs/questions
/// Q-660 item 3: an undecodable AP-REQ or KRB-PRIV is keyd's uniform
/// `Denied` ⇒ AUTHERROR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnsealedCode {
    /// KRB5_KPASSWD_HARDERROR (2): keyd, the audit trail or the store not
    /// available, dird busy, an unknown outcome.
    HardError,
    /// KRB5_KPASSWD_AUTHERROR (3): keyd refused before or in the
    /// cryptographic chain (uniform, A-26).
    AuthError,
}

impl UnsealedCode {
    /// The RFC 3244 result code value (also the wire code).
    /// Spec: RFC 3244 §2.
    #[must_use]
    pub const fn value(self) -> u16 {
        match self {
            UnsealedCode::HardError => codes::UNSEALED_HARDERROR as u16,
            UnsealedCode::AuthError => codes::UNSEALED_AUTHERROR as u16,
        }
    }

    /// The wire code. Spec: docs/50 §3.3.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            UnsealedCode::HardError => codes::UNSEALED_HARDERROR,
            UnsealedCode::AuthError => codes::UNSEALED_AUTHERROR,
        }
    }

    /// Code → value (closed table).
    #[must_use]
    pub const fn from_code(code: u8) -> Option<UnsealedCode> {
        match code {
            codes::UNSEALED_HARDERROR => Some(UnsealedCode::HardError),
            codes::UNSEALED_AUTHERROR => Some(UnsealedCode::AuthError),
            _ => None,
        }
    }
}

/// dird's answer to one `ChangePassword`.
/// Spec: docs/53 §5.5–§5.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KpasswdAnswer {
    /// keyd's sealed reply (success, or a sealed failure).
    Sealed(SealedReply),
    /// No context to seal in: the front's KRB-ERROR with this code.
    Unsealed(UnsealedCode),
}
