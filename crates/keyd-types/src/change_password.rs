//! The arguments and the result types of keyd's three change-password
//! operations (role `Ldap`, task K3): `open_change_password_request`,
//! `complete_change_password` and `seal_change_password_error`.
//!
//! keyd verifies the AP-REQ for `kadmin/changepw`, decrypts the KRB-PRIV
//! under the Authenticator's subkey, judges the ChangePasswdData and keeps
//! the new password — none of which leaves keyd: the caller (dird) receives
//! a one-time request context id, the ticket's non-secret facts and a
//! **verdict** (docs/53 §5.5). The context is then consumed exactly once:
//! by `complete_change_password` (which installs the password and only then
//! seals the success reply) or by `seal_change_password_error` (which seals
//! a non-zero result code). So an authenticated reply — a KRB-PRIV under the
//! client's subkey — always states what keyd did (docs/53 §5.5: "exactly one
//! reply per context; success only after the install").
//!
//! # The verdict carries the request kind
//!
//! A ChangePasswdData with `targname` or `targrealm` is a request to set a
//! password ([MS-KILE] 3.1.5.12), which phase 1 refuses (docs/53 R53-1):
//! its verdict is always [`ChangePasswordVerdict::SetNotSupported`]. Every
//! other verdict is about a change request. So the decoded request kind is
//! the verdict itself — not a second field that could contradict it.
//!
//! # Which error a caller may seal
//!
//! [`ChangePasswordVerdict::permits_error`]: a context whose verdict is not
//! acceptable is sealed with **its verdict's** result code and no other; an
//! acceptable one only with a code the caller decides after keyd —
//! KRB5_KPASSWD_HARDERROR (2), KRB5_KPASSWD_AUTHERROR (3) or
//! KRB5_KPASSWD_ACCESSDENIED (5) (docs/53 §5.7: dird's rows). MALFORMED (1)
//! and BAD_VERSION (6) describe a message keyd could not open, never one it
//! opened, and SOFTERROR (4) / INITIAL_FLAG_NEEDED (7) are keyd's findings,
//! so none of them is sealable for an acceptable request. Class closed
//! (docs/CLEAN-ROOM.md): "an authenticated reply that states an outcome other
//! than what was established" — a sealed code is bound to keyd's verdict by
//! construction, not by the caller's discipline.
//!
//! # Addresses
//!
//! [`HostAddr`] is the address of a connection's end as the front's kernel
//! reported it (`accept`): IPv4 or IPv6, with an IPv4-mapped IPv6 address
//! always held as IPv4 — RFC 4120 7.1: "IPv4-mapped IPv6 addresses MUST be
//! represented as addresses of type 2". The representation is private, so a
//! mapped address of type 24 cannot be built.
//!
//! Written only from RFC 3244 §2, RFC 4120 §2.1, §3.2.3, §3.2.4, §3.5.1,
//! §3.5.2, §5.5.2, §5.7.1, §7.1, §7.5.3 (pinned copies, SHA-256 verified
//! against tools/spec-pin/manifest.json), [MS-KILE] 3.1.5.12 (as recorded in
//! docs/53 §2.2), docs/53 §4.5, §5.4-§5.7 and docs/questions/Q-601, Q-603,
//! Q-604, Q-620 (decisions A-117, A-121), opened in this session. No other
//! implementation was consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: RFC 3244 §2; RFC 4120 2.1, 3.2.4, 3.5.2, 5.7.1, 7.1; docs/53 §4.5,
//! §5.4-§5.7; docs/questions/Q-601 item 2, Q-603, Q-604 (A-117).

use crate::tokens::ChangePasswordCtxId;
use core::fmt;
use krb_proto::{
    ApRep, HostAddress, KerberosTime, KrbPriv, NonZeroResultCode, PrincipalName, Realm, TicketFlags,
};

/// The address type of an IPv4 address: two (2).
/// Spec: RFC 4120 7.1 ("The type of IPv4 addresses is two (2)"), 7.5.3.
pub const ADDRESS_TYPE_IPV4: i32 = 2;

/// The directional address type: three (3).
/// Spec: RFC 4120 7.1 ("Directional addresses are type (3)"), 7.5.3.
pub const ADDRESS_TYPE_DIRECTIONAL: i32 = 3;

/// The address type of an IPv6 address: twenty-four (24).
/// Spec: RFC 4120 7.1 ("The type of IPv6 addresses is twenty-four (24)"),
/// 7.5.3.
pub const ADDRESS_TYPE_IPV6: i32 = 24;

/// The directional address of the party that sent the original KRB_AP_REQ
/// (the client): 0, as a four-octet unsigned integer in network byte order.
/// Spec: RFC 4120 7.1 ("If the message is originated by the party sending
/// the original KRB_AP_REQ message, then an address of 0 SHOULD be used").
pub const DIRECTIONAL_AP_REQ_SENDER: [u8; 4] = 0u32.to_be_bytes();

/// The directional address of the party to whom the KRB_AP_REQ was sent
/// (keyd, answering): 1, four octets, network byte order.
/// Spec: RFC 4120 7.1 ("If the message is originated by the party to whom
/// that KRB_AP_REQ was sent, then the address 1 SHOULD be used").
pub const DIRECTIONAL_AP_REQ_RECIPIENT: [u8; 4] = 1u32.to_be_bytes();

/// The prefix of an IPv4-mapped IPv6 address (`::ffff:0:0/96`): ten zero
/// octets, then two `0xff` octets, then the IPv4 address.
/// Spec: RFC 4120 7.1 (IPv4-mapped IPv6 addresses, type 2); the address form
/// as used in the operating system's report of a dual-stack socket's peer.
const IPV4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

/// The address of one end of a connection, as the kernel of the socket's
/// host reported it (module documentation). Not secret.
/// Spec: docs/53 §5.5 (`peer: HostAddr`, `local: HostAddr`); RFC 4120 7.1.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostAddr(Repr);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Repr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl HostAddr {
    /// An IPv4 address. Spec: RFC 4120 7.1 (4 octets, MSB first).
    #[must_use]
    pub const fn ipv4(octets: [u8; 4]) -> HostAddr {
        HostAddr(Repr::V4(octets))
    }

    /// An IPv6 address; an IPv4-mapped one becomes the IPv4 address it maps
    /// (RFC 4120 7.1: such addresses "MUST be represented as addresses of
    /// type 2"). Spec: RFC 4120 7.1 (16 octets, MSB first).
    #[must_use]
    pub fn ipv6(octets: [u8; 16]) -> HostAddr {
        match (octets.get(..12), octets.get(12..)) {
            (Some(prefix), Some(v4)) if prefix == IPV4_MAPPED_PREFIX => {
                let mut ipv4 = [0u8; 4];
                ipv4.copy_from_slice(v4);
                HostAddr(Repr::V4(ipv4))
            }
            _ => HostAddr(Repr::V6(octets)),
        }
    }

    /// The RFC 4120 address type: [`ADDRESS_TYPE_IPV4`] or
    /// [`ADDRESS_TYPE_IPV6`]. Spec: RFC 4120 7.1, 7.5.3.
    #[must_use]
    pub const fn addr_type(&self) -> i32 {
        match self.0 {
            Repr::V4(_) => ADDRESS_TYPE_IPV4,
            Repr::V6(_) => ADDRESS_TYPE_IPV6,
        }
    }

    /// The address octets (4 or 16), MSB first. Spec: RFC 4120 7.1.
    #[must_use]
    pub fn octets(&self) -> &[u8] {
        match &self.0 {
            Repr::V4(octets) => octets,
            Repr::V6(octets) => octets,
        }
    }

    /// This address as a Kerberos HostAddress. Spec: RFC 4120 5.2.5, 7.1.
    #[must_use]
    pub fn host_address(&self) -> HostAddress {
        HostAddress {
            addr_type: self.addr_type(),
            address: self.octets().to_vec(),
        }
    }

    /// Whether the HostAddress `claimed` is exactly this address: the same
    /// type and the same octets. An IPv6 HostAddress that is IPv4-mapped is
    /// never equal to anything (RFC 4120 7.1: it "MUST" be type 2).
    /// Spec: RFC 4120 3.5.2 ("the recipient verifies that the operating
    /// system's report of the sender's address matches the sender's address
    /// in the message"), 7.1.
    #[must_use]
    pub fn is(&self, claimed: &HostAddress) -> bool {
        claimed.addr_type == self.addr_type() && claimed.address.as_slice() == self.octets()
    }
}

impl fmt::Debug for HostAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Repr::V4(o) => write!(f, "HostAddr({}.{}.{}.{})", o[0], o[1], o[2], o[3]),
            Repr::V6(o) => {
                f.write_str("HostAddr(")?;
                for (i, pair) in o.chunks(2).enumerate() {
                    if i > 0 {
                        f.write_str(":")?;
                    }
                    for octet in pair {
                        write!(f, "{octet:02x}")?;
                    }
                }
                f.write_str(")")
            }
        }
    }
}

/// keyd's verdict on an opened change-password request: whether it may be
/// completed, or which result code its error reply carries. Decided by keyd
/// after the AP-REQ and the KRB-PRIV verified (so it reaches only the holder
/// of the subkey), in docs/53 §5.4's order: the ChangePasswdData (malformed,
/// too long, a set request), the password's encoding, the password policy,
/// then the INITIAL flag.
///
/// Spec: docs/53 §5.4 items 4-7, §5.5 (`verdict: Acceptable |
/// InitialFlagNeeded | SetNotSupported | PasswordRefused`), §5.7;
/// docs/questions/Q-620 item 5 (the ChangePasswdData decoding failures);
/// RFC 3244 §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangePasswordVerdict {
    /// A change of the ticket client's own password, to a password that
    /// passed the policy, under an INITIAL ticket: may be completed
    /// (`complete_change_password`, on dird's decision).
    Acceptable,
    /// The ChangePasswdData does not decode (a field after `targrealm`, a
    /// wrong type, non-DER) — the KRB-PRIV itself decoded, so the reply is a
    /// KRB-PRIV (RFC 3244 §2: KRB-ERROR only when the server "cannot decode
    /// the client AP-REQ or KRB-PRIV message"). KRB5_KPASSWD_MALFORMED (1).
    /// Spec: docs/questions/Q-603 item 6, Q-620 item 5.
    Malformed,
    /// The ticket is not INITIAL. KRB5_KPASSWD_INITIAL_FLAG_NEEDED (7).
    /// Spec: RFC 3244 §2 ("replying with status 0x0007 if it is not set and
    /// should be"); RFC 4120 2.1; docs/53 R53-9.
    InitialFlagNeeded,
    /// `targname` or `targrealm` present: a set request, not supported in
    /// phase 1, refused without looking the target up.
    /// KRB5_KPASSWD_ACCESSDENIED (5).
    /// Spec: [MS-KILE] 3.1.5.12; docs/53 R53-1, §5.4 item 4; Q-600 item 2.
    SetNotSupported,
    /// The new password is longer than the bound, not UTF-8, or breaks the
    /// password policy — which rule is never reported.
    /// KRB5_KPASSWD_SOFTERROR (4).
    /// Spec: RFC 3244 §2; RFC 3961 §3; [MS-SAMR] 3.1.1.7.2; docs/53 §5.4
    /// items 5-6, §6.3; docs/questions/Q-603 item 7, Q-620 item 5.
    PasswordRefused,
}

impl ChangePasswordVerdict {
    /// The result code of this verdict's error reply; `None` for
    /// [`ChangePasswordVerdict::Acceptable`].
    /// Spec: docs/53 §5.7; RFC 3244 §2.
    #[must_use]
    pub const fn result_code(self) -> Option<NonZeroResultCode> {
        match self {
            ChangePasswordVerdict::Acceptable => None,
            ChangePasswordVerdict::Malformed => Some(NonZeroResultCode::Malformed),
            ChangePasswordVerdict::InitialFlagNeeded => Some(NonZeroResultCode::InitialFlagNeeded),
            ChangePasswordVerdict::SetNotSupported => Some(NonZeroResultCode::AccessDenied),
            ChangePasswordVerdict::PasswordRefused => Some(NonZeroResultCode::SoftError),
        }
    }

    /// Whether an error reply with `code` may be sealed for a context with
    /// this verdict (module documentation): the verdict's own code when it
    /// is not acceptable; HARDERROR, AUTHERROR or ACCESSDENIED when it is.
    /// Spec: docs/53 §5.5, §5.7; RFC 3244 §2.
    #[must_use]
    pub const fn permits_error(self, code: NonZeroResultCode) -> bool {
        match self.result_code() {
            Some(own) => own as u16 == code as u16,
            None => matches!(
                code,
                NonZeroResultCode::HardError
                    | NonZeroResultCode::AuthError
                    | NonZeroResultCode::AccessDenied
            ),
        }
    }
}

/// The answer of `open_change_password_request`: a one-time request
/// context id, the ticket's non-secret facts, and keyd's verdict. There is
/// no key field and no password field (docs/10 §12 I1, I7): the session key,
/// the subkey and the new password stay in keyd under `ctx_id`.
/// Spec: docs/53 §5.5 (`struct ChangePasswordContext { ctx_id, crealm,
/// cname, authtime, endtime, flags, verdict }`); RFC 4120 5.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePasswordContext {
    /// The one-time, caller-bound request-context token.
    pub ctx_id: ChangePasswordCtxId,
    /// Client realm from the ticket (equal to the authenticator's).
    pub crealm: Realm,
    /// Client name from the ticket (equal to the authenticator's).
    pub cname: PrincipalName,
    /// Time of initial authentication — for the PEP's hot list and
    /// `ticket_age` (docs/53 §5.6 step 4). Spec: RFC 4120 5.3.
    pub authtime: KerberosTime,
    /// Ticket expiration time. Spec: RFC 4120 5.3.
    pub endtime: KerberosTime,
    /// Ticket flags (never INVALID: such a ticket is refused).
    /// Spec: RFC 4120 2.2, 5.3.
    pub flags: TicketFlags,
    /// keyd's verdict (docs/53 §5.4).
    pub verdict: ChangePasswordVerdict,
}

/// A reply keyd sealed for one request context: the AP-REP (key usage 12,
/// under the ticket session key) and the KRB-PRIV (key usage 13, under the
/// Authenticator's subkey) whose user-data is the result data. The front
/// frames the two (RFC 3244 §2, reply message).
///
/// `Debug` prints only the encrypted parts' lengths (docs/53 §9: no message
/// octets in a log).
/// Spec: docs/53 §5.5 (`struct SealedReply { ap_rep, krb_priv }`); RFC 3244
/// §2; RFC 4120 5.5.2, 5.7.1, 7.5.1 items 12, 13.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedReply {
    /// The KRB_AP_REP. Spec: RFC 4120 5.5.2.
    pub ap_rep: ApRep,
    /// The KRB-PRIV carrying the result data. Spec: RFC 4120 5.7.1; RFC 3244
    /// §2.
    pub krb_priv: KrbPriv,
}

impl fmt::Debug for SealedReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedReply")
            .field("ap_rep_cipher_len", &self.ap_rep.enc_part.cipher.len())
            .field("krb_priv_cipher_len", &self.krb_priv.enc_part.cipher.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4120 7.1: "IPv4-mapped IPv6 addresses MUST be represented as
    /// addresses of type 2" — a mapped address is held as IPv4 (type 2, 4
    /// octets); any other IPv6 address keeps type 24 and 16 octets.
    #[test]
    fn ipv4_mapped_addresses_are_type_2() {
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..].copy_from_slice(&[192, 0, 2, 7]);
        let host = HostAddr::ipv6(mapped);
        assert_eq!(host, HostAddr::ipv4([192, 0, 2, 7]));
        assert_eq!(host.addr_type(), ADDRESS_TYPE_IPV4);
        assert_eq!(host.octets(), &[192, 0, 2, 7]);
        let v6 = HostAddr::ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        assert_eq!(v6.addr_type(), ADDRESS_TYPE_IPV6);
        assert_eq!(v6.octets().len(), 16);
        // The mapped form as type 24 never matches: it MUST be type 2.
        assert!(!host.is(&HostAddress {
            addr_type: ADDRESS_TYPE_IPV6,
            address: mapped.to_vec(),
        }));
        assert!(host.is(&HostAddress {
            addr_type: ADDRESS_TYPE_IPV4,
            address: vec![192, 0, 2, 7],
        }));
        assert!(!host.is(&HostAddress {
            addr_type: ADDRESS_TYPE_IPV4,
            address: vec![192, 0, 2, 8],
        }));
    }

    /// RFC 4120 7.1, 7.5.3: the address types and the two directional
    /// values (four octets, network byte order).
    #[test]
    fn address_constants_follow_rfc4120() {
        assert_eq!(
            (
                ADDRESS_TYPE_IPV4,
                ADDRESS_TYPE_DIRECTIONAL,
                ADDRESS_TYPE_IPV6
            ),
            (2, 3, 24)
        );
        assert_eq!(DIRECTIONAL_AP_REQ_SENDER, [0, 0, 0, 0]);
        assert_eq!(DIRECTIONAL_AP_REQ_RECIPIENT, [0, 0, 0, 1]);
    }

    /// docs/53 §5.7; RFC 3244 §2: each verdict's code, and the codes a
    /// caller may seal (module documentation).
    #[test]
    fn verdicts_map_to_their_result_codes() {
        use ChangePasswordVerdict as V;
        use NonZeroResultCode as C;
        assert_eq!(V::Acceptable.result_code(), None);
        assert_eq!(V::Malformed.result_code(), Some(C::Malformed));
        assert_eq!(
            V::InitialFlagNeeded.result_code(),
            Some(C::InitialFlagNeeded)
        );
        assert_eq!(V::SetNotSupported.result_code(), Some(C::AccessDenied));
        assert_eq!(V::PasswordRefused.result_code(), Some(C::SoftError));
        let all = [
            C::Malformed,
            C::HardError,
            C::AuthError,
            C::SoftError,
            C::AccessDenied,
            C::BadVersion,
            C::InitialFlagNeeded,
        ];
        for code in all {
            assert_eq!(
                V::Acceptable.permits_error(code),
                matches!(code, C::HardError | C::AuthError | C::AccessDenied),
                "{code:?}"
            );
            for verdict in [
                V::Malformed,
                V::InitialFlagNeeded,
                V::SetNotSupported,
                V::PasswordRefused,
            ] {
                assert_eq!(
                    verdict.permits_error(code),
                    verdict.result_code() == Some(code),
                    "{verdict:?} {code:?}"
                );
            }
            // BAD_VERSION is never sealed: a context exists only for a
            // request keyd opened.
            if code == C::BadVersion {
                assert!(!V::Acceptable.permits_error(code));
            }
        }
    }
}
