//! The dird-kpasswd channel's codec: identity, layout, bounds, closed
//! tables, field domains, the refusal table, and the "no cleartext
//! password" value rules.
//!
//! Sources (each test names its own): docs/50 §3.3 (framing, envelope,
//! exact version, closed kinds, one encoding per value, no trailing octet,
//! bound before allocation) and the channel-magic registry (A-64); docs/53
//! §4.3, §5.1, §5.5, §5.7, §5.9, R53-4; RFC 3244 §2; RFC 4120 §5.7.1, §5.10,
//! §7.1; X.690 8.1.2.2; A-59. Every frame is built by hand or by this crate
//! from hand-made values (tests/common).

mod common;

use common::*;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipc::{decode_body, decode_frame, decode_reply, Direction, FrameStatus, Refused, Reply};
use ipc_kpasswd::{
    channel::{codes, reply_kind, request_kind, ENC_KRB_PRIV_PART_IDENTIFIER},
    decode_request, ApRepOctets, ApReqOctets, ChangePasswordRequest, FrontZone, KpasswdReply,
    KpasswdRequest, KrbPrivOctets, ObservedAddress, Rejection, SealedReply, UnsealedCode,
    KPASSWD_CHANNEL, KPASSWD_MAGIC, KPASSWD_VERSION, MAX_REPLY_BODY, MAX_REQUEST_BODY,
    MAX_REQUEST_FIELD, MAX_REQUEST_MESSAGES, MAX_SEALED_MESSAGES, REPLY_LIMIT,
};

fn reply_of(body: &[u8]) -> Result<Reply<KpasswdReply>, ipc::Error> {
    decode_reply::<KpasswdReply>(KPASSWD_CHANNEL, body)
}

/// docs/50 the channel-magic registry (A-64: `dird-kpasswd.sock |
/// ipc-kpasswd | 0x4B50 ("KP") | 1`); docs/53 §5.9 (request ≤ 64 KiB +
/// header, reply ≤ 8 KiB); RFC 3244 §2 (the 16-bit message length and the
/// 6-octet header); A-59 (no kind is 0xFF).
#[test]
fn the_channel_identity_and_bounds() {
    assert_eq!(KPASSWD_MAGIC, 0x4B50);
    assert_eq!(&KPASSWD_MAGIC.to_be_bytes(), b"KP");
    assert_eq!(KPASSWD_VERSION, 1);
    assert_eq!(MAX_REQUEST_MESSAGES, 65_535 - 6);
    assert_eq!(MAX_REQUEST_FIELD, MAX_REQUEST_MESSAGES - 1);
    assert_eq!(MAX_REQUEST_BODY, 64 * 1024 + 64);
    assert_eq!(MAX_REPLY_BODY, 8 * 1024);
    for kind in request_kind::ALL.iter().chain(reply_kind::ALL) {
        assert_ne!(*kind, ipc::REFUSED_KIND);
    }
}

/// RFC 4120 §5.10 (AP-REQ 14, AP-REP 15, KRB-PRIV 21, EncKrbPrivPart 28);
/// X.690 8.1.2.2 (one identifier octet: class `01`, constructed `1`, the tag
/// number) — the channel's constants are what the derivation gives.
#[test]
fn the_identifier_octets_follow_x690() {
    assert_eq!(ipc_kpasswd::channel::AP_REQ_IDENTIFIER, AP_REQ);
    assert_eq!(ipc_kpasswd::channel::AP_REP_IDENTIFIER, AP_REP);
    assert_eq!(ipc_kpasswd::channel::KRB_PRIV_IDENTIFIER, KRB_PRIV);
    assert_eq!(ENC_KRB_PRIV_PART_IDENTIFIER, ENC_KRB_PRIV_PART);
    for (identifier, tag) in [(AP_REQ, 14u8), (AP_REP, 15), (KRB_PRIV, 21)] {
        assert_eq!(identifier >> 6, 0b01, "application class");
        assert_eq!(identifier & 0b0010_0000, 0b0010_0000, "constructed");
        assert_eq!(identifier & 0b0001_1111, tag, "tag number");
    }
}

/// docs/50 §3.3 (`body := magic:u16 ‖ version:u8 ‖ kind:u8 ‖ payload`;
/// `bytes<max>` = u32 length + octets; enum = u8); docs/53 §4.3 (ap_req,
/// krb_priv, the peer's address, the local address): the exact octets of a
/// `ChangePassword` frame, and its round trip.
#[test]
fn a_change_password_frame_has_the_documented_layout() {
    let request = request();
    let frame = ipc::encode_frame(
        KPASSWD_CHANNEL,
        Direction::Request,
        &KpasswdRequest::ChangePassword(request.clone()),
    )
    .unwrap();
    let bytes = frame.as_bytes();
    let body_len = 4 + (4 + 40) + (4 + 24) + (1 + 4) + (1 + 16);
    assert_eq!(&bytes[..4], &(body_len as u32).to_be_bytes());
    let body = frame.body();
    assert_eq!(
        &body[..4],
        &[0x4B, 0x50, 0x01, request_kind::CHANGE_PASSWORD]
    );
    assert_eq!(&body[4..8], &40u32.to_be_bytes());
    assert_eq!(&body[8..48], request.ap_req().as_bytes());
    assert_eq!(&body[48..52], &24u32.to_be_bytes());
    assert_eq!(&body[52..76], request.krb_priv().as_bytes());
    assert_eq!(&body[76..81], &[codes::FAMILY_IPV4, 192, 0, 2, 10]);
    assert_eq!(body[81], codes::FAMILY_IPV6);
    assert_eq!(
        &body[82..98],
        &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x464).octets()
    );
    assert_eq!(body.len(), body_len);
    assert_eq!(
        decode_request(body),
        Ok(KpasswdRequest::ChangePassword(request))
    );
    assert!(ipc::round_trip_is_canonical::<KpasswdRequest>(
        KPASSWD_CHANNEL,
        Direction::Request,
        body
    )
    .unwrap());
}

/// docs/50 §3.3 (round trip `encode(decode(b)) == b`; replies decoded with
/// the same strictness); docs/53 §5.5–§5.7 (`Sealed`, `Unsealed`).
#[test]
fn every_message_round_trips() {
    let ping = request_body(&KpasswdRequest::Ping);
    assert_eq!(ping, vec![0x4B, 0x50, 0x01, request_kind::PING]);
    assert_eq!(decode_request(&ping), Ok(KpasswdRequest::Ping));
    for reply in [
        KpasswdReply::Pong {
            zone: FrontZone::Internal,
        },
        KpasswdReply::Sealed(sealed()),
        KpasswdReply::Unsealed(UnsealedCode::HardError),
        KpasswdReply::Unsealed(UnsealedCode::AuthError),
    ] {
        let body = reply_body(&reply);
        assert_eq!(reply_of(&body), Ok(Reply::Message(reply)));
        assert!(
            ipc::reply_round_trip_is_canonical::<KpasswdReply>(KPASSWD_CHANNEL, &body).unwrap()
        );
    }
    assert_eq!(
        reply_body(&KpasswdReply::Pong {
            zone: FrontZone::Internal
        }),
        vec![0x4B, 0x50, 0x01, reply_kind::PONG, codes::ZONE_INTERNAL]
    );
    assert_eq!(
        reply_body(&KpasswdReply::Unsealed(UnsealedCode::AuthError)),
        vec![0x4B, 0x50, 0x01, reply_kind::UNSEALED, 3]
    );
}

/// docs/50 §3.3 (wrong magic ⇒ close; version ≠ current ⇒
/// `Refused{VersionMismatch}` + close; unknown kind ⇒ close; trailing ⇒
/// `Malformed` + close); A-59 (0xFF is never a request kind).
#[test]
fn the_refusal_table() {
    let ping = request_body(&KpasswdRequest::Ping);
    let mut magic = ping.clone();
    magic[0] = 0x44;
    assert_eq!(decode_request(&magic), Err(Rejection::Close));
    let mut version = ping.clone();
    version[2] = 2;
    assert_eq!(
        decode_request(&version),
        Err(Rejection::Refuse(Refused::VersionMismatch))
    );
    for kind in [0x00, 0x03, 0x81, 0x82, ipc::REFUSED_KIND] {
        let mut unknown = ping.clone();
        unknown[3] = kind;
        assert_eq!(decode_request(&unknown), Err(Rejection::Close), "{kind}");
    }
    let mut trailing = ping.clone();
    trailing.push(0);
    assert_eq!(
        decode_request(&trailing),
        Err(Rejection::Refuse(Refused::Malformed))
    );
    let change = request_body(&KpasswdRequest::ChangePassword(request()));
    assert_eq!(
        decode_request(&change[..change.len() - 1]),
        Err(Rejection::Refuse(Refused::Malformed))
    );
    assert_eq!(decode_request(&change[..3]), Err(Rejection::Close));
}

/// RFC 3244 §2 (the KRB-PRIV's user-data is encrypted under the subkey);
/// RFC 4120 §5.7.1 (KRB-PRIV `[APPLICATION 21]` carries only `enc-part`;
/// the cleartext EncKrbPrivPart is `[APPLICATION 28]`); docs/53 R53-4 ("only
/// keyd decrypts the new password"): a KRB-PRIV field accepts only the
/// KRB-PRIV identifier — never the cleartext EncKrbPrivPart, never a bare
/// ChangePasswdData (a SEQUENCE), never raw password octets.
#[test]
fn no_cleartext_password_form_is_a_krb_priv() {
    assert!(KrbPrivOctets::new(&octets(KRB_PRIV, 16, 0)).is_some());
    for refused in [
        octets(ENC_KRB_PRIV_PART, 16, 0),
        octets(SEQUENCE, 16, 0),
        b"correct horse battery staple".to_vec(),
        octets(AP_REQ, 16, 0),
        Vec::new(),
    ] {
        assert!(KrbPrivOctets::new(&refused).is_none(), "{refused:?}");
    }
    assert!(ApReqOctets::new(&octets(KRB_PRIV, 16, 0)).is_none());
    assert!(ApReqOctets::new(&[]).is_none());
    assert!(ApRepOctets::new(&octets(AP_REQ, 16, 0)).is_none());
}

/// docs/50 §3.3 (a field outside its domain is refused — `UnknownCode` for
/// the identifier, `LengthOverBound` for an empty message) — and the same
/// on the wire: a `ChangePassword` whose KRB-PRIV is an EncKrbPrivPart is
/// `Refused{Malformed}` before anything reaches dird.
#[test]
fn a_wrong_identifier_on_the_wire_is_refused() {
    let good = request_body(&KpasswdRequest::ChangePassword(request()));
    // The KRB-PRIV starts at body offset 52 (see the layout test).
    let mut cleartext = good.clone();
    cleartext[52] = ENC_KRB_PRIV_PART;
    assert_eq!(
        decode_body::<KpasswdRequest>(KPASSWD_CHANNEL, Direction::Request, &cleartext),
        Err(ipc::Error::UnknownCode)
    );
    assert_eq!(
        decode_request(&cleartext),
        Err(Rejection::Refuse(Refused::Malformed))
    );
    let mut ap_req = good.clone();
    ap_req[8] = KRB_PRIV;
    assert_eq!(
        decode_body::<KpasswdRequest>(KPASSWD_CHANNEL, Direction::Request, &ap_req),
        Err(ipc::Error::UnknownCode)
    );
    // An empty AP-REQ: length 0, then the rest shifted.
    let mut empty = vec![0x4B, 0x50, 0x01, request_kind::CHANGE_PASSWORD];
    empty.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        decode_body::<KpasswdRequest>(KPASSWD_CHANNEL, Direction::Request, &empty),
        Err(ipc::Error::LengthOverBound)
    );
}

/// RFC 3244 §2 (one message ≤ 65,535 octets with its 6-octet header);
/// docs/53 §5.9 ("both fields together ≤ one message"): the two messages
/// together at most 65,529 octets — accepted at the bound, refused above it,
/// at construction and on the wire; the largest request fits the request
/// body bound.
#[test]
fn a_request_carries_at_most_one_rfc3244_message() {
    let max = MAX_REQUEST_MESSAGES as usize;
    let fits = ChangePasswordRequest::new(
        ApReqOctets::new(&octets(AP_REQ, max - 1, 1)).unwrap(),
        KrbPrivOctets::new(&octets(KRB_PRIV, 1, 2)).unwrap(),
        peer_v4(),
        local_v6(),
    )
    .expect("at the bound");
    let body = request_body(&KpasswdRequest::ChangePassword(fits.clone()));
    assert!(body.len() <= MAX_REQUEST_BODY as usize);
    assert_eq!(
        decode_request(&body),
        Ok(KpasswdRequest::ChangePassword(fits))
    );
    assert!(ChangePasswordRequest::new(
        ApReqOctets::new(&octets(AP_REQ, max - 1, 1)).unwrap(),
        KrbPrivOctets::new(&octets(KRB_PRIV, 2, 2)).unwrap(),
        peer_v4(),
        local_v6(),
    )
    .is_none());
    assert!(ApReqOctets::new(&octets(AP_REQ, max, 1)).is_none());
    // On the wire: the same two fields, one octet over the joint bound.
    let mut over = vec![0x4B, 0x50, 0x01, request_kind::CHANGE_PASSWORD];
    over.extend_from_slice(&((max - 1) as u32).to_be_bytes());
    over.extend_from_slice(&octets(AP_REQ, max - 1, 1));
    over.extend_from_slice(&2u32.to_be_bytes());
    over.extend_from_slice(&octets(KRB_PRIV, 2, 2));
    over.extend_from_slice(&[codes::FAMILY_IPV4, 192, 0, 2, 10]);
    over.extend_from_slice(&[codes::FAMILY_IPV4, 192, 0, 2, 11]);
    assert_eq!(
        decode_body::<KpasswdRequest>(KPASSWD_CHANNEL, Direction::Request, &over),
        Err(ipc::Error::LengthOverBound)
    );
}

/// RFC 4120 §7.1 ("IPv4-mapped IPv6 addresses MUST be represented as
/// addresses of type 2"); docs/50 §3.3 (one encoding per value): a mapped
/// address is held as IPv4, and refused in the IPv6 form on the wire.
#[test]
fn an_ipv4_mapped_address_has_one_spelling() {
    let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped());
    assert_eq!(ObservedAddress::new(mapped), peer_v4());
    let good = request_body(&KpasswdRequest::ChangePassword(request()));
    let mut wire = good[..76].to_vec();
    wire.push(codes::FAMILY_IPV6);
    wire.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped().octets());
    wire.extend_from_slice(&good[81..]);
    assert_eq!(
        decode_body::<KpasswdRequest>(KPASSWD_CHANNEL, Direction::Request, &wire),
        Err(ipc::Error::UnknownCode)
    );
    let mut family = good.clone();
    family[76] = 0x04;
    assert_eq!(
        decode_body::<KpasswdRequest>(KPASSWD_CHANNEL, Direction::Request, &family),
        Err(ipc::Error::UnknownCode)
    );
}

/// RFC 3244 §2 (codes 0–7; 0 "is not allowed in a KRB-ERROR message");
/// docs/53 §5.7 (the KRB-ERROR rows dird decides: HARDERROR, AUTHERROR):
/// `Unsealed` admits exactly 2 and 3 — success, the codes keyd seals
/// (4, 5, 7), the front's own (1, 6) and anything else are refused.
#[test]
fn unsealed_admits_only_hard_and_auth_errors() {
    assert_eq!(UnsealedCode::HardError.value(), 2);
    assert_eq!(UnsealedCode::AuthError.value(), 3);
    for code in 0u8..=255 {
        let mut body = vec![0x4B, 0x50, 0x01, reply_kind::UNSEALED, code];
        let decoded = reply_of(&body);
        match code {
            2 => assert_eq!(
                decoded,
                Ok(Reply::Message(KpasswdReply::Unsealed(
                    UnsealedCode::HardError
                )))
            ),
            3 => assert_eq!(
                decoded,
                Ok(Reply::Message(KpasswdReply::Unsealed(
                    UnsealedCode::AuthError
                )))
            ),
            _ => assert_eq!(decoded, Err(ipc::Error::UnknownCode), "{code}"),
        }
        body.push(0);
        assert!(reply_of(&body).is_err());
    }
}

/// docs/53 §5.9 ("reply ≤ 8 KiB"); docs/50 §3.3 (bound before allocation):
/// a sealed reply's two messages together at most `MAX_SEALED_MESSAGES`; a
/// reply frame announcing more than the reply bound is refused at its
/// length prefix.
#[test]
fn the_reply_bound() {
    let half = (MAX_SEALED_MESSAGES / 2) as usize;
    assert!(SealedReply::new(
        ApRepOctets::new(&octets(AP_REP, half, 1)).unwrap(),
        KrbPrivOctets::new(&octets(KRB_PRIV, half, 2)).unwrap(),
    )
    .is_some());
    assert!(SealedReply::new(
        ApRepOctets::new(&octets(AP_REP, half + 1, 1)).unwrap(),
        KrbPrivOctets::new(&octets(KRB_PRIV, half, 2)).unwrap(),
    )
    .is_none());
    let mut prefix = (MAX_REPLY_BODY + 1).to_be_bytes().to_vec();
    prefix.extend_from_slice(&[0; 8]);
    assert_eq!(
        decode_frame(&prefix, REPLY_LIMIT)
            .map(|status| matches!(status, FrameStatus::NeedMore { .. })),
        Err(ipc::Error::FrameTooLarge)
    );
}

/// docs/53 §9 ("never … the KRB-PRIV / AP-REQ octets"); docs/50 §8.2: the
/// `Debug` output of a request and a reply shows lengths, not octets.
#[test]
fn debug_output_carries_no_message_octets() {
    let request = format!("{:?}", KpasswdRequest::ChangePassword(request()));
    let reply = format!("{:?}", KpasswdReply::Sealed(sealed()));
    for text in [&request, &reply] {
        for filler in ["161", "178", "195", "212", "0xa1", "0xb2", "a1", "b2"] {
            assert!(!text.contains(&format!("[{filler}")), "{text}");
            assert!(!text.contains(&format!(", {filler},")), "{text}");
        }
    }
    assert!(request.contains("len: 40"), "{request}");
    assert!(request.contains("len: 24"), "{request}");
}
