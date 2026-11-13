//! Tier 1 (docs/50 §9: "codecs: round-trip for every op, canonicity
//! (`encode(decode(b)) == b`), every bound, every unknown kind, trailing
//! octet, wrong version"): the directory-view channel's message set.
//!
//! Sources: docs/50 §3.3 (framing, primitives, refusal rules), §3.4 (the
//! dird-kdc rows), §9; A-59 (`REFUSED_KIND`); [MS-DTYP] 2.4.2.2 (SID
//! packet); RFC 4120 5.2.1 (KerberosString), 5.2.3 (KerberosTime). Every
//! value is hand-made (tests/common).

mod common;

use common::*;
use dtyp::{Sid, SECURITY_NT_AUTHORITY};
use ipc::{
    decode_body, decode_reply, encode_frame, encode_refused, reply_round_trip_is_canonical,
    round_trip_is_canonical, Direction, Error, Refused, Reply, REFUSED_KIND,
};
use ipc_directory::channel::{
    reply_kind, request_kind, MAX_GROUPS, MAX_REPLY_BODY, MAX_REQUEST_BODY,
};
use ipc_directory::typed::{ConversionError, Query, Request};
use ipc_directory::wire::{DirectoryReply, DirectoryRequest, WireClient};
use ipc_directory::{DIRECTORY_CHANNEL, DIRECTORY_MAGIC, DIRECTORY_VERSION};
use kdc::{AccountKind, AccountState, ArmorPolicy, ClientAccount};
use keyd_types::{KeyHandle, KeyPurpose, PrincipalId};
use krb_proto::{EtypeInfo2Entry, KerberosString};
use pdp::Tier;
use std::collections::BTreeSet;

/// docs/50 §3.3 (round trip), §3.4: every request kind — typed → wire →
/// body → wire → typed — is the identity, and the body is canonical.
#[test]
fn every_request_round_trips_canonically() {
    let mut kinds = BTreeSet::new();
    for request in requests() {
        let body = request_body(&request);
        assert_eq!(body[..2], DIRECTORY_MAGIC.to_be_bytes());
        assert_eq!(body[2], DIRECTORY_VERSION);
        kinds.insert(body[3]);
        assert_eq!(decode_request(&body).unwrap(), request);
        assert_eq!(
            round_trip_is_canonical::<DirectoryRequest>(
                DIRECTORY_CHANNEL,
                Direction::Request,
                &body
            ),
            Ok(true)
        );
    }
    assert_eq!(kinds.into_iter().collect::<Vec<_>>(), request_kind::ALL);
}

/// docs/50 §3.3, §3.4; A-59: every reply kind and every closed code round
/// trips canonically, and the typed readers give back the values.
#[test]
fn every_reply_round_trips_canonically() {
    let mut kinds = BTreeSet::new();
    for reply in replies() {
        let body = reply_body(&reply);
        kinds.insert(body[3]);
        assert_eq!(
            decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, &body).unwrap(),
            Reply::Message(reply.clone())
        );
        assert_eq!(
            reply_round_trip_is_canonical::<DirectoryReply>(DIRECTORY_CHANNEL, &body),
            Ok(true)
        );
    }
    assert_eq!(kinds.into_iter().collect::<Vec<_>>(), reply_kind::ALL);

    let client = DirectoryReply::from_client(&Ok(Some(client_account())));
    assert_eq!(client.into_client(), Ok(Ok(Some(client_account()))));
    let computer = DirectoryReply::from_client(&Ok(Some(computer_account())));
    assert_eq!(computer.into_client(), Ok(Ok(Some(computer_account()))));
    let service = DirectoryReply::from_service(&Ok(Some(service_account())));
    assert_eq!(service.into_service(), Ok(Ok(Some(service_account()))));
    assert_eq!(
        DirectoryReply::from_domain(&domain()).into_domain(),
        Ok(domain())
    );
    let groups: BTreeSet<Sid> = [sid(513), sid(1031)].into_iter().collect();
    assert_eq!(
        DirectoryReply::from_groups(&Ok(groups.clone())).into_groups(),
        Ok(Ok(groups))
    );
}

/// docs/50 §3.4: a reply is read only as the answer to its own request.
#[test]
fn a_reply_answers_only_its_own_request() {
    assert_eq!(
        DirectoryReply::Pong.into_client(),
        Err(ConversionError::UnexpectedReply)
    );
    assert_eq!(
        DirectoryReply::from_client(&Ok(None)).into_service(),
        Err(ConversionError::UnexpectedReply)
    );
    assert_eq!(
        DirectoryReply::Tier(Tier::Tier0).into_groups(),
        Err(ConversionError::UnexpectedReply)
    );
    assert_eq!(
        DirectoryReply::from_groups(&Ok(BTreeSet::new())).into_tier(),
        Err(ConversionError::UnexpectedReply)
    );
    assert_eq!(
        DirectoryReply::ViewEnded.into_domain(),
        Err(ConversionError::UnexpectedReply)
    );
    assert_eq!(
        DirectoryReply::Pong.into_view_begun(),
        Err(ConversionError::UnexpectedReply)
    );
}

/// docs/50 §3.3: wrong magic and unknown kind ⇒ close (no refusal); wrong
/// version ⇒ `Refused{VersionMismatch}`; a trailing octet or truncation ⇒
/// `Malformed`; `REFUSED_KIND` is no request (A-59) but is the shared
/// refusal among replies.
#[test]
fn envelope_and_payload_errors_map_to_the_refusal_table() {
    let body = request_body(&Request::Query {
        view: 1,
        query: Query::ExpandGroups { sid: sid(1010) },
    });
    let decode =
        |b: &[u8]| decode_body::<DirectoryRequest>(DIRECTORY_CHANNEL, Direction::Request, b);

    let mut wrong_magic = body.clone();
    wrong_magic[0] ^= 0x01;
    assert_eq!(decode(&wrong_magic), Err(Error::WrongMagic));
    assert_eq!(Error::WrongMagic.refusal(), None);

    let mut wrong_version = body.clone();
    wrong_version[2] = DIRECTORY_VERSION + 1;
    assert_eq!(decode(&wrong_version), Err(Error::VersionMismatch));
    assert_eq!(
        Error::VersionMismatch.refusal(),
        Some(Refused::VersionMismatch)
    );

    for kind in [0x00, 0x09, 0x81, REFUSED_KIND] {
        let mut unknown = body.clone();
        unknown[3] = kind;
        assert_eq!(decode(&unknown), Err(Error::UnknownKind), "kind {kind:#x}");
    }

    let mut trailing = body.clone();
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(Error::TrailingBytes));
    assert_eq!(Error::TrailingBytes.refusal(), Some(Refused::Malformed));
    assert_eq!(decode(&body[..body.len() - 1]), Err(Error::Truncated));

    let refusal = encode_refused(DIRECTORY_CHANNEL, Refused::Busy).unwrap();
    assert_eq!(
        decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, refusal.body()),
        Ok(Reply::Refused(Refused::Busy))
    );
}

/// [MS-DTYP] 2.4.2.2; RFC 4120 5.2.1, 5.2.3; docs/50 §3.3 ("Kerberos values
/// … decoded in krb-proto"; "a single encoding per value"): content that
/// the strict decoders refuse is refused, and a group set out of ascending
/// order (or repeated) has no second encoding.
#[test]
fn typed_layer_refuses_what_the_strict_decoders_refuse() {
    let typed = |wire: DirectoryRequest| Request::from_wire(&wire);
    // A SID with revision 2.
    let mut bad_sid = sid(1010).encode();
    bad_sid[0] = 2;
    assert_eq!(
        typed(DirectoryRequest::ExpandGroups {
            view: 1,
            sid: bad_sid,
        }),
        Err(ConversionError::Sid)
    );
    // A SID with an octet beyond its packet.
    let mut long_sid = sid(1010).encode();
    long_sid.push(0);
    assert_eq!(
        typed(DirectoryRequest::ExpandGroups {
            view: 1,
            sid: long_sid,
        }),
        Err(ConversionError::Sid)
    );
    // Groups descending, then repeated.
    for groups in [
        vec![sid(1031).encode(), sid(1030).encode()],
        vec![sid(1030).encode(), sid(1030).encode()],
    ] {
        assert_eq!(
            typed(DirectoryRequest::TierOf {
                view: 1,
                sid: sid(1010).encode(),
                groups,
            }),
            Err(ConversionError::GroupOrder)
        );
    }
    // A realm with a non-IA5 octet; a name that is not DER.
    let name_der = ipc::DerBlob::new(name(1, &["alice"]).encode().unwrap());
    assert_eq!(
        typed(DirectoryRequest::Client {
            view: 1,
            realm: vec![b'E', 0x80],
            name: name_der.clone(),
        }),
        Err(ConversionError::KerberosString)
    );
    let mut bad_der = name_der.as_der().to_vec();
    bad_der[0] = 0x31;
    assert_eq!(
        typed(DirectoryRequest::Service {
            view: 1,
            realm: realm().as_bytes().to_vec(),
            name: ipc::DerBlob::new(bad_der),
        }),
        Err(ConversionError::PrincipalName)
    );
    // A time with month 13 in a record.
    let mut wire = WireClient::from_account(&client_account());
    if let Some(time) = wire.state.expires.as_mut() {
        time.month = 13;
    }
    assert_eq!(wire.to_account(), Err(ConversionError::KerberosTime));
    // A salt with a non-IA5 octet.
    let mut wire = WireClient::from_account(&client_account());
    wire.etype_info[0].salt = Some(vec![0xFF]);
    assert_eq!(wire.to_account(), Err(ConversionError::KerberosString));
    // An empty naming-context label.
    let mut domain_reply = DirectoryReply::from_domain(&domain());
    if let DirectoryReply::Domain { naming_context, .. } = &mut domain_reply {
        naming_context[0].clear();
    }
    assert_eq!(domain_reply.into_domain(), Err(ConversionError::Label));
}

/// docs/50 §3.3 ("bound before allocation"; `seq<T,max>`), §3.4;
/// docs/questions/Q-270 item 4: the largest legitimate `TierOf` request
/// (MAX_GROUPS SIDs of 15 sub-authorities) and the largest client record fit
/// their body bounds; one group more is refused when encoding and decoding;
/// a declared body over the bound is refused at the prefix.
#[test]
fn bounds_hold_at_their_edges() {
    let big_sid = |n: u32| {
        let mut sub = [7u32; 15];
        sub[14] = n;
        Sid::new(SECURITY_NT_AUTHORITY, &sub).unwrap()
    };
    let groups: BTreeSet<Sid> = (0..MAX_GROUPS).map(big_sid).collect();
    let largest = Request::Query {
        view: u64::MAX,
        query: Query::TierOf {
            sid: big_sid(u32::MAX),
            groups: groups.clone(),
        },
    };
    let body = request_body(&largest);
    assert!(body.len() <= MAX_REQUEST_BODY as usize);
    assert_eq!(decode_request(&body).unwrap(), largest);

    let account = ClientAccount {
        key: KeyHandle::new(
            PrincipalId::from_bytes([1; 16]),
            KeyPurpose::PrincipalLongterm,
        ),
        sid: big_sid(u32::MAX),
        groups: groups.clone(),
        tier: Tier::Tier0,
        state: AccountState {
            enabled: true,
            locked: true,
            expires: Some(kt(9999, 12, 31, 23, 59, 59)),
            revoked_before: Some(kt(1970, 1, 1, 0, 0, 0)),
        },
        etype_info: (17..21)
            .map(|etype| EtypeInfo2Entry {
                etype,
                salt: Some(KerberosString::new(&"S".repeat(4096)).unwrap()),
                s2kparams: Some(vec![0xFF; 4]),
            })
            .collect(),
        kind: AccountKind::Computer,
        armor_policy: ArmorPolicy::BootstrapAllowed,
    };
    let reply = DirectoryReply::from_client(&Ok(Some(account.clone())));
    let body = reply_body(&reply);
    assert!(body.len() <= MAX_REPLY_BODY as usize);
    let decoded = decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, &body).unwrap();
    let Reply::Message(decoded) = decoded else {
        panic!("a message")
    };
    assert_eq!(decoded.into_client(), Ok(Ok(Some(account))));

    // One group more: not encodable, and not decodable.
    let mut too_many = groups.clone();
    too_many.insert(big_sid(MAX_GROUPS));
    let wire = Request::Query {
        view: 1,
        query: Query::TierOf {
            sid: sid(1),
            groups: too_many,
        },
    }
    .to_wire()
    .unwrap();
    assert_eq!(
        encode_frame(DIRECTORY_CHANNEL, Direction::Request, &wire).err(),
        Some(Error::CountOverBound)
    );
    let mut forged = request_body(&Request::Query {
        view: 1,
        query: Query::TierOf {
            sid: sid(1),
            groups: BTreeSet::new(),
        },
    });
    let count_at = forged.len() - 4;
    forged[count_at..].copy_from_slice(&(MAX_GROUPS + 1).to_be_bytes());
    assert_eq!(
        decode_body::<DirectoryRequest>(DIRECTORY_CHANNEL, Direction::Request, &forged),
        Err(Error::CountOverBound)
    );

    // A declared length over the request bound, refused at the prefix.
    let mut prefix = (MAX_REQUEST_BODY + 1).to_be_bytes().to_vec();
    prefix.extend_from_slice(&[0; 8]);
    assert_eq!(
        ipc::decode_frame(&prefix, DIRECTORY_CHANNEL.limit(Direction::Request)).err(),
        Some(Error::FrameTooLarge)
    );
}

/// docs/50 §3.3 ("a single encoding per value"): every single-octet change
/// of every sample body either is refused (ipc or typed layer) or decodes to
/// a value that re-encodes to exactly the changed body.
#[test]
fn mutation_sweep_finds_no_second_encoding() {
    for request in requests() {
        let body = request_body(&request);
        for at in 0..body.len() {
            for flip in [0x01u8, 0x80, 0xFF] {
                let mut changed = body.clone();
                changed[at] ^= flip;
                if let Ok(typed) = decode_request(&changed) {
                    assert_eq!(request_body(&typed), changed, "request {request:?} at {at}");
                }
            }
        }
    }
    for reply in replies() {
        let body = reply_body(&reply);
        for at in 0..body.len() {
            for flip in [0x01u8, 0x80, 0xFF] {
                let mut changed = body.clone();
                changed[at] ^= flip;
                if let Ok(Reply::Message(decoded)) =
                    decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, &changed)
                {
                    assert_eq!(reply_body(&decoded), changed, "reply at {at}");
                    // The typed readers must accept or refuse, never panic.
                    let _ = decoded.clone().into_client();
                    let _ = decoded.clone().into_service();
                    let _ = decoded.clone().into_groups();
                    let _ = decoded.clone().into_domain();
                }
            }
        }
    }
}
