//! Tier 1 (docs/50 §9: "codecs: round-trip for every op, canonicity
//! (`encode(decode(b)) == b`), every bound, every unknown kind, trailing
//! octet, wrong version"): the directory-view channel's message set.
//!
//! Sources: docs/50 §3.3 (framing, primitives, refusal rules), §3.4 (the
//! dird-kdc rows), §9; A-59 (`REFUSED_KIND`); [MS-DTYP] 2.4.2.2 (SID
//! packet); RFC 4120 5.2.1 (KerberosString), 5.2.2 (PrincipalName), 5.2.3
//! (KerberosTime); docs/59 §7.1, §7.5 (the attested name resolution on
//! `Client` / `Service` replies, task PN10); ITU-T X.690 (02/2021) §8.1.3,
//! §10.1 (DER lengths, for the resolution-name bound). Every value is
//! hand-made (tests/common).

mod common;

use common::*;
use dtyp::{Sid, SECURITY_NT_AUTHORITY};
use ipc::{
    decode_body, decode_reply, encode_frame, encode_refused, reply_round_trip_is_canonical,
    round_trip_is_canonical, Direction, Error, Refused, Reply, REFUSED_KIND,
};
use ipc_directory::channel::{
    reply_kind, request_kind, MAX_GROUPS, MAX_REPLY_BODY, MAX_REQUEST_BODY, MAX_RESOLUTION_NAME,
    MAX_RESOLUTION_REALM,
};
use ipc_directory::typed::{ConversionError, Query, Request};
use ipc_directory::wire::{DirectoryReply, DirectoryRequest, WireClient, WireNameResolution};
use ipc_directory::{DIRECTORY_CHANNEL, DIRECTORY_MAGIC, DIRECTORY_VERSION};
use kdc::{AccountKind, AccountState, ArmorPolicy, ClientAccount};
use keyd_types::sealed_store::MAX_NAME_OCTETS;
use keyd_types::{
    AttestedNameResolution, KeyHandle, KeyPurpose, NameResolution, NameResolutionFields,
    PrincipalId, NAME_RESOLUTION_TAG_LEN,
};
use krb_proto::limits::MAX_NAME_COMPONENTS;
use krb_proto::{EtypeInfo2Entry, KerberosString, PrincipalName};
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

    // Records compare through their wire form (tests/common), the
    // resolution's fields and tag included (task PN10).
    let client = DirectoryReply::from_client(&Ok(Some(client_account())));
    assert_eq!(
        client.into_client().map(|answer| client_wire(&answer)),
        Ok(client_wire(&Ok(Some(client_account()))))
    );
    let computer = DirectoryReply::from_client(&Ok(Some(computer_account())));
    assert_eq!(
        computer.into_client().map(|answer| client_wire(&answer)),
        Ok(client_wire(&Ok(Some(computer_account()))))
    );
    let service = DirectoryReply::from_service(&Ok(Some(service_account())));
    assert_eq!(
        service.into_service().map(|answer| service_wire(&answer)),
        Ok(service_wire(&Ok(Some(service_account()))))
    );
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
        DirectoryReply::Pong.into_client().err(),
        Some(ConversionError::UnexpectedReply)
    );
    assert_eq!(
        DirectoryReply::from_client(&Ok(None)).into_service().err(),
        Some(ConversionError::UnexpectedReply)
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
    let mut wire = WireClient::from_account(&client_account()).unwrap();
    if let Some(time) = wire.state.expires.as_mut() {
        time.month = 13;
    }
    assert_eq!(wire.to_account().err(), Some(ConversionError::KerberosTime));
    // A salt with a non-IA5 octet.
    let mut wire = WireClient::from_account(&client_account()).unwrap();
    wire.etype_info[0].salt = Some(vec![0xFF]);
    assert_eq!(
        wire.to_account().err(),
        Some(ConversionError::KerberosString)
    );
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

    let key = KeyHandle::new(
        PrincipalId::from_bytes([1; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    let account = ClientAccount {
        key,
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
        // Task PN10: the largest resolution — two realms and two names at
        // their bounds (keyd-types; ipc-directory MAX_RESOLUTION_*).
        resolution: largest_resolution(key),
    };
    let reply = DirectoryReply::from_client(&Ok(Some(account.clone())));
    let body = reply_body(&reply);
    assert!(body.len() <= MAX_REPLY_BODY as usize);
    let decoded = decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, &body).unwrap();
    let Reply::Message(decoded) = decoded else {
        panic!("a message")
    };
    assert_eq!(
        decoded.into_client().map(|answer| client_wire(&answer)),
        Ok(client_wire(&Ok(Some(account))))
    );

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

/// The largest name a resolution holds: `MAX_NAME_COMPONENTS` components of
/// `MAX_NAME_OCTETS` octets, under the name-type whose Int32 takes four
/// contents octets (RFC 4120 §5.2.2, §5.2.4; X.690 §8.3.2; keyd-types'
/// bounds).
fn largest_name() -> PrincipalName {
    PrincipalName {
        name_type: i32::MIN,
        name_string: (0..MAX_NAME_COMPONENTS)
            .map(|_| KerberosString::new(&"n".repeat(MAX_NAME_OCTETS)).unwrap())
            .collect(),
    }
}

/// The largest resolution a record can carry (docs/59 §7.1 bounds): both
/// realms and both names at their bounds, every other field at its widest.
fn largest_resolution(key: KeyHandle) -> AttestedNameResolution {
    let realm = KerberosString::new(&"R".repeat(MAX_NAME_OCTETS)).unwrap();
    let resolution = NameResolution::new(NameResolutionFields {
        realm_as_sent: realm.clone(),
        name_as_sent: largest_name(),
        canonical_realm: realm,
        canonical_name: largest_name(),
        principal: key.principal,
        key_purpose: key.purpose,
        snapshot: u64::MAX,
        issued_at: kt(9999, 12, 31, 23, 59, 59),
    })
    .unwrap();
    AttestedNameResolution::new(resolution, [0xFF; NAME_RESOLUTION_TAG_LEN])
}

/// docs/59 §7.1, §7.5 (task PN10): a record's resolution crosses the
/// channel unchanged — every field and the tag's 32 octets as sent (the
/// channel neither computes nor checks a tag; keyd verifies it, §7.2) — for
/// a client and a service record.
#[test]
fn a_records_resolution_crosses_the_channel_unchanged() {
    for account in [client_account(), computer_account()] {
        let reply = DirectoryReply::from_client(&Ok(Some(account.clone())));
        let decoded =
            decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, &reply_body(&reply)).unwrap();
        let Reply::Message(decoded) = decoded else {
            panic!("a message")
        };
        let back = decoded.into_client().unwrap().unwrap().unwrap();
        assert_eq!(
            back.resolution.resolution(),
            account.resolution.resolution()
        );
        assert_eq!(back.resolution.tag(), account.resolution.tag());
    }
    let account = service_account();
    let reply = DirectoryReply::from_service(&Ok(Some(account.clone())));
    let decoded = decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, &reply_body(&reply)).unwrap();
    let Reply::Message(decoded) = decoded else {
        panic!("a message")
    };
    let back = decoded.into_service().unwrap().unwrap().unwrap();
    assert_eq!(
        back.resolution.resolution(),
        account.resolution.resolution()
    );
    assert_eq!(back.resolution.tag(), account.resolution.tag());
}

/// RFC 4120 §5.2.2 under DER (X.690 §8.1.3.4-§8.1.3.5, §10.1: the fewest
/// length octets): the name bound is exactly the DER length of the largest
/// name a resolution holds, so it admits every such name and nothing a
/// resolution could not hold; the realm bound is keyd-types' (task PN10).
#[test]
fn the_resolution_bounds_are_the_largest_resolution() {
    assert_eq!(
        largest_name().encode().unwrap().len(),
        MAX_RESOLUTION_NAME as usize
    );
    assert_eq!(MAX_RESOLUTION_NAME, 16_468);
    assert_eq!(MAX_RESOLUTION_REALM as usize, MAX_NAME_OCTETS);
    let wire = WireNameResolution::from_attested(&largest_resolution(KeyHandle::new(
        PrincipalId::from_bytes([9; 16]),
        KeyPurpose::Service,
    )))
    .unwrap();
    assert_eq!(
        wire.name_as_sent.as_der().len(),
        MAX_RESOLUTION_NAME as usize
    );
    assert_eq!(
        wire.to_attested().unwrap().resolution().snapshot(),
        u64::MAX
    );
}

/// docs/59 §7.1 (the bounds), AGENTS.md §6 (strict and bounded): a realm one
/// octet over its bound is refused when encoding and when decoding (at its
/// length prefix, before any allocation); a name with a component one octet
/// too long — within the DER bound — is refused by the typed layer
/// (`NameResolution::new`); an over-long DER is refused when encoding.
#[test]
fn a_resolution_outside_its_bounds_is_refused() {
    let account = service_account();
    let record = |edit: &dyn Fn(&mut WireNameResolution)| {
        let mut wire = ipc_directory::wire::WireService::from_account(&account).unwrap();
        edit(&mut wire.resolution);
        DirectoryReply::Service(Some(wire))
    };
    // A realm over the bound: not encodable.
    let over = record(&|r| r.realm_as_sent = vec![b'R'; MAX_RESOLUTION_REALM as usize + 1]);
    assert_eq!(
        encode_frame(DIRECTORY_CHANNEL, Direction::Reply, &over).err(),
        Some(Error::LengthOverBound)
    );
    // ... and not decodable: the declared length is refused at the prefix.
    let fits = record(&|r| r.realm_as_sent = vec![b'R'; MAX_RESOLUTION_REALM as usize]);
    let mut body = reply_body(&fits);
    let at = body
        .windows(4)
        .position(|w| w == MAX_RESOLUTION_REALM.to_be_bytes())
        .unwrap();
    body[at..at + 4].copy_from_slice(&(MAX_RESOLUTION_REALM + 1).to_be_bytes());
    assert_eq!(
        decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, &body).err(),
        Some(Error::LengthOverBound)
    );
    // A name DER over the bound: not encodable.
    let long_der = record(&|r| {
        r.canonical_name = ipc::DerBlob::new(vec![0x30; MAX_RESOLUTION_NAME as usize + 1]);
    });
    assert_eq!(
        encode_frame(DIRECTORY_CHANNEL, Direction::Reply, &long_der).err(),
        Some(Error::LengthOverBound)
    );
    // Within the DER bound but outside a resolution's — a component one
    // octet over keyd-types' bound (krb-proto bounds no component's octets,
    // RFC 4120 §5.2.1; it bounds the component count itself): refused by
    // the typed layer.
    let too_long = PrincipalName {
        name_type: 1,
        name_string: vec![KerberosString::new(&"n".repeat(MAX_NAME_OCTETS + 1)).unwrap()],
    };
    let der = too_long.encode().unwrap();
    assert!(der.len() <= MAX_RESOLUTION_NAME as usize);
    let reply = record(&|r| r.name_as_sent = ipc::DerBlob::new(der.clone()));
    let decoded = decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, &reply_body(&reply)).unwrap();
    let Reply::Message(decoded) = decoded else {
        panic!("a message")
    };
    assert_eq!(
        decoded.into_service().err(),
        Some(ConversionError::NameResolution)
    );
}

/// docs/50 §3.3 ("exact version", "no trailing octet"; the channel's
/// version stays 1 by the codecs' precedent — docs/questions/Q-1045 item 1,
/// A-184; Q-1046): a `Client` / `Service` record of the layout before task
/// PN10 — the same fields without the resolution — is refused
/// (`Truncated`), never read as a record without one.
#[test]
fn a_record_of_the_old_layout_is_refused_not_misread() {
    let resolution_octets = |r: &WireNameResolution| {
        4 + r.realm_as_sent.len()
            + 4
            + r.name_as_sent.as_der().len()
            + 4
            + r.canonical_realm.len()
            + 4
            + r.canonical_name.as_der().len()
            + 16
            + 1
            + 8
            + 7
            + NAME_RESOLUTION_TAG_LEN
    };
    let client = WireClient::from_account(&client_account()).unwrap();
    let body = reply_body(&DirectoryReply::Client(Some(client.clone())));
    let old = &body[..body.len() - resolution_octets(&client.resolution)];
    assert_eq!(
        decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, old).err(),
        Some(Error::Truncated)
    );
    let service = ipc_directory::wire::WireService::from_account(&service_account()).unwrap();
    let body = reply_body(&DirectoryReply::Service(Some(service.clone())));
    let old = &body[..body.len() - resolution_octets(&service.resolution)];
    assert_eq!(
        decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, old).err(),
        Some(Error::Truncated)
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
