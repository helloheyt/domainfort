//! Hand-made sample values for the directory-view channel tests.
//!
//! The SID layout S-1-5-21-1-2-3-<RID> follows the [MS-DTYP] 2.4.2.4 example
//! ("three sub authority values of 1, 2, and 3"); names, handles, salts and
//! times are this project's own test data. No vector or fixture comes from
//! any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

use dtyp::{Sid, SECURITY_NT_AUTHORITY};
use ipc::{decode_body, encode_frame, Direction};
use ipc_directory::typed::{DomainDescription, Query, Request};
use ipc_directory::wire::{DirectoryReply, DirectoryRequest};
use ipc_directory::{ViewFailure, DIRECTORY_CHANNEL};
use kdc::{
    AccountKind, AccountSourceError, AccountState, ArmorPolicy, ClientAccount, ServiceAccount,
};
use keyd_types::{KeyHandle, KeyPurpose, PrincipalId};
use krb_proto::{EtypeInfo2Entry, KerberosString, KerberosTime, PrincipalName, Realm};
use pdp::{PipError, PolicyVersion, Tier};
use std::collections::BTreeSet;

pub fn sid(rid: u32) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, rid]).unwrap()
}

pub fn realm() -> Realm {
    Realm::new("EXAMPLE.TEST").unwrap()
}

pub fn name(name_type: i32, parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type,
        name_string: parts
            .iter()
            .map(|p| KerberosString::new(p).unwrap())
            .collect(),
    }
}

pub fn kt(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
    KerberosTime::new(y, mo, d, h, mi, s).unwrap()
}

/// A client record with every optional part present.
pub fn client_account() -> ClientAccount {
    ClientAccount {
        key: KeyHandle::new(
            PrincipalId::from_bytes([0xA1; 16]),
            KeyPurpose::PrincipalLongterm,
        ),
        sid: sid(1010),
        groups: [sid(1030), sid(1031), sid(513)].into_iter().collect(),
        tier: Tier::Tier2,
        state: AccountState {
            enabled: true,
            locked: false,
            expires: Some(kt(2027, 1, 1, 0, 0, 0)),
            revoked_before: Some(kt(2026, 11, 5, 12, 0, 1)),
        },
        etype_info: vec![
            EtypeInfo2Entry {
                etype: 18,
                salt: Some(KerberosString::new("EXAMPLE.TESTalice").unwrap()),
                s2kparams: Some(vec![0, 0, 0x80, 0]),
            },
            EtypeInfo2Entry {
                etype: 17,
                salt: Some(KerberosString::new("EXAMPLE.TESTalice").unwrap()),
                s2kparams: None,
            },
        ],
        kind: AccountKind::User,
        armor_policy: ArmorPolicy::Required,
    }
}

/// A computer client record with no optional part.
pub fn computer_account() -> ClientAccount {
    ClientAccount {
        key: KeyHandle::new(
            PrincipalId::from_bytes([0xC0; 16]),
            KeyPurpose::PrincipalLongterm,
        ),
        sid: sid(1020),
        groups: BTreeSet::new(),
        tier: Tier::Untiered,
        state: AccountState::ACTIVE,
        etype_info: Vec::new(),
        kind: AccountKind::Computer,
        armor_policy: ArmorPolicy::BootstrapAllowed,
    }
}

pub fn service_account() -> ServiceAccount {
    ServiceAccount {
        key: KeyHandle::new(PrincipalId::from_bytes([0x5E; 16]), KeyPurpose::Service),
        state: AccountState {
            enabled: false,
            locked: true,
            expires: None,
            revoked_before: Some(kt(2026, 11, 1, 0, 0, 1)),
        },
        enctypes: vec![18, 17],
    }
}

pub fn domain() -> DomainDescription {
    DomainDescription {
        realm: realm(),
        naming_context: vec![String::from("example"), String::from("test")],
        krbtgt: KeyHandle::new(PrincipalId::from_bytes([0x7B; 16]), KeyPurpose::Krbtgt),
        policy_version: PolicyVersion(7),
    }
}

/// One typed request of every kind (and both query families twice).
pub fn requests() -> Vec<Request> {
    vec![
        Request::BeginView,
        Request::Query {
            view: 1,
            query: Query::Client {
                realm: realm(),
                name: name(1, &["alice"]),
            },
        },
        Request::Query {
            view: 2,
            query: Query::Service {
                realm: realm(),
                name: name(3, &["host", "ws01.example.test"]),
            },
        },
        Request::Query {
            view: 3,
            query: Query::ExpandGroups { sid: sid(1010) },
        },
        Request::Query {
            view: u64::MAX,
            query: Query::TierOf {
                sid: sid(1010),
                groups: [sid(1030), sid(513)].into_iter().collect(),
            },
        },
        Request::Query {
            view: 4,
            query: Query::TierOf {
                sid: sid(1010),
                groups: BTreeSet::new(),
            },
        },
        Request::EndView { view: 9 },
        Request::DescribeDomain,
        Request::Ping,
    ]
}

/// One wire reply of every kind and every closed code.
pub fn replies() -> Vec<DirectoryReply> {
    let mut all = vec![
        DirectoryReply::ViewBegun {
            view: 1,
            policy_version: 7,
        },
        DirectoryReply::from_client(&Ok(Some(client_account()))),
        DirectoryReply::from_client(&Ok(Some(computer_account()))),
        DirectoryReply::from_client(&Ok(None)),
        DirectoryReply::from_service(&Ok(Some(service_account()))),
        DirectoryReply::from_service(&Ok(None)),
        DirectoryReply::from_groups(&Ok([sid(1030), sid(1031)].into_iter().collect())),
        DirectoryReply::from_groups(&Ok(BTreeSet::new())),
        DirectoryReply::ViewEnded,
        DirectoryReply::from_domain(&domain()),
        DirectoryReply::Pong,
    ];
    for tier in [Tier::Tier0, Tier::Tier1, Tier::Tier2, Tier::Untiered] {
        all.push(DirectoryReply::from_tier(&Ok(tier)));
    }
    for error in [AccountSourceError::Failed, AccountSourceError::Unavailable] {
        all.push(DirectoryReply::from_client(&Err(error)));
    }
    for error in [PipError::NotFound, PipError::Unavailable] {
        all.push(DirectoryReply::from_groups(&Err(error)));
    }
    for failure in [
        ViewFailure::UnknownView,
        ViewFailure::ViewOpen,
        ViewFailure::ViewLimit,
        ViewFailure::Expired,
        ViewFailure::Snapshot,
    ] {
        all.push(DirectoryReply::ViewFailure(failure));
    }
    all
}

/// The request body of a typed request.
pub fn request_body(request: &Request) -> Vec<u8> {
    let wire = request.to_wire().unwrap();
    encode_frame(DIRECTORY_CHANNEL, Direction::Request, &wire)
        .unwrap()
        .body()
        .to_vec()
}

/// Decode a request body back to its typed request.
pub fn decode_request(body: &[u8]) -> Result<Request, String> {
    let wire: DirectoryRequest =
        decode_body(DIRECTORY_CHANNEL, Direction::Request, body).map_err(|e| e.to_string())?;
    Request::from_wire(&wire).map_err(|e| e.to_string())
}

/// The reply body of a wire reply.
pub fn reply_body(reply: &DirectoryReply) -> Vec<u8> {
    encode_frame(DIRECTORY_CHANNEL, Direction::Reply, reply)
        .unwrap()
        .body()
        .to_vec()
}
