//! The operation digest (R2; docs/52 §3.2, §5; decision A-102): the
//! application data an admin AP-REQ's `cksum` is computed over (RFC 4120
//! §5.5.1, key usage 10).
//!
//! What is checked: the digest dird computes from the request it decoded is
//! the SHA-256 of the label, the envelope header and the **exact payload
//! octets after `auth`** of the frame it received (so client and dird agree
//! by construction, not by convention); it depends on every bound field and
//! on the kind, never on the AP-REQs; `CompletePasswordSet` binds its
//! target only; and one hand-built known answer pins the layout.
//!
//! Sources: docs/52 §5 items 1, 5; docs/51 §7.1, §7.3, §7.6; docs/50 §3.3;
//! RFC 4120 §5.5.1; FIPS 180-4 (SHA-256, via the approved `sha2`). Every
//! value is constructed by hand for these tests; no vector comes from any
//! other implementation.

use dtyp::Guid;
use ipc::{encode_frame, encode_payload, Direction};
use ipc_dird_admin::{
    decode_request, operation_digest, wire_operation_digest, AccountExpires, Auth, KeyOperation,
    KeyRef, LookupKey, Operation, PasswordSetOutcome, Request, WireAuth, ADMIN_CHANNEL,
    OPERATION_DIGEST_LABEL, REQUEST_LIMIT,
};
use sha2::{Digest, Sha256};

fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0xD1,
        data3: 0x0002,
        data4: [0xD, 0x16, 0xE5, 0x7, 0xD, 0x16, 0xE5, 0x7],
    }
}

fn auth(seed: u8, approvals: usize) -> Auth {
    Auth {
        requester: vec![seed; 200],
        approvals: (0..approvals).map(|i| vec![seed, i as u8, 7]).collect(),
    }
}

/// One operation of every kind, with distinct values.
fn operations() -> Vec<Operation> {
    vec![
        Operation::CreateUser {
            parent: guid(1),
            sam: "carol".into(),
            upn: Some("carol@example.test".into()),
            description: None,
        },
        Operation::CreateComputer {
            parent: guid(2),
            name: "ws02".into(),
            dns_host_name: "ws02.example.test".into(),
            spn: None,
        },
        Operation::CreateGroup {
            parent: guid(3),
            sam: "ops".into(),
            group_type: Some(0x8000_0002),
        },
        Operation::CreateOu {
            parent: guid(4),
            name: "Branch".into(),
        },
        Operation::CreateContainer {
            parent: guid(4),
            name: "Branch".into(),
        },
        Operation::BeginPasswordSet { target: guid(5) },
        Operation::CompletePasswordSet {
            target: guid(5),
            outcome: PasswordSetOutcome::Completed,
            kvnos: vec![2],
        },
        Operation::SetEnabled {
            target: guid(5),
            enabled: true,
        },
        Operation::SetAccountExpires {
            target: guid(5),
            value: AccountExpires::Never,
        },
        Operation::AddMember {
            group: guid(7),
            member: guid(5),
        },
        Operation::RemoveMember {
            group: guid(7),
            member: guid(5),
        },
        Operation::Delete { target: guid(5) },
        Operation::Lookup(LookupKey::SamAccountName("carol".into())),
        Operation::RequestKeyOperation {
            operation: KeyOperation::RotateKey { service: guid(30) },
        },
        Operation::Approve {
            id: 41,
            operation: KeyOperation::RotateKey { service: guid(30) },
        },
    ]
}

/// The request frame body (`magic ‖ version ‖ kind ‖ payload`).
fn body(auth: &Auth, operation: &Operation) -> Vec<u8> {
    let request = Request::Operation {
        auth: auth.clone(),
        operation: operation.clone(),
    };
    encode_frame(
        ADMIN_CHANNEL,
        Direction::Request,
        &request.to_wire().unwrap(),
    )
    .unwrap()
    .body()
    .to_vec()
}

/// The octets of the `auth` field alone.
fn auth_len(auth: &Auth) -> usize {
    let wire = WireAuth {
        requester: auth.requester.clone(),
        approvals: auth.approvals.clone(),
    };
    encode_payload(&wire, REQUEST_LIMIT).unwrap().len()
}

/// docs/52 §5 item 1 ("exactly the octets dird reads"): for every kind but
/// `CompletePasswordSet`, the digest of the request dird decoded is the
/// SHA-256 of the label, the frame's own magic / version / kind octets and
/// the frame's own payload octets after `auth` — cut out of the received
/// body, not re-encoded.
#[test]
fn the_digest_covers_the_exact_payload_after_auth() {
    for operation in operations() {
        let auth = auth(0x6E, 1);
        let body = body(&auth, &operation);
        let Request::Operation {
            operation: decoded, ..
        } = decode_request(&body).unwrap()
        else {
            panic!("an operation");
        };
        let after_auth = &body[4 + auth_len(&auth)..];
        let bound: &[u8] = match operation {
            // The target only: the outcome and kvnos are admind's report.
            Operation::CompletePasswordSet { .. } => &after_auth[..16],
            _ => after_auth,
        };
        let mut octets = OPERATION_DIGEST_LABEL.to_vec();
        octets.extend_from_slice(&body[..4]);
        octets.extend_from_slice(bound);
        let expected = <[u8; 32]>::from(Sha256::digest(&octets));
        let digest = operation_digest(&decoded).unwrap();
        assert_eq!(digest.as_bytes(), &expected, "{operation:?}");
        // The typed and the wire forms agree.
        assert_eq!(
            wire_operation_digest(&decoded.to_wire().unwrap()).unwrap(),
            digest
        );
    }
}

/// The digest binds the operation and nothing else: every operation of the
/// list (two of which share their fields and differ only in kind, three of
/// which share one target) has its own digest, and the AP-REQs do not
/// change it (the requester's or the approvers' — an approval is bound to
/// the same operation as the request). Source: docs/52 §5 items 1, 4.
#[test]
fn every_operation_has_its_own_digest_and_the_tickets_none() {
    let all: Vec<_> = operations()
        .iter()
        .map(|o| operation_digest(o).unwrap())
        .collect();
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
    for operation in operations() {
        let one = body(&auth(1, 0), &operation);
        let other = body(&auth(2, 2), &operation);
        assert_ne!(one, other);
        let digest_of = |b: &[u8]| match decode_request(b).unwrap() {
            Request::Operation { operation, .. } => operation_digest(&operation).unwrap(),
            Request::Ping => panic!("an operation"),
        };
        assert_eq!(digest_of(&one), digest_of(&other));
    }
    // A changed field changes the digest.
    let a = operation_digest(&Operation::Approve {
        id: 41,
        operation: KeyOperation::RotateKey { service: guid(30) },
    })
    .unwrap();
    for changed in [
        Operation::Approve {
            id: 42,
            operation: KeyOperation::RotateKey { service: guid(30) },
        },
        Operation::Approve {
            id: 41,
            operation: KeyOperation::RotateKey { service: guid(31) },
        },
        Operation::Approve {
            id: 41,
            operation: KeyOperation::RetireKvno {
                key: KeyRef::Service(guid(30)),
                kvno: 1,
            },
        },
    ] {
        assert_ne!(operation_digest(&changed).unwrap(), a);
    }
}

/// docs/52 §5 items 1, 5: `CompletePasswordSet` binds its target only — the
/// client cannot know the outcome or the kvnos admind reports — and is never
/// the `BeginPasswordSet` digest of the same target (another kind).
#[test]
fn complete_password_set_binds_its_target_only() {
    let complete = |target, outcome, kvnos| {
        operation_digest(&Operation::CompletePasswordSet {
            target,
            outcome,
            kvnos,
        })
        .unwrap()
    };
    let a = complete(guid(5), PasswordSetOutcome::Completed, vec![2, 3]);
    assert_eq!(a, complete(guid(5), PasswordSetOutcome::Failed, vec![]));
    assert_eq!(a, complete(guid(5), PasswordSetOutcome::Completed, vec![9]));
    assert_ne!(
        a,
        complete(guid(6), PasswordSetOutcome::Completed, vec![2, 3])
    );
    assert_ne!(
        a,
        operation_digest(&Operation::BeginPasswordSet { target: guid(5) }).unwrap()
    );
}

/// A known answer built by hand from the definition (docs/52 §5 item 1):
/// SHA-256 of the label, `44 41` (the magic), `01` (the version), `06`
/// (`BeginPasswordSet`) and the target's 16-octet objectGUID packet
/// ([MS-DTYP] 2.3.4.2 — the little-endian Data1..Data3, then Data4).
#[test]
fn a_hand_built_known_answer() {
    assert_eq!(
        OPERATION_DIGEST_LABEL,
        b"dird-admin AP-REQ operation binding, layout 1"
    );
    let target = Guid {
        data1: 0x0403_0201,
        data2: 0x0605,
        data3: 0x0807,
        data4: [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
    };
    let mut octets = b"dird-admin AP-REQ operation binding, layout 1".to_vec();
    octets.extend_from_slice(&[0x44, 0x41, 0x01, 0x06]);
    octets.extend_from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ]);
    assert_eq!(
        operation_digest(&Operation::BeginPasswordSet { target })
            .unwrap()
            .as_bytes(),
        &<[u8; 32]>::from(Sha256::digest(&octets))
    );
}
