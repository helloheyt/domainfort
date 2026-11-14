//! The pending key-operation requests' fixed parts (task A10): the
//! operation digest binds every field of the request, the table's lifetime
//! is bounded, the operations' codes and purposes. The steps themselves run
//! against the real dird in crates/directory-daemon tests/admin_service.rs.
//!
//! Sources: docs/51 §5.6 ("the operation digest", "bounded in time"), §6;
//! docs/24 §6 (principle: sign the exact operation); docs/10 §1, §7;
//! docs/questions/Q-420. Every value is constructed by hand for these
//! tests; no vector comes from any other implementation (SHA-256 itself is
//! the approved `sha2`'s — only its use is checked here).

use core::time::Duration;
use directory_admin::{
    operation_digest, ConfigError, KeyAdminOperation, KeyOperation, KeyOperationOutcome, KeyRef,
    KeyRequests, KeyTargets, KEY_REQUEST_LIFETIME, MAX_KEY_REQUEST_LIFETIME,
};
use dtyp::Guid;
use ipc_audit::{DirAdminOperation, KeydOperation};
use keyd_types::KeyPurpose;
use std::collections::BTreeSet;

fn guid(n: u8) -> Guid {
    let mut packet = [0u8; 16];
    packet[0] = 0xA1;
    packet[15] = n;
    Guid::from_packet(&packet)
}

/// docs/51 §5.6; docs/24 §6: the digest is a function of the request — the
/// same inputs give the same digest; changing the id, the operation, its
/// kvno, the key set, the requester or the expiry changes it.
#[test]
fn the_digest_binds_every_field() {
    let base = operation_digest(7, &KeyOperation::RotateKrbtgt, guid(1), guid(2), 1000);
    assert_eq!(
        base,
        operation_digest(7, &KeyOperation::RotateKrbtgt, guid(1), guid(2), 1000)
    );
    let retire = |kvno| KeyOperation::RetireKvno {
        key: KeyRef::Krbtgt,
        kvno,
    };
    let variants = [
        operation_digest(8, &KeyOperation::RotateKrbtgt, guid(1), guid(2), 1000),
        operation_digest(7, &retire(0), guid(1), guid(2), 1000),
        operation_digest(7, &retire(1), guid(1), guid(2), 1000),
        operation_digest(7, &retire(2), guid(1), guid(2), 1000),
        operation_digest(
            7,
            &KeyOperation::RotateKey { service: guid(1) },
            guid(1),
            guid(2),
            1000,
        ),
        operation_digest(7, &KeyOperation::RotateKrbtgt, guid(3), guid(2), 1000),
        operation_digest(7, &KeyOperation::RotateKrbtgt, guid(1), guid(4), 1000),
        operation_digest(7, &KeyOperation::RotateKrbtgt, guid(1), guid(2), 1001),
    ];
    let mut all: BTreeSet<[u8; 32]> = variants.iter().copied().collect();
    assert_eq!(all.len(), variants.len());
    assert!(all.insert(base), "every variant differs from the base");
}

/// docs/10 §1, §7: the keyd operation and the key purpose of each request.
#[test]
fn operations_name_their_keyd_operation_and_purpose() {
    let service = guid(5);
    for (operation, keyd, purpose, kvno) in [
        (
            KeyOperation::RotateKrbtgt,
            KeydOperation::RotateKrbtgt,
            KeyPurpose::Krbtgt,
            true,
        ),
        (
            KeyOperation::RotateKey { service },
            KeydOperation::RotateKey,
            KeyPurpose::Service,
            true,
        ),
        (
            KeyOperation::RetireKvno {
                key: KeyRef::Krbtgt,
                kvno: 1,
            },
            KeydOperation::RetireKvno,
            KeyPurpose::Krbtgt,
            false,
        ),
        (
            KeyOperation::RetireKvno {
                key: KeyRef::Service(service),
                kvno: 1,
            },
            KeydOperation::RetireKvno,
            KeyPurpose::Service,
            false,
        ),
    ] {
        assert_eq!(operation.keyd_operation(), keyd);
        assert_eq!(operation.purpose(), purpose);
        assert_eq!(operation.answers_kvno(), kvno);
    }
    // keyadm's steps carry no ticket; `Complete` records two events.
    let steps = [
        (
            KeyAdminOperation::RequestKeyOperation {
                operation: KeyOperation::RotateKrbtgt,
            },
            DirAdminOperation::RequestKeyOperation,
            true,
            1,
        ),
        (
            KeyAdminOperation::Approve {
                id: 1,
                operation: KeyOperation::RotateKrbtgt,
            },
            DirAdminOperation::Approve,
            true,
            1,
        ),
        (
            KeyAdminOperation::FetchApproved { id: 1 },
            DirAdminOperation::FetchApproved,
            false,
            1,
        ),
        (
            KeyAdminOperation::Complete {
                id: 1,
                outcome: KeyOperationOutcome::Refused,
            },
            DirAdminOperation::Complete,
            false,
            2,
        ),
        (
            KeyAdminOperation::ListPendingDestruction { cursor: None },
            DirAdminOperation::ListPendingDestruction,
            false,
            1,
        ),
    ];
    for (step, code, ticket, events) in steps {
        assert_eq!(step.code(), code);
        assert_eq!(step.takes_ticket(), ticket);
        assert_eq!(step.audit_events(), events);
    }
}

/// docs/51 §5.6 ("bounded in time"): the lifetime is 1 s ..= one hour; a
/// new table is empty.
#[test]
fn the_lifetime_is_bounded() {
    let targets = || KeyTargets {
        krbtgt: guid(1),
        services: BTreeSet::from([guid(2), guid(3)]),
    };
    for lifetime in [
        Duration::ZERO,
        MAX_KEY_REQUEST_LIFETIME + Duration::from_secs(1),
    ] {
        assert_eq!(
            KeyRequests::new(targets(), lifetime, 0).unwrap_err(),
            ConfigError::KeyRequestLifetime
        );
    }
    for lifetime in [
        Duration::from_secs(1),
        KEY_REQUEST_LIFETIME,
        MAX_KEY_REQUEST_LIFETIME,
    ] {
        let table = KeyRequests::new(targets(), lifetime, 0).unwrap();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }
}
