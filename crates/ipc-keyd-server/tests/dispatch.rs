//! The server-side dispatcher and the client over the in-process loopback:
//! the caller identity comes from the transport, `now` from the daemon's
//! clock, malformed input is refused before keyd is called, and every
//! transport failure or refusal reaches the caller as `Unavailable` —
//! never `Denied`.
//!
//! Sources: docs/50 §3.2 (R50-3: identity only from peer credentials; the
//! client verifies the server's uid), §3.3 (refusal table), §3.4, §3.5
//! (R50-5: keyd fills `now` from its own clock), §3.6, §3.7 (R50-8:
//! `Unavailable`, never a disguised wrong password), §9; docs/10 §2, §9;
//! A-56; A-59; A-62 (two-interval hold-down); docs/52 §3.12, §7 R9
//! (docs/questions/Q-466: the client expects its role on every connection,
//! the `Ping` reply names it, a state call carries its fate). Every value
//! is constructed by hand for these tests; no vector comes from any other
//! implementation.

#[path = "../../ipc-keyd/tests/samples/mod.rs"]
mod samples;
mod support;

use ipc::{encode_frame, Direction, Refused};
use ipc_keyd::{
    CallFailure, ClientConfigError, ExpectedPeer, IssuanceCall, KeydClient, KeydReply, RequestFate,
    TransportError, Unserved, DEFAULT_DEADLINE, KEYD_CHANNEL,
};
use ipc_keyd_server::{dispatch, Dispatch};
use keyd::{
    AuditRecord, AuthnError, CallerId, InMemoryKeyStore, IssueError, KeyPurpose, Keyd, KeydConfig,
    Kvno, OsEntropy, PrincipalBinding, Role,
};
use krb_proto::KerberosTime;
use support::{share, Loopback, Shared, KEYD_UID};
use zeroize::Zeroizing;

#[derive(Default)]
struct Records(Vec<AuditRecord>);

impl keyd::AuditSink for Records {
    fn record(&mut self, record: &AuditRecord) {
        self.0.push(record.clone());
    }
}

type DevKeyd = Keyd<InMemoryKeyStore, Records, OsEntropy>;

const KDC: CallerId = CallerId {
    uid: 100,
    role: Role::Kdc,
};
const DIRECTORY: CallerId = CallerId {
    uid: 200,
    role: Role::Directory,
};
const ADMIN: CallerId = CallerId {
    uid: 300,
    role: Role::Admin,
};
const LDAP: CallerId = CallerId {
    uid: 400,
    role: Role::Ldap,
};

/// keyd's start time in these tests.
fn started() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 9, 0, 0).unwrap()
}

/// `started()` plus `secs` (within the same day).
fn after(secs: u32) -> KerberosTime {
    let total = 9 * 3600 + secs;
    KerberosTime::new(
        2026,
        11,
        13,
        (total / 3600) as u8,
        ((total % 3600) / 60) as u8,
        (total % 60) as u8,
    )
    .unwrap()
}

/// A development keyd (TESTS ONLY: the insecure store that holds krbtgt,
/// docs/33 §6.1 / A-16) started at `started()`.
fn dev_keyd() -> DevKeyd {
    let store = InMemoryKeyStore::new_insecure_development_allowing_krbtgt(16);
    let config = KeydConfig::new(samples::realm());
    Keyd::new(config, store, Records::default(), &started()).unwrap()
}

/// A server whose clock is past the two-interval hold-down (A-62).
fn served() -> Shared<InMemoryKeyStore, Records, OsEntropy> {
    share(dev_keyd(), after(3600))
}

/// A client of `caller`'s role (task R9: it expects that role of keyd on
/// every connection).
fn client(
    server: &Shared<InMemoryKeyStore, Records, OsEntropy>,
    caller: CallerId,
) -> KeydClient<Loopback<InMemoryKeyStore, Records, OsEntropy>> {
    KeydClient::new(
        Loopback::new(server, caller),
        ExpectedPeer::new(KEYD_UID, caller.role).unwrap(),
        DEFAULT_DEADLINE,
    )
}

/// The reply message of a `Dispatch::Reply`.
fn reply_of(outcome: Dispatch) -> KeydReply {
    let Dispatch::Reply(frame) = outcome else {
        panic!("expected a reply, got {outcome:?}");
    };
    match ipc::decode_reply::<KeydReply>(KEYD_CHANNEL, frame.body()).unwrap() {
        ipc::Reply::Message(reply) => reply,
        ipc::Reply::Refused(refused) => panic!("refused {refused:?}"),
    }
}

/// The refusal of a `Dispatch::ReplyAndClose`.
fn refusal_of(outcome: Dispatch) -> Refused {
    let Dispatch::ReplyAndClose(frame) = outcome else {
        panic!("expected a refusal, got {outcome:?}");
    };
    match ipc::decode_reply::<KeydReply>(KEYD_CHANNEL, frame.body()).unwrap() {
        ipc::Reply::Refused(refused) => refused,
        ipc::Reply::Message(reply) => panic!("message {reply:?}"),
    }
}

fn body_of(call: &ipc_keyd::Call) -> Vec<u8> {
    encode_frame(KEYD_CHANNEL, Direction::Request, &call.to_wire().unwrap())
        .unwrap()
        .body()
        .to_vec()
}

/// docs/50 R50-3, §3.2 ("`CallerId { uid, role }` built once per connection
/// and handed to every operation"); docs/10 §2 (capability table): the very
/// same request octets get each caller's own authorization result. No field
/// of any request can carry a role (tests/messages.rs).
#[test]
fn caller_identity_comes_from_the_transport() {
    let mut keyd = dev_keyd();
    let now = after(3600);
    let create = body_of(&ipc_keyd::Call::CreateKey {
        handle: samples::handle(0x5E, KeyPurpose::Service),
        binding: PrincipalBinding::new(
            samples::realm(),
            samples::name(3, &["host", "files.example.org"]),
        ),
    });
    for caller in [KDC, DIRECTORY, LDAP] {
        assert_eq!(
            reply_of(dispatch(&mut keyd, caller, now, &create)),
            KeydReply::Failure(keyd::Error::Denied),
            "{caller:?}"
        );
    }
    assert_eq!(
        reply_of(dispatch(&mut keyd, ADMIN, now, &create)),
        KeydReply::CreateKey(Kvno::INITIAL)
    );
    // keyd recorded each caller's uid and role as the transport gave them.
    let records = &keyd.audit_sink().0;
    let seen: Vec<(u32, Role)> = records
        .iter()
        .map(|r| (r.caller_uid, r.caller_role))
        .collect();
    assert_eq!(
        seen,
        vec![
            (100, Role::Kdc),
            (200, Role::Directory),
            (400, Role::Ldap),
            (300, Role::Admin)
        ]
    );

    // Q-351 (A-87): the same DescribeConfig octets are answered, to the two
    // roles that may call it, with the role the transport gave the caller —
    // the identity keyd authorized with — beside the same description.
    let describe = body_of(&ipc_keyd::Call::DescribeConfig);
    for (caller, allowed) in [
        (KDC, true),
        (LDAP, true),
        (DIRECTORY, false),
        (ADMIN, false),
    ] {
        let reply = reply_of(dispatch(&mut keyd, caller, now, &describe));
        match reply {
            KeydReply::DescribeConfig(described) => {
                assert!(allowed, "{caller:?}");
                assert_eq!(described.caller_role, caller.role);
                assert_eq!(described.realm, samples::realm().as_bytes());
            }
            other => {
                assert!(!allowed, "{caller:?}");
                assert_eq!(other, KeydReply::Failure(keyd::Error::Denied));
            }
        }
    }
    // Task R9 (docs/questions/Q-466 item 2): every role may ping, and the
    // reply names the role keyd resolved for the caller.
    let ping = body_of(&ipc_keyd::Call::Ping);
    for caller in [KDC, DIRECTORY, ADMIN, LDAP] {
        assert_eq!(
            reply_of(dispatch(&mut keyd, caller, now, &ping)),
            KeydReply::Ping(caller.role)
        );
    }
}

/// docs/50 R50-5, §3.5; A-56; A-62: keyd's `now` is the daemon's clock
/// argument. The same request octets are held (`Unavailable`) while the
/// daemon's clock is inside the two-interval hold-down after keyd's start
/// and served after it — the request has no field that could move it.
#[test]
fn now_is_the_daemons_clock() {
    let mut keyd = dev_keyd();
    let preauth = body_of(&ipc_keyd::Call::VerifyPreauth {
        client: samples::handle(0xA1, KeyPurpose::PrincipalLongterm),
        padata: samples::padata(2),
        armor: None,
    });
    // Skew 300 s (RFC 4120 §8.2 default): held through started + 600.
    for secs in [0, 1, 300, 600] {
        assert_eq!(
            reply_of(dispatch(&mut keyd, KDC, after(secs), &preauth)),
            KeydReply::AuthnFailure(AuthnError::Unavailable),
            "+{secs}"
        );
    }
    // Served from started + 601: the unknown client is the uniform Denied.
    assert_eq!(
        reply_of(dispatch(&mut keyd, KDC, after(601), &preauth)),
        KeydReply::AuthnFailure(AuthnError::Denied)
    );
}

/// docs/50 §3.3 (refusal table; A-59 / Q-225 item 3): a body the ipc layer
/// refuses is answered `Malformed` (payload) or `VersionMismatch`, or closed
/// without a reply (wrong magic, unknown kind, too short); a body whose
/// Kerberos value krb-proto refuses is `Malformed`. keyd is never called.
#[test]
fn malformed_requests_never_reach_keyd() {
    let mut keyd = dev_keyd();
    let now = after(3600);
    let ping = body_of(&ipc_keyd::Call::Ping);

    let mut wrong_version = ping.clone();
    wrong_version[2] = 2;
    assert_eq!(
        refusal_of(dispatch(&mut keyd, KDC, now, &wrong_version)),
        Refused::VersionMismatch
    );
    let mut trailing = ping.clone();
    trailing.push(0);
    assert_eq!(
        refusal_of(dispatch(&mut keyd, KDC, now, &trailing)),
        Refused::Malformed
    );
    let mut bad_der = body_of(&ipc_keyd::Call::VerifyPreauth {
        client: samples::handle(0xA1, KeyPurpose::PrincipalLongterm),
        padata: samples::padata(2),
        armor: None,
    });
    bad_der[25] = 0x31;
    assert_eq!(
        refusal_of(dispatch(&mut keyd, KDC, now, &bad_der)),
        Refused::Malformed
    );
    let mut bad_purpose = body_of(&ipc_keyd::Call::CreateKey {
        handle: samples::handle(0x5E, KeyPurpose::Service),
        binding: samples::binding(),
    });
    bad_purpose[20] = 0x09; // purpose code outside the closed table
    assert_eq!(
        refusal_of(dispatch(&mut keyd, ADMIN, now, &bad_purpose)),
        Refused::Malformed
    );
    let mut non_utf8_password = body_of(&ipc_keyd::Call::VerifySecret {
        handle: samples::handle(0xA1, KeyPurpose::PrincipalLongterm),
        candidate: samples::password("x"),
    });
    *non_utf8_password.last_mut().unwrap() = 0xFF;
    assert_eq!(
        refusal_of(dispatch(&mut keyd, DIRECTORY, now, &non_utf8_password)),
        Refused::Malformed
    );

    let mut wrong_magic = ping.clone();
    wrong_magic[0] ^= 0x01;
    let mut unknown_kind = ping.clone();
    unknown_kind[3] = 0x42;
    let mut refused_kind = ping.clone();
    refused_kind[3] = ipc::REFUSED_KIND;
    for body in [
        wrong_magic,
        unknown_kind,
        refused_kind,
        vec![0x4B, 0x44, 0x01],
    ] {
        assert!(matches!(
            dispatch(&mut keyd, KDC, now, &body),
            Dispatch::Close
        ));
    }
    assert!(keyd.audit_sink().0.is_empty(), "keyd was never called");
}

/// docs/50 §3.4: every Directory and Admin operation (and the Kdc / Ldap
/// support operations) through the client and the loopback gives keyd's own
/// results — kvnos keyd chose, the uniform `Denied`, dual control refused.
/// Since A-102 (docs/52 §4.2, §4.4, §4.6) every Directory / Admin state
/// change after `create_key` runs on a decision only dird (Ldap) registers,
/// and the executions name only its id.
#[test]
fn admin_and_directory_operations_through_the_client() {
    let server = served();
    let mut admin = client(&server, ADMIN);
    let mut directory = client(&server, DIRECTORY);
    let mut kdc = client(&server, KDC);
    let mut ldap = client(&server, LDAP);
    let approvers = [
        keyd::PrincipalId::from_bytes([1; 16]),
        keyd::PrincipalId::from_bytes([2; 16]),
    ];

    let service = samples::handle(0x5E, KeyPurpose::Service);
    let service_binding = PrincipalBinding::new(
        samples::realm(),
        samples::name(3, &["host", "files.example.org"]),
    );
    assert_eq!(
        admin.create_key(&service, &service_binding),
        Ok(Ok(Kvno::new(1)))
    );
    assert_eq!(
        admin.create_key(&service, &service_binding),
        Ok(Err(keyd::Error::Denied))
    );
    // No decision: refused (NoDecision).
    let rotate = keyd::DecisionId::new(11);
    assert_eq!(admin.rotate_key(rotate), Ok(Err(keyd::Error::Denied)));
    assert_eq!(
        ldap.register_decision(
            rotate,
            &keyd::DecidedOperation::RotateKey { handle: service },
            &approvers,
            900
        ),
        Ok(Ok(()))
    );
    assert_eq!(admin.rotate_key(rotate), Ok(Ok(Kvno::new(2))));
    // Presented again: the recorded result, no second rotation.
    assert_eq!(admin.rotate_key(rotate), Ok(Ok(Kvno::new(2))));
    let retire = keyd::DecisionId::new(12);
    assert_eq!(
        ldap.register_decision(
            retire,
            &keyd::DecidedOperation::RetireKvno {
                handle: service,
                kvno: Kvno::new(1),
            },
            &approvers,
            900
        ),
        Ok(Ok(()))
    );
    // The wrong execution for that id is refused (DecisionMismatch) and does
    // not consume it.
    assert_eq!(admin.rotate_key(retire), Ok(Err(keyd::Error::Denied)));
    assert_eq!(admin.retire_kvno(retire), Ok(Ok(())));
    // Only dird (Ldap) registers decisions.
    assert_eq!(
        admin.register_decision(
            keyd::DecisionId::new(13),
            &keyd::DecidedOperation::RotateKey { handle: service },
            &approvers,
            900
        ),
        Ok(Err(keyd::Error::Denied))
    );

    let krbtgt = samples::KRBTGT;
    let krbtgt_binding = PrincipalBinding::new(
        samples::realm(),
        samples::name(2, &["krbtgt", "EXAMPLE.ORG"]),
    );
    assert_eq!(
        admin.create_key(&krbtgt, &krbtgt_binding),
        Ok(Ok(Kvno::new(1)))
    );
    // Dual control: two distinct approvers or no decision at all.
    let rotate_krbtgt = keyd::DecisionId::new(14);
    assert_eq!(
        ldap.register_decision(
            rotate_krbtgt,
            &keyd::DecidedOperation::RotateKrbtgt { krbtgt },
            &[approvers[0], approvers[0]],
            900
        ),
        Ok(Err(keyd::Error::Denied))
    );
    assert_eq!(
        admin.rotate_krbtgt(rotate_krbtgt),
        Ok(Err(keyd::Error::Denied))
    );
    assert_eq!(
        ldap.register_decision(
            rotate_krbtgt,
            &keyd::DecidedOperation::RotateKrbtgt { krbtgt },
            &approvers,
            900
        ),
        Ok(Ok(()))
    );
    assert_eq!(admin.rotate_krbtgt(rotate_krbtgt), Ok(Ok(Kvno::new(2))));
    // Task F3 (docs/questions/Q-976): dird (Ldap) revokes a registered key
    // decision through `0x19`; keyadm's execution is then refused, and only
    // Ldap may revoke. An executed decision is not revoked.
    let revoked = keyd::DecisionId::new(17);
    assert_eq!(
        ldap.register_decision(
            revoked,
            &keyd::DecidedOperation::RotateKrbtgt { krbtgt },
            &approvers,
            900
        ),
        Ok(Ok(()))
    );
    assert_eq!(admin.revoke_decision(revoked), Err(keyd::Error::Denied));
    assert_eq!(ldap.revoke_decision(revoked), Ok(()));
    assert_eq!(ldap.revoke_decision(revoked), Ok(()));
    assert_eq!(admin.rotate_krbtgt(revoked), Ok(Err(keyd::Error::Denied)));
    assert_eq!(
        ldap.revoke_decision(rotate_krbtgt),
        Err(keyd::Error::Denied)
    );

    let alice = samples::handle(0xA1, KeyPurpose::PrincipalLongterm);
    let pass = || Zeroizing::new(String::from(samples::PASSWORD));
    // Task A15a / A-102: no set_secret without dird's decision, which binds
    // the binding and the salt (N4).
    let set_alice = keyd::DecidedOperation::SetSecret {
        kind: keyd::AccountKind::User,
        targets: vec![keyd::SetSecretTarget {
            handle: alice,
            binding: samples::binding(),
            salt: String::from("EXAMPLE.ORGalice"),
        }],
    };
    assert_eq!(
        directory.set_secret(&alice, &samples::binding(), pass(), "EXAMPLE.ORGalice"),
        Ok(Err(keyd::Error::Denied))
    );
    assert_eq!(
        directory.register_decision(
            keyd::DecisionId::new(15),
            &set_alice,
            &[],
            keyd::MAX_SET_SECRET_GRANT_SECS
        ),
        Ok(Err(keyd::Error::Denied))
    );
    assert_eq!(
        ldap.register_decision(
            keyd::DecisionId::new(15),
            &set_alice,
            &[],
            keyd::MAX_SET_SECRET_GRANT_SECS
        ),
        Ok(Ok(()))
    );
    assert_eq!(
        directory.set_secret(&alice, &samples::binding(), pass(), "EXAMPLE.ORGalice"),
        Ok(Ok(Kvno::INITIAL))
    );
    // The decision is spent.
    assert_eq!(
        directory.set_secret(&alice, &samples::binding(), pass(), "EXAMPLE.ORGalice"),
        Ok(Err(keyd::Error::Denied))
    );
    // The Directory role may not create keys; the Admin role may not set
    // secrets (docs/10 §2).
    assert_eq!(
        directory.create_key(&alice, &samples::binding()),
        Ok(Err(keyd::Error::Denied))
    );
    assert_eq!(
        admin.set_secret(&alice, &samples::binding(), pass(), "EXAMPLE.ORGalice"),
        Ok(Err(keyd::Error::Denied))
    );
    // Destruction: on dird's destroy decision only, listed for the sweep
    // until it runs; the id presented again gives the recorded result.
    let destroy = keyd::DecisionId::new(16);
    assert_eq!(admin.destroy_key_set(destroy), Ok(Err(keyd::Error::Denied)));
    assert_eq!(
        ldap.register_decision(
            destroy,
            &keyd::DecidedOperation::DestroyKeySet {
                principal: alice.principal,
            },
            &[],
            3600
        ),
        Ok(Ok(()))
    );
    let page = admin.list_destroy_decisions(None).unwrap();
    assert_eq!(
        page.entries,
        vec![keyd::PendingDestruction {
            decision: destroy,
            principal: alice.principal,
        }]
    );
    assert_eq!(page.next, None);
    assert_eq!(
        directory.list_destroy_decisions(None),
        Err(keyd::Error::Denied)
    );
    assert_eq!(admin.destroy_key_set(destroy), Ok(Ok(())));
    assert_eq!(admin.destroy_key_set(destroy), Ok(Ok(())));
    assert!(admin
        .list_destroy_decisions(None)
        .unwrap()
        .entries
        .is_empty());
    // The ceremony's end (R3): Admin only; afterwards no create_key. Task
    // PN11 (Q-1056, A-188): no seal before the attestation key is installed.
    assert_eq!(ldap.seal_ceremony(), Err(keyd::Error::Denied));
    assert_eq!(admin.seal_ceremony(), Err(keyd::Error::Denied));
    assert_eq!(
        admin.install_attestation_key(samples::attestation_key()),
        Ok(Ok(()))
    );
    assert_eq!(admin.seal_ceremony(), Ok(()));
    let other = samples::handle(0x77, KeyPurpose::Service);
    assert_eq!(
        admin.create_key(&other, &service_binding),
        Ok(Err(keyd::Error::Denied))
    );

    let description = kdc.describe_config().unwrap();
    assert_eq!(description, server.borrow().keyd.config().description());
    assert_eq!(ldap.describe_config().unwrap(), description);
    assert_eq!(directory.describe_config(), Err(keyd::Error::Denied));
    // Q-351 (A-87): each caller is told the role keyd resolved for it.
    for (client, role) in [(&mut kdc, Role::Kdc), (&mut ldap, Role::Ldap)] {
        let described = client.describe_config_with_role().unwrap();
        assert_eq!(described.caller_role, role);
        assert_eq!(described.description, description);
    }
    for (c, role) in [
        (&mut admin, Role::Admin),
        (&mut directory, Role::Directory),
        (&mut kdc, Role::Kdc),
        (&mut ldap, Role::Ldap),
    ] {
        assert_eq!(c.ping(), Ok(role));
    }
    // A service ticket that is not one is keyd's uniform Denied — unbound
    // (0x07), and bound to an operation digest (0x15, Q-523); keyd derives
    // the purpose from each operation's binding (R2).
    assert_eq!(
        ldap.open_and_verify_service_ticket(&service.principal, &[0x30, 0x00]),
        Err(AuthnError::Denied)
    );
    assert_eq!(
        ldap.verify_operation_ticket(
            &service.principal,
            &keyd::OperationDigest::new([0xD4; 32]),
            &[0x30, 0x00]
        ),
        Err(AuthnError::Denied)
    );
    // One connection per client, kept across calls (R50-7).
    assert_eq!(server.borrow().connects, 4);
}

/// docs/50 R50-3, §3.2 ("the client verifies the server's uid … so that a
/// process that captured the socket path receives no password"): a peer
/// that is not keyd's uid, or whose credentials cannot be read, receives
/// nothing; the caller sees `Unavailable`.
#[test]
fn the_client_verifies_the_servers_uid_before_sending() {
    let server = served();
    let mut impostor = KeydClient::new(
        Loopback {
            peer_uid: KEYD_UID + 1,
            ..Loopback::new(&server, DIRECTORY)
        },
        ExpectedPeer::new(KEYD_UID, Role::Directory).unwrap(),
        DEFAULT_DEADLINE,
    );
    let alice = samples::handle(0xA1, KeyPurpose::PrincipalLongterm);
    let pass = Zeroizing::new(String::from(samples::PASSWORD));
    // A state call: not sent, and the fate says so (task R9).
    assert_eq!(
        impostor.set_secret(&alice, &samples::binding(), pass, "EXAMPLE.ORGalice"),
        Err(CallFailure {
            unserved: Unserved::PeerMismatch,
            fate: RequestFate::NotSent,
        })
    );
    let ping = || IssuanceCall::new(ipc_keyd::Call::Ping).unwrap();
    assert_eq!(impostor.call(&ping()), Err(Unserved::PeerMismatch));
    server.borrow_mut().faults.peer_credentials_unreadable = true;
    let mut directory = client(&server, DIRECTORY);
    assert_eq!(
        directory.call(&ping()),
        Err(Unserved::Transport(TransportError::PeerCredentials))
    );
    assert!(server.borrow().received.is_empty(), "nothing was sent");
    assert!(server.borrow().keyd.audit_sink().0.is_empty());

    // uid 0 is never accepted as keyd's (docs/50 §3.2; Q-245 item 5): no
    // expectation, hence no client, can be made with it (task R9).
    assert_eq!(
        ExpectedPeer::new(0, Role::Kdc),
        Err(ClientConfigError::RootServerUid)
    );
}

/// docs/50 §3.6, §3.7 (R50-8); docs/10 §9; Q-217 (A-56); Q-240 item 8: keyd
/// down, a deadline, `Busy`, `Unavailable`, `Malformed`, `VersionMismatch`,
/// a non-canonical reply and a reply of another operation each reach the
/// caller as the `Unavailable` variant of the operation's error type —
/// never `Denied` — and the connection is dropped (the next call
/// reconnects). A state call (`set_secret`) is never answered either: it
/// ends in a `CallFailure` carrying its fate (task R9; the fates
/// themselves: crates/ipc-keyd tests/connection_rules.rs).
#[test]
fn every_transport_failure_is_unavailable() {
    use support::Faults;
    let faults = [
        Faults {
            refuse_connect: true,
            ..Faults::default()
        },
        Faults {
            deadline: true,
            ..Faults::default()
        },
        Faults {
            refuse: Some(Refused::Busy),
            ..Faults::default()
        },
        Faults {
            refuse: Some(Refused::Unavailable),
            ..Faults::default()
        },
        Faults {
            refuse: Some(Refused::Malformed),
            ..Faults::default()
        },
        Faults {
            refuse: Some(Refused::VersionMismatch),
            ..Faults::default()
        },
        Faults {
            trailing_reply_octet: true,
            ..Faults::default()
        },
        Faults {
            foreign_reply: true,
            ..Faults::default()
        },
    ];
    let alice = samples::handle(0xA1, KeyPurpose::PrincipalLongterm);
    for fault in faults {
        let server = served();
        server.borrow_mut().faults = fault;
        let mut kdc = client(&server, KDC);
        let mut directory = client(&server, DIRECTORY);
        assert_eq!(
            kdc.verify_preauth(&alice, &samples::padata(2), None),
            Err(AuthnError::Unavailable),
            "{fault:?}"
        );
        let resolution = samples::resolution(
            samples::name(1, &["alice"]),
            samples::name(1, &["alice"]),
            alice,
            0x9C,
        );
        assert_eq!(
            kdc.issue_as_rep(
                &alice,
                &samples::KRBTGT,
                &samples::proof(),
                None,
                &samples::as_template(false),
                keyd::AsResolutions {
                    client: &resolution,
                    server: None,
                },
            ),
            Err(IssueError::Unavailable),
            "{fault:?}"
        );
        assert_eq!(
            kdc.seal_fast_error(
                &keyd::FastConversation::As(keyd::ArmorId::from_bytes([1; 16])),
                &samples::krb_error(),
                &[]
            ),
            Err(keyd::Error::Unavailable),
            "{fault:?}"
        );
        assert!(
            matches!(
                directory.set_secret(
                    &alice,
                    &samples::binding(),
                    Zeroizing::new(String::from("x")),
                    "EXAMPLE.ORGalice"
                ),
                Err(CallFailure { .. })
            ),
            "{fault:?}"
        );
        // Once keyd is back, the same client reconnects and is served.
        server.borrow_mut().faults = Faults::default();
        assert_eq!(kdc.ping(), Ok(Role::Kdc), "{fault:?}");
    }
}
