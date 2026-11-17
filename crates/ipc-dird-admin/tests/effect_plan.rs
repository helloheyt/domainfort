//! The effect plan's canonical form and the plan protocol on the wire (task
//! MA2): one encoding per plan, every canonical rule enforced by the
//! decoder, the digest a `Commit` names covering the plan, and no frame that
//! executes a planned operation without one.
//!
//! Sources (project documents, opened in this session): docs/research/
//! r5-a-admin-model.md §3.3 (`PlanOperation`, `EffectPlan`, `Commit` with
//! `OperationDigest = H(op ‖ fields ‖ plan.digest)`); docs/questions/Q-874
//! items 1-3; docs/50 §3.3 (one encoding per value, closed tables, no
//! trailing octet); FIPS 180-4 (SHA-256 through the approved `sha2`); this
//! crate's own layout (crate::plan module documentation); docs/59 §4.2 (a
//! key's form: printable ASCII, folded), §4.4 N1 (one holder per key), §4.6,
//! §10 (PN7); docs/questions/Q-1008 item 2, Q-1037 (`NamesReleased`). The
//! plans are this test's own data.

use dtyp::{Guid, Sid, SECURITY_NT_AUTHORITY};
use ipc_dird_admin::channel::{
    request_kind, MAX_PLAN, MAX_PLAN_RELEASED_NAME, MAX_PLAN_RELEASED_NAMES,
};
use ipc_dird_admin::{
    operation_digest, plan_digest, Auth, ConversionError, Effect, EffectPlan, KeyOperation,
    Operation, PlanError, PlanPrincipal, PlanPrincipalKind, PlanTier, PolicyReferenceKind, Reply,
    Request, RevocationKind, PLAN_DIGEST_LABEL,
};
use std::collections::BTreeSet;

fn sid(rid: u32) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, rid]).unwrap()
}

fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0x5A,
        data3: 0x0007,
        data4: [7; 8],
    }
}

fn user(rid: u32, name: &str) -> PlanPrincipal {
    PlanPrincipal {
        sid: sid(rid),
        guid: guid(rid),
        kind: PlanPrincipalKind::User,
        name: name.into(),
    }
}

fn group(rid: u32, name: &str) -> PlanPrincipal {
    PlanPrincipal {
        kind: PlanPrincipalKind::Group,
        ..user(rid, name)
    }
}

fn set(rids: &[u32]) -> BTreeSet<Sid> {
    rids.iter().map(|r| sid(*r)).collect()
}

fn names(keys: &[&str]) -> BTreeSet<String> {
    keys.iter().map(|k| (*k).to_owned()).collect()
}

/// A plan of every effect kind.
fn every_effect() -> EffectPlan {
    EffectPlan::new(
        [
            user(1101, "carol"),
            user(1102, "dave"),
            user(1103, "Erin"),
            group(1201, "tier0"),
            group(1202, "project"),
        ],
        [
            Effect::MembershipDelta {
                gained: set(&[1201]),
                lost: set(&[]),
                principals: set(&[1101, 1102, 1202]),
            },
            Effect::TierDelta {
                subject: (PlanTier::None, PlanTier::Tier0),
                object: (PlanTier::None, PlanTier::Tier0),
                principals: set(&[1101, 1102]),
            },
            Effect::PolicyReference {
                reference: PolicyReferenceKind::TierMap(PlanTier::Tier0),
                principals: set(&[1201]),
            },
            Effect::TicketsRevoked {
                kind: RevocationKind::PasswordSet,
                principals: set(&[1101]),
            },
            Effect::ProtectedDataLoss {
                principals: set(&[1101]),
            },
            Effect::KeyDestruction {
                kvno: Some(3),
                principals: set(&[1102]),
            },
            Effect::NamesReleased {
                names: names(&["erin"]),
                principals: set(&[1103]),
            },
        ],
    )
    .unwrap()
}

/// Canonical: the plan decodes from its own encoding into the same plan,
/// re-encodes to the same octets, and its digest is SHA-256 over the label
/// and those octets; the input order of principals and effects does not
/// matter (the constructor sorts), so equal plans have equal bytes.
#[test]
fn a_plan_has_one_encoding_and_its_digest() {
    let plan = every_effect();
    let bytes = plan.encode().unwrap();
    assert_eq!(EffectPlan::decode(&bytes).unwrap(), plan);
    use sha2::{Digest, Sha256};
    let mut input = PLAN_DIGEST_LABEL.to_vec();
    input.extend(&bytes);
    assert_eq!(
        plan_digest(&bytes),
        <[u8; 32]>::from(Sha256::digest(&input))
    );
    assert_eq!(plan.digest().unwrap(), plan_digest(&bytes));
    // The same effects and principals in another order: the same bytes.
    let mut effects = plan.effects().to_vec();
    effects.reverse();
    let mut principals = plan.principals().to_vec();
    principals.reverse();
    let again = EffectPlan::new(principals, effects).unwrap();
    assert_eq!(again.encode().unwrap(), bytes);
    // The empty plan: the layout octet and two empty sequences.
    assert_eq!(
        EffectPlan::empty().encode().unwrap(),
        vec![1, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

/// The constructor and the decoder refuse what breaks a canonical rule: an
/// effect without principals, a `MembershipDelta` that changes nothing or
/// gains and loses the same group, a `TierDelta` that changes no tier, a
/// tier-map reference without a tier, two effects with one head, a SID no
/// principal names, a name that is not printable ASCII.
#[test]
fn non_canonical_plans_are_refused() {
    let carol = || user(1101, "carol");
    let malformed = |effects: Vec<Effect>| EffectPlan::new([carol(), group(1201, "g")], effects);
    for effects in [
        vec![Effect::ProtectedDataLoss {
            principals: set(&[]),
        }],
        vec![Effect::MembershipDelta {
            gained: set(&[]),
            lost: set(&[]),
            principals: set(&[1101]),
        }],
        vec![Effect::MembershipDelta {
            gained: set(&[1201]),
            lost: set(&[1201]),
            principals: set(&[1101]),
        }],
        vec![Effect::TierDelta {
            subject: (PlanTier::Tier1, PlanTier::Tier1),
            object: (PlanTier::None, PlanTier::None),
            principals: set(&[1101]),
        }],
        vec![Effect::PolicyReference {
            reference: PolicyReferenceKind::TierMap(PlanTier::None),
            principals: set(&[1201]),
        }],
        vec![
            Effect::ProtectedDataLoss {
                principals: set(&[1101]),
            },
            Effect::ProtectedDataLoss {
                principals: set(&[1201]),
            },
        ],
        vec![Effect::ProtectedDataLoss {
            principals: set(&[1999]),
        }],
    ] {
        assert_eq!(
            malformed(effects.clone()),
            Err(PlanError::Malformed),
            "{effects:?}"
        );
    }
    let mut bad_name = carol();
    bad_name.name = "caröl".into();
    assert_eq!(
        EffectPlan::new(
            [bad_name],
            [Effect::ProtectedDataLoss {
                principals: set(&[1101]),
            }]
        ),
        Err(PlanError::Malformed)
    );
}

/// The decoder enforces the layout octet by octet: another layout, a
/// trailing octet, an unknown tag or code, principals out of order, a
/// principal no effect names — each refused; nothing is a second spelling.
#[test]
fn the_decoder_is_strict() {
    let bytes = every_effect().encode().unwrap();
    // Another layout.
    let mut other = bytes.clone();
    other[0] = 2;
    assert_eq!(EffectPlan::decode(&other), Err(PlanError::Malformed));
    // A trailing octet; a truncated plan.
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(EffectPlan::decode(&longer).is_err());
    assert!(EffectPlan::decode(&bytes[..bytes.len() - 1]).is_err());
    // A principal no effect names (the empty plan plus one principal).
    let mut unnamed = vec![1];
    unnamed.extend(1u32.to_be_bytes());
    let packet = sid(1101).encode();
    unnamed.extend((packet.len() as u32).to_be_bytes());
    unnamed.extend(&packet);
    unnamed.extend(guid(1101).to_packet());
    unnamed.push(1);
    unnamed.extend(5u32.to_be_bytes());
    unnamed.extend(b"carol");
    unnamed.extend(0u32.to_be_bytes());
    assert_eq!(EffectPlan::decode(&unnamed), Err(PlanError::Malformed));
    // An unknown effect tag: the first effect of a one-effect plan.
    let one = EffectPlan::new(
        [user(1101, "carol")],
        [Effect::ProtectedDataLoss {
            principals: set(&[1101]),
        }],
    )
    .unwrap()
    .encode()
    .unwrap();
    let tag_at = one.len() - (4 + 4 + packet.len()) - 1;
    assert_eq!(one[tag_at], 5);
    // 7 is `NamesReleased` (task PN7); 8 is the first unknown tag.
    for tag in [0u8, 8, 0xFF] {
        let mut bad = one.clone();
        bad[tag_at] = tag;
        assert!(EffectPlan::decode(&bad).is_err(), "tag {tag}");
    }
    // Over the bound.
    assert_eq!(
        EffectPlan::decode(&vec![0; MAX_PLAN + 1]),
        Err(PlanError::TooLarge)
    );
}

/// A closure beyond the plan's bounds is not a plan (`TooLarge`): the PEP
/// refuses such an operation (`PlanTooLarge`, fail closed).
#[test]
fn a_plan_beyond_its_bounds_is_too_large() {
    let principals: Vec<PlanPrincipal> = (0..300).map(|i| user(5000 + i, "u")).collect();
    let all: BTreeSet<Sid> = principals.iter().map(|p| p.sid).collect();
    assert_eq!(
        EffectPlan::new(principals, [Effect::ProtectedDataLoss { principals: all }]),
        Err(PlanError::TooLarge)
    );
}

/// Task PN7 (docs/59 §10; Q-1037): a `NamesReleased` has one form — the
/// names of exactly one principal, non-empty, each in a namespace key's form
/// (printable ASCII without `A`-`Z`, docs/59 §4.2); no principal and no name
/// in two of them (one holder per key, docs/59 §4.4 N1); within its bounds
/// (36 names of at most 2048 octets — Q-1008 item 2); and the digest covers
/// every name.
#[test]
fn released_names_have_one_form_and_their_bounds() {
    let plan =
        |effects: Vec<Effect>| EffectPlan::new([user(1103, "erin"), user(1104, "frank")], effects);
    let released = |keys: &[&str], rids: &[u32]| Effect::NamesReleased {
        names: names(keys),
        principals: set(rids),
    };
    // A computer's keys — sAMAccountName, base name, SPN, host name.
    let computer = [
        "erin$",
        "erin",
        "host/erin.example.test",
        "erin.example.test",
    ];
    let ok = plan(vec![released(&computer, &[1103])]).unwrap();
    let bytes = ok.encode().unwrap();
    assert_eq!(EffectPlan::decode(&bytes).unwrap(), ok);
    // The digest covers the names: two names fewer, another digest.
    let fewer = plan(vec![released(&computer[..2], &[1103])]).unwrap();
    assert_ne!(fewer.digest().unwrap(), ok.digest().unwrap());
    // Two holders, each with its own names.
    assert!(plan(vec![
        released(&["erin"], &[1103]),
        released(&["frank"], &[1104])
    ])
    .is_ok());
    for effects in [
        vec![released(&[], &[1103])],
        vec![released(&[""], &[1103])],
        vec![released(&["erin"], &[1103, 1104])],
        vec![released(&["Erin"], &[1103])],
        vec![released(&["erin\n"], &[1103])],
        vec![released(&["er\u{7f}in"], &[1103])],
        vec![released(&["érin"], &[1103])],
        // One holder in two effects.
        vec![released(&["erin"], &[1103]), released(&["erin$"], &[1103])],
        // One name, two holders.
        vec![
            released(&["erin"], &[1103]),
            released(&["erin", "frank"], &[1104]),
        ],
    ] {
        assert_eq!(
            plan(effects.clone()),
            Err(PlanError::Malformed),
            "{effects:?}"
        );
    }
    // The bounds: a name of 2048 octets, 36 names.
    let longest = "a".repeat(MAX_PLAN_RELEASED_NAME as usize);
    assert!(plan(vec![released(&[&longest], &[1103])]).is_ok());
    let longer = "a".repeat(MAX_PLAN_RELEASED_NAME as usize + 1);
    assert_eq!(
        plan(vec![released(&[&longer], &[1103])]),
        Err(PlanError::TooLarge)
    );
    let many: Vec<String> = (0..=MAX_PLAN_RELEASED_NAMES)
        .map(|i| format!("n{i}"))
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert!(plan(vec![released(&many[1..], &[1103])]).is_ok());
    assert_eq!(
        plan(vec![released(&many, &[1103])]),
        Err(PlanError::TooLarge)
    );
}

/// The decoder holds released names to their form octet by octet: out of
/// order, repeated, or with an upper-case letter — refused; nothing is a
/// second spelling (docs/50 §3.3).
#[test]
fn the_decoder_holds_released_names_to_their_form() {
    let plan = EffectPlan::new(
        [user(1103, "erin")],
        [Effect::NamesReleased {
            names: names(&["a", "b"]),
            principals: set(&[1103]),
        }],
    )
    .unwrap();
    let bytes = plan.encode().unwrap();
    assert_eq!(EffectPlan::decode(&bytes).unwrap(), plan);
    // The head: tag 7, two names of one octet each (u32 counts and lengths).
    let head = [7u8, 0, 0, 0, 2, 0, 0, 0, 1, b'a', 0, 0, 0, 1, b'b'];
    let at = bytes
        .windows(head.len())
        .position(|w| w == head)
        .expect("the head");
    for (first, second) in [(b'b', b'a'), (b'a', b'a'), (b'a', b'B')] {
        let mut bad = bytes.clone();
        bad[at + 9] = first;
        bad[at + 14] = second;
        assert_eq!(
            EffectPlan::decode(&bad),
            Err(PlanError::Malformed),
            "{first} {second}"
        );
    }
}

/// No second path (r5-a §3.3): the planned kinds are not requests of their
/// own — a bare frame of one is an unknown kind and does not encode — they
/// travel inside `PlanOperation` and `Commit`; a `Commit` of a key operation
/// only inside a `Propose`.
#[test]
fn a_planned_operation_has_no_frame_without_its_plan() {
    let auth = || Auth::of(vec![0x6E; 40]);
    for kind in request_kind::PLANNED {
        assert!(!request_kind::ALL.contains(kind), "{kind:#x}");
    }
    let disable = Operation::SetEnabled {
        target: guid(1),
        enabled: false,
    };
    let bare = Request::Operation {
        auth: auth(),
        operation: disable.clone(),
    };
    assert!(ipc::encode_frame(
        ipc_dird_admin::ADMIN_CHANNEL,
        ipc::Direction::Request,
        &bare.to_wire().unwrap()
    )
    .is_err());
    for operation in [
        Operation::PlanOperation(Box::new(disable.clone())),
        Operation::Commit {
            plan: [9; 32],
            operation: Box::new(disable.clone()),
        },
        Operation::Propose {
            reason_ref: None,
            operation: Box::new(Operation::Commit {
                plan: [9; 32],
                operation: Box::new(Operation::KeyOperation(KeyOperation::RotateKrbtgt)),
            }),
        },
    ] {
        let request = Request::Operation {
            auth: auth(),
            operation,
        };
        let frame = ipc::encode_frame(
            ipc_dird_admin::ADMIN_CHANNEL,
            ipc::Direction::Request,
            &request.to_wire().unwrap(),
        )
        .unwrap();
        assert_eq!(
            ipc_dird_admin::decode_request(frame.body()).unwrap(),
            request
        );
    }
    // A key operation's `Commit` at top level: no frame.
    let alone = Request::Operation {
        auth: auth(),
        operation: Operation::Commit {
            plan: [9; 32],
            operation: Box::new(Operation::KeyOperation(KeyOperation::RotateKrbtgt)),
        },
    };
    assert!(ipc::encode_frame(
        ipc_dird_admin::ADMIN_CHANNEL,
        ipc::Direction::Request,
        &alone.to_wire().unwrap()
    )
    .is_err());
    // A `Propose` of a bare planned operation: no frame either.
    let proposed = Request::Operation {
        auth: auth(),
        operation: Operation::Propose {
            reason_ref: None,
            operation: Box::new(disable),
        },
    };
    assert!(ipc::encode_frame(
        ipc_dird_admin::ADMIN_CHANNEL,
        ipc::Direction::Request,
        &proposed.to_wire().unwrap()
    )
    .is_err());
}

/// r5-a §3.3: the operation digest of a `Commit` covers the plan digest —
/// another plan, another digest (what the requester's AP-REQ and the
/// approvers' `Approve` bind); and it is not the bare operation's digest.
#[test]
fn the_commit_digest_covers_the_plan() {
    let add = Operation::AddMember {
        group: guid(1),
        member: guid(2),
    };
    let commit = |plan: [u8; 32]| Operation::Commit {
        plan,
        operation: Box::new(add.clone()),
    };
    let a = operation_digest(&commit([1; 32])).unwrap();
    let b = operation_digest(&commit([2; 32])).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, operation_digest(&add).unwrap());
    assert_ne!(
        operation_digest(&Operation::PlanOperation(Box::new(add.clone()))).unwrap(),
        a
    );
}

/// A client renders exactly what is bound: a `Plan` reply whose digest is
/// not its plan's, and a shown request whose plan is not the one its
/// `Commit` names, do not convert (`ConversionError::Plan`).
#[test]
fn plans_are_checked_against_their_digests_when_received() {
    let plan = every_effect();
    let wrong = ipc_dird_admin::AdminReply::Plan {
        plan: plan.encode().unwrap(),
        digest: [0; 32],
    };
    assert_eq!(Reply::from_wire(&wrong), Err(ConversionError::Plan));
    let right = ipc_dird_admin::AdminReply::Plan {
        plan: plan.encode().unwrap(),
        digest: plan.digest().unwrap(),
    };
    assert_eq!(
        Reply::from_wire(&right).unwrap(),
        Reply::Plan {
            plan: plan.clone(),
            digest: plan.digest().unwrap()
        }
    );
    let shown = |commit_plan: [u8; 32], plan: Option<EffectPlan>| {
        Reply::RequestShown(Box::new(ipc_dird_admin::RequestShown {
            id: 1,
            digest: [3; 32],
            state: ipc_dird_admin::RequestState::Pending,
            requester: sid(1101),
            approvers: vec![],
            quorum: 2,
            expires: 9,
            reason_ref: None,
            operation: Operation::Commit {
                plan: commit_plan,
                operation: Box::new(Operation::Delete { target: guid(5) }),
            },
            facts: vec![],
            plan,
        }))
    };
    assert_eq!(
        shown([0; 32], Some(plan.clone())).to_wire(),
        Err(ConversionError::Plan)
    );
    assert_eq!(
        shown(plan.digest().unwrap(), None).to_wire(),
        Err(ConversionError::Plan)
    );
    let good = shown(plan.digest().unwrap(), Some(plan));
    let wire = good.to_wire().unwrap();
    assert_eq!(Reply::from_wire(&wire).unwrap(), good);
}
