//! Tier 1 (docs/50 §9: in-process): the policy file, format 2.
//!
//! The tier-map tests are dird's own tests of format 1 (moved from
//! crates/directory-daemon/tests/startup_files.rs with the decoder, A-68),
//! run on format 2: the behaviour for the tier map is unchanged. The rest
//! covers what format 2 adds: every rule type round-trips; the construction
//! refusals of the rule model fail the whole load (A-51); the format-1 file
//! is refused as superseded; the version is carried into the snapshot;
//! the mandatory-FAST set leads the snapshot (docs/48 §7.2).
//!
//! Sources: docs/50 §3.3 (round trip, one encoding per value), §7.2;
//! docs/11 §3, §6; docs/48 §7.1-§7.3; docs/15 §6; [MS-DTYP] 2.4.2.2; A-36,
//! A-39, A-48, A-51, A-68; docs/questions/Q-270 item 2. Every value is
//! hand-made.

mod common;

use common::*;
use pdp::{
    change_password_as_rules, mandatory_fast_rules, Action, ActionMatch, AuthMatch, ContextMatch,
    Dn, Effect, IpScope, KerbResKind, Match, PolicyVersion, ResourceMatch, Rule, RuleError, RuleId,
    SubjectMatch, Tier, CHANGE_PASSWORD_AS_RULE_COUNT, MANDATORY_FAST_RULE_COUNT,
};
use policy_store::{
    codes, DevelopmentPolicy, PolicyError, FORMAT, MARKER, MAX_POLICY_FILE, RESERVED_RULE_COUNT,
    SUPERSEDED_FORMAT,
};

/// docs/50 §3.3 (round trip; "a single encoding per value"), §7.2; A-36:
/// the policy file round-trips; its first octets are the marker and the
/// format number; every single-octet change is refused or re-encodes to
/// itself (moved from dird, format 1).
#[test]
fn the_development_policy_round_trips_and_is_marked() {
    let policy = sample_policy();
    let file = policy.encode().unwrap();
    assert_eq!(&file[..MARKER.len()], MARKER);
    assert_eq!(file[MARKER.len()], FORMAT);
    assert_eq!(FORMAT, 2);
    assert_eq!(DevelopmentPolicy::decode(&file).unwrap(), policy);
    let empty = minimal_policy(1);
    assert_eq!(
        DevelopmentPolicy::decode(&empty.encode().unwrap()).unwrap(),
        empty
    );
    for at in 0..file.len() {
        for flip in [0x01u8, 0x80] {
            let mut changed = file.clone();
            changed[at] ^= flip;
            if let Ok(decoded) = DevelopmentPolicy::decode(&changed) {
                assert_eq!(decoded.encode().unwrap(), changed, "octet {at}");
            }
        }
    }
}

/// docs/50 §7.2 ("invalid … ⇒ do not start"); Q-270 item 2: an unmarked
/// file, another format, a structure error, a bad or unordered SID, a
/// repeated or empty or malformed DN, an Untiered entry, an oversized file —
/// each refused (moved from dird, format 1, on format 2).
#[test]
fn the_development_policy_refuses_every_broken_tier_map_rule() {
    let file = sample_policy().encode().unwrap();
    let mut unmarked = file.clone();
    unmarked[0] = b'S';
    assert_eq!(
        DevelopmentPolicy::decode(&unmarked),
        Err(PolicyError::NotMarked)
    );
    assert_eq!(DevelopmentPolicy::decode(&[]), Err(PolicyError::NotMarked));
    let mut format = file.clone();
    format[MARKER.len()] = FORMAT + 1;
    assert_eq!(DevelopmentPolicy::decode(&format), Err(PolicyError::Format));
    let mut trailing = file.clone();
    trailing.push(0);
    assert!(matches!(
        DevelopmentPolicy::decode(&trailing),
        Err(PolicyError::Structure(ipc::Error::TrailingBytes))
    ));
    assert!(matches!(
        DevelopmentPolicy::decode(&file[..file.len() - 1]),
        Err(PolicyError::Structure(_))
    ));
    let mut huge = MARKER.to_vec();
    huge.resize(MAX_POLICY_FILE as usize + 1, 0);
    assert_eq!(DevelopmentPolicy::decode(&huge), Err(PolicyError::TooLarge));

    let boot = bootstrap().encode();
    let raw = |principals: &[(Vec<u8>, u8)], subtrees: &[(Vec<&str>, u8)]| {
        raw_file(principals, subtrees, &boot, 100, &[], &[])
    };
    assert!(
        DevelopmentPolicy::decode(&raw(&[(sid(1).encode(), 0)], &[(vec!["ou=A", "dc=x"], 1)]))
            .is_ok()
    );
    let mut bad_revision = sid(1).encode();
    bad_revision[0] = 2;
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[(bad_revision, 0)], &[])),
        Err(PolicyError::Principal)
    );
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[(sid(2).encode(), 0), (sid(1).encode(), 0)], &[])),
        Err(PolicyError::Principal)
    );
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[(sid(1).encode(), 0), (sid(1).encode(), 1)], &[])),
        Err(PolicyError::Principal)
    );
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[(sid(1).encode(), 3)], &[])),
        Err(PolicyError::Untiered)
    );
    assert!(matches!(
        DevelopmentPolicy::decode(&raw(&[(sid(1).encode(), 4)], &[])),
        Err(PolicyError::Structure(ipc::Error::UnknownCode))
    ));
    for dn in [
        vec![],
        vec!["ou"],
        vec!["=x"],
        vec!["ou="],
        vec!["ou=\u{7f}"],
    ] {
        assert_eq!(
            DevelopmentPolicy::decode(&raw(&[], &[(dn.clone(), 1)])),
            Err(PolicyError::Subtree),
            "{dn:?}"
        );
    }
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[], &[(vec!["ou=A"], 1), (vec!["ou=A"], 2)])),
        Err(PolicyError::Subtree)
    );
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[], &[(vec!["ou=A"], 3)])),
        Err(PolicyError::Untiered)
    );
    // The encoder refuses what the decoder refuses.
    let mut untiered = sample_policy();
    untiered.principals.insert(sid(9), Tier::Untiered);
    assert_eq!(untiered.encode(), Err(PolicyError::Untiered));
    let mut empty_dn = sample_policy();
    empty_dn.subtrees.push((Dn::new(Vec::new()), Tier::Tier0));
    assert_eq!(empty_dn.encode(), Err(PolicyError::Subtree));
}

/// A-68 ("the old version refused or migrated, as documented"): a genuine
/// format-1 file — dird's P8 layout, marker ‖ 1 ‖ version ‖ principals ‖
/// subtrees — is refused as superseded, never read as format 2.
#[test]
fn a_format_1_file_is_refused_as_superseded() {
    let mut v1 = MARKER.to_vec();
    v1.push(SUPERSEDED_FORMAT);
    v1.extend_from_slice(&5u64.to_be_bytes());
    v1.extend_from_slice(&0u32.to_be_bytes());
    v1.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(DevelopmentPolicy::decode(&v1), Err(PolicyError::Superseded));
    let mut zero = v1.clone();
    zero[MARKER.len()] = 0;
    assert_eq!(DevelopmentPolicy::decode(&zero), Err(PolicyError::Format));
}

/// docs/11 §3: every matcher variant, both effects and every obligation
/// round-trip through the file exactly.
#[test]
fn every_rule_type_round_trips() {
    let policy = sample_policy();
    let decoded = DevelopmentPolicy::decode(&policy.encode().unwrap()).unwrap();
    assert_eq!(decoded.rules, every_rule_type());
    assert_eq!(decoded.anonymous, vec![root_dse_grant()]);
    assert_eq!(decoded.mandatory_fast, fast());
    // Each rule alone round-trips too.
    for rule in every_rule_type() {
        let mut one = minimal_policy(3);
        one.rules = vec![rule.clone()];
        let back = DevelopmentPolicy::decode(&one.encode().unwrap()).unwrap();
        assert_eq!(back.rules, vec![rule]);
    }
}

/// The layout of the crate documentation, octet by octet: a hand-written
/// rule decodes to the rule it describes (the format is pinned, not only
/// self-consistent).
#[test]
fn a_hand_written_rule_decodes_as_documented() {
    let resource = Raw::default()
        .u8(codes::resource_match::KERBEROS)
        .u8(1) // Some
        .u8(codes::kerberos_kind::TGT)
        .0;
    let rule = Raw::default()
        .u32(7)
        .u8(1) // Deny
        .u8(codes::action_match::EXACT)
        .u8(11) // KdcAs
        .raw(&resource)
        .u8(codes::subject_match::NOT_MEMBER_OF)
        .bytes(&sid(77).encode())
        .u8(0)
        .u8(0)
        .u8(0) // min_transport
        .u8(1)
        .u8(0) // src_net: Some(Internal)
        .u8(0) // time_window: absent
        .u8(1)
        .u8(0) // armored: Some(false)
        .u32(0) // no obligation
        .0;
    let file = raw_file(&[], &[], &bootstrap().encode(), 100, &[rule], &[]);
    let policy = DevelopmentPolicy::decode(&file).unwrap();
    assert_eq!(
        policy.rules,
        vec![Rule {
            id: RuleId(7),
            effect: Effect::Deny,
            when: Match {
                action: ActionMatch::Exact(Action::KdcAs),
                resource: ResourceMatch::Kerberos {
                    kind: Some(KerbResKind::Tgt)
                },
                subject: SubjectMatch::NotMemberOf(sid(77)),
                context: ContextMatch {
                    src_net: Some(IpScope::Internal),
                    ..ContextMatch::ANY
                },
                auth: AuthMatch::UNARMORED,
            },
            obligations: Vec::new(),
        }]
    );
    assert_eq!(policy.encode().unwrap(), file);
}

/// The layout of the crate documentation (`6 Kerberos kind:Option<… | 2
/// ChangePassword>`, wire.rs), octet by octet: the change-password
/// service's resource kind (docs/53 §5.2, task K5) is code 2 with no
/// payload; the next code is unknown and refuses the file (docs/50 §3.3:
/// closed table).
#[test]
fn the_change_password_kind_decodes_as_documented() {
    let resource = |kind: u8| {
        Raw::default()
            .u8(codes::resource_match::KERBEROS)
            .u8(1) // Some
            .u8(kind)
            .0
    };
    let rule = |kind: u8| {
        Raw::default()
            .u32(7)
            .u8(1) // Deny
            .u8(codes::action_match::EXACT)
            .u8(11) // KdcAs
            .raw(&resource(kind))
            .u8(codes::subject_match::ANY)
            .u8(0)
            .u8(0)
            .u8(0) // min_transport
            .u8(0) // src_net: absent
            .u8(0) // time_window: absent
            .u8(1)
            .u8(0) // armored: Some(false)
            .u32(0) // no obligation
            .0
    };
    let file = |kind: u8| raw_file(&[], &[], &bootstrap().encode(), 100, &[rule(kind)], &[]);
    assert_eq!(codes::kerberos_kind::CHANGE_PASSWORD, 2);
    let policy = DevelopmentPolicy::decode(&file(2)).unwrap();
    assert_eq!(
        policy.rules[0].when.resource,
        ResourceMatch::Kerberos {
            kind: Some(KerbResKind::ChangePassword)
        }
    );
    assert_eq!(policy.rules[0].when.auth, AuthMatch::UNARMORED);
    assert_eq!(policy.encode().unwrap(), file(2));
    assert!(matches!(
        DevelopmentPolicy::decode(&file(3)),
        Err(PolicyError::Structure(_))
    ));
}

/// A-51 (crates/pdp policy.rs: "a loader that met a `RuleError` builds no
/// snapshot at all"); Q-164 item 2: a rule over the empty subtree base
/// refuses the whole file — in a rule and in an anonymous grant.
#[test]
fn an_empty_subtree_base_refuses_the_whole_load() {
    let empty_base = Raw::default()
        .u8(codes::resource_match::DIR_SUBTREE)
        .dn(&[])
        .0;
    let good_base = Raw::default()
        .u8(codes::resource_match::DIR_SUBTREE)
        .dn(&["ou=A", "dc=x"])
        .0;
    let boot = bootstrap().encode();
    assert!(DevelopmentPolicy::decode(&raw_file(
        &[],
        &[],
        &boot,
        100,
        &[raw_rule(1, &good_base)],
        &[]
    ))
    .is_ok());
    assert_eq!(
        DevelopmentPolicy::decode(&raw_file(
            &[],
            &[],
            &boot,
            100,
            &[raw_rule(1, &good_base), raw_rule(2, &empty_base)],
            &[]
        )),
        Err(PolicyError::Rule(RuleError::EmptySubtreeBase))
    );
    assert_eq!(
        DevelopmentPolicy::decode(&raw_file(
            &[],
            &[],
            &boot,
            100,
            &[],
            &[raw_grant(&empty_base, 0)]
        )),
        Err(PolicyError::Rule(RuleError::EmptySubtreeBase))
    );
    // A malformed component of a rule subtree is a value fault.
    let bad_component = Raw::default()
        .u8(codes::resource_match::DIR_SUBTREE)
        .dn(&["ou"])
        .0;
    assert_eq!(
        DevelopmentPolicy::decode(&raw_file(
            &[],
            &[],
            &boot,
            100,
            &[raw_rule(1, &bad_component)],
            &[]
        )),
        Err(PolicyError::RuleValue)
    );
}

/// A-51 (Q-170 item 3: External is forbidden in the anonymous allowlist);
/// docs/15 §6 ("only these, from the internal network"): an anonymous grant
/// for External, or over every resource, refuses the whole file.
#[test]
fn an_external_or_unbounded_anonymous_grant_refuses_the_whole_load() {
    let root_dse = Raw::default().u8(codes::resource_match::ROOT_DSE).0;
    let any = Raw::default().u8(codes::resource_match::ANY).0;
    let boot = bootstrap().encode();
    let internal = codes::ip_scope(IpScope::Internal);
    let external = codes::ip_scope(IpScope::External);
    let ok = DevelopmentPolicy::decode(&raw_file(
        &[],
        &[],
        &boot,
        100,
        &[],
        &[raw_grant(&root_dse, internal)],
    ))
    .unwrap();
    assert_eq!(ok.anonymous, vec![root_dse_grant()]);
    assert_eq!(
        DevelopmentPolicy::decode(&raw_file(
            &[],
            &[],
            &boot,
            100,
            &[],
            &[
                raw_grant(&root_dse, internal),
                raw_grant(&root_dse, external)
            ]
        )),
        Err(PolicyError::Rule(RuleError::AnonymousExternalNetwork))
    );
    assert_eq!(
        DevelopmentPolicy::decode(&raw_file(
            &[],
            &[],
            &boot,
            100,
            &[],
            &[raw_grant(&any, internal)]
        )),
        Err(PolicyError::Rule(RuleError::UnboundedAnonymousResource))
    );
    // An unknown network code is a structure fault.
    assert!(matches!(
        DevelopmentPolicy::decode(&raw_file(
            &[],
            &[],
            &boot,
            100,
            &[],
            &[raw_grant(&root_dse, 2)]
        )),
        Err(PolicyError::Structure(ipc::Error::UnknownCode))
    ));
}

/// Values inside rules: an undecodable SID, a non-printable or empty or
/// overlong text, a reversed time window — each refuses the file
/// (fail closed); unknown codes are structure faults.
#[test]
fn bad_rule_values_are_refused() {
    let boot = bootstrap().encode();
    let file_with = |rule: Vec<u8>| raw_file(&[], &[], &boot, 100, &[rule], &[]);
    let with_subject = |subject: Vec<u8>| {
        Raw::default()
            .u32(1)
            .u8(0)
            .u8(0)
            .u8(codes::resource_match::ANY)
            .raw(&subject)
            .u8(0)
            .u8(0)
            .u8(0)
            .u8(0)
            .u8(0)
            .u8(0)
            .u32(0)
            .0
    };
    let mut bad_sid = sid(5).encode();
    bad_sid.push(0); // trailing octet inside the packet
    assert_eq!(
        DevelopmentPolicy::decode(&file_with(with_subject(
            Raw::default()
                .u8(codes::subject_match::MEMBER_OF)
                .bytes(&bad_sid)
                .0
        ))),
        Err(PolicyError::RuleValue)
    );
    for text in [&b""[..], b"tab\there", b"caf\xc3\xa9", &[b'a'; 1025][..]] {
        let share = Raw::default().u8(codes::resource_match::FILE).bytes(text).0;
        let result = DevelopmentPolicy::decode(&file_with(raw_rule(1, &share)));
        assert!(
            matches!(
                result,
                Err(PolicyError::RuleValue)
                    | Err(PolicyError::Structure(ipc::Error::LengthOverBound))
            ),
            "{result:?}"
        );
    }
    let reversed = Raw::default()
        .u32(1)
        .u8(0)
        .u8(0)
        .u8(codes::resource_match::ANY)
        .u8(codes::subject_match::ANY)
        .u8(0)
        .u8(0)
        .u8(0)
        .u8(0)
        .u8(1)
        .u64(20)
        .u64(10)
        .u8(0)
        .u32(0)
        .0;
    assert_eq!(
        DevelopmentPolicy::decode(&file_with(reversed)),
        Err(PolicyError::RuleValue)
    );
    for unknown_resource in [8u8, 0xFF] {
        assert!(matches!(
            DevelopmentPolicy::decode(&file_with(raw_rule(1, &[unknown_resource]))),
            Err(PolicyError::Structure(ipc::Error::UnknownCode))
        ));
    }
    // Encoder side: a text the decoder refuses is not written.
    let mut policy = minimal_policy(1);
    policy.rules = vec![Rule {
        id: RuleId(1),
        effect: Effect::Allow,
        when: Match {
            action: ActionMatch::Any,
            resource: ResourceMatch::File {
                share: pdp::ShareId(String::new()),
            },
            subject: SubjectMatch::Any,
            context: ContextMatch::ANY,
            auth: AuthMatch::ANY,
        },
        obligations: Vec::new(),
    }];
    assert_eq!(policy.encode(), Err(PolicyError::RuleValue));
}

/// Rule ids identify the rule in the audit record of a coarse deny (crates/
/// pdp policy.rs): unique, and outside the range of the default Kerberos
/// rule set — the mandatory-FAST set and, after it, the change-password
/// service's AS set (task K5; docs/53 §5.2) — which must fit in `u32`.
#[test]
fn rule_ids_are_unique_and_clear_of_the_fast_range() {
    let any = Raw::default().u8(codes::resource_match::ANY).0;
    let boot = bootstrap().encode();
    let ids = |rules: &[u32], first: u32| {
        let raw: Vec<Vec<u8>> = rules.iter().map(|id| raw_rule(*id, &any)).collect();
        DevelopmentPolicy::decode(&raw_file(&[], &[], &boot, first, &raw, &[]))
    };
    assert_eq!(
        RESERVED_RULE_COUNT,
        MANDATORY_FAST_RULE_COUNT + CHANGE_PASSWORD_AS_RULE_COUNT
    );
    assert!(ids(&[1, 2, 99, 100 + RESERVED_RULE_COUNT], 100).is_ok());
    assert_eq!(ids(&[1, 1], 100), Err(PolicyError::RuleId));
    for inside in 100..100 + RESERVED_RULE_COUNT {
        assert_eq!(ids(&[inside], 100), Err(PolicyError::RuleId), "{inside}");
    }
    assert_eq!(
        ids(&[], u32::MAX - (RESERVED_RULE_COUNT - 2)),
        Err(PolicyError::Bootstrap)
    );
    assert!(ids(&[], u32::MAX - (RESERVED_RULE_COUNT - 1)).is_ok());
    // The bootstrap packet must be a SID.
    assert_eq!(
        DevelopmentPolicy::decode(&raw_file(&[], &[], &[1, 0], 100, &[], &[])),
        Err(PolicyError::Bootstrap)
    );
}

/// docs/11 §6 (P9, D39); docs/50 §3.4 (the version every view carries);
/// docs/48 §7.2 (the mandatory-FAST set is policy data); docs/53 §5.2 (task
/// K5: the change-password service's AS set, for the same group, after
/// it): the snapshot has the file's version, the FAST set of the bootstrap
/// group first, then the change-password set, then the file's rules in
/// order, and the anonymous allowlist.
#[test]
fn the_snapshot_carries_the_version_the_fast_set_and_the_rules() {
    let policy = sample_policy();
    let decoded = DevelopmentPolicy::decode(&policy.encode().unwrap()).unwrap();
    assert_eq!(decoded.version, PolicyVersion(42));
    let snapshot = decoded.snapshot().unwrap();
    assert_eq!(snapshot.version(), PolicyVersion(42));
    let mut fast = mandatory_fast_rules(bootstrap(), RuleId(100)).unwrap();
    assert_eq!(fast.len(), MANDATORY_FAST_RULE_COUNT as usize);
    fast.extend(
        change_password_as_rules(bootstrap(), RuleId(100 + MANDATORY_FAST_RULE_COUNT)).unwrap(),
    );
    let count = fast.len();
    assert_eq!(count, RESERVED_RULE_COUNT as usize);
    assert_eq!(decoded.mandatory_fast.rules().unwrap(), fast);
    assert_eq!(&snapshot.rules()[..count], fast.as_slice());
    assert_eq!(&snapshot.rules()[count..], every_rule_type().as_slice());
    assert_eq!(snapshot.anonymous_allowlist(), &[root_dse_grant()]);
    // Another version, another snapshot version.
    let mut other = minimal_policy(43);
    other.rules = vec![every_rule_type()[0].clone()];
    let snapshot = DevelopmentPolicy::decode(&other.encode().unwrap())
        .unwrap()
        .snapshot()
        .unwrap();
    assert_eq!(snapshot.version(), PolicyVersion(43));
    assert_eq!(snapshot.rules().len(), count + 1);
}
