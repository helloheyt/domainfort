//! `DnsSelfUpdate` end to end (task DN6): the signer's own host decided
//! from its verified identity, the new address set judged, written through
//! the one write checker with the zone serial taken in the same
//! transaction, and seen by the zone projection.
//!
//! Source: docs/54 §4.5 (the write path: Subject only from the verified
//! signer, the target its own computer, PDP `DnsUpdate`, `DnsSelfUpdate`
//! through the one checker with `take_counter_value("dns-zone-serial")` in
//! the same `WriteTxn`, audit acknowledged before the commit), §5.2 (the
//! record is an attribute of the owner; dies with it), §5.3 (one LDH label,
//! `<computerName>.<zone>`), §5.4 (SERIAL; 0 skipped), §5.5 (users never;
//! structural accounts never; ≤ 8 addresses inside the registrable
//! networks, never loopback/unspecified/multicast; a duplicate changes
//! nothing), §5.6 (the owner's tier); docs/questions/Q-614 items 2, 3, 5-8;
//! RFC 2136 §2.5.1 ("silently ignored"), §3.6 ("If the zone appears to
//! change, the SOA must appear to change as well"), §7.11 (never zero);
//! [MS-ADTS] v20261026 3.1.1.5.3.1.1.2; RFC 1035 §3.4.1. The domain is the
//! shared fixture (tests/common); the extra computers, addresses and times
//! are this project's own test data, each time derived in a comment. No
//! vector or fixture comes from any other implementation.

mod common;

use std::net::{IpAddr, Ipv4Addr};

use common::*;
use config::Network;
use directory_admin::{
    AppliedDnsUpdate, DnsHostUpdate, DnsRegistration, DnsUpdateFailure, DnsUpdateRefusal,
    DnsUpdateTicket, Operation, SetEnabled, CHANGE_SEQ_COUNTER, DNS_ZONE_SERIAL_COUNTER,
};
use directory_pip::{
    host_address_value, DnsName, KpasswdService, SoaParameters, ZoneParameters, HOST_ADDRESS,
};
use dirstore::{NewObject, Origin};
use ipc_audit::{EventBody, WindowSummary};
use krb_proto::constants::KRB_NT_PRINCIPAL;
use krb_proto::{KerberosString, KerberosTime, PrincipalName};
use pdp::{ReasonCode, Tier};

/// Extra computers of these tests (GUID = `guid(id)`), outside the shared
/// fixture's RID order: their objectSids use RIDs 5000+ directly (the raw
/// store takes them as given).
const WS02: u32 = 60;
const WS03: u32 = 61;

fn a(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, last)
}

/// The registrable network of the tests: 192.0.2.0/24.
fn registration() -> DnsRegistration {
    DnsRegistration::new(vec![Network::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
        24,
    )
    .unwrap()])
    .unwrap()
}

/// The standard domain with DNS self-updates enabled, ou=Staff classified
/// Tier2 (so ws01 is not Tier0), and a policy rule granting `DnsUpdate` on
/// example.test; then — in one raw transaction, as provisioning would —
/// the zone serial counter (first value `first`), dc01's address
/// (192.0.2.1) and the extra computers: ws02$ whose dNSHostName is
/// web.example.test, and w_3$ whose computerName is no LDH label.
fn dns_domain(test: &str, first: u64) -> Domain {
    let d = Domain::with_extra(
        test,
        Extra {
            staff_tier: Some(Tier::Tier2),
            dns: Some(registration()),
            dns_rule: true,
            ..Extra::default()
        },
    );
    dns_store(&d, first);
    d
}

fn dns_store(d: &Domain, first: u64) {
    let mut txn = d.store.begin_write().unwrap();
    txn.create_counter(DNS_ZONE_SERIAL_COUNTER, first, u64::MAX)
        .unwrap();
    let seq =
        |txn: &mut dirstore::WriteTxn<'_>| txn.take_counter_value(CHANGE_SEQ_COUNTER).unwrap();
    let at = directory_admin::wall_clock(&provisioned_at()).unwrap();
    let o = |s| Origin {
        wall_clock: at,
        origin_node: NODE_ID,
        origin_seq: s,
    };
    let s = seq(&mut txn);
    txn.modify_object(
        guid(DC01),
        vec![dirstore::AttributeChange::Replace {
            id: HOST_ADDRESS,
            values: vec![host_address_value(a(1))],
        }],
        &o(s),
    )
    .unwrap();
    let text = |s: &str| vec![s.as_bytes().to_vec()];
    let mut created = Vec::new();
    for (id, rid_value, cn, host) in [
        (WS02, 5002u32, "ws02", "web.example.test"),
        (WS03, 5003u32, "w_3", "w_3.example.test"),
    ] {
        let class = d.p1.class(d.p1.class_by_name("computer").unwrap()).unwrap();
        let attributes = vec![
            (d.attr("cn"), text(cn)),
            (d.attr("sAMAccountName"), text(&format!("{cn}$"))),
            (d.attr("objectSid"), vec![account_sid(rid_value).encode()]),
            (
                d.attr("userAccountControl"),
                vec![flags(
                    ad_schema::flags::user_account_control::ADS_UF_WORKSTATION_TRUST_ACCOUNT,
                )],
            ),
            (d.attr("accountExpires"), vec![int64(i64::MAX)]),
            (
                d.attr("pwdLastSet"),
                vec![int64(PROVISIONED_DSTIME * 10_000_000)],
            ),
            (d.attr("whenCreated"), vec![int64(PROVISIONED_DSTIME)]),
            (d.attr("dNSHostName"), text(host)),
            (
                d.attr("nTSecurityDescriptor"),
                vec![child_sd(&root_sd(), class.schema_id_guid).encode().unwrap()],
            ),
        ];
        let s = seq(&mut txn);
        created.push((guid(id), o(s)));
        txn.create_object(
            NewObject {
                guid: guid(id),
                parent: Some(guid(STAFF_OU)),
                classes: class.object_class.clone(),
                attributes,
            },
            &o(s),
        )
        .unwrap();
    }
    // Written beneath the checker (which refuses both since rule N6), they
    // carry the namespace keys their names give (tests/common `namespace`;
    // task PN4b), so the signer's lookup by name reaches them and the DNS
    // rule itself is what refuses them.
    namespace::write_namespace_keys(&d.store, &mut txn, &d.ctx, &created);
    txn.commit().unwrap();
}

/// The verified signer `sam` (one component, the realm): the facts dird's
/// DNS PEP passes after keyd verified the MIC (docs/54 §7.5 step 2).
fn signer(sam: &str) -> DnsUpdateTicket {
    DnsUpdateTicket {
        crealm: realm(),
        cname: PrincipalName {
            name_type: KRB_NT_PRINCIPAL,
            name_string: vec![KerberosString::new(sam).unwrap()],
        },
        authtime: authtime(),
    }
}

fn update(addresses: &[Ipv4Addr], renewed: &[Ipv4Addr]) -> DnsHostUpdate {
    DnsHostUpdate {
        addresses: addresses.to_vec(),
        renewed: renewed.to_vec(),
    }
}

/// The stand-in decision event of these tests: the real one is the `Dns`
/// shape of docs/54 §9 (task DN12, not built yet); what matters here is
/// that a real audit client delivered it and a (fake) auditd acknowledged
/// it before the write (docs/52 R6).
fn decision_event() -> EventBody {
    EventBody::WindowSummary(WindowSummary {
        suppressed_noise: 0,
        refused_gating: 0,
        unrecorded_outcomes: 0,
    })
}

/// One self-update at `at`: begin the `WriteTxn`, take the view, decide the
/// host, judge the update, have the decision acknowledged, apply, commit
/// (or abort on a refusal). `Ok(None)`: nothing to write.
fn run(
    d: &Domain,
    sam: &str,
    up: &DnsHostUpdate,
    at: &KerberosTime,
) -> Result<Option<AppliedDnsUpdate>, DnsUpdateRefusal> {
    let mut txn = d.store.begin_write().expect("begin write");
    let view = d.ctx.view(&d.store, &d.tiers).expect("view");
    let host = d
        .admin
        .dns_update_host(&signer(sam), &view, &d.policy, at)?;
    let Some(prepared) = d.admin.prepare_dns_self_update(host, up)? else {
        txn.abort().unwrap();
        return Ok(None);
    };
    drop(view);
    let acked = linked::acknowledged(prepared.with_intent(decision_event()));
    match d.admin.apply_dns_self_update(acked, &mut txn, at) {
        Ok(applied) => {
            txn.commit().expect("commit");
            Ok(Some(applied))
        }
        Err(refusal) => {
            txn.abort().expect("abort");
            Err(refusal)
        }
    }
}

/// The stored addresses of `id` with each one's registration time (the
/// attr-stamp's wall clock, DSTIME).
fn stored(d: &Domain, id: u32) -> Vec<(Vec<u8>, u64)> {
    d.object(guid(id))
        .and_then(|o| o.attribute(HOST_ADDRESS).cloned())
        .map(|a| {
            a.values
                .into_iter()
                .map(|v| (v.value, v.stamp.wall_clock.0))
                .collect()
        })
        .unwrap_or_default()
}

fn params() -> ZoneParameters {
    ZoneParameters {
        soa: SoaParameters {
            rname: DnsName::from_labels([&b"hostmaster"[..], b"example", b"test"]).unwrap(),
            refresh: 900,
            retry: 300,
            expire: 604_800,
            minimum: 60,
        },
        infrastructure_ttl: 3_600,
        host_ttl: 1_200,
        kpasswd: KpasswdService::Absent,
        max_record_age: 7 * 86_400,
        registrable_networks: registration().networks().to_vec(),
    }
}

fn image_hosts(d: &Domain, at: &KerberosTime) -> (u32, usize) {
    let view = d.ctx.view(&d.store, &d.tiers).unwrap();
    let projection = view.zone_projection(&params(), at).unwrap();
    (projection.image().serial(), projection.image().host_count())
}

/// docs/54 §4.5, §5.2, §5.4: ws01 registers two addresses: decided from its
/// own identity (label ws01, host ws01.example.test), written with the
/// change-seq and the zone serial in one transaction; the new SERIAL is the
/// counter's next value; the projection serves ws01 beside the DC; each
/// value's registration time is the write's (now).
#[test]
fn a_host_registers_its_own_addresses() {
    let d = dns_domain("dns-register", 1);
    {
        let view = d.ctx.view(&d.store, &d.tiers).unwrap();
        let host = d
            .admin
            .dns_update_host(&signer("ws01$"), &view, &d.policy, &now())
            .unwrap();
        assert_eq!(host.label(), "ws01");
        assert_eq!(host.host_name(), "ws01.example.test");
        assert_eq!(host.owner(), guid(WS01));
        assert_eq!(host.requester(), &sid_of(WS01));
        assert!(host.addresses().is_empty());
    }
    assert_eq!(image_hosts(&d, &now()), (1, 1));
    let seq_before = d.counter_next(CHANGE_SEQ_COUNTER);
    let applied = run(
        &d,
        "ws01$",
        &update(&[a(10), a(11)], &[a(10), a(11)]),
        &now(),
    )
    .unwrap()
    .expect("a write");
    assert_eq!(applied.serial(), 2);
    assert_eq!(d.counter_next(DNS_ZONE_SERIAL_COUNTER), 2);
    assert_eq!(d.counter_next(CHANGE_SEQ_COUNTER), seq_before + 1);
    let now_dstime = u64::try_from(NOW_DSTIME).unwrap();
    assert_eq!(
        stored(&d, WS01),
        vec![
            (vec![192, 0, 2, 10], now_dstime),
            (vec![192, 0, 2, 11], now_dstime)
        ]
    );
    assert_eq!(image_hosts(&d, &now()), (2, 2));
}

/// RFC 2136 §2.5.1 / docs/54 §5.5: the same set again, nothing renewed —
/// no write, no SERIAL; renewed — the address's registration time becomes
/// the new write's and SERIAL moves (two originating writes, two
/// change-seqs, one transaction — docs/questions/Q-991 item 5).
#[test]
fn renewal_restamps_and_duplicates_change_nothing() {
    let d = dns_domain("dns-renew", 1);
    run(&d, "ws01$", &update(&[a(10), a(11)], &[]), &now()).unwrap();
    assert_eq!(
        run(&d, "ws01$", &update(&[a(11), a(10)], &[]), &now()),
        Ok(None)
    );
    assert_eq!(d.counter_next(DNS_ZONE_SERIAL_COUNTER), 2);
    // An hour later: 2026-11-13T11:00:00Z = NOW_DSTIME + 3600.
    let later = kt(2026, 11, 13, 11, 0, 0);
    let seq_before = d.counter_next(CHANGE_SEQ_COUNTER);
    let applied = run(&d, "ws01$", &update(&[a(10), a(11)], &[a(10)]), &later)
        .unwrap()
        .unwrap();
    assert_eq!(applied.serial(), 3);
    assert_eq!(d.counter_next(CHANGE_SEQ_COUNTER), seq_before + 2);
    let now_dstime = u64::try_from(NOW_DSTIME).unwrap();
    assert_eq!(
        stored(&d, WS01),
        vec![
            (vec![192, 0, 2, 10], now_dstime + 3_600),
            (vec![192, 0, 2, 11], now_dstime)
        ]
    );
    // Removing the record is a change too.
    let applied = run(&d, "ws01$", &update(&[], &[]), &later)
        .unwrap()
        .unwrap();
    assert_eq!(applied.serial(), 4);
    assert!(stored(&d, WS01).is_empty());
    assert_eq!(image_hosts(&d, &later), (4, 1));
}

/// RFC 2136 §7.11 ("if the result of the increment is zero … increment it
/// again"); docs/54 §5.4: a counter whose next value would be 2³² is taken
/// twice, so SERIAL goes from 0xFFFFFFFF to 1.
#[test]
fn the_serial_skips_zero() {
    let d = dns_domain("dns-serial-zero", 0xFFFF_FFFF);
    assert_eq!(image_hosts(&d, &now()).0, 0xFFFF_FFFF);
    let applied = run(&d, "ws01$", &update(&[a(10)], &[]), &now())
        .unwrap()
        .unwrap();
    assert_eq!(applied.serial(), 1);
    assert_eq!(d.counter_next(DNS_ZONE_SERIAL_COUNTER), 0x1_0000_0001);
    assert_eq!(image_hosts(&d, &now()).0, 1);
}

/// docs/54 §5.5 (structural refusals, before any value is judged): a user
/// has no host name; the DC and a service object are structural; a computer
/// whose dNSHostName is not `<computerName>.<zone>`, or whose computerName
/// is not one LDH label, has none either; an unknown signer is not
/// authenticated. Nothing is written.
#[test]
fn only_a_named_computer_updates_its_own_record() {
    let d = dns_domain("dns-who", 1);
    let up = update(&[a(10)], &[]);
    for (sam, refusal) in [
        ("bob", DnsUpdateRefusal::NotAComputer),
        ("dc01$", DnsUpdateRefusal::Protected),
        ("ldap-svc$", DnsUpdateRefusal::Protected),
        ("ws02$", DnsUpdateRefusal::NoHostName),
        ("w_3$", DnsUpdateRefusal::NoHostName),
        ("nobody$", DnsUpdateRefusal::Unauthenticated),
        ("disabled", DnsUpdateRefusal::Unauthenticated),
    ] {
        assert_eq!(run(&d, sam, &up, &now()), Err(refusal), "{sam}");
    }
    assert_eq!(d.counter_next(DNS_ZONE_SERIAL_COUNTER), 1);
    assert_eq!(
        stored(&d, DC01),
        vec![(
            vec![192, 0, 2, 1],
            u64::try_from(PROVISIONED_DSTIME).unwrap()
        )]
    );
}

/// docs/54 §5.5; Q-614 items 2, 8: every address registrable (never
/// loopback, unspecified, multicast; inside 192.0.2.0/24), at most eight,
/// none twice, renewed ⊆ the new set.
#[test]
fn addresses_are_bounded_and_registrable() {
    let d = dns_domain("dns-values", 1);
    for bad in [
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(224, 0, 0, 251),
        Ipv4Addr::new(198, 51, 100, 7),
    ] {
        assert_eq!(
            run(&d, "ws01$", &update(&[a(10), bad], &[]), &now()),
            Err(DnsUpdateRefusal::AddressNotAllowed),
            "{bad}"
        );
    }
    let nine: Vec<Ipv4Addr> = (10..19).map(a).collect();
    assert_eq!(
        run(&d, "ws01$", &update(&nine, &[]), &now()),
        Err(DnsUpdateRefusal::TooManyAddresses)
    );
    assert!(run(&d, "ws01$", &update(&nine[..8], &[]), &now())
        .unwrap()
        .is_some());
    assert_eq!(
        run(&d, "ws01$", &update(&[a(10), a(10)], &[]), &now()),
        Err(DnsUpdateRefusal::RequestInvalid)
    );
    assert_eq!(
        run(&d, "ws01$", &update(&[a(10)], &[a(11)]), &now()),
        Err(DnsUpdateRefusal::RequestInvalid)
    );
}

/// docs/54 §5.6; Q-614 items 5-6; A-36: the PDP decides `DnsUpdate` with the
/// owner's tier — ws01 in an unclassified ou=Staff is Tier0 for writes, so
/// its own update is a tier violation; without the policy rule, no grant;
/// without the DNS configuration, nothing is decided (fail closed).
#[test]
fn the_pdp_and_the_configuration_decide() {
    let unclassified = Domain::with_extra(
        "dns-tier0",
        Extra {
            dns: Some(registration()),
            dns_rule: true,
            ..Extra::default()
        },
    );
    dns_store(&unclassified, 1);
    assert_eq!(
        run(&unclassified, "ws01$", &update(&[a(10)], &[]), &now()),
        Err(DnsUpdateRefusal::PolicyDenied(ReasonCode::TierViolation))
    );
    let no_rule = Domain::with_extra(
        "dns-no-rule",
        Extra {
            staff_tier: Some(Tier::Tier2),
            dns: Some(registration()),
            ..Extra::default()
        },
    );
    dns_store(&no_rule, 1);
    assert_eq!(
        run(&no_rule, "ws01$", &update(&[a(10)], &[]), &now()),
        Err(DnsUpdateRefusal::PolicyDenied(ReasonCode::NoGrant))
    );
    let off = Domain::with_extra(
        "dns-off",
        Extra {
            staff_tier: Some(Tier::Tier2),
            dns_rule: true,
            ..Extra::default()
        },
    );
    dns_store(&off, 1);
    assert_eq!(
        run(&off, "ws01$", &update(&[a(10)], &[]), &now()),
        Err(DnsUpdateRefusal::Failed(DnsUpdateFailure::NotConfigured))
    );
    // DNS enabled but no zone serial counter (A-83: never created here).
    let no_counter = Domain::with_extra(
        "dns-no-counter",
        Extra {
            staff_tier: Some(Tier::Tier2),
            dns: Some(registration()),
            dns_rule: true,
            ..Extra::default()
        },
    );
    assert_eq!(
        run(&no_counter, "ws01$", &update(&[a(10)], &[]), &now()),
        Err(DnsUpdateRefusal::Failed(DnsUpdateFailure::Store))
    );
}

/// docs/54 §4.5 step 6 (re-verified at the write; crate apply's rule): a
/// write committed between the view and the apply ⇒ `Conflict`, nothing
/// written.
#[test]
fn a_moved_directory_conflicts() {
    let mut d = dns_domain("dns-conflict", 1);
    let view = d.ctx.view(&d.store, &d.tiers).unwrap();
    let host = d
        .admin
        .dns_update_host(&signer("ws01$"), &view, &d.policy, &now())
        .unwrap();
    let prepared = d
        .admin
        .prepare_dns_self_update(host, &update(&[a(10)], &[]))
        .unwrap()
        .unwrap();
    drop(view);
    // Another write commits meanwhile (an administrator disables bob).
    let op = Operation::SetEnabled(SetEnabled {
        target: guid(BOB),
        enabled: false,
    });
    let request = d.request(op, "admin1");
    assert!(matches!(d.run_request(&request), Ran::Applied { .. }));
    let mut txn = d.store.begin_write().unwrap();
    let acked = linked::acknowledged(prepared.with_intent(decision_event()));
    assert_eq!(
        d.admin.apply_dns_self_update(acked, &mut txn, &now()),
        Err(DnsUpdateRefusal::Conflict)
    );
    txn.abort().unwrap();
    assert!(stored(&d, WS01).is_empty());
    assert_eq!(d.counter_next(DNS_ZONE_SERIAL_COUNTER), 1);
}

/// RFC 2136 §3.6; docs/54 §4.4, §5.2: an admin write to a computer that
/// holds a host record changes the zone (a disabled host leaves the image;
/// a deleted one takes its record with it — the dangling-record class), so
/// its commit takes the zone serial too; a write to an object without one
/// does not.
#[test]
fn admin_writes_to_a_host_move_the_serial() {
    let mut d = dns_domain("dns-admin", 1);
    run(&d, "ws01$", &update(&[a(10)], &[]), &now()).unwrap();
    assert_eq!(image_hosts(&d, &now()), (2, 2));
    // bob holds no record: the serial stays.
    let op = Operation::SetEnabled(SetEnabled {
        target: guid(BOB),
        enabled: false,
    });
    let request = d.request(op, "admin1");
    assert!(matches!(d.run_request(&request), Ran::Applied { .. }));
    assert_eq!(d.counter_next(DNS_ZONE_SERIAL_COUNTER), 2);
    // ws01 holds one: disabling it moves the serial and empties its slot.
    let op = Operation::SetEnabled(SetEnabled {
        target: guid(WS01),
        enabled: false,
    });
    let request = d.request(op, "admin1");
    assert!(matches!(d.run_request(&request), Ran::Applied { .. }));
    assert_eq!(d.counter_next(DNS_ZONE_SERIAL_COUNTER), 3);
    assert_eq!(image_hosts(&d, &now()), (3, 1));
    // Deleting it moves the serial again and removes the record.
    let request = d.request(Operation::Delete { target: guid(WS01) }, "admin1");
    assert!(matches!(d.run_request(&request), Ran::Applied { .. }));
    assert_eq!(d.counter_next(DNS_ZONE_SERIAL_COUNTER), 4);
    assert!(d.object(guid(WS01)).is_none());
    assert_eq!(image_hosts(&d, &now()), (4, 1));
}
