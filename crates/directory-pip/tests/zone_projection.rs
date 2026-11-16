//! The zone projection and the DNS record tier (task DN6).
//!
//! Source: docs/54 §3.1 (the phase-1 records: SOA, NS, A, SRV
//! `_kerberos._udp`, `_kerberos._tcp`, `_ldap._tcp`; `_kpasswd` only with
//! kpasswd), §4.4 (the image: usable computers only, addresses not aged
//! past `dns_record_max_age`, inside `dns_registrable_networks`; nothing else
//! of an object), §5.1 (SOA / NS / SRV synthesized), §5.3 (one LDH label,
//! `<computerName>.<zone>`), §5.4 (SERIAL from the `dns-zone-serial`
//! counter), §5.6 (`object_tier` of `Resource::Dns{record}` = the owner's);
//! docs/questions/Q-614 items 3, 6-8; [MS-ADTS] v20261026 3.1.1.5.3.1.1.2
//! (computerName.fullDomainDnsName); RFC 1035 §2.3.1, §2.3.3, §3.4.1; RFC
//! 2136 §7.11; docs/47 §4 (`usable_at`); A-36 (unclassified ⇒ Tier0 for
//! writes). Names, addresses and times are this project's own test data;
//! each time is derived in a comment. No vector or fixture comes from any
//! other implementation.

mod common;

use common::*;
use config::Network;
use directory_pip::{
    host_address_value, ZoneParameters, ZoneProjectionError, DNS_ZONE_SERIAL_COUNTER, HOST_ADDRESS,
};
use dirstore::{AttributeChange, NodeId, Origin, Timestamp};
use dns_zone::{
    HostRecordParts, KpasswdService, SoaParameters, SrvService, ZoneImage, ZoneImageParts,
};
use parse_dns::Name;
use pdp::{Dn, Pip, PipError, RecordKey, Resource, Tier, ZoneId};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

/// DSTIME of the test "now", 2026-11-13T10:00:00Z: 20 770 days after
/// 1970-01-01 = 1 794 528 000 s, + 10 h = 1 794 564 000 s, + 11 644 473 600
/// (1601 → 1970) = 13 439 037 600 ([MS-DRSR] 5.51).
const NOW_DSTIME: u64 = 13_439_037_600;
/// One hour before now.
const HOUR_AGO: u64 = NOW_DSTIME - 3_600;
/// Eight days before now (older than the seven-day maximum age).
const EIGHT_DAYS_AGO: u64 = NOW_DSTIME - 8 * 86_400;
/// `dns_record_max_age` of the tests: seven days, in seconds (docs/54 §5.2
/// "e.g. 7 days").
const MAX_AGE: u64 = 7 * 86_400;

const WS02: u32 = 22;
const WS03: u32 = 23;
const WS04: u32 = 24;
const WS05: u32 = 25;
const WS06: u32 = 26;
const DC02: u32 = 27;

fn name(labels: &[&str]) -> Name {
    Name::from_labels(labels.iter().map(|l| l.as_bytes())).unwrap()
}

fn net() -> Network {
    Network::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap()
}

fn soa() -> SoaParameters {
    SoaParameters {
        rname: name(&["hostmaster", "example", "test"]),
        refresh: 900,
        retry: 300,
        expire: 604_800,
        minimum: 60,
    }
}

fn params() -> ZoneParameters {
    ZoneParameters {
        soa: soa(),
        infrastructure_ttl: 3_600,
        host_ttl: 1_200,
        kpasswd: KpasswdService::Absent,
        max_record_age: MAX_AGE,
        registrable_networks: vec![net()],
    }
}

fn a(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, last)
}

/// Write host addresses of `id` as registered at the DSTIME `at` (the
/// attr-stamp's wall clock — the unit every writer of the store uses).
fn register(d: &Dir, id: u32, addresses: &[Ipv4Addr], at: u64) {
    let mut txn = d.store.begin_write().unwrap();
    let origin = Origin {
        wall_clock: Timestamp(at),
        origin_node: NodeId([0xD1; 16]),
        origin_seq: d.origin().origin_seq,
    };
    txn.modify_object(
        guid(id),
        vec![AttributeChange::Replace {
            id: HOST_ADDRESS,
            values: addresses.iter().copied().map(host_address_value).collect(),
        }],
        &origin,
    )
    .unwrap();
    txn.commit().unwrap();
}

/// The zone serial counter, first value `first`.
fn serial_counter(d: &Dir, first: u64) {
    let mut txn = d.store.begin_write().unwrap();
    txn.create_counter(DNS_ZONE_SERIAL_COUNTER, first, u64::MAX)
        .unwrap();
    txn.commit().unwrap();
}

fn computer(
    d: &Dir,
    id: u32,
    sam: &str,
    host: &str,
    uac_bits: u32,
    extra: &[(&str, Vec<Vec<u8>>)],
) {
    let mut attrs = vec![
        ("userAccountControl", vec![bits(uac_bits)]),
        ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
        ("dNSHostName", vec![host.as_bytes().to_vec()]),
    ];
    attrs.extend(extra.iter().cloned());
    d.create_all(vec![d.computer(id, STAFF_OU, sam, &attrs)]);
}

/// The standard directory plus: dc01's dNSHostName and address
/// (192.0.2.1, provisioned eight days ago — the DC never ages), ws01 at
/// 192.0.2.10 (an hour ago), and member computers the image must leave
/// out: ws02 disabled, ws03 expired (accountExpires 2026-01-01), ws04
/// registered eight days ago, ws05 outside the registrable network, ws06
/// whose dNSHostName is not `<computerName>.<zone>`; the serial counter at
/// `first`.
fn zone_dir(test: &str, first: u64) -> Dir {
    let d = Dir::standard(test);
    let wt = uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT;
    d.set(DC01, "dNSHostName", vec![b"dc01.example.test".to_vec()]);
    // The DC as provisioning writes it: its `HostName` key with its name
    // (task PN4b; docs/59 §4.3, §5.2).
    d.write_principal_keys(&[DC01], &BTreeSet::new());
    computer(
        &d,
        WS02,
        "ws02$",
        "ws02.example.test",
        wt | uac::ADS_UF_ACCOUNT_DISABLE,
        &[],
    );
    computer(
        &d,
        WS03,
        "ws03$",
        "ws03.example.test",
        wt,
        &[("accountExpires", vec![int64(EXPIRES_2026)])],
    );
    computer(&d, WS04, "ws04$", "ws04.example.test", wt, &[]);
    computer(&d, WS05, "ws05$", "ws05.example.test", wt, &[]);
    computer(&d, WS06, "ws06$", "web.example.test", wt, &[]);
    register(&d, DC01, &[a(1)], EIGHT_DAYS_AGO);
    register(&d, WS01, &[a(10)], HOUR_AGO);
    register(&d, WS02, &[a(20)], HOUR_AGO);
    register(&d, WS03, &[a(30)], HOUR_AGO);
    register(&d, WS04, &[a(40)], EIGHT_DAYS_AGO);
    register(&d, WS05, &[Ipv4Addr::new(198, 51, 100, 50)], HOUR_AGO);
    register(&d, WS06, &[a(60)], HOUR_AGO);
    serial_counter(&d, first);
    d
}

fn host(label: &str, addresses: &[Ipv4Addr]) -> HostRecordParts {
    HostRecordParts {
        label: label.as_bytes().to_vec(),
        addresses: addresses.to_vec(),
        ttl: 1_200,
    }
}

fn expected(serial: u32, hosts: Vec<HostRecordParts>) -> ZoneImage {
    ZoneImage::new(ZoneImageParts {
        apex: name(&["example", "test"]),
        serial,
        soa: soa(),
        infrastructure_ttl: 3_600,
        dc: host("dc01", &[a(1)]),
        hosts,
        kpasswd: KpasswdService::Absent,
    })
    .unwrap()
}

/// docs/54 §3.1, §4.4, §5.1, §5.4: the image holds the synthesized
/// infrastructure, the DC (not aged) and exactly the usable member host
/// whose names pass the rule and whose address is fresh and registrable;
/// SERIAL is the counter's next value; `valid_until` is ws01's address
/// reaching the maximum age (an hour ago + 7 days).
#[test]
fn the_image_holds_exactly_the_servable_hosts() {
    let d = zone_dir("zone-image", 1);
    let view = d.view();
    let projection = view.zone_projection(&params(), &now()).unwrap();
    assert_eq!(
        projection.image(),
        &expected(1, vec![host("ws01", &[a(10)])])
    );
    assert_eq!(
        projection.image().dc_name(),
        &name(&["dc01", "example", "test"])
    );
    assert_eq!(
        projection.image().srv_services().collect::<Vec<_>>(),
        vec![
            SrvService::KerberosUdp,
            SrvService::KerberosTcp,
            SrvService::LdapTcp
        ]
    );
    // 2026-11-13T09:00:00Z + 7 days = 2026-11-20T09:00:00Z.
    assert_eq!(projection.valid_until(), Some(kt(2026, 11, 20, 9, 0, 0)));
    // The kpasswd switch adds its SRV record (docs/54 §3.1) — `_kpasswd._tcp`
    // only: one record per service that exists (docs/questions/Q-1004,
    // A-172; kpasswd-front serves TCP only).
    let mut with_kpasswd = params();
    with_kpasswd.kpasswd = KpasswdService::Present;
    let projection = view.zone_projection(&with_kpasswd, &now()).unwrap();
    assert_eq!(projection.image().srv_services().count(), 4);
}

/// docs/54 §4.4, §5.2: an address leaves the image at its maximum age, and
/// an account at its accountExpires; `valid_until` names the earlier.
#[test]
fn time_alone_changes_the_image_at_valid_until() {
    let d = zone_dir("zone-time", 1);
    // ws04 again, fresh, with an expiry two hours from now:
    // 2026-11-13T12:00:00Z = DSTIME 13 439 044 800 → FILETIME × 10^7.
    d.set(WS04, "accountExpires", vec![int64(134_390_448_000_000_000)]);
    // Writing the stale 192.0.2.40 again keeps its old stamp (a Replace
    // keeps a value already present — dirstore `AttributeChange::Replace`):
    // still out of the image. A new address is registered now.
    register(&d, WS04, &[a(40)], HOUR_AGO);
    assert_eq!(
        d.view().zone_projection(&params(), &now()).unwrap().image(),
        &expected(1, vec![host("ws01", &[a(10)])])
    );
    register(&d, WS04, &[a(40), a(41)], HOUR_AGO);
    let view = d.view();
    let projection = view.zone_projection(&params(), &now()).unwrap();
    assert_eq!(
        projection.image(),
        &expected(1, vec![host("ws01", &[a(10)]), host("ws04", &[a(41)])])
    );
    assert_eq!(projection.valid_until(), Some(kt(2026, 11, 13, 12, 0, 0)));
    // At that instant ws04 is gone (expired), ws01 stays.
    let later = view
        .zone_projection(&params(), &kt(2026, 11, 13, 12, 0, 0))
        .unwrap();
    assert_eq!(later.image(), &expected(1, vec![host("ws01", &[a(10)])]));
    // A week later ws01's address has aged out too.
    let week = view
        .zone_projection(&params(), &kt(2026, 11, 20, 9, 0, 0))
        .unwrap();
    assert_eq!(week.image(), &expected(1, vec![]));
    assert_eq!(week.valid_until(), None);
}

/// docs/54 §5.4; RFC 2136 §7.11: SERIAL is the counter's next value modulo
/// 2³², never 0 — a counter whose next value is 2³² shows no image.
#[test]
fn the_serial_comes_from_the_counter() {
    let d = zone_dir("zone-serial", 0x1_0000_0005);
    let view = d.view();
    assert_eq!(
        view.zone_projection(&params(), &now())
            .unwrap()
            .image()
            .serial(),
        5
    );
    let d = zone_dir("zone-serial-zero", 0x1_0000_0000);
    let view = d.view();
    assert_eq!(
        view.zone_projection(&params(), &now()),
        Err(ZoneProjectionError::NoZoneSerial)
    );
}

/// Fail closed (docs/54 §4.4): no counter, a DC without a host name or an
/// address, no DC or two DCs (OD-2) — no image.
#[test]
fn an_unprojectable_directory_gives_no_image() {
    let d = Dir::standard("zone-no-counter");
    d.set(DC01, "dNSHostName", vec![b"dc01.example.test".to_vec()]);
    register(&d, DC01, &[a(1)], HOUR_AGO);
    assert_eq!(
        d.view().zone_projection(&params(), &now()),
        Err(ZoneProjectionError::NoZoneSerial)
    );
    serial_counter(&d, 1);
    assert!(d.view().zone_projection(&params(), &now()).is_ok());
    // The DC without an address.
    register(&d, DC01, &[], HOUR_AGO);
    assert_eq!(
        d.view().zone_projection(&params(), &now()),
        Err(ZoneProjectionError::DcAddress)
    );
    // The DC whose dNSHostName is not dc01.example.test.
    register(&d, DC01, &[a(1)], HOUR_AGO);
    d.set(DC01, "dNSHostName", vec![b"dc.example.test".to_vec()]);
    assert_eq!(
        d.view().zone_projection(&params(), &now()),
        Err(ZoneProjectionError::DcName)
    );
    d.set(DC01, "dNSHostName", vec![b"dc01.example.test".to_vec()]);
    // A second DC account.
    computer(
        &d,
        DC02,
        "dc02$",
        "dc02.example.test",
        uac::ADS_UF_SERVER_TRUST_ACCOUNT,
        &[],
    );
    assert_eq!(
        d.view().zone_projection(&params(), &now()),
        Err(ZoneProjectionError::DcAccount)
    );
    // No DC at all.
    let d = Dir::new("zone-no-dc");
    let mut objects = d.standard_objects();
    objects.retain(|o| o.guid != guid(DC01));
    d.create_all(objects);
    serial_counter(&d, 1);
    assert_eq!(
        d.view().zone_projection(&params(), &now()),
        Err(ZoneProjectionError::DcAccount)
    );
}

/// docs/54 §5.6; Q-614 item 6; A-36: `object_tier` of a DNS record is the
/// tier of the one computer owning its name (case-insensitive, RFC 1035
/// §2.3.3); no owner, no record key, another zone, a name that is not one
/// LDH label, or names that fail the rule ⇒ Tier0.
#[test]
fn the_record_tier_is_the_owners() {
    let d = zone_dir("zone-tier", 1);
    let dns = |zone: &str, record: Option<&str>| Resource::Dns {
        zone: ZoneId(zone.into()),
        record: record.map(|r| RecordKey(r.into())),
    };
    let staff = Dn::new(vec![
        "ou=Staff".into(),
        "dc=example".into(),
        "dc=test".into(),
    ]);
    let tiers =
        directory_pip::TierMap::new(Default::default(), vec![(staff, Tier::Tier2)]).unwrap();
    let view = d.view_with(&tiers);
    assert_eq!(
        view.object_tier(&dns("example.test", Some("ws01"))),
        Ok(Tier::Tier2)
    );
    assert_eq!(
        view.object_tier(&dns("EXAMPLE.test", Some("WS01"))),
        Ok(Tier::Tier2)
    );
    // The DC is Tier0 by structure (docs/47 §6.3).
    assert_eq!(
        view.object_tier(&dns("example.test", Some("dc01"))),
        Ok(Tier::Tier0)
    );
    for (zone, record) in [
        ("example.test", None),
        ("example.test", Some("nobody")),
        ("other.test", Some("ws01")),
        ("example.test", Some("ws01.example.test")),
        ("example.test", Some("_ldap")),
        ("example.test", Some("*")),
        // ws06's dNSHostName is web.example.test: no host name.
        ("example.test", Some("ws06")),
        ("example.test", Some("web")),
        // alice is a user: no host name.
        ("example.test", Some("alice")),
    ] {
        assert_eq!(
            view.object_tier(&dns(zone, record)),
            Ok(Tier::Tier0),
            "{zone} {record:?}"
        );
    }
    // Unclassified owner: Tier0 for writes (A-36).
    let plain = d.view();
    assert_eq!(
        plain.object_tier(&dns("example.test", Some("ws01"))),
        Ok(Tier::Tier0)
    );
    assert_eq!(
        plain.dns_record_owner("example.test", "WS01"),
        Ok(Some(guid(WS01)))
    );
    assert_eq!(
        plain.dns_record_owner("EXAMPLE.TEST", "Dc01"),
        Ok(Some(guid(DC01)))
    );
    assert_eq!(plain.dns_record_owner("example.test", "ws06"), Ok(None));
}

/// docs/questions/Q-1036 item 6; docs/59 §4.1 (`HostName` = `fold(host)`),
/// §5.3 (no lookup by name through a per-attribute index), §6.1 step 3 (the
/// re-derivation fails closed); [MS-ADTS] 3.1.1.5.3.1.1.2; RFC 1035 §2.3.3:
/// the owner of a DNS label is the holder of the `HostName` key
/// `fold(<label>.<zone>)` in the namespace's union index — the one probe —
/// whatever the case of the request. A name held as another kind (a user
/// whose sAMAccountName is spelled like a host name) owns no record; a
/// computer written beneath the checker holds no key and owns none; a
/// holder whose names no longer give the key it holds (changed beneath the
/// checker) is a fault, not an owner.
#[test]
fn the_record_owner_is_the_host_name_keys_holder() {
    let d = Dir::standard("zone-owner-key");
    let wt = || vec![bits(uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT)];
    d.create_all(vec![d.user(
        70,
        STAFF_OU,
        "ws07.example.test",
        &[("userAccountControl", vec![bits(uac::ADS_UF_NORMAL_ACCOUNT)])],
    )]);
    d.create_all_beneath_checker(vec![d.computer(
        71,
        STAFF_OU,
        "ws08$",
        &[
            ("userAccountControl", wt()),
            ("dNSHostName", vec![b"ws08.example.test".to_vec()]),
        ],
    )]);
    let view = d.view();
    assert_eq!(
        view.dns_record_owner("Example.Test", "WS01"),
        Ok(Some(guid(WS01)))
    );
    assert_eq!(view.dns_record_owner("example.test", "ws07"), Ok(None));
    assert_eq!(view.dns_record_owner("example.test", "ws08"), Ok(None));
    drop(view);
    d.set(WS01, "dNSHostName", vec![b"other.example.test".to_vec()]);
    assert_eq!(
        d.view().dns_record_owner("example.test", "ws01"),
        Err(PipError::Unavailable)
    );
}
