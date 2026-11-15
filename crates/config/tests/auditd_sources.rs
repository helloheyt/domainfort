//! auditd's `uid → source` map names dnsd and kpasswd-front (task DN12).
//!
//! Sources: docs/50 §3.2 ("auditd: every service's uid, each marked as the
//! event's source — the source is set from the uid, not from the event
//! body"), R50-3 (one source per uid, uid 0 never mapped); docs/54 §4.3 (the
//! process `dnsd`), §9 ("dnsd — a new source"); docs/53 §9 (kpasswd-front);
//! docs/questions/Q-619 item 2, Q-950 (A-157), Q-955 item 1 (A-158), Q-960.
//! Uids and paths are test values written for these tests.

use config::{AuditSource, AuditdSettings, ErrorKind};

/// An auditd file whose map is `uid_sources`.
fn auditd_file(uid_sources: &str) -> String {
    format!(
        "run_as_uid = 805\nrun_as_gid = 805\naudit_socket = /run/auditd/audit.sock\n\
         audit_log_path = /var/log/audit/domain-audit.log\nuid_sources = {uid_sources}\n"
    )
}

/// docs/50 §3.2; docs/54 §4.3, §9; docs/53 §9: every daemon that talks to
/// auditd — the five of before and the two fronts appended by DN12 — is
/// mapped by its process name, in file order.
#[test]
fn dnsd_and_kpasswd_front_are_mapped_by_name() {
    let text = auditd_file(
        "801:keyd, 802:dird, 803:kdc, 804:ldap-front, 806:admind, 807:dnsd, 808:kpasswd-front",
    );
    let settings = AuditdSettings::parse(text.as_bytes()).expect("valid auditd file");
    assert_eq!(
        settings.uid_sources().iter().collect::<Vec<_>>(),
        [
            (801, AuditSource::Keyd),
            (802, AuditSource::Dird),
            (803, AuditSource::Kdc),
            (804, AuditSource::LdapFront),
            (806, AuditSource::Admind),
            (807, AuditSource::Dnsd),
            (808, AuditSource::KpasswdFront),
        ]
    );
    assert_eq!(
        settings.uid_sources().source_of(807),
        Some(AuditSource::Dnsd)
    );
    assert_eq!(
        settings.uid_sources().source_of(808),
        Some(AuditSource::KpasswdFront)
    );
}

/// docs/50 §3.2: each front alone is a valid map (a deployment adds the
/// fronts it runs).
#[test]
fn each_front_alone_is_a_valid_map() {
    for (entry, source) in [
        ("807:dnsd", AuditSource::Dnsd),
        ("808:kpasswd-front", AuditSource::KpasswdFront),
    ] {
        let settings = AuditdSettings::parse(auditd_file(entry).as_bytes()).expect(entry);
        assert_eq!(settings.uid_sources().len(), 1);
        assert_eq!(
            settings.uid_sources().iter().next().map(|e| e.1),
            Some(source)
        );
    }
}

/// docs/50 R50-3, §3.2 (one source per uid, each source at most one uid,
/// uid 0 never mapped, auditd's own uid never mapped): the rules hold for the
/// new names as for the others; a spelling that is not a process name is
/// refused (closed table).
#[test]
fn the_map_rules_hold_for_the_new_sources() {
    let refused = |map: &str| {
        AuditdSettings::parse(auditd_file(map).as_bytes())
            .expect_err(map)
            .kind()
    };
    assert_eq!(refused("807:dnsd, 809:dnsd"), ErrorKind::DuplicateEntry);
    assert_eq!(
        refused("808:kpasswd-front, 809:kpasswd-front"),
        ErrorKind::DuplicateEntry
    );
    assert_eq!(
        refused("807:dnsd, 807:kpasswd-front"),
        ErrorKind::DuplicateId
    );
    assert_eq!(refused("0:dnsd"), ErrorKind::ReservedId, "uid 0");
    assert_eq!(
        refused("805:kpasswd-front"),
        ErrorKind::DuplicateId,
        "auditd's own uid"
    );
    for misspelled in [
        "807:Dnsd",
        "807:dns",
        "807:dns-daemon",
        "808:kpasswd",
        "808:kpasswd_front",
        "808:kpasswd-front-daemon",
    ] {
        assert_eq!(refused(misspelled), ErrorKind::UnknownName, "{misspelled}");
    }
}
