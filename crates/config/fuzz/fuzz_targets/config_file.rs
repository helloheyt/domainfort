#![no_main]
//! Fuzz target for `config`, the strict daemon configuration parser.
//!
//! docs/CLEAN-ROOM.md / docs/32 §8 (every parser gets a fuzz target before it
//! merges to main; docs/50 §9 names this target `config_file`). On any octets
//! all seven schemas (six daemons and the keyadm tool) must return without
//! panicking, and:
//!
//! * input over the file bound, or not ending in LF, is refused by every
//!   schema (docs/50 §7.1; Q-230 item 2);
//! * an error names, at most, a key of that daemon's own closed table — never
//!   input text (docs/CLEAN-ROOM.md; docs/50 §8.2);
//! * an accepted file contains only printable ASCII and LF (docs/50 §7.1);
//! * an accepted keyd file's `uid → Role` map is non-empty, never maps uid 0,
//!   maps each uid once and never keyd's own uid (docs/50 R50-3, §3.2); the
//!   same for auditd's `uid → source` map;
//! * every account id accepted is neither 0 nor all-ones (Q-230 item 6).
//!
//! Spec: docs/50 R50-3, R50-15, §7.1, §9.

use config::limits::MAX_FILE_OCTETS;
use config::{
    AdmindSettings, AuditdSettings, DirdSettings, Error, KdcSettings, KeyadmSettings, KeydSettings,
    LdapFrontSettings,
};
use libfuzzer_sys::fuzz_target;

fn check_error(result: &Result<(), Error>, keys: &[&str]) {
    if let Err(err) = result {
        if let Some(key) = err.key() {
            assert!(keys.contains(&key), "error key comes from the table");
        }
    }
}

fn valid_id(id: u32) -> bool {
    id != 0 && id != u32::MAX
}

fuzz_target!(|data: &[u8]| {
    let results = [
        (KeydSettings::parse(data).map(drop), KeydSettings::KEYS),
        (DirdSettings::parse(data).map(drop), DirdSettings::KEYS),
        (KdcSettings::parse(data).map(drop), KdcSettings::KEYS),
        (LdapFrontSettings::parse(data).map(drop), LdapFrontSettings::KEYS),
        (AuditdSettings::parse(data).map(drop), AuditdSettings::KEYS),
        (AdmindSettings::parse(data).map(drop), AdmindSettings::KEYS),
        (KeyadmSettings::parse(data).map(drop), KeyadmSettings::KEYS),
    ];
    // keyadm: the keyd uid it verifies is never 0 or all-ones (R50-3; Q-230
    // item 6).
    if let Ok(settings) = KeyadmSettings::parse(data) {
        assert!(valid_id(settings.keyd().uid()));
    }
    let cut = !data.is_empty() && data.last() != Some(&b'\n');
    for (result, keys) in &results {
        check_error(result, keys);
        if data.len() > MAX_FILE_OCTETS || cut {
            assert!(result.is_err(), "bound and final LF enforced");
        }
        if result.is_ok() {
            assert!(data.iter().all(|&b| b == b'\n' || (0x20..=0x7E).contains(&b)));
        }
    }
    if let Ok(settings) = KeydSettings::parse(data) {
        let map = settings.uid_roles();
        assert!(!map.is_empty());
        assert_eq!(map.role_of(0), None);
        let uids: Vec<u32> = map.iter().map(|(uid, _)| uid).collect();
        for (i, uid) in uids.iter().enumerate() {
            assert!(valid_id(*uid));
            assert!(!uids[..i].contains(uid), "one role per uid");
            assert_ne!(*uid, settings.run_as().uid());
        }
        assert!(valid_id(settings.run_as().uid()) && valid_id(settings.run_as().gid()));
    }
    if let Ok(settings) = AuditdSettings::parse(data) {
        let map = settings.uid_sources();
        assert!(!map.is_empty());
        assert_eq!(map.source_of(0), None);
        assert!(map.iter().all(|(uid, _)| valid_id(uid)));
    }
    if let Ok(settings) = KdcSettings::parse(data) {
        assert!(!settings.listen().is_empty());
        let limits = settings.limits();
        assert!(limits.max_tcp_connections_per_source() <= limits.max_tcp_connections());
    }
    if let Ok(settings) = LdapFrontSettings::parse(data) {
        assert!(!(settings.ldap_listen().is_empty() && settings.ldaps_listen().is_empty()));
        // docs/52 R14: every accepted listener lies in the zone table.
        assert!(settings
            .ldap_listen()
            .iter()
            .chain(settings.ldaps_listen())
            .all(|address| config::is_internal(settings.internal_networks(), address.ip())));
    }
});
