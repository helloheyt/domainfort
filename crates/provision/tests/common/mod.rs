//! Shared fixtures of the provision tests. Every value is constructed by
//! hand for these tests (obviously fake names, accounts and paths under a
//! fresh temporary directory); no vector comes from any other
//! implementation.

#![allow(dead_code)]

use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use test_scratch::ScratchDir;

use directory_admin::{RandomError, RandomSource};
use krb_proto::KerberosTime;
use provision::install::Halt;
use provision::{
    Account, Accounts, DomainInput, FilePath, Names, Network, Owner, Ownership, OwnershipError,
    Paths, Progress, Staged, Step,
};

/// A unique scratch directory (mode 0700), removed on drop — inside the
/// workspace (crates/test-scratch, Q-480): the products installed here are
/// read back through crates/protected-file, whose walk from `/` accepts it
/// with the test account as the owner, and its paths are valid
/// configuration paths. Socket paths under it stay short.
pub struct TempDir {
    scratch: ScratchDir,
}

impl TempDir {
    pub fn new() -> TempDir {
        TempDir {
            scratch: ScratchDir::new("prv").unwrap(),
        }
    }

    pub fn path(&self) -> &Path {
        self.scratch.path()
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.scratch.join(name)
    }
}

/// The test process's uid (the owner of a directory it just created).
pub fn my_uid(dir: &TempDir) -> u32 {
    std::fs::metadata(dir.path()).unwrap().uid()
}

/// The tests need a non-root uid (it stands in for dird's or keyadm's,
/// and uid 0 is never mapped — docs/50 R50-3).
pub fn skip_as_root(uid: u32) -> bool {
    if uid == 0 {
        eprintln!("skipped: running as root");
        true
    } else {
        false
    }
}

/// The provisioning time of the tests (test data).
pub fn now() -> KerberosTime {
    KerberosTime::new(2026, 11, 14, 10, 0, 0).unwrap()
}

/// A time on the provisioning day (test data).
pub fn at(hour: u8, minute: u8, second: u8) -> KerberosTime {
    KerberosTime::new(2026, 11, 14, hour, minute, second).unwrap()
}

/// Deterministic draws (tests only — A-15: production uses `OsRandom`):
/// each fill is a counter in its last eight octets behind eight 0x5A
/// octets, so every GUID is non-NULL and distinct.
#[derive(Debug, Default)]
pub struct CountingRandom {
    pub fills: u64,
}

impl RandomSource for CountingRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        self.fills += 1;
        let mut pattern = [0x5Au8; 16];
        pattern[8..].copy_from_slice(&self.fills.to_be_bytes());
        for (i, o) in out.iter_mut().enumerate() {
            *o = pattern[i % 16];
        }
        Ok(())
    }
}

/// A source that fails at its `fail_at`-th fill (from 1).
#[derive(Debug)]
pub struct FailingRandom {
    pub fail_at: u64,
    pub inner: CountingRandom,
}

impl RandomSource for FailingRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        if self.inner.fills + 1 == self.fail_at {
            return Err(RandomError);
        }
        self.inner.fill(out)
    }
}

/// A source that returns only zero octets (a broken CSPRNG: NULL GUIDs).
#[derive(Debug, Default)]
pub struct ZeroRandom;

impl RandomSource for ZeroRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        out.fill(0);
        Ok(())
    }
}

/// The test's [`Ownership`]: records every requested owner (it cannot
/// change owners without root); fails on `fail_on` if set.
#[derive(Debug)]
pub struct Recorder {
    pub root_uid: u32,
    pub records: Vec<(Staged, Owner)>,
    pub fail_on: Option<Staged>,
}

impl Recorder {
    pub fn new(root_uid: u32) -> Recorder {
        Recorder {
            root_uid,
            records: Vec::new(),
            fail_on: None,
        }
    }

    pub fn owner_of(&self, what: Staged) -> Option<Owner> {
        self.records
            .iter()
            .find(|(w, _)| *w == what)
            .map(|(_, o)| *o)
    }
}

impl Ownership for Recorder {
    fn root_uid(&self) -> u32 {
        self.root_uid
    }

    fn change_owner(
        &mut self,
        _fd: std::os::fd::BorrowedFd<'_>,
        what: Staged,
        owner: Owner,
    ) -> Result<(), OwnershipError> {
        if self.fail_on == Some(what) {
            return Err(OwnershipError);
        }
        self.records.push((what, owner));
        Ok(())
    }
}

/// A [`Progress`] that halts at `step` (a simulated crash there) and
/// records every step before it.
#[derive(Debug)]
pub struct HaltAt {
    pub step: Option<Step>,
    pub seen: Vec<Step>,
}

impl HaltAt {
    pub fn new(step: Step) -> HaltAt {
        HaltAt {
            step: Some(step),
            seen: Vec::new(),
        }
    }

    pub fn never() -> HaltAt {
        HaltAt {
            step: None,
            seen: Vec::new(),
        }
    }
}

impl Progress for HaltAt {
    fn reached(&mut self, step: Step) -> Result<(), Halt> {
        if self.step == Some(step) {
            return Err(Halt);
        }
        self.seen.push(step);
        Ok(())
    }
}

/// A path under `dir`.
pub fn path(dir: &TempDir, rest: &str) -> FilePath {
    FilePath::parse(dir.join(rest).to_str().unwrap()).unwrap()
}

/// The fixed test accounts (obviously fake ids), with dird's and keyadm's
/// uids chosen by the test.
pub fn accounts(dird_uid: u32, keyadm_uid: u32) -> Accounts {
    Accounts {
        keyd: Account {
            uid: 61001,
            gid: 61001,
        },
        dird: Account {
            uid: dird_uid,
            gid: dird_uid,
        },
        kdc: Account {
            uid: 61003,
            gid: 61003,
        },
        ldap_front: Account {
            uid: 61004,
            gid: 61004,
        },
        auditd: Account {
            uid: 61005,
            gid: 61005,
        },
        admind: Account {
            uid: 61006,
            gid: 61006,
        },
        // Task K9: the two network fronts (obviously fake ids).
        kpasswd_front: Account {
            uid: 61008,
            gid: 61008,
        },
        dnsd: Account {
            uid: 61009,
            gid: 61009,
        },
        keyadm_uid,
        admin_socket_group: 61010,
    }
}

/// The test input under `dir` (the directories `etc` and `var` are
/// created, mode 0755): realm EXAMPLE.TEST, two first administrators.
pub fn input(dir: &TempDir, dird_uid: u32, keyadm_uid: u32) -> DomainInput {
    for sub in ["etc", "var"] {
        let _ = std::fs::DirBuilder::new().mode(0o755).create(dir.join(sub));
    }
    DomainInput {
        realm: "EXAMPLE.TEST".to_owned(),
        naming_context: vec!["example".to_owned(), "test".to_owned()],
        dc_fqdn: "dc1.example.test".to_owned(),
        accounts: accounts(dird_uid, keyadm_uid),
        paths: Paths {
            staging: path(dir, "etc/provision-staging"),
            database: path(dir, "var/directory.redb"),
            integrity_key: path(dir, "etc/integrity.key"),
            policy: path(dir, "etc/policy.store"),
            manifest: path(dir, "etc/provision.manifest"),
            audit_log: path(dir, "var/audit.log"),
            keyd_config: path(dir, "etc/keyd.conf"),
            dird_config: path(dir, "etc/dird.conf"),
            kdc_config: path(dir, "etc/kdc.conf"),
            ldap_front_config: path(dir, "etc/ldap-front.conf"),
            auditd_config: path(dir, "etc/auditd.conf"),
            admind_config: path(dir, "etc/admind.conf"),
            keyadm_config: path(dir, "etc/keyadm.conf"),
            kpasswd_front_config: path(dir, "etc/kpasswd-front.conf"),
            dnsd_config: path(dir, "etc/dnsd.conf"),
            keyd_socket: path(dir, "run/keyd/keyd.sock"),
            dird_kdc_socket: path(dir, "run/dird-kdc/dird-kdc.sock"),
            dird_ldap_socket: path(dir, "run/dird-ldap/dird-ldap.sock"),
            dird_admin_socket: path(dir, "run/dird-admin/dird-admin.sock"),
            dird_kpasswd_socket: path(dir, "run/dird-kpasswd/dird-kpasswd.sock"),
            dird_dns_socket: path(dir, "run/dird-dns/dird-dns.sock"),
            audit_socket: path(dir, "run/auditd/audit.sock"),
            admin_socket: path(dir, "run/admind/admin.sock"),
            tls_certificate: path(dir, "etc/dc-cert.der"),
            tls_private_key: path(dir, "etc/dc-key.der"),
            policy_next: path(dir, "var/dird-policy/policy.next"),
        },
        network: Network {
            kdc_listen: vec!["127.0.0.1:88".to_owned()],
            ldap_listen: Vec::new(),
            ldaps_listen: vec!["127.0.0.1:636".to_owned()],
            // The LDAPS listener (127.0.0.1) lies inside the internal
            // networks (docs/52 R14: ldap-front listens only there).
            internal_networks: vec!["10.0.0.0/8".to_owned(), "127.0.0.0/8".to_owned()],
            // Task K9: TCP 464 (docs/53 R53-3) and port 53 (docs/54 §4.3),
            // inside the internal networks.
            kpasswd_listen: vec!["127.0.0.1:464".to_owned()],
            dnsd_listen: vec!["127.0.0.1:53".to_owned()],
            // Task DN10b: the DC's host record (docs/54 §3.1), inside the
            // IPv4 internal network 10.0.0.0/8 (not loopback).
            dc_addresses: vec!["10.0.0.10".to_owned()],
        },
        names: Names {
            tier0_ou: "Tier0".to_owned(),
            workstations_ou: Some("Workstations".to_owned()),
            tier0_group: "tier0-admins".to_owned(),
            bootstrap_group: "machine-bootstrap".to_owned(),
            dc_name: "DC1".to_owned(),
            ldap_service_name: "ldapsvc".to_owned(),
            admin_service_name: "adminsvc".to_owned(),
            change_password_service_name: "changepwsvc".to_owned(),
            first_admins: vec!["alice".to_owned(), "bob".to_owned()],
        },
    }
}

/// Every file target and the staging directory of `input`.
pub fn every_written_path(input: &DomainInput) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = provision::Target::installation_order()
        .iter()
        .map(|t| t.path(&input.paths).as_path().to_path_buf())
        .collect();
    paths.push(input.paths.staging.as_path().to_path_buf());
    paths
}

/// `true` if nothing of `input` exists (no target, no staging directory).
pub fn nothing_written(input: &DomainInput) -> bool {
    every_written_path(input)
        .iter()
        .all(|p| std::fs::symlink_metadata(p).is_err())
}

/// The mode bits (permissions) of `path`.
pub fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}
