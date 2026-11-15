//! `provision domain` end to end on the real filesystem (a fresh temporary
//! directory), with the test's [`Recorder`] in place of root's `fchown`
//! (it records and checks each requested owner) and the test's uid
//! standing in for dird's — then the produced files are opened exactly as
//! the daemons open them at start.
//!
//! Sources: docs/51 §4.3 steps 1-9, §4.4 (refuse to overwrite; staging and
//! rename; the crash table); Q-270 items 1-3 (dird's start: the 0400
//! integrity key, the root-owned policy, the dird-owned 0600 database with
//! its NC root and krbtgt); A-68, A-69 (dird's and kdc's policy loaders);
//! docs/50 §7.1 (every configuration parsed by its schema); docs/47 §1.3,
//! §1.4 (the account source resolves the first administrators; the krbtgt
//! handle); A-86 (the manifest parses back). Fixtures: tests/common.

mod common;

use common::*;

use std::os::unix::fs::MetadataExt;

use directory_daemon::startup::{read_integrity_key, read_policy};
use directory_pip::{DirectoryContext, NamingContext};
use dirstore::Store;
use kdc::AccountSource;
use keyd_types::KeydConfig;
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_INST};
use krb_proto::{KerberosString, PrincipalName, Realm};
use provision::install::InstallCause;
use provision::{
    install, provision_domain, InstallState, ObjectRole, Owner, Plan, ProvisionError, Staged, Step,
    Target,
};
use provision_manifest::Manifest;

/// Run `provision domain` with the recorder and a halting point.
fn run(
    input: &provision::DomainInput,
    recorder: &mut Recorder,
    progress: &mut HaltAt,
) -> Result<(Plan, provision::Installed), ProvisionError> {
    provision_domain(
        input,
        now(),
        &mut CountingRandom::default(),
        recorder,
        progress,
    )
}

/// docs/51 §4.3 steps 3-9: every file installed with its mode, every
/// requested owner as the step names it, the staging directory removed;
/// then each file passes the check its daemon makes at start.
#[test]
fn provisioning_installs_files_the_daemons_accept() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let input = input(&dir, uid, 61007);
    let mut recorder = Recorder::new(uid);
    let mut progress = HaltAt::never();
    let (plan, installed) = run(&input, &mut recorder, &mut progress).unwrap();

    // Steps 3-9: the steps in order, the database renamed last.
    let installs: Vec<Target> = progress
        .seen
        .iter()
        .filter_map(|s| match s {
            Step::Installed(t) => Some(*t),
            _ => None,
        })
        .collect();
    assert_eq!(installs, Target::installation_order());
    assert_eq!(installs.last(), Some(&Target::Store));
    assert_eq!(progress.seen.first(), Some(&Step::StagingCreated));
    assert_eq!(progress.seen.last(), Some(&Step::StagingRemoved));
    // Nine configuration files since task K9 (kpasswd-front, dnsd), the
    // policy, the key, the manifest, the database.
    assert_eq!(installed.targets.len(), 13);
    assert!(std::fs::symlink_metadata(input.paths.staging.as_path()).is_err());

    // Owners (Q-270 item 3; A-68; docs/51 §4.3): root for everything but
    // the database, which is dird's.
    let root = Owner { uid: 0, gid: 0 };
    assert_eq!(recorder.owner_of(Staged::StagingDirectory), Some(root));
    assert_eq!(recorder.owner_of(Staged::IntegrityKey), Some(root));
    assert_eq!(recorder.owner_of(Staged::Policy), Some(root));
    assert_eq!(recorder.owner_of(Staged::Manifest), Some(root));
    for daemon in provision::Daemon::ALL {
        assert_eq!(recorder.owner_of(Staged::Config(daemon)), Some(root));
    }
    assert_eq!(
        recorder.owner_of(Staged::Store),
        Some(Owner { uid, gid: uid })
    );
    assert_eq!(recorder.records.len(), 14);

    // Modes: key 0400, database 0600, the rest 0644.
    let p = &input.paths;
    assert_eq!(mode(p.integrity_key.as_path()), 0o400);
    assert_eq!(mode(p.database.as_path()), 0o600);
    for path in [
        &p.policy,
        &p.manifest,
        &p.keyd_config,
        &p.dird_config,
        &p.kdc_config,
        &p.kpasswd_front_config,
        &p.dnsd_config,
    ] {
        assert_eq!(mode(path.as_path()), 0o644, "{path:?}");
    }

    // The integrity key: dird's own reader (root-owned 0400, 32 octets —
    // the test's uid stands in for root here: no chown without root).
    let key = read_integrity_key(p.integrity_key.as_path(), uid).unwrap();
    assert_eq!(
        std::fs::metadata(p.integrity_key.as_path()).unwrap().len(),
        32
    );

    // The database: dird's file rule (owned by dird's uid, no group /
    // other access), then the store with that key, then the domain check
    // dird makes before it binds anything (Q-270 item 3).
    let meta = std::fs::symlink_metadata(p.database.as_path()).unwrap();
    assert!(meta.file_type().is_file());
    assert_eq!(meta.uid(), uid);
    assert_eq!(meta.mode() & 0o077, 0);
    let schema = ad_schema::phase1().unwrap();
    let store = Store::open(p.database.as_path(), key, schema.schema().clone()).unwrap();
    let realm = Realm::new("EXAMPLE.TEST").unwrap();
    let nc = NamingContext::new(&["example", "test"]).unwrap();
    let ctx = DirectoryContext::new(schema, &KeydConfig::new(realm.clone()), nc).unwrap();

    // The policy: dird's and kdc's loaders (A-68, A-69).
    let policy = read_policy(p.policy.as_path(), uid).unwrap();
    assert_eq!(policy, plan.policy);
    let kdc_policy = kdc_daemon::startup::read_policy(p.policy.as_path(), uid).unwrap();
    assert_eq!(kdc_policy.version, policy.version);
    policy.snapshot().unwrap();
    let tiers = directory_daemon::policy::tier_map(&policy).unwrap();

    let domain = ipc_directory_server::describe(&ctx, &store, &tiers, policy.version).unwrap();
    assert_eq!(
        domain.krbtgt.principal.as_bytes(),
        &plan.object(ObjectRole::Krbtgt).unwrap().guid.to_packet()
    );
    assert_eq!(domain.naming_context, vec!["example", "test"]);

    // directory-pip resolves the krbtgt account and both first
    // administrators (docs/47 §1.3, §1.4): usable now (enabled, never
    // expiring, pwdLastSet set), Tier0 through the Tier-0 group.
    let view = ctx.view(&store, &tiers).unwrap();
    let handle = view.krbtgt_handle(&plan.domain_sid).unwrap();
    assert_eq!(handle, domain.krbtgt);
    for (i, name) in ["alice", "bob"].iter().enumerate() {
        let cname = PrincipalName {
            name_type: KRB_NT_PRINCIPAL,
            name_string: vec![KerberosString::new(name).unwrap()],
        };
        let account = view.client(&realm, &cname).unwrap().unwrap();
        let planned = plan.object(ObjectRole::FirstAdmin(i)).unwrap();
        assert_eq!(Some(account.sid), planned.sid);
        assert!(account.state.usable_at(&at(10, 0, 5)));
        assert_eq!(account.tier, pdp::Tier::Tier0);
        let tier0 = plan.object(ObjectRole::Tier0Group).unwrap().sid.unwrap();
        assert!(account.groups.contains(&tier0));
    }
    // krbtgt is never an AS client (docs/47 §1.3 step 6).
    let krbtgt_name = PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![KerberosString::new("krbtgt").unwrap()],
    };
    assert!(view.client(&realm, &krbtgt_name).unwrap().is_none());
    // Task K9 (RFC 3244 §2; docs/53 §5.2; docs/questions/Q-964 items 4,
    // 13): `kadmin/changepw` resolves as the KDC's AS and dird's kpasswd
    // service resolve it — the account source's `service` — to the
    // manifest's change-password service object, its key set
    // `(GUID, ChangePasswordService)`, usable now.
    let changepw_name = PrincipalName {
        name_type: KRB_NT_SRV_INST,
        name_string: ["kadmin", "changepw"]
            .iter()
            .map(|c| KerberosString::new(c).unwrap())
            .collect(),
    };
    let changepw = view.service(&realm, &changepw_name).unwrap().unwrap();
    assert_eq!(changepw.key, plan.manifest.change_password_service().handle);
    assert_eq!(
        changepw.key.purpose,
        keyd_types::KeyPurpose::ChangePasswordService
    );
    assert!(changepw.state.usable_at(&at(10, 0, 5)));
    drop(view);

    // The engine dird builds at start accepts the store (its domain check).
    let engine = directory_daemon::DirectoryEngine::new(
        std::sync::Arc::new(store),
        DirectoryContext::new(
            ad_schema::phase1().unwrap(),
            &KeydConfig::new(realm),
            NamingContext::new(&["example", "test"]).unwrap(),
        )
        .unwrap(),
        tiers,
        policy.version,
        ipc_directory_server::ViewLimits {
            max_views: 4,
            lifetime: core::time::Duration::from_secs(5),
        },
    );
    assert!(engine.is_ok());

    // Every configuration file parses with its daemon's schema (dird
    // without the three A8 keys until that schema is merged).
    let read = |path: &provision::FilePath| std::fs::read(path.as_path()).unwrap();
    config::KeydSettings::parse(&read(&p.keyd_config)).unwrap();
    config::KdcSettings::parse(&read(&p.kdc_config)).unwrap();
    config::LdapFrontSettings::parse(&read(&p.ldap_front_config)).unwrap();
    config::AuditdSettings::parse(&read(&p.auditd_config)).unwrap();
    config::AdmindSettings::parse(&read(&p.admind_config)).unwrap();
    config::KeyadmSettings::parse(&read(&p.keyadm_config)).unwrap();
    // dird's whole file, admin-channel keys included (A-91).
    let dird_settings = config::DirdSettings::parse(&read(&p.dird_config)).unwrap();
    assert_eq!(dird_settings.run_as().uid(), uid);
    assert_eq!(dird_settings.database_path().as_str(), p.database.as_str());

    // The manifest parses back (A-86), and has only identifiers.
    let manifest = Manifest::parse(&read(&p.manifest)).unwrap();
    assert_eq!(manifest, plan.manifest);
}

/// docs/51 §4.4 ("every target path absent; no `--force`"): any existing
/// target — of any kind, a dangling link included — refuses the run with
/// nothing written.
#[test]
fn any_existing_target_refuses_with_nothing_written() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let base = input(&dir, uid, 61007);
    for target in Target::installation_order() {
        let path = target.path(&base.paths).as_path().to_path_buf();
        std::fs::write(&path, b"x").unwrap();
        let mut recorder = Recorder::new(uid);
        let mut rng = CountingRandom::default();
        let err = provision_domain(&base, now(), &mut rng, &mut recorder, &mut HaltAt::never())
            .unwrap_err();
        assert_eq!(err.state(), InstallState::NothingWritten, "{target:?}");
        assert!(matches!(
            err,
            ProvisionError::Install(provision::InstallError {
                cause: InstallCause::Exists(_),
                ..
            })
        ));
        // No draw was made and nothing else exists.
        assert_eq!(rng.fills, 0);
        assert!(recorder.records.is_empty());
        std::fs::remove_file(&path).unwrap();
        assert!(nothing_written(&base), "{target:?}");
    }
    // The staging directory, and a dangling link at a target.
    std::fs::create_dir(base.paths.staging.as_path()).unwrap();
    let err = run(&base, &mut Recorder::new(uid), &mut HaltAt::never()).unwrap_err();
    assert_eq!(err.state(), InstallState::NothingWritten);
    std::fs::remove_dir(base.paths.staging.as_path()).unwrap();
    std::os::unix::fs::symlink(dir.join("nowhere"), base.paths.policy.as_path()).unwrap();
    let err = run(&base, &mut Recorder::new(uid), &mut HaltAt::never()).unwrap_err();
    assert_eq!(err.state(), InstallState::NothingWritten);
    std::fs::remove_file(base.paths.policy.as_path()).unwrap();
    assert!(nothing_written(&base));
}

/// docs/51 §4.4: a parent directory writable by others, or missing,
/// refuses the run with nothing written.
#[test]
fn unsafe_or_missing_parents_refuse_with_nothing_written() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let mut i = input(&dir, uid, 61007);
    i.paths.database = path(&dir, "missing/directory.redb");
    let err = run(&i, &mut Recorder::new(uid), &mut HaltAt::never()).unwrap_err();
    assert_eq!(err.state(), InstallState::NothingWritten);
    assert!(nothing_written(&i));
    let i = input(&dir, uid, 61007);
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.join("var"), std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = run(&i, &mut Recorder::new(uid), &mut HaltAt::never()).unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Install(provision::InstallError {
            cause: InstallCause::ParentWritable(_),
            ..
        })
    ));
    assert!(nothing_written(&i));
    std::fs::set_permissions(dir.join("var"), std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Task R11c (docs/52 C13; docs/questions Q-532 item 2, A-109): every path
/// is walked from `/` — a symbolic link in a directory component of a
/// target (here `etc`, a link to a real directory) or of the staging
/// directory refuses the run with nothing written, and nothing is created
/// under the link's target.
#[test]
fn a_link_in_a_directory_component_refuses_with_nothing_written() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let i = input(&dir, uid, 61007);
    std::fs::remove_dir(dir.join("etc")).unwrap();
    std::fs::create_dir(dir.join("etc-real")).unwrap();
    std::os::unix::fs::symlink(dir.join("etc-real"), dir.join("etc")).unwrap();
    let mut rng = CountingRandom::default();
    let mut recorder = Recorder::new(uid);
    let err =
        provision_domain(&i, now(), &mut rng, &mut recorder, &mut HaltAt::never()).unwrap_err();
    assert_eq!(err.state(), InstallState::NothingWritten);
    assert!(matches!(
        err,
        ProvisionError::Install(provision::InstallError {
            cause: InstallCause::Parent(_),
            ..
        })
    ));
    assert_eq!(rng.fills, 0);
    assert!(recorder.records.is_empty());
    assert_eq!(std::fs::read_dir(dir.join("etc-real")).unwrap().count(), 0);
}

/// Task R11c (Q-468 option 2(b), A-102): every directory on every path
/// must be root's — with another account standing in for root, the test
/// account's own directories are refused before anything is written.
#[test]
fn a_directory_not_owned_by_root_refuses_with_nothing_written() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let i = input(&dir, uid, 61007);
    let err = run(&i, &mut Recorder::new(uid + 1), &mut HaltAt::never()).unwrap_err();
    assert_eq!(err.state(), InstallState::NothingWritten);
    assert!(matches!(
        err,
        ProvisionError::Install(provision::InstallError {
            cause: InstallCause::ParentOwner(_),
            ..
        })
    ));
    assert!(nothing_written(&i));
}

/// A-15 / A-77: a CSPRNG failure stops the run before anything is
/// written.
#[test]
fn a_csprng_failure_writes_nothing() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let i = input(&dir, uid, 61007);
    for fail_at in [1, 5, 13, 14] {
        let mut rng = FailingRandom {
            fail_at,
            inner: CountingRandom::default(),
        };
        let mut recorder = Recorder::new(uid);
        let err =
            provision_domain(&i, now(), &mut rng, &mut recorder, &mut HaltAt::never()).unwrap_err();
        assert!(matches!(
            err,
            ProvisionError::Plan(provision::PlanError::Random)
        ));
        assert_eq!(err.state(), InstallState::NothingWritten);
        assert!(recorder.records.is_empty());
        assert!(nothing_written(&i));
    }
}

/// Where each target is after a halt.
fn installed(input: &provision::DomainInput) -> Vec<Target> {
    Target::installation_order()
        .into_iter()
        .filter(|t| std::fs::symlink_metadata(t.path(&input.paths).as_path()).is_ok())
        .collect()
}

/// docs/51 §4.4 (the crash table of module `install`): a crash — here a
/// halt — at each point leaves the documented state, and a re-run refuses
/// without writing anything.
#[test]
fn a_crash_at_each_point_leaves_the_documented_state_and_a_rerun_refuses() {
    let cases: Vec<(Step, InstallState, usize)> = vec![
        (Step::StagingCreated, InstallState::StagingOnly, 0),
        (
            Step::Staged(Target::IntegrityKey),
            InstallState::StagingOnly,
            0,
        ),
        (Step::Staged(Target::Store), InstallState::StagingOnly, 0),
        (
            Step::Staged(Target::Config(provision::Daemon::Admind)),
            InstallState::StagingOnly,
            0,
        ),
        (Step::StagingSynced, InstallState::StagingOnly, 0),
        (
            Step::Installed(Target::Config(provision::Daemon::Keyd)),
            InstallState::PartlyInstalled,
            1,
        ),
        (
            Step::Installed(Target::Manifest),
            InstallState::PartlyInstalled,
            12,
        ),
        (Step::TargetsSynced, InstallState::PartlyInstalled, 12),
        (
            Step::Installed(Target::Store),
            InstallState::InstalledStagingLeft,
            13,
        ),
        (Step::StagingRemoved, InstallState::InstalledStagingLeft, 13),
    ];
    for (step, state, in_place) in cases {
        let dir = TempDir::new();
        let uid = my_uid(&dir);
        if skip_as_root(uid) {
            return;
        }
        let i = input(&dir, uid, 61007);
        let err = run(&i, &mut Recorder::new(uid), &mut HaltAt::new(step)).unwrap_err();
        assert_eq!(err.state(), state, "{step:?}");
        let present = installed(&i);
        assert_eq!(present.len(), in_place, "{step:?}: {present:?}");
        // The database is never in place before every other target.
        if present.contains(&Target::Store) {
            assert_eq!(present.len(), 13, "{step:?}");
        }
        let staging_left = std::fs::symlink_metadata(i.paths.staging.as_path()).is_ok();
        assert_eq!(staging_left, step != Step::StagingRemoved, "{step:?}");
        // A re-run refuses at once, draws nothing and writes nothing.
        let before: Vec<bool> = every_written_path(&i)
            .iter()
            .map(|p| std::fs::symlink_metadata(p).is_ok())
            .collect();
        let mut rng = CountingRandom::default();
        let mut recorder = Recorder::new(uid);
        let again =
            provision_domain(&i, now(), &mut rng, &mut recorder, &mut HaltAt::never()).unwrap_err();
        assert_eq!(again.state(), InstallState::NothingWritten, "{step:?}");
        assert_eq!(rng.fills, 0);
        assert!(recorder.records.is_empty());
        let after: Vec<bool> = every_written_path(&i)
            .iter()
            .map(|p| std::fs::symlink_metadata(p).is_ok())
            .collect();
        assert_eq!(before, after, "{step:?}");
    }
}

/// The owner change failing (as root would on a broken filesystem) stops
/// the run in the staging state; nothing is installed.
#[test]
fn an_owner_change_failure_leaves_only_the_staging_directory() {
    for fail_on in [
        Staged::StagingDirectory,
        Staged::IntegrityKey,
        Staged::Store,
        Staged::Manifest,
    ] {
        let dir = TempDir::new();
        let uid = my_uid(&dir);
        if skip_as_root(uid) {
            return;
        }
        let i = input(&dir, uid, 61007);
        let mut recorder = Recorder::new(uid);
        recorder.fail_on = Some(fail_on);
        let err = run(&i, &mut recorder, &mut HaltAt::never()).unwrap_err();
        assert_eq!(err.state(), InstallState::StagingOnly, "{fail_on:?}");
        assert!(installed(&i).is_empty());
    }
}

/// docs/51 §4.4: the plan is built only after the pre-check; `install`
/// itself repeats the pre-check (a target created after the plan is still
/// refused, with nothing written).
#[test]
fn install_repeats_the_precheck() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let i = input(&dir, uid, 61007);
    let plan = Plan::build(&i, now(), &mut CountingRandom::default()).unwrap();
    std::fs::write(i.paths.manifest.as_path(), b"late").unwrap();
    let err = install(&plan, &mut Recorder::new(uid), &mut HaltAt::never()).unwrap_err();
    assert_eq!(err.state, InstallState::NothingWritten);
    assert!(std::fs::symlink_metadata(i.paths.staging.as_path()).is_err());
}
