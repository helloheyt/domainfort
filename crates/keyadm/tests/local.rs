//! keyadm's local rules, without keyd: the outcome classification, the
//! command line, the refusal to run as root, the report and exit status,
//! and the configuration-file rule.
//!
//! Each test names its source (docs/51 §x, docs/50 §x, docs/10 §x, A-xx).
//! Every value is constructed by hand for these tests (obviously fake); no
//! vector comes from any other implementation.

use dtyp::{Guid, Sid};
use ipc::Refused;
use ipc_keyd::{Answer, CallFailure, ConversionError, RequestFate, TransportError, Unserved};
use keyadm::ceremony::{
    classify, CeremonyReport, GrantReport, NotSent, Outcome, Step, StepReport, Unknown,
};
use keyadm::cli::{self, Command, UsageError};
use keyadm::identity::{refuse_root, IdentityError};
use keyadm::report::{self, EXIT_COMPLETE, EXIT_INCOMPLETE, EXIT_NOTHING_ATTEMPTED};
use keyadm::settings::{read_settings, read_settings_owned_by, SettingsError};
use keyd_types::{Error as KeydError, Kvno};
use provision_manifest::{Manifest, ManifestFields};
use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

fn guid(last: u8) -> Guid {
    let mut packet = [0u8; 16];
    packet[15] = last;
    Guid::from_packet(&packet)
}

/// An obviously fake manifest (realm EXAMPLE.TEST, the [MS-DTYP] 2.4.2.4
/// example domain SID).
fn manifest() -> Manifest {
    Manifest::new(&ManifestFields {
        realm: "EXAMPLE.TEST".to_owned(),
        domain_sid: Sid::parse_sid_string("S-1-5-21-1-2-3").unwrap(),
        naming_context: vec!["example".to_owned(), "test".to_owned()],
        dc_fqdn: "dc1.example.test".to_owned(),
        krbtgt: guid(1),
        ldap_service: guid(2),
        admin_service: guid(3),
        first_admins: vec![(guid(4), "alice".to_owned()), (guid(5), "bob".to_owned())],
    })
    .unwrap()
}

fn create(result: Result<Answer, CallFailure>) -> Outcome<Kvno> {
    classify(result, |answer| match answer {
        Answer::CreateKey(result) => Some(result),
        _ => None,
    })
}

/// A failure as the ipc-keyd client reports it (`call_with_fate`).
fn failed(unserved: Unserved, fate: RequestFate) -> Result<Answer, CallFailure> {
    Err(CallFailure { unserved, fate })
}

// ---- outcome classification --------------------------------------------------

/// crates/keyadm ceremony.rs table (from docs/50 R50-3, §3.6, §3.7, the
/// keyd-daemon engine's refusal points, and the client's request fate —
/// docs/questions/Q-367, A-88): what was certainly not sent, not performed,
/// answered, or is unknown.
#[test]
fn every_client_result_is_classified() {
    use RequestFate::{NotPerformed, NotSent as Unsent, OutcomeUnknown};
    let kvno = Kvno::new(1);
    assert_eq!(
        create(Ok(Answer::CreateKey(Ok(kvno)))),
        Outcome::Answered(Ok(kvno))
    );
    assert_eq!(
        create(Ok(Answer::CreateKey(Err(KeydError::Denied)))),
        Outcome::Answered(Err(KeydError::Denied))
    );
    // keyd's own Unavailable answer is keyd's answer (refused before it
    // stored anything).
    assert_eq!(
        create(Ok(Answer::CreateKey(Err(KeydError::Unavailable)))),
        Outcome::Answered(Err(KeydError::Unavailable))
    );
    // Not sent — R50-3: the peer uid check fails before anything is sent;
    // the connection, the deadline before writing, encoding.
    assert_eq!(
        create(failed(Unserved::PeerMismatch, Unsent)),
        Outcome::NotSent(NotSent::PeerMismatch)
    );
    assert_eq!(
        create(failed(Unserved::Transport(TransportError::Connect), Unsent)),
        Outcome::NotSent(NotSent::Connect)
    );
    assert_eq!(
        create(failed(
            Unserved::Transport(TransportError::PeerCredentials),
            Unsent
        )),
        Outcome::NotSent(NotSent::PeerCredentials)
    );
    assert_eq!(
        create(failed(
            Unserved::Transport(TransportError::DeadlineExceeded),
            Unsent
        )),
        Outcome::NotSent(NotSent::Transport(TransportError::DeadlineExceeded))
    );
    assert_eq!(
        create(failed(Unserved::Unencodable, Unsent)),
        Outcome::NotSent(NotSent::Unencodable)
    );
    // A failed DescribeConfig check (a client that requires one; keyadm's
    // never does): only that was sent.
    assert_eq!(
        create(failed(Unserved::Refused(Refused::Busy), Unsent)),
        Outcome::NotSent(NotSent::PeerMismatch)
    );
    // Not performed — every shared refusal, keyd's Unavailable included
    // (A-88: keyd-daemon refuses a key-state change only before keyd runs
    // it; Busy while auditd is away; Malformed / VersionMismatch before
    // decoding).
    for refused in [
        Refused::Unavailable,
        Refused::Busy,
        Refused::Malformed,
        Refused::VersionMismatch,
    ] {
        assert_eq!(
            create(failed(Unserved::Refused(refused), NotPerformed)),
            Outcome::NotPerformed(refused)
        );
    }
    // Outcome unknown — the request was sent and no usable reply came.
    for transport in [
        TransportError::Closed,
        TransportError::DeadlineExceeded,
        TransportError::Io,
        TransportError::Framing,
    ] {
        assert_eq!(
            create(failed(Unserved::Transport(transport), OutcomeUnknown)),
            Outcome::Unknown(Unknown::Transport(transport))
        );
    }
    assert_eq!(
        create(failed(
            Unserved::MalformedReply(ipc::Error::FrameTooShort),
            OutcomeUnknown
        )),
        Outcome::Unknown(Unknown::MalformedReply)
    );
    assert_eq!(
        create(failed(
            Unserved::UnexpectedReply(ConversionError::UnexpectedReply),
            OutcomeUnknown
        )),
        Outcome::Unknown(Unknown::UnexpectedReply)
    );
    // An answer of another operation (never produced by the client, which
    // checks it) is unknown, not success.
    assert_eq!(
        create(Ok(Answer::Ping(Ok(())))),
        Outcome::Unknown(Unknown::UnexpectedReply)
    );
    // A pairing the client never produces claims the least: "not
    // performed" without a refusal is unknown.
    assert_eq!(
        create(failed(
            Unserved::Transport(TransportError::Closed),
            NotPerformed
        )),
        Outcome::Unknown(Unknown::Transport(TransportError::Closed))
    );
    assert_eq!(
        create(failed(Unserved::PeerMismatch, NotPerformed)),
        Outcome::Unknown(Unknown::UnexpectedReply)
    );
}

// ---- command line --------------------------------------------------------------

/// docs/51 §6 (`ceremony <manifest>`), the configuration path first as the
/// daemons take it; exactly three arguments, no options; the A10 commands
/// take a decimal request id (`destroy-sweep` nothing) — the rest of their
/// grammar is in tests/key_operations_local.rs.
#[test]
fn the_command_line_is_exact() {
    let args = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
    assert_eq!(
        cli::parse(args(&[
            "/etc/test/keyadm.conf",
            "ceremony",
            "/etc/test/manifest"
        ])),
        Ok(Command::Ceremony {
            config: PathBuf::from("/etc/test/keyadm.conf"),
            manifest: PathBuf::from("/etc/test/manifest"),
        })
    );
    for bad in [
        &[][..],
        &["/c"][..],
        &["/c", "ceremony"][..],
        &["/c", "ceremony", "/m", "extra"][..],
        &["/c", "Ceremony", "/m"][..],
        &["ceremony", "/m", "/c"][..],
        &["/c", "destroy-sweep", "/m"][..],
        &["/c", "rotate-krbtgt", "/m"][..],
        &["/c", "--force", "/m"][..],
    ] {
        assert_eq!(cli::parse(args(bad)), Err(UsageError), "{bad:?}");
    }
}

// ---- identity -------------------------------------------------------------------

/// docs/50 R50-3 ("uid 0 is never mapped"): keyadm refuses a real or
/// effective uid of 0 before doing anything else.
#[test]
fn root_is_refused() {
    assert_eq!(refuse_root(0, 0), Err(IdentityError::Root));
    assert_eq!(refuse_root(4102, 0), Err(IdentityError::Root));
    assert_eq!(refuse_root(0, 4102), Err(IdentityError::Root));
    assert_eq!(refuse_root(4102, 4102), Ok(()));
    assert!(IdentityError::Root.to_string().contains("root"));
}

// ---- report and exit status --------------------------------------------------------

fn step(step: Step, outcome: Outcome<Kvno>) -> StepReport {
    StepReport { step, outcome }
}

/// docs/51 §4.3 step 11; docs/10 §10 (handles, bindings and kvnos are not
/// secret): a complete ceremony prints each key set's handle, binding and
/// kvno — and, since task A15a, each first administrator's grant — and
/// exits 0.
#[test]
fn a_complete_report_prints_handles_bindings_and_kvnos() {
    let m = manifest();
    let report = CeremonyReport {
        contact: Outcome::Answered(Ok(())),
        steps: Step::ALL
            .iter()
            .map(|s| step(*s, Outcome::Answered(Ok(Kvno::new(1)))))
            .collect(),
        grants: (0..m.first_admins().len())
            .map(|admin| GrantReport {
                admin,
                outcome: Outcome::Answered(Ok(())),
            })
            .collect(),
        first_admins: m.first_admins().len(),
    };
    assert!(report.is_complete());
    assert_eq!(report::exit_code(&report), EXIT_COMPLETE);
    let text = report::render(&report, &m).join("\n");
    for expected in [
        "created krbtgt: principal 00000000-0000-0000-0000-000000000001 purpose Krbtgt binding NT-SRV-INST:krbtgt/EXAMPLE.TEST kvno 1",
        "created ldap service: principal 00000000-0000-0000-0000-000000000002 purpose Service binding NT-SRV-HST:ldap/dc1.example.test kvno 1",
        "created admin service: principal 00000000-0000-0000-0000-000000000003 purpose Service binding NT-SRV-HST:admind/dc1.example.test kvno 1",
        "ceremony complete: 3 of 3 key sets created",
        "granted the initial secret of first administrator alice: principal 00000000-0000-0000-0000-000000000004 purpose PrincipalLongterm binding NT-PRINCIPAL:alice; live for 900 s",
        "2 of 2 first administrators' initial secrets granted",
        "run provision first-admin-secret within 15 minutes",
    ] {
        assert!(text.contains(expected), "{expected}\n---\n{text}");
    }
    // Without the grants the ceremony is not complete (task A15a).
    let without = CeremonyReport {
        grants: Vec::new(),
        ..report.clone()
    };
    assert!(!without.is_complete());
    assert!(without.key_sets_created());
    assert_eq!(report::exit_code(&without), EXIT_INCOMPLETE);
}

/// Task A15a (docs/questions/Q-451): a grant keyd refuses stops the
/// ceremony after the key sets — exit 2 — and the report says that keyd
/// grants keyadm only the initial secret of a user with no key set yet; an
/// unknown outcome says the grant MAY exist.
#[test]
fn a_refused_grant_stops_after_the_key_sets() {
    let m = manifest();
    let created: Vec<StepReport> = Step::ALL
        .iter()
        .map(|s| step(*s, Outcome::Answered(Ok(Kvno::new(1)))))
        .collect();
    let report = CeremonyReport {
        contact: Outcome::Answered(Ok(())),
        steps: created.clone(),
        grants: vec![GrantReport {
            admin: 0,
            outcome: Outcome::Answered(Err(KeydError::Denied)),
        }],
        first_admins: m.first_admins().len(),
    };
    assert!(!report.is_complete());
    assert_eq!(report::exit_code(&report), EXIT_INCOMPLETE);
    let text = report::render(&report, &m).join("\n");
    assert!(
        text.contains("first administrator alice: principal 00000000-0000-0000-0000-000000000004 purpose PrincipalLongterm binding NT-PRINCIPAL:alice: keyd refused the grant (denied); not granted"),
        "{text}"
    );
    assert!(text.contains("0 of 2 first administrators' initial secrets granted"));
    assert!(text.contains("initial secret of a user that has no key set yet"));
    let unknown = CeremonyReport {
        grants: vec![GrantReport {
            admin: 0,
            outcome: Outcome::Unknown(Unknown::Transport(TransportError::Closed)),
        }],
        ..report
    };
    let text = report::render(&unknown, &m).join("\n");
    assert!(
        text.contains("the grant MAY have been registered"),
        "{text}"
    );
}

/// docs/51 §4.3 step 11 ("a repeated ceremony on a keyd that was not
/// restarted fails closed"), §4.5 / A-77 (restart and repeat); docs/10 §9
/// (one uniform Denied): a refusal at the first step exits 2 and explains.
#[test]
fn a_refused_first_step_stops_and_explains() {
    let m = manifest();
    let report = CeremonyReport {
        contact: Outcome::Answered(Ok(())),
        steps: vec![step(
            Step::Krbtgt,
            Outcome::Answered(Err(KeydError::Denied)),
        )],
        grants: Vec::new(),
        first_admins: m.first_admins().len(),
    };
    assert_eq!(report::exit_code(&report), EXIT_INCOMPLETE);
    assert_eq!(
        report.not_attempted(),
        [Step::LdapService, Step::AdminService]
    );
    let text = report::render(&report, &m).join("\n");
    assert!(
        text.contains("krbtgt: keyd refused (denied); not created"),
        "{text}"
    );
    assert!(text.contains("0 of 3 key sets created; not attempted: ldap service, admin service"));
    assert!(text.contains("may already exist"));
    assert!(text.contains("restart keyd"));
}

/// The ceremony.rs table; Q-367 (A-88: "outcome unknown — check before
/// retrying"): an unknown outcome is reported as sent, outcome unknown and
/// "MAY have been created", after the created ones, with the pointer to
/// keyd's audit log.
#[test]
fn an_unknown_outcome_says_the_key_set_may_exist() {
    let m = manifest();
    let report = CeremonyReport {
        contact: Outcome::Answered(Ok(())),
        steps: vec![
            step(Step::Krbtgt, Outcome::Answered(Ok(Kvno::new(1)))),
            step(
                Step::LdapService,
                Outcome::Unknown(Unknown::Transport(TransportError::DeadlineExceeded)),
            ),
        ],
        grants: Vec::new(),
        first_admins: m.first_admins().len(),
    };
    assert_eq!(report::exit_code(&report), EXIT_INCOMPLETE);
    assert_eq!(report.created(), [(Step::Krbtgt, Kvno::new(1))]);
    let text = report::render(&report, &m).join("\n");
    assert!(
        text.contains(
            "ldap service: keyd did not answer in time after the request was sent; outcome unknown, the key set MAY have been created"
        ),
        "{text}"
    );
    assert!(text.contains("1 of 3 key sets created; not attempted: admin service"));
    assert!(text.contains("check keyd's audit log before anything else"));
}

/// docs/10 §10 (A-88: keyd's `Unavailable` on a key-state change means "not
/// performed"); docs/50 R50-3, §3.6, §3.7; Q-367 (A-88): the three fates of
/// a `create_key` keyd did not answer — not sent, not performed, outcome
/// unknown — each with its own report text; only the unknown one says the
/// key set MAY exist and points to the audit log. Each stops the ceremony
/// at the krbtgt step (exit 2: a step was attempted), and at the contact
/// (`ping`) each attempts nothing (exit 1).
#[test]
fn the_three_fates_are_reported_apart() {
    let m = manifest();
    let cases = [
        (
            Outcome::NotSent(NotSent::Transport(TransportError::DeadlineExceeded)),
            "krbtgt: the deadline passed before the request was sent (nothing was sent); not created",
        ),
        (
            Outcome::NotSent(NotSent::Connect),
            "krbtgt: the keyd socket could not be connected (nothing was sent); not created",
        ),
        (
            Outcome::NotPerformed(Refused::Unavailable),
            "krbtgt: keyd answered unavailable (not performed); not created",
        ),
        (
            Outcome::NotPerformed(Refused::Busy),
            "krbtgt: keyd is busy or cannot reach auditd (not performed); not created",
        ),
        (
            Outcome::Unknown(Unknown::Transport(TransportError::Closed)),
            "krbtgt: keyd closed the connection after the request was sent; outcome unknown, the key set MAY have been created",
        ),
    ];
    for (outcome, expected) in cases {
        let unknown = outcome.outcome_unknown();
        let report = CeremonyReport {
            contact: Outcome::Answered(Ok(())),
            steps: vec![step(Step::Krbtgt, outcome)],
            grants: Vec::new(),
            first_admins: m.first_admins().len(),
        };
        assert_eq!(report::exit_code(&report), EXIT_INCOMPLETE, "{expected}");
        assert_eq!(report.created(), []);
        let text = report::render(&report, &m).join("\n");
        assert!(text.contains(expected), "{expected}\n---\n{text}");
        assert_eq!(text.contains("MAY have been created"), unknown, "{text}");
        assert_eq!(text.contains("audit log"), unknown, "{text}");
        assert!(text.contains("0 of 3 key sets created"));

        let contact = CeremonyReport {
            contact: match outcome {
                Outcome::NotSent(reason) => Outcome::NotSent(reason),
                Outcome::NotPerformed(refused) => Outcome::NotPerformed(refused),
                Outcome::Unknown(reason) => Outcome::Unknown(reason),
                Outcome::Answered(_) => unreachable!("only the three fates"),
            },
            steps: Vec::new(),
            grants: Vec::new(),
            first_admins: m.first_admins().len(),
        };
        assert_eq!(report::exit_code(&contact), EXIT_NOTHING_ATTEMPTED);
        let text = report::render(&contact, &m).join("\n");
        assert!(text.contains("contact failed: "), "{text}");
        assert!(text.contains("no create_key was sent"), "{text}");
    }
}

/// docs/50 R50-3 (nothing is sent to a peer that is not keyd): a failed
/// contact attempts no create_key and exits 1.
#[test]
fn a_failed_contact_attempts_nothing() {
    let m = manifest();
    for contact in [
        Outcome::NotSent(NotSent::PeerMismatch),
        Outcome::NotSent(NotSent::Connect),
        Outcome::Unknown(Unknown::Transport(TransportError::Closed)),
        Outcome::NotPerformed(Refused::Busy),
        Outcome::NotPerformed(Refused::Unavailable),
        Outcome::Answered(Err(KeydError::Denied)),
    ] {
        let report = CeremonyReport {
            contact,
            steps: Vec::new(),
            grants: Vec::new(),
            first_admins: m.first_admins().len(),
        };
        assert_eq!(report::exit_code(&report), EXIT_NOTHING_ATTEMPTED);
        let text = report::render(&report, &m).join("\n");
        assert!(text.contains("no create_key was sent"), "{text}");
    }
}

// ---- configuration file --------------------------------------------------------------

/// docs/50 §7.1 ("file root:0644"): a configuration file the test user owns
/// is refused (wrong ownership) before it is parsed; a missing one is
/// unreadable.
#[test]
fn a_configuration_file_not_owned_by_root_is_refused() {
    // Inside the workspace (crates/test-scratch): the protected-file walk
    // from `/` accepts it for the test account (Q-480).
    let scratch = test_scratch::ScratchDir::new("keyadm-local").unwrap();
    let dir = scratch.path().to_path_buf();
    let path = dir.join("keyadm.conf");
    std::fs::write(
        &path,
        "keyd_socket = /run/test-keyd/keyd.sock\nkeyd_uid = 4101\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let owner = std::fs::metadata(&path).unwrap().uid();
    if owner != 0 {
        assert_eq!(read_settings(&path), Err(SettingsError::Permissions));
    }
    // A missing file is unreadable (asked with the test account standing in
    // for root: with root's expectation the walk refuses the test account's
    // own scratch directory first — task T, Q-468).
    assert_eq!(
        read_settings_owned_by(&dir.join("absent"), owner),
        Err(SettingsError::Unreadable)
    );
    assert_eq!(read_settings(&dir), Err(SettingsError::Permissions));
    let _ = std::fs::remove_dir_all(&dir);
}
