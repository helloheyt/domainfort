//! keyadm's local rules, without keyd: the outcome classification, the
//! command line, the refusal to run as root, the report and exit status,
//! and the configuration-file rule.
//!
//! Each test names its source (docs/51 §x, docs/50 §x, docs/10 §x, A-xx).
//! Every value is constructed by hand for these tests (obviously fake); no
//! vector comes from any other implementation.

use dtyp::{Guid, Sid};
use ipc::Refused;
use ipc_keyd::{Answer, ConversionError, TransportError, Unserved};
use keyadm::ceremony::{classify, CeremonyReport, NotSent, Outcome, Step, StepReport, Unknown};
use keyadm::cli::{self, Command, UsageError};
use keyadm::identity::{refuse_root, IdentityError};
use keyadm::report::{self, EXIT_COMPLETE, EXIT_INCOMPLETE, EXIT_NOTHING_ATTEMPTED};
use keyadm::settings::{read_settings, SettingsError};
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

fn create(result: Result<Answer, Unserved>) -> Outcome<Kvno> {
    classify(result, |answer| match answer {
        Answer::CreateKey(result) => Some(result),
        _ => None,
    })
}

// ---- outcome classification --------------------------------------------------

/// crates/keyadm ceremony.rs table (from docs/50 R50-3, §3.6, §3.7 and the
/// keyd-daemon engine's refusal points): what was certainly not sent, not
/// run, answered, or is unknown.
#[test]
fn every_client_result_is_classified() {
    let kvno = Kvno::new(1);
    assert_eq!(
        create(Ok(Answer::CreateKey(Ok(kvno)))),
        Outcome::Answered(Ok(kvno))
    );
    assert_eq!(
        create(Ok(Answer::CreateKey(Err(KeydError::Denied)))),
        Outcome::Answered(Err(KeydError::Denied))
    );
    // R50-3: the peer uid check fails before anything is sent.
    assert_eq!(
        create(Err(Unserved::PeerMismatch)),
        Outcome::NotSent(NotSent::PeerMismatch)
    );
    assert_eq!(
        create(Err(Unserved::Transport(TransportError::Connect))),
        Outcome::NotSent(NotSent::Connect)
    );
    assert_eq!(
        create(Err(Unserved::Transport(TransportError::PeerCredentials))),
        Outcome::NotSent(NotSent::PeerCredentials)
    );
    assert_eq!(
        create(Err(Unserved::Unencodable)),
        Outcome::NotSent(NotSent::Unencodable)
    );
    // Refused before keyd runs the operation (the audit gate / queue → Busy;
    // decoding → Malformed / VersionMismatch).
    for refused in [Refused::Busy, Refused::Malformed, Refused::VersionMismatch] {
        assert_eq!(
            create(Err(Unserved::Refused(refused))),
            Outcome::NotRun(refused)
        );
    }
    // Possibly after keyd ran it: unknown.
    assert_eq!(
        create(Err(Unserved::Refused(Refused::Unavailable))),
        Outcome::Unknown(Unknown::RefusedUnavailable)
    );
    for transport in [
        TransportError::Closed,
        TransportError::DeadlineExceeded,
        TransportError::Io,
        TransportError::Framing,
    ] {
        assert_eq!(
            create(Err(Unserved::Transport(transport))),
            Outcome::Unknown(Unknown::Transport(transport))
        );
    }
    assert_eq!(
        create(Err(Unserved::MalformedReply(ipc::Error::FrameTooShort))),
        Outcome::Unknown(Unknown::MalformedReply)
    );
    assert_eq!(
        create(Err(Unserved::UnexpectedReply(
            ConversionError::UnexpectedReply
        ))),
        Outcome::Unknown(Unknown::UnexpectedReply)
    );
    // An answer of another operation (never produced by the client, which
    // checks it) is unknown, not success.
    assert_eq!(
        create(Ok(Answer::Ping(Ok(())))),
        Outcome::Unknown(Unknown::UnexpectedReply)
    );
}

// ---- command line --------------------------------------------------------------

/// docs/51 §6 (`ceremony <manifest>`), the configuration path first as the
/// daemons take it; exactly three arguments, no options; the A9/A10
/// commands have no code path yet.
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
/// kvno and exits 0.
#[test]
fn a_complete_report_prints_handles_bindings_and_kvnos() {
    let m = manifest();
    let report = CeremonyReport {
        contact: Outcome::Answered(Ok(())),
        steps: Step::ALL
            .iter()
            .map(|s| step(*s, Outcome::Answered(Ok(Kvno::new(1)))))
            .collect(),
    };
    assert!(report.is_complete());
    assert_eq!(report::exit_code(&report), EXIT_COMPLETE);
    let text = report::render(&report, &m).join("\n");
    for expected in [
        "created krbtgt: principal 00000000-0000-0000-0000-000000000001 purpose Krbtgt binding NT-SRV-INST:krbtgt/EXAMPLE.TEST kvno 1",
        "created ldap service: principal 00000000-0000-0000-0000-000000000002 purpose Service binding NT-SRV-HST:ldap/dc1.example.test kvno 1",
        "created admin service: principal 00000000-0000-0000-0000-000000000003 purpose Service binding NT-SRV-HST:admind/dc1.example.test kvno 1",
        "ceremony complete: 3 of 3 key sets created",
    ] {
        assert!(text.contains(expected), "{expected}\n---\n{text}");
    }
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

/// The ceremony.rs table: an unknown outcome is reported as "MAY have been
/// created", after the created ones.
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
    };
    assert_eq!(report::exit_code(&report), EXIT_INCOMPLETE);
    assert_eq!(report.created(), [(Step::Krbtgt, Kvno::new(1))]);
    let text = report::render(&report, &m).join("\n");
    assert!(text
        .contains("ldap service: keyd did not answer in time; the key set MAY have been created"));
    assert!(text.contains("1 of 3 key sets created; not attempted: admin service"));
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
        Outcome::NotRun(Refused::Busy),
        Outcome::Answered(Err(KeydError::Denied)),
    ] {
        let report = CeremonyReport {
            contact,
            steps: Vec::new(),
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
    let dir = std::env::temp_dir().join(format!("keyadm-local-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
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
    assert_eq!(
        read_settings(&dir.join("absent")),
        Err(SettingsError::Unreadable)
    );
    assert_eq!(read_settings(&dir), Err(SettingsError::Permissions));
    let _ = std::fs::remove_dir_all(&dir);
}
