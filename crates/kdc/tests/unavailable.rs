//! An unavailable keyd or account source (docs/50 §3.7, R50-8; decision
//! A-56, docs/questions/Q-217): every exchange path on which keyd does not
//! serve a call — the `Unavailable` variant of its errors — or the account
//! source cannot be reached answers KDC_ERR_SVC_UNAVAILABLE ("29 A service
//! is not available", RFC 4120 §7.5.9) over TCP and nothing over UDP, and is
//! audited with its own reason; never KDC_ERR_PREAUTH_FAILED or
//! KRB_AP_ERR_BAD_INTEGRITY. And keyd's own startup hold-down (RFC 4120
//! §3.2.3; docs/50 R50-6) reaches the client the same way, decided before
//! any secret-dependent work.
//!
//! The custody's `unavailable` switch plays the keyd IPC client that must
//! report keyd down / a deadline / Busy as `Unavailable` (docs/50 §3.6,
//! §3.7). Every value is constructed by hand for these tests; no vector
//! comes from any other implementation.
//!
//! Sources: RFC 4120 §3.2.3, §7.5.9, §5.1.4 (UDP silence); docs/50 R50-6,
//! R50-8, §3.5, §3.7; docs/questions/Q-217, Q-222 (A-56); main-session
//! decision 14 (one audit event per request).

mod common;

use common::*;
use kdc::{
    AccountSource, AccountSourceError, AuditOutcome, AuditReason, ClientAccount, InMemoryAccounts,
    KdcReply, Peer, PolicyInputs, ServiceAccount, Transport,
};
use krb_proto::constants::KDC_ERR_SVC_UNAVAILABLE;
use krb_proto::{KerberosTime, PrincipalName, Realm};
use pdp::IpScope;

/// The one audit event of the last request: refused with code 29 (TCP) or
/// dropped (UDP), for `reason`.
fn assert_event(f: &Fixture, transport: Transport, reason: AuditReason) {
    let event = f.events().last().unwrap();
    assert_eq!(event.reason, reason);
    assert_eq!(event.transport, transport);
    let expected = match transport {
        Transport::Tcp => AuditOutcome::Refused {
            error_code: KDC_ERR_SVC_UNAVAILABLE,
        },
        Transport::Udp => AuditOutcome::Dropped,
    };
    assert_eq!(event.outcome, expected);
}

/// The reply must be KDC_ERR_SVC_UNAVAILABLE, unarmored, without e-text or
/// e-data (RFC 4120 5.9.1; main-session decision 11).
fn assert_plain_29(reply: KdcReply) {
    let error = error_of(reply);
    assert_eq!(error.error_code, KDC_ERR_SVC_UNAVAILABLE);
    assert!(error.e_text.is_none());
    assert!(error.e_data.is_none(), "unarmored, no METHOD-DATA");
}

/// The bootstrap AS-REQ of the computer account (unarmored,
/// PA-ENC-TIMESTAMP made with `key` at `when`; docs/48 §7.3). Its nonce
/// differs from the fixture's own bootstrap, so the KDC's retransmit cache
/// (RFC 4120 3.1.2) never answers it with that earlier reply.
fn bootstrap_request(key: &krb_crypto::ProtocolKey, when: KerberosTime) -> Vec<u8> {
    let mut spec = AsReqSpec::machine();
    spec.nonce = 0x0B0B_0B0B;
    spec.padata = Some(vec![pa_enc_timestamp(key, when)]);
    spec.encode()
}

/// One request of each exchange path, built fresh at `when` (each armor and
/// authenticator is new, RFC 6113 5.4; docs/48 §3.3).
#[derive(Debug, Clone, Copy)]
enum Path {
    /// Unarmored AS (the computer account's bootstrap).
    UnarmoredAs,
    /// Armored AS (alice, encrypted challenge).
    ArmoredAs,
    /// Armored TGS (alice's TGT, implicit armor).
    Tgs,
}

fn request(f: &mut Fixture, path: Path, tgt: &Tgt, when: KerberosTime) -> Vec<u8> {
    match path {
        Path::UnarmoredAs => bootstrap_request(&machine_key(AES256), when),
        Path::ArmoredAs => {
            let spec = AsReqSpec::alice().with_challenge(&alice_key(AES256));
            f.fast_as_request(&spec, when).0
        }
        Path::Tgs => {
            let mut spec = TgsReqSpec::service();
            spec.ctime = when;
            spec.encode(tgt).0
        }
    }
}

/// docs/50 §3.7 / A-56: whichever keyd call of whichever path does not get
/// served, the client gets KDC_ERR_SVC_UNAVAILABLE over TCP — unarmored even
/// inside an open FAST conversation, since keyd could not seal it — and
/// nothing over UDP; the event says `CustodyUnavailable`.
#[test]
fn custody_unavailable_is_svc_unavailable_on_every_path() {
    let cases = [
        (Path::UnarmoredAs, CustodyOp::VerifyPreauth),
        (Path::UnarmoredAs, CustodyOp::IssueAsRep),
        (Path::ArmoredAs, CustodyOp::OpenFastArmor),
        (Path::ArmoredAs, CustodyOp::VerifyPreauth),
        (Path::ArmoredAs, CustodyOp::IssueAsRep),
        (Path::Tgs, CustodyOp::OpenAndVerifyTgt),
        (Path::Tgs, CustodyOp::IssueTgsRep),
    ];
    for (path, op) in cases {
        for transport in [Transport::Tcp, Transport::Udp] {
            let mut f = Fixture::new();
            let tgt = obtain_tgt(&mut f);
            f.kdc.audit_sink_mut().events.clear();
            f.kdc.custody_mut().unavailable = vec![op];
            let req = request(&mut f, path, &tgt, now());
            let reply = f.send_at(&req, transport, now());
            match transport {
                Transport::Tcp => assert_plain_29(reply),
                Transport::Udp => assert_eq!(reply, KdcReply::Silent, "{path:?} {op:?}"),
            }
            assert_eq!(f.events().len(), 1, "one event per request");
            assert_event(&f, transport, AuditReason::CustodyUnavailable);
            // keyd was not asked to seal the error (it is the one not serving).
            assert!(
                !f.keyd_ops().contains(&keyd::Operation::SealFastError),
                "{path:?} {op:?}"
            );
        }
    }
}

/// An account source that answers from `inner`, except: lookups of the
/// client `fail_client` and — if `fail_service` — every service lookup
/// cannot reach the source (`AccountSourceError::Unavailable`).
struct PartlyUnavailable<'a> {
    inner: &'a InMemoryAccounts,
    fail_client: Option<PrincipalName>,
    fail_service: bool,
}

impl AccountSource for PartlyUnavailable<'_> {
    fn client(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ClientAccount>, AccountSourceError> {
        if self
            .fail_client
            .as_ref()
            .is_some_and(|n| n.name_string == name.name_string)
        {
            return Err(AccountSourceError::Unavailable);
        }
        self.inner.client(realm, name)
    }

    fn service(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ServiceAccount>, AccountSourceError> {
        if self.fail_service {
            return Err(AccountSourceError::Unavailable);
        }
        self.inner.service(realm, name)
    }
}

/// Send `request` with an account source that cannot reach `fail_client` /
/// the services.
fn send_with_partial(
    f: &mut Fixture,
    request: &[u8],
    transport: Transport,
    fail_client: Option<PrincipalName>,
    fail_service: bool,
) -> KdcReply {
    let accounts = PartlyUnavailable {
        inner: &f.accounts,
        fail_client,
        fail_service,
    };
    f.kdc.handle(
        request,
        Peer {
            transport,
            src_net: IpScope::Internal,
        },
        now(),
        &PolicyInputs {
            snapshot: &f.snapshot,
            pip: &f.pip,
        },
        &accounts,
    )
}

/// docs/50 §3.7 (R50-8, "dird down ⇒ fail closed with an explicit
/// Unavailable"): an unreachable account source is KDC_ERR_SVC_UNAVAILABLE
/// over TCP and nothing over UDP, audited `AccountSourceUnavailable`. Before
/// the FAST armor is open (unarmored AS) keyd is never asked; once it is
/// open (the armor principal, the inner client, the TGS client and service
/// lookups), keyd is reachable and seals the refusal under the armor key
/// (docs/48 §6.1) — its PA-FX-ERROR carries code 29 too.
#[test]
fn account_source_unavailable_is_svc_unavailable_on_every_lookup() {
    // Unarmored AS: R6, before keyd and before the FAST gate.
    for transport in [Transport::Tcp, Transport::Udp] {
        let mut f = Fixture::new();
        f.accounts().set_unavailable(true);
        let reply = f.send_at(&AsReqSpec::alice().encode(), transport, now());
        match transport {
            Transport::Tcp => assert_plain_29(reply),
            Transport::Udp => assert_eq!(reply, KdcReply::Silent),
        }
        assert_event(&f, transport, AuditReason::AccountSourceUnavailable);
        assert!(f.keyd_records().is_empty(), "keyd is not asked");
    }

    // Armored AS: the armor principal (A5), then the inner client (A8).
    for fail in [machine_name(), alice_name()] {
        let mut f = Fixture::new();
        let spec = AsReqSpec::alice().with_challenge(&alice_key(AES256));
        let (request, armor) = f.fast_as_request(&spec, now());
        let reply = send_with_partial(&mut f, &request, Transport::Tcp, Some(fail.clone()), false);
        let error = open_fast_error(reply, &armor.key);
        assert_eq!(error.outer.error_code, KDC_ERR_SVC_UNAVAILABLE);
        assert_eq!(error.inner.error_code, KDC_ERR_SVC_UNAVAILABLE);
        assert_event(&f, Transport::Tcp, AuditReason::AccountSourceUnavailable);
        assert!(f.events().last().unwrap().armor.reply_armored);

        let (request, _) = f.fast_as_request(&spec, now());
        let reply = send_with_partial(&mut f, &request, Transport::Udp, Some(fail), false);
        assert_eq!(reply, KdcReply::Silent);
        assert_event(&f, Transport::Udp, AuditReason::AccountSourceUnavailable);
    }

    // Armored TGS: the client re-evaluation (step 7), the service (step 8).
    for (fail_client, fail_service) in [(Some(alice_name()), false), (None, true)] {
        let mut f = Fixture::new();
        let tgt = obtain_tgt(&mut f);
        let mut spec = TgsReqSpec::service();
        spec.cusec = 11;
        let (request, _) = spec.encode(&tgt);
        let reply = send_with_partial(
            &mut f,
            &request,
            Transport::Tcp,
            fail_client.clone(),
            fail_service,
        );
        let error = open_fast_error(reply, &spec.armor_key(&tgt.session));
        assert_eq!(error.outer.error_code, KDC_ERR_SVC_UNAVAILABLE);
        assert_eq!(error.inner.error_code, KDC_ERR_SVC_UNAVAILABLE);
        assert_event(&f, Transport::Tcp, AuditReason::AccountSourceUnavailable);

        spec.cusec = 12;
        let (request, _) = spec.encode(&tgt);
        let reply = send_with_partial(&mut f, &request, Transport::Udp, fail_client, fail_service);
        assert_eq!(reply, KdcReply::Silent);
        assert_event(&f, Transport::Udp, AuditReason::AccountSourceUnavailable);
    }
}

/// RFC 4120 §3.2.3 / docs/50 R50-6 through the KDC: a keyd that has just
/// started holds every exchange — the bootstrap AS, the armored AS and the
/// TGS all get KDC_ERR_SVC_UNAVAILABLE over TCP and nothing over UDP, a
/// wrong password exactly as a right one (decided before any secret, A-56)
/// — up to and including start + 2·skew, and serves them all one second
/// later (two skew intervals, A-62). The tickets come from a fixture whose
/// keyd started earlier (same keys).
#[test]
fn keyd_startup_hold_down_reaches_the_client_as_svc_unavailable() {
    let mut donor = Fixture::new();
    let alice_tgt = obtain_tgt(&mut donor);
    let mut setup = Setup::new();
    setup.keyd_started = now();
    setup.machine_tgt = Some(donor.machine_tgt);
    let mut f = setup.build();

    let wrong_machine_key = aes256(&[0x0B; 32]);
    for when in [now(), at(150), at(300), at(301), at(600)] {
        for path in [Path::UnarmoredAs, Path::ArmoredAs, Path::Tgs] {
            for transport in [Transport::Tcp, Transport::Udp] {
                let req = request(&mut f, path, &alice_tgt, when);
                let reply = f.send_at(&req, transport, when);
                match transport {
                    Transport::Tcp => assert_plain_29(reply),
                    Transport::Udp => assert_eq!(reply, KdcReply::Silent),
                }
                assert_event(&f, transport, AuditReason::CustodyUnavailable);
                let record = f.keyd_records().last().unwrap();
                assert_eq!(record.result, keyd::AuditOutcome::Unavailable);
                assert_eq!(record.reason, keyd::AuditReason::StartupHoldDown);
            }
        }
        // The wrong password gets the same answer and the same records.
        let right = f.send_at(
            &bootstrap_request(&machine_key(AES256), when),
            Transport::Tcp,
            when,
        );
        let right_record = f.keyd_records().last().unwrap().clone();
        let right_event = f.events().last().unwrap().clone();
        let wrong = f.send_at(
            &bootstrap_request(&wrong_machine_key, when),
            Transport::Tcp,
            when,
        );
        assert_eq!(right, wrong);
        assert_eq!(f.keyd_records().last().unwrap(), &right_record);
        assert_eq!(f.events().last().unwrap(), &right_event);
    }

    // One second after the two intervals: every path is served.
    let served = at(601);
    let bootstrap = f.send_at(
        &bootstrap_request(&machine_key(AES256), served),
        Transport::Tcp,
        served,
    );
    open_as_rep(&sent(bootstrap), &machine_key(AES256));
    let tgt = obtain_tgt_at(&mut f, AsReqSpec::alice(), served);
    let mut spec = TgsReqSpec::service();
    spec.ctime = served;
    let (request, _) = spec.encode(&tgt);
    let reply = f.send_at(&request, Transport::Tcp, served);
    open_tgs_rep(&sent(reply), &tgt, &spec);
    assert!(f
        .events()
        .iter()
        .rev()
        .take(3)
        .all(|e| e.outcome == AuditOutcome::Issued));
}
