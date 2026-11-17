//! Task PN13 (docs/59 §10 row PN13, §10.1): the one principal namespace and
//! keyd's binding by dird's attested name resolution, end to end over the
//! real daemons and sockets of module `admin_world` — `provision domain`,
//! the key ceremony (which installs the attestation key in keyd), auditd,
//! keyd, dird, the kdc, ldap-front and admind in the docs/50 §7.5 order.
//!
//! 1. [`issuance_rests_on_the_attested_resolutions_dird_hands_the_kdc`] —
//!    the AS and TGS exchanges of the running chain succeed because dird's
//!    resolutions reach keyd and verify there, and fail closed exactly when
//!    they do not: keyd's clock more than the window ahead of dird's (every
//!    resolution dird signs is stale at keyd), and a dird that attests with
//!    a key the ceremony did not give keyd (every tag is wrong at keyd).
//!    Each time the clocks agree again, or dird runs on its produced key
//!    again, the login works — and the verified audit log holds every
//!    issuance and every refusal with keyd's reason.
//! 2. [`a_compromised_kdc_on_keyd_sock_binds_no_name_to_another_key_set`] —
//!    the view of a compromised KDC: the test uid holds the KDC's role on
//!    the produced `keyd.sock` (the world's Kerberos phase; docs/50 §3.2),
//!    takes dird's genuine resolutions from `dird-kdc.sock` exactly as the
//!    KDC does, and asks keyd to issue with them misapplied — a wrong tag,
//!    a stale one, another object's, another purpose's, a ticket name the
//!    resolution does not hold. Every one is refused `Denied`, audited with
//!    its reason, and the legitimate login afterwards still works. (Since
//!    task PN11b the KDC names a resolved key set to keyd only by its
//!    resolution — no handle beside it — so "a resolution with another key
//!    set" is expressed as the nearest state that still exists: bob's
//!    resolution with alice's proof, another object's resolution for a
//!    request naming this service; docs/questions/Q-1080.)
//! 3. [`no_pac_name_shapes_are_refused_through_the_admin_plane`] — the
//!    noPac name shapes over `admin.sock` → admind → `dird-admin.sock` →
//!    dird's one write checker: `dc$` beside a user `dc` (and the reverse),
//!    the DC's own base name, a UPN local part beside another object's
//!    sAMAccountName (both ways), one SPN in two casings, the reserved
//!    names in any case without their claim — each refused, nothing
//!    written; then the user `dc` logs in as itself, and neither `dc$` nor
//!    a computer's base name reaches any account through a fallback. (One
//!    SPN in two casings is reachable on a second object only under the
//!    first one's computer name — its host is its own derived dNSHostName —
//!    so it is a `Conflict` there and an `Invalid` value under any other
//!    name: docs/questions/Q-1070 item 2.)
//!
//! # What stays unit-level, and why (docs/59 §10.1, "attacks")
//!
//! Recorded in docs/questions/Q-1070 item 1.
//!
//! * A caller-supplied `PRINCIPAL_NAME_KEY`: no wire of the running system
//!   can carry it — the admin channel is a closed set of operations with
//!   fixed fields (crates/ipc-dird-admin, the kind table: `CreateUser {sam,
//!   upn?, description?}`, `CreateComputer {name, spn?}`, …; no attribute
//!   list), and LDAP has no write path. The checker's refusal of the
//!   attribute in any caller's input (docs/59 N7) is crates/directory-admin
//!   `invariants::tests::a_caller_cannot_supply_or_change_the_keys`.
//! * A resolution tagged under another use's label: crate name-attestation
//!   exposes no function that tags anything but a `NameResolution` behind
//!   its own label (class C42, by construction), so neither a compromised
//!   KDC nor this test can make one; its refusal is that crate's unit test
//!   `a_tag_of_another_use_is_refused`.
//! * The resolution checks one by one (realm, the exact 30 s edges, a
//!   resolution for the krbtgt) on keyd's library: crates/keyd
//!   tests/issuance_by_resolution.rs; the KDC's forwarding:
//!   crates/kdc tests/name_resolution.rs.
//!
//! Sources (each opened in this session; the pinned copies' SHA-256
//! checked against tools/spec-pin/manifest.json): RFC 4120 §3.1.5, §6.2
//! ("The name type does not partition the name space"; "Names of any type
//! with an initial component of 'krbtgt' are reserved"), §6.2.1 (the host
//! component "MUST be lowercase"), §7.3; [MS-KILE] v20261110 3.1.5.7 (name
//! comparisons "MUST NOT be case sensitive"), 3.3.5.1.1 and 3.3.5.6.1 (the
//! lookup chains — sAMAccountName, then cname + "$", then the UPN — that
//! the one namespace replaces by one probe); [MS-ADTS] v20261026
//! 3.1.1.5.1.3 (UPN / SPN uniqueness), 3.1.1.5.3.1.1.2 (dNSHostName =
//! computerName.fullDomainDnsName), 3.1.1.5.3.1.1.4 (the SPN's host is the
//! machine's), 3.1.1.13.6 (one object per name); [MS-SAMR] v20260427
//! 3.1.1.6 items 8-14, 3.1.1.8.4 item 2 (sAMAccountName unique over a
//! union); RFC 3244 §2 (`kadmin/changepw`); docs/59 §3 (M1-M4), §4.1-§4.4
//! (N1-N7), §6.2, §7.1-§7.2, §7.5, §9 (S4), §10.1; docs/50 §3.2, §3.4,
//! §3.5 (R50-5), §7.5, §9; docs/51 §5.2; docs/10 §2 (b), §4 step 1;
//! A-173, A-188..A-191; docs/questions/Q-1067, Q-1080 (task PN11b). Every
//! value is hand-made test data; no vector comes from any other
//! implementation.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

mod admin_world;

use admin_world::*;
use common::{FastError, ServiceTicket, TgsReqSpec, Tgt};
use dtyp::Guid;
use ipc_admin::{RefusalStatus, Reply};
use ipc_audit::{
    AdminRefusal, DecisionResult, DirAdminEvent, DirAdminOperation, DirAdminStage, EventBody,
    KdcEvent, KdcExchange, KdcOutcome, KeydOperation, KeydOutcome, KeydReason, KeydRecord,
    KeydRole, OutcomeResult,
};
use ipc_dird_admin::{LookupKey, Operation};
use ipc_keyd::KeydClient;
use keyd::KeyHandle;
use keyd_types::{
    AsRepParts, AsServerKeySet, AsTicketTemplate, AttestedNameResolution, EncTypeId, IssueError,
    TgsRepParts, TgsTicketTemplate,
};
use krb_crypto::ProtocolKey;
use krb_proto::constants::{KDC_ERR_CLIENT_REVOKED, KDC_ERR_C_PRINCIPAL_UNKNOWN, KRB_ERR_GENERIC};
use krb_proto::{
    ApOptions, ApReq, AsRep, EncAsRepPart, EncTgsRepPart, KerberosTime, KrbError, PrincipalName,
    TgsRep, TicketFlags,
};
use provision::ObjectRole;
use std::os::unix::fs::PermissionsExt;
use support::kdcd::connector;
use support::{within, TEST_BOUND};

// ---------------------------------------------------------------------------
// Time.
// ---------------------------------------------------------------------------

/// keyd's freshness window for a name resolution: 30 s on keyd's own clock
/// (docs/59 §7.2 step 3; docs/questions/Q-1011 item 3, A-173) — the
/// constant keyd-types defines once.
const WINDOW_SECS: i64 = keyd_types::NAME_RESOLUTION_WINDOW_SECS as i64;

/// `t` moved `secs` seconds (the project's one KerberosTime scale).
fn shifted(t: &KerberosTime, secs: i64) -> KerberosTime {
    krb_proto::kerberos_time_from_seconds(krb_proto::kerberos_time_seconds(t) + secs).unwrap()
}

/// The earlier of two times.
fn earlier(a: KerberosTime, b: KerberosTime) -> KerberosTime {
    if krb_proto::kerberos_time_seconds(&a) <= krb_proto::kerberos_time_seconds(&b) {
        a
    } else {
        b
    }
}

// ---------------------------------------------------------------------------
// The audit log.
// ---------------------------------------------------------------------------

fn keyd_records(events: &[(u64, EventBody)]) -> Vec<&KeydRecord> {
    events
        .iter()
        .filter_map(|(_, e)| match e {
            EventBody::Keyd(r) => Some(r.as_ref()),
            _ => None,
        })
        .collect()
}

fn kdc_events(events: &[(u64, EventBody)]) -> Vec<&KdcEvent> {
    events
        .iter()
        .filter_map(|(_, e)| match e {
            EventBody::Kdc(k) => Some(k.as_ref()),
            _ => None,
        })
        .collect()
}

fn dir_admin_events(events: &[(u64, EventBody)]) -> Vec<&DirAdminEvent> {
    events
        .iter()
        .filter_map(|(_, e)| match e {
            EventBody::DirAdmin(d) => Some(d.as_ref()),
            _ => None,
        })
        .collect()
}

/// The name components of an audited principal.
fn components(principal: &Option<ipc_audit::Principal>) -> Vec<String> {
    principal
        .as_ref()
        .and_then(|p| p.components())
        .map(|c| {
            c.iter()
                .map(|t| t.as_text().unwrap_or("?").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// keyd's issuance records (`IssueAsRep`, `IssueTgsRep`) of the Kdc role
/// with `result`, in log order: (operation, reason, principal).
fn issuances(
    records: &[&KeydRecord],
    result: KeydOutcome,
) -> Vec<(KeydOperation, KeydReason, Option<[u8; 16]>)> {
    records
        .iter()
        .filter(|r| {
            matches!(r.op, KeydOperation::IssueAsRep | KeydOperation::IssueTgsRep)
                && r.caller_role == KeydRole::Kdc
                && r.result == result
        })
        .map(|r| (r.op, r.reason, r.principal))
        .collect()
}

/// The KDC's events of `exchange` by `client` with `outcome`.
fn kdc_count(
    events: &[&KdcEvent],
    exchange: KdcExchange,
    client: &str,
    outcome: KdcOutcome,
) -> usize {
    events
        .iter()
        .filter(|e| {
            e.exchange == Some(exchange)
                && components(&e.client) == [client]
                && e.outcome == outcome
        })
        .count()
}

// ---------------------------------------------------------------------------
// The Kerberos client.
// ---------------------------------------------------------------------------

/// A refusal of the running kdc: the KRB-ERROR's code and whether it came
/// armored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refused {
    code: i32,
    armored: bool,
}

/// The refusal `reply` carries. Armored (RFC 6113 §5.4.4: e-data =
/// METHOD-DATA with PA-FX-FAST) — opened under `armor_key`, the inner
/// PA-FX-ERROR's code equal to the outer one; otherwise the outer code: the
/// KDC sends the same code unarmored when keyd declines to seal it (docs/48
/// §6.2 item 3; docs/questions/Q-125 item 10).
fn refusal_of(reply: Vec<u8>, armor_key: &ProtocolKey) -> Refused {
    let outer = KrbError::decode(&reply).expect("a KRB-ERROR");
    if outer.e_data.is_none() {
        return Refused {
            code: outer.error_code,
            armored: false,
        };
    }
    let inner = common::open_fast_error(kdc::KdcReply::Send(reply), armor_key);
    assert_eq!(inner.inner.error_code, outer.error_code, "RFC 6113 §5.4.4");
    Refused {
        code: outer.error_code,
        armored: true,
    }
}

/// An armored AS for `sam` with `password` through the running kdc (RFC
/// 6113 §5.4.1.1 armor on `armor_tgt`, the encrypted challenge of §5.4.6)
/// at the world time — as [`World::armored_as`], but a refusal is read
/// whether keyd sealed it or not ([`refusal_of`]).
/// Spec: RFC 4120 §3.1, §3.1.5; RFC 6113 §5.4.1.1, §5.4.4, §5.4.6.
fn try_armored_as(
    w: &mut World,
    armor_tgt: &Tgt,
    sam: &str,
    password: &str,
) -> Result<Tgt, Refused> {
    let key = common::password_key(common::AES256, password, &user_salt(sam));
    let n = w.fresh();
    let armor = common::Armor::new(armor_tgt, w.now, n);
    let spec = common::AsReqSpec {
        nonce: w.fresh(),
        ..common::AsReqSpec::for_client(realm(), principal(sam))
    }
    .with_challenge(&key);
    let reply = w.kdc(&spec.encode_armored(&armor, w.now));
    if AsRep::decode(&reply).is_ok() {
        let tgt = common::open_fast_as_rep(&reply, &armor.key, &key);
        assert_eq!(tgt.rep.0.cname, principal(sam), "RFC 4120 §3.1.5");
        Ok(tgt)
    } else {
        Err(refusal_of(reply, &armor.key))
    }
}

/// An armored TGS by the client of `tgt` for `sname` through the running
/// kdc (implicit armor, RFC 6113 §5.4.2) at the world time: the service
/// ticket, or the refusal ([`refusal_of`]).
/// Spec: RFC 4120 §3.3, §3.3.4, §5.5.1; RFC 6113 §5.4.2-§5.4.4.
fn try_service_ticket(
    w: &mut World,
    tgt: &Tgt,
    sname: &PrincipalName,
) -> Result<ServiceTicket, Refused> {
    let spec = TgsReqSpec {
        sname: Some(sname.clone()),
        nonce: w.fresh(),
        ctime: w.now,
        cusec: w.fresh(),
        ..TgsReqSpec::service()
    }
    .for_client_of(tgt);
    let (request, _) = spec.encode(tgt);
    let reply = w.kdc(&request);
    if TgsRep::decode(&reply).is_ok() {
        let (rep, part) = common::open_tgs_rep(&reply, tgt, &spec);
        assert_eq!(&part.0.sname, sname, "RFC 4120 §3.3.4");
        Ok(common::service_ticket(&rep, &part))
    } else {
        Err(refusal_of(reply, &spec.armor_key(&tgt.session)))
    }
}

/// The error code of a refused armored AS.
fn as_error(result: Result<Tgt, Box<FastError>>) -> i32 {
    match result {
        Ok(tgt) => panic!("a TGT was issued: {:?}", tgt.rep.0.cname),
        Err(error) => error.inner.error_code,
    }
}

// ---------------------------------------------------------------------------
// The compromised KDC: the KDC's role on keyd.sock.
// ---------------------------------------------------------------------------

/// A keyd client holding the KDC's role on the produced `keyd.sock` (the
/// world's Kerberos phase maps the test uid to Role::Kdc there — the uid
/// the kdc daemon runs as; docs/50 §3.2): what a compromised KDC can call.
fn kdc_role_on_keyd(w: &World) -> KeydClient<connector::KeydConnector> {
    KeydClient::new(
        connector::keyd(w.input.paths.keyd_socket.as_path()),
        ipc_keyd::ExpectedPeer::new(w.uid, keyd::Role::Kdc).unwrap(),
        ipc_keyd::DEFAULT_DEADLINE,
    )
}

/// A first administrator's account as the compromised KDC knows it: the
/// key set handle (the manifest's) and, for the PA-ENC-TIMESTAMP the KDC
/// would relay, the password and salt (test data; the KDC never holds
/// them — the client made the timestamp).
struct Account<'a> {
    sam: &'a str,
    password: &'a str,
    handle: KeyHandle,
}

/// The `n`-th first administrator.
fn first_admin(w: &World, n: usize) -> Account<'static> {
    let (sam, password) = [(ALICE, ALICE_PASSWORD), (BOB, BOB_PASSWORD)][n];
    Account {
        sam,
        password,
        handle: w.manifest.first_admins()[n].key_set().handle,
    }
}

/// One TGT a compromised KDC asks keyd for: `who`'s PA-ENC-TIMESTAMP
/// relayed at the world time (`verify_preauth` with `who`'s key set handle,
/// RFC 4120 §5.2.7.2 — the proof binds that key set), then `issue_as_rep`
/// with `resolution` as dird's statement of the client's name — since task
/// PN11b the call's only name of the client's key set (keyd looks it up by
/// the resolution and requires the proof to be bound to it; docs/questions/
/// Q-1067, Q-1080) — and a template naming `cname`. On success the enc-part
/// opens under `who`'s key with the template's nonce (RFC 4120 §3.1.5).
/// Spec: docs/50 §3.4 (`VerifyPreauth`, `IssueAsRep`); docs/59 §7.2, §7.5;
/// docs/10 §4 step 1.
fn issue_tgt(
    w: &mut World,
    keyd: &mut KeydClient<connector::KeydConnector>,
    who: &Account<'_>,
    cname: &PrincipalName,
    resolution: &AttestedNameResolution,
) -> Result<AsRepParts, IssueError> {
    let key = common::password_key(common::AES256, who.password, &user_salt(who.sam));
    let padata = common::pa_enc_timestamp(&key, w.now);
    let proof = keyd
        .verify_preauth(&who.handle, &padata, None)
        .expect("keyd verifies the relayed timestamp");
    let template = AsTicketTemplate {
        crealm: realm(),
        cname: cname.clone(),
        sname: common::krbtgt_name(),
        starttime: None,
        endtime: shifted(&w.now, 3600),
        renew_till: None,
        flags: TicketFlags::empty(),
        session_enctype: EncTypeId::Aes256CtsHmacSha196,
        nonce: w.fresh(),
    };
    let krbtgt = w.manifest.krbtgt().handle;
    let issued = keyd.issue_as_rep(
        resolution,
        AsServerKeySet::LocalTgt(&krbtgt),
        &proof,
        None,
        &template,
    );
    if let Ok(parts) = &issued {
        let part = EncAsRepPart::decode(&common::open(&key, 3, &parts.enc_part)).unwrap();
        assert_eq!(part.0.nonce, template.nonce, "RFC 4120 §3.1.5");
        assert_eq!(parts.ticket.sname, common::krbtgt_name(), "RFC 4120 §7.3");
    }
    issued
}

/// One service ticket a compromised KDC asks keyd for: the client of `tgt`
/// asks for `sname` (an unarmored TGS-REQ body and its PA-TGS-REQ
/// authenticator, RFC 4120 §5.5.1, fresh at the world time), keyd opens the
/// TGT (`open_and_verify_tgt`), then `issue_tgs_rep` with `resolution` as
/// dird's statement of the service's name — since task PN11b the call's
/// only name of the service's key set: keyd seals under the key set the
/// resolution names (docs/questions/Q-1067). On success the ticket names
/// `sname` and the enc-part opens under the TGT's session key (key usage
/// 8). Spec: docs/50 §3.4 (`OpenAndVerifyTgt`, `IssueTgsRep`); docs/59
/// §7.2, §7.5; RFC 4120 §3.3.3.
fn issue_service(
    w: &mut World,
    keyd: &mut KeydClient<connector::KeydConnector>,
    tgt: &Tgt,
    sname: &PrincipalName,
    resolution: &AttestedNameResolution,
) -> Result<TgsRepParts, IssueError> {
    let nonce = w.fresh();
    let spec = TgsReqSpec {
        sname: Some(sname.clone()),
        nonce,
        ctime: w.now,
        cusec: w.fresh(),
        subkey: None,
        armored: false,
        ..TgsReqSpec::service()
    }
    .for_client_of(tgt);
    let body = spec.body().encode().unwrap();
    let ap_req = ApReq {
        ap_options: ApOptions::empty(),
        ticket: tgt.rep.0.ticket.clone(),
        authenticator: common::authenticator(&tgt.session, &spec, &body),
    };
    let krbtgt = w.manifest.krbtgt().handle;
    let ctx = keyd
        .open_and_verify_tgt(&krbtgt, &ap_req, &body, None)
        .expect("keyd opens the TGT");
    let template = TgsTicketTemplate {
        sname: sname.clone(),
        starttime: Some(w.now),
        endtime: earlier(shifted(&w.now, 3600), ctx.endtime),
        renew_till: None,
        flags: TicketFlags::empty(),
        session_enctype: EncTypeId::Aes256CtsHmacSha196,
        nonce,
    };
    let issued = keyd.issue_tgs_rep(resolution, &ctx.ctx_id, &template);
    if let Ok(parts) = &issued {
        assert_eq!(&parts.ticket.sname, sname, "RFC 4120 §3.3.3");
        let part = EncTgsRepPart::decode(&common::open(&tgt.session, 8, &parts.enc_part)).unwrap();
        assert_eq!(part.0.nonce, nonce);
    }
    issued
}

/// `resolution` with one bit of its tag flipped: not dird's statement.
fn flipped(resolution: &AttestedNameResolution) -> AttestedNameResolution {
    let mut tag = *resolution.tag();
    tag[0] ^= 0x80;
    AttestedNameResolution::new(resolution.resolution().clone(), tag)
}

// ---------------------------------------------------------------------------
// 1. The running chain: issuance rests on dird's attested resolutions.
// ---------------------------------------------------------------------------

/// docs/59 §7.2 steps 1 and 3, §7.4, §7.5; docs/50 §3.5 (R50-5: keyd's own
/// clock), §7.5; RFC 4120 §3.1, §3.3. From `provision domain` through the
/// ceremony (the attestation key installed in keyd) to alice's AS and TGS
/// over the running kdc: they succeed while dird's resolutions verify at
/// keyd, and are refused (KRB_ERR_GENERIC, keyd `Denied`) while keyd's
/// clock runs more than the window ahead of dird's — `NameResolutionStale`
/// — and while dird attests with a key keyd does not hold —
/// `NameResolutionInvalid`; the log of the run records each issuance and
/// each refusal, after the ceremony installed the key.
#[test]
fn issuance_rests_on_the_attested_resolutions_dird_hands_the_kdc() {
    within(TEST_BOUND, || {
        let _serial = serial();
        let Some(mut w) = World::provisioned() else {
            return;
        };

        // ---- provisioning ⇒ ceremony ⇒ daemons (docs/51 §4.3; docs/50 §7.5)
        w.start_auditd();
        let ceremony = w.ceremony();
        assert!(ceremony.is_complete(), "keyadm ceremony: {:?}", w.captured);
        assert!(
            ceremony.attestation_key_installed(),
            "the ceremony installed the attestation key in keyd (task PN9)"
        );
        let (secrets, _) = w.first_admin_secret();
        assert!(secrets.is_complete(), "first-admin-secret");
        w.workstation_secret();
        w.keyd_phase(KeydPhase::Kerberos);
        w.start_dird();
        w.start_kdc();
        w.start_front();
        w.start_admind();

        // ---- the logins: AS (armored) and TGS ------------------------------------
        let ws = w.bootstrap_workstation();
        let alice_tgt = w
            .armored_as(&ws, ALICE, ALICE_PASSWORD)
            .unwrap_or_else(|e| panic!("alice's AS: {}", e.inner.error_code));
        let ldap = w.ldap_service();
        let ticket = try_service_ticket(&mut w, &alice_tgt, &ldap).expect("alice's TGS");
        assert_eq!(ticket.cname, principal(ALICE), "RFC 4120 §3.3.4");

        // ---- keyd's clock beyond the window ahead of dird's ---------------------
        // R50-5: keyd judges a resolution's freshness on its own clock. The
        // world moves on (keyd with it) while dird's and the kdc's clock is
        // held back by more than the window: every resolution dird now signs
        // is stale at keyd — the AS and the TGS are refused. (The client's
        // timestamps stay within the Kerberos skew of both.)
        // keyd seals only an error stamped with its own `now` (docs/48 §6.1;
        // crates/keyd `seal_fast_error` step 3), which the kdc's held clock
        // is not, so these two refusals go out unarmored (docs/48 §6.2 item
        // 3) — the code is what is asserted (docs/questions/Q-1071).
        let held = w.now;
        w.advance(WINDOW_SECS + 1);
        w.clock.set(held);
        assert_eq!(
            try_armored_as(&mut w, &ws, ALICE, ALICE_PASSWORD)
                .err()
                .map(|r| r.code),
            Some(KRB_ERR_GENERIC),
            "keyd refuses a stale resolution; the KDC cannot explain it (docs/10 §9)"
        );
        assert_eq!(
            try_service_ticket(&mut w, &alice_tgt, &ldap)
                .err()
                .map(|r| r.code),
            Some(KRB_ERR_GENERIC),
            "the TGS too: the service's resolution is stale at keyd"
        );
        // The clocks agree again: dird's resolutions are fresh at keyd.
        w.clock.set(w.now);
        let alice_tgt = w
            .armored_as(&ws, ALICE, ALICE_PASSWORD)
            .unwrap_or_else(|e| panic!("alice's AS again: {}", e.inner.error_code));
        try_service_ticket(&mut w, &alice_tgt, &ldap).expect("alice's TGS again");

        // ---- dird attesting with a key keyd does not hold ------------------------
        // docs/59 §7.2 step 1, §7.4: keyd verifies the tag under the key the
        // ceremony installed. A dird that holds another key (a second key
        // file, read with dird's own reader) signs resolutions no keyd tag
        // check accepts: nothing is issued.
        w.stop_dird();
        let foreign = w.dir.join("etc/foreign-attestation.key");
        std::fs::write(&foreign, [0x5Au8; name_attestation::ATTESTATION_KEY_LEN]).unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o400)).unwrap();
        w.start_dird_attesting_with(&foreign);
        w.advance(1);
        // The clocks agree: keyd seals each refusal (RFC 6113 §5.4.4).
        let armored_generic = Refused {
            code: KRB_ERR_GENERIC,
            armored: true,
        };
        assert_eq!(
            try_armored_as(&mut w, &ws, ALICE, ALICE_PASSWORD).err(),
            Some(armored_generic),
            "a resolution under another key is not dird's statement to keyd"
        );
        assert_eq!(
            try_service_ticket(&mut w, &alice_tgt, &ldap).err(),
            Some(armored_generic)
        );
        // dird on its produced key: the login works again.
        w.stop_dird();
        w.start_dird();
        w.advance(1);
        let alice_tgt = w
            .armored_as(&ws, ALICE, ALICE_PASSWORD)
            .unwrap_or_else(|e| panic!("alice's AS on the produced key: {}", e.inner.error_code));
        try_service_ticket(&mut w, &alice_tgt, &ldap).expect("alice's TGS on the produced key");

        // ---- the audit log of the run ----------------------------------------------
        let alice = first_admin(&w, 0).handle;
        let ldap_handle = w.manifest.ldap_service().handle;
        let workstation = w.workstation.keys[0].handle;
        let events = w.finish();
        let keyd = keyd_records(&events);
        let install = keyd
            .iter()
            .position(|r| {
                r.op == KeydOperation::InstallAttestationKey
                    && r.result == KeydOutcome::Success
                    && r.caller_role == KeydRole::Admin
            })
            .expect("keyd recorded the ceremony's installation of the key");
        let first_issuance = keyd
            .iter()
            .position(|r| matches!(r.op, KeydOperation::IssueAsRep | KeydOperation::IssueTgsRep))
            .expect("keyd recorded issuances");
        assert!(install < first_issuance, "the key before any issuance");
        let alice_id = Some(*alice.principal.as_bytes());
        let ldap_id = Some(*ldap_handle.principal.as_bytes());
        let workstation_id = Some(*workstation.principal.as_bytes());
        use KeydOperation::{IssueAsRep as As, IssueTgsRep as Tgs};
        assert_eq!(
            issuances(&keyd, KeydOutcome::Success),
            vec![
                (As, KeydReason::None, workstation_id),
                (As, KeydReason::None, alice_id),
                (Tgs, KeydReason::None, ldap_id),
                (As, KeydReason::None, alice_id),
                (Tgs, KeydReason::None, ldap_id),
                (As, KeydReason::None, alice_id),
                (Tgs, KeydReason::None, ldap_id),
            ],
            "every issuance of the run, each through a verified resolution"
        );
        // An AS refusal names the key set of alice's proof (keyd's own
        // record); a TGS refusal whose resolution does not verify names no
        // key set — task PN11b: the request names the service's key set
        // only in that resolution, and keyd records no unverified field
        // (docs/questions/Q-1080 item 7; formerly the KDC's handle, ldap).
        assert_eq!(
            issuances(&keyd, KeydOutcome::Denied),
            vec![
                (As, KeydReason::NameResolutionStale, alice_id),
                (Tgs, KeydReason::NameResolutionStale, None),
                (As, KeydReason::NameResolutionInvalid, alice_id),
                (Tgs, KeydReason::NameResolutionInvalid, None),
            ],
            "every refusal, with keyd's reason"
        );
        let kdc = kdc_events(&events);
        let generic = KdcOutcome::Refused {
            error_code: KRB_ERR_GENERIC,
        };
        assert_eq!(
            kdc_count(&kdc, KdcExchange::As, ALICE, KdcOutcome::Issued),
            3
        );
        assert_eq!(kdc_count(&kdc, KdcExchange::As, ALICE, generic), 2);
        assert_eq!(
            kdc_count(&kdc, KdcExchange::Tgs, ALICE, KdcOutcome::Issued),
            3
        );
        assert_eq!(kdc_count(&kdc, KdcExchange::Tgs, ALICE, generic), 2);
        // The attestation key stays in its two files (docs/CLEAN-ROOM.md; docs/59
        // §7.4): not in the audit log of a run with refusals, nor anywhere
        // else the run left (compared, never printed).
        let key_copy = provision_common::keyadm_attestation_key(&w.input.paths, w.uid);
        let produced = key_copy.expose();
        for (path, octets) in w.files() {
            let holds = octets
                .windows(produced.len())
                .any(|window| window == produced.as_slice());
            let key_file = path == w.input.paths.attestation_key.as_path()
                || path == w.input.paths.keyadm_attestation_key.as_path();
            assert_eq!(holds, key_file, "the attestation key in {path:?}");
        }
    });
}

// ---------------------------------------------------------------------------
// 2. A compromised KDC on keyd.sock.
// ---------------------------------------------------------------------------

/// docs/59 §7.2 steps 1, 3, 4, 5, §9 (S4), §10.1 (the attacks: "a
/// resolution with a wrong tag / stale / `principal` of another object /
/// another purpose / a name in the template that is not in the resolution
/// ⇒ `Denied`"); docs/50 §3.2, §3.4. The KDC's role on the running keyd's
/// produced socket, dird's genuine resolutions read from the running dird
/// as the KDC reads them: each misapplication is refused with keyd's
/// uniform `Denied` and audited with its reason; each request made right
/// issues; and afterwards the legitimate login over the running kdc works.
#[test]
fn a_compromised_kdc_on_keyd_sock_binds_no_name_to_another_key_set() {
    within(TEST_BOUND, || {
        let _serial = serial();
        let Some(mut w) = World::started() else {
            return;
        };
        let ws = w.bootstrap_workstation();
        let alice_tgt = w
            .armored_as(&ws, ALICE, ALICE_PASSWORD)
            .unwrap_or_else(|e| panic!("alice's AS: {}", e.inner.error_code));
        let mut kdc = kdc_role_on_keyd(&w);
        let alice = first_admin(&w, 0);
        let alice_name = principal(ALICE);
        let bob_name = principal(BOB);

        // ---- AS --------------------------------------------------------------------
        // The request made right: dird's resolution of alice, her key set,
        // her name — issued (the control for every attack below).
        let genuine = w.dird_client_resolution(ALICE);
        issue_tgt(&mut w, &mut kdc, &alice, &alice_name, &genuine)
            .expect("dird's resolution, applied as stated, issues");
        // A wrong tag (docs/59 §7.2 step 1).
        assert_eq!(
            issue_tgt(&mut w, &mut kdc, &alice, &alice_name, &flipped(&genuine)),
            Err(IssueError::Denied)
        );
        // Another object's resolution: bob's, genuine, with alice's proof
        // (step 4; docs/10 §4 step 1). Task PN11b: no client handle travels
        // beside the resolution, so keyd resolves bob's key set and refuses
        // because alice's proof is not bound to it — TokenPrincipalMismatch,
        // formerly NameResolutionMismatch (docs/questions/Q-1080 item 4).
        let bob = w.dird_client_resolution(BOB);
        assert_eq!(
            issue_tgt(&mut w, &mut kdc, &alice, &alice_name, &bob),
            Err(IssueError::Denied)
        );
        // A ticket name the resolution does not hold: alice's genuine
        // resolution and key set, the template naming bob (step 5 — the KDC
        // choosing the name the TGT carries).
        assert_eq!(
            issue_tgt(&mut w, &mut kdc, &alice, &bob_name, &genuine),
            Err(IssueError::Denied)
        );
        // A stale resolution: dird's genuine statement, presented once the
        // window has passed on keyd's clock (step 3; S4 — within the window
        // a true resolution replayed for the same names is the documented
        // residual).
        w.advance(WINDOW_SECS + 1);
        assert_eq!(
            issue_tgt(&mut w, &mut kdc, &alice, &alice_name, &genuine),
            Err(IssueError::Denied)
        );
        let fresh = w.dird_client_resolution(ALICE);
        issue_tgt(&mut w, &mut kdc, &alice, &alice_name, &fresh)
            .expect("a fresh resolution issues again");

        // ---- TGS -------------------------------------------------------------------
        let ldap = w.ldap_service();
        let ldap_handle = w.manifest.ldap_service().handle;
        let admin_sname = w.admin_service();
        let service = |w: &World, name: &PrincipalName| {
            w.dird_resolution(name, DirdQuery::Service)
                .expect("dird resolves the service")
        };
        let ldap_resolution = service(&w, &ldap);
        issue_service(&mut w, &mut kdc, &alice_tgt, &ldap, &ldap_resolution)
            .expect("dird's resolution of the LDAP service, applied as stated, issues");
        // A wrong tag.
        assert_eq!(
            issue_service(
                &mut w,
                &mut kdc,
                &alice_tgt,
                &ldap,
                &flipped(&ldap_resolution)
            ),
            Err(IssueError::Denied)
        );
        // Another object's resolution: the admin service's, genuine, for a
        // request naming the LDAP service. Task PN11b: the KDC can no longer
        // name the LDAP service's key set beside it — keyd resolves the
        // admin service's key set and refuses because the ticket's name is
        // not the resolution's (docs/questions/Q-1080 item 4).
        let admin_resolution = service(&w, &admin_sname);
        assert_eq!(
            issue_service(&mut w, &mut kdc, &alice_tgt, &ldap, &admin_resolution),
            Err(IssueError::Denied)
        );
        // Another purpose: dird's genuine resolution of the LDAP service
        // object's own account name (a client lookup: its principal, the
        // PrincipalLongterm purpose) for a request naming the LDAP service.
        // Task PN11b: the purpose it names is the key set keyd would reach,
        // so the capability table refuses it — PurposeMismatch, formerly
        // NameResolutionMismatch (docs/10 §2 (b); docs/questions/Q-1080
        // item 4).
        let ldap_object = w.plan.object(ObjectRole::LdapService).unwrap();
        let ldap_sam = ldap_object.sam_account_name.clone().unwrap();
        let longterm = w
            .dird_resolution(&principal(&ldap_sam), DirdQuery::Client)
            .expect("dird resolves the LDAP service object's account name");
        assert_eq!(longterm.resolution().principal(), ldap_handle.principal);
        assert_eq!(
            longterm.resolution().key_purpose(),
            keyd::KeyPurpose::PrincipalLongterm
        );
        assert_eq!(
            issue_service(&mut w, &mut kdc, &alice_tgt, &ldap, &longterm),
            Err(IssueError::Denied)
        );
        // A ticket name the resolution does not hold: the LDAP service's
        // genuine resolution, the request and template naming the admin
        // service.
        assert_eq!(
            issue_service(&mut w, &mut kdc, &alice_tgt, &admin_sname, &ldap_resolution),
            Err(IssueError::Denied)
        );
        // A stale resolution.
        w.advance(WINDOW_SECS + 1);
        assert_eq!(
            issue_service(&mut w, &mut kdc, &alice_tgt, &ldap, &ldap_resolution),
            Err(IssueError::Denied)
        );
        drop(kdc);

        // ---- the legitimate login still works (no state was poisoned) -------------
        w.advance(1);
        let alice_tgt = w
            .armored_as(&ws, ALICE, ALICE_PASSWORD)
            .unwrap_or_else(|e| panic!("alice's AS after the attacks: {}", e.inner.error_code));
        let ticket =
            try_service_ticket(&mut w, &alice_tgt, &ldap).expect("alice's TGS after the attacks");
        assert_eq!(ticket.cname, alice_name);
        let bob_tgt = w
            .armored_as(&ws, BOB, BOB_PASSWORD)
            .unwrap_or_else(|e| panic!("bob's AS after the attacks: {}", e.inner.error_code));
        try_service_ticket(&mut w, &bob_tgt, &admin_sname).expect("bob's TGS after the attacks");

        // ---- every refusal audited, with its reason ---------------------------------
        let alice_id = Some(*alice.handle.principal.as_bytes());
        let bob_id = Some(*first_admin(&w, 1).handle.principal.as_bytes());
        let ldap_id = Some(*ldap_handle.principal.as_bytes());
        let admin_id = Some(*w.manifest.admin_service().handle.principal.as_bytes());
        let events = w.finish();
        let keyd = keyd_records(&events);
        use KeydOperation::{IssueAsRep as As, IssueTgsRep as Tgs};
        use KeydReason::{
            NameResolutionInvalid as Invalid, NameResolutionMismatch as Mismatch,
            NameResolutionStale as Stale, PurposeMismatch as Purpose,
            TokenPrincipalMismatch as NotTheProofs,
        };
        // Task PN11b (docs/questions/Q-1080 items 4, 7): a record names the
        // key set keyd knows — at AS the proof's (alice's), then the verified
        // client resolution's (bob's, in the attack that presents it); at TGS
        // the verified resolution's, or none when it does not verify. Before
        // PN11b every record named the key set the KDC's handle asked for.
        assert_eq!(
            issuances(&keyd, KeydOutcome::Denied),
            vec![
                (As, Invalid, alice_id),
                (As, NotTheProofs, bob_id),
                (As, Mismatch, alice_id),
                (As, Stale, alice_id),
                (Tgs, Invalid, None),
                (Tgs, Mismatch, admin_id),
                (Tgs, Purpose, ldap_id),
                (Tgs, Mismatch, ldap_id),
                (Tgs, Stale, None),
            ],
            "each attack: one refusal record of the Kdc role, keyd's reason"
        );
        // Each TGS refusal names the purpose of the key set the verified
        // resolution names — the admin service's AdminService set, the LDAP
        // object's PrincipalLongterm set, the LDAP service's Service set —
        // and none for a resolution that did not verify (formerly always
        // the Service set the KDC's handle named).
        use ipc_audit::KeyPurposeCode as Code;
        assert_eq!(
            keyd.iter()
                .filter(|r| r.op == KeydOperation::IssueTgsRep && r.result == KeydOutcome::Denied)
                .map(|r| r.purpose)
                .collect::<Vec<_>>(),
            vec![
                None,
                Some(Code::AdminService),
                Some(Code::PrincipalLongterm),
                Some(Code::Service),
                None,
            ]
        );
        // The running kdc served only the legitimate exchanges — every one
        // issued (the compromised KDC's calls went to keyd.sock directly, so
        // keyd's records above are their only trace, as for a real one).
        let kdc_log = kdc_events(&events);
        assert!(
            kdc_log.iter().all(|e| e.outcome == KdcOutcome::Issued),
            "the running kdc refused nothing: {:?}",
            kdc_log.iter().map(|e| e.outcome).collect::<Vec<_>>()
        );
    });
}

// ---------------------------------------------------------------------------
// 3. noPac name shapes through the admin plane.
// ---------------------------------------------------------------------------

fn create_user(parent: Guid, sam: &str, upn: Option<&str>) -> Operation {
    Operation::CreateUser {
        parent,
        sam: sam.to_owned(),
        upn: upn.map(str::to_owned),
        description: None,
    }
}

fn create_computer(parent: Guid, name: &str, spn: Option<&str>) -> Operation {
    Operation::CreateComputer {
        parent,
        name: name.to_owned(),
        spn: spn.map(str::to_owned),
    }
}

/// What a `DirAdmin` event of a create says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Said {
    Proceed,
    Refused(AdminRefusal),
    Committed,
}

fn said(event: &DirAdminEvent) -> Said {
    match event.stage {
        DirAdminStage::Decision(DecisionResult::Proceed) => Said::Proceed,
        DirAdminStage::Decision(DecisionResult::Refused(code)) => Said::Refused(code),
        DirAdminStage::Outcome(OutcomeResult::Committed { .. }) => Said::Committed,
        other => panic!("an unexpected admin event: {other:?}"),
    }
}

/// docs/59 §3 (M1, M2), §4.1-§4.4 (N1-N4, N6, N7), §6.2, §10.1 ("noPac:
/// computer `dc$` when user `dc` exists (and the reverse) ⇒ Conflict; UPN
/// `bob@realm` when sam `bob` exists on another object ⇒ Conflict; one SPN
/// in two casings on two objects ⇒ Conflict; `ADMIND/<host>`,
/// `KADMIN/changepw`, `KRBTGT/<host>` without the claim ⇒ refused");
/// [MS-SAMR] 3.1.1.8.4 item 2 (unique over a union), 3.1.1.6 item 11 (the
/// final "$"); [MS-ADTS] 3.1.1.5.1.3, 3.1.1.5.3.1.1.2, 3.1.1.5.3.1.1.4,
/// 3.1.1.13.6; RFC 4120 §6.2, §6.2.1; [MS-KILE] 3.1.5.7, 3.3.5.6.1;
/// RFC 3244 §2. Over the running admin plane: each name shape is refused —
/// a name another object holds in any form as `Conflict`, a reserved or
/// malformed name as `Invalid` — and nothing it named is written; then the
/// user `dc` logs in as itself, and `dc$` and a computer's base name reach
/// no account: the "$" and UPN fallbacks of [MS-KILE] 3.3.5.6.1 do not
/// exist, so neither can land on another object.
#[test]
fn no_pac_name_shapes_are_refused_through_the_admin_plane() {
    within(TEST_BOUND, || {
        let _serial = serial();
        let Some(mut w) = World::started() else {
            return;
        };
        let ws = w.bootstrap_workstation();
        let alice_tgt = w
            .armored_as(&ws, ALICE, ALICE_PASSWORD)
            .unwrap_or_else(|e| panic!("alice's AS: {}", e.inner.error_code));
        let alice = w.persona(ALICE, &alice_tgt);
        w.advance(10);
        w.keyd_phase(KeydPhase::Admin);
        let workstations = w.guid(ObjectRole::WorkstationsOu);
        // A second container, so that two objects of one name never share a
        // parent: a refusal below is the namespace's (N1), never the RDN
        // check of one container (docs/46 §8.3 item 3).
        let servers = w
            .forward(
                &alice,
                &[],
                Operation::CreateOu {
                    parent: workstations,
                    name: "Servers".to_owned(),
                },
            )
            .created();
        let mut expected: Vec<(DirAdminOperation, Said)> = vec![
            (DirAdminOperation::CreateOu, Said::Proceed),
            (DirAdminOperation::CreateOu, Said::Committed),
        ];
        let mut attempt =
            |w: &mut World,
             operation: Operation,
             refusal: Option<(RefusalStatus, AdminRefusal)>| {
                let op = match &operation {
                    Operation::CreateUser { .. } => DirAdminOperation::CreateUser,
                    Operation::CreateComputer { .. } => DirAdminOperation::CreateComputer,
                    other => panic!("not a create: {other:?}"),
                };
                let got = w.forward(&alice, &[], operation.clone());
                match refusal {
                    None => {
                        expected.extend([(op, Said::Proceed), (op, Said::Committed)]);
                        Some(got.created())
                    }
                    Some((status, code)) => {
                        assert_eq!(got.refusal(), status, "{operation:?}");
                        expected.push((op, Said::Refused(code)));
                        None
                    }
                }
            };
        let conflict = Some((RefusalStatus::Conflict, AdminRefusal::Conflict));
        let bad_name = Some((RefusalStatus::Invalid, AdminRefusal::AccountNameInvalid));
        let bad_value = Some((RefusalStatus::Invalid, AdminRefusal::ValueInvalid));

        // ---- `dc$` beside a user `dc`, and the reverse (N1; [MS-SAMR]
        // 3.1.1.8.4 item 2 — the union; [MS-KILE] 3.3.5.6.1 step 2's
        // cname + "$") -----------------------------------------------------------------
        let dc_user = attempt(&mut w, create_user(workstations, "dc", None), None).unwrap();
        attempt(&mut w, create_computer(servers, "dc", None), conflict);
        attempt(&mut w, create_computer(servers, "DC", None), conflict);
        attempt(&mut w, create_computer(servers, "srv1", None), None).unwrap();
        attempt(&mut w, create_user(workstations, "srv1", None), conflict);
        attempt(&mut w, create_user(workstations, "SRV1", None), conflict);
        // A user named as a computer account: the final "$" is a computer's
        // alone (N2; [MS-SAMR] 3.1.1.6 item 11 without its exception, A-79).
        attempt(&mut w, create_user(workstations, "srv2$", None), bad_name);
        // The DC's own names: its account `DC1$` holds `dc1$`, `dc1` and
        // `dc1.example.org` (docs/59 §4.3) — noPac's target.
        attempt(&mut w, create_computer(servers, "dc1", None), conflict);
        attempt(&mut w, create_user(workstations, "dc1", None), conflict);
        attempt(&mut w, create_user(workstations, "Dc1", None), conflict);

        // ---- a UPN local part beside another object's sAMAccountName, both
        // ways (N1, N3; [MS-KILE] 3.3.5.6.1 step 3's cname@realm) --------------------
        attempt(
            &mut w,
            create_user(workstations, "robert", Some("bob@example.org")),
            conflict,
        );
        attempt(
            &mut w,
            create_user(workstations, "robert", Some("BOB@EXAMPLE.ORG")),
            conflict,
        );
        attempt(
            &mut w,
            create_user(workstations, "carl1", Some("carl@example.org")),
            None,
        )
        .unwrap();
        attempt(&mut w, create_user(workstations, "carl", None), conflict);
        attempt(&mut w, create_computer(servers, "carl", None), conflict);
        // A foreign suffix is no name of this realm (N3; docs/59 §4.2 —
        // stricter than [MS-DRSR] 4.1.4.2.22, documented there).
        attempt(
            &mut w,
            create_user(workstations, "erin", Some("erin@foreign.example")),
            bad_value,
        );

        // ---- one SPN in two casings on two objects (N1, N4; RFC 4120 §6.2.1;
        // [MS-ADTS] 3.1.1.5.1.3, 3.1.1.5.3.1.1.4) ----------------------------------------
        attempt(
            &mut w,
            create_computer(workstations, "web1", Some("http/web1.example.org")),
            None,
        )
        .unwrap();
        // The SPN's host is the object's own derived dNSHostName ([MS-ADTS]
        // 3.1.1.5.3.1.1.2, folded — N6), so a second object can spell the
        // SPN only under the same computer name in another case: the key of
        // the SPN and of every name it holds is taken.
        attempt(
            &mut w,
            create_computer(servers, "WEB1", Some("HTTP/web1.example.org")),
            conflict,
        );
        // Under any other name, the host is not its own: refused as a value.
        attempt(
            &mut w,
            create_computer(servers, "web2", Some("HTTP/web1.example.org")),
            bad_value,
        );

        // ---- reserved names without their claim, in any case (A-163 on the
        // folded key; RFC 4120 §6.2 "krbtgt" reserved, §7.3; RFC 3244 §2;
        // A-73) ---------------------------------------------------------------------------
        for spn in [
            "ADMIND/ws3.example.org",
            "admind/ws3.example.org",
            "Admind/ws3.example.org",
            "KRBTGT/ws3.example.org",
            "krbtgt/ws3.example.org",
            "KADMIN/changepw",
            "kadmin/changepw",
        ] {
            attempt(
                &mut w,
                create_computer(servers, "ws3", Some(spn)),
                bad_value,
            );
        }
        attempt(&mut w, create_user(workstations, "KRBTGT", None), bad_name);
        attempt(&mut w, create_user(workstations, "krbtgt", None), bad_name);
        // The same computer with an unreserved SPN on its own host: created
        // — the refusals above were the names, not the object.
        attempt(
            &mut w,
            create_computer(servers, "ws3", Some("host/ws3.example.org")),
            None,
        )
        .unwrap();

        // ---- nothing a refused create named exists ------------------------------------
        let lookup = |w: &mut World, sam: &str| {
            w.forward(
                &alice,
                &[],
                Operation::Lookup(LookupKey::SamAccountName(sam.to_owned())),
            )
        };
        for sam in [
            "dc$", "DC$", "srv1", "srv2$", "dc1", "robert", "carl", "erin", "web2$",
        ] {
            assert_eq!(
                lookup(&mut w, sam).refusal(),
                RefusalStatus::NotFound,
                "{sam} was not created"
            );
        }
        match lookup(&mut w, "dc").reply() {
            Reply::Found(found) => {
                assert_eq!(found.guid, dc_user);
                assert_eq!(found.class, "user");
            }
            other => panic!("Lookup dc: {other:?}"),
        }

        // ---- the legitimate login afterwards: `dc` is the user `dc` ------------------
        match w
            .set_password(&alice, &[], dc_user, NEW_USER_PASSWORD)
            .reply()
        {
            Reply::PasswordChanged(changed) => assert_eq!(changed.kvnos, vec![1]),
            other => panic!("SetPassword: {other:?}"),
        }
        assert_eq!(
            w.forward(
                &alice,
                &[],
                Operation::SetEnabled {
                    target: dc_user,
                    enabled: true
                }
            )
            .reply(),
            Reply::Done
        );
        w.advance(10);
        w.keyd_phase(KeydPhase::Kerberos);
        let dc_tgt = w
            .armored_as(&ws, "dc", NEW_USER_PASSWORD)
            .unwrap_or_else(|e| panic!("dc's AS: {}", e.inner.error_code));
        assert_eq!(dc_tgt.rep.0.cname, principal("dc"), "RFC 4120 §3.1.5");
        let ldap = w.ldap_service();
        let ticket = try_service_ticket(&mut w, &dc_tgt, &ldap).expect("dc's TGS");
        assert_eq!(ticket.cname, principal("dc"));
        // `dc$` names no account (its computer was never written) — not the
        // user `dc` through any fallback.
        assert_eq!(
            as_error(w.armored_as(&ws, "dc$", NEW_USER_PASSWORD)),
            KDC_ERR_C_PRINCIPAL_UNKNOWN
        );
        // A computer's base name is no client name ([MS-KILE] 3.3.5.6.1
        // step 2's cname + "$" retry does not exist — docs/59 §3 M1): `srv1`
        // is unknown, while the computer `srv1$` exists (disabled since its
        // create, so it is refused as revoked — RFC 4120 §7.5.9).
        assert_eq!(
            as_error(w.armored_as(&ws, "srv1", NEW_USER_PASSWORD)),
            KDC_ERR_C_PRINCIPAL_UNKNOWN
        );
        assert_eq!(
            as_error(w.armored_as(&ws, "srv1$", NEW_USER_PASSWORD)),
            KDC_ERR_CLIENT_REVOKED
        );
        // A UPN local part is no client name either in phase 1 (R47-1:
        // AS = sAMAccountName; docs/59 §6.3 wave 2): `carl` is unknown.
        assert_eq!(
            as_error(w.armored_as(&ws, "carl", NEW_USER_PASSWORD)),
            KDC_ERR_C_PRINCIPAL_UNKNOWN
        );
        // The first administrators are untouched.
        w.armored_as(&ws, BOB, BOB_PASSWORD)
            .unwrap_or_else(|e| panic!("bob's AS after the attempts: {}", e.inner.error_code));

        // ---- the decision trail -----------------------------------------------------------
        let events = w.finish();
        let creates: Vec<(DirAdminOperation, Said)> = dir_admin_events(&events)
            .into_iter()
            .filter(|e| {
                matches!(
                    e.operation,
                    DirAdminOperation::CreateUser
                        | DirAdminOperation::CreateComputer
                        | DirAdminOperation::CreateOu
                )
            })
            .map(|e| (e.operation, said(e)))
            .collect();
        assert_eq!(
            creates, expected,
            "dird's decision and outcome for every create, in order"
        );
    });
}
