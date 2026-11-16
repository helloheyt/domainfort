//! Hand-built sample calls and answers covering every message of the keyd
//! channel, with optional fields both present and absent and every error
//! variant of keyd's three error types.
//!
//! Source: docs/50 §3.4 (the keyd channel's rows), §9 tier 1 ("round-trip
//! for each op"); docs/10 §4-§9 (the operations, their results and errors);
//! RFC 4120 §5 / RFC 6113 §5.4 (the shapes of the Kerberos values, built
//! with krb-proto's types). Every value is constructed by hand for these
//! tests; no vector comes from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

use ipc_keyd::{
    AccountKind, Answer, AttestationKeyOctets, Call, DecidedOperation, DecisionId, DescribedConfig,
    DestructionPage, Password, PendingDestruction, SetSecretTarget, TgsFast,
};
use keyd_types::{
    ArmorId, AsRepParts, AsTicketTemplate, AttestedNameResolution, AuthnError, AuthnProof,
    ChangePasswordContext, ChangePasswordCtxId, ChangePasswordVerdict, ConfigDescription, CtxId,
    EncTypeId, ExchangeId, FastArmor, FastConversation, HostAddr, IssueError, KeyHandle,
    KeyPurpose, Kvno, NameResolution, NameResolutionFields, PrincipalBinding, PrincipalId, Role,
    SealedReply, ServiceContext, ServiceCtxId, TgsRepParts, TgsTicketTemplate, TgtContext,
    TicketPolicy,
};
use krb_proto::{
    ApOptions, ApRep, ApReq, Checksum, EncryptedData, FastOptions, KdcOptions, KdcReqBody,
    KerberosString, KerberosTime, KrbError, KrbFastArmor, KrbFastArmoredReq, KrbFastReq, KrbPriv,
    Microseconds, NonZeroResultCode, PaData, PrincipalName, Realm, Ticket, TicketFlags,
};
use zeroize::Zeroizing;

pub const PASSWORD: &str = "Nook-Petrel-16-Quay";

/// A made-up attestation key (task PN9): 32 octets, a pattern no test
/// output may show (`0x6B`, decimal 107).
pub const ATTESTATION_KEY: [u8; 32] = [0x6B; 32];

/// [`ATTESTATION_KEY`] as the call's carrier.
pub fn attestation_key() -> AttestationKeyOctets {
    AttestationKeyOctets::from_slice(&ATTESTATION_KEY).unwrap()
}

pub fn realm() -> Realm {
    Realm::new("EXAMPLE.ORG").unwrap()
}

pub fn name(name_type: i32, parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type,
        name_string: parts
            .iter()
            .map(|p| KerberosString::new(p).unwrap())
            .collect(),
    }
}

pub fn time(offset_minutes: u8) -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 10, offset_minutes, 7).unwrap()
}

/// A name resolution as dird would state it (task PN11): `sent` resolved to
/// `canonical` and the key set `key`, issued at `time(3)`, with a made-up
/// tag `[tag; 32]` — the codec carries the tag, it never checks it (keyd
/// does, docs/59 §7.2), so no MAC is needed here.
pub fn resolution(
    sent: PrincipalName,
    canonical: PrincipalName,
    key: KeyHandle,
    tag: u8,
) -> AttestedNameResolution {
    let resolution = NameResolution::new(NameResolutionFields {
        realm_as_sent: realm(),
        name_as_sent: sent,
        canonical_realm: realm(),
        canonical_name: canonical,
        principal: key.principal,
        key_purpose: key.purpose,
        snapshot: 0x0102_0304_0506_0708,
        issued_at: time(3),
    })
    .unwrap();
    AttestedNameResolution::new(resolution, [tag; 32])
}

pub fn handle(octet: u8, purpose: KeyPurpose) -> KeyHandle {
    KeyHandle::new(PrincipalId::from_bytes([octet; 16]), purpose)
}

pub fn enc(etype: i32, kvno: Option<u32>, octet: u8) -> EncryptedData {
    EncryptedData {
        etype,
        kvno,
        cipher: vec![octet; 40],
    }
}

pub fn ticket() -> Ticket {
    Ticket {
        realm: realm(),
        sname: name(2, &["krbtgt", "EXAMPLE.ORG"]),
        enc_part: enc(18, Some(1), 0x5A),
    }
}

pub fn ap_req() -> ApReq {
    ApReq {
        ap_options: ApOptions::empty(),
        ticket: ticket(),
        authenticator: enc(18, None, 0x3C),
    }
}

pub fn armored_req(with_armor: bool) -> KrbFastArmoredReq {
    KrbFastArmoredReq {
        armor: with_armor.then(|| KrbFastArmor {
            armor_type: 1,
            armor_value: ap_req().encode().unwrap(),
        }),
        req_checksum: Checksum {
            cksumtype: 16,
            checksum: vec![0x77; 12],
        },
        enc_fast_req: enc(18, None, 0x66),
    }
}

pub fn req_body() -> KdcReqBody {
    KdcReqBody {
        kdc_options: KdcOptions::empty(),
        cname: Some(name(1, &["alice"])),
        realm: realm(),
        sname: Some(name(2, &["krbtgt", "EXAMPLE.ORG"])),
        from: None,
        till: time(59),
        rtime: None,
        nonce: 0x1357_9BDF,
        etype: vec![18, 17],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    }
}

pub fn fast_req() -> KrbFastReq {
    KrbFastReq {
        fast_options: FastOptions::empty(),
        padata: vec![padata(138)],
        req_body: req_body(),
    }
}

pub fn padata(padata_type: i32) -> PaData {
    PaData {
        padata_type,
        padata_value: enc(18, None, 0x11).encode().unwrap(),
    }
}

pub fn krb_error() -> KrbError {
    KrbError {
        ctime: None,
        cusec: None,
        stime: time(0),
        susec: Microseconds::new(0).unwrap(),
        error_code: 25,
        crealm: Some(realm()),
        cname: Some(name(1, &["alice"])),
        realm: realm(),
        sname: name(2, &["krbtgt", "EXAMPLE.ORG"]),
        e_text: None,
        e_data: None,
    }
}

pub fn flags(bits: u32) -> TicketFlags {
    TicketFlags(krb_proto::KerberosFlags::from_bits(bits))
}

pub fn binding() -> PrincipalBinding {
    PrincipalBinding::new(realm(), name(1, &["alice"]))
}

pub fn password(text: &str) -> Password {
    Password::new(Zeroizing::new(String::from(text)))
}

pub fn proof() -> AuthnProof {
    AuthnProof {
        exchange_id: ExchangeId::from_bytes([0xE1; 16]),
        client: PrincipalId::from_bytes([0xA1; 16]),
        authtime: time(1),
    }
}

pub fn as_template(full: bool) -> AsTicketTemplate {
    AsTicketTemplate {
        client: PrincipalId::from_bytes([0xA1; 16]),
        crealm: realm(),
        cname: name(1, &["alice"]),
        sname: name(2, &["krbtgt", "EXAMPLE.ORG"]),
        starttime: full.then(|| time(2)),
        endtime: time(58),
        renew_till: full.then(|| time(59)),
        flags: flags(0x0080_0000),
        session_enctype: EncTypeId::Aes256CtsHmacSha196,
        nonce: 0x0102_0304,
    }
}

pub fn tgs_template(full: bool) -> TgsTicketTemplate {
    TgsTicketTemplate {
        sname: name(3, &["host", "files.example.org"]),
        starttime: full.then(|| time(3)),
        endtime: time(57),
        renew_till: full.then(|| time(56)),
        flags: flags(0),
        session_enctype: EncTypeId::Aes128CtsHmacSha196,
        nonce: u32::MAX,
    }
}

pub const KRBTGT: KeyHandle =
    KeyHandle::new(PrincipalId::from_bytes([0x7B; 16]), KeyPurpose::Krbtgt);

/// One call of every operation, optional fields present, plus the
/// variants with optional fields absent.
pub fn calls() -> Vec<Call> {
    let alice = handle(0xA1, KeyPurpose::PrincipalLongterm);
    let service = handle(0x5E, KeyPurpose::Service);
    vec![
        Call::VerifyPreauth {
            client: alice,
            padata: padata(2),
            armor: Some(ArmorId::from_bytes([0xAA; 16])),
        },
        Call::VerifyPreauth {
            client: alice,
            padata: padata(138),
            armor: None,
        },
        Call::IssueAsRep {
            client: alice,
            krbtgt: KRBTGT,
            proof: proof(),
            armor: Some(ArmorId::from_bytes([0xAB; 16])),
            template: as_template(true),
            client_resolution: Box::new(resolution(
                name(10, &["ALICE"]),
                name(1, &["alice"]),
                alice,
                0x9A,
            )),
            server_resolution: Some(Box::new(resolution(
                name(2, &["kadmin", "changepw"]),
                name(2, &["kadmin", "changepw"]),
                handle(0xC7, KeyPurpose::ChangePasswordService),
                0x9B,
            ))),
        },
        Call::IssueAsRep {
            client: alice,
            krbtgt: KRBTGT,
            proof: proof(),
            armor: None,
            template: as_template(false),
            client_resolution: Box::new(resolution(
                name(1, &["alice"]),
                name(1, &["alice"]),
                alice,
                0x9C,
            )),
            server_resolution: None,
        },
        Call::OpenFastArmor {
            krbtgt: KRBTGT,
            armored_req: armored_req(true),
            outer_req_body: req_body().encode().unwrap(),
        },
        Call::OpenAndVerifyTgt {
            krbtgt: KRBTGT,
            ap_req: ap_req(),
            req_body: req_body().encode().unwrap(),
            fast: Some(TgsFast {
                ap_req_octets: ap_req().encode().unwrap(),
                armored_req: armored_req(false),
            }),
        },
        Call::OpenAndVerifyTgt {
            krbtgt: KRBTGT,
            ap_req: ap_req(),
            req_body: Vec::new(),
            fast: None,
        },
        Call::IssueTgsRep {
            service,
            ctx: CtxId::from_bytes([0xC1; 16]),
            template: tgs_template(true),
            service_resolution: Box::new(resolution(
                name(3, &["host", "files.example.org"]),
                name(3, &["host", "files.example.org"]),
                service,
                0x9D,
            )),
        },
        Call::IssueTgsRep {
            service: KRBTGT,
            ctx: CtxId::from_bytes([0xC2; 16]),
            template: tgs_template(false),
            service_resolution: Box::new(resolution(
                name(3, &["HOST", "files.example.org"]),
                name(3, &["host", "files.example.org"]),
                service,
                0x9E,
            )),
        },
        Call::SealFastError {
            conversation: FastConversation::As(ArmorId::from_bytes([0xAC; 16])),
            error: krb_error(),
            padata: vec![padata(19), padata(133), padata(138)],
        },
        Call::SealFastError {
            conversation: FastConversation::Tgs(CtxId::from_bytes([0xC3; 16])),
            error: krb_error(),
            padata: Vec::new(),
        },
        // R2 / Q-523: the unbound verification (0x07) and the
        // operation-bound one (0x15), each naming only the principal.
        Call::OpenAndVerifyServiceTicket {
            service: service.principal,
            ap_req_octets: ap_req().encode().unwrap(),
        },
        Call::VerifyOperationTicket {
            service: PrincipalId::from_bytes([0xAD; 16]),
            operation: keyd_types::OperationDigest::new([0xD1; 32]),
            ap_req_octets: ap_req().encode().unwrap(),
        },
        Call::SetSecret {
            handle: alice,
            binding: binding(),
            password: password(PASSWORD),
            salt: String::from("EXAMPLE.ORGalice"),
        },
        Call::VerifySecret {
            handle: alice,
            candidate: password(PASSWORD),
        },
        Call::CreateKey {
            handle: service,
            binding: PrincipalBinding::new(realm(), name(3, &["host", "files.example.org"])),
        },
        // A-102 (docs/52 §4.6): the executions carry only dird's decision id.
        Call::RotateKey {
            decision: DecisionId::new(1),
        },
        Call::RotateKrbtgt {
            decision: DecisionId::new(u64::MAX),
        },
        Call::RetireKvno {
            decision: DecisionId::new(0x0102_0304_0506_0708),
        },
        Call::DestroyKeySet {
            decision: DecisionId::new(0),
        },
        Call::DescribeConfig,
        Call::Ping,
        // Task A15a: a user's grant, a computer's (two targets), and the
        // shapes the codec carries for keyd to judge (none; a zero
        // lifetime).
        Call::GrantSetSecret {
            kind: AccountKind::User,
            targets: vec![alice_target()],
            lifetime_secs: 30,
        },
        Call::GrantSetSecret {
            kind: AccountKind::Computer,
            targets: computer_targets(),
            lifetime_secs: 900,
        },
        Call::GrantSetSecret {
            kind: AccountKind::Computer,
            targets: Vec::new(),
            lifetime_secs: 0,
        },
        // A-102 (docs/52 §4.2, §4.6): every decided operation, and the
        // shapes the codec carries for keyd to judge (no target, no
        // approver, a kvno 0, a zero lifetime).
        Call::RegisterDecision {
            id: DecisionId::new(7),
            operation: DecidedOperation::SetSecret {
                kind: AccountKind::User,
                targets: vec![alice_target()],
            },
            approvers: Vec::new(),
            lifetime_secs: 30,
        },
        Call::RegisterDecision {
            id: DecisionId::new(8),
            operation: DecidedOperation::SetSecret {
                kind: AccountKind::Computer,
                targets: computer_targets(),
            },
            approvers: vec![approver(0x0A)],
            lifetime_secs: 30,
        },
        Call::RegisterDecision {
            id: DecisionId::new(9),
            operation: DecidedOperation::SetSecret {
                kind: AccountKind::Computer,
                targets: Vec::new(),
            },
            approvers: Vec::new(),
            lifetime_secs: 0,
        },
        Call::RegisterDecision {
            id: DecisionId::new(10),
            operation: DecidedOperation::RotateKrbtgt { krbtgt: KRBTGT },
            approvers: vec![approver(0x01), approver(0x02)],
            lifetime_secs: 900,
        },
        Call::RegisterDecision {
            id: DecisionId::new(11),
            operation: DecidedOperation::RotateKey { handle: service },
            approvers: vec![approver(0x01), approver(0x02), approver(0x03)],
            lifetime_secs: 3600,
        },
        Call::RegisterDecision {
            id: DecisionId::new(12),
            operation: DecidedOperation::RetireKvno {
                handle: service,
                kvno: Kvno::new(7),
            },
            approvers: vec![approver(0x01), approver(0x02)],
            lifetime_secs: 900,
        },
        Call::RegisterDecision {
            id: DecisionId::new(u64::MAX),
            operation: DecidedOperation::RetireKvno {
                handle: KRBTGT,
                kvno: Kvno::new(0),
            },
            approvers: Vec::new(),
            lifetime_secs: u32::MAX,
        },
        Call::RegisterDecision {
            id: DecisionId::new(13),
            operation: DecidedOperation::DestroyKeySet {
                principal: alice.principal,
            },
            approvers: Vec::new(),
            lifetime_secs: 604_800,
        },
        Call::SealCeremony,
        Call::ListDestroyDecisions { after: None },
        Call::ListDestroyDecisions {
            after: Some(DecisionId::new(42)),
        },
        // Task K4 (docs/53 §5.5): a user's own change decision (code 6) and
        // the three change-password operations — an IPv4 and an IPv6
        // connection, every non-zero result code the codec carries.
        Call::RegisterDecision {
            id: DecisionId::new(14),
            operation: DecidedOperation::ChangePassword {
                target: alice_target(),
            },
            approvers: Vec::new(),
            lifetime_secs: 30,
        },
        Call::OpenChangePasswordRequest {
            service: PrincipalId::from_bytes([0xCF; 16]),
            ap_req_octets: ap_req().encode().unwrap(),
            krb_priv_octets: krb_priv().encode().unwrap(),
            peer: HostAddr::ipv4([192, 0, 2, 10]),
            local: HostAddr::ipv4([192, 0, 2, 1]),
        },
        Call::OpenChangePasswordRequest {
            service: PrincipalId::from_bytes([0xCF; 16]),
            ap_req_octets: ap_req().encode().unwrap(),
            krb_priv_octets: krb_priv().encode().unwrap(),
            peer: HostAddr::ipv6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a,
            ]),
            local: HostAddr::ipv6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ]),
        },
        Call::CompleteChangePassword {
            ctx: ChangePasswordCtxId::from_bytes([0xCC; 16]),
            target: handle(0xA1, KeyPurpose::PrincipalLongterm),
        },
        Call::SealChangePasswordError {
            ctx: ChangePasswordCtxId::from_bytes([0xCD; 16]),
            code: NonZeroResultCode::Malformed,
        },
        Call::SealChangePasswordError {
            ctx: ChangePasswordCtxId::from_bytes([0xCE; 16]),
            code: NonZeroResultCode::InitialFlagNeeded,
        },
        // Task F3 (docs/questions/Q-976): the revocation names an id only.
        Call::RevokeDecision {
            id: DecisionId::new(15),
        },
        Call::RevokeDecision {
            id: DecisionId::new(u64::MAX),
        },
        // Task PN9 (docs/59 §7.5): the key only — the made-up key, and one
        // whose only non-zero octet is the last.
        Call::InstallAttestationKey {
            key: attestation_key(),
        },
        Call::InstallAttestationKey {
            key: AttestationKeyOctets::from_slice(&{
                let mut key = [0u8; 32];
                key[31] = 0x01;
                key
            })
            .unwrap(),
        },
    ]
}

/// A KRB-PRIV (RFC 4120 5.7.1): opaque ciphertext under key usage 13.
pub fn krb_priv() -> KrbPriv {
    KrbPriv {
        enc_part: enc(18, None, 0x13),
    }
}

/// A sealed change-password reply (docs/53 §5.5): an AP-REP (RFC 4120
/// 5.5.2) and a KRB-PRIV, both opaque ciphertext here.
pub fn sealed_reply() -> SealedReply {
    SealedReply {
        ap_rep: ApRep {
            enc_part: enc(18, None, 0x12),
        },
        krb_priv: krb_priv(),
    }
}

/// An opened change-password request with `verdict` (docs/53 §5.5).
pub fn change_password_context(verdict: ChangePasswordVerdict) -> ChangePasswordContext {
    ChangePasswordContext {
        ctx_id: ChangePasswordCtxId::from_bytes([0xCB; 16]),
        crealm: realm(),
        cname: name(1, &["alice"]),
        authtime: time(5),
        endtime: time(10),
        flags: flags(0x0060_0000),
        verdict,
    }
}

/// An approver's principal id (made up for these tests).
pub fn approver(octet: u8) -> PrincipalId {
    PrincipalId::from_bytes([octet; 16])
}

/// alice's one key target: handle, binding and salt (N4, A-102).
pub fn alice_target() -> SetSecretTarget {
    SetSecretTarget {
        handle: handle(0xA1, KeyPurpose::PrincipalLongterm),
        binding: binding(),
        salt: String::from("EXAMPLE.ORGalice"),
    }
}

/// A computer's two key targets (docs/47 §9.1), each with its salt.
pub fn computer_targets() -> Vec<SetSecretTarget> {
    vec![
        SetSecretTarget {
            handle: handle(0xC7, KeyPurpose::PrincipalLongterm),
            binding: PrincipalBinding::new(realm(), name(1, &["ws7$"])),
            salt: String::from("EXAMPLE.ORGhostws7.example.org"),
        },
        SetSecretTarget {
            handle: handle(0xC7, KeyPurpose::Service),
            binding: PrincipalBinding::new(realm(), name(3, &["host", "ws7.example.org"])),
            salt: String::from("EXAMPLE.ORGhostws7.example.org"),
        },
    ]
}

/// A page of pending destroy decisions: `count` entries from id `first`.
pub fn destruction_page(first: u64, count: u64, next: Option<u64>) -> DestructionPage {
    DestructionPage {
        entries: (0..count)
            .map(|i| PendingDestruction {
                decision: DecisionId::new(first + i),
                principal: PrincipalId::from_bytes([i as u8; 16]),
            })
            .collect(),
        next: next.map(DecisionId::new),
    }
}

pub fn description(s2k: bool) -> ConfigDescription {
    ConfigDescription {
        realm: realm(),
        enctypes: vec![
            EncTypeId::Aes256CtsHmacSha384192,
            EncTypeId::Aes256CtsHmacSha196,
            EncTypeId::Aes128CtsHmacSha196,
            EncTypeId::Aes128CtsHmacSha256128,
        ],
        clock_skew_secs: 300,
        token_lifetime_secs: 60,
        ticket_policy: TicketPolicy::default(),
        s2k_params: s2k.then_some([0x00, 0x00, 0x10, 0x00]),
    }
}

/// Every caller role of keyd-types (docs/10 §2, the phase-1 variants).
pub const ROLES: [Role; 4] = [Role::Kdc, Role::Directory, Role::Admin, Role::Ldap];

/// keyd's `DescribeConfig` result for a caller keyd resolved to `role`
/// (docs/questions/Q-351, A-87).
pub fn described(s2k: bool, role: Role) -> DescribedConfig {
    DescribedConfig {
        description: description(s2k),
        caller_role: role,
    }
}

pub fn tgt_context(fast: bool) -> TgtContext {
    TgtContext {
        ctx_id: CtxId::from_bytes([0xC4; 16]),
        crealm: realm(),
        cname: name(1, &["alice"]),
        authtime: time(1),
        starttime: fast.then(|| time(2)),
        endtime: time(50),
        renew_till: fast.then(|| time(55)),
        flags: flags(0x0060_0000),
        fast_req: fast.then(fast_req),
    }
}

/// Every operation's success answer (optional parts both ways) and every
/// error variant of every error type.
pub fn answers() -> Vec<Answer> {
    let mut answers = vec![
        Answer::VerifyPreauth(Ok(proof())),
        Answer::IssueAsRep(Ok(AsRepParts {
            ticket: ticket(),
            enc_part: enc(18, Some(3), 0x21),
            fast_rep: Some(enc(18, None, 0x22)),
        })),
        Answer::IssueAsRep(Ok(AsRepParts {
            ticket: ticket(),
            enc_part: enc(17, Some(1), 0x23),
            fast_rep: None,
        })),
        Answer::OpenFastArmor(Ok(FastArmor {
            armor_id: ArmorId::from_bytes([0xAD; 16]),
            armor_crealm: realm(),
            armor_cname: name(1, &["ws1$"]),
            armor_authtime: time(4),
            fast_req: fast_req(),
        })),
        Answer::OpenAndVerifyTgt(Ok(tgt_context(true))),
        Answer::OpenAndVerifyTgt(Ok(tgt_context(false))),
        Answer::IssueTgsRep(Ok(TgsRepParts {
            ticket: ticket(),
            enc_part: enc(18, None, 0x24),
            fast_rep: Some(enc(18, None, 0x25)),
        })),
        Answer::SealFastError(Ok(enc(18, None, 0x26))),
        Answer::OpenAndVerifyServiceTicket(Ok(ServiceContext {
            ctx_id: ServiceCtxId::from_bytes([0x5C; 16]),
            crealm: realm(),
            cname: name(1, &["alice"]),
            authtime: time(5),
            endtime: time(45),
            flags: flags(0x0040_0000),
            subkey_present: true,
        })),
        Answer::OpenAndVerifyServiceTicket(Ok(ServiceContext {
            ctx_id: ServiceCtxId::from_bytes([0x5D; 16]),
            crealm: realm(),
            cname: name(1, &["alice"]),
            authtime: time(5),
            endtime: time(45),
            flags: flags(0),
            subkey_present: false,
        })),
        // Q-523: the operation digest keyd verified, and no context id.
        Answer::VerifyOperationTicket(Ok(keyd_types::OperationTicket {
            crealm: realm(),
            cname: name(1, &["alice"]),
            authtime: time(5),
            endtime: time(45),
            flags: flags(0),
            operation: keyd_types::OperationDigest::new([0xD2; 32]),
        })),
        Answer::SetSecret(Ok(Kvno::INITIAL)),
        Answer::VerifySecret(Ok(())),
        Answer::CreateKey(Ok(Kvno::new(1))),
        Answer::RotateKey(Ok(Kvno::new(2))),
        Answer::RotateKrbtgt(Ok(Kvno::new(u32::MAX))),
        Answer::RetireKvno(Ok(())),
        Answer::DestroyKeySet(Ok(())),
        Answer::DescribeConfig(Ok(described(false, Role::Kdc))),
        Answer::Ping(Ok(Role::Directory)),
        Answer::GrantSetSecret(Ok(())),
        Answer::RegisterDecision(Ok(())),
        Answer::SealCeremony(Ok(())),
        Answer::ListDestroyDecisions(Ok(destruction_page(1, 0, None))),
        Answer::ListDestroyDecisions(Ok(destruction_page(5, 3, Some(7)))),
        Answer::ListDestroyDecisions(Ok(destruction_page(1, 64, Some(64)))),
        Answer::CompleteChangePassword(Ok(sealed_reply())),
        Answer::SealChangePasswordError(Ok(sealed_reply())),
        // Task F3 (docs/questions/Q-976).
        Answer::RevokeDecision(Ok(())),
        // Task PN9 (docs/59 §7.5).
        Answer::InstallAttestationKey(Ok(())),
    ];
    // Task K4: every verdict of the closed table.
    for verdict in [
        ChangePasswordVerdict::Acceptable,
        ChangePasswordVerdict::Malformed,
        ChangePasswordVerdict::InitialFlagNeeded,
        ChangePasswordVerdict::SetNotSupported,
        ChangePasswordVerdict::PasswordRefused,
    ] {
        answers.push(Answer::OpenChangePasswordRequest(Ok(
            change_password_context(verdict),
        )));
    }
    // The caller role of the DescribeConfig reply: every value of the closed
    // table (Q-351, A-87) — the codec carries any role; keyd answers only
    // Kdc and Ldap callers (docs/10 §2).
    for role in ROLES {
        answers.push(Answer::DescribeConfig(Ok(described(true, role))));
    }
    // The caller role of the Ping reply (task R9, Q-466 item 2): every value
    // of the same closed table — every role may ping (docs/10 §2).
    for role in ROLES {
        answers.push(Answer::Ping(Ok(role)));
    }
    for error in [
        AuthnError::Denied,
        AuthnError::TicketExpired,
        AuthnError::TicketNotYetValid,
        AuthnError::Skew,
        AuthnError::Replay,
        AuthnError::Unavailable,
    ] {
        answers.push(Answer::VerifyPreauth(Err(error)));
        answers.push(Answer::OpenFastArmor(Err(error)));
        answers.push(Answer::OpenAndVerifyTgt(Err(error)));
        answers.push(Answer::OpenAndVerifyServiceTicket(Err(error)));
        answers.push(Answer::VerifyOperationTicket(Err(error)));
        answers.push(Answer::OpenChangePasswordRequest(Err(error)));
    }
    for error in [
        IssueError::Denied,
        IssueError::BadTemplate,
        IssueError::Unavailable,
    ] {
        answers.push(Answer::IssueAsRep(Err(error)));
        answers.push(Answer::IssueTgsRep(Err(error)));
    }
    for error in [
        keyd_types::Error::Denied,
        keyd_types::Error::Unavailable,
        keyd_types::Error::RateLimited,
    ] {
        answers.push(Answer::SealFastError(Err(error)));
        answers.push(Answer::SetSecret(Err(error)));
        answers.push(Answer::VerifySecret(Err(error)));
        answers.push(Answer::CreateKey(Err(error)));
        answers.push(Answer::RotateKey(Err(error)));
        answers.push(Answer::RotateKrbtgt(Err(error)));
        answers.push(Answer::RetireKvno(Err(error)));
        answers.push(Answer::DestroyKeySet(Err(error)));
        answers.push(Answer::DescribeConfig(Err(error)));
        answers.push(Answer::Ping(Err(error)));
        answers.push(Answer::GrantSetSecret(Err(error)));
        answers.push(Answer::RegisterDecision(Err(error)));
        answers.push(Answer::SealCeremony(Err(error)));
        answers.push(Answer::ListDestroyDecisions(Err(error)));
        answers.push(Answer::CompleteChangePassword(Err(error)));
        answers.push(Answer::SealChangePasswordError(Err(error)));
        answers.push(Answer::RevokeDecision(Err(error)));
        answers.push(Answer::InstallAttestationKey(Err(error)));
    }
    answers
}
