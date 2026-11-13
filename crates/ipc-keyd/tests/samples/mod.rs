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

use ipc_keyd::{Answer, Call, Password, TgsFast};
use keyd::{
    ArmorId, AsRepParts, AsTicketTemplate, AuthnError, AuthnProof, ConfigDescription, CtxId,
    DualControlToken, ExchangeId, FastArmor, FastConversation, IssueError, KeyHandle, KeyPurpose,
    Kvno, PrincipalBinding, PrincipalId, ServiceContext, ServiceCtxId, TgsRepParts,
    TgsTicketTemplate, TgtContext, TicketPolicy,
};
use krb_crypto::EncType;
use krb_proto::{
    ApOptions, ApReq, Checksum, EncryptedData, FastOptions, KdcOptions, KdcReqBody, KerberosString,
    KerberosTime, KrbError, KrbFastArmor, KrbFastArmoredReq, KrbFastReq, Microseconds, PaData,
    PrincipalName, Realm, Ticket, TicketFlags,
};
use zeroize::Zeroizing;

pub const PASSWORD: &str = "correct-horse-battery-staple";

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
        session_enctype: EncType::Aes256CtsHmacSha196,
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
        session_enctype: EncType::Aes128CtsHmacSha196,
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
        },
        Call::IssueAsRep {
            client: alice,
            krbtgt: KRBTGT,
            proof: proof(),
            armor: None,
            template: as_template(false),
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
        },
        Call::IssueTgsRep {
            service: KRBTGT,
            ctx: CtxId::from_bytes([0xC2; 16]),
            template: tgs_template(false),
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
        Call::OpenAndVerifyServiceTicket {
            service,
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
        Call::RotateKey { handle: service },
        Call::RotateKrbtgt {
            krbtgt: KRBTGT,
            approval: DualControlToken {
                approver_1: PrincipalId::from_bytes([0x01; 16]),
                approver_2: PrincipalId::from_bytes([0x02; 16]),
            },
        },
        Call::RetireKvno {
            handle: service,
            kvno: Kvno::new(7),
        },
        Call::DestroyKeySet { handle: alice },
        Call::DescribeConfig,
        Call::Ping,
    ]
}

pub fn description(s2k: bool) -> ConfigDescription {
    ConfigDescription {
        realm: realm(),
        enctypes: vec![
            EncType::Aes256CtsHmacSha384192,
            EncType::Aes256CtsHmacSha196,
            EncType::Aes128CtsHmacSha196,
            EncType::Aes128CtsHmacSha256128,
        ],
        clock_skew_secs: 300,
        token_lifetime_secs: 60,
        ticket_policy: TicketPolicy::default(),
        s2k_params: s2k.then_some([0x00, 0x00, 0x10, 0x00]),
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
        Answer::SetSecret(Ok(Kvno::INITIAL)),
        Answer::VerifySecret(Ok(())),
        Answer::CreateKey(Ok(Kvno::new(1))),
        Answer::RotateKey(Ok(Kvno::new(2))),
        Answer::RotateKrbtgt(Ok(Kvno::new(u32::MAX))),
        Answer::RetireKvno(Ok(())),
        Answer::DestroyKeySet(Ok(())),
        Answer::DescribeConfig(Ok(description(true))),
        Answer::DescribeConfig(Ok(description(false))),
        Answer::Ping(Ok(())),
    ];
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
        keyd::Error::Denied,
        keyd::Error::Unavailable,
        keyd::Error::RateLimited,
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
    }
    answers
}
