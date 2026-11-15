//! The front's replies, without a network: the KRB-ERROR encoder field by
//! field and code by code, the framing of keyd's sealed reply, and the pins
//! of the front's copies (the service name, the clock conversion) to keyd's
//! one definitions.
//!
//! Sources: RFC 3244 §2 (reply message; result codes 1–7; "not allowed in a
//! KRB-ERROR"; the result string "may be omitted"); RFC 4120 §5.2.3, §5.9.1,
//! §6.2, §7.5.9; docs/53 §5.5, §5.7; docs/questions Q-604 items 1, 5, Q-621
//! item 6; crates/keyd-types `CHANGE_PASSWORD_SERVICE_NAME` and
//! `kerberos_time_seconds` (this project's own definitions).

use ipc_kpasswd::{ApRepOctets, KrbPrivOctets, SealedReply, UnsealedCode};
use kpasswd_front::clock::{kerberos_time_from_unix, ServerTime};
use kpasswd_front::reply::{result_code_of, sealed_reply, ReplyEncoder, CHANGE_PASSWORD_SERVICE};
use krb_proto::constants::{KRB_ERR_GENERIC, KRB_NT_SRV_INST};
use krb_proto::{KerberosTime, KrbError, Microseconds, NonZeroResultCode};
use parse_kpasswd::{ReplyBody, ReplyMessage};

fn time() -> ServerTime {
    ServerTime {
        stime: KerberosTime::new(2026, 11, 15, 12, 34, 56).unwrap(),
        susec: Microseconds::new(654_321).unwrap(),
    }
}

const ALL_CODES: [NonZeroResultCode; 7] = [
    NonZeroResultCode::Malformed,
    NonZeroResultCode::HardError,
    NonZeroResultCode::AuthError,
    NonZeroResultCode::SoftError,
    NonZeroResultCode::AccessDenied,
    NonZeroResultCode::BadVersion,
    NonZeroResultCode::InitialFlagNeeded,
];

/// docs/53 §5.7; Q-604 items 1, 5; RFC 4120 §5.9.1 (the fields), §6.2
/// (NT-SRV-INST), §7.5.9 (60 = KRB_ERR_GENERIC); RFC 3244 §2 (AP_REP length
/// 0 ⇒ KRB-ERROR; e-data = the result code, the string omitted): for every
/// code the front can send, the KRB-ERROR decodes to exactly the documented
/// fields and the reply frame is a KRB-ERROR reply of version 0x0001.
#[test]
fn every_krb_error_has_the_documented_fields() {
    let encoder = ReplyEncoder::new("EXAMPLE.TEST").unwrap();
    for code in ALL_CODES {
        let frame = encoder.krb_error(code, time()).unwrap();
        let message = ReplyMessage::parse_tcp(&frame).unwrap();
        let ReplyBody::KrbError { krb_error } = message.body() else {
            panic!("not a KRB-ERROR reply");
        };
        assert_eq!(krb_error[0], 0x7E, "[APPLICATION 30] (RFC 4120 §5.10)");
        let error = KrbError::decode(krb_error).unwrap();
        assert_eq!(error.error_code, KRB_ERR_GENERIC);
        assert_eq!(error.stime, time().stime);
        assert_eq!(error.susec, time().susec);
        assert_eq!(error.realm.as_str(), "EXAMPLE.TEST");
        assert_eq!(error.sname.name_type, KRB_NT_SRV_INST);
        let sname: Vec<&str> = error.sname.name_string.iter().map(|s| s.as_str()).collect();
        assert_eq!(sname, CHANGE_PASSWORD_SERVICE);
        assert_eq!(error.e_data, Some(code.value().to_be_bytes().to_vec()));
        assert_eq!(
            NonZeroResultCode::from_result_data(error.e_data.as_deref().unwrap()),
            Ok(code)
        );
        assert!(error.ctime.is_none() && error.cusec.is_none());
        assert!(error.crealm.is_none() && error.cname.is_none());
        assert!(error.e_text.is_none());
        // Re-encoding is exact (krb-proto's lossless rule).
        assert_eq!(error.encode().unwrap(), krb_error);
    }
}

/// docs/53 §5.7 (the KRB-ERROR "is smaller than any valid request"): even
/// with the longest realm the configuration admits a value line for, the
/// KRB-ERROR reply fits an RFC 3244 message many times over.
#[test]
fn a_krb_error_is_small() {
    let encoder = ReplyEncoder::new(&"R".repeat(900)).unwrap();
    let frame = encoder
        .krb_error(NonZeroResultCode::Malformed, time())
        .unwrap();
    assert!(frame.len() < 1100, "{}", frame.len());
}

/// RFC 4120 §5.2.1, §5.2.2: the encoder refuses a realm a KerberosString
/// cannot hold (empty, a control character, a non-IA5 octet).
#[test]
fn the_encoder_refuses_an_invalid_realm() {
    for realm in ["", "A\u{1}B", "\u{e9}"] {
        assert!(ReplyEncoder::new(realm).is_err(), "{realm:?}");
    }
}

/// docs/53 §5.7 (dird's rows: AUTHERROR, HARDERROR): the channel's unsealed
/// codes map to RFC 3244's.
#[test]
fn unsealed_codes_map_to_rfc3244_codes() {
    assert_eq!(
        result_code_of(UnsealedCode::AuthError),
        NonZeroResultCode::AuthError
    );
    assert_eq!(
        result_code_of(UnsealedCode::HardError),
        NonZeroResultCode::HardError
    );
}

/// docs/53 §5.5 ("SealedReply { ap_rep, krb_priv } — the front frames
/// it"); RFC 3244 §2 (reply message): keyd's two messages travel unchanged
/// in a reply of version 0x0001 whose AP_REP length is the AP-REP's.
#[test]
fn a_sealed_reply_is_framed_unchanged() {
    let ap_rep = {
        let mut v = vec![0x41; 40];
        v[0] = 0x6F;
        v
    };
    let krb_priv = {
        let mut v = vec![0x42; 25];
        v[0] = 0x75;
        v
    };
    let sealed = SealedReply::new(
        ApRepOctets::new(&ap_rep).unwrap(),
        KrbPrivOctets::new(&krb_priv).unwrap(),
    )
    .unwrap();
    let frame = sealed_reply(&sealed).unwrap();
    let total = 6 + 40 + 25;
    assert_eq!(&frame[..4], &(total as u32).to_be_bytes());
    assert_eq!(&frame[4..10], &[0, total as u8, 0x00, 0x01, 0, 40]);
    assert_eq!(&frame[10..50], &ap_rep[..]);
    assert_eq!(&frame[50..], &krb_priv[..]);
}

/// Pin of the front's copy of the service name to keyd's one definition
/// (crates/keyd-types; RFC 3244 §2 "kadmin/changepw"); docs/questions/Q-955
/// item 5.
#[test]
fn the_service_name_is_keyds() {
    assert_eq!(
        CHANGE_PASSWORD_SERVICE,
        keyd_types::CHANGE_PASSWORD_SERVICE_NAME
    );
}

/// Pin of the front's clock conversion to keyd's one KerberosTime scale
/// (crates/keyd-types `kerberos_time_seconds`; RFC 4120 §5.2.3): for
/// instants across leap days, century years and the range ends, the
/// difference on keyd's scale is the Unix difference.
#[test]
fn the_clock_conversion_agrees_with_keyds_scale() {
    let epoch = keyd_types::kerberos_time_seconds(&kerberos_time_from_unix(0).unwrap());
    let last =
        keyd_types::kerberos_time_seconds(&KerberosTime::new(9999, 12, 31, 23, 59, 59).unwrap());
    let last_unix = u64::try_from(last - epoch).unwrap();
    for secs in [
        0u64,
        59,
        86_399,
        86_400,
        951_782_400,   // 2000-02-29T00:00:00Z
        951_868_799,   // 2000-02-29T23:59:59Z
        4_107_542_400, // 2100-03-01T00:00:00Z (2100 is not a leap year)
        1_794_744_000,
        last_unix,
    ] {
        let time = kerberos_time_from_unix(secs).unwrap();
        assert_eq!(
            keyd_types::kerberos_time_seconds(&time) - epoch,
            i64::try_from(secs).unwrap(),
            "{secs}"
        );
    }
    assert_eq!(kerberos_time_from_unix(last_unix + 1), None);
}
