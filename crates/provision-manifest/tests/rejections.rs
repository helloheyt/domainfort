//! Every format and manifest rule rejects what it must, with its typed
//! error, its line and its key — and never echoes the input.
//!
//! Each test names its source: the docs/50 §7.1 format rule, the docs/51 /
//! docs/47 / RFC 4120 / [MS-DTYP] / [MS-SAMR] rule, or the decision (A-xx,
//! P-xx) the input violates. Inputs are the `common` sample with one line
//! changed.

mod common;

use common::{fields, guid, line_of, remove, set, SAMPLE};
use provision_manifest::limits::{MAX_FILE_OCTETS, MAX_LINES, MAX_LINE_OCTETS};
use provision_manifest::{keys, Error, ErrorKind, Manifest};

fn error(text: &str) -> Error {
    Manifest::parse(text.as_bytes()).expect_err("the input must be rejected")
}

/// The sample with `key` set to `value` is rejected with `kind` at `key`'s
/// line, naming `key`; the error's text does not contain `value` (checked
/// for values of four octets or more — a shorter one, such as `2`, can occur
/// in the fixed text by chance, e.g. as a line number).
fn rejects(key: &'static str, value: &str, kind: ErrorKind) {
    let text = set(SAMPLE, key, value);
    let err = error(&text);
    assert_eq!(err.kind(), kind, "{key} = {value}: {err}");
    assert_eq!(err.key(), Some(key), "{key} = {value}");
    assert_eq!(err.line(), line_of(&text, key), "{key} = {value}");
    if value.len() >= 4 {
        assert!(
            !err.to_string().contains(value),
            "the error must not echo the value: {err}"
        );
    }
}

// ---- format (docs/50 §7.1) ---------------------------------------------------

/// docs/50 §7.1 ("duplicate … ⇒ refuse").
#[test]
fn a_duplicate_key_is_rejected() {
    let text = format!("{SAMPLE}realm = EXAMPLE.TEST\n");
    let err = error(&text);
    assert_eq!(err.kind(), ErrorKind::DuplicateKey);
    assert_eq!(err.key(), Some(keys::REALM));
    assert_eq!(err.line(), Some(11));
}

/// docs/50 R50-15 ("a closed key table"), §7.1 ("unknown key ⇒ refuse").
#[test]
fn an_unknown_key_is_rejected() {
    let text = format!("{SAMPLE}krbtgt_kvno = 1\n");
    let err = error(&text);
    assert_eq!(err.kind(), ErrorKind::UnknownKey);
    assert_eq!(err.key(), None);
    assert_eq!(err.line(), Some(11));
}

/// docs/50 §7.1 ("missing-required ⇒ refuse"): every manifest key is
/// required.
#[test]
fn every_missing_key_is_rejected() {
    for key in Manifest::KEYS {
        let err = error(&remove(SAMPLE, key));
        assert_eq!(err.kind(), ErrorKind::MissingKey, "{key}");
        assert_eq!(err.key(), Some(*key));
    }
}

/// docs/50 §7.1 ("printable ASCII only"); PENDING-OWNER P-6: a UTF-8
/// letter, a TAB, a CR (CRLF line ends) and a NUL are refused.
#[test]
fn non_ascii_and_control_octets_are_rejected() {
    for bad in [
        "realm = EXAMPL\u{c9}.TEST",
        "realm =\tEXAMPLE.TEST",
        "realm = EXAMPLE.TEST\r",
        "realm = EXAMPLE\u{0}.TEST",
    ] {
        let text = SAMPLE.replace("realm = EXAMPLE.TEST", bad);
        let err = error(&text);
        assert_eq!(err.kind(), ErrorKind::InvalidCharacter, "{bad:?}");
        assert_eq!(err.line(), Some(3));
    }
    let text = format!("{SAMPLE}# caf\u{e9}\n");
    assert_eq!(error(&text).kind(), ErrorKind::InvalidCharacter);
}

/// docs/50 §7.1 ("file ≤ 64 KiB", "line ≤ 1024"); AGENTS.md §6 (bounded):
/// an oversized input, an over-long line and too many lines are refused.
#[test]
fn oversize_inputs_are_rejected() {
    let comment = format!("#{}\n", "x".repeat(MAX_LINE_OCTETS - 1));
    let big = SAMPLE.to_owned() + &comment.repeat(MAX_FILE_OCTETS / comment.len() + 1);
    assert!(big.len() > MAX_FILE_OCTETS);
    assert_eq!(error(&big).kind(), ErrorKind::FileTooLarge);

    let long = format!("{SAMPLE}#{}\n", "x".repeat(MAX_LINE_OCTETS));
    let err = error(&long);
    assert_eq!(err.kind(), ErrorKind::LineTooLong);
    assert_eq!(err.line(), Some(11));

    let many = SAMPLE.to_owned() + &"\n".repeat(MAX_LINES);
    assert_eq!(error(&many).kind(), ErrorKind::TooManyLines);

    let value = format!("dc={}", "a".repeat(980));
    let err = error(&set(SAMPLE, keys::NAMING_CONTEXT, &value));
    assert_eq!(err.kind(), ErrorKind::ValueTooLong);
}

/// docs/50 §7.1 (fail closed on a cut last line).
#[test]
fn a_missing_final_newline_is_rejected() {
    let cut = SAMPLE.trim_end_matches('\n');
    assert_eq!(error(cut).kind(), ErrorKind::MissingFinalNewline);
}

/// docs/50 R50-15 (`key = value`, one spelling): indentation, no spaces
/// around `=`, a trailing space, a section header.
#[test]
fn malformed_lines_are_rejected() {
    for bad in [
        " realm = EXAMPLE.TEST",
        "realm=EXAMPLE.TEST",
        "realm = EXAMPLE.TEST ",
        "[manifest]",
        "Realm = EXAMPLE.TEST",
    ] {
        let text = SAMPLE.replace("realm = EXAMPLE.TEST", bad);
        assert_eq!(error(&text).kind(), ErrorKind::MalformedLine, "{bad:?}");
    }
}

// ---- values ------------------------------------------------------------------

/// docs/50 §3.3 (D57: exact version, no fallback), applied to the manifest.
#[test]
fn another_version_is_rejected() {
    for v in ["2", "0", "01", "1.0"] {
        rejects(keys::MANIFEST_VERSION, v, ErrorKind::UnsupportedVersion);
    }
}

/// [MS-DTYP] 2.5.1.1 (`8HEXDIG "-" 4HEXDIG "-" 4HEXDIG "-" 4HEXDIG "-"
/// 12HEXDIG`), one lower-case spelling (A-31 route): upper case, braces,
/// short, long, a misplaced dash, a non-hex digit are refused; and the NULL
/// GUID (docs/51 §4.1: an objectGUID "MUST NOT be the NULL GUID").
#[test]
fn bad_guid_syntax_is_rejected() {
    let binding = ":NT-SRV-INST:krbtgt/EXAMPLE.TEST";
    for bad in [
        "AB721A53-1E2F-11D0-9819-00AA0040529B",
        "{ab721a53-1e2f-11d0-9819-00aa0040529b}",
        "ab721a53-1e2f-11d0-9819-00aa0040529",
        "ab721a53-1e2f-11d0-9819-00aa0040529b0",
        "ab721a531-e2f-11d0-9819-00aa0040529b",
        "ab721a53-1e2f-11d0-9819-00aa0040529g",
        "ab721a53_1e2f_11d0_9819_00aa0040529b",
    ] {
        let text = set(SAMPLE, keys::KRBTGT, &format!("{bad}{binding}"));
        let err = error(&text);
        assert!(
            matches!(
                err.kind(),
                ErrorKind::InvalidGuid | ErrorKind::InvalidObjectEntry
            ),
            "{bad}: {err}"
        );
        assert_eq!(err.key(), Some(keys::KRBTGT));
    }
    rejects(
        keys::KRBTGT,
        "00000000-0000-0000-0000-000000000000:NT-SRV-INST:krbtgt/EXAMPLE.TEST",
        ErrorKind::NullGuid,
    );
}

/// [MS-DTYP] 2.4.2.4 (S-1-5-21 followed by three 32-bit values), 2.4.2.1
/// (canonical string): the wrong authority, the wrong first SubAuthority,
/// the wrong count, a leading zero, an overflow, a lower-case prefix.
#[test]
fn bad_domain_sid_syntax_is_rejected() {
    for bad in [
        "S-1-5-32-544",
        "S-1-1-21-1-2-3",
        "S-1-5-21-1-2",
        "S-1-5-21-1-2-3-4",
        "S-1-5-21-01-2-3",
        "S-1-5-21-1-2-4294967296",
        "s-1-5-21-1-2-3",
        "S-1-5-21-1-2-3-",
        "S-1-5-21",
    ] {
        rejects(keys::DOMAIN_SID, bad, ErrorKind::InvalidDomainSid);
    }
}

/// docs/47 §3.3 item 3 (the realm is the domain's DNS name in upper case);
/// A-55 (the NC must name the realm): a lower-case realm, characters outside
/// the realm alphabet, and a realm that is not the NC's DNS name.
#[test]
fn a_realm_not_naming_the_nc_in_upper_case_is_rejected() {
    rejects(keys::REALM, "example.test", ErrorKind::InvalidRealm);
    rejects(keys::REALM, "EXAMPLE_TEST", ErrorKind::InvalidRealm);
    let other = set(SAMPLE, keys::REALM, "OTHER.TEST");
    let other = set(
        &other,
        keys::KRBTGT,
        &format!("{}:NT-SRV-INST:krbtgt/OTHER.TEST", common::guid_text(1)),
    );
    let err = error(&other);
    assert_eq!(err.kind(), ErrorKind::RealmMismatch);
    assert_eq!(err.key(), Some(keys::NAMING_CONTEXT));
}

/// A-53 (`dc=` components, no space after the comma); crates/directory-pip
/// (≤ 16 labels): upper-case attribute, a space, an empty label, 17 labels.
#[test]
fn a_bad_naming_context_is_rejected() {
    for bad in [
        "DC=example,dc=test",
        "dc=example, dc=test",
        "dc=example,,dc=test",
        "dc=,dc=test",
        "ou=example,dc=test",
        "dc=exa.mple,dc=test",
    ] {
        rejects(keys::NAMING_CONTEXT, bad, ErrorKind::InvalidNamingContext);
    }
    let labels: Vec<String> = (0..17).map(|i| format!("dc=l{i}")).collect();
    rejects(
        keys::NAMING_CONTEXT,
        &labels.join(","),
        ErrorKind::InvalidNamingContext,
    );
}

/// RFC 4120 §6.2.1 ("the name of the host MUST be lowercase"): an
/// upper-case or malformed DC host name.
#[test]
fn a_bad_dc_host_name_is_rejected() {
    for bad in [
        "DC1.example.test",
        "dc1..example.test",
        "dc1.example.test.",
        "dc_1.example.test",
    ] {
        rejects(keys::DC_FQDN, bad, ErrorKind::InvalidHostName);
    }
}

/// docs/51 §4.3 step 11; docs/47 §1.4, §9.1; RFC 4120 §6.2.1, §7.3; A-19,
/// A-73: each binding must be exactly the one its object's rule fixes.
#[test]
fn a_binding_other_than_the_fixed_one_is_rejected() {
    let g1 = common::guid_text(1);
    let g2 = common::guid_text(2);
    let g3 = common::guid_text(3);
    for (key, value) in [
        (keys::KRBTGT, format!("{g1}:NT-SRV-INST:krbtgt/OTHER.TEST")),
        (keys::KRBTGT, format!("{g1}:NT-SRV-HST:krbtgt/EXAMPLE.TEST")),
        (keys::KRBTGT, format!("{g1}:NT-SRV-INST:krbtgt")),
        (
            keys::KRBTGT,
            format!("{g1}:NT-SRV-INST:krbtgt/EXAMPLE.TEST/x"),
        ),
        (
            keys::LDAP_SERVICE,
            format!("{g2}:NT-SRV-HST:ldap/dc2.example.test"),
        ),
        (
            keys::LDAP_SERVICE,
            format!("{g2}:NT-SRV-HST:LDAP/dc1.example.test"),
        ),
        (
            keys::LDAP_SERVICE,
            format!("{g2}:NT-SRV-INST:ldap/dc1.example.test"),
        ),
        (keys::LDAP_SERVICE, format!("{g2}:3:ldap/dc1.example.test")),
        (
            keys::ADMIN_SERVICE,
            format!("{g3}:NT-SRV-HST:admin/dc1.example.test"),
        ),
        (
            keys::ADMIN_SERVICE,
            format!("{g3}:NT-SRV-HST:admind/dc1.example.test@EXAMPLE.TEST"),
        ),
    ] {
        rejects(key, &value, ErrorKind::BindingMismatch);
    }
    rejects(
        keys::ADMIN_SERVICE,
        &format!("{g3}NT-SRV-HST:admind/dc1.example.test"),
        ErrorKind::InvalidObjectEntry,
    );
}

/// docs/51 §4.3 step 2 (each objectGUID distinct): a GUID given to two
/// objects — service and krbtgt, administrator and service, two
/// administrators.
#[test]
fn a_guid_used_twice_is_rejected() {
    let g1 = common::guid_text(1);
    let g3 = common::guid_text(3);
    let g4 = common::guid_text(4);
    rejects(
        keys::LDAP_SERVICE,
        &format!("{g1}:NT-SRV-HST:ldap/dc1.example.test"),
        ErrorKind::DuplicateGuid,
    );
    rejects(
        keys::FIRST_ADMINS,
        &format!("{g3}:NT-PRINCIPAL:alice, {g4}:NT-PRINCIPAL:bob"),
        ErrorKind::DuplicateGuid,
    );
    rejects(
        keys::FIRST_ADMINS,
        &format!("{g4}:NT-PRINCIPAL:alice, {g4}:NT-PRINCIPAL:bob"),
        ErrorKind::DuplicateGuid,
    );
}

/// docs/questions/Q-295 (P-22: provisioning requires at least two tier-0
/// administrators) and the bound MAX_FIRST_ADMINS (8); docs/50 §7.1 (list
/// separator exactly ", ").
#[test]
fn the_first_admin_count_and_list_syntax_are_enforced() {
    let g4 = common::guid_text(4);
    let g5 = common::guid_text(5);
    rejects(
        keys::FIRST_ADMINS,
        &format!("{g4}:NT-PRINCIPAL:alice"),
        ErrorKind::TooFewFirstAdmins,
    );
    let nine: Vec<String> = (0x10u8..0x19)
        .map(|i| format!("{}:NT-PRINCIPAL:a{i}", common::guid_text(i)))
        .collect();
    rejects(
        keys::FIRST_ADMINS,
        &nine.join(", "),
        ErrorKind::TooManyFirstAdmins,
    );
    for bad in [
        format!("{g4}:NT-PRINCIPAL:alice,{g5}:NT-PRINCIPAL:bob"),
        format!("{g4}:NT-PRINCIPAL:alice,  {g5}:NT-PRINCIPAL:bob"),
        format!("{g4}:NT-PRINCIPAL:alice, , {g5}:NT-PRINCIPAL:bob"),
    ] {
        rejects(keys::FIRST_ADMINS, &bad, ErrorKind::InvalidList);
    }
}

/// [MS-SAMR] 3.1.1.6 items 8, 9, 10, 12, 14; RFC 4120 §6.2 (krbtgt
/// reserved); docs/47 §1.1 (uniqueness folds A-Z); the manifest's binding
/// for a user is NT-PRINCIPAL (docs/47 §9.1).
#[test]
fn bad_first_admin_names_are_rejected() {
    let g4 = common::guid_text(4);
    let g5 = common::guid_text(5);
    let with = |name: &str| format!("{g4}:NT-PRINCIPAL:{name}, {g5}:NT-PRINCIPAL:bob");
    for bad in [
        "a/b",
        "a\\b",
        "a[b",
        "a]b",
        "a:b",
        "a|b",
        "a<b",
        "a>b",
        "a+b",
        "a=b",
        "a;b",
        "a?b",
        "a*b",
        "a\"b",
        "alice.",
        "abcdefghijklmnopqrstu",
    ] {
        rejects(
            keys::FIRST_ADMINS,
            &with(bad),
            ErrorKind::InvalidAccountName,
        );
    }
    rejects(
        keys::FIRST_ADMINS,
        &with("krbtgt"),
        ErrorKind::ReservedAccountName,
    );
    rejects(
        keys::FIRST_ADMINS,
        &with("KrbTgt"),
        ErrorKind::ReservedAccountName,
    );
    rejects(
        keys::FIRST_ADMINS,
        &format!("{g4}:NT-PRINCIPAL:alice, {g5}:NT-PRINCIPAL:ALICE"),
        ErrorKind::DuplicateAccountName,
    );
    rejects(
        keys::FIRST_ADMINS,
        &format!("{g4}:NT-SRV-HST:alice, {g5}:NT-PRINCIPAL:bob"),
        ErrorKind::BindingMismatch,
    );
    rejects(
        keys::FIRST_ADMINS,
        &format!("{g4}:NT-PRINCIPAL:, {g5}:NT-PRINCIPAL:bob"),
        ErrorKind::InvalidAccountName,
    );
}

/// docs/51 §4.3 step 8 (A4 writes through the builder): the builder refuses
/// a non-printable field before writing anything, and the counts with their
/// own kinds.
#[test]
fn the_builder_refuses_what_the_parser_would() {
    let mut f = fields();
    f.realm = "EXAMPLE.TEST\nfirst_admins = x".to_owned();
    let err = Manifest::new(&f).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidCharacter);
    assert_eq!(err.key(), Some(keys::REALM));

    let mut f = fields();
    f.first_admins.truncate(1);
    assert_eq!(
        Manifest::new(&f).unwrap_err().kind(),
        ErrorKind::TooFewFirstAdmins
    );
    let mut f = fields();
    f.first_admins = (0..9).map(|i| (guid(0x20 + i), format!("u{i}"))).collect();
    assert_eq!(
        Manifest::new(&f).unwrap_err().kind(),
        ErrorKind::TooManyFirstAdmins
    );

    let mut f = fields();
    f.ldap_service = f.krbtgt;
    let err = Manifest::new(&f).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DuplicateGuid);
    assert_eq!(err.key(), Some(keys::LDAP_SERVICE));

    let mut f = fields();
    f.dc_fqdn = "DC1.example.test".to_owned();
    assert_eq!(
        Manifest::new(&f).unwrap_err().kind(),
        ErrorKind::InvalidHostName
    );
}
