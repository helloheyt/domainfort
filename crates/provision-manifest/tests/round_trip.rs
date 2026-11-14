//! What a valid manifest means, and the encode / decode round trip.
//!
//! Each test names its source (docs/51 §x, docs/47 §x, RFC 4120 §x,
//! [MS-DTYP] / [MS-DRSR] sections, A-xx). Values are the obviously fake
//! samples of `common`.

mod common;

use common::{fields, guid, guid_text, set, SAMPLE};
use keyd_types::KeyPurpose;
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST, KRB_NT_SRV_INST};
use provision_manifest::{binding_text, keys, Manifest};

fn components(set: &provision_manifest::KeySet) -> Vec<String> {
    set.binding
        .name
        .name_string
        .iter()
        .map(|c| c.as_str().to_owned())
        .collect()
}

/// docs/50 §7.1 (one spelling per line form) and docs/51 §4.3 step 8: the
/// canonical sample parses, and encodes back to exactly the same octets.
#[test]
fn the_sample_parses_and_encodes_back_identically() {
    let manifest = Manifest::parse(SAMPLE.as_bytes()).unwrap();
    assert_eq!(manifest.encode(), SAMPLE);
    assert_eq!(Manifest::parse(manifest.encode().as_bytes()), Ok(manifest));
}

/// docs/51 §4.3 step 8 (`provision domain` writes the manifest; A4): the
/// builder accepts exactly what the parser reads — building from the
/// sample's values gives the sample.
#[test]
fn the_builder_writes_what_the_parser_reads() {
    let built = Manifest::new(&fields()).unwrap();
    assert_eq!(built.encode(), SAMPLE);
    assert_eq!(Manifest::parse(SAMPLE.as_bytes()), Ok(built));
}

/// docs/52 §2 row 37 (N4, A-102; required — A-105, Q-473): `provision
/// domain` writes each first administrator's salt; the manifest writes them
/// as the last key, in `first_admins` order, parses back to itself, and
/// hands each one out beside its administrator; replacing them gives the
/// same manifest with the new salts (values obviously fake).
#[test]
fn first_admin_salts_round_trip() {
    let built = Manifest::new(&fields()).unwrap();
    let salts: Vec<&str> = built.first_admins().iter().map(|a| a.salt()).collect();
    assert_eq!(salts, ["salt-a", "salt-b"]);
    assert!(built
        .encode()
        .ends_with("first_admin_salts = salt-a, salt-b\n"));
    let resalted = built
        .with_first_admin_salts(&["salt-c".to_owned(), "salt-d".to_owned()])
        .unwrap();
    let text = resalted.encode();
    assert_eq!(text, SAMPLE.replace("salt-a, salt-b", "salt-c, salt-d"));
    assert_eq!(Manifest::parse(text.as_bytes()), Ok(resalted.clone()));
    let salts: Vec<&str> = resalted.first_admins().iter().map(|a| a.salt()).collect();
    assert_eq!(salts, ["salt-c", "salt-d"]);
    assert_eq!(resalted.realm(), built.realm());
    assert_eq!(keys::FIRST_ADMIN_SALTS, "first_admin_salts");
}

/// docs/51 §4.3 step 11 (`create_key((GUID_krbtgt, Krbtgt), NT-SRV-INST
/// [krbtgt, REALM])`); docs/47 §1.4 (R47-2); RFC 4120 §7.3 ("a two-part name
/// of type NT-SRV-INST, with the first part "krbtgt" and the second part the
/// name of the realm"); docs/47 §2.3 (PrincipalId = objectGUID packet).
#[test]
fn the_krbtgt_key_set_is_krbtgt_purpose_bound_to_krbtgt_realm() {
    let manifest = Manifest::parse(SAMPLE.as_bytes()).unwrap();
    let krbtgt = manifest.krbtgt();
    assert_eq!(krbtgt.handle.purpose, KeyPurpose::Krbtgt);
    assert_eq!(krbtgt.handle.principal.as_bytes(), &guid(1).to_packet());
    assert_eq!(krbtgt.binding.realm.as_str(), "EXAMPLE.TEST");
    assert_eq!(krbtgt.binding.name.name_type, KRB_NT_SRV_INST);
    assert_eq!(components(krbtgt), ["krbtgt", "EXAMPLE.TEST"]);
    assert_eq!(krbtgt.binding_text(), "NT-SRV-INST:krbtgt/EXAMPLE.TEST");
    assert_eq!(krbtgt.guid_text(), guid_text(1));
}

/// docs/51 §4.3 step 11 (`(GUID_ldap, Service)`, NT-SRV-HST [ldap, fqdn]
/// and `(GUID_admin, AdminService)`, [admind, fqdn] — R2, docs/52 §5 item 3,
/// the admin service's own purpose); docs/10 §5ב; A-73 (`admind/<fqdn>`);
/// RFC 4120 §6.2.1 ("a two-component name of type NT-SRV-HST").
#[test]
fn the_service_key_sets_are_service_purpose_bound_to_class_and_host() {
    let manifest = Manifest::parse(SAMPLE.as_bytes()).unwrap();
    let ldap = manifest.ldap_service();
    assert_eq!(ldap.handle.purpose, KeyPurpose::Service);
    assert_eq!(ldap.handle.principal.as_bytes(), &guid(2).to_packet());
    assert_eq!(ldap.binding.name.name_type, KRB_NT_SRV_HST);
    assert_eq!(components(ldap), ["ldap", "dc1.example.test"]);
    let admin = manifest.admin_service();
    assert_eq!(admin.handle.purpose, KeyPurpose::AdminService);
    assert_eq!(admin.handle.principal.as_bytes(), &guid(3).to_packet());
    assert_eq!(admin.binding.name.name_type, KRB_NT_SRV_HST);
    assert_eq!(components(admin), ["admind", "dc1.example.test"]);
    assert_eq!(admin.binding.realm.as_str(), "EXAMPLE.TEST");
}

/// docs/51 §4.3 step 12 (`set_secret((GUID, PrincipalLongterm), binding
/// NT-PRINCIPAL [sAMAccountName], …)`); docs/47 §9.1 (user row).
#[test]
fn each_first_admin_is_principal_longterm_bound_to_its_account_name() {
    let manifest = Manifest::parse(SAMPLE.as_bytes()).unwrap();
    let admins = manifest.first_admins();
    assert_eq!(admins.len(), 2);
    for (admin, (last, name)) in admins.iter().zip([(4u8, "alice"), (5u8, "bob")]) {
        assert_eq!(admin.sam_account_name(), name);
        let key_set = admin.key_set();
        assert_eq!(key_set.handle.purpose, KeyPurpose::PrincipalLongterm);
        assert_eq!(key_set.handle.principal.as_bytes(), &guid(last).to_packet());
        assert_eq!(key_set.binding.name.name_type, KRB_NT_PRINCIPAL);
        assert_eq!(components(key_set), [name]);
        assert_eq!(
            binding_text(&key_set.binding),
            format!("NT-PRINCIPAL:{name}")
        );
    }
}

/// docs/51 §4.3 step 8 (realm, domain SID, NC DN); [MS-DTYP] 2.4.2.4 (the
/// example domain S-1-5-21-1-2-3).
#[test]
fn the_domain_values_are_kept() {
    let manifest = Manifest::parse(SAMPLE.as_bytes()).unwrap();
    assert_eq!(manifest.realm().as_str(), "EXAMPLE.TEST");
    assert_eq!(manifest.domain_sid().to_sid_string(), "S-1-5-21-1-2-3");
    assert_eq!(manifest.naming_context_labels(), ["example", "test"]);
    assert_eq!(manifest.dc_fqdn(), "dc1.example.test");
}

/// [MS-DRSR] 5.16.3.16: the printed object ACE type
/// `ab721a53-1e2f-11d0-9819-00aa0040529b` is the packet
/// `53 1a 72 ab 2f 1e d0 11 98 19 00 aa 00 40 52 9b` — the GUID text maps
/// group 1 to Data1, 2 to Data2, 3 to Data3, groups 4-5 to Data4 in array
/// order ([MS-DTYP] 2.3.4.1, 2.3.4.2, 2.5.1.1; A-31 route).
#[test]
fn the_guid_text_follows_the_ms_drsr_5_16_3_16_example() {
    let text = set(
        SAMPLE,
        keys::KRBTGT,
        "ab721a53-1e2f-11d0-9819-00aa0040529b:NT-SRV-INST:krbtgt/EXAMPLE.TEST",
    );
    let manifest = Manifest::parse(text.as_bytes()).unwrap();
    assert_eq!(
        manifest.krbtgt().handle.principal.as_bytes(),
        &[
            0x53, 0x1a, 0x72, 0xab, 0x2f, 0x1e, 0xd0, 0x11, 0x98, 0x19, 0x00, 0xaa, 0x00, 0x40,
            0x52, 0x9b
        ]
    );
    assert_eq!(
        manifest.krbtgt().guid_text(),
        "ab721a53-1e2f-11d0-9819-00aa0040529b"
    );
    assert_eq!(manifest.encode(), text);
}

/// docs/50 §7.1: comments, empty lines and key order carry no meaning — a
/// reordered, commented manifest is the same manifest.
#[test]
fn comments_empty_lines_and_order_carry_no_meaning() {
    let mut lines: Vec<&str> = SAMPLE.lines().skip(1).collect();
    lines.reverse();
    let shuffled = format!("# a comment\n\n{}\n\n# end\n", lines.join("\n#\n"));
    assert_eq!(
        Manifest::parse(shuffled.as_bytes()),
        Manifest::parse(SAMPLE.as_bytes())
    );
}

/// docs/questions/Q-295 / P-22 (at least two first administrators) and the
/// project bound MAX_FIRST_ADMINS (8): two and eight are accepted, with
/// 20-character names ([MS-SAMR] 3.1.1.6 item 12) — the longest list fits
/// one line.
#[test]
fn two_to_eight_first_admins_with_twenty_character_names_fit() {
    for count in [2u8, 8] {
        let mut f = fields();
        f.first_admins = (0..count)
            .map(|i| (guid(0x10 + i), format!("admin{i}{}", "x".repeat(14))))
            .collect();
        f.first_admin_salts = (0..count).map(|i| format!("salt-{i}")).collect();
        let manifest = Manifest::new(&f).unwrap();
        assert_eq!(manifest.first_admins().len(), usize::from(count));
        assert!(manifest
            .first_admins()
            .iter()
            .all(|a| a.sam_account_name().len() == 20));
        assert_eq!(Manifest::parse(manifest.encode().as_bytes()), Ok(manifest));
    }
}

/// [MS-SAMR] 3.1.1.6 items 8-10: the characters a sAMAccountName may hold
/// besides letters and digits (no space, none of item 10's table) are
/// accepted and round-trip.
#[test]
fn account_names_with_permitted_punctuation_round_trip() {
    let mut f = fields();
    f.first_admins = vec![
        (guid(4), "a.b-c_d".to_owned()),
        (guid(5), "x!#$%&'()".to_owned()),
    ];
    let manifest = Manifest::new(&f).unwrap();
    assert_eq!(manifest.first_admins()[0].sam_account_name(), "a.b-c_d");
    assert_eq!(Manifest::parse(manifest.encode().as_bytes()), Ok(manifest));
}
