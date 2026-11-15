//! Shared samples for the manifest tests.
//!
//! Every value is constructed by hand for these tests and obviously fake:
//! the realm EXAMPLE.TEST (".test"), the [MS-DTYP] 2.4.2.4 example domain
//! SID S-1-5-21-1-2-3, GUIDs ...0001 to ...0006 (...0006 the
//! change-password service object, task K9), administrators alice and
//! bob with the placeholder salts `salt-a` and `salt-b` (not the
//! directory's salt rule — the manifest only carries the text). No vector
//! comes from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

use dtyp::{Guid, Sid};
use provision_manifest::ManifestFields;

/// A valid manifest in the canonical form the encoder writes.
/// Source: docs/51 §4.3 step 8 (what the manifest holds); crate docs (the
/// format).
pub const SAMPLE: &str = "\
# provisioning manifest (docs/51 4.3 step 8): identifiers only, no secret
manifest_version = 1
realm = EXAMPLE.TEST
domain_sid = S-1-5-21-1-2-3
naming_context = dc=example,dc=test
dc_fqdn = dc1.example.test
krbtgt = 00000000-0000-0000-0000-000000000001:NT-SRV-INST:krbtgt/EXAMPLE.TEST
ldap_service = 00000000-0000-0000-0000-000000000002:NT-SRV-HST:ldap/dc1.example.test
admin_service = 00000000-0000-0000-0000-000000000003:NT-SRV-HST:admind/dc1.example.test
change_password_service = 00000000-0000-0000-0000-000000000006:NT-SRV-INST:kadmin/changepw
first_admins = 00000000-0000-0000-0000-000000000004:NT-PRINCIPAL:alice, 00000000-0000-0000-0000-000000000005:NT-PRINCIPAL:bob
first_admin_salts = salt-a, salt-b
";

/// The GUID whose packet is fifteen zero octets and then `last`.
pub fn guid(last: u8) -> Guid {
    let mut packet = [0u8; 16];
    packet[15] = last;
    Guid::from_packet(&packet)
}

/// The text of [`guid`]: `00000000-0000-0000-0000-0000000000<last>`.
pub fn guid_text(last: u8) -> String {
    format!("00000000-0000-0000-0000-0000000000{last:02x}")
}

/// The fields of [`SAMPLE`].
pub fn fields() -> ManifestFields {
    ManifestFields {
        realm: "EXAMPLE.TEST".to_owned(),
        domain_sid: Sid::parse_sid_string("S-1-5-21-1-2-3").unwrap(),
        naming_context: vec!["example".to_owned(), "test".to_owned()],
        dc_fqdn: "dc1.example.test".to_owned(),
        krbtgt: guid(1),
        ldap_service: guid(2),
        admin_service: guid(3),
        change_password_service: guid(6),
        first_admins: vec![(guid(4), "alice".to_owned()), (guid(5), "bob".to_owned())],
        first_admin_salts: vec!["salt-a".to_owned(), "salt-b".to_owned()],
    }
}

/// `text` with the value of `key` replaced by `value` (the key must be on
/// exactly one line).
pub fn set(text: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key} = ");
    let mut found = 0;
    let out: Vec<String> = text
        .lines()
        .map(|line| {
            if line.starts_with(&prefix) {
                found += 1;
                format!("{prefix}{value}")
            } else {
                line.to_owned()
            }
        })
        .collect();
    assert_eq!(found, 1, "key {key} must be on exactly one line");
    out.join("\n") + "\n"
}

/// `text` without the line of `key`.
pub fn remove(text: &str, key: &str) -> String {
    let prefix = format!("{key} = ");
    let out: Vec<&str> = text.lines().filter(|l| !l.starts_with(&prefix)).collect();
    out.join("\n") + "\n"
}

/// The 1-based line of `key` in `text`.
pub fn line_of(text: &str, key: &str) -> Option<u32> {
    let prefix = format!("{key} = ");
    text.lines()
        .position(|line| line.starts_with(&prefix))
        .and_then(|index| u32::try_from(index + 1).ok())
}
