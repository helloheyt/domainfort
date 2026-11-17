#![no_main]
//! Fuzz target for the request form of the one principal namespace
//! (docs/59 §8, task PN1: `principal_key_of_request`).
//!
//! docs/CLEAN-ROOM.md requires a fuzz target for every parser before it merges to
//! `main`; `key_of_request` parses the principal name and realm a client
//! sends. Input layout: octet 0 is the name-type (sign-extended), octet 1
//! picks the class of a stored object; the rest is cut at each 0xFF octet —
//! the first piece is the request's realm, every further piece (up to
//! krb-proto's `MAX_NAME_COMPONENTS`) a name component. Pieces that are not
//! KerberosString content are skipped as krb-proto's decoder would refuse
//! them.
//!
//! Properties (tests/support/properties.rs, shared with the deterministic
//! test tests/one_equivalence.rs): no panic; the name-type and case are not
//! significant; a probed key is a key's form and never names the krbtgt
//! account; the key is the request's components folded (injectivity); and
//! — with pieces 1-4 read as a stored object's sAMAccountName,
//! userPrincipalName, servicePrincipalName and dNSHostName — every object
//! `keys_of_names` accepts stores keys its own names probe (writer and
//! reader agree, class C49).
//!
//! Spec: docs/59 §4.2, §4.3, §8, §10.1; RFC 4120 §6.2; [MS-KILE] 3.1.5.7,
//! 3.3.5.1.1, 3.3.5.6.1; [MS-ADTS] 2.2.21; RFC 4120 §5.2.1, §5.2.2
//! (KerberosString, PrincipalName).

#[path = "../../tests/support/properties.rs"]
mod properties;

use krb_proto::limits::MAX_NAME_COMPONENTS;
use krb_proto::{KerberosString, PrincipalName, Realm};
use libfuzzer_sys::fuzz_target;
use principal_names::{NameContext, PrincipalClass, PrincipalNames};

/// The classes octet 1 selects among. Spec: docs/59 §4.3.
const CLASSES: [PrincipalClass; 6] = [
    PrincipalClass::User,
    PrincipalClass::Computer,
    PrincipalClass::DomainController,
    PrincipalClass::ProvisionedService,
    PrincipalClass::TicketGrantingService,
    PrincipalClass::Group,
];

fuzz_target!(|data: &[u8]| {
    let [type_octet, class_octet, rest @ ..] = data else {
        return;
    };
    let ctx = NameContext::new("example.test").expect("the test realm's DNS name");
    let mut pieces = rest.split(|octet| *octet == 0xFF);
    let Ok(realm) = Realm::from_bytes(pieces.next().unwrap_or(&[])) else {
        return;
    };
    let pieces: Vec<&[u8]> = pieces.take(MAX_NAME_COMPONENTS).collect();

    // The request side.
    let name_string: Option<Vec<KerberosString>> = pieces
        .iter()
        .map(|piece| KerberosString::from_bytes(piece).ok())
        .collect();
    if let Some(name_string) = name_string {
        let name = PrincipalName {
            name_type: i32::from(i8::from_ne_bytes([*type_octet])),
            name_string,
        };
        properties::check_request(&name, &realm, &ctx);
    }

    // The write side, against the request side.
    let text = |i: usize| pieces.get(i).and_then(|p| core::str::from_utf8(p).ok());
    let class = CLASSES[usize::from(*class_octet) % CLASSES.len()];
    if let Some(sam) = text(0) {
        let names = PrincipalNames {
            class,
            sam_account_name: sam,
            user_principal_name: text(1).filter(|s| !s.is_empty()),
            service_principal_names: text(2).filter(|s| !s.is_empty()).into_iter().collect(),
            dns_host_name: text(3).filter(|s| !s.is_empty()),
        };
        let alias = Realm::new("EXAMPLE.TEST").expect("the test realm");
        properties::check_stored(&names, &alias, &ctx);
    }
});
