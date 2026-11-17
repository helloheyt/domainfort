//! The lookup side: the one key a request's name probes.
//!
//! `key_of_request` turns a principal name and realm received in a request
//! (attacker-supplied: already decoded and bounded by krb-proto, but
//! otherwise untrusted) into at most one probe of the namespace index —
//! never a chain of probes through separate name spaces (class C31,
//! docs/59 §3 M1). The name-type is ignored: "It is not significant when
//! checking for equivalence" (RFC 4120 §6.2).
//!
//! | the request (any name-type) | result |
//! |---|---|
//! | a realm that is not a realm alias (compared folded) | [`RequestKey::Foreign`] |
//! | two components, the first "krbtgt" (folded) | [`RequestKey::LocalTgs`] if the second is a realm alias, else [`RequestKey::Foreign`] |
//! | one component without "@" | `Key(fold(c))` |
//! | one component with exactly one "@" | `Key(fold(local))` if the suffix is a realm alias |
//! | two or three components, none empty, none holding "/" or "@" | `Key(fold(c0 "/" c1 ["/" c2]))` |
//! | anything else | [`RequestKey::NoSuchPrincipal`] |
//!
//! And a `Key` never names the krbtgt account: a key whose initial
//! component is "krbtgt" (`KRBTGT`, `krbtgt@<realm>`, `krbtgt/a/b`) or that
//! equals a realm alias is [`RequestKey::NoSuchPrincipal`] — the only way to
//! the TGS is [`RequestKey::LocalTgs`] (RFC 4120 §6.2 "reserved", §7.3;
//! docs/59 §4.2: "`krbtgt/X` never reaches the index").
//!
//! A suffix that is not a realm alias is "no such principal", where
//! [MS-DRSR] 4.1.4.2.22 would take the part before the "@" whatever the
//! domain — a deliberate, stricter deviation (Q-1007 item 3, decided
//! A-173). A request key is at most [`crate::MAX_KEY_OCTETS`] octets: a
//! longer name cannot be a stored key, so it is "no such principal" before
//! anything is allocated.
//!
//! The probe and what is accepted from the object it finds (the kinds a
//! lookup context takes, the phase-1 octet-for-octet acceptance of R47-1)
//! are the lookup's (docs/59 §6, task PN4); this function decides only
//! which key, if any, is probed.
//!
//! Spec: docs/59 §4.2 (the request table); docs/questions/Q-1007 items 2,
//! 3, 5, 9; [MS-KILE] 3.1.5.7, 3.3.5.1.1 (server lookup: `krbtgt/X`;
//! KerberosString[0] + "/" + the rest), 3.3.5.6.1 (client lookup: cname,
//! cname + "$", cname@realm; NT-ENTERPRISE UPNClientName before the "@");
//! [MS-ADTS] 2.2.21 ("either two parts or three parts"); [MS-DRSR]
//! 4.1.4.2.22; RFC 4120 §6.2, §7.3.

use crate::context::NameContext;
use crate::key::{folded_eq, PrincipalKey, MAX_KEY_COMPONENTS, UPN_SEPARATOR};
use crate::reserved::{is_tgs_name, TGS_NAME};
use krb_proto::{KerberosString, PrincipalName, Realm};

/// What a request's name probes (module documentation).
/// Spec: docs/59 §4.2 (`RequestKey`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestKey {
    /// The realm (or the realm a `krbtgt/X` name names) is not one of this
    /// realm's aliases: the cross-realm path (phase 7) — "no such principal"
    /// in phase 1. Spec: docs/59 §4.2; [MS-KILE] 3.3.5.6.1 ("If the realm
    /// field is not present in the request or is the DC's domain name").
    Foreign,
    /// `krbtgt/<alias>`: the local ticket-granting service — the krbtgt
    /// account, never through the index. Spec: RFC 4120 §7.3; [MS-KILE]
    /// 3.3.5.1.1 step 1; docs/59 §4.2.
    LocalTgs,
    /// The one key to probe. Spec: docs/59 §4.2, §6.1 step 2.
    Key(PrincipalKey),
    /// No object can hold this name. Spec: docs/59 §4.2 ("every other
    /// form").
    NoSuchPrincipal,
}

/// The key the request name `name` in realm `realm` probes (module
/// documentation). Total and panic-free on every input.
/// Spec: docs/59 §4.2; RFC 4120 §6.2; [MS-KILE] 3.1.5.7, 3.3.5.1.1,
/// 3.3.5.6.1; [MS-ADTS] 2.2.21; Q-1007 items 2, 3, 5.
#[must_use]
pub fn key_of_request(name: &PrincipalName, realm: &Realm, ctx: &NameContext) -> RequestKey {
    if !ctx.is_realm_alias(realm.as_str()) {
        return RequestKey::Foreign;
    }
    let key = match name.name_string.as_slice() {
        [] => return RequestKey::NoSuchPrincipal,
        [first, instance] if folded_eq(TGS_NAME, first.as_str()) => {
            return if ctx.is_realm_alias(instance.as_str()) {
                RequestKey::LocalTgs
            } else {
                RequestKey::Foreign
            };
        }
        [only] => one_component(only.as_str(), ctx),
        parts if parts.len() <= MAX_KEY_COMPONENTS => service_form(parts),
        _ => None,
    };
    match key {
        Some(key) if !is_tgs_name(key.first_component()) && !ctx.is_alias_key(&key) => {
            RequestKey::Key(key)
        }
        _ => RequestKey::NoSuchPrincipal,
    }
}

/// The key of a one-component name: the component itself, or — with
/// exactly one "@" — its local part when the suffix is a realm alias.
/// Spec: [MS-KILE] 3.3.5.6.1 (NT-PRINCIPAL steps 1-3, NT-ENTERPRISE steps
/// 1-5); Q-1007 items 2-3; docs/59 §4.2.
fn one_component(component: &str, ctx: &NameContext) -> Option<PrincipalKey> {
    match component.split_once(UPN_SEPARATOR) {
        None => PrincipalKey::of_components(&[component]).ok(),
        Some((local, suffix)) => {
            if ctx.is_realm_alias(suffix) {
                PrincipalKey::of_components(&[local]).ok()
            } else {
                None
            }
        }
    }
}

/// The key of a two- or three-component name: the components joined with
/// "/" (each non-empty, without "/" or "@").
/// Spec: [MS-KILE] 3.3.5.1.1 ("KerberosString[0] + "/" + the concatenation
/// of the remaining KerberosString elements in order"); [MS-ADTS] 2.2.21;
/// docs/59 §4.2; Q-1007 item 5.
fn service_form(parts: &[KerberosString]) -> Option<PrincipalKey> {
    let mut components = [""; MAX_KEY_COMPONENTS];
    for (slot, part) in components.iter_mut().zip(parts) {
        *slot = part.as_str();
    }
    let components = components.get(..parts.len())?;
    PrincipalKey::of_components(components).ok()
}
