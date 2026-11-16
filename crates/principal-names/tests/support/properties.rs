//! The properties of the one equivalence, checked on every input by the
//! deterministic test `tests/one_equivalence.rs` and by the fuzz target
//! `fuzz/fuzz_targets/principal_key_of_request.rs` (both include this file,
//! so the two check the same statement).
//!
//! 1. `key_of_request` is total and panic-free (AGENTS.md §6).
//! 2. The name-type is not significant (RFC 4120 §6.2) and neither is case
//!    ([MS-KILE] 3.1.5.7): every name-type, and the request upper- or
//!    lower-cased (name and realm), give the same outcome.
//! 3. A `Key` is a key's form: non-empty, at most `MAX_KEY_OCTETS`,
//!    printable and its own fold, no "@", one to three non-empty components,
//!    "/" only when the request had more than one component, never the TGS's
//!    reserved name nor a realm alias (docs/59 §4.2).
//! 4. A `Key` is exactly the request's components folded and joined with
//!    "/" — or, for one component `local@alias`, the folded local part: the
//!    docs/59 §4.2 table restated independently, so two requests probe the
//!    same key only if they are the same name after the fold (injectivity).
//! 5. Writer and reader agree (class C49): for every object `keys_of_names`
//!    accepts, each stored name, sent as a request the way a client spells
//!    it, probes exactly the key the object stores for it.
//! 6. The writer and the stored-name reading agree (task PN10c): for every
//!    object `keys_of_names` accepts (but the krbtgt account, whose binding
//!    is the TGS's name), its sAMAccountName and each servicePrincipalName,
//!    in principal-name form (one component; the SPN split at "/"), have
//!    through `key_of_stored_name` exactly the key the object stores for
//!    that name — and its userPrincipalName, a request's spelling only, has
//!    none.
//!
//! Source: docs/59 §4.2, §4.3, §4.4, §7.3, §10.1; RFC 4120 §6.2; [MS-KILE]
//! 3.1.5.7, 3.3.5.1.1, 3.3.5.6.1; Q-1007 items 2, 5; Q-1066 (task PN10c).
//! Test code only; no vector from any other implementation.
#![allow(dead_code)] // each including crate uses a subset

use krb_proto::{KerberosString, PrincipalName, Realm};
use principal_names::{
    fold, key_of_request, key_of_stored_name, keys_of_names, reserved_name_of, KeySet, NameContext,
    NameKind, PrincipalKey, PrincipalNames, RequestKey, ReservedName, MAX_KEY_COMPONENTS,
    MAX_KEY_OCTETS,
};

/// The name-types every request is also tried under (RFC 4120 §6.2 table,
/// an unregistered value, the extremes).
const NAME_TYPES: [i32; 8] = [0, 1, 2, 3, 7, 10, -1, i32::MAX];

/// `s` with its ASCII letters mapped by `f`, as a KerberosString (case
/// changes keep the KerberosString rules).
fn recased(s: &KerberosString, f: fn(&str) -> String) -> KerberosString {
    KerberosString::new(&f(s.as_str())).expect("a case change keeps a KerberosString")
}

/// Properties 1-4 for one request; returns its outcome.
pub fn check_request(name: &PrincipalName, realm: &Realm, ctx: &NameContext) -> RequestKey {
    let outcome = key_of_request(name, realm, ctx);

    // Property 2: name-type and case.
    for name_type in NAME_TYPES {
        let typed = PrincipalName {
            name_type,
            name_string: name.name_string.clone(),
        };
        assert_eq!(
            key_of_request(&typed, realm, ctx),
            outcome,
            "name-type {name_type}"
        );
    }
    for f in [str::to_ascii_uppercase, str::to_ascii_lowercase] {
        let cased = PrincipalName {
            name_type: name.name_type,
            name_string: name.name_string.iter().map(|c| recased(c, f)).collect(),
        };
        assert_eq!(
            key_of_request(&cased, &recased(realm, f), ctx),
            outcome,
            "case of {name:?} @ {realm:?}"
        );
    }

    if let RequestKey::Key(key) = &outcome {
        check_key_form(key);
        check_probe_not_reserved(key, ctx);
        // Property 3: "/" only for a multi-component request.
        assert_eq!(
            key.as_str().contains('/'),
            name.name_string.len() > 1,
            "{name:?}"
        );
        // Property 4: the table, restated.
        assert_eq!(
            Some(key.as_str().to_owned()),
            restated(name, ctx),
            "{name:?}"
        );
    }
    outcome
}

/// Property 3: the form of every key, from either side.
pub fn check_key_form(key: &PrincipalKey) {
    let text = key.as_str();
    assert!(!text.is_empty() && text.len() <= MAX_KEY_OCTETS, "{text:?}");
    assert_eq!(
        fold(text).as_deref(),
        Some(text),
        "not its own fold: {text:?}"
    );
    assert!(!text.contains('@'), "{text:?}");
    let components: Vec<&str> = text.split('/').collect();
    assert!(components.len() <= MAX_KEY_COMPONENTS, "{text:?}");
    assert!(components.iter().all(|c| !c.is_empty()), "{text:?}");
    assert_eq!(key.as_bytes(), text.as_bytes());
}

/// Property 3, request side: a probed key never names the krbtgt account.
fn check_probe_not_reserved(key: &PrincipalKey, ctx: &NameContext) {
    assert_ne!(
        reserved_name_of(key),
        Some(ReservedName::TicketGrantingService),
        "{key:?}"
    );
    assert!(!ctx.is_realm_alias(key.as_str()), "{key:?}");
}

/// The docs/59 §4.2 table's `Key` column, restated without the crate's
/// helpers: one component `local@suffix` ⇒ the lower-cased local part;
/// otherwise the lower-cased components joined with "/".
fn restated(name: &PrincipalName, ctx: &NameContext) -> Option<String> {
    let parts: Vec<&str> = name
        .name_string
        .iter()
        .map(KerberosString::as_str)
        .collect();
    if let [only] = parts.as_slice() {
        if let Some((local, suffix)) = only.split_once('@') {
            assert!(ctx.is_realm_alias(suffix));
            return Some(local.to_ascii_lowercase());
        }
    }
    Some(parts.join("/").to_ascii_lowercase())
}

/// The principal name a client sends for `components` (NT-PRINCIPAL; the
/// name-type is a hint only).
fn request(components: &[&str]) -> Option<PrincipalName> {
    Some(PrincipalName {
        name_type: krb_proto::constants::KRB_NT_PRINCIPAL,
        name_string: components
            .iter()
            .map(|c| KerberosString::new(c).ok())
            .collect::<Option<Vec<_>>>()?,
    })
}

/// Property 6 for one accepted object (module documentation).
fn check_stored_names(names: &PrincipalNames<'_>, keys: &KeySet, ctx: &NameContext) {
    let reads_as = |components: &[&str], kind: NameKind| {
        let Some(name) = request(components) else {
            return;
        };
        match key_of_stored_name(&name, ctx) {
            Ok(key) => assert!(
                keys.kinds_of(&key).contains(kind),
                "{components:?} reads as {key:?}, which carries no {kind:?} in {keys:?}"
            ),
            Err(refused) => panic!("{components:?} ({kind:?}) has no stored key: {refused:?}"),
        }
    };
    reads_as(&[names.sam_account_name], NameKind::SamAccountName);
    for spn in &names.service_principal_names {
        let parts: Vec<&str> = spn.split('/').collect();
        reads_as(&parts, NameKind::ServicePrincipalName);
    }
    if let Some(name) = names.user_principal_name.and_then(|upn| request(&[upn])) {
        assert!(
            key_of_stored_name(&name, ctx).is_err(),
            "a userPrincipalName is no stored binding form: {name:?}"
        );
    }
}

/// Property 5 for one stored name: the request `components` must probe a
/// key of `keys` that carries `kind`.
fn assert_probes(
    keys: &KeySet,
    kind: NameKind,
    components: &[&str],
    realm: &Realm,
    ctx: &NameContext,
) {
    let Some(name) = request(components) else {
        return;
    };
    match check_request(&name, realm, ctx) {
        RequestKey::Key(key) => {
            check_probe_not_reserved(&key, ctx);
            assert!(
                keys.kinds_of(&key).contains(kind),
                "{components:?} probes {key:?}, which carries no {kind:?} in {keys:?}"
            );
        }
        other => panic!("{components:?} ({kind:?}) probes nothing: {other:?}"),
    }
}

/// Properties 3 and 5 for one object: every key it stores is a key's form,
/// and every stored name, sent as a request in `realm` (an alias of
/// `ctx`), probes its own key. Returns the keys, if accepted.
pub fn check_stored(
    names: &PrincipalNames<'_>,
    realm: &Realm,
    ctx: &NameContext,
) -> Option<KeySet> {
    let keys = keys_of_names(names, ctx).ok()?;
    assert!(keys.len() <= principal_names::MAX_KEYS_PER_OBJECT);
    for (key, kinds) in keys.iter() {
        check_key_form(key);
        assert!(!kinds.is_empty());
    }
    if names.class == principal_names::PrincipalClass::TicketGrantingService {
        // Reached only as `krbtgt/<alias>` (docs/59 §4.2).
        let tgs = request(&["krbtgt", realm.as_str()]).expect("TGS name");
        assert_eq!(check_request(&tgs, realm, ctx), RequestKey::LocalTgs);
        return Some(keys);
    }
    check_stored_names(names, &keys, ctx);
    let sam = names.sam_account_name;
    assert_probes(&keys, NameKind::SamAccountName, &[sam], realm, ctx);
    if let Some(base) = sam.strip_suffix('$') {
        assert_probes(&keys, NameKind::ComputerBase, &[base], realm, ctx);
    }
    if let Some(upn) = names.user_principal_name {
        assert_probes(&keys, NameKind::UpnLocal, &[upn], realm, ctx);
    }
    for spn in &names.service_principal_names {
        let parts: Vec<&str> = spn.split('/').collect();
        assert_probes(&keys, NameKind::ServicePrincipalName, &parts, realm, ctx);
    }
    if let Some(host) = names.dns_host_name {
        if names.class != principal_names::PrincipalClass::ProvisionedService {
            assert_probes(&keys, NameKind::HostName, &[host], realm, ctx);
        }
    }
    Some(keys)
}
