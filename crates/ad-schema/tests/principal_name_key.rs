//! The internal principal-name key (task PN2) in a real (temporary)
//! dirstore: uniqueness over the union of every object's names, set
//! semantics on one object, release with the holder, bounds and holders.
//!
//! Source: docs/59 §4.1 (one namespace; one object can hold one key through
//! two names, and the key set stores it once), §4.4 N1 (all keys of all
//! objects distinct), §4.6 (the attribute), §5.4 (a name change removes and
//! adds keys in the same commit), §10.1 (the attack shapes: a computer
//! `dc$` beside a user `dc`; a UPN `bob@realm` beside another object's
//! sAMAccountName `bob`); docs/questions/Q-1008 items 1-2 (A-173: unique,
//! released with the tombstone; "a value ≤ 2048 octets"); docs/46 §5.4
//! (sAMAccountName rangeLower 1 — no name is empty), §8.5; RFC 4120 §6.2
//! ("Ignoring the name type, no two names can be the same"); [MS-SAMR]
//! v20260427 3.1.1.8.4 item 2 (sAMAccountName unique "with respect to the
//! union of all sAMAccountName and msDS-AdditionalSamAccountName attribute
//! values for all other objects"); dirstore's documented store contract
//! (`WriteTxn::create_object` / `modify_object` / `delete_object`,
//! `Snapshot::lookup_unique`). The keys are written here by hand in the
//! folded form crate `principal-names` gives them (docs/59 §4.2) — this
//! project's own test data; nothing computes or writes keys yet (tasks PN1,
//! PN5).

mod common;

use ad_schema::{PRINCIPAL_NAME_KEY, PRINCIPAL_NAME_KEY_MAX_OCTETS};
use common::*;
use dirstore::{AttributeChange, Error, NewObject, Violation};
use dtyp::Guid;

/// `obj` with these principal-name keys. The internal attribute has no
/// lDAPDisplayName, so it is added by its id.
fn with_keys(mut obj: NewObject, keys: &[&[u8]]) -> NewObject {
    obj.attributes.push((
        PRINCIPAL_NAME_KEY,
        keys.iter().map(|k| k.to_vec()).collect(),
    ));
    obj
}

/// The live object holding `key`, by the store's unique index.
fn holder(f: &Fixture, key: &[u8]) -> Option<Guid> {
    f.store
        .snapshot()
        .unwrap()
        .lookup_unique(PRINCIPAL_NAME_KEY, key)
        .unwrap()
}

/// `true` if `result` is the store's refusal of a key another live object
/// holds.
fn key_taken(result: Result<(), Error>) -> bool {
    matches!(result, Err(Error::ValueNotUnique(a)) if a == PRINCIPAL_NAME_KEY)
}

/// A Replace of the object's keys.
fn replace_keys(keys: &[&[u8]]) -> AttributeChange {
    AttributeChange::Replace {
        id: PRINCIPAL_NAME_KEY,
        values: keys.iter().map(|k| k.to_vec()).collect(),
    }
}

#[test]
fn keys_are_unique_over_the_union_of_names() {
    // Each refused object below has names that every per-attribute unique
    // index (sAMAccountName, userPrincipalName) accepts — the collision is
    // between names of different attributes, so only the one key attribute
    // can see it (docs/59 §4.4 N1, §10.1; Q-1008 item 1).
    let f = Fixture::new("pnk-union");
    f.tree();
    f.create(with_keys(f.user(10, guid(2), "dc", &[]), &[b"dc"]))
        .unwrap();
    f.create(with_keys(f.user(11, guid(2), "bob", &[]), &[b"bob"]))
        .unwrap();
    f.create(with_keys(f.group(12, guid(2), "staff", &[]), &[b"staff"]))
        .unwrap();
    // A computer `dc$` beside the user `dc`: its base-name key `dc` is the
    // user's sAMAccountName key.
    let obj = with_keys(f.computer(20, guid(2), "dc$", &[]), &[b"dc$", b"dc"]);
    assert!(key_taken(f.create(obj)));
    // A user whose UPN local part is another user's sAMAccountName.
    let upn = |v: &[u8]| ("userPrincipalName", vec![v.to_vec()]);
    let obj = with_keys(
        f.user(21, guid(2), "carol", &[upn(b"bob@example.test")]),
        &[b"carol", b"bob"],
    );
    assert!(key_taken(f.create(obj)));
    // A computer whose base name is a group's sAMAccountName.
    let obj = with_keys(
        f.computer(22, guid(2), "staff$", &[]),
        &[b"staff$", b"staff"],
    );
    assert!(key_taken(f.create(obj)));
    // Nothing of a refused object was written; each key names its holder.
    {
        let snap = f.store.snapshot().unwrap();
        for n in [20, 21, 22] {
            assert!(snap.get_object(guid(n)).unwrap().is_none(), "object {n}");
        }
    }
    assert_eq!(holder(&f, b"dc"), Some(guid(10)));
    assert_eq!(holder(&f, b"bob"), Some(guid(11)));
    assert_eq!(holder(&f, b"staff"), Some(guid(12)));
    assert_eq!(holder(&f, b"dc$"), None);
    // Within one write transaction too: the second of two creations that
    // take one key is refused before the commit, and the first commits.
    let mut txn = f.store.begin_write().unwrap();
    txn.create_object(
        with_keys(f.user(30, guid(3), "erin", &[]), &[b"erin"]),
        &f.origin(),
    )
    .unwrap();
    let second = txn.create_object(
        with_keys(f.computer(31, guid(3), "erin$", &[]), &[b"erin$", b"erin"]),
        &f.origin(),
    );
    assert!(key_taken(second));
    txn.commit().unwrap();
    assert_eq!(holder(&f, b"erin"), Some(guid(30)));
    assert_eq!(holder(&f, b"erin$"), None);
    // Control: free keys are accepted — a computer's account and base name,
    // and a user whose sAMAccountName and UPN local part give one key.
    f.create(with_keys(
        f.computer(23, guid(2), "ws01$", &[]),
        &[b"ws01$", b"ws01"],
    ))
    .unwrap();
    f.create(with_keys(
        f.user(24, guid(2), "dave", &[upn(b"dave@example.test")]),
        &[b"dave"],
    ))
    .unwrap();
    assert_eq!(holder(&f, b"ws01"), Some(guid(23)));
    assert_eq!(holder(&f, b"dave"), Some(guid(24)));
}

#[test]
fn the_store_compares_keys_by_their_octets() {
    // The attribute is OctetString, so the store's comparison key is the
    // octets themselves (dirstore `comparison::unique_key`: "the raw bytes
    // for every other syntax" than Utf8String; docs/59 §4.6: "OctetString =
    // the bytes — already folded"); the namespace's fold is crate `principal-names`'
    // (docs/59 §4.2; Q-1008 items 1, 4), applied by the one writer before
    // the store sees a key (docs/59 §5.1, N7). So `bob` and `BOB` are two
    // keys to the store — pinned here so that changing the syntax is a
    // visible decision.
    let f = Fixture::new("pnk-octets");
    f.tree();
    f.create(with_keys(f.user(10, guid(2), "bob", &[]), &[b"bob"]))
        .unwrap();
    f.create(with_keys(
        f.user(11, guid(2), "robert", &[]),
        &[b"robert", b"BOB"],
    ))
    .unwrap();
    assert_eq!(holder(&f, b"bob"), Some(guid(10)));
    assert_eq!(holder(&f, b"BOB"), Some(guid(11)));
    assert_eq!(holder(&f, b"Bob"), None);
}

#[test]
fn one_object_holds_each_key_once() {
    // Values are a set: a repeated value in one write is refused, not
    // merged (dirstore `DuplicateValue`) — so the writer stores a key
    // reached through two names once (docs/59 §4.1), and an object's own
    // key never collides with itself.
    let f = Fixture::new("pnk-set");
    f.tree();
    let upn = ("userPrincipalName", vec![b"bob@example.test".to_vec()]);
    let obj = with_keys(
        f.user(10, guid(2), "bob", std::slice::from_ref(&upn)),
        &[b"bob", b"bob"],
    );
    assert_eq!(
        f.refused(obj),
        Violation::DuplicateValue(PRINCIPAL_NAME_KEY)
    );
    // sAMAccountName `bob` and the UPN local part `bob`: one key, once.
    f.create(with_keys(f.user(10, guid(2), "bob", &[upn]), &[b"bob"]))
        .unwrap();
    // A repeat in a modify is refused too.
    let mut txn = f.store.begin_write().unwrap();
    let repeat = txn.modify_object(guid(10), vec![replace_keys(&[b"bob", b"bob"])], &f.origin());
    assert!(matches!(
        repeat,
        Err(Error::Rejected(Violation::DuplicateValue(a))) if a == PRINCIPAL_NAME_KEY
    ));
    txn.abort().unwrap();
    // Keeping its own key and adding another: no collision with itself.
    let mut txn = f.store.begin_write().unwrap();
    txn.modify_object(
        guid(10),
        vec![replace_keys(&[b"bob", b"robert"])],
        &f.origin(),
    )
    .unwrap();
    txn.commit().unwrap();
    assert_eq!(holder(&f, b"bob"), Some(guid(10)));
    assert_eq!(holder(&f, b"robert"), Some(guid(10)));
    let snap = f.store.snapshot().unwrap();
    let obj = snap.get_object(guid(10)).unwrap().unwrap();
    let keys: Vec<&[u8]> = obj
        .attribute(PRINCIPAL_NAME_KEY)
        .unwrap()
        .values
        .iter()
        .map(|v| v.value.as_slice())
        .collect();
    assert_eq!(keys, vec![&b"bob"[..], &b"robert"[..]]);
}

#[test]
fn a_key_is_released_with_its_name_and_with_its_holder() {
    // Q-1008 item 1: unique entries follow every change in the same commit
    // and go with the tombstone (dirstore `modify_object`, `delete_object`:
    // "its name and unique values are released"); docs/59 §5.4: a name
    // change re-derives the keys and the store removes / adds them in one
    // commit.
    let f = Fixture::new("pnk-release");
    f.tree();
    f.create(with_keys(f.user(10, guid(2), "dc", &[]), &[b"dc"]))
        .unwrap();
    let upn = ("userPrincipalName", vec![b"robert@example.test".to_vec()]);
    f.create(with_keys(
        f.user(11, guid(2), "bob", &[upn]),
        &[b"bob", b"robert"],
    ))
    .unwrap();
    // While held, a key cannot be taken by a modify either.
    f.create(with_keys(f.user(12, guid(2), "rob", &[]), &[b"rob"]))
        .unwrap();
    let mut txn = f.store.begin_write().unwrap();
    let taken = txn.modify_object(
        guid(12),
        vec![replace_keys(&[b"rob", b"robert"])],
        &f.origin(),
    );
    assert!(key_taken(taken));
    txn.abort().unwrap();
    // The UPN removed and its key with it, in one commit: `robert` is free.
    let mut txn = f.store.begin_write().unwrap();
    let upn_id = f.attr("userPrincipalName");
    txn.modify_object(
        guid(11),
        vec![
            AttributeChange::Replace {
                id: upn_id,
                values: vec![],
            },
            replace_keys(&[b"bob"]),
        ],
        &f.origin(),
    )
    .unwrap();
    txn.commit().unwrap();
    assert_eq!(holder(&f, b"robert"), None);
    f.create(with_keys(f.user(13, guid(2), "robert", &[]), &[b"robert"]))
        .unwrap();
    assert_eq!(holder(&f, b"robert"), Some(guid(13)));
    // The holder deleted: its keys go with the tombstone.
    let mut txn = f.store.begin_write().unwrap();
    txn.delete_object(guid(10), &f.origin()).unwrap();
    txn.commit().unwrap();
    assert_eq!(holder(&f, b"dc"), None);
    f.create(with_keys(
        f.computer(20, guid(2), "dc$", &[]),
        &[b"dc$", b"dc"],
    ))
    .unwrap();
    assert_eq!(holder(&f, b"dc"), Some(guid(20)));
}

#[test]
fn key_bounds_and_holder_classes_in_the_store() {
    // Q-1008 item 2 (A-173): a value ≤ 2048 octets; crate `internal`: no
    // empty key (docs/46 §5.4 — a name is never empty); docs/59 §4.3, §4.6:
    // only user, computer and group hold keys.
    let f = Fixture::new("pnk-bounds");
    // An NC root may not hold one.
    let root = f.object(
        1,
        None,
        "domainDNS",
        &[
            ("dc", vec![b"example".to_vec()]),
            ("objectSid", vec![domain_sid()]),
        ],
    );
    assert_eq!(
        f.refused(with_keys(root, &[b"example"])),
        Violation::AttributeNotAllowed(PRINCIPAL_NAME_KEY)
    );
    f.tree();
    // Neither may an organizational unit or a container.
    let ou = f.object(
        4,
        Some(guid(1)),
        "organizationalUnit",
        &[("ou", vec![b"Sales".to_vec()])],
    );
    assert_eq!(
        f.refused(with_keys(ou, &[b"sales"])),
        Violation::AttributeNotAllowed(PRINCIPAL_NAME_KEY)
    );
    let container = f.object(
        5,
        Some(guid(1)),
        "container",
        &[("cn", vec![b"Hosts".to_vec()])],
    );
    assert_eq!(
        f.refused(with_keys(container, &[b"hosts"])),
        Violation::AttributeNotAllowed(PRINCIPAL_NAME_KEY)
    );
    // 2048 octets: accepted; 2049: too large; an empty key: out of range.
    let longest = vec![b'k'; PRINCIPAL_NAME_KEY_MAX_OCTETS];
    f.create(with_keys(
        f.computer(10, guid(2), "ws10$", &[]),
        &[longest.as_slice()],
    ))
    .unwrap();
    assert_eq!(holder(&f, &longest), Some(guid(10)));
    let too_long = vec![b'k'; PRINCIPAL_NAME_KEY_MAX_OCTETS + 1];
    assert_eq!(
        f.refused(with_keys(
            f.computer(11, guid(2), "ws11$", &[]),
            &[too_long.as_slice()]
        )),
        Violation::ValueTooLarge(PRINCIPAL_NAME_KEY)
    );
    assert_eq!(
        f.refused(with_keys(f.computer(11, guid(2), "ws11$", &[]), &[b""])),
        Violation::ValueOutOfRange(PRINCIPAL_NAME_KEY)
    );
}
