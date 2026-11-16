//! The principal namespace of a test store written beneath the one checker
//! (task PN4b; docs/59 §5.1, §5.5; docs/questions/Q-1026 item 5, Q-1031).
//!
//! In the product a principal's namespace keys (`PRINCIPAL_NAME_KEY`) are
//! written only by crates/directory-admin's one checker, which derives them
//! with `principal_names::keys_of_names` from the object's stored names
//! (docs/59 N7), and `Provisioning::begin` marks the store whose every
//! principal got them (`principal-namespace`, Q-1008 item 5). A test fixture
//! that writes objects through dirstore directly writes beneath the checker,
//! so its store holds neither — and since the one lookup path probes only
//! the namespace's index (task PN4b), no principal of such a store could be
//! found by name. This module is the ONE helper the fixture crates share
//! (crates/directory-pip tests/common, crates/directory-daemon
//! tests/support — reused by kdc-daemon, admin-daemon, ldap-front and
//! e2e-tests — crates/directory-admin tests/common and crates/ldap's search
//! tests, each through `#[path]`), so that their stores hold exactly what
//! the checker would have written:
//!
//! * [`write_namespace_keys`] — for objects created in a write transaction:
//!   each principal's keys are `DirectoryView::principal_keys` of the object
//!   as the transaction holds it — `keys_of_names` of its stored names, with
//!   its class from authoritative data, the context's provisioned service
//!   objects and the context's realm (crates/directory-pip `principal.rs`),
//!   the derivation the lookup re-checks (docs/59 §6.1 step 3) — written as
//!   its `PRINCIPAL_NAME_KEY` values in the same transaction under the
//!   create's own stamp, as the checker writes them with the create. Never a
//!   hand-written key.
//! * [`create_namespace_marker`] — the marker counter, with the name and the
//!   one-value range of crates/directory-admin `PRINCIPAL_NAMESPACE_COUNTER`,
//!   `_FIRST`, `_END_EXCLUSIVE` ([`NAMESPACE_MARKER`]: those constants are
//!   not reachable from every crate that reuses this module; pinned equal
//!   to them by crates/directory-admin tests/common, whose fixture runs in
//!   every directory-admin test).
//!
//! An object the checker would refuse — the namespace refuses one of its
//! names, or its record is inconsistent — has no keys to write: the helper
//! panics, naming it. A fixture that means to hold such an object (to test
//! what a record written beneath the checker does) writes it without keys,
//! explicitly.
//!
//! Source: docs/59 §4.3, §4.6, §5.1, §5.5, §6.1; docs/questions/Q-1008 item
//! 5, Q-1026 items 4-5, Q-1029 items 1, 7, Q-1031 (A-178, A-179). Test-only;
//! this project's own code, no other implementation consulted.
#![allow(dead_code)] // each including test binary uses a different subset

use directory_pip::{DirectoryContext, TierMap};
use dirstore::{AttributeChange, Origin, Store, WriteTxn};
use dtyp::Guid;

/// The `principal-namespace` marker: `(name, first, end_exclusive)` — a
/// named counter whose one value is never taken (crates/directory-admin
/// `config.rs`; docs/questions/Q-1029 item 7).
/// Spec: docs/59 §5.2 (c), §5.5; docs/questions/Q-1008 item 5 (A-173).
pub const NAMESPACE_MARKER: (&str, u64, u64) = ("principal-namespace", 1, 2);

/// Create the `principal-namespace` marker in `txn` (module documentation).
/// Spec: docs/59 §5.5; docs/questions/Q-1008 item 5, Q-1031.
pub fn create_namespace_marker(txn: &mut WriteTxn<'_>) {
    let (name, first, end_exclusive) = NAMESPACE_MARKER;
    txn.create_counter(name, first, end_exclusive)
        .expect("the principal-namespace marker");
}

/// Write the namespace keys of every principal among `created` — objects
/// created in `txn`, each with the origin given — as its `PRINCIPAL_NAME_KEY`
/// values (module documentation): `principal_keys` of the object as `txn`
/// holds it, in `ctx`'s realm, with `ctx`'s provisioned service objects. An
/// object that is not a security principal holds none. Panics if a
/// principal's names or record give no keys, or if a key is another
/// object's (the union index refuses it — a store the checker cannot write).
/// Spec: docs/59 §4.3, §5.1 (N7), §6.1 step 3; docs/questions/Q-1026 item 5.
pub fn write_namespace_keys(
    store: &Store,
    txn: &mut WriteTxn<'_>,
    ctx: &DirectoryContext,
    created: &[(Guid, Origin)],
) {
    let tiers = TierMap::empty();
    // The view only lends the derivation its schema and context: the object
    // itself is read from `txn`, which sees this transaction's creates.
    let view = ctx.view(store, &tiers).expect("view");
    for (guid, origin) in created {
        let object = txn
            .get_object(*guid)
            .expect("store")
            .expect("an object created in this transaction");
        let keys = match view.principal_keys(&object, ctx.service_objects()) {
            Ok(Some(keys)) => keys,
            Ok(None) => continue,
            Err(e) => panic!(
                "{guid:?}: the one checker would refuse this principal ({e}); \
                 write it without namespace keys explicitly"
            ),
        };
        txn.modify_object(
            *guid,
            vec![AttributeChange::Replace {
                id: ad_schema::PRINCIPAL_NAME_KEY,
                values: keys.keys().map(|k| k.as_bytes().to_vec()).collect(),
            }],
            origin,
        )
        .unwrap_or_else(|e| panic!("{guid:?}: namespace keys refused: {e:?}"));
    }
}
