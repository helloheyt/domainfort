//! The visibility gate (docs/52 R10, decision A-102): a `VisibleObject` is
//! built only after the PDP allowed the rule's question, and "absent" and
//! "not visible" are one verdict.
//!
//! A compile-fail test would need a new dependency (task U); instead these
//! tests show that the only constructors — `VisibilityGate::visible` and
//! `VisibilityGate::child` — run the check: the same object is visible or
//! not according to the PDP decision alone, a policy that allows nothing
//! yields no `VisibleObject` at all, and an absent identity gets exactly the
//! verdict of a hidden one.
//!
//! The directory (this project's own test data; the SID layout
//! S-1-5-21-1-2-3-<RID> follows the [MS-DTYP] 2.4.2.4 example; no vector or
//! fixture comes from any other implementation):
//!
//! ```text
//! dc=example,dc=test     NC root      staff: LC + RP
//! ├─ ou=Staff                         staff: LC + RP
//! │  ├─ alice (user)                  staff: LC + RP   (the requester)
//! │  ├─ staff (global security group: alice)   staff: LC + RP
//! │  └─ secret (user)                 nothing for staff
//! └─ ou=Vault                         staff: RP only (not listable)
//!    └─ vaulted (user)                staff: LC + RP
//! ```
//!
//! Sources (each test names its own): docs/52 §3.6, §7 (R10); docs/11 §4,
//! §7, §8; docs/49 §6.1 items 2-3, §9 (R49-13); docs/51 §5.2 row 10;
//! [MS-ADTS] v20261026 3.1.1.4.3, 5.1.3.3.6; docs/questions/Q-200 item 5,
//! Q-485 (the admin plane's rule = the LDAP rule and `DirRead`).

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{guid, int64, sid_of, Dir, GLOBAL_SECURITY, WHEN_CREATED};
use directory_pip::{
    hides, DirectoryView, PepView, UnseenCause, Visibility, VisibilityGate, VisibilityRule,
    VisibleObject,
};
use dirstore::{AttrId, NewObject};
use dtyp::{
    AccessMask, Ace, Acl, Control, MaskSidAce, SecurityDescriptor, Sid, ACL_REVISION_DS,
    SECURITY_NT_AUTHORITY,
};
use pdp::access_check::rights::{RIGHT_DS_LIST_CONTENTS, RIGHT_DS_READ_PROPERTY};
use pdp::{
    Action, ActionMatch, AuthContext, AuthMatch, AuthStrength, Context, ContextMatch, Effect,
    Instant, IpScope, Match, Pip, PolicySnapshot, PolicyVersion, ReasonCode, ResourceMatch, Rule,
    RuleId, Subject, SubjectMatch, SubtreeBase, Transport, TransportSec,
};

const ROOT: u32 = 1;
const STAFF_OU: u32 = 2;
const VAULT: u32 = 3;
const ALICE: u32 = 10;
const SECRET: u32 = 11;
const VAULTED: u32 = 12;
const STAFF: u32 = 30;
/// No object has this GUID.
const NOBODY: u32 = 999;

// ------------------------------------------------------------- descriptors --

/// A self-relative descriptor with this DACL ([MS-DTYP] 2.4.6).
fn sd(aces: Vec<Ace>) -> Vec<u8> {
    SecurityDescriptor {
        sbz1: 0,
        control: Control(Control::SELF_RELATIVE | Control::DACL_PRESENT | Control::GROUP_DEFAULTED),
        owner_sid: Some(Sid::new(SECURITY_NT_AUTHORITY, &[18]).unwrap()),
        group_sid: None,
        sacl: None,
        dacl: Some(Acl {
            acl_revision: ACL_REVISION_DS,
            aces,
        }),
    }
    .encode()
    .unwrap()
}

/// ACCESS_ALLOWED_ACE ([MS-DTYP] 2.4.4.2).
fn allow(mask: u32, sid: Sid) -> Ace {
    Ace::AccessAllowed(MaskSidAce {
        ace_flags: 0,
        mask: AccessMask(mask),
        sid,
    })
}

/// The group staff may list and read ([MS-ADTS] 5.1.3.2: LC, RP).
fn open_sd() -> Vec<u8> {
    sd(vec![allow(
        RIGHT_DS_LIST_CONTENTS | RIGHT_DS_READ_PROPERTY,
        sid_of(STAFF),
    )])
}

// --------------------------------------------------------------- directory --

fn object(
    d: &Dir,
    id: u32,
    parent: Option<u32>,
    class: &str,
    descriptor: Vec<u8>,
    attrs: &[(&str, Vec<Vec<u8>>)],
) -> NewObject {
    let mut attributes: Vec<(AttrId, Vec<Vec<u8>>)> =
        attrs.iter().map(|(n, v)| (d.attr(n), v.clone())).collect();
    attributes.push((d.attr("nTSecurityDescriptor"), vec![descriptor]));
    NewObject {
        guid: guid(id),
        parent: parent.map(guid),
        classes: d.p1.class(d.class(class)).unwrap().object_class.clone(),
        attributes,
    }
}

fn user(d: &Dir, id: u32, parent: u32, sam: &str, descriptor: Vec<u8>) -> NewObject {
    object(
        d,
        id,
        Some(parent),
        "user",
        descriptor,
        &[
            ("cn", vec![sam.as_bytes().to_vec()]),
            ("sAMAccountName", vec![sam.as_bytes().to_vec()]),
            ("objectSid", vec![sid_of(id).encode()]),
            ("whenCreated", vec![int64(WHEN_CREATED)]),
        ],
    )
}

/// The directory of the module documentation.
fn directory(test: &str) -> Dir {
    let d = Dir::new(test);
    let objects = vec![
        object(
            &d,
            ROOT,
            None,
            "domainDNS",
            open_sd(),
            &[
                ("dc", vec![b"example".to_vec()]),
                ("objectSid", vec![common::domain_sid().encode()]),
            ],
        ),
        object(
            &d,
            STAFF_OU,
            Some(ROOT),
            "organizationalUnit",
            open_sd(),
            &[("ou", vec![b"Staff".to_vec()])],
        ),
        object(
            &d,
            VAULT,
            Some(ROOT),
            "organizationalUnit",
            sd(vec![allow(RIGHT_DS_READ_PROPERTY, sid_of(STAFF))]),
            &[("ou", vec![b"Vault".to_vec()])],
        ),
        user(&d, ALICE, STAFF_OU, "alice", open_sd()),
        // Granted to someone else only: the requester has no right on it.
        user(
            &d,
            SECRET,
            STAFF_OU,
            "secret",
            sd(vec![allow(
                RIGHT_DS_LIST_CONTENTS | RIGHT_DS_READ_PROPERTY,
                sid_of(ALICE + 1000),
            )]),
        ),
        user(&d, VAULTED, VAULT, "vaulted", open_sd()),
        object(
            &d,
            STAFF,
            Some(STAFF_OU),
            "group",
            open_sd(),
            &[
                ("cn", vec![b"staff".to_vec()]),
                ("sAMAccountName", vec![b"staff".to_vec()]),
                ("objectSid", vec![sid_of(STAFF).encode()]),
                ("groupType", vec![GLOBAL_SECURITY.to_be_bytes().to_vec()]),
                ("member", vec![guid(ALICE).to_packet().to_vec()]),
            ],
        ),
    ];
    d.create_all(objects);
    d
}

// ------------------------------------------------------- policy & requester --

/// Allow DirRead and DirList on the naming context's subtree (docs/11 §3).
fn allow_reads() -> PolicySnapshot {
    PolicySnapshot::new(
        PolicyVersion(1),
        vec![Rule {
            id: RuleId(1),
            effect: Effect::Allow,
            when: Match {
                action: ActionMatch::AnyOf(vec![Action::DirRead, Action::DirList]),
                resource: ResourceMatch::DirSubtree {
                    base: SubtreeBase::new(common::naming_context().dn().clone()).unwrap(),
                },
                subject: SubjectMatch::Any,
                context: ContextMatch::ANY,
                auth: AuthMatch::ANY,
            },
            obligations: vec![],
        }],
        vec![],
    )
}

/// No rule at all: deny by default (docs/11 §3, P2).
fn allow_nothing() -> PolicySnapshot {
    PolicySnapshot::new(PolicyVersion(1), vec![], vec![])
}

/// alice, from a verified ticket (docs/11 P3), her tier from the PIP.
fn alice(view: &DirectoryView<'_>) -> Subject {
    let groups = BTreeSet::from([sid_of(STAFF)]);
    let tier = view.tier_of(&sid_of(ALICE), &groups).unwrap();
    Subject {
        principal: sid_of(ALICE),
        groups,
        claims: BTreeMap::new(),
        auth: AuthContext {
            strength: AuthStrength::Kerberos,
            armored: false,
            ticket_age: core::time::Duration::ZERO,
            ticket_verified: true,
        },
        tier,
    }
}

/// An LDAPS context; `encrypted` false makes every read fail layer 2
/// (pdp `required_sec`: an authenticated read needs `{encrypted}`).
fn context(encrypted: bool) -> Context {
    Context {
        src_net: IpScope::Internal,
        time: Instant(1_794_564_000),
        transport: Transport::Ldaps,
        transport_sec: TransportSec {
            encrypted,
            sealed: false,
            channel_bound: false,
        },
    }
}

fn gate<'v, 'a>(
    view: &'v DirectoryView<'a>,
    policy: &'v PolicySnapshot,
    rule: VisibilityRule,
) -> VisibilityGate<'v, 'a> {
    VisibilityGate::new(view, policy, alice(view), context(true), rule)
}

/// The visible object, or a panic naming the verdict.
fn seen<'v>(verdict: Visibility<'v>) -> VisibleObject<'v> {
    match verdict {
        Visibility::Visible { object, decision } => {
            assert_eq!(decision.effect, Effect::Allow);
            object
        }
        other => panic!("not visible: {other:?}"),
    }
}

/// The cause of a not-found verdict, or a panic naming the verdict.
fn unseen(verdict: Visibility<'_>) -> UnseenCause {
    match verdict {
        Visibility::NotFound(unseen) => unseen.audit_cause(),
        other => panic!("not a not-found verdict: {other:?}"),
    }
}

// ------------------------------------------------------------------- tests --

/// docs/52 R10 + A-55 (docs/11 §7-§8; docs/49 §9 R49-13): under
/// `ListParent`, an object whose parent may not be listed and an identity
/// nobody has get the same variant; only the audit-only cause differs.
#[test]
fn absent_and_hidden_are_one_verdict() {
    let d = directory("gate-one-verdict");
    let view = d.view();
    let policy = allow_reads();
    let mut g = gate(&view, &policy, VisibilityRule::ListParent);
    assert_eq!(
        unseen(g.visible(guid(VAULTED)).unwrap()),
        UnseenCause::Hidden(ReasonCode::Acl)
    );
    assert_eq!(
        unseen(g.visible(guid(NOBODY)).unwrap()),
        UnseenCause::Absent
    );
    let mut g = gate(&view, &policy, VisibilityRule::ListAndRead);
    for hidden in [SECRET, VAULTED] {
        assert_eq!(
            unseen(g.visible(guid(hidden)).unwrap()),
            UnseenCause::Hidden(ReasonCode::Acl)
        );
    }
    assert_eq!(
        unseen(g.visible(guid(NOBODY)).unwrap()),
        UnseenCause::Absent
    );
}

/// The only constructor runs the check (docs/52 R10): the same view and the
/// same requester, two policies — every object of the directory is visible
/// or not according to the PDP decision alone, and a policy that allows
/// nothing (deny by default, docs/11 P2) yields no `VisibleObject` at all,
/// under either rule.
#[test]
fn a_visible_object_exists_only_after_an_allow() {
    let d = directory("gate-only-after-allow");
    let view = d.view();
    let all = [ROOT, STAFF_OU, VAULT, ALICE, SECRET, VAULTED, STAFF];
    let denied = allow_nothing();
    for rule in [VisibilityRule::ListParent, VisibilityRule::ListAndRead] {
        let mut g = gate(&view, &denied, rule);
        for id in all {
            assert_eq!(
                unseen(g.visible(guid(id)).unwrap()),
                UnseenCause::Hidden(ReasonCode::NoGrant),
                "{rule:?} {id}"
            );
        }
    }
    let allowed = allow_reads();
    let mut g = gate(&view, &allowed, VisibilityRule::ListParent);
    for id in [ROOT, STAFF_OU, VAULT, ALICE, SECRET, STAFF] {
        let object = seen(g.visible(guid(id)).unwrap());
        assert_eq!(object.guid(), guid(id));
        assert_eq!(Some(object.dn().clone()), view.dn_of(guid(id)).unwrap());
    }
}

/// [MS-ADTS] 5.1.3.3.6 ("If a user is granted the RIGHT_DS_LIST_CONTENTS
/// access right on a container, all child objects of that container are
/// visible to the user"; otherwise none is) and pdp `decide_visibility`
/// (the NC root decides on itself): under `ListParent` secret is visible
/// though its own descriptor grants nothing, vaulted is not though its own
/// descriptor grants everything, and the NC root is visible by its own LC.
#[test]
fn list_parent_is_the_parents_list_right() {
    let d = directory("gate-list-parent");
    let view = d.view();
    let policy = allow_reads();
    let mut g = gate(&view, &policy, VisibilityRule::ListParent);
    assert!(seen(g.visible(guid(ROOT)).unwrap()).is_nc_root());
    assert!(!seen(g.visible(guid(SECRET)).unwrap()).is_nc_root());
    assert!(matches!(
        g.visible(guid(VAULTED)).unwrap(),
        Visibility::NotFound(_)
    ));
    assert_eq!(g.rule(), VisibilityRule::ListParent);
}

/// docs/questions/Q-485 (decided): the admin plane's rule is [MS-ADTS]
/// 5.1.3.3.6 **and** `DirRead` on the whole object (docs/51 §5.2 row 10).
/// vaulted — readable, but under a container the requester may not list —
/// is NotFound, exactly as the LDAP search hides it; secret — under a
/// listable container, but not readable — is NotFound too; every object
/// visible under `ListAndRead` is visible under `ListParent`.
#[test]
fn list_and_read_needs_both_questions() {
    let d = directory("gate-list-and-read");
    let view = d.view();
    let policy = allow_reads();
    let mut admin = gate(&view, &policy, VisibilityRule::ListAndRead);
    let mut ldap = gate(&view, &policy, VisibilityRule::ListParent);
    assert_eq!(
        unseen(admin.visible(guid(VAULTED)).unwrap()),
        UnseenCause::Hidden(ReasonCode::Acl)
    );
    assert!(matches!(
        ldap.visible(guid(VAULTED)).unwrap(),
        Visibility::NotFound(_)
    ));
    assert_eq!(
        unseen(admin.visible(guid(SECRET)).unwrap()),
        UnseenCause::Hidden(ReasonCode::Acl)
    );
    for id in [ROOT, STAFF_OU, VAULT, ALICE, SECRET, VAULTED, STAFF, NOBODY] {
        if let Visibility::Visible { decision, .. } = admin.visible(guid(id)).unwrap() {
            assert_eq!(decision.effect, Effect::Allow);
            seen(ldap.visible(guid(id)).unwrap());
        }
    }
    seen(admin.visible(guid(ALICE)).unwrap());
    assert!(seen(admin.visible(guid(ROOT)).unwrap()).is_nc_root());
}

/// [MS-ADTS] 5.1.3.3.6 and 3.1.1.1.4 (a child's DN is its RDN followed by
/// the parent's DN); docs/49 §6.1 item 3: `child` gives a child of a
/// listable container its DN; a child of a container that may not be
/// listed is not found; an object that is not a child of the container,
/// and an identity nobody has, are not found either.
#[test]
fn child_follows_the_parents_listing() {
    let d = directory("gate-child-list");
    let view = d.view();
    let policy = allow_reads();
    let mut g = gate(&view, &policy, VisibilityRule::ListParent);
    let staff = seen(g.visible(guid(STAFF_OU)).unwrap());
    let vault = seen(g.visible(guid(VAULT)).unwrap());
    let alice = seen(g.child(&staff, guid(ALICE)).unwrap());
    assert_eq!(alice.dn(), &view.dn_of(guid(ALICE)).unwrap().unwrap());
    assert_eq!(
        alice.dn().rdns(),
        ["cn=alice", "ou=Staff", "dc=example", "dc=test"]
    );
    seen(g.child(&staff, guid(SECRET)).unwrap());
    assert_eq!(
        unseen(g.child(&vault, guid(VAULTED)).unwrap()),
        UnseenCause::Hidden(ReasonCode::Acl)
    );
    assert_eq!(
        unseen(g.child(&staff, guid(VAULTED)).unwrap()),
        UnseenCause::Absent
    );
    assert_eq!(
        unseen(g.child(&staff, guid(NOBODY)).unwrap()),
        UnseenCause::Absent
    );
    assert!(g.may_list(staff.dn()));
    assert!(!g.may_list(vault.dn()));
}

/// docs/questions/Q-485; [MS-ADTS] 5.1.3.3.6; docs/51 §5.2 row 10: under
/// `ListAndRead` a child needs its parent's listing and its own read right.
#[test]
fn child_under_list_and_read_needs_both() {
    let d = directory("gate-child-list-read");
    let view = d.view();
    let policy = allow_reads();
    let mut g = gate(&view, &policy, VisibilityRule::ListAndRead);
    let staff = seen(g.visible(guid(STAFF_OU)).unwrap());
    let vault = seen(g.visible(guid(VAULT)).unwrap());
    assert_eq!(
        unseen(g.child(&vault, guid(VAULTED)).unwrap()),
        UnseenCause::Hidden(ReasonCode::Acl)
    );
    seen(g.child(&staff, guid(ALICE)).unwrap());
    assert_eq!(
        unseen(g.child(&staff, guid(SECRET)).unwrap()),
        UnseenCause::Hidden(ReasonCode::Acl)
    );
}

/// docs/questions/Q-200 item 5 (A-55) and docs/11 §4 (layer 2 precedes the
/// object): a refusal that does not depend on the object is reported
/// before any lookup — `request_refusal` — and on an object it is
/// `Refused`, never `NotFound`; with the transport floor met, or with a
/// denial that hides the NC root, there is no request refusal.
#[test]
fn a_request_level_refusal_comes_first() {
    let d = directory("gate-request-refusal");
    let view = d.view();
    let policy = allow_reads();
    let mut weak = VisibilityGate::new(
        &view,
        &policy,
        alice(&view),
        context(false),
        VisibilityRule::ListParent,
    );
    let refusal = weak.request_refusal().expect("a request-level refusal");
    assert_eq!(refusal.reason, ReasonCode::WeakTransport);
    match weak.visible(guid(ALICE)).unwrap() {
        Visibility::Refused(decision) => assert_eq!(decision.reason, ReasonCode::WeakTransport),
        other => panic!("{other:?}"),
    }
    for rule in [VisibilityRule::ListParent, VisibilityRule::ListAndRead] {
        assert_eq!(gate(&view, &policy, rule).request_refusal(), None);
        let nothing = allow_nothing();
        assert_eq!(gate(&view, &nothing, rule).request_refusal(), None);
    }
}

/// docs/49 §9 (R49-13: a PDP Deny on an invisible target → noSuchObject;
/// `PipFailure` / `InvalidRequest` / `SubjectMismatch` → other; layer 1 →
/// operationsError; layer 2 → 13 / 8) and docs/11 §4: exactly the reasons
/// of the layers that read the resource hide it.
#[test]
fn hides_is_exactly_the_object_dependent_reasons() {
    for reason in [
        ReasonCode::CoarseDeny(RuleId(7)),
        ReasonCode::NoGrant,
        ReasonCode::TierViolation,
        ReasonCode::Acl,
        ReasonCode::NoSuchPath,
        ReasonCode::Sensitive,
    ] {
        assert!(hides(reason), "{reason:?}");
    }
    for reason in [
        ReasonCode::Allowed,
        ReasonCode::InvalidRequest,
        ReasonCode::Unauthenticated,
        ReasonCode::WeakTransport,
        ReasonCode::PipFailure,
        ReasonCode::SubjectMismatch,
    ] {
        assert!(!hides(reason), "{reason:?}");
    }
}

/// [MS-ADTS] 3.1.1.4.3 ("RIGHT_DS_READ_PROPERTY on OA by
/// O!nTSecurityDescriptor"): an attribute read is asked of a visible object
/// only — alice's descriptor grants staff RP, secret's (visible under
/// `ListParent`) grants nothing.
#[test]
fn attribute_reads_are_asked_of_visible_objects() {
    let d = directory("gate-attribute-read");
    let view = d.view();
    let policy = allow_reads();
    let mut g = gate(&view, &policy, VisibilityRule::ListParent);
    let cn = d.p1.attribute_schema_id_guid(d.attr("cn")).unwrap();
    let alice = seen(g.visible(guid(ALICE)).unwrap());
    let secret = seen(g.visible(guid(SECRET)).unwrap());
    assert!(g.may_read(&alice, cn));
    assert!(!g.may_read(&secret, cn));
}

/// docs/52 R10: taking a visible object apart keeps a proof naming it; the
/// parts are the object and DN the view holds.
#[test]
fn the_proof_names_the_object() {
    let d = directory("gate-proof");
    let view = d.view();
    let policy = allow_reads();
    let mut g = gate(&view, &policy, VisibilityRule::ListAndRead);
    let (object, dn, proof) = seen(g.visible(guid(ALICE)).unwrap()).into_parts();
    assert_eq!(proof.guid(), guid(ALICE));
    assert_eq!(object.guid, guid(ALICE));
    assert_eq!(Some(dn), view.dn_of(guid(ALICE)).unwrap());
}

// ------------------------------------------------------ the PEP's view (R-a) --

/// docs/52 R-a (A-103 on docs/questions/Q-486): the gate a PEP gets from its
/// `PepView` is the gate — for every object of the directory (and an
/// absent one), under both rules and both policies, its verdicts are the
/// ones `VisibilityGate::new` over the same view gives. Behaviour is
/// unchanged; only the way a PEP reaches the gate is.
#[test]
fn the_pep_views_gate_is_the_gate() {
    let d = directory("pep-view-gate");
    let view = d.view();
    let pep = PepView::new(&view);
    for policy in [allow_reads(), allow_nothing()] {
        for rule in [VisibilityRule::ListParent, VisibilityRule::ListAndRead] {
            let mut direct = gate(&view, &policy, rule);
            let mut through = pep.gate(&policy, alice(&view), context(true), rule);
            assert_eq!(through.rule(), rule);
            assert_eq!(through.request_refusal(), direct.request_refusal());
            for id in [ROOT, STAFF_OU, VAULT, ALICE, SECRET, VAULTED, STAFF, NOBODY] {
                assert_eq!(
                    through.visible(guid(id)).unwrap(),
                    direct.visible(guid(id)).unwrap(),
                    "{id} under {rule:?}"
                );
            }
        }
    }
}

/// docs/52 R-a: a `PepView` locates — it names GUIDs a gate question can be
/// asked about — but hands out no object: `vaulted`, under a container
/// alice may not list, is found by its unique sAMAccountName and its parent
/// pointer, yet its content is reachable only through the gate, which
/// answers it exactly like an identity nobody has. The two locators that
/// act on an object take it visible (a container's children, an object's
/// back links). Source: docs/questions/Q-486 R-a; docs/49 §6.1 item 3;
/// docs/questions/Q-485 (the list rule); A-55.
#[test]
fn a_pep_view_locates_but_hands_out_no_object() {
    let d = directory("pep-view-locators");
    let view = d.view();
    let pep = PepView::new(&view);
    let policy = allow_reads();
    let mut g = pep.gate(
        &policy,
        alice(&view),
        context(true),
        VisibilityRule::ListParent,
    );
    // Locators.
    let located = pep
        .lookup_unique(d.attr("sAMAccountName"), b"vaulted")
        .unwrap();
    assert_eq!(located, Some(guid(VAULTED)));
    assert_eq!(
        pep.parent_of(guid(VAULTED)).unwrap(),
        Some(Some(guid(VAULT)))
    );
    assert_eq!(pep.parent_of(guid(ROOT)).unwrap(), Some(None));
    assert_eq!(pep.parent_of(guid(NOBODY)).unwrap(), None);
    assert!(pep.names_object(guid(VAULTED)).unwrap());
    assert!(!pep.names_object(guid(NOBODY)).unwrap());
    // ... but the content of what was located comes only through the gate:
    // hidden, answered like an absent identity.
    assert_eq!(
        unseen(g.visible(guid(VAULTED)).unwrap()),
        UnseenCause::Hidden(ReasonCode::Acl)
    );
    assert_eq!(
        unseen(g.visible(guid(NOBODY)).unwrap()),
        UnseenCause::Absent
    );
    // A visible container's children; a visible object's back links.
    let root = seen(g.visible(guid(ROOT)).unwrap());
    let page = pep.children(&root, None, 16).unwrap();
    let mut children = page.children.clone();
    children.sort();
    let mut expected = vec![guid(STAFF_OU), guid(VAULT)];
    expected.sort();
    assert_eq!(children, expected);
    assert!(page.next.is_none());
    let alice_object = seen(g.visible(guid(ALICE)).unwrap());
    assert_eq!(
        pep.back_links(&alice_object, d.attr("memberOf")).unwrap(),
        vec![guid(STAFF)]
    );
}
