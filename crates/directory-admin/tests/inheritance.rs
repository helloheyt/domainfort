//! The security descriptor of a created object and its inheritance.
//!
//! Sources: docs/51 §10 (R51-19; decided A-76 / Q-294 (a): CreateSecurityDescriptor
//! with the parent's SD, no creator SD, owner = the requester; the root SD
//! holds inheritable ACEs for the Tier-0 group); A-84 / Q-335 (b) (an
//! inheritable ACE stays effective at every depth, not one generation
//! only); [MS-ADTS] v20261026 6.1.3 items 1, 4, 5, 7, 6.1.3.7; [MS-DTYP]
//! 2.4.4.1 (INHERITED_ACE) as implemented by crate dtyp; docs/11 §4, §5 (the
//! access check through `decide`). Fixtures: tests/common (the root SD
//! grants the Tier-0 group ADMIN_RIGHTS with CONTAINER_INHERIT_ACE).

mod common;

use common::*;
use directory_admin::{AdminSubject, CreateContainerLike, CreateUser, Operation, Reply};
use dtyp::{ace_flags, Ace, SecurityDescriptor};
use pdp::access_check::rights::{RIGHT_DELETE, RIGHT_DS_WRITE_PROPERTY};
use pdp::{
    AccessRequest, Action, AttrId, Context, Effect, Instant, IpScope, Resource, Transport,
    TransportSec,
};

fn created(reply: &Reply) -> dtyp::Guid {
    match reply {
        Reply::Created { guid, .. } => *guid,
        other => panic!("{other:?}"),
    }
}

/// A-84 at depth 2: admin1 creates ou=Lab below the NC root (depth 1) and a
/// user "deep" in it (depth 2), both through the admin plane. The user's SD
/// is owned by admin1 (6.1.3.7, A-76), has a DACL (6.1.3 item 7) whose ACEs
/// are all inherited (INHERITED_ACE), and the root's inheritable allow for
/// the Tier-0 group reaches it: admin2 — a member — may write its
/// userAccountControl through `decide` (over the admin plane's local
/// socket, `Transport::LocalIpc`), while bob — not a member — is denied.
#[test]
fn the_root_grant_reaches_a_user_two_levels_down() {
    let mut d = Domain::new("inherit-depth2");
    let lab = created(
        d.run(
            Operation::CreateOu(CreateContainerLike {
                parent: guid(ROOT),
                name: "Lab".into(),
            }),
            "admin1",
            &[],
        )
        .applied()
        .1
        .reply(),
    );
    let deep = created(
        d.run(
            Operation::CreateUser(CreateUser {
                parent: lab,
                sam: "deep".into(),
                upn: None,
                description: None,
            }),
            "admin1",
            &[],
        )
        .applied()
        .1
        .reply(),
    );
    let obj = d.object(deep).unwrap();
    let sd = SecurityDescriptor::decode(
        &obj.attribute(d.attr("nTSecurityDescriptor"))
            .unwrap()
            .values[0]
            .value,
    )
    .unwrap();
    assert_eq!(sd.owner_sid, Some(sid_of(ADMIN1)));
    let dacl = sd.dacl.expect("a DACL");
    assert!(!dacl.aces.is_empty());
    for ace in &dacl.aces {
        let flags = match ace {
            Ace::AccessAllowed(a) | Ace::AccessDenied(a) => a.ace_flags,
            Ace::AccessAllowedObject(a) | Ace::AccessDeniedObject(a) => a.ace_flags,
            other => panic!("{other:?}"),
        };
        assert_ne!(flags & ace_flags::INHERITED_ACE, 0);
    }

    let view = d.view();
    let subject = |sam: &str| {
        AdminSubject::from_verified_ticket(&view, &realm(), &ticket(sam).cname, &authtime(), &now())
            .unwrap()
            .subject()
            .clone()
    };
    let deep_dn = view.dn_of(deep).unwrap().unwrap();
    assert_eq!(deep_dn, dn(&["cn=deep", "ou=Lab", "dc=example", "dc=test"]));
    let uac_guid =
        d.p1.attribute_schema_id_guid(d.attr("userAccountControl"))
            .unwrap();
    let request = |subject, action: Action, attr: Option<AttrId>| AccessRequest {
        subject,
        resource: Resource::DirObject {
            dn: deep_dn.clone(),
            attr,
        },
        action,
        context: Context {
            src_net: IpScope::Internal,
            // 2026-11-13T10:00:00Z = 1 794 564 000 s since 1970 (see
            // NOW_DSTIME in tests/common).
            time: Instant(1_794_564_000),
            transport: Transport::LocalIpc,
            // What the admin PEP reports once keyd verified the AP-REQ's
            // operation binding (R2, docs/52 §5 item 4).
            transport_sec: TransportSec {
                encrypted: true,
                sealed: true,
                channel_bound: true,
            },
        },
    };
    let decision = pdp::decide(
        &request(subject("admin2"), Action::DirWrite, Some(AttrId(uac_guid))),
        &d.policy,
        &view,
    );
    assert_eq!(decision.effect, Effect::Allow, "{decision:?}");
    let decision = pdp::decide(
        &request(subject("admin2"), Action::DirDelete, None),
        &d.policy,
        &view,
    );
    assert_eq!(decision.effect, Effect::Allow, "{decision:?}");
    let decision = pdp::decide(
        &request(subject("bob"), Action::DirWrite, Some(AttrId(uac_guid))),
        &d.policy,
        &view,
    );
    assert_eq!(decision.effect, Effect::Deny);

    // The ACL layer itself (docs/11 §5): the inherited grant names the
    // Tier-0 group, so a Tier-0 member is granted WP and DELETE on the
    // object and a non-member nothing.
    let object = pdp::DirObjectContext {
        object_class: d.class_guid("user"),
        superclasses: vec![],
        object_sid: Some(account_sid(FIRST_ADMIN_RID)),
    };
    let sd = SecurityDescriptor::decode(
        &obj.attribute(d.attr("nTSecurityDescriptor"))
            .unwrap()
            .values[0]
            .value,
    )
    .unwrap();
    for mask in [RIGHT_DS_WRITE_PROPERTY, RIGHT_DELETE] {
        assert!(pdp::acl_grants(
            &subject("admin2"),
            &sd,
            &object,
            &pdp::Right::Object { mask }
        ));
        assert!(!pdp::acl_grants(
            &subject("bob"),
            &sd,
            &object,
            &pdp::Right::Object { mask }
        ));
    }
}

/// [MS-ADTS] 6.1.3 item 7 ("NULL DACLs are disallowed"; A-84): below a
/// parent whose DACL has no inheritable ACE, the new object would have no
/// DACL — the create is refused. ou=Bare is given such a DACL (a
/// non-inheritable grant to the Tier-0 group only) by provisioning-style
/// direct write.
#[test]
fn a_create_whose_descriptor_would_have_no_dacl_is_refused() {
    let mut d = Domain::new("inherit-no-dacl");
    // ou=Bare under the root, with a DACL that grants the Tier-0 group the
    // admin rights on the OU itself but nothing inheritable.
    let bare = guid(500);
    let sd = sd_with(
        sid_of(TIER0_GROUP),
        vec![Ace::AccessAllowed(dtyp::MaskSidAce {
            ace_flags: 0,
            mask: dtyp::AccessMask(ADMIN_RIGHTS),
            sid: sid_of(TIER0_GROUP),
        })],
    );
    {
        let mut txn = d.store.begin_write().unwrap();
        let ou = d.p1.class_by_name("organizationalUnit").unwrap();
        let origin = dirstore::Origin {
            wall_clock: directory_admin::wall_clock(&now()).unwrap(),
            origin_node: NODE_ID,
            origin_seq: txn
                .take_counter_value(directory_admin::CHANGE_SEQ_COUNTER)
                .unwrap(),
        };
        txn.create_object(
            dirstore::NewObject {
                guid: bare,
                parent: Some(guid(ROOT)),
                classes: d.p1.class(ou).unwrap().object_class.clone(),
                attributes: vec![
                    (d.attr("ou"), vec![b"Bare".to_vec()]),
                    (d.attr("nTSecurityDescriptor"), vec![sd.encode().unwrap()]),
                ],
            },
            &origin,
        )
        .unwrap();
        txn.commit().unwrap();
    }
    let r = d
        .run(
            Operation::CreateContainer(CreateContainerLike {
                parent: bare,
                name: "c".into(),
            }),
            "admin1",
            &[],
        )
        .refused();
    assert_eq!(
        r.event().stage,
        ipc_audit::DirAdminStage::Decision(ipc_audit::DecisionResult::Refused(
            ipc_audit::AdminRefusal::ValueInvalid
        ))
    );
}
