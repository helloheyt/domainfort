//! Group expansion for the PDP Subject (docs/47 §5.3, R47-8; Q-116 / A-37).
//!
//! One transitive closure over the memberOf back links (the groups whose
//! `member` holds the object), restricted to security-enabled groups: a
//! group without GROUP_TYPE_SECURITY_ENABLED is neither entered nor
//! traversed — the subgraph of [MS-DRSR] 4.1.8.3 (`IsMatchedGroup` requires
//! "GROUP_TYPE_SECURITY_ENABLED in w!groupType", 4.1.8.2.6). The result is
//! the objectSid of every group reached (Closure = the vertices reachable
//! from the start, 4.1.8.2.2).
//!
//! Stricter than [MS-DRSR] (decided, A-37):
//! - **bounds** (project choice): at most [`MAX_EXPANDED_GROUPS`] groups and
//!   [`MAX_NESTING_DEPTH`] levels of nesting on any path; exceeding either is
//!   an error, never a partial set (precedent: STATUS_TOO_MANY_CONTEXT_IDS,
//!   [MS-DRSR] 4.1.8.1.5);
//! - **a cycle is an error**: the management plane refuses a `member` write
//!   that closes a cycle, so one found here comes from an inconsistent or
//!   replayed store (P-7) — fail closed (AGENTS.md §6).
//!
//! The walk is a depth-first search with "on the current path" / "done"
//! marks: reaching an on-path group is a cycle; reaching a done group reuses
//! its remembered height, so the longest nesting chain is measured exactly
//! and every group is read once (a diamond is not a cycle).
//!
//! The SAME function feeds `ClientAccount.groups` and `Pip::expand_groups`,
//! from the same snapshot (docs/47 §5.3 item 5).
//!
//! Spec: docs/47 §5.3 (R47-8); [MS-DRSR] 4.1.8.1.5, 4.1.8.2.2, 4.1.8.2.6,
//! 4.1.8.3; [MS-ADTS] 2.2.12, 3.1.1.4.5.19; docs/46 §2.3 item 4; Q-116.

use crate::error::Fault;
use crate::record;
use crate::view::DirectoryView;
use ad_schema::flags::group_type::GROUP_TYPE_SECURITY_ENABLED;
use dirstore::Object;
use dtyp::{Guid, Sid};
use std::collections::{BTreeMap, BTreeSet};

/// Most groups one expansion may return (project choice, tunable; below the
/// wire bound `[range(0,10000)] cDsNames` of [MS-DRSR] 4.1.8.1.5).
/// Spec: docs/47 §5.3 item 3 (R47-8).
pub const MAX_EXPANDED_GROUPS: usize = 1024;

/// Most levels of group nesting on any path from the start: a direct
/// membership is level 1 (project choice, tunable).
/// Spec: docs/47 §5.3 item 3 (R47-8).
pub const MAX_NESTING_DEPTH: usize = 16;

/// The state of a group during the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    /// On the current path: reaching it again closes a cycle.
    OnPath,
    /// Fully explored; `height` = the longest chain of security groups above
    /// it (0 = it is in none).
    Done { height: usize },
    /// Not security-enabled: neither entered nor traversed.
    Skipped,
}

/// The walk's state.
struct Walk<'v, 'a> {
    view: &'v DirectoryView<'a>,
    marks: BTreeMap<Guid, Mark>,
    sids: BTreeSet<Sid>,
}

/// `true` if `group` is a group object whose groupType has
/// GROUP_TYPE_SECURITY_ENABLED ("Specifies a security-enabled group").
/// A back-link source that is not a group, or a group without groupType (a
/// must), is an inconsistent record: `Err`.
/// Spec: [MS-ADTS] 2.2.12; [MS-DRSR] 4.1.8.2.6; docs/46 §4.4 (groupType must
/// on group).
fn is_security_group(view: &DirectoryView<'_>, group: &Object) -> Result<bool, Fault> {
    if view.most_specific_class(group)? != view.ctx.ids.group {
        return Err(Fault::Unavailable);
    }
    let group_type = record::flags(group, view.ctx.ids.group_type)?.ok_or(Fault::Unavailable)?;
    Ok(group_type & GROUP_TYPE_SECURITY_ENABLED != 0)
}

impl Walk<'_, '_> {
    /// Explore the security groups above `node`, which sits at nesting level
    /// `depth`; returns the height above `node`. Recursion depth is bounded
    /// by [`MAX_NESTING_DEPTH`] + 1.
    /// Spec: docs/47 §5.3; [MS-DRSR] 4.1.8.2.2, 4.1.8.3.
    fn visit(&mut self, node: Guid, depth: usize) -> Result<usize, Fault> {
        let ids = self.view.ctx.ids;
        let mut height = 0usize;
        for source in self.view.snapshot.back_links(node, ids.member_of)? {
            let level = depth.checked_add(1).ok_or(Fault::Unavailable)?;
            match self.marks.get(&source).copied() {
                Some(Mark::OnPath) => return Err(Fault::Unavailable),
                Some(Mark::Skipped) => continue,
                Some(Mark::Done { height: above }) => {
                    if level.checked_add(above).ok_or(Fault::Unavailable)? > MAX_NESTING_DEPTH {
                        return Err(Fault::Unavailable);
                    }
                    height = height.max(above.checked_add(1).ok_or(Fault::Unavailable)?);
                    continue;
                }
                None => {}
            }
            let group = self
                .view
                .snapshot
                .get_object(source)?
                .ok_or(Fault::Unavailable)?;
            if !is_security_group(self.view, &group)? {
                self.marks.insert(source, Mark::Skipped);
                continue;
            }
            if level > MAX_NESTING_DEPTH {
                return Err(Fault::Unavailable);
            }
            // objectSid is a must on group (docs/46 §4.4).
            let sid = record::sid(&group, ids.object_sid)?.ok_or(Fault::Unavailable)?;
            if self.sids.len() >= MAX_EXPANDED_GROUPS {
                return Err(Fault::Unavailable);
            }
            self.sids.insert(sid);
            self.marks.insert(source, Mark::OnPath);
            let above = self.visit(source, level)?;
            self.marks.insert(source, Mark::Done { height: above });
            height = height.max(above.checked_add(1).ok_or(Fault::Unavailable)?);
        }
        Ok(height)
    }
}

/// The objectSids of every security-enabled group `start` is a member of,
/// directly or through nested security-enabled groups (module docs). `Err`
/// on a cycle, a bound exceeded or an inconsistent record.
/// Spec: docs/47 §5.3 (R47-8).
pub(crate) fn expand(view: &DirectoryView<'_>, start: &Object) -> Result<BTreeSet<Sid>, Fault> {
    let mut walk = Walk {
        view,
        marks: BTreeMap::new(),
        sids: BTreeSet::new(),
    };
    // The start itself is on the path: a group that (transitively) contains
    // itself is a cycle.
    walk.marks.insert(start.guid, Mark::OnPath);
    walk.visit(start.guid, 0)?;
    Ok(walk.sids)
}
