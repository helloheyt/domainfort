#![forbid(unsafe_code)]
//! `directory-pip`: the KDC's [`kdc::AccountSource`] and the PDP's
//! [`pdp::Pip`] over the directory — dirstore + the phase-1 AD schema
//! (docs/47, decided as A-38).
//!
//! # What it is
//!
//! A [`DirectoryContext`] is built once from the phase-1 schema and keyd's
//! configuration. For each request the caller takes a [`DirectoryView`] —
//! ONE dirstore snapshot plus the request's [`TierMap`] — and hands the same
//! view to the KDC twice: as the request's account source and as the PIP in
//! its `PolicyInputs` (docs/47 §8.1, R47-11, R47-14). Groups, tier and state
//! therefore come from one consistent picture.
//!
//! # The rules (docs/47 §12, all accepted)
//!
//! - **Names (R47-1):** AS client = exactly one component, accepted only
//!   as an object's sAMAccountName, re-compared octet for octet; user or
//!   computer only; never the krbtgt account (RID 502). TGS server = two or
//!   more components joined with "/", accepted only as a computer's
//!   servicePrincipalName, octet for octet. No UPN, "$", enterprise or
//!   canonicalisation fallbacks. Both go through the one lookup path by
//!   name, [`DirectoryView::canonical_principal`] (tasks PN4, PN4b; docs/59
//!   §6): one key per request from crate `principal-names`, one probe of
//!   the namespace's union index (`PRINCIPAL_NAME_KEY` — no per-attribute
//!   index is asked for a name), the kind and the key purpose read from the
//!   object found, and R47-1 as the acceptance of wave 2 (module `resolve`;
//!   docs/questions/Q-1026, Q-1027, Q-1042). The DNS record owner is found
//!   through the same probe, by its `HostName` key (module `host`;
//!   Q-1036 item 6).
//! - **dird's statement (task PN10; docs/59 §7):** every account record the
//!   view answers carries the resolution of its lookup —
//!   `ResolvedPrincipal::name_resolution`, attested by the
//!   [`NameResolutionSigner`] the deployment installs on the context (dird's
//!   attestation key, crates/ipc-directory-server); no signer ⇒ no record
//!   (fail closed). A reserved key purpose resolves only on a configured
//!   provisioned service object (A-163 at the lookup; Q-1027 item 6). The
//!   `principal-namespace` marker is defined here, with dird's check of it
//!   ([`principal_namespace_marked`]; docs/59 §5.5).
//! - **krbtgt (R47-2):** never a client or a service;
//!   [`DirectoryView::krbtgt_handle`] gives `KdcConfig.krbtgt`.
//! - **Keys (R47-3):** `KeyHandle = (objectGUID, purpose)`.
//! - **Salt (R47-4):** [`account_salt`], [MS-KILE] 3.1.1.2 — one public
//!   function for the password path and PA-ETYPE-INFO2.
//! - **State (R47-5, R47-6, R47-7):** enabled / expired / usable from
//!   userAccountControl, accountExpires, pwdLastSet; `locked = false`;
//!   `revoked_before = max(whenCreated + 1 s, floor_s(pwdLastSet) + 1 s)` —
//!   a ticket first authenticated at or before the second of the account's
//!   creation or of its last password set is revoked (Q-965 (a), A-161).
//! - **Groups (R47-8):** a bounded transitive closure over memberOf, security
//!   groups only; a cycle or a bound exceeded is an error.
//! - **Tier (R47-9):** a [`TierMap`] passed in as data, plus DC accounts,
//!   krbtgt and the domain root as Tier0; an unclassified object is Tier0
//!   for writes.
//! - **Enctypes (R47-10):** keyd's configured list and s2kparams.
//! - **Kind and armor policy (docs/48 §3.1, §7.2; Q-127 interim, P-10):**
//!   from the most specific objectClass — a computer object is
//!   `AccountKind::Computer` with `ArmorPolicy::BootstrapAllowed` (it may get
//!   its TGT unarmored, and its TGT may armor others' AS requests); a user is
//!   `AccountKind::User` with `ArmorPolicy::Required`.
//!
//! Every failure fails closed: `AccountSourceError` (the KDC refuses) or a
//! `PipError` (the PDP denies).
//!
//! # The visibility gate (docs/52 R10, A-102)
//!
//! A PEP that shows directory content to a requester, or acts on an object
//! a requester names, obtains it as a [`VisibleObject`] — which only the
//! [`VisibilityGate`] builds, after the PDP's visibility decision over this
//! view — and gets "absent" and "not visible" as one verdict,
//! [`Visibility::NotFound`] (docs/11 §7, §8; A-55). The LDAP search and the
//! admin plane use it; the KDC's account source does not (it is the
//! authority's own lookup, not a requester's read — module `visible`).
//!
//! A PEP receives the directory as a [`PepView`] — the gate, the locators
//! of gate questions, the PIP and the account source — never the
//! [`DirectoryView`] or its snapshot, so a new PEP cannot put a raw object on
//! the wire (docs/52 R-a; decision A-103 on docs/questions/Q-486). The raw
//! snapshot is reachable only through
//! [`DirectoryView::authority_snapshot`], for the authority's own reads
//! (module `pep`).
//!
//! # Effect-plan facts (task MA3; docs/research/r5-a-admin-model.md §3.3)
//!
//! [`DirectoryView::principal_facts`] answers what the PIP will say about a
//! principal once an admin write is committed — its expansion, subject tier
//! and object tier — with the view's own functions, under a [`MemberChange`]
//! (the member set the write gives one group) or a candidate tier map
//! (module `facts`); [`DirectoryView::member_closure`] and
//! [`DirectoryView::principals_under`] find which principals to ask about;
//! [`DirectoryView::account_state_of`] is the KDC's account state of a
//! record. Written only from r5-a (§3.3, §11 MA3), docs/questions/Q-874,
//! PENDING-OWNER A-36, A-147, docs/47 §4-§6 and this crate's own code
//! (interpretations in docs/questions/Q-980..Q-984). No other
//! implementation was consulted or recalled (AGENTS.md §1-3).
//!
//! # DNS: the host record, its tier, and the zone projection (task DN6)
//!
//! A member host's DNS addresses are an attribute of its own computer object
//! (module `host`; docs/54 §5.2, decision A-119 on docs/questions/Q-614):
//! [`host_label`] derives its one LDH label from its sAMAccountName and
//! dNSHostName ([MS-ADTS] 3.1.1.5.3.1.1.2), so the name comes from the
//! identity, never from a message. `Pip::object_tier` of
//! `Resource::Dns { zone, record: Some(k) }` is the tier of the one computer
//! owning `k` (docs/54 §5.6; Q-614 item 6) — so a computer that is not Tier0
//! may update its own record. [`DirectoryView::zone_projection`] (module
//! `zone`) builds dnsd's `dns_zone::ZoneImage` from one snapshot: SOA / NS /
//! SRV synthesized, the DC's and the usable member hosts' A records, SERIAL
//! from the `dns-zone-serial` counter, and the instant the image holds until
//! ([`ZoneProjection::valid_until`]). Written only from docs/54 (§3.1, §4.4,
//! §5.1-§5.6), docs/questions/Q-613, Q-614, Q-616, Q-618, PENDING-OWNER
//! A-111, A-119, the pinned [MS-ADTS] v20261026 3.1.1.2.6, 3.1.1.5.3.1.1.2,
//! [MS-ADSC] v20240423 2.21, 2.67, [MS-ADA1] v20180912 2.315, RFC 1035
//! §2.3.1, §2.3.3, §2.3.4, §3.4.1 and RFC 2136 §3.6, §7.11, §7.12 (opened
//! in-session from tools/spec-pin/cache/, SHA-256 verified), and this
//! repository's crates dns-zone, parse-dns and config; interpretations in
//! docs/questions/Q-991..Q-994. No other implementation was consulted or
//! recalled (AGENTS.md §1-3).
//!
//! # Residuals and follow-ups (documented, not hidden)
//!
//! - The tier map is trusted as given: verifying the signed policy store
//!   over it (docs/06 §9, D17) is a follow-up.
//! - DNs reach the PIP only in the directory's own form
//!   ([`DirectoryView::dn_of`]), which ends with the configured
//!   [`NamingContext`] (A-53: the NC root maps to exactly that DN). An LDAP
//!   client's DN, already parsed by the LDAP layer (RFC 4514, parse-ldap),
//!   is resolved with [`DirectoryView::lookup_dn`] (case-folded, docs/49
//!   §7). An object outside the naming context has no DN here.
//! - Phase 1 has no primaryGroupID, no builtin groups, no sIDHistory and no
//!   contextual SIDs in the expansion (docs/47 §5.3 item 6).
//! - No fuzz target: no network parser here — the input is MAC-verified
//!   dirstore records and names already decoded by krb-proto (docs/47
//!   §10.2).
//!
//! # Provenance
//!
//! Written only from docs/47 (in full; R47-1..R47-14, A-38), docs/48 §3.1,
//! §7.2-§7.3 (A-33), the decided questions Q-110..Q-117, Q-127 (interim),
//! PENDING-OWNER (A-18, A-19, A-27..A-38, P-6, P-9, P-10, P-11), docs/46,
//! and the pinned specifications opened in-session from
//! `tools/spec-pin/cache/` (SHA-256 verified against
//! `tools/spec-pin/manifest.json`): [MS-KILE] v20260928 3.1.1.2, 3.3.1.1,
//! 3.3.3, 3.3.5.6.3, 4.4; [MS-ADTS] v20261026 2.2.12, 2.2.16, 3.1.1.4.5.17;
//! [MS-SAMR] v20260427 2.2.1.14, 2.2.6.1, 3.1.1.6 (items 11-24), 3.1.1.8.1,
//! 3.1.5.14.4; [MS-DRSR] v20260309 4.1.8.2.2, 4.1.8.2.6, 4.1.8.3, 5.51;
//! [MS-DTYP] v20241119 2.3.3, 2.4.2.4; RFC 4120 3.3.3.1, 6.2. The source and
//! documentation of this project's own crates dirstore, ad-schema, kdc, pdp,
//! keyd, krb-proto and dtyp were read for their APIs. The visibility gate
//! (module `visible`, task U) only from docs/52 §3.6 and §7 (R10), docs/11
//! §4, §6-§8, docs/49 §6.1 and §9, docs/51 §5.2 row 10, PENDING-OWNER A-51,
//! A-55, A-89, A-102, docs/questions/Q-200 and Q-358, and [MS-ADTS]
//! v20261026 3.1.1.4.3 and 5.1.3.3.6 (pinned PDF, SHA-256 55b59eb1…b2b1
//! verified), with this repository's ldap and directory-admin code. No other
//! implementation was consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/47 §1-§12; docs/11 §6; docs/06 §8-§10.

mod error;
mod facts;
mod groups;
mod host;
mod names;
mod naming;
mod pep;
mod principal;
mod record;
mod resolve;
mod salt;
mod state;
mod tier;
mod time;
mod view;
mod visible;
mod zone;

pub use error::ViewError;
pub use facts::{PrincipalFacts, PrincipalKind};
pub use groups::{MemberChange, MAX_EXPANDED_GROUPS, MAX_NESTING_DEPTH};
// A computer's DNS host record: the rules its writer, the PIP and the zone
// projection share (task DN6; docs/54 §5.2-§5.5).
pub use host::{
    computer_label, host_address_of, host_address_value, host_label, registrable, zone_serial,
    DNS_ZONE_SERIAL_COUNTER, DNS_ZONE_SERIAL_END_EXCLUSIVE, DNS_ZONE_SERIAL_FIRST, HOST_ADDRESS,
    MAX_HOST_ADDRESSES,
};
pub use naming::{NamingContext, MAX_NC_LABELS, NC_RDN_ATTRIBUTE};
pub use pep::PepView;
// An object's principal names and keys in the one namespace (task PN1;
// docs/59 §4.3): `DirectoryView::{principal_names_of, principal_keys}`.
pub use principal::{name_context_of, PrincipalNamesError};
// The `principal-namespace` marker, defined once beside the namespace it
// marks (task PN10; docs/questions/Q-1043 item 1, A-185), and dird's check
// of it (docs/59 §5.5).
pub use principal::{
    principal_namespace_marked, PRINCIPAL_NAMESPACE_COUNTER, PRINCIPAL_NAMESPACE_END_EXCLUSIVE,
    PRINCIPAL_NAMESPACE_FIRST,
};
// The one lookup path by name (task PN4; docs/59 §6.1-§6.3):
// `DirectoryView::canonical_principal`; from task PN10 its attestation
// (docs/59 §7.1, §7.4): the signer the deployment installs.
pub use resolve::{LookupCtx, NameResolutionSigner, ResolvedPrincipal, SignerRefused};
pub use salt::{account_salt, AccountKind, SaltError};
pub use tier::TierMap;
pub use time::{dstime_of, time_of_dstime};
pub use view::{DirectoryContext, DirectoryView, MAX_DN_DEPTH};
pub use visible::{
    hides, GateFault, Unseen, UnseenCause, Visibility, VisibilityGate, VisibilityProof,
    VisibilityRule, VisibleObject,
};
// The zone projection (task DN6; docs/54 §4.4): the one function from the
// directory to dnsd's zone image, for dird's DNS channel (task DN10a).
pub use zone::{ZoneParameters, ZoneProjection, ZoneProjectionError, MAX_ZONE_WALK_OBJECTS};
// The zone crate's types the projection's API speaks in, so its consumer
// (dird, task DN10a) names them through this crate.
pub use dns_zone::{KpasswdService, SoaParameters, ZoneImage, ZoneImageError, ZoneImageParts};
pub use parse_dns::Name as DnsName;
