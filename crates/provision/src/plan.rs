//! The plan: everything `provision domain` will write, computed from the
//! input, the provisioning time and the CSPRNG — with **no filesystem
//! effect** (steps 1-2 and the content of steps 4-8 of docs/51 §4.3). The
//! installer (module `install`) only writes what the plan holds.
//!
//! # The draws (step 2; R51-3, A-77)
//!
//! Every identifier comes from the CSPRNG, in this order, all before
//! anything is built: the domain SID's three SubAuthority values
//! (`S-1-5-21-r1-r2-r3`, [MS-DTYP] 2.4.2.4), one objectGUID per object (16
//! octets, never the NULL GUID, all distinct — [MS-ADTS] 3.1.1.5.2.4), the
//! NodeId (16 octets, never all zero — docs/29 §2 as cited in docs/51 §4.3
//! step 2; directory-admin refuses a zero node id), the integrity key (32
//! octets, `dirstore::INTEGRITY_KEY_LEN`). A source failure, a NULL or
//! repeated GUID or a zero node id stops the run before anything is written
//! (fail closed; no retry — a CSPRNG that repeats is broken). The readiness
//! threshold of D74 is a documented residual until P-18 (A-77).
//!
//! # The objects (step 5) — creation order
//!
//! | # | object | class | parent | RID | key values |
//! |---|---|---|---|---|---|
//! | 1 | NC root | domainDNS | — | — | `dc` = n1; objectSid = domain SID; the root SD (module `descriptor`) |
//! | 2 | Tier-0 OU | organizationalUnit | NC root | — | `ou` |
//! | 3 | workstations OU (optional) | organizationalUnit | NC root | — | `ou` |
//! | 4 | krbtgt | user | Tier-0 OU | 502 (fixed) | cn = sAMAccountName = "krbtgt"; UAC = N; accountExpires = never; no pwdLastSet |
//! | 5 | DC computer | computer | Tier-0 OU | counter | cn = name, sAMAccountName = name‖"$"; UAC = ST; dNSHostName = fqdn; accountExpires = never; no SPN; its host record = the `--dc-address` values (task DN10b — the zone's A record of the DC, docs/54 §3.1) |
//! | 6 | LDAP service | computer | Tier-0 OU | counter | as 5 with UAC = WT and SPN `ldap/<fqdn>` |
//! | 7 | admin service | computer | Tier-0 OU | counter | as 5 with UAC = WT and SPN `admind/<fqdn>` |
//! | 8 | change-password service (task K9) | computer | Tier-0 OU | counter | as 5 with UAC = WT and SPN `kadmin/changepw` (RFC 3244 §2) |
//! | 9.. | first administrators | user | Tier-0 OU | counter | cn = sAMAccountName; UAC = N; pwdLastSet = now; accountExpires = never |
//! | n-1 | Tier-0 group | group | Tier-0 OU | counter | groupType = 0x80000002; member = the first administrators |
//! | n | bootstrap group | group | workstations OU, else NC root | counter | groupType = 0x80000002; no member |
//!
//! Every object: objectGUID from the CSPRNG; whenCreated = whenChanged =
//! the provisioning time (DSTIME); nTSecurityDescriptor = the root's
//! (row 1) or `directory_admin::new_object_descriptor(parent's SD, class,
//! Tier-0 group SID)` — exactly the runtime computation (A-84; owner: the
//! Tier-0 group, docs/questions/Q-376 item 2). The counter RIDs are 1101,
//! 1102, … in creation order (the first takes of a counter created in the
//! same transaction with first value 1101, A-75); the installer checks
//! each taken value against the plan.
//!
//! Spec: docs/51 §4.3 steps 1-8, §8.3, §10, §11; [MS-SAMR] v20260427
//! 2.2.1.14, 3.1.1.6 items 11, 12, 14, 20, 22-24, 3.1.1.8.1 items 1.2, 2.2,
//! 3.1.1.9.2; [MS-ADTS] v20261026 3.1.1.5.2.4, 6.1.3; [MS-DTYP] v20241119
//! 2.4.2.4; docs/46 §4.4, §5.4, §8.1; docs/47 §1.4, §4.1, §6.3; RFC 3244
//! §2 and docs/53 R53-6, §5.2, §10 (K9) for row 8; A-72, A-75, A-76, A-79,
//! A-83, A-84, A-89, A-117, P-22; docs/questions/Q-964 item 13, Q-972.

use core::fmt;
use std::collections::BTreeSet;

use ad_schema::flags::group_type::{GROUP_TYPE_ACCOUNT_GROUP, GROUP_TYPE_SECURITY_ENABLED};
use ad_schema::flags::user_account_control::{
    ADS_UF_NORMAL_ACCOUNT, ADS_UF_SERVER_TRUST_ACCOUNT, ADS_UF_WORKSTATION_TRUST_ACCOUNT,
};
use config::DirdSettings;
use directory_admin::{
    computer_sam, filetime, new_object_descriptor, DnsRegistration, RandomSource,
    ACCOUNT_EXPIRES_NEVER, RID_END_EXCLUSIVE, RID_FIRST,
};
use directory_pip::{
    account_salt, dstime_of, host_address_value, registrable, AccountKind, NamingContext,
    HOST_ADDRESS, NC_RDN_ATTRIBUTE,
};
use dirstore::{AttrId, ClassId, NodeId, INTEGRITY_KEY_LEN};
use dtyp::{Guid, SecurityDescriptor, Sid, GUID_PACKET_LEN, SECURITY_NT_AUTHORITY};
use keyd_types::CHANGE_PASSWORD_SERVICE_NAME;
use krb_proto::{KerberosTime, Realm};
use pdp::Dn;
use policy_store::DevelopmentPolicy;
use provision_manifest::{Manifest, ManifestFields, ADMIN_SERVICE_CLASS, LDAP_SERVICE_CLASS};
use zeroize::Zeroizing;

use crate::configs::{domain_configs, ConfigFile, Daemon};
use crate::descriptor::domain_root_descriptor;
use crate::ids::{integer32, integer64, object_ref, text, ClassIds, SchemaIds};
use crate::input::{Account, DomainInput, InputError, InputErrorKind, Paths, KRBTGT_NAME};
use crate::policy::{domain_policy, CreatableClasses, DomainPolicyInput};

/// SECURITY_NT_NON_UNIQUE: the first SubAuthority of a domain SID.
/// Spec: [MS-DTYP] 2.4.2.4 ("21: SECURITY_NT_NON_UNIQUE, indicates a domain
/// id will follow. 1-2-3: The next three SubAuthority arrays contain 32-bit
/// random numbers to uniquely identify the domain").
pub const SECURITY_NT_NON_UNIQUE: u32 = 21;

/// DOMAIN_USER_RID_KRBTGT — the only fixed RID provisioning writes (no
/// 500 / 501 / 512, A-79).
/// Spec: [MS-SAMR] 2.2.1.14 ("DOMAIN_USER_RID_KRBTGT 0x000001F6");
/// docs/51 §4.3 step 5, §8.3.
pub const DOMAIN_USER_RID_KRBTGT: u32 = 0x0000_01F6;

/// The groupType of both provisioned groups: GROUP_TYPE_SECURITY_ACCOUNT =
/// SECURITY_ENABLED | ACCOUNT_GROUP (0x80000002).
/// Spec: [MS-SAMR] 3.1.1.8.1 item 2.2 (the default GROUP_TYPE_SECURITY_
/// ACCOUNT); docs/51 §4.3 step 5 ("`0x80000002`").
pub const PROVISIONED_GROUP_TYPE: u32 = GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_ACCOUNT_GROUP;

/// The change-seq counter's range, `[1, u64::MAX)` (docs/questions/Q-376
/// item 4). Defined by crate directory-admin, whose provisioning session
/// creates the counter (docs/52 R13; A-83); re-exported here unchanged.
pub use directory_admin::{CHANGE_SEQ_END_EXCLUSIVE, CHANGE_SEQ_FIRST};

/// The integrity key: wiped on drop, never printed.
/// Spec: docs/51 §4.3 step 4, §4.4 ("the integrity key only in the 0400
/// file"); AGENTS.md §6 (secrets never in logs or debug output).
pub(crate) struct IntegrityKeyMaterial(Zeroizing<[u8; INTEGRITY_KEY_LEN]>);

impl IntegrityKeyMaterial {
    /// The key octets.
    pub(crate) fn bytes(&self) -> &[u8; INTEGRITY_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for IntegrityKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IntegrityKeyMaterial(<redacted>)")
    }
}

/// Which object of the domain a planned object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectRole {
    /// The naming context's root (domainDNS).
    NamingContextRoot,
    /// The Tier-0 OU.
    Tier0Ou,
    /// The workstations OU.
    WorkstationsOu,
    /// The krbtgt account.
    Krbtgt,
    /// The DC's computer account.
    DcComputer,
    /// The LDAP service object.
    LdapService,
    /// The admin service object.
    AdminService,
    /// The change-password service object (`kadmin/changepw`, task K9).
    ChangePasswordService,
    /// The n-th first administrator (from 0).
    FirstAdmin(usize),
    /// The Tier-0 group.
    Tier0Group,
    /// The bootstrap group.
    BootstrapGroup,
}

/// Where an object's RID comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RidSource {
    /// Not a security principal (no objectSid), or the NC root (the domain
    /// SID itself).
    None,
    /// The fixed DOMAIN_USER_RID_KRBTGT.
    Fixed(u32),
    /// The RID counter; the value the installer must take.
    Counter(u32),
}

/// One object the store will hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedObject {
    /// Which object.
    pub role: ObjectRole,
    /// objectGUID.
    pub guid: Guid,
    /// The parent's objectGUID (`None` for the NC root).
    pub parent: Option<Guid>,
    /// The most specific class's lDAPDisplayName.
    pub class_name: &'static str,
    /// The objectClass chain.
    pub classes: Vec<ClassId>,
    /// Where the RID comes from.
    pub rid: RidSource,
    /// objectSid, if any.
    pub sid: Option<Sid>,
    /// The DN in the directory's canonical form (leaf first).
    pub dn: Dn,
    /// sAMAccountName, if any.
    pub sam_account_name: Option<String>,
    /// The security descriptor.
    pub descriptor: SecurityDescriptor,
    /// Every stored attribute (`NewObject.attributes`).
    pub attributes: Vec<(AttrId, Vec<Vec<u8>>)>,
}

/// Why no plan was built. Nothing was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// The input broke a rule.
    Input(InputError),
    /// The CSPRNG failed (A-15: fail closed).
    Random,
    /// The CSPRNG produced a NULL or repeated GUID or a zero node id.
    RandomUnusable,
    /// The provisioning time is outside the representable range.
    Time,
    /// The phase-1 schema lacks a name provisioning needs.
    Schema,
    /// A security descriptor could not be built (root, or a child through
    /// directory-admin's computation).
    Descriptor,
    /// The policy was refused by its own rules (pdp / policy-store).
    Policy,
    /// A generated configuration file was refused by its schema.
    Config(Daemon, config::Error),
    /// The manifest builder refused the values.
    Manifest(provision_manifest::Error),
    /// The manifest's canonical text did not parse back to itself.
    ManifestRoundTrip,
    /// A first administrator's salt could not be formed by the directory's
    /// salt function (A-102: the manifest carries it, docs/52 N4).
    Salt,
    /// A planned RID or SID could not be formed.
    Sid,
    /// dird's generated file names no DNS registration networks the write
    /// checker accepts (task DN10b: the provisioning session's zone comes
    /// from that file).
    DnsRegistration,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::Input(e) => write!(f, "input refused: {e}"),
            PlanError::Random => f.write_str("the CSPRNG failed"),
            PlanError::RandomUnusable => {
                f.write_str("the CSPRNG produced an unusable identifier (NULL, repeated or zero)")
            }
            PlanError::Time => f.write_str("the provisioning time is out of range"),
            PlanError::Schema => f.write_str("the schema lacks a definition provisioning needs"),
            PlanError::Descriptor => f.write_str("a security descriptor could not be built"),
            PlanError::Policy => f.write_str("the policy was refused by its own rules"),
            PlanError::Config(daemon, e) => {
                write!(f, "generated {} configuration refused: {e}", daemon.name())
            }
            PlanError::Manifest(e) => write!(f, "manifest refused: {e}"),
            PlanError::ManifestRoundTrip => f.write_str("manifest did not parse back"),
            PlanError::Salt => f.write_str("a first administrator's salt cannot be formed"),
            PlanError::Sid => f.write_str("a SID could not be formed"),
            PlanError::DnsRegistration => {
                f.write_str("dird's generated file names no usable DNS registration networks")
            }
        }
    }
}

impl std::error::Error for PlanError {}

/// The owner of the database file. Spec: docs/51 §4.3 step 5 ("ownership ⇒
/// dird's uid, mode 0600"); docs/50 §6.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    /// The uid.
    pub uid: u32,
    /// The gid.
    pub gid: u32,
}

impl Owner {
    /// root:root. Spec: docs/51 §4.3 steps 3, 4, 6-8 (root-owned files).
    pub const ROOT: Owner = Owner { uid: 0, gid: 0 };
}

impl From<Account> for Owner {
    fn from(account: Account) -> Owner {
        Owner {
            uid: account.uid,
            gid: account.gid,
        }
    }
}

/// Everything `provision domain` will write (module documentation).
#[derive(Debug)]
pub struct Plan {
    /// The provisioning time (whenCreated, whenChanged, pwdLastSet, the
    /// write stamps).
    pub now: KerberosTime,
    /// The realm.
    pub realm: Realm,
    /// The naming context.
    pub naming_context: NamingContext,
    /// The domain SID.
    pub domain_sid: Sid,
    /// This DC's node id (dird's `node_id`, every write's `origin_node`).
    pub node_id: NodeId,
    key: IntegrityKeyMaterial,
    /// The objects, in creation order.
    pub objects: Vec<PlannedObject>,
    /// The policy.
    pub policy: DevelopmentPolicy,
    /// The policy file.
    pub policy_file: Vec<u8>,
    /// The configuration files.
    pub configs: Vec<ConfigFile>,
    /// The manifest.
    pub manifest: Manifest,
    /// The paths of the input.
    pub paths: Paths,
    /// The owner of the database file (dird's account).
    pub store_owner: Owner,
    /// The provisioning session's host-record networks: dird's
    /// `dns_registrable_networks` as its own schema parsed them back (task
    /// DN10b; docs/questions/Q-1014).
    pub dns_registration: DnsRegistration,
}

/// The registrable networks of dird's generated file, as dird's own schema
/// parses them (crate config `DirdSettings::dns_service`), as the write
/// checker's rule (`DnsRegistration::new`: at least one, all IPv4).
///
/// # Errors
/// [`PlanError::DnsRegistration`]; a file its schema refuses
/// ([`PlanError::Config`] — already checked by `parse_back`).
///
/// Spec: docs/54 §5.5; docs/questions/Q-1001 item 3, Q-1003 items 1-2,
/// Q-1014.
fn dird_dns_registration(configs: &[ConfigFile]) -> Result<DnsRegistration, PlanError> {
    let dird = configs
        .iter()
        .find(|file| file.daemon == Daemon::Dird)
        .ok_or(PlanError::DnsRegistration)?;
    let settings = DirdSettings::parse(dird.text().as_bytes())
        .map_err(|e| PlanError::Config(Daemon::Dird, e))?;
    let networks = settings
        .dns_service()
        .ok_or(PlanError::DnsRegistration)?
        .registrable_networks()
        .to_vec();
    DnsRegistration::new(networks).map_err(|_| PlanError::DnsRegistration)
}

/// The draws of step 2.
struct Draws {
    sub: [u32; 3],
    guids: Vec<Guid>,
    node_id: NodeId,
    key: IntegrityKeyMaterial,
}

/// Fill `out` from the CSPRNG. Spec: A-15 ("read_exact, fail closed").
fn fill<R: RandomSource>(rng: &mut R, out: &mut [u8]) -> Result<(), PlanError> {
    rng.fill(out).map_err(|_| PlanError::Random)
}

/// Draw every identifier (module documentation, "The draws").
/// Spec: docs/51 §4.3 step 2 (R51-3); [MS-DTYP] 2.4.2.4; [MS-ADTS]
/// 3.1.1.5.2.4; A-15; A-77.
fn draw<R: RandomSource>(rng: &mut R, objects: usize) -> Result<Draws, PlanError> {
    let mut sub_octets = [0u8; 12];
    fill(rng, &mut sub_octets)?;
    let mut sub = [0u32; 3];
    for (value, chunk) in sub.iter_mut().zip(sub_octets.chunks_exact(4)) {
        let bytes: [u8; 4] = chunk.try_into().map_err(|_| PlanError::Random)?;
        *value = u32::from_be_bytes(bytes);
    }
    let mut guids = Vec::with_capacity(objects);
    let mut seen = BTreeSet::new();
    for _ in 0..objects {
        let mut packet = [0u8; GUID_PACKET_LEN];
        fill(rng, &mut packet)?;
        // [MS-ADTS] 3.1.1.5.2.4: "This value MUST NOT be the NULL GUID";
        // docs/51 §4.3 step 2: distinct from each other.
        if packet == [0u8; GUID_PACKET_LEN] || !seen.insert(packet) {
            return Err(PlanError::RandomUnusable);
        }
        guids.push(Guid::from_packet(&packet));
    }
    let mut node = [0u8; 16];
    fill(rng, &mut node)?;
    if node == [0u8; 16] {
        return Err(PlanError::RandomUnusable);
    }
    let mut key = Zeroizing::new([0u8; INTEGRITY_KEY_LEN]);
    fill(rng, key.as_mut_slice())?;
    Ok(Draws {
        sub,
        guids,
        node_id: NodeId(node),
        key: IntegrityKeyMaterial(key),
    })
}

/// `domain ‖ rid`. Spec: [MS-SAMR] 3.1.1.9.2 ("concatenating that value
/// with the account domain security identifier").
fn principal_sid(domain: &Sid, rid: u32) -> Result<Sid, PlanError> {
    let mut sub = domain.sub_authority().to_vec();
    sub.push(rid);
    Sid::new(domain.identifier_authority(), &sub).map_err(|_| PlanError::Sid)
}

/// A child DN: `att=value` prepended to the parent's DN.
/// Spec: [MS-ADTS] 3.1.1.1.4 ("the RDN of the child, followed by "," and
/// the DN of the parent"); directory-pip `dn_of` (the canonical form).
fn child_dn(att: &str, value: &str, parent: &Dn) -> Dn {
    let mut rdns = Vec::with_capacity(parent.rdns().len() + 1);
    rdns.push(format!("{att}={value}"));
    rdns.extend(parent.rdns().iter().cloned());
    Dn::new(rdns)
}

/// What a planned object is, before its SD and stamps.
struct Spec<'a> {
    role: ObjectRole,
    class: &'a ClassIds,
    class_name: &'static str,
    parent: Option<usize>,
    rdn_att: &'static str,
    rdn: String,
    rid: RidSource,
    sam: Option<String>,
    values: Vec<(AttrId, Vec<Vec<u8>>)>,
}

impl Plan {
    /// Build the plan (module documentation): check the input (step 1),
    /// draw the identifiers (step 2), compute the objects with their
    /// descriptors (step 5), the policy (step 6), the configuration files
    /// (step 7, each parsed back) and the manifest (step 8, parsed back).
    /// Nothing is written.
    ///
    /// # Errors
    /// [`PlanError`].
    ///
    /// Spec: docs/51 §4.3 steps 1-8; module documentation.
    pub fn build<R: RandomSource>(
        input: &DomainInput,
        now: KerberosTime,
        rng: &mut R,
    ) -> Result<Plan, PlanError> {
        let checked = input.check().map_err(PlanError::Input)?;
        let schema = ad_schema::phase1().map_err(|_| PlanError::Schema)?;
        let ids = SchemaIds::resolve(&schema).map_err(|_| PlanError::Schema)?;
        let n = &input.names;
        let object_count = 9 + usize::from(n.workstations_ou.is_some()) + n.first_admins.len();
        let draws = draw(rng, object_count)?;

        let dstime = dstime_of(&now).ok_or(PlanError::Time)?;
        let pwd_last_set = filetime(&now).ok_or(PlanError::Time)?;
        let stamp = integer64(dstime);

        // The domain SID: S-1-5-21-r1-r2-r3 ([MS-DTYP] 2.4.2.4).
        let [r1, r2, r3] = draws.sub;
        let domain_sid = Sid::new(SECURITY_NT_AUTHORITY, &[SECURITY_NT_NON_UNIQUE, r1, r2, r3])
            .map_err(|_| PlanError::Sid)?;

        // The RIDs of the counter, in creation order (module documentation).
        let admins = n.first_admins.len();
        let counter_rid = |k: usize| -> Result<u32, PlanError> {
            let value = RID_FIRST
                .checked_add(u64::try_from(k).map_err(|_| PlanError::Sid)?)
                .filter(|v| *v < RID_END_EXCLUSIVE)
                .ok_or(PlanError::Sid)?;
            u32::try_from(value).map_err(|_| PlanError::Sid)
        };
        let rid_dc = counter_rid(0)?;
        let rid_ldap = counter_rid(1)?;
        let rid_admin_svc = counter_rid(2)?;
        let rid_changepw_svc = counter_rid(3)?;
        let rid_admins: Vec<u32> = (0..admins)
            .map(|i| counter_rid(4 + i))
            .collect::<Result<_, _>>()?;
        let rid_tier0 = counter_rid(4 + admins)?;
        let rid_bootstrap = counter_rid(5 + admins)?;
        let tier0_sid = principal_sid(&domain_sid, rid_tier0)?;
        let bootstrap_sid = principal_sid(&domain_sid, rid_bootstrap)?;

        let realm_text = checked.realm.as_str().to_owned();
        let fqdn = input.dc_fqdn.as_str();
        let ldap_spn = format!("{LDAP_SERVICE_CLASS}/{fqdn}");
        let admin_spn = format!("{ADMIN_SERVICE_CLASS}/{fqdn}");
        // RFC 3244 §2: "the service principal kadmin/changepw@REALM" — the
        // two components of keyd-types' one definition, joined with "/" as
        // an SPN value (docs/47 §9.1: "the single SPN split on '/'").
        let changepw_spn = CHANGE_PASSWORD_SERVICE_NAME.join("/");
        let flags = |v: u32| vec![integer32(v)];
        let never = || vec![integer64(ACCOUNT_EXPIRES_NEVER)];

        // The specs, in creation order. Parents are indexes into the list.
        let mut specs: Vec<Spec<'_>> = Vec::with_capacity(object_count);
        let root_label =
            checked
                .naming_context
                .labels()
                .first()
                .cloned()
                .ok_or(PlanError::Input(InputError::new(
                    "naming-context",
                    crate::input::InputErrorKind::NamingContext,
                )))?;
        specs.push(Spec {
            role: ObjectRole::NamingContextRoot,
            class: &ids.domain_dns,
            class_name: "domainDNS",
            parent: None,
            rdn_att: NC_RDN_ATTRIBUTE,
            rdn: root_label.clone(),
            rid: RidSource::None,
            sam: None,
            // dc = n1 (docs/51 §4.3 step 5; A-53: the rest of the DN is
            // configuration); objectSid = the domain SID ([MS-DTYP]
            // 2.4.2.4; docs/46 §4.4: may on domainDNS via samDomainBase).
            values: vec![
                (ids.dc, vec![text(&root_label)]),
                (ids.object_sid, vec![domain_sid.encode()]),
            ],
        });
        specs.push(Spec {
            role: ObjectRole::Tier0Ou,
            class: &ids.organizational_unit,
            class_name: "organizationalUnit",
            parent: Some(0),
            rdn_att: "ou",
            rdn: n.tier0_ou.clone(),
            rid: RidSource::None,
            sam: None,
            values: vec![(ids.ou, vec![text(&n.tier0_ou)])],
        });
        let tier0_ou = 1usize;
        let workstations_ou = match &n.workstations_ou {
            Some(ws) => {
                specs.push(Spec {
                    role: ObjectRole::WorkstationsOu,
                    class: &ids.organizational_unit,
                    class_name: "organizationalUnit",
                    parent: Some(0),
                    rdn_att: "ou",
                    rdn: ws.clone(),
                    rid: RidSource::None,
                    sam: None,
                    values: vec![(ids.ou, vec![text(ws)])],
                });
                Some(specs.len() - 1)
            }
            None => None,
        };
        // krbtgt: [MS-SAMR] 2.2.1.14 (RID 0x1F6), 3.1.1.6 item 14 (the name),
        // item 20 (N), item 22 (no ACCOUNTDISABLE), 3.1.1.8.1 item 1.2
        // (accountExpires default); no pwdLastSet (docs/51 §4.3 step 5).
        specs.push(Spec {
            role: ObjectRole::Krbtgt,
            class: &ids.user,
            class_name: "user",
            parent: Some(tier0_ou),
            rdn_att: "cn",
            rdn: KRBTGT_NAME.to_owned(),
            rid: RidSource::Fixed(DOMAIN_USER_RID_KRBTGT),
            sam: Some(KRBTGT_NAME.to_owned()),
            values: vec![
                (ids.cn, vec![text(KRBTGT_NAME)]),
                (ids.sam_account_name, vec![text(KRBTGT_NAME)]),
                (ids.user_account_control, flags(ADS_UF_NORMAL_ACCOUNT)),
                (ids.account_expires, never()),
            ],
        });
        // The DC: ST ("computer account for a DC", docs/47 §4.1; [MS-SAMR]
        // 3.1.1.6 items 20, 23), sAMAccountName = name‖"$" (item 11), no
        // SPN and no key set in phase 1 (docs/51 §4.3 step 5);
        // primaryGroupID is not in the phase-1 schema (A-79 / Q-298 item 2).
        let computer = |role, name: &str, uac: u32, spn: Option<&str>, rid: u32| {
            let sam = computer_sam(name);
            let mut values = vec![
                (ids.cn, vec![text(name)]),
                (ids.sam_account_name, vec![text(&sam)]),
                (ids.user_account_control, flags(uac)),
                (ids.account_expires, never()),
                (ids.dns_host_name, vec![text(fqdn)]),
            ];
            if let Some(spn) = spn {
                values.push((ids.service_principal_name, vec![text(spn)]));
            }
            Spec {
                role,
                class: &ids.computer,
                class_name: "computer",
                parent: Some(tier0_ou),
                rdn_att: "cn",
                rdn: name.to_owned(),
                rid: RidSource::Counter(rid),
                sam: Some(sam),
                values,
            }
        };
        // Task DN10b: the DC's own host record — its addresses as the
        // internal host-address attribute (four octets each, RFC 1035
        // §3.4.1; ad-schema `HOST_ADDRESS`), written with the DC account's
        // create through the one checker's host-record rule (docs/54 §3.1:
        // "written in `provision domain` only"; docs/questions/Q-1003 item 2).
        let mut dc = computer(
            ObjectRole::DcComputer,
            &n.dc_name,
            ADS_UF_SERVER_TRUST_ACCOUNT,
            None,
            rid_dc,
        );
        dc.values.push((
            HOST_ADDRESS,
            checked
                .dc_addresses
                .iter()
                .copied()
                .map(host_address_value)
                .collect(),
        ));
        specs.push(dc);
        // The service objects: one SPN each, host in lower case (docs/10
        // §5ב / A-46; RFC 4120 §6.2.1 as cited in docs/47 §1.3); WT
        // (docs/51 §4.3 step 5); the admin class per A-73.
        specs.push(computer(
            ObjectRole::LdapService,
            &n.ldap_service_name,
            ADS_UF_WORKSTATION_TRUST_ACCOUNT,
            Some(&ldap_spn),
            rid_ldap,
        ));
        specs.push(computer(
            ObjectRole::AdminService,
            &n.admin_service_name,
            ADS_UF_WORKSTATION_TRUST_ACCOUNT,
            Some(&admin_spn),
            rid_admin_svc,
        ));
        // Task K9 — the change-password service object (docs/53 §5.2: a
        // dedicated service object at provisioning, as the LDAP and admin
        // service objects are, with the SPN `kadmin/changepw`; RFC 3244 §2): WT, the DC's
        // dNSHostName (a computer requires one — Q-355 item 3), its one SPN
        // `kadmin/changepw` — a fixed instance, not a host (RFC 4120 §6.2,
        // NT-SRV-INST), which only its provisioning claim may carry
        // (directory-admin `ProvisioningRole::ChangePasswordServiceObject`,
        // docs/questions/Q-972). Its key set `(GUID, ChangePasswordService)`
        // comes from the ceremony's `create_key` (docs/53 §5.2).
        specs.push(computer(
            ObjectRole::ChangePasswordService,
            &n.change_password_service_name,
            ADS_UF_WORKSTATION_TRUST_ACCOUNT,
            Some(&changepw_spn),
            rid_changepw_svc,
        ));
        // The first administrators: N enabled (no D — docs/51 §4.3 step 5:
        // "enabled, no key set until the ceremony, so it cannot
        // authenticate"), pwdLastSet = the provisioning time (docs/47 §9.2;
        // A-79), accountExpires never.
        let first_admin_index = specs.len();
        for (i, (sam, rid)) in n.first_admins.iter().zip(&rid_admins).enumerate() {
            specs.push(Spec {
                role: ObjectRole::FirstAdmin(i),
                class: &ids.user,
                class_name: "user",
                parent: Some(tier0_ou),
                rdn_att: "cn",
                rdn: sam.clone(),
                rid: RidSource::Counter(*rid),
                sam: Some(sam.clone()),
                values: vec![
                    (ids.cn, vec![text(sam)]),
                    (ids.sam_account_name, vec![text(sam)]),
                    (ids.user_account_control, flags(ADS_UF_NORMAL_ACCOUNT)),
                    (ids.account_expires, never()),
                    (ids.pwd_last_set, vec![integer64(pwd_last_set)]),
                ],
            });
        }
        let admin_guids: Vec<Guid> = draws
            .guids
            .get(first_admin_index..first_admin_index + admins)
            .ok_or(PlanError::RandomUnusable)?
            .to_vec();
        // The Tier-0 group: 0x80000002, member = the first administrators
        // (docs/51 §4.3 step 5; docs/46 §8.2).
        specs.push(Spec {
            role: ObjectRole::Tier0Group,
            class: &ids.group,
            class_name: "group",
            parent: Some(tier0_ou),
            rdn_att: "cn",
            rdn: n.tier0_group.clone(),
            rid: RidSource::Counter(rid_tier0),
            sam: Some(n.tier0_group.clone()),
            values: vec![
                (ids.cn, vec![text(&n.tier0_group)]),
                (ids.sam_account_name, vec![text(&n.tier0_group)]),
                (ids.group_type, flags(PROVISIONED_GROUP_TYPE)),
                (
                    ids.member,
                    admin_guids.iter().copied().map(object_ref).collect(),
                ),
            ],
        });
        // The bootstrap group: empty, in the workstations OU if there is
        // one (docs/51 §4.3 step 5), else under the NC root
        // (docs/questions/Q-376 item 1).
        specs.push(Spec {
            role: ObjectRole::BootstrapGroup,
            class: &ids.group,
            class_name: "group",
            parent: Some(workstations_ou.unwrap_or(0)),
            rdn_att: "cn",
            rdn: n.bootstrap_group.clone(),
            rid: RidSource::Counter(rid_bootstrap),
            sam: Some(n.bootstrap_group.clone()),
            values: vec![
                (ids.cn, vec![text(&n.bootstrap_group)]),
                (ids.sam_account_name, vec![text(&n.bootstrap_group)]),
                (ids.group_type, flags(PROVISIONED_GROUP_TYPE)),
            ],
        });
        if specs.len() != object_count || draws.guids.len() != object_count {
            return Err(PlanError::RandomUnusable);
        }

        // Descriptors, SIDs, DNs and stamps, parents first.
        let root_sd = domain_root_descriptor(tier0_sid, &ids).map_err(|_| PlanError::Descriptor)?;
        let mut objects: Vec<PlannedObject> = Vec::with_capacity(object_count);
        for (spec, guid) in specs.into_iter().zip(draws.guids.iter().copied()) {
            let (parent_guid, dn, descriptor) = match spec.parent {
                None => (None, checked.naming_context.dn().clone(), root_sd.clone()),
                Some(index) => {
                    let parent = objects.get(index).ok_or(PlanError::Descriptor)?;
                    // A-84 / docs/51 §10: the runtime computation, owner =
                    // the Tier-0 group (Q-376 item 2).
                    let sd = new_object_descriptor(&parent.descriptor, spec.class.guid, &tier0_sid)
                        .map_err(|_| PlanError::Descriptor)?;
                    (
                        Some(parent.guid),
                        child_dn(spec.rdn_att, &spec.rdn, &parent.dn),
                        sd,
                    )
                }
            };
            let sid = match spec.rid {
                RidSource::None if spec.role == ObjectRole::NamingContextRoot => Some(domain_sid),
                RidSource::None => None,
                RidSource::Fixed(rid) | RidSource::Counter(rid) => {
                    Some(principal_sid(&domain_sid, rid)?)
                }
            };
            let mut attributes = spec.values;
            if let (Some(sid), true) = (sid, spec.role != ObjectRole::NamingContextRoot) {
                attributes.push((ids.object_sid, vec![sid.encode()]));
            }
            attributes.push((ids.when_created, vec![stamp.clone()]));
            attributes.push((ids.when_changed, vec![stamp.clone()]));
            attributes.push((
                ids.nt_security_descriptor,
                vec![descriptor.encode().map_err(|_| PlanError::Descriptor)?],
            ));
            objects.push(PlannedObject {
                role: spec.role,
                guid,
                parent: parent_guid,
                class_name: spec.class_name,
                classes: spec.class.chain.clone(),
                rid: spec.rid,
                sid,
                dn,
                sam_account_name: spec.sam,
                descriptor,
                attributes,
            });
        }

        // Step 6: the policy, encoded and decoded back.
        let object_dn = |role: ObjectRole| {
            objects
                .iter()
                .find(|o| o.role == role)
                .map(|o| o.dn.clone())
                .ok_or(PlanError::Policy)
        };
        let policy = domain_policy(&DomainPolicyInput {
            tier0_group: tier0_sid,
            bootstrap_group: bootstrap_sid,
            nc_root: checked.naming_context.dn().clone(),
            tier0_ou: object_dn(ObjectRole::Tier0Ou)?,
            classes: CreatableClasses {
                user: ids.user.guid,
                computer: ids.computer.guid,
                group: ids.group.guid,
                organizational_unit: ids.organizational_unit.guid,
                container: ids.container.guid,
            },
        })
        .map_err(|_| PlanError::Policy)?;
        let policy_file = policy.encode().map_err(|_| PlanError::Policy)?;
        if DevelopmentPolicy::decode(&policy_file).as_ref() != Ok(&policy) {
            return Err(PlanError::Policy);
        }

        // Step 7: the configuration files, each parsed back.
        let configs = domain_configs(input, &draws.node_id);
        for file in &configs {
            file.parse_back()
                .map_err(|e| PlanError::Config(file.daemon, e))?;
        }

        // Task DN10b: the provisioning session's zone — the registrable
        // networks of dird's own parsed file (one rule set, dird's: the
        // session and dird judge a host record against the same networks),
        // and every DC address registrable in them by the write checker's own
        // rule (directory-pip `registrable`), refused here with the flag's
        // name before anything is written; the checker judges them again at
        // the write (docs/54 §3.1, §5.5; docs/questions/Q-1003 item 2, Q-1014).
        let dns_registration = dird_dns_registration(&configs)?;
        if !checked
            .dc_addresses
            .iter()
            .all(|address| registrable(*address, dns_registration.networks()))
        {
            return Err(PlanError::Input(InputError::new(
                "dc-address",
                InputErrorKind::DcAddressNotRegistrable,
            )));
        }

        // Step 8: the manifest, through the builder (which parses its own
        // canonical text, A-86).
        let guid_of = |role: ObjectRole| {
            objects
                .iter()
                .find(|o| o.role == role)
                .map(|o| o.guid)
                .ok_or(PlanError::RandomUnusable)
        };
        // A-102 (docs/52 §2 row 37, N4): each first administrator's
        // string-to-key salt, by the directory's own function (R47-4) — the
        // salt `first-admin-secret` derives the same way and presents — is
        // written into the manifest (a required key — A-105, Q-473), so that
        // keyadm's ceremony grant binds exactly it without keyadm linking the
        // directory code (D104).
        let first_admin_salts = n
            .first_admins
            .iter()
            .map(|sam| {
                account_salt(&checked.realm, AccountKind::User, sam)
                    .map(|salt| salt.as_str().to_owned())
            })
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| PlanError::Salt)?;
        let manifest = Manifest::new(&ManifestFields {
            realm: realm_text,
            domain_sid,
            naming_context: checked.naming_context.labels().to_vec(),
            dc_fqdn: fqdn.to_owned(),
            krbtgt: guid_of(ObjectRole::Krbtgt)?,
            ldap_service: guid_of(ObjectRole::LdapService)?,
            admin_service: guid_of(ObjectRole::AdminService)?,
            change_password_service: guid_of(ObjectRole::ChangePasswordService)?,
            first_admins: admin_guids
                .iter()
                .copied()
                .zip(n.first_admins.clone())
                .collect(),
            first_admin_salts,
        })
        .map_err(PlanError::Manifest)?;
        if Manifest::parse(manifest.encode().as_bytes()).as_ref() != Ok(&manifest) {
            return Err(PlanError::ManifestRoundTrip);
        }

        Ok(Plan {
            now,
            realm: checked.realm,
            naming_context: checked.naming_context,
            domain_sid,
            node_id: draws.node_id,
            key: draws.key,
            objects,
            policy,
            policy_file,
            configs,
            manifest,
            paths: input.paths.clone(),
            store_owner: Owner::from(input.accounts.dird),
            dns_registration,
        })
    }

    /// The integrity key (installer only). Spec: docs/51 §4.3 step 4.
    pub(crate) fn integrity_key(&self) -> &IntegrityKeyMaterial {
        &self.key
    }

    /// The planned object of `role`, if any.
    #[must_use]
    pub fn object(&self, role: ObjectRole) -> Option<&PlannedObject> {
        self.objects.iter().find(|o| o.role == role)
    }

    /// The number of RID-counter takes the store write makes (every
    /// security principal but krbtgt).
    #[must_use]
    pub fn counter_rids(&self) -> usize {
        self.objects
            .iter()
            .filter(|o| matches!(o.rid, RidSource::Counter(_)))
            .count()
    }
}
