# Active Directory attack classes

This document lists the known families of weakness in Windows Active Directory deployments, gives
Domainfort's design answer for each, and states whether that answer is enforced by code today or
only designed.

## Why a domain controller is the target

A domain controller holds the keys from which every credential in the domain is derived. Whoever
controls it can issue tickets for any user, computer or service, change any group membership or
policy, and, through policy, run code on every member. Compromise of one domain controller is
compromise of the whole organisation.

Most of the weaknesses below are not implementation bugs. They follow from design choices and from
defaults kept for backward compatibility. Four roots recur:

1. **Privilege granted from data a client can influence** — an attribute, a link, a name or an
   identifier that the requester, or someone it controls, can write.
2. **One all-powerful identity on the server** — whatever runs the domain controller also controls
   its keys.
3. **Readable secrets at rest** — the directory database holds every password hash.
4. **Legacy defaults** — weak protocols and options that stay available for old clients.

Domainfort answers each root structurally. Privilege is derived only from authoritative directory
facts. Processes are separated, and `keyd` is the only holder of long-term keys. The directory store
cannot hold secrets. Weak options have no code path. The aim is to remove a whole class **by
construction**, not to switch it off **by configuration**: an option that does not exist cannot be
re-enabled by a mistaken setting, a compromised administrator or a downgrade. Several weaknesses
published after the design was written fell into classes it had already closed (name confusion,
delegation flaws, fallback to NTLM).

Closing a class is not the same as zero risk. What remains is listed under
[Residual risks](#residual-risks).

## How to read the tables

- **Weakness class** is described generically. Public nicknames are given where the project's design
  sources use them; CVE numbers are omitted. This document describes classes and defences, not
  attack procedures.
- **Implemented** means the named crate enforces the answer today. This includes classes that are
  impossible today because the code has no path for them; the row then names the crate that makes
  the path absent and gives the design for when the feature is added.
- **Designed** means the answer is part of the design and will be built in the named phase of the
  [roadmap](STATUS.md#roadmap).
- **Tier 0** is the set of objects and accounts that control the directory, the KDC, `keyd` or the
  policy. Tier-0 objects are writable only by tier-0 subjects, whatever an ACL says.

Domainfort is pre-alpha; see [STATUS.md](STATUS.md). The architecture these answers rely on is in
[ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY-MODEL.md](SECURITY-MODEL.md).

## Insecure options with no code path

The following options do not exist in Domainfort. They are not disabled defaults: there is no
setting, flag or compatibility mode that brings them back, and a client that asks for one is
refused. For protocols that are not built yet, the rule binds their implementation.

| Absent option | Why | What it may break, and the alternative |
|---|---|---|
| NTLM (all versions) and LM, including NTLM inside SPNEGO and NTLM pass-through | pass-the-hash, relay, offline cracking | access by IP address, old applications, computers outside the domain — use names, and restrict NTLM on clients |
| SMB 1 and every dialect older than SMB 3.1.1 | the source of wormable vulnerability families | very old devices — no alternative |
| NetBIOS, WINS, LLMNR, mailslots | name-resolution poisoning | short-name lookup without DNS — set a DNS suffix through policy |
| RC4-HMAC, DES and 3DES in Kerberos | weak ciphers, downgrade, cheap offline attacks on service tickets | old keytabs, applications with a fixed RC4 type — regenerate keytabs with AES |
| Turning off Kerberos pre-authentication | offline guessing of AS replies | — |
| Unconstrained delegation | theft of forwarded ticket-granting tickets | old services that depend on it — resource-based delegation |
| A PAC without its full signature set | PAC forgery | — |
| LDAP simple bind with a clear-text password; SASL DIGEST-MD5 | password disclosure | printers and scanners that search LDAP — LDAPS |
| Anonymous LDAP access beyond the rootDSE | directory enumeration | — |
| Unauthenticated RPC (except the endpoint-mapper lookup); anonymous or guest SMB access | information gathering | old tools — no alternative |
| RPC authentication below packet privacy; RPC over UDP; RPC over HTTP; DCOM | attack surface without a proven need | — |
| Netlogon without AES and sealing | the class of flaws behind well-known secure-channel attacks | — |
| Stored passwords in Group Policy preferences | the decryption key is public | local administrator passwords |
| Unsigned DNS dynamic updates; open zone transfer; record creation by ordinary users | DNS poisoning and enumeration | — |

SMB compression, multichannel and RDMA are also left out of the first SMB implementation. The
per-protocol profile is in [PROTOCOLS.md](PROTOCOLS.md).

## 1. Kerberos and protocol-level attacks

| Weakness class | Why it exists in typical AD deployments | Domainfort's design answer | Status |
|---|---|---|---|
| Pre-authentication not required, so AS replies can be guessed offline (AS-REP roasting) | An account option turns pre-authentication off for old clients | Pre-authentication is mandatory for every principal: the FAST encrypted challenge, or the encrypted timestamp for the computer bootstrap only. The account flag that disables it cannot be written | **Implemented** — `kdc`, `keyd`; the flag is refused by the write invariants in `directory-admin` |
| Cheap offline cracking of service tickets (Kerberoasting) | RC4 service tickets; service accounts with human-chosen passwords | Only the four AES encryption types exist (17, 18, 19, 20). In phase 1 only computer objects can carry a service principal name. Service accounts get random passwords as managed service accounts; accounts with a service name get a minimum password length | **Implemented:** AES only (`krb-crypto`, `keyd-types`); service names on computers only (`ad-schema`). **Designed:** managed service accounts — phase 3; the minimum length. A residual remains against AES |
| Forged ticket-granting tickets from a stolen `krbtgt` key (golden ticket) | The `krbtgt` key sits in the domain controller's database and memory | The `krbtgt` key exists only inside `keyd`, and no operation returns it. It is rotated only on a dual-controlled decision. Hardware security modules hold the most critical keys | **Implemented:** custody and dual-controlled rotation (`keyd`). **Designed:** HSM custody. Residual |
| Forged service tickets from a service key (silver ticket) | Service keys are exposed; services do not validate the PAC | Service keys exist only in `keyd`, which also verifies service tickets for the domain controller's own services. The PAC carries every signature and can be validated against the KDC | **Implemented:** service keys and ticket verification in `keyd`. **Designed:** PAC — phase 2 |
| PAC forgery; a PAC accepted without its full signatures | Signature checks were added late, and some paths skip them | The PAC is always present, carries the full signature set and is always verified; no path skips a signature. It is built inside `keyd` from directory facts | **Designed** — phase 2. Today no PAC is issued, and the "no PAC" account flag cannot be written (`directory-admin`) |
| Account-name spoofing through the computer `$` convention (noPac) | Name lookup falls back across separate name forms; ordinary users may create computer accounts by default | One principal namespace: every name an object answers to is one key in one unique index, so `x` and `x$` cannot name two objects. One lookup, with no `$`, UPN or canonicalisation fallback. After provisioning, computer accounts are created only through the administration plane under a policy decision, so there is no per-user creation quota to abuse. The PAC will bind the requester | **Implemented** — `principal-names`, `directory-pip`, `directory-admin`. **Designed:** requester binding in the PAC — phase 2. See [PRINCIPAL-NAMESPACE.md](PRINCIPAL-NAMESPACE.md) |
| Unconstrained delegation and theft of forwarded tickets | Services are trusted to receive users' ticket-granting tickets | No unconstrained delegation. Forwarded and proxy tickets are refused, and the delegation account flags cannot be written | **Implemented** — `kdc`, `directory-admin` |
| Flaws in constrained-delegation validation (CheckSum) | The service-for-user rules are complex | Phase 1 has no service-for-user extension and no constrained delegation. When added: constrained and resource-based delegation only, each target a policy decision, the constraints validated structurally | **Implemented:** no code path (`kdc`). **Designed:** phase 3 |
| Abuse of resource-based constrained delegation | Users can create computer accounts and write the delegation attribute of objects they control | No per-user computer creation. The delegation attribute is not in the phase-1 schema, so the store refuses any write to it. When added: a tight ACL, the tier invariant, and a policy decision per target | **Implemented:** attribute absent (`ad-schema`, `dirstore`). **Designed:** phase 3 |
| Adding a key credential to another account (shadow credentials) | The key-credential attribute is writable by delegated principals | The attribute is not in the phase-1 schema. When key-based logon is added: a tight ACL, the tier invariant, and audit | **Implemented:** attribute absent (`ad-schema`, `dirstore`). **Designed:** with PKINIT, not yet scheduled |
| The replication interface used to read secrets or inject changes (DCSync, DCShadow) | Replication rights are delegated to accounts that are not domain controllers | No replication interface exists, and the store holds no secrets. Future replication runs only between domain controllers, over mutually authenticated TLS with domain-controller certificates | **Implemented:** no code path (`dirstore` has no replication interface). **Designed:** phase 4 |
| NTLM relay, including coerced authentication (PetitPotam and similar) | NTLM is kept for compatibility | NTLM does not exist | **Implemented** — no crate contains NTLM |
| Kerberos relay | Binds are not tied to the TLS channel; integrity without encryption | The Kerberos bind to LDAP requires channel binding to the TLS connection. SMB encryption is mandatory | **Designed:** LDAP — phase 1 (see [LDAP-GSSAPI-BIND.md](LDAP-GSSAPI-BIND.md)); SMB — phase 2. Today LDAP refuses every SASL mechanism (`ldap`) |
| Pass-the-hash | NT hashes are stored and accepted by NTLM and RC4 | Users have no NT hash. Without NTLM and RC4, a hash is not a logon credential | **Implemented** — AES types only (`keyd-types`, `krb-crypto`); secret attributes cannot be stored (`dirstore`) |
| Netlogon secure-channel flaws (Zerologon; channels without sealing) | Legacy secure-channel cryptography kept for compatibility | Channels without AES or without sealing have no code path; the secure channel is based on Kerberos; rate limits apply | **Designed** — phase 2 |
| Passwords stored in Group Policy preferences | The decryption key is published | Refused when written; local administrator passwords replace them | **Designed** — phase 3 |
| Poisoning of directory-integrated DNS | Authenticated users may create DNS records | Unsigned updates and updates over UDP are refused. Each record is updatable only by its owner; ordinary users cannot create records | **Implemented:** unsigned and UDP updates refused (`dns-daemon`). **Designed:** the owner check in `dird` — phase 1 |
| Broadcast name-resolution poisoning (LLMNR, NBT-NS) | Fallback when DNS does not answer | Not implemented; the guidance is to disable it on members | **Implemented** — no code path |
| Reflection and amplification through the UDP LDAP ping | Windows locates domain controllers with an unauthenticated UDP query | The single query and a minimal reply only, with a size cap, per-source rate limits, internal interfaces only, never exposed to the internet | **Designed** — phase 2; no UDP LDAP listener exists today. The limiter exists (`rate-limit`) |
| Memory-safety bugs in protocol parsers (for example SMBGhost, in SMB compression code) | Parsers in memory-unsafe languages; complex optional features | Rust with `unsafe` forbidden in every crate; strict, bounded parsers, each with a fuzz target; no SMB compression | **Implemented** — `parse-asn1`, `parse-ldap`, `parse-dns`, `parse-kpasswd`, `parse-x509`; continuous fuzzing is not running yet |

## 2. Privilege from names, links and attributes a client can influence

This is the most frequent root in recent findings: Active Directory grants privilege based on a name,
a link or an identifier that an attacker can influence. Renaming an account (noPac), a writable
successor link (BadSuccessor), an injected SID (SID history), Unicode in account names and duplicate
service names all share it. Domainfort's answer covers the class: one strict, canonical treatment of
every identifier, with enforced uniqueness and no ambiguous names, and privilege decided only from
authoritative sources — never from a name or link the client influenced. The detailed design is in
[PRINCIPAL-NAMESPACE.md](PRINCIPAL-NAMESPACE.md).

| Weakness class | Why it exists in typical AD deployments | Domainfort's design answer | Status |
|---|---|---|---|
| A writable link that makes one account inherit another's privileges (BadSuccessor) | A new account-migration feature let the KDC grant privileges from an attribute the client could write, with no independent check | No feature grants privilege from a client-writable link or attribute. A ticket's identity comes only from the directory's own authenticated statement of the name resolution. Every new feature is reviewed for "can a writable attribute grant privilege?" and is not added until it passes | **Implemented** for the phase-1 KDC — `name-attestation`, `keyd`, `directory-pip`. The review rule applies to every future feature |
| Unicode handling in account names (KerberLoss) | Two names that look different map to one account, or the reverse | Phase 1 accepts printable-ASCII names only and compares them through one fold function; a name with any other octet has no key and is refused | **Implemented** — `principal-names`, `dirstore`. Open design question: a Unicode normalisation rule |
| Improper authorization around names (ResetNightmare) | Authorization is decided in several places, from names | One central policy decision point, deny by default; identity from one authoritative source | **Implemented** — `pdp`, `directory-pip` |
| Duplicate service principal names, so a ticket is issued under the wrong key | Uniqueness is checked per attribute, not across all name forms; fallback to NTLM; RC4 | One unique key space for every principal name — account name, service name, UPN, DNS host name. No NTLM fallback; AES only | **Implemented** — `principal-names`, `ad-schema` (the unique principal-name key), `dirstore` |
| The same principal seen differently across protocols (Kerberos, LDAP, certificates, UPN, account name, SID) | Each protocol maps identities its own way; mismatches cause identity confusion | One principal is one authoritative identity in every protocol; mappings are strong and explicit, never implicit | **Implemented** for Kerberos and the directory — `principal-names`, `name-attestation`. **Designed:** certificate mapping — phase 6 |
| Injected SID history; SID filtering turned off across trusts | Trust semantics accept SIDs from another forest | Trusts are out of scope. When added: SID filtering mandatory, no SID history, foreign principals checked | **Implemented:** no SID history attribute in the schema and the trust-account flag cannot be written (`ad-schema`, `directory-admin`). **Designed:** beyond phase 6 |
| Stored data later interpreted or trusted (service names, SIDs, attribute content, constructed attributes) | Values written by one party are re-read as input to a decision | Strict validation of what is stored. Attribute content is never interpreted or executed. Constructed attributes are computed from trusted state only and never stored. Every write passes one checked write path | **Implemented** — `dirstore` (schema-validated writes, derived attributes never stored, per-record integrity tag), `directory-admin` |

## 3. Secrets at rest and in memory

| Weakness class | Why it exists in typical AD deployments | Domainfort's design answer | Status |
|---|---|---|---|
| Offline extraction of every credential from the directory database, a backup or a VM snapshot | The database holds every password hash | The directory store holds no user hashes: an attribute in the secret class can never be written to it. Key material lives only in `keyd`. A stolen store is not a credential compromise | **Implemented** — `dirstore`, `keyd` |
| Keys readable in a raw disk image or VM snapshot | Keys at rest are not bound to hardware | Keys are sealed to an HSM or TPM and cannot be opened from a raw snapshot | **Designed.** The sealed key-store format exists (`keyd-types`); sealing and the hardware anchor await decisions (see [STATUS.md](STATUS.md)). Today keys are held in memory only |
| A local recovery administrator on the domain controller used as a backdoor (DSRM) | A separate local account exists for recovery | No such account. Recovery and maintenance go through a controlled, audited path | **Implemented:** no local recovery account exists. **Designed:** the recovery path — phase 4 |
| Delegated read of managed service account passwords (gMSA) | Delegated principals can read the password blob | The secret is computed in `keyd` and released only after a policy decision; it sits in the secret attribute class | **Designed** — phase 3. The secret attribute class is enforced today (`pdp`, `dirstore`) |
| Local administrator passwords readable as an attribute (older LAPS, in clear text) | A clear-text attribute readable through delegation | No clear-text secret attribute is readable through delegation; release is authorised and audited | **Designed** — phase 3 |
| "Full control of the domain controller equals the domain" | No separation between running the domain controller and controlling its keys | `keyd` is a separate process under its own account. A compromise of the KDC, a network front or `dird` does not yield long-term keys | **Implemented** — `keyd`, `keyd-daemon`. The superuser on the host is contained only once hardware custody exists (designed); see [KEY-CUSTODY.md](KEY-CUSTODY.md) |
| Reading secrets from process memory through a debug privilege | A privilege grants access to every process's memory | Process separation; secrets only in `keyd`; daemons are non-dumpable, and `keyd` locks its memory | **Implemented** — `daemon-sandbox`, `keyd-daemon` |

## 4. Persistence and over-broad privileges

Public guidance from CISA and NSA reaches the same conclusion as this design: the built-in
permissions of Active Directory are broader than needed. In Domainfort, no single right or group
silently equals control of the domain. Administration is a fine-grained policy decision on the
administration plane, not membership in a powerful group.

| Weakness class | Why it exists in typical AD deployments | Domainfort's design answer | Status |
|---|---|---|---|
| One protected ACL template copied to every privileged account (AdminSDHolder) | A single ACL point propagates to all administrators, so one write gives persistence | No propagating ACL point. Tier-0 protection is an invariant checked before, and independently of, the ACL | **Implemented** — `pdp` |
| Changing a class's default security descriptor in the schema | A schema change alters the ACL of every future object of that class | No online schema change path: the schema is compiled data. New objects get no default security descriptor from the schema. Later: schema change is tier 0, with dual approval and validation of the default descriptor | **Implemented** — `ad-schema`, `dirstore`, `directory-admin`. **Designed:** controlled schema change, not yet scheduled |
| Ownership as a hidden path to rewrite an ACL (WriteOwner, WriteDACL) | An object's owner can always rewrite its DACL | Ownership never crosses tiers. The administration plane has a closed set of operations with no operation that changes an ACL or an owner; LDAP is read-only | **Implemented** — `pdp`, `directory-admin`, `ldap` |
| Broad legacy groups and anonymous enumeration | Compatibility groups grant wide read access by default | Deny by default; no legacy access groups; anonymous access is the rootDSE only, from internal networks | **Implemented** — `pdp`, `ldap`; no built-in groups (`provision`, `directory-pip`) |
| A backup right that reads the database and the system secrets | Backing up the domain controller needs a right that reads authentication material | No Windows privilege model; the store holds no secrets. Backups go through an encrypted path that `keyd` takes part in | **Implemented:** no privileges, no secrets in the store (`pdp`, `dirstore`). **Designed:** the backup path — phase 4 |
| A restore right that writes anywhere | Restore needs unrestricted write | Restore is tier 0 only, audited, with integrity checks | **Designed** — phase 4. Records already carry an integrity tag (`dirstore`) |
| Coarse built-in operator groups (server, account, print operators) | Convenience groups that manage services and accounts on the domain controller | No built-in groups; fine-grained policy on the administration plane; the tier invariant | **Implemented** — `provision`, `directory-pip`, `pdp` |
| DNS administrators loading an arbitrary library into the DNS service | A plugin setting loads code into a privileged service | No plugin or library-loading path. The DNS front answers only from a typed, read-only zone image | **Implemented** — `dns-daemon`, `dns-zone` |
| Forced password change of another account | Delegated rights allow resetting a password | Password sets go only through the administration plane: a policy decision, the tier invariant, dual control on tier-0 accounts, and an effect plan | **Implemented** — `directory-admin`, `pdp` |
| Generic write, full control and group-membership rights used to take over objects | Fine-grained ACL edges chain into escalation paths | Closed operation set; the tier invariant; a membership change shows every principal whose tier changes, and a tier-0 change needs a second approver | **Implemented** — `directory-admin`, `pdp` |
| Writing a service name onto an account to crack its ticket (targeted Kerberoasting) | Service-name writes are delegated; target passwords are human-chosen | In phase 1 a service name is single-valued, allowed on computers only, and written through the one checked write path. Later, managed service accounts with random passwords leave nothing to crack | **Implemented:** `ad-schema`, `directory-admin`. **Designed:** phase 3 |

Built-in attack-path analysis, which finds chains of such edges before an attacker does, is
designed and not yet scheduled.

## 5. Remote management and code-execution paths

| Weakness class | Why it exists in typical AD deployments | Domainfort's design answer | Status |
|---|---|---|---|
| Built-in remote management interfaces on the domain controller: service control, remote registry, task scheduler, WMI, DCOM, the print spooler (PrintNightmare) | The domain controller is a general-purpose Windows server and exposes them | None of them is implemented. The domain controller runs the minimum, and administration goes only through the administration plane | **Implemented** — no such interface in any crate; administration through `admin-daemon` |
| Editing a Group Policy object runs code on every computer it applies to | Delegated policy editing and SYSVOL write access | Policy that leads to code execution is tier-controlled. Editing it is a high-tier, signed and audited operation. SYSVOL is served from a signed, immutable image with no write path over SMB, and policy images are released under dual control | **Designed** — phase 3 |

## 6. Ticket theft, revocation and branch offices

| Weakness class | Why it exists in typical AD deployments | Domainfort's design answer | Status |
|---|---|---|---|
| Reuse of a stolen ticket or key (pass-the-ticket, overpass-the-hash) | Inherent in Kerberos: a ticket is usable anywhere until it expires | Reduce the blast radius and detect: bounded ticket lifetimes, mandatory FAST, no forwarded or proxy tickets, a profile like Protected Users for privileged accounts, authentication policy silos that limit where an account may log on, device claims, and channel binding where possible | **Implemented:** FAST, flags and lifetimes per ticket policy, forwarding refused (`kdc`, `keyd`). **Designed:** silos and device claims, not yet scheduled; channel binding for LDAP — phase 1. Reduced, not eliminated |
| Revocation latency: a ticket keeps a group snapshot after access is withdrawn | The ticket carries its authorization data until it expires | The TGS reads the client account again on every request: a disabled, expired or deleted account is refused. One revocation cut-off for password sets applies on every path. The PAC is rebuilt at every TGS. A global re-authentication can be forced | **Implemented:** re-evaluation and the revocation cut-off (`kdc`, `directory-pip`). **Designed:** PAC rebuild — phase 2; forced re-authentication, not yet scheduled |
| A read-only branch domain controller that caches secrets | It caches passwords in a less protected place and has its own `krbtgt` | If a branch mode is added: no sensitive secrets cached by default, no privileged accounts exposed, a scoped key. A KDC proxy is preferred over a read-only domain controller | **Designed**, conditional; KDC proxy — phase 3. The read-only DC account flag cannot be written today (`directory-admin`) |

## 7. Certificate services

Active Directory Certificate Services is one of the largest escalation surfaces in Active Directory.
Its private key is as critical as the `krbtgt` key, so Domainfort extends the same custody model to
it: the key never leaves `keyd`, operations are narrow, and the requester never decides the
identity. Rows use the ESC numbering of public research. No certificate authority exists in the code
today; this whole family is **designed for phase 6** unless a row says otherwise.

| Weakness class | Why it exists in typical AD deployments | Domainfort's design answer | Status |
|---|---|---|---|
| ESC1 — a template lets the requester choose the subject alternative name | Templates allow it for flexibility | The requester never decides identity; the server sets the subject alternative name from the authenticated object | **Designed** — phase 6 |
| ESC2, ESC3 — over-broad extended key usage; enrolment on behalf of other users | Broad templates and delegated enrolment | Minimal key usage per template; enrolment on behalf of others does not exist by default | **Designed** — phase 6 |
| ESC4, ESC5 — weak ACLs on templates or other PKI objects | Delegated write access to PKI configuration | Templates and PKI objects are tier 0; changes pass the policy decision point and are audited | **Designed** — phase 6 |
| ESC6 — a CA-wide setting that accepts a subject alternative name from the request | A legacy CA flag | The setting does not exist; there is no path from the request to the subject alternative name | **Designed** — phase 6 |
| ESC7 — CA management roles abused | Powerful CA roles delegated loosely | CA roles map to tier 0, with separation of duties | **Designed** — phase 6 |
| ESC8, ESC11 — relay to web enrolment or to the RPC enrolment interface | NTLM accepted; enrolment over HTTP | No NTLM; enrolment only Kerberos-authenticated and encrypted; no web enrolment over HTTP | **Designed** — phase 6; no NTLM exists today |
| ESC9, ESC10 — weak mapping from a certificate to an account | Implicit mappings | Strong mapping is mandatory; no implicit mapping | **Designed** — phase 6 |
| Certificate mapping through a spoofed DNS host name (Certifried) | DNS host names are not unique across computers | Strong mapping; the DNS host name is one key in the unique principal namespace | **Implemented:** uniqueness (`principal-names`). **Designed:** mapping — phase 6 |
| ESC13 — an issuance policy linked to a group | Policy-to-group links grant membership through a certificate | No policy-to-group link, or tier 0 only | **Designed** — phase 6 |
| ESC15, ESC16 — application policies in version-1 templates; the security extension disabled | Legacy templates and settings | The security extension is mandatory; legacy version-1 templates are not supported | **Designed** — phase 6 |
| Theft of the CA private key (golden certificate) | The key sits on the CA server | The CA key lives in `keyd` or an HSM and is used, never handed out; there is no export operation | **Designed** — phase 6 |
| Persistence through a certificate that survives a password reset | Long-lived certificates; weak revocation | Strong mapping, short lifetimes, effective revocation (CRL, OCSP) | **Designed** — phase 6 |

## 8. Foundational classes

These apply to any identity infrastructure, Domainfort included. If they are not designed for, the
same weakness returns in a new form.

| Weakness class | Why it exists in typical AD deployments | Domainfort's design answer | Status |
|---|---|---|---|
| Hypervisor administrator controls the domain controller | Memory and disk of a VM are open to the host | Keys in an HSM or TPM, so a host compromise does not extract them | **Designed**, not yet scheduled |
| VM snapshot or clone rollback: reviving old state, lingering objects | Restoring a snapshot rewinds the directory | Anti-rollback protection, encrypted storage, keys that do not open from a raw snapshot | **Designed.** The sealed key-store format carries a generation counter and a root digest (`keyd-types`) |
| Boot or firmware compromise | The chain of trust breaks before the operating system | Measured or verified boot and TPM attestation of the domain controller | **Designed**, not yet scheduled |
| Physical access | Disk and memory can be removed | Disk encryption, HSM, console lock | **Designed** (deployment requirement) |
| Ageing cryptography, including post-quantum | Algorithms are fixed in code | Versioned algorithm sets; rotation without data loss; post-quantum readiness for PKINIT, certificates and TLS; a migration path for SHA-1-based checksums that Windows still requires; a floor that can be raised | **Implemented:** AES with SHA-2 (RFC 8009) beside AES with SHA-1 (`krb-crypto`); key rotation by version number (`keyd`); sealed records name their sealing suite (`keyd-types`). **Designed:** the rest |
| Negotiation downgrade (SMB dialect, Kerberos encryption type, TLS version, SPNEGO mechanism) | Peers pick the weakest common option | Every negotiation is authenticated, with a hard floor; below the floor the answer is a refusal, never a fallback | **Implemented:** TLS 1.3 only (`ldap-front`); AES only and mandatory FAST (`kdc`); the legacy change-password version refused (`kpasswd-front`). **Designed:** SMB 3.1.1 and Kerberos-only SPNEGO — phase 2 |
| A rogue domain controller at join time; trust on first use | A joining computer cannot tell the real domain from an impostor | Mutual authentication at join: the domain proves itself with Kerberos or a certificate, the device with a TPM-backed key or a one-time token. No trust on first use | **Designed** — phase 1 (Linux members), phase 2 (Windows members) |
| Replication as an attack surface: conflicting writes, version-vector manipulation, winning a conflict to override security | Last-writer-wins replication applies to security data too | Security-aware conflict resolution: a replicated change never escalates. Signed provenance per change, version-vector integrity, replication only between authenticated domain controllers | **Designed** — phase 4. Per-value change stamps are already stored (`dirstore`) |
| A malicious update or a compromised build of the product itself | The update channel and the build chain are targets | Reproducible builds, signed releases, an authenticated and encrypted update channel, a transparency log, an SBOM per release | **Implemented in part:** locked dependency graph, licence and banned-crate checks, a scan for vendored code (see [BUILDING.md](BUILDING.md)). **Designed:** the rest |
| A rogue or hijacked tier-0 administrator who also erases the traces | The administration plane can do everything | An audit log that resists tampering even by tier 0 (append-only, signed, forwarded off the machine at once); separation of duties and multi-party approval for destructive operations; multi-party, audited break-glass | **Implemented:** dual control (`directory-admin`, `keyd`); append-only, hash-chained log with acknowledged intent (`audit-log`, `ipc-audit-client`). **Designed:** signing, off-box forwarding, break-glass |
| Anti-forensics: disabling audit, deleting records, living off the land | Audit can be switched off and attackers stay below the radar | Audit cannot be disabled from the data plane; canaries and honeytokens raise certain alerts; behavioural baselines; policy denials as a detection signal | **Implemented:** no state change without an acknowledged audit record; every policy decision is audited (`ipc-audit-client`, `pdp`). **Designed:** canaries and baselines, not yet scheduled |

## Outside the current scope

These are not built and not planned for the current phases. The design commitments are recorded so
that the same mistakes are not repeated if they are added:

- **Forest trusts:** SID filtering mandatory, no SID history, foreign principals checked.
- **Coexistence with Windows domain controllers:** packet privacy only, replication only between
  domain controllers, and a separate design decision before any code.
- **Hybrid identity synchronisation:** the synchronisation identity would be tier 0 and would use
  `keyd`'s compute-don't-give model.
- **Software and update distribution:** always authenticated, signed and encrypted, never plain HTTP.

## Residual risks

These classes cannot be removed by construction. Each is contained, and the containment is stated.
Implementation-state risks of the current pre-alpha code (development key store, unsigned policy and
others) are listed separately in [SECURITY-MODEL.md](SECURITY-MODEL.md#residual-risks).

| Residual risk | Why it cannot be removed by construction | Compensating controls |
|---|---|---|
| Offline guessing of service tickets under AES | Any authenticated principal may request a service ticket; this is part of the protocol | Random service passwords (managed service accounts, phase 3), a minimum password length for accounts with a service name, monitoring |
| A computer-account password hash for Windows protocols | Netlogon and Windows time signing derive keys from it (phase 2) | Held only inside `keyd`; not a logon credential (no NTLM, no RC4); computer passwords are long and random, so offline cracking is impractical |
| Unauthenticated UDP (LDAP ping, DNS) | Windows requires UDP for these | Reply size caps, per-source rate limits, internal interfaces only, never exposed to the internet; a forged answer cannot produce valid Kerberos tickets |
| A compromised online KDC path can issue tickets and assert their contents | Structural for any KDC | No key extraction; `keyd` is audited and rate-limited; `krbtgt` rotation; short tickets; an issuance spike is a detection signal |
| Forged tickets if the `krbtgt` key is ever stolen | The `krbtgt` key is the domain's root of trust and must exist | Isolated custody in `keyd`, HSM planned; rotation; short tickets |
| Compromise of a client or an administrator's workstation, and ticket reuse between member servers | Outside the domain controller's boundary; it cannot see client memory | Short tickets, re-evaluation at every TGS, privileged-access workstations, a Protected-Users-like profile, endpoint telemetry; the limit of the domain controller's visibility is documented |
| Timing side channels | Cannot be proven absent in software | Constant-time comparisons, uniform errors; reduced, not eliminated |
| Non-timing side channels in an HSM (cache, electromagnetic, power) | Hardware physics | A validated HSM (FIPS or Common Criteria); the assumption is documented |
| Baseboard management controllers and out-of-band management | Hardware below the operating system, present in every server | Isolated management network, no default credentials, updated or disabled; assumed compromised unless hardened |
| New certificate-services variants | Research on certificate services continues | Security extension mandatory, legacy templates unsupported, strong mapping; the class is closed in principle, not only per instance |
| Deep group nesting as a denial of service on token building | Group semantics allow nesting | Nesting depth at most 16, closure at most 1024 groups, cycles refused (`directory-admin`) |
| Escape from process isolation; system-call abuse | The kernel is shared | A per-process system-call allow-list, a minimal base image and namespaces are planned; isolation is per user account today |
| Name and identity confusion across protocols | Each protocol has its own name forms | One principal namespace; certificate mapping comes later; reduced, not eliminated |
| Human and operational factors: helpdesk, administrators, vendors, break-glass | Social, not code | Procedures, separation of duties, a tamper-evident log, dual control for break-glass |
| The supply chain: a compromised dependency or a poisoned build | Domainfort links dependencies | Licence allow-list and a ban on protocol-logic libraries, a locked dependency graph; SBOM and reproducible builds planned |

## Open design questions

- A Unicode normalisation rule for principal names; phase 1 accepts printable ASCII only.
- Whether FAST can be required of Windows members, depending on the supported Windows versions.
- Whether policy may restrict which principals can request service tickets without breaking clients.
- Whether coexistence with Windows domain controllers will be supported at all.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
