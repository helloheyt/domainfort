# Status and roadmap

**Domainfort is pre-alpha.** Nothing here should protect real systems yet. This page describes what
exists in the code today, what works end to end, what comes next, and what is waiting on decisions
outside the code.

## Roadmap

| Phase | Goal | State |
|---|---|---|
| 0 — Foundations | Pinned specifications, provenance enforcement, dependency policy, an isolated interoperability lab | done |
| 1 — Native core | Directory, Kerberos with FAST, change password, LDAP, DNS, time, key custody, audit, provisioning, administration; Linux members join and log on | **in progress** |
| 2 — Windows members | Windows computers join, start and log users on, with NTLM disabled on the client: PAC, DCE/RPC, SMB 3.1.1, Netlogon over Kerberos, LDAP ping, Windows time | designed, not started |
| 3 — Policy and secrets | Group Policy for Windows, a policy client for Linux, managed service accounts, local administrator passwords, delegation, KDC proxy | planned |
| 4 — Several domain controllers | Native replication over mutually authenticated TLS, high availability, backup and recovery | planned |
| 5 — Management compatibility | Compatibility with common Microsoft management tools | planned |
| 6 — Certificate services | Secure-by-default certificate authority, smart-card logon, automatic enrolment for Linux | planned |
| Beyond | The wider set of Windows Server roles, managed through a full command-line and graphical interface | long-term goal |

The phase 1 exit criteria include Linux members joining and logging on, all traffic encrypted,
fuzzers running continuously, and an external security review of the KDC.

## The crates

55 crates, grouped by area.

### Encoding and parsers

| Crate | What it is |
|---|---|
| `parse-asn1` | Strict DER decoder and canonical encoder for the ASN.1 subset Kerberos uses. |
| `parse-ldap` | Strict LDAP message codec and distinguished-name parser. |
| `parse-dns` | Strict, bounded DNS message codec for queries, updates and TSIG records. |
| `parse-kpasswd` | Strict, bounded framing of the change-password protocol's messages. |
| `parse-x509` | Strict, bounded reader of X.509 v3 certificates. |
| `dtyp` | Windows security data types — SIDs, ACLs, security descriptors — and descriptor inheritance. |

### Kerberos

| Crate | What it is |
|---|---|
| `krb-crypto` | The AES Kerberos encryption and checksum profiles, PRF+ and KRB-FX-CF2, on approved primitives; linked only by `keyd`. |
| `krb-proto` | Typed Kerberos V5 and FAST messages with strict DER decoding and canonical encoding. |
| `kdc` | The KDC as a library: AS and TGS, mandatory FAST, a policy decision at every step; no keys, no sockets. |
| `kdc-daemon` | The KDC process: UDP and TCP 88, bounded queues, rate limits, audit. |
| `gss-token` | Strict framing of Kerberos GSS-API tokens — the initial-context token, the authenticator checksum, the wrap-token header — with no cryptography; groundwork for the LDAP Kerberos bind, not linked by a daemon yet. |

### Key custody

| Crate | What it is |
|---|---|
| `keyd-types` | The cryptography-free vocabulary of the key holder's interface: identifiers, roles, the capability table, the sealed key store format. |
| `keyd` | The key-custody core: "compute, don't give", the decision table, the ceremony state, the custody backend interface. |
| `keyd-daemon` | The `keyd` process (development key store only). |
| `keyadm` | The one-shot key-administration tool: key ceremony, execution of decided key operations. |

### Directory and policy

| Crate | What it is |
|---|---|
| `dirstore` | The directory storage engine over an embedded key-value store: per-record integrity MAC, snapshots, tombstones, link and uniqueness indexes. |
| `ad-schema` | A first subset of the Active Directory schema, as data. |
| `principal-names` | The one definition of principal-name equivalence — one fold, one key form — shared by the write path, the lookup and the key holder ([PRINCIPAL-NAMESPACE.md](PRINCIPAL-NAMESPACE.md)). |
| `name-attestation` | The tag over `dird`'s name resolutions: `dird` signs every resolution it hands the KDC, and the key holder verifies it before it reaches any key. |
| `directory-pip` | The directory as seen by the KDC and the policy decision point: account lookup, group expansion, tier classification, the visibility gate, the one revocation rule. |
| `pdp` | The central policy decision point and the Windows access check. |
| `policy-store` | The policy file loaded by `dird` and the KDC (currently an explicitly unsigned development format). |
| `ldap` | The LDAP engine — the enforcement point behind the LDAP front; read-only. |
| `directory-admin` | The write enforcement point: the one checked write path, dual control, effect plans, password changes. |
| `admin-password-policy` | The password policy: one rule set, applied at one enforcement point. |
| `directory-daemon` | The `dird` process. |

### DNS

| Crate | What it is |
|---|---|
| `dns-zone` | The validated zone image and the total answer function. |
| `dns-daemon` | The DNS front process on UDP and TCP 53. |
| `rate-limit` | The per-source and global admission limiter shared by the network fronts. |

### Other network fronts

| Crate | What it is |
|---|---|
| `ldap-front` | The LDAP front: TLS 1.3, StartTLS, framing, canonical re-encoding. |
| `kpasswd-front` | The change-password front on TCP 464. |

### Internal channels

| Crate | What it is |
|---|---|
| `ipc` | The framing and field codec under every internal channel. |
| `ipc-keyd` | The key holder's channel: messages and client, with no cryptography. |
| `ipc-keyd-server` | The key holder's side of its channel. |
| `ipc-directory` | The directory-view channel between the KDC and `dird`, and the KDC's client. |
| `ipc-directory-server` | `dird`'s side of the directory-view channel. |
| `ipc-ldap` | The channel between the LDAP front and `dird` (front side). |
| `ipc-ldap-server` | `dird`'s side of the LDAP channel. |
| `ipc-dns` | The channel between the DNS front and `dird`, and the front's client. |
| `ipc-dns-server` | `dird`'s side of the DNS channel. |
| `ipc-kpasswd` | The channel between the change-password front and `dird`; no clear-text password is representable on it. |
| `ipc-dird-admin` | The channel between the administration daemon and `dird`, including the operation digest and effect plans. |
| `ipc-admin` | The administrators' channel to the administration daemon. |
| `ipc-audit` | The audit channel's wire shapes and event codec. |
| `ipc-audit-client` | The single audit client and the audit gate every daemon uses. |

### Audit

| Crate | What it is |
|---|---|
| `audit-log` | The append-only, hash-chained audit log format, writer and verifier. |
| `audit-daemon` | The audit process. |

### Administration and provisioning

| Crate | What it is |
|---|---|
| `admin-daemon` | The local administration daemon. |
| `provision` | The offline provisioning tool. |
| `provision-manifest` | The non-secret provisioning manifest: one format, one parser. |

### Platform and testing

| Crate | What it is |
|---|---|
| `config` | Strict, hand-parsed configuration for every daemon. |
| `daemon-sandbox` | Process hardening through safe operating-system calls. |
| `protected-file` | The one way a daemon or tool opens a protected file. |
| `test-scratch` | Scratch directories for tests. |
| `e2e-tests` | End-to-end tests over real sockets across the daemons. |

## What works end to end today

These run in the test suite, with real daemons over real Unix and network sockets on the local
machine:

- **Login.** A computer obtains its ticket-granting ticket, a user authenticates with FAST armor,
  and a service ticket is issued — over UDP and over TCP — with the audit trail checked end to end.
- **Provisioning to first login.** `provision domain`, the key ceremony, every daemon started in
  order, administration operations through the administration socket — including a dual-controlled
  policy change — and then the login of a newly created user.
- **Change password.** An armored AS exchange obtains a `kadmin/changepw` ticket from the KDC; the
  request travels over `dird`'s real change-password channel to a real `keyd` process; the
  password is changed, the new one verifies and the old one does not. Reusing the ticket, replaying
  the request, a computer account, a tier-0 account, a password that violates the policy, a wrong
  peer and an audit daemon that withholds its acknowledgement are all refused, with nothing
  written. The decision is acknowledged by the audit daemon before the commit. (The front's TCP
  framing and replies are tested separately; a test through the TCP front itself is still to come.)
- **LDAP.** The LDAP front, `dird` and the audit daemon together: LDAPS, StartTLS, injection
  attempts, and refusal of password binds.
- **Fail closed.** `keyd`, `dird` and the audit daemon stopped and restarted; policy
  version mismatches; channels deliberately cross-wired to the wrong daemon.
- **DNS.** `dird` builds the zone image from the directory — the domain controller's records from
  provisioning, a service record only for a service that actually listens, a serial that advances
  only through the one checked write — and the DNS front serves it over UDP and TCP 53: freshness,
  refresh by serial number, internal sources only, rate limits, UDP size rules and TCP framing
  bounds.
- **Principal namespace.** Every ticket rests on `dird`'s signed name resolution, verified by the
  key holder, which finds the key set only from that resolution. A forged, stale or mismatched
  resolution sent by a compromised KDC is refused and audited; the account-name spoofing shapes
  (names that differ only in a final "$", reserved names in another case, colliding service names)
  are refused at write time with nothing written, and the KDC has no fallback lookup. See
  [PRINCIPAL-NAMESPACE.md](PRINCIPAL-NAMESPACE.md).
- **Distinct accounts.** On Linux as root, the daemons run under distinct accounts and the audit
  daemon labels each record with the right source; process hardening is applied and verified.

What does **not** work yet: no Windows or Linux computer can join; there is no Kerberos bind for
LDAP; secure dynamic DNS updates are not accepted yet; there is no time service; there is no
shipped command-line or graphical administration client; keys do not survive a `keyd` restart
([KEY-CUSTODY.md](KEY-CUSTODY.md#key-storage-the-main-gap-before-deployment)).

## What is next

Work that does not depend on outside decisions:

- **The Kerberos bind for LDAP**, designed in [LDAP-GSSAPI-BIND.md](LDAP-GSSAPI-BIND.md): the TLS
  front computes the TLS 1.3 channel-binding value once per connection, a dedicated LDAP service
  key, the key holder's two acceptor operations, and the engine's bind state machine. The token
  framing (`gss-token`) is done.
- **The last key handle the KDC states:** pre-authentication takes the client's signed name
  resolution, and the key holder stamps the time of an armored error itself.
- **An end-to-end test through the change-password front** over TCP.
- **The Linux member side:** the interface documentation it needs (the POSIX user and group
  database, PAM, NSS) is now in the project's allowed sources; the design comes next.
- **Build hardening:** a check of every artifact's complete linked set against a closed list of
  what it may contain, and supply-chain tooling as a required part of the gate.

## Waiting on decisions outside the code

| Area | What it is waiting for |
|---|---|
| Persistent key store | A sealed key store backend, awaiting a cryptographic library decision for the sealing suite; a hardware-anchored (TPM) backend, awaiting a dependency decision. |
| Signed policy and signed audit log | A decision on the signature scheme and the custody of the signing keys. |
| Kerberos bind for LDAP | A decision on the channel-binding digest: RFC 4121 defines it as MD5, which the project otherwise refuses ([LDAP-GSSAPI-BIND.md](LDAP-GSSAPI-BIND.md#open-design-questions)). Everything else in the bind can be built before it. |
| DNS | Specifications for IPv6 address records, negative caching, TKEY and DNSSEC record formats, and DNS over TLS being added to the allowed sources. |
| Time | The authenticated-encryption specification NTS mandates being added to the allowed sources; a decision on the domain controller's own time source. |
| Windows-facing phase | A decision on the supported Windows versions; the file-system specification SMB needs being added to the allowed sources; further interoperability recordings. |
| Administration client (CLI and GUI) | A decision on the network path from the administrator's workstation. |
| Fuzzing | Approval of the fuzzing harness dependencies. |
| Stronger process isolation | A decision on seccomp, Landlock or namespaces, which need `unsafe` code or a new dependency. |
| FIPS-validated cryptography | The FIPS build of the TLS cryptography library carries a licence outside the allow-list. |
