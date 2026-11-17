# Protocols

For each protocol: what is implemented now, what is planned, and what is deliberately absent.
"Absent" means there is no code path — not a disabled option.

A domain controller cannot change the protocols Windows speaks on the wire. "Rewriting securely"
therefore means four things: implement only the secure subset of each protocol; implement it in
memory-safe Rust with strict, bounded, fuzzed parsers; where a protocol is weak and Windows cannot
do without it, minimise it (least information, internal networks only, rate limits) and document
what remains; and where both ends are Domainfort (Linux members, server to server), use modern
protocols without compromise.

The standards referenced here are listed in [STANDARDS.md](STANDARDS.md).

## Summary

| Protocol | Ports | Today | Next |
|---|---|---|---|
| Kerberos | UDP/TCP 88 | AS and TGS with mandatory FAST, AES only | PAC, GSS-API acceptor, delegation (later) |
| Kerberos change password | TCP 464 | complete flow (users, armored only) | — |
| LDAP | TCP 389 (StartTLS), 636 (LDAPS) | read-only: rootDSE, directory search for authenticated clients | Kerberos bind with SASL sealing; machine self-write |
| DNS | UDP/TCP 53 | authoritative front, zone image, signed-update forwarding | directory-backed zone, GSS-TSIG updates, DNSSEC |
| Time | UDP 123, TCP 4460 | — | NTS for Linux members and upstream; MS-SNTP for Windows |
| SMB | TCP 445 | — | SMB 3.1.1 only, always encrypted; SYSVOL as a signed image |
| DCE/RPC | TCP 135 + fixed range | — | packet privacy only; Kerberos only |
| Netlogon | over RPC | — | Kerberos-based secure channel only |

## Kerberos

**Standards:** RFC 4120, RFC 3961, RFC 3962, RFC 8009, RFC 6113 (FAST), RFC 3244 (change password),
RFC 4121, RFC 4178; [MS-KILE], [MS-PAC], [MS-SFU], [MS-PKCA], [MS-KKDCP], [MS-SPNG].

### Implemented

- **AS and TGS exchanges** over UDP and TCP, with strict DER decoding (ITU-T X.690) and canonical
  encoding; the retransmission and "response too big" rules of RFC 4120; one realm; exact name
  matching (no case folding, aliases, enterprise names, referrals or canonicalisation).
- **FAST is mandatory** (RFC 6113). Every AS exchange is armored with a computer account's ticket;
  every TGS exchange uses the implicit armor of its TGS request. Only the inner request is
  processed, refusals after the armor is opened are themselves armored, and every FAST key stays in
  the key holder. An unarmored request receives a `KDC_ERR_PREAUTH_REQUIRED` that advertises only
  FAST. **One documented exception:** a computer account that the policy allows to bootstrap may
  obtain its own ticket-granting ticket without armor, using an encrypted timestamp — this is how a
  computer obtains the armor ticket in the first place.
- **Pre-authentication is mandatory** for every principal: inside FAST, the encrypted challenge
  (RFC 6113 §5.4.6) with the reply key strengthened; for the bootstrap case, the encrypted
  timestamp. Only `PA-ETYPE-INFO2` is ever sent.
- **AES only:** `aes128-cts-hmac-sha1-96` (17), `aes256-cts-hmac-sha1-96` (18),
  `aes128-cts-hmac-sha256-128` (19) and `aes256-cts-hmac-sha384-192` (20). The Kerberos encryption
  profiles are written on approved AES, SHA and HMAC primitives and verified against the test
  vectors of RFC 3962 and RFC 8009.
- **Policy at every step:** every AS and TGS step is a decision of the central policy decision
  point. At TGS time the client account is read again: a disabled, locked, expired or deleted
  account is refused, and tickets issued before a password set are revoked.
- **Restricted options:** flag options are honoured only when the ticket policy allows them;
  forwarding, proxying, post-dating, user-to-user, renewal and validation requests are refused
  with `KDC_ERR_BADOPTION`.
- **Terse errors:** a `KRB-ERROR` never carries error text or internal detail. When the key holder
  or the directory is unavailable, the answer is `KDC_ERR_SVC_UNAVAILABLE` over TCP and silence
  over UDP — never "wrong password".
- **Change password (RFC 3244)** — see the next section.

### Change password

- Served by `kpasswd-front` on **TCP 464 only**; there is no UDP listener.
- Only the protocol version defined by RFC 3244 is accepted; the legacy version is answered with
  a version error and never forwarded.
- The ticket for `kadmin/changepw` can be obtained **only through an armored AS exchange**, only by
  user accounts, with a fixed profile (initial ticket, at most 300 seconds, never renewable,
  forwardable or proxiable). The TGS refuses that service name.
- The front passes the AP-REQ and the encrypted `KRB-PRIV` to `dird` as opaque bytes. The key
  holder verifies the request and is the only process that decrypts the new password; `dird`
  decides through the policy decision point and writes through the one checked write path; the key
  holder applies the password policy, installs the new key and seals the reply.
- The change revokes the ticket used for it, so one ticket allows at most one change.
- Accounts in tier 0 cannot currently use this path; their passwords are set through the
  administration plane.

### Planned

- **PAC** ([MS-PAC]), required by Windows members: always present, with the full set of signatures,
  always verified; built by the key holder from directory facts at every TGS, with identities
  resolved by SID and GUID rather than by name.
- **GSS-API acceptor** for Kerberos (RFC 4121) and SPNEGO with Kerberos only (RFC 4178, [MS-SPNG]),
  terminating inside the key holder, for LDAP, SMB and RPC.
- **Windows compatibility** details from [MS-KILE].
- **Later:** constrained and resource-based delegation ([MS-SFU]); PKINIT for computers
  (RFC 4556, [MS-PKCA]); Kerberos over HTTPS through a KDC proxy ([MS-KKDCP]); cross-realm trusts
  only if required.

### Deliberately absent

RC4-HMAC, DES and 3DES; turning off pre-authentication; unconstrained delegation; a PAC without the
full signature set; `PA-ETYPE-INFO` and `PA-PW-SALT`; error text in `KRB-ERROR`; the legacy
change-password version; change password over UDP.

## LDAP

**Standards:** RFC 4511, RFC 4512, RFC 4513, RFC 4514, RFC 4517, RFC 8446, RFC 5280; [MS-ADTS];
for the planned bind: RFC 4422, RFC 4752, RFC 4121, RFC 2743, RFC 9266 (and, for the Windows-facing
phase, RFC 5929 and [MS-SPNG]).

### Implemented

- **`ldap-front`** accepts LDAP on TCP 389 with StartTLS and on TCP 636 (LDAPS), on internal
  networks only, with global and per-source connection limits.
- **TLS 1.3 only** (RFC 8446), with `TLS_AES_256_GCM_SHA384` and `TLS_AES_128_GCM_SHA256`, in the
  server's order. The domain controller's certificate and key are checked at start (RFC 5280
  structure, signature and key algorithms, key match, validity).
- **StartTLS** is protected against injection: a StartTLS request with further bytes already
  buffered is refused and the connection closed, and no clear-text bytes are processed after it.
- A **strict LDAP codec** bounds each message by the connection's authentication state before any
  allocation. The front re-encodes every message in one canonical form and passes it to the LDAP
  engine in `dird`, which decodes only that canonical form.
- **The engine is read-only:**
  - the **rootDSE** ([MS-ADTS]) is readable anonymously from internal networks;
  - **directory search** — base, one-level and subtree, with server-side paging and bounds on
    visits, size, time, result octets and filter depth — is available to authenticated clients
    only. The Kerberos bind that authenticates clients is planned, so in a deployment today only
    the rootDSE is reachable;
  - secret attributes and security descriptors are never returned; an object that does not exist
    and an object the client may not see produce identical answers.
- **Refusals:** a simple bind with a password is refused before any lookup; an unauthenticated
  simple bind is refused; every SASL mechanism is refused until the Kerberos bind is built; every
  write operation (add, modify, delete, rename, compare) is refused; critical controls are refused.

### Planned

- **Kerberos bind for native clients** (designed; the GSS token framing crate `gss-token` exists):
  SASL (RFC 4422) GSSAPI (RFC 4752) **over TLS 1.3 only**, with no SASL security layer, bound to the
  TLS connection with the `tls-exporter` channel binding (RFC 9266), one GSSAPI exchange per TLS
  connection, and all Kerberos cryptography inside the key holder. GSSAPI is advertised only once a
  successful bind is possible. Details and open questions: [LDAP-GSSAPI-BIND.md](LDAP-GSSAPI-BIND.md).
- **Kerberos bind for Windows members** (Windows-facing phase): GSS-SPNEGO or GSSAPI with the
  **SASL security layer providing confidentiality (sealing)**, the protection Windows members use;
  the security layer will terminate inside the key holder. Whether TLS is offered next to it, with
  `tls-server-end-point` channel binding (RFC 5929) as Windows clients expect, is an open design
  decision.
- **One narrow write path:** a computer updating its own permitted attributes during join, through
  the one checked write path. Administrative writes over LDAP are not planned: administration goes
  through the administration plane, with dual control and effect plans.
- **The LDAP ping over UDP** ([MS-ADTS]) that Windows uses to locate a domain controller: the
  single query and the minimal reply only, internal networks only, rate-limited, with a reply size
  cap.

### Deliberately absent

Simple bind with a clear-text password; SASL DIGEST-MD5; NTLM through SPNEGO; anonymous access
beyond the rootDSE; administrative writes over LDAP; TLS below 1.3 on the LDAP front.

## DNS

**Standards:** RFC 1034, RFC 1035, RFC 2782, RFC 2136, RFC 3645, RFC 8945; planned: RFC 4033–4035,
RFC 7858; [MS-GSSA], [MS-ADTS] (domain controller locator records).

### Implemented

- A **strict, bounded DNS codec** for queries, updates and TSIG records, with fixed section-count
  profiles.
- An **authoritative zone image**: the zone apex, SOA and NS records, the domain controller's host
  record, member host records, and the SRV records Windows and Linux use to locate the domain
  controller (RFC 2782). The image is typed and validated when built, so an invalid image —
  wildcard names, names outside the zone, an SRV target without an address — cannot exist.
- An **answer function** that maps every request to exactly one verdict: authoritative answers
  only — no recursion, no cache, no wildcards, no CNAME, no zone transfer, `ANY` refused. A UDP
  reply is at most 512 octets and at most four times the size of the request (error replies at most
  the request's size); otherwise it is truncated.
- **`dns-daemon`** serves UDP and TCP 53 on internal networks only, with rate limits, connection
  slots and TCP deadlines. It answers only from a zone image fetched from `dird` and refreshed by
  serial number; it does not start without a first valid image and answers `SERVFAIL` once its image
  is older than the configured maximum.
- **Dynamic updates:** an update received over TCP and signed with GSS-TSIG is forwarded to `dird`
  unchanged, with its transport and source address; an unsigned update is refused; an update signed
  with any other TSIG algorithm is refused; updates over UDP are refused for now. IPv6 address
  queries return no data for now.

### Planned

- **The directory side:** `dird` building the zone image from the directory and serving it to
  `dns-daemon` (until then `dns-daemon` cannot start against a real `dird`).
- **Secure dynamic updates** with GSS-TSIG (RFC 3645, [MS-GSSA]) from Kerberos-authenticated
  members, verified by the key holder; each record updatable only by its owner; ordinary users
  cannot create records. A signed update over UDP will be accepted only on a security context
  established over TCP from the same address.
- **DNSSEC** signing of the zone (RFC 4033–4035); DNS over TLS for Linux members as an option
  (RFC 7858); IPv6 address records.

### Deliberately absent

Recursion on the authoritative server; open zone transfer; unsigned dynamic updates; record
creation by ordinary users; wildcard records.

## Time

**Standards:** RFC 5905 (NTPv4), RFC 8915 (NTS); [MS-SNTP].

Kerberos depends on synchronised clocks, so whoever controls time influences authentication.

### Implemented

Nothing yet.

### Planned

- **NTS** (RFC 8915): a server for Linux members and an NTS client towards upstream time sources.
  No unauthenticated time path.
- **Windows members** ([MS-SNTP]), in the Windows-facing phase: Windows signs time responses with a
  key derived from the computer account's secret. The plan is to keep only a single-purpose
  signing key in the key holder, derived once from the machine-generated computer password, and
  to let the key holder check and write the timestamps itself, so a compromised time process
  cannot sign a false time.
- NTS needs a specification (the mandatory authenticated-encryption mode) to be added to the
  project's allowed sources first; see [STATUS.md](STATUS.md).

### Deliberately absent

Unauthenticated time synchronisation for domain members; the symmetric and legacy NTP
authentication modes.

## SMB

**Standards:** [MS-SMB2], [MS-DFSC]; [MS-SRVS] (minimal).

### Planned (Windows-facing phase)

- **SMB 3.1.1 only**, with pre-authentication integrity (SHA-512).
- **Encryption required** for every request after session setup (AES-256-GCM preferred,
  AES-128-GCM otherwise).
- **Kerberos only**, through SPNEGO, with all session cryptography inside the key holder.
- Shares `IPC$`, `SYSVOL` and `NETLOGON` only. **SYSVOL is served from a signed, immutable image**
  with no file system behind it, so path traversal, symbolic links and alternate data streams have
  nothing to act on. There is no write path over SMB; policy images are produced by a dual-controlled
  release.
- DFS referrals for the domain, the domain controller and SYSVOL only.

### Deliberately absent

SMB 1 and every dialect older than 3.1.1; NTLM; guest and null sessions; compression; multichannel
and RDMA.

## DCE/RPC

**Standards:** The Open Group C706; [MS-RPCE].

### Planned (Windows-facing phase)

- Transports `ncacn_ip_tcp` and `ncacn_np` (named pipes over SMB); a fixed dynamic port range.
- The **endpoint mapper** on TCP 135 for lookups only — the only unauthenticated call.
- **Packet privacy (encryption and integrity) required** on every interface; Kerberos
  authentication.
- A strict NDR decoder with bounded allocation, and per-connection workers that hold no keys.
- Service subsets as the lab recordings show they are needed: [MS-SAMR], [MS-LSAD], [MS-LSAT],
  [MS-DSSP], [MS-SRVS]; later [MS-BKRP] and [MS-GKDI].

### Deliberately absent

Unauthenticated binds (except the endpoint-mapper lookup); authentication levels below packet
privacy; RPC over UDP; RPC over HTTP; DCOM; NTLM.

## Netlogon

**Standard:** [MS-NRPC].

### Planned (Windows-facing phase)

- A **secure channel based on Kerberos only.** The legacy secure-channel setup, the Netlogon
  security provider and session keys derived from the computer password hash have no code path —
  which makes the class of flaws behind well-known attacks on the Netlogon secure channel impossible
  by construction.
- Computer password changes on the channel, through the one checked write path, for the channel's
  own computer object only.
- Domain-controller location answers derived from the same facts as DNS and LDAP.

### Deliberately absent

Channels without AES or without sealing; NTLM pass-through; mailslots; operations that export
secrets.

## Later phases

| Area | Standards | Notes |
|---|---|---|
| Group Policy | [MS-GPOL], [MS-GPREG], [MS-GPSB], [MS-GPSCR] | Signed policy releases; stored passwords in policy preferences refused. |
| Managed service accounts and local administrator passwords | [MS-GKDI] | Secrets computed in the key holder, never handed out. |
| Certificate services | [MS-WCCE], [MS-ICPR], [MS-XCEP], [MS-WSTEP]; RFC 5280, RFC 2986, RFC 5652, RFC 7030 | Secure by default: the requester never chooses the subject alternative name; strong certificate mapping. |
| Management compatibility | [MS-ADDM], [MS-WSDS], [MS-WSPELD], [MS-WSTIM], [MS-ADCAP], [MS-DNSP] | For Microsoft management tools, much later. |
| Multiple domain controllers | — | A native replication protocol over mutually authenticated TLS. [MS-DRSR] only if coexistence with Windows domain controllers is decided. |
