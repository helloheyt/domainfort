# Architecture

This document describes how Domainfort is put together today: which processes exist, what each one
may and may not hold, how they talk to each other, in what order they start, and how they behave
when something is missing. Planned components are marked as such.

## Design rules

The architecture follows a few rules that apply everywhere:

- **Separate what parses from what holds.** A process that parses bytes from the network holds no
  long-term key, no directory store and no outbound connection it does not strictly need. A
  compromise of a parser should not reach keys or the directory.
- **One owner per asset.** Long-term keys live in one process (`keyd`). The directory store lives
  in one process (`dird`). The audit log is written by one process (`audit-daemon`).
- **Compute, don't give.** The key holder performs operations *with* keys and returns results. No
  operation returns long-term key material to anyone.
- **Every boundary is checked.** Every internal channel identifies its peer, accepts only the
  messages defined for that peer's role, and bounds every length before allocating memory.
- **Fail closed.** If a dependency is missing, an input is malformed, or a check cannot be
  completed, the answer is a refusal — never a fallback to a weaker mode.
- **Memory-safe Rust only.** Every crate forbids `unsafe` code. Cryptographic primitives come from
  approved libraries; this project never implements them.

## The processes

| Process | Crate | Listens on | Talks to | Holds | Never holds |
|---|---|---|---|---|---|
| `keyd` | `keyd-daemon` | `keyd.sock` (local only) | `audit-daemon` | every long-term key; one-time decisions registered by `dird`; replay cache and short-lived exchange state | any network socket |
| `dird` | `directory-daemon` | `dird-kdc.sock`, `dird-ldap.sock`, `dird-admin.sock`, `dird-kpasswd.sock` (local only) | `keyd`, `audit-daemon` | the directory store and its integrity key; the policy; the LDAP engine; the write path; pending dual-control requests | long-term Kerberos keys, passwords |
| KDC | `kdc-daemon` | UDP and TCP 88, internal networks only | `keyd`, `dird`, `audit-daemon` | its retransmit cache, the policy, rate limiters | any key, the directory store, any cryptographic code |
| LDAP front | `ldap-front` | TCP 389 (StartTLS) and TCP 636 (LDAPS), internal networks only | `dird`, `audit-daemon` | TLS state, the TLS server key | the directory store, any channel to `keyd`, the LDAP engine |
| DNS server | `dns-daemon` | UDP and TCP 53, internal networks only | `dird`, `audit-daemon` | a typed, read-only zone image; rate limiters | any key, the directory store, any channel to `keyd` |
| Change-password front | `kpasswd-front` | TCP 464 only, internal networks only | `dird`, `audit-daemon` | framing buffers | any key, the directory store, any channel to `keyd`, any clear-text password |
| Audit daemon | `audit-daemon` | `audit.sock` (local only) | — | the append-only, hash-chained audit log | any secret |
| Admin daemon | `admin-daemon` | `admin.sock` (local only) | `dird`, `keyd`, `audit-daemon` | nothing persistent (stateless) | the directory store |
| `keyadm` (tool) | `keyadm` | — | `keyd` only | nothing | any Kerberos client, any channel to `dird` |
| `provision` (tool) | `provision` | — | `keyd` (one step only) | nothing after it exits | — |

Each daemon runs under its own numeric user account. A process's identity on an internal channel
**is** that account.

### keyd — the key holder

`keyd` is the only process in which a long-term key exists and in which Kerberos cryptography is
performed. Only `keyd` links the Kerberos cryptography crate. `dird`, the KDC, the network fronts
and the administration daemon each have tests that fail if they link what they must not contain —
the Kerberos cryptography, `keyd` itself, and (for every process except `dird`) the directory store.

- **Compute, don't give.** The KDC asks `keyd` to verify pre-authentication, open an armor ticket,
  issue a ticket, or seal an error; `dird` asks it to verify an administrator's ticket or to open a
  change-password request. None of these return a key.
- **Roles by account.** `keyd` maps each connecting account to exactly one of four roles — the
  KDC, the administration plane (`admin-daemon`), the directory service (`dird`), or key
  administration (`keyadm`) — from a static table loaded at start. The superuser is never mapped. A closed, compile-time
  capability table states which operations each role may call.
- **No state change without a decision.** For the administration roles, `keyd` performs no key
  state change unless `dird` — the component that owns the policy decision — registered a
  one-time, operation-bound decision for it first. `keyd` executes exactly the registered
  parameters and nothing supplied by the caller (see the
  [security model](SECURITY-MODEL.md#one-decision-owner-for-every-key-change)).
- **Ceremony state.** Creating key sets and granting the first administrators' initial secrets is
  possible only while `keyd` is in its provisioning state, which a one-time seal ends.
- **Its own clock.** `keyd` reads the time itself; no request carries a time value.
- **Start hold-down.** The replay cache lives in memory, so after every start `keyd` refuses the
  Kerberos-path operations for twice the allowed clock skew (RFC 4120 §3.2.3).
- **Development key store only, for now.** Keys are held in memory and are lost when `keyd`
  stops; the provisioning key ceremony is repeated after each start. The format of the sealed,
  persistent key store and its custody interface exist; the sealing itself is waiting on a
  cryptographic library decision (see [STATUS.md](STATUS.md)).

### dird — the directory and the policy decision point

`dird` is the only process that opens the directory store and holds its integrity key. It hosts:

- the **directory-view service** for the KDC: each KDC connection pins one consistent snapshot of
  the directory and one policy version for the lifetime of a request;
- the **LDAP engine**, the enforcement point behind `ldap-front` (one Unix connection per client
  connection, no multiplexing);
- the **administration service** for `admin-daemon`: the write enforcement point, dual control,
  effect plans;
- the **change-password service** for `kpasswd-front`.

Every access decision goes through the **policy decision point**, a pure library linked into the
enforcement points (`dird` and the KDC). It evaluates five layers, each deny-by-default:
authentication, the transport floor, coarse global rules, the tier-0 write invariant (checked
*before* the object's ACL), and finally the object ACL and attribute class. An explicit deny at any
layer stops evaluation; any failure to obtain an input is a deny; search results are filtered,
never refused with an error that would reveal what exists.

Every directory write — online, through the administration plane or the change-password
service, and offline, during provisioning — passes **one checked write path**. The storage
engine's mutating calls are reachable only from that path, and a write is committed only as a
value that the checker alone can build after all invariants passed.

The policy file and the integrity key are currently read from **development sources**: an
unsigned policy format and a root-only key file. Both must be named explicitly in the
configuration, and `dird` prints a fixed warning at every start.

### The network fronts

| Front | What it does | What it cannot do |
|---|---|---|
| KDC | Parses AS and TGS requests (strict DER), applies the policy at every step, asks `keyd` for every key operation, answers over UDP or TCP | issue a ticket on its own, read a key, read the store directly |
| `ldap-front` | Terminates TLS 1.3, frames LDAP messages, re-encodes each one in a single canonical form and hands it to `dird` | run the LDAP engine, read the store, reach `keyd` |
| `dns-daemon` | Answers queries for the domain's zone from a typed image fetched from `dird` and refreshed by serial number; forwards signed updates to `dird` as opaque bytes | decide or apply an update, hold a key |
| `kpasswd-front` | Frames RFC 3244 requests on TCP 464 and hands the AP-REQ and the encrypted KRB-PRIV to `dird` as opaque bytes | read the new password, forge a request (that needs a ticket) or forge a success (that needs the session subkey) |

All fronts bind only to addresses inside the configured internal networks and drop traffic from
other sources before reading it. Each has per-source and global rate limits or connection limits
and bounded deadlines.

### The administration plane

- **`admin-daemon`** listens on a local socket only; there is no network administration API yet.
  It checks each request syntactically, then forwards it to `dird` with the administrators'
  Kerberos AP-REQs untouched — it has no field in which it could claim an identity. `dird` verifies
  the tickets through `keyd`, decides with the policy decision point, and audits. For a password
  set, `admin-daemon` asks `dird` to begin, hands the password to `keyd`, and asks `dird` to
  complete, so **the password never reaches `dird`**.
- **`keyadm`** is a one-shot tool for key administration. It talks to `keyd` only. Before the
  ceremony is sealed it creates the domain's key sets; afterwards it can only execute a key
  operation that `dird` decided, named by its decision id.
- **`provision`** is an offline tool run before any daemon starts. `provision domain` draws the
  domain SID, every object GUID and the integrity key from the system's secure random source,
  writes the initial directory through the same checked write path, writes the policy, every
  configuration file and a non-secret provisioning manifest, and installs them atomically.
  `provision first-admin-secret` sets the first administrators' passwords after the key ceremony.

There is no shipped command-line or graphical administration client yet; see
[STATUS.md](STATUS.md).

## Diagram

```text
                    internal networks only
     UDP/TCP 88        TCP 389 / 636        UDP/TCP 53            TCP 464
         |                  |                   |                    |
     +-------+        +------------+       +------------+     +---------------+
     |  KDC  |        | ldap-front |       | dns-daemon |     | kpasswd-front |
     +-------+        +------------+       +------------+     +---------------+
      |     |               |                   |                    |
      |     | dird-kdc      | dird-ldap         | dird-dns           | dird-kpasswd
      |     |               |                   | (dird side         |
      |     v               v                   v  planned)          v
      |   +-------------------------------------------------------------+
      |   |                            dird                             |
      |   |  directory store (sole owner) + integrity key               |
      |   |  policy decision point . LDAP engine . one checked write    |
      |   |  path . dual control and effect plans                       |
      |   +-------------------------------------------------------------+
      |               | keyd.sock                       ^ dird-admin.sock
      | keyd.sock     | (directory service role)        |
      | (KDC role)    v                                 |
      |   +------------------------------+        +--------------+
      +-->|            keyd              |<-------| admin-daemon |<-- admin.sock
          | every long-term key          |  keyd  +--------------+    (local only)
          | computes, never gives        |  .sock
          | no network socket            |  (administration-plane role)
          +------------------------------+
                      ^ keyd.sock (key administration role)
                  +--------+
                  | keyadm |   one-shot tool          provision: offline tool,
                  +--------+                          run before any daemon

     every daemon ---- audit.sock ----> audit-daemon  (append-only, hash-chained log)
```

## How processes talk

All internal communication uses **Unix domain stream sockets** on the same host — one socket per
(server, channel), each in its own directory owned by the server's account.

### Identity

- **The peer's identity comes from the kernel, never from the message.** A server reads the
  connecting process's user id from the socket's peer credentials and maps it to a role through a
  static table. An unmapped account is disconnected without a reply. The superuser is never mapped.
- **Clients verify the server, too.** Every client is constructed with the server's expected user
  id — and, for `keyd`, the role `keyd` must report for the client — and checks them on every new
  connection before sending any request. A client cannot be constructed without this expectation.
- Directory permissions on the socket directories add defence in depth; the authorisation itself
  is the account-to-role table.

### The wire format

Every channel uses the same hand-defined framing and field codec rather than a general-purpose
serializer:

```text
Frame   := length:u32 (big-endian) || body[length]
body    := magic:u16 || version:u8 || kind:u8 || payload
```

- The length is checked against the channel's maximum **before** anything is allocated or read.
- Each channel has its own magic number, so a client of one channel cannot reach another channel's
  parser.
- The version must match exactly. There is no negotiation and no fallback.
- Message kinds come from a closed table; an unknown kind closes the connection. One reply kind is
  reserved on every channel for a refusal.
- Every value has exactly one encoding; a body with trailing bytes is malformed. Decoders are
  tested for `encode(decode(b)) == b`.
- Kerberos structures inside a payload travel as DER and are decoded by the same strict Kerberos
  codec the KDC uses.
- Buffers that carry a secret are wiped after use on both sides.
- Clients decode replies with the same strictness as servers decode requests.
- Each connection carries one request at a time (no pipelining), and a request that has been sent
  is never silently resent: for a state-changing call, the `keyd` client reports whether the
  request was not sent, refused, or has an unknown outcome.

## Configuration and hardening

- **Configuration** is one strict, hand-parsed file per daemon: `key = value` lines, printable
  ASCII, bounded size, a closed table of keys, every value typed. An unknown, duplicate or missing
  key prevents start-up. There is no override from the environment, no include mechanism and no
  secret in any configuration file — only paths to protected files.
- **Protected files** (configuration, policy, manifest, keys, certificates, data files) are opened
  through one module that walks the path one component at a time from `/`, refuses symbolic links
  at every step, checks the owner and permissions of every directory on the way, and re-checks the
  opened file.
- **Start-up hardening** (Linux): while the process still has a single thread, each daemon reads its
  privileged files and binds its privileged ports as root, then drops to its own numeric user and
  group with supplementary groups cleared, sets no-new-privileges, drops every capability, disables
  core dumps, marks itself non-dumpable, sets a restrictive file-creation mask and resource limits —
  and `keyd` and `admin-daemon` lock their memory. The hardened state is read back and verified;
  any failure stops the daemon. Only then is the asynchronous runtime started.
- Additional isolation through seccomp filters, Landlock or namespaces is not used yet: it would
  require `unsafe` code or a new dependency, which needs an explicit decision.

## Start order

1. **`provision domain`** (offline, as root) — once, before anything runs.
2. **`audit-daemon`** — verifies the whole hash chain of the existing log (a torn last record is
   recovered into a new segment; any other break prevents start), then listens.
3. **`keyd`** — configuration, account-to-role table, key store, hardening; the start hold-down
   begins.
4. **`keyadm ceremony`** — creates the domain's key sets and seals the ceremony (repeated after
   each `keyd` start while the development key store is in use), followed once by
   `provision first-admin-secret`.
5. **`dird`** — opens the store with its integrity key (a wrong key is detected as tampering),
   loads the policy, verifies `audit-daemon`, and listens.
6. **KDC** — binds its ports as root before dropping privileges, verifies `keyd` (its role and
   configuration) and `dird` (realm, naming context, policy version), and starts serving UDP and
   TCP 88 only after all checks succeed.
7. **`ldap-front`**, **`kpasswd-front`**, **`dns-daemon`**, **`admin-daemon`** — each verifies
   `audit-daemon` and its upstream before serving. `dns-daemon` does not answer anything until it
   holds a first valid zone image from `dird`.

Every daemon verifies the audit daemon at start and does not start without it. Any start-up
failure exits with an error code; restarting with back-off is the service manager's job. There is
no network health endpoint; each channel has a ping message for its authorised peer.

## Fail-closed behaviour

| Situation | Behaviour |
|---|---|
| `keyd` unavailable, busy, or in its start hold-down | The KDC answers `KDC_ERR_SVC_UNAVAILABLE` over TCP and stays silent over UDP — never "wrong password". The decision is made before any secret-dependent work and does not depend on the request, so it is not an oracle. |
| `dird` unavailable | The KDC refuses in the same way; `ldap-front` closes the connection (no answer without the enforcement point); `kpasswd-front` returns a hard error. |
| The KDC's policy version differs from the version of `dird`'s view | The request fails closed (answered as service unavailable) until both processes run the same policy version. |
| A server answers under an unexpected account, role or configuration | The connection is dropped before any request is sent; at start-up, the daemon does not start. |
| `audit-daemon` unreachable or not acknowledging | Every operation that must be audited before it happens is refused as not performed. |
| `dns-daemon` has no zone image, or its image is older than the configured maximum age | No start; later, `SERVFAIL` to every query. |
| A malformed frame, wrong magic or unknown message kind | The connection is closed. |
| A restarted `keyd` or `dird` | The first request after the restart reaches the new process; held connections are checked before reuse. Exchanges in progress fail and the client starts again. |

## The audit pipeline

Every daemon sends its audit events to `audit-daemon` over `audit.sock`.

- **The source of an event is set by the audit daemon** from the sender's account, never taken
  from the event. Each kind of event is accepted only from the one daemon that may produce it; a
  batch containing another daemon's event shape is refused and counted.
- Each sender has one audit client, which verifies on every connection that the audit daemon runs
  under the expected account and records the sender under the expected source.
- Events are framed with the same codec as every other channel and carry only identifiers, codes
  and metadata — never keys, passwords, tickets, raw request bytes or attribute values.
- The audit daemon appends each batch to a **hash-chained log** (SHA-256 over each record,
  including the previous record's hash), writes, flushes and syncs it, and only then
  acknowledges. A batch resent after a lost acknowledgement is not appended twice; a reused
  sequence number with different content is refused and recorded.
- **Intent before mutation.** For every state change — a key change in `keyd`, a directory write
  or dual-control step in `dird`, a password set in `admin-daemon` — the daemon first records its
  intent or decision and waits for the audit daemon's acknowledgement. Without the
  acknowledgement within a short deadline, the operation is not performed and a "not performed"
  record is written. After the operation, the outcome is written into a slot reserved in advance;
  an outcome that still fails to arrive is counted, so the gap itself is visible in the log. This
  is enforced by type: the functions that change state take an acknowledged-intent value, which only
  the audit gate can create.
- **Noise is summarised, not dropped.** Refused connections, malformed messages and rate-limited
  traffic are counted and sent as periodic window summaries, at most one per heartbeat, so a flood
  cannot flood the log.

The log is not signed yet and is kept on the domain controller only; both are planned (see
[SECURITY-MODEL.md](SECURITY-MODEL.md#residual-risks)).
