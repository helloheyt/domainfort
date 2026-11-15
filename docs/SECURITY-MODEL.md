# Security model

This document explains what Domainfort defends, against whom, and how. Its central idea is simple:
**the goal is not to find vulnerabilities and patch them one by one, but to build infrastructure in
which whole classes of vulnerability have no place to exist.**

The architecture this relies on is described in [ARCHITECTURE.md](ARCHITECTURE.md).

## What is protected

| Asset | Why it matters |
|---|---|
| Long-term keys (the `krbtgt` key, service keys, account keys) | Whoever holds them can mint credentials for the whole domain. |
| Integrity of the directory | Group memberships, tiers and security descriptors decide who may do what. |
| The policy | It decides every access request. |
| Passwords in transit | A password seen once is a credential forever. |
| The audit log | It is how misuse — including misuse by administrators — is detected. |
| Availability of authentication | Every member depends on it. |

## Threat model

Domainfort is designed to hold against the following adversaries:

- **An attacker on the internal network** who can send arbitrary, malformed or spoofed packets to
  every listening port, flood them, replay captured traffic and attempt downgrades.
- **A compromised domain member or user account**, including a user who tries to guess passwords,
  to reach objects it should not see, or to escalate by changing its own attributes.
- **A compromised network-facing process.** Every parser is assumed breakable. A process that
  parses network bytes is therefore given nothing worth stealing: no long-term key, no directory
  store, no channel to the key holder unless it needs one, and only the narrow messages of its own
  role on each internal channel.
- **A single compromised or careless administrator.** Changes to tier-0 objects, to the policy and
  to keys need a second, independent approver who sees exactly what will happen, and every step
  is audited.
- **A compromised component of the administration plane** — for example the local administration
  daemon. It forwards administrators' signed requests but cannot alter them, cannot claim an
  identity, and never sees anything it does not need.
- **A local unprivileged account on the domain controller**, which may try to redirect privileged
  file accesses, impersonate a daemon on a local socket, or read a process's memory.
- **The supply chain** — dependencies that change unexpectedly or bring in code with unwanted
  capabilities.

Out of scope, or only contained: the superuser on the domain controller itself; physical access to
the machine; a compromise of `keyd` itself or of the online KDC path (see
[Residual risks](#residual-risks)); and timing side channels, which are bounded where practical but
not eliminated.

## No code path for weak options

Weak options are not disabled by default — they do not exist in the code. There is no setting, flag
or compatibility mode that brings them back, because there is nothing to bring back.

| Absent | Notes |
|---|---|
| NTLM (all versions), LM | No NTLM means no reusable password hashes for users. |
| SMB 1 | Only SMB 3.1.1 is planned. |
| RC4-HMAC, DES, 3DES in Kerberos | Only the four AES encryption types exist (17, 18, 19, 20). Any other type number is an error. |
| LDAP simple bind with a password | Refused before any lookup and without consulting the key holder. |
| SASL DIGEST-MD5 | Not implemented. |
| Unauthenticated RPC (except the endpoint-mapper lookup) | Planned RPC services require authentication with privacy. |
| NetBIOS, WINS, LLMNR | Not implemented. |
| Netlogon without AES and sealing | The planned secure channel is Kerberos-based only. |
| Stored passwords in Group Policy preferences | Will be refused when written. |
| TLS below 1.3 on the LDAP front | The TLS configuration admits TLS 1.3 with AES-GCM suites only. |
| Kerberos requests without FAST armor | Except one narrow, documented bootstrap case for computer accounts. |
| Unsigned or UDP DNS updates | Only GSS-TSIG-signed updates over TCP are forwarded for a decision. |
| The legacy version of the change-password protocol | Answered with a version error; never forwarded. |

## Root cause first

When a weakness is found — by a review, a test, or a report — the response follows a fixed order:

1. **Name the class.** What general kind of flaw is this? For example: "a component performs a
   privileged change without the decision of the component that owns it", "a value from one trust
   domain is accepted in another", "an error reveals whether something exists", "a time window
   between check and use".
2. **Look for a root-level change that makes the whole class impossible by construction** — not
   detected, not discouraged: impossible. Typical tools are a type that can only be built after
   the check (a capability or proof object); a single chokepoint every instance must pass; removing
   the capability from the component that should not have it; making the unsafe state impossible
   to represent; or splitting processes so the data never reaches the wrong one.
3. **If such a change is possible, change the infrastructure** and apply it everywhere the class
   can occur — not only where it was found.
4. **Only if it is impossible**, make a local fix and record why the class cannot be eliminated and
   what risk remains.

The following sections are examples of classes that the current code makes impossible by
construction. Each names the class, the structural change, and what is left.

### Keys never leave the key holder

- **Class:** a process that parses untrusted input also holds, or can obtain, long-term key
  material.
- **Structural change:** `keyd` is the only process that holds long-term keys, and no operation it
  offers returns one. It verifies, seals, issues and derives on behalf of its callers. Only `keyd`
  links the Kerberos cryptography crate; the KDC, the fronts and the administration daemon have
  tests that fail if they ever link it, the directory store, or `keyd`. Even the FAST armor keys
  and the change-password subkey stay inside `keyd`, and a new password sent with the
  change-password protocol is decrypted only inside `keyd`.
- **What remains:** `keyd` itself is the concentration point; its interface is kept narrow and every
  operation is audited.

### One decision owner for every key change

- **Class:** a component performs a privileged state change on its own judgment, without the
  decision of the component that owns that decision — or a component vouches for a fact (such as
  "these two people approved") that it cannot prove.
- **Structural change:** `keyd` performs no key change for the administration roles unless `dird`,
  which owns the policy decision, has registered a one-time, operation-bound decision for it. The
  key-administration tool names only the decision's id; `keyd` executes the parameters it holds,
  not parameters supplied by the caller. The dual-control proof for a `krbtgt` rotation is built
  inside `keyd` from the decision's verified approvers and cannot be expressed by anyone else. A
  decision is consumed by its first use and its result kept until it expires, so presenting the id
  again returns the same result instead of acting twice. Withdrawing or rejecting an approved key
  request revokes the decision in `keyd` before the request disappears. Creating keys is possible
  only during the provisioning ceremony, which a one-time seal ends.
- **What remains:** `dird` is a deliberate chokepoint and is therefore equivalent to tier 0.

### Change-password requests without armor cannot be expressed

- **Class:** a client chooses a weaker option in its request and the server honours it.
- **Structural change:** a ticket for the change-password service can be issued only on the
  armored (FAST) path. The unarmored path of the KDC has no value that names that service, and inside
  `keyd` the issuance step for it holds the armor directly rather than as an optional field. An
  unarmored request for it is therefore not refused by a check that could be forgotten — it cannot
  be represented at all, in the KDC or in `keyd`. The ticket profile is fixed (at most 300 seconds,
  never renewable, forwardable or proxiable) and enforced in `keyd`; the TGS refuses the name.
- **Related:** the channel between the change-password front and `dird` has no type that can hold a
  clear-text password: the crate does not link the Kerberos message codec, has no secret field, and
  accepts only the encrypted message form.

### One dual-control mechanism, re-evaluated at every step

- **Classes:** two implementations of one control drift apart; an approval is judged against a
  state that changes before execution; a human approval control is flooded.
- **Structural change:** every dual-controlled operation — on tier-0 directory objects, on the
  policy, and on keys — goes through one table of pending requests in `dird`: propose, approve,
  reject, withdraw, list, show. There is no field on the wire for approvals carried inside a
  request; the older mechanisms were removed. At every approval and again at execution, `dird`
  re-evaluates everything the approval was judged on: the policy version, a SHA-256 digest of every
  directory record the operation's dry run read, and the standing of the requester and of each
  approver. Any change drops the request. An approver is shown the operation from `dird`'s own
  record, never from text the requester supplied, and approves one request by its exact operation
  digest. A request that needs no approver is refused; requests are bounded per requester and in
  total, and expire.
- **What remains:** requests live in memory and are lost when `dird` restarts (the safe direction);
  human factors such as approving without reading cannot be removed by code.

### The approved effect is the executed effect

- **Class:** what an approver approves is smaller than what is executed. Example: adding a group
  with forty members to a tier-0 group silently moves all forty members to tier 0, while the
  approver sees only "add one member".
- **Structural change:** operations whose effect reaches beyond their direct target — membership
  changes, enabling or disabling an account, account expiry, deletion, password sets, policy
  changes and key operations — require an **effect plan**. `dird` computes the plan with the same
  functions that enforce the rules (the same group expansion, the same tier classification, the
  same account-state logic) and returns its bytes and digest. The plan's digest is part of the
  operation digest that every administrator's ticket and every approval are bound to. `dird`
  keeps no plans: it recomputes the plan when the request is proposed, at every approval and at
  execution, and any difference stops the operation. An approver must be able to see every
  principal the plan names.
- **What remains:** effects outside the model are not shown; very large plans are refused rather
  than truncated.

### Revocation at one-second resolution, in one place

- **Class:** a time window between check and use caused by resolution. A password set is recorded
  with sub-second precision, while ticket times have one-second precision, so a ticket obtained
  earlier in the same second as the password change could survive it.
- **Structural change:** there is exactly one definition of the revocation cut-off for an account —
  a password set revokes every ticket authenticated **at or before** its second — and every path
  that checks revocation uses it: the AS exchange and armor, the TGS exchange, LDAP, the
  administration plane and the change-password service. A single change in that definition closes
  the window on every path at once.
- **What remains:** a ticket obtained in the same second *after* the change is revoked too, which
  costs one extra authentication — the safe direction.

### Reserved service names belong to their provisioned object

- **Class:** a privileged service name is carried by an object other than the one provisioned for
  it — for example a second computer object claiming the change-password service's name.
- **Structural change:** one general rule in the write path: a reserved key purpose derived from a
  name can be carried only by the provisioning claim that owns it. The match is exhaustive, so a
  newly added reserved purpose fails closed until it is assigned. The online write path refuses any
  service principal name from which a reserved key purpose derives, and the change-password service starts only if the object in the
  directory is the one recorded at provisioning.

### What a binary links cannot depend on what is built with it

- **Class:** an artifact's linked code depends on which other crates happen to be built in the same
  build (feature unification), so a daemon can silently gain code — for example the key holder's
  cryptography or the directory store — that it must never contain.
- **Structural change:** no manifest in the workspace declares an optional dependency, so features
  cannot pull crates into a binary. Code that converts between audit shapes lives with the crate
  that already links the source, and the audit client is its own crate. Separate crates replace
  features wherever a capability must stay out of some processes, and guard tests check, for each
  sensitive daemon, that it does not link the crates it must not contain.
- **What remains:** a build-time check of every artifact's complete linked set is planned.

### More examples

| Class | Structural change |
|---|---|
| A valid credential is attached to a different operation than its owner intended (confused deputy) | An administrator's Kerberos authenticator carries a checksum over the digest of the exact operation, verified inside `keyd`. A ticket for the administration service without that binding is refused. |
| A key is used under a name it is not bound to | Inside `keyd`, a key can be obtained only through a proof type that is produced by checking the binding between the name and the key; there is no accessor that skips it. |
| An error reveals what the authority would hide | `keyd` can build a specific refusal reason only from a value that exists after the whole cryptographic chain verified; before that, every failure is the same uniform denial. The directory has one visibility gate, in which "does not exist" and "exists but not visible" are the same answer. |
| A write invariant is enforced on only one of several write paths | One checked write path for online and offline writes, the only door to the store's mutating calls. Group nesting depth and closure size are bounded; cycles are refused. |
| A mandatory audit record is lost, forged or not flushed | The audit daemon sets each event's source from the sender's account; each event shape is accepted only from its one sender; state-changing functions take an acknowledged-intent value that only the audit gate creates; a single close path flushes. |
| The peer's identity is verified only if the caller remembers to | Clients cannot be constructed without the expected server account (and role); the check runs on every new connection before any request. |
| A privileged file access can be redirected through a symbolic link | One module opens every protected file, walking from `/` one component at a time without following links and checking each directory's owner and permissions. |
| A test hook is reachable from product code | Test seams exist only behind a development-only feature, and a test checks that no daemon's product entry point uses them. |
| A security time value is supplied by a less trusted caller | `keyd` reads its own clock; no request carries a time. |
| State lost on restart makes a guard more permissive | `keyd` refuses the Kerberos-path operations for twice the clock skew after every start, because its replay cache was lost. |

## Parsers

Every parser that handles untrusted input is strict and bounded:

- definite lengths only; a length is checked against a fixed maximum **before** any allocation;
- recursion depth and element counts are bounded;
- one canonical encoding per value — non-canonical input (for example non-minimal DER) is refused;
- no general-purpose deserializer anywhere: every format, including internal IPC, configuration,
  policy and the provisioning manifest, has its own hand-written, closed codec;
- parsers are written not to panic on any input, and non-test code avoids `unwrap`, `expect` and
  explicit panics;
- each network-facing parser is its own crate, and the parser runs in a process that holds nothing
  of value.

Every parser has a fuzz target in a workspace detached from the product build (46 targets in 27
crates). Continuous fuzzing is not set up yet; see [BUILDING.md](BUILDING.md#fuzzing).

## Secrets

- Keys, passwords, the `krbtgt` key and raw request bytes never appear in logs, panics, debug output
  or error messages. Secret-bearing types have no printing implementation that shows their content.
- Buffers that carry a password or key are wiped after use, on both ends of a channel.
- Operational log lines are fixed texts with codes and identifiers.
- Core dumps are disabled and the daemons are non-dumpable; `keyd` and the administration daemon
  lock their memory.
- No secret is ever placed in a command line, an environment variable or a configuration file;
  configuration names paths to protected files.
- A password set through the administration plane goes from the administration daemon to `keyd`;
  it never reaches `dird`. A password changed with the change-password protocol is decrypted only
  in `keyd`.
- User accounts never have an NT hash; there is no NTLM and no RC4.

## Dependencies

- **Licence allow-list:** MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0.
  Anything else is refused; `cargo deny` and the dependency installation script check it.
- **No vendored code.** Dependencies are declared in `Cargo.toml`, pinned with checksums in
  `Cargo.lock`, and downloaded at build time from the official registry. No third-party code is
  copied into the repository, and a scan in CI looks for signs of it.
- **No protocol logic from others.** No library that implements Kerberos, LDAP, SMB, DCE/RPC, NDR,
  a DNS server or directory logic may be added; that logic is this project's own work. Examples
  are banned in `deny.toml`.
- **No cryptographic primitives implemented in-house.** AES, SHA-1, SHA-2, HMAC and PBKDF2 come from
  the RustCrypto crates; TLS comes from rustls with the aws-lc-rs provider, linked only by the LDAP
  front. Protocol-level constructions defined by the Kerberos RFCs (key derivation, ciphertext
  stealing, the encrypt-with-integrity layouts) are written here on top of those primitives and are
  verified against the RFC test vectors.
- **A new dependency needs explicit approval.** The current direct dependencies are: `aes`, `sha1`,
  `sha2`, `hmac`, `pbkdf2`, `zeroize` (cryptography and secret hygiene), `rustls` and `aws-lc-rs`
  (TLS), `redb` (embedded storage), `tokio` (asynchronous runtime) and `rustix` (operating-system
  calls without `unsafe` in this project's code).
- The check gate builds with `--locked`, so a change to the dependency graph that was not reviewed
  is a failure.

## Residual risks

These are stated plainly because they are real.

| Risk | Status |
|---|---|
| **Development key store.** `keyd` keeps keys in memory only; they are lost on restart and are not sealed by hardware. | The sealed, persistent store's format and custody interface exist; the sealing is waiting on a cryptographic library decision, and a hardware-anchored backend is planned. Not deployable until then. |
| **Development integrity key and unsigned policy.** `dird` reads its store integrity key from a root-only file and its policy from an unsigned format. | Both must be named explicitly in configuration and produce a warning at every start. A signed policy store is planned. |
| **Unsigned, local audit log.** The log is hash-chained, so changes inside it are detectable, but it is not signed and not copied off the machine. Changing the last records needs a head held elsewhere to detect. | Signing the chain head and forwarding off-box are planned. |
| **`dird` is equivalent to tier 0.** It is the single decision owner for writes and key changes. | Deliberate concentration; narrower designs in which `keyd` verifies the human approvals itself are under consideration. |
| **A compromised online KDC path can mint tickets.** This is structural for any KDC. | Contained by key isolation, short ticket lifetimes, rotation and audit; hardware security modules are planned for the most critical keys. |
| **Unauthenticated UDP.** DNS and Kerberos over UDP cannot authenticate the source address. | Internal networks only, per-source and global limits, replies no larger than allowed; a forged DNS answer still cannot produce valid Kerberos tickets. |
| **Process isolation is user-based.** seccomp filters, Landlock and namespaces are not used yet. | Needs `unsafe` code or a new dependency, which requires an explicit decision. |
| **Fuzzing has not run continuously.** | The targets exist; running them awaits approval of the fuzzing harness dependency. |
| **Timing.** Response times of large directory searches depend on the size of the visible subtree. | Bounded by budgets, not hidden. |
| **Windows-facing protocols are not built yet.** Some Windows requirements are fixed by Windows itself (for example the checksum types older clients use, or time signing that depends on a computer-account secret). | Each will be confined to a narrow, documented path when that part is built. |
| **Human factors** — approving without reading, approval fatigue, look-alike names. | Mitigated by showing the effect plan and the server's own record of the request; not eliminable by code. |
| **Pre-alpha software.** No external audit has been performed. | — |

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
