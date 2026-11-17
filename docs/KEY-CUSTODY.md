# Key custody

This document describes `keyd`, the process that holds every Kerberos key of a Domainfort domain:
why it exists, what it computes, who may call it, and what remains when something around it is
compromised. The short overview is in [ARCHITECTURE.md](ARCHITECTURE.md#keyd--the-key-holder); this
page goes deeper and does not repeat it.

> **The key store is development-only today.** Keys live in process memory and are lost when
> `keyd` stops. A sealed, persistent store is designed but not built. This is the main gap before
> any real deployment (see [Key storage](#key-storage-the-main-gap-before-deployment)).

## Status at a glance

| Mechanism | Status |
|---|---|
| Compute-don't-give interface, roles, key purposes, one-time tokens, replay cache, throttle | implemented |
| Issuance through `dird`'s attested name resolutions; the key set reached only through `store::bound_by` | implemented |
| FAST inside `keyd`; start hold-down; key ceremony and seal; decision table; audit gate | implemented |
| Pre-authentication by name resolution; `keyd` stamping the time of an armored error itself | planned |
| Sealed persistent key store with a TPM or HSM backend | format and backend interface implemented; the store, its start sequence and the hardware backends planned |

## Why one process holds every key

- The KDC, the fronts and every parser handle attacker-controlled bytes. If one held a long-term
  key, one parser bug could leak `krbtgt`: offline forgery for the whole realm until rotation. With
  one holder, a compromised KDC can use `keyd` only online, through its role's narrow operations,
  while the compromise lasts; it cannot carry a key away.
- One small process to harden (no network socket, memory locked, not dumpable, no core dumps) and
  audit. The cost: `keyd` is the concentration point, so its interface is kept narrow.
- **Only `keyd` links `krb-crypto`** (in the normal dependency graph, only `keyd` and the two crates
  wrapping it reach it). The KDC daemon, `dird`, the administration daemon and each front have a
  guard test that fails if they link it; the KDC's also forbids the name-attestation, HMAC and SHA-2
  crates. The guard `weak_primitive_confinement` confines SHA-1 to `krb-crypto` and fails if an
  MD4, MD5, RC4, DES or CRC-32 crate enters the lock file.

## What keyd holds

- **Key sets**, one per `KeyHandle` (principal id plus purpose), with a current key version and at
  most one previous one; sealing uses the current, opening may try both until one is retired.
- **Five purposes** (`KeyPurpose`), each usable only by its own operations: `PrincipalLongterm`,
  `Krbtgt`, `Service`, `AdminService` (`admind/<host>`), `ChangePasswordService` (`kadmin/changepw`).
- **One name binding per key set**, fixed at creation, from a binding that passed the creation rule
  (`check_new_binding`): an `AdminService` set, for example, binds only to an `admind/<host>` name,
  and no other set may take one.
- **AES keys only** (types 17–20; default 18 then 17). No NT hash: the build contains no MD4 code.
- **The attestation key** that verifies `dird`'s name resolutions, installed in the ceremony; and
  bounded, in-memory state: token tables, replay cache, decision table, throttle, ceremony state.

## Compute, don't give

A naive design would offer `encrypt(key, bytes)` or `decrypt(key, bytes)`, which an attacker can use
as an oracle without ever reading the key. `keyd` leaves no place for one:

1. **No generic operation.** The closed `Operation` enum has no export, read, encrypt, decrypt or
   sign operation, and each handle's purpose is checked against its slot (`purpose_permitted`).
2. **`keyd` builds what it seals.** The KDC supplies only a ticket template (times, requested flags);
   `keyd` checks it against the ticket policy, draws the session key, builds the encrypted parts and
   sets the flags that record what it verified, such as INITIAL and PRE-AUTHENT (RFC 4120 §2.1).
3. **Uniform errors.** Every failure before the whole cryptographic chain verified is the same
   `Denied`. A specific class (clock skew, not yet valid, expired, replay) can only be built from
   `ChainVerified`, a type made from evidence of the verified steps.
4. **Key usage numbers** separate every use of one key (RFC 3961 §2; RFC 6113 §6.2).

### What leaves and what never leaves

| Leaves `keyd` | Never leaves `keyd` |
|---|---|
| Sealed tickets and reply parts; the sealed FAST reply or error; the sealed change-password reply | Long-term keys: `krbtgt`, account keys, service keys |
| One-time token ids (128 random bits) | Session keys and authenticator subkeys — no current operation returns one |
| Non-secret facts: client realm and name, times, flags, verdict codes | FAST armor, challenge, strengthen and reply keys (the strengthen key only inside the sealed FAST reply) |
| The decrypted inner FAST request (`KrbFastReq`) | The new password of a change-password request |
| The key version `keyd` chose; its non-secret configuration; the caller's own role | The attestation key: `keyd` only verifies with it, never tags |

### Keys only through a proof of the name binding

Inside `keyd`, key material is reachable only through `BoundKeys`, a proof type that one of four
doors builds after its check:

| Door | Used for | Check |
|---|---|---|
| `store::bound_by` | AS and TGS issuance under a client or service key set (the AS client, the change-password service, every TGS service) | Takes a `VerifiedNameResolution` — `dird`'s statement whose tag, realm and freshness (30 seconds on `keyd`'s clock) were checked — and looks the key set up itself from it. Refuses a `krbtgt` set; the resolution's canonical name must be the set's bound name, and the ticket's name one of the resolution's names. |
| `StoredKeySet::ticket_granting` | Sealing a TGT; opening a TGT or FAST armor ticket | A `Krbtgt` set bound exactly to `krbtgt/<REALM>` (RFC 4120 §7.3) |
| `StoredKeySet::accepting` | Verifying a service AP-REQ (administration channel, change password) | The ticket's server name and the set's binding are one principal in the namespace's one equivalence |
| `StoredKeySet::bound_to` | `set_secret` on an existing key set | The set is bound to the request's own binding |

Pre-authentication reads the current key through `unbound_current`, which names a closed
`UnboundUse`; it issues nothing, and its proof is redeemed only by `issue_as_rep` through `bound_by`.
A test (`key_access_inventory`) pins which file uses which door. **Each resolved key set is named
once:** `issue_as_rep` and `issue_tgs_rep` take no handle for the client or service key set, only
the resolution, which the KDC forwards but cannot make or change; only the `krbtgt`, which has no
resolution, keeps its handle. See [PRINCIPAL-NAMESPACE.md](PRINCIPAL-NAMESPACE.md).

## Roles and operations

A caller's role comes from its connection's kernel-reported user id, through a static table; the
superuser is never mapped (see [ARCHITECTURE.md](ARCHITECTURE.md#identity)). `CAPABILITY_TABLE` is a
compile-time constant whose security-relevant cells are pinned by compile-time assertions.

| Role | Held by | Operations |
|---|---|---|
| `Kdc` | the KDC (`kdc-daemon`) | `verify_preauth`, `issue_as_rep`, `open_and_verify_tgt`, `issue_tgs_rep`, `open_fast_armor`, `seal_fast_error`, `describe_config`, `ping` |
| `Ldap` | `dird` | `verify_operation_ticket` (administrators' tickets), `open_change_password_request`, `complete_change_password`, `seal_change_password_error`, `register_decision`, `revoke_decision`, `list_destroy_decisions`, `describe_config`, `ping`; `open_and_verify_service_ticket` (for the planned LDAP Kerberos bind; no product path calls it yet) |
| `Directory` | `admin-daemon`; `provision first-admin-secret` runs under its account | `set_secret` (only on a live decision or ceremony grant), `ping` |
| `Admin` | `keyadm` | before the seal: `create_key`, `install_attestation_key`, `grant_set_secret`; always: `seal_ceremony`, `list_destroy_decisions`, `ping`; only by a `dird` decision id: `rotate_key`, `rotate_krbtgt`, `retire_kvno`, `destroy_key_set` |
| none | — | `verify_secret` exists but no role may call it: it would be a password-guessing path that bypasses FAST |

Every call is admitted in this order, before any key, token, throttle or replay entry is read: the
role permits the operation; each handle's purpose fits its slot; the start hold-down; the ceremony
state (`provisioning_only` operations are `Denied` after the seal); for `requires_decision`
operations, a live decision. Each table is an exhaustive match: a new operation does not compile
until it is classified.

**Decisions** ([SECURITY-MODEL.md](SECURITY-MODEL.md#one-decision-owner-for-every-key-change)):
after the ceremony, `keyd` changes no key for `Directory` or `Admin`, and completes no password
change, without a one-time decision `dird` registered. It runs the registered parameters, never the
caller's; key operations need two distinct approvers. Decisions run at most once, expire (password
sets 30 seconds, key operations an hour, destructions seven days) and are lost at a restart, which
only makes `keyd` stricter. `keyd` still enforces the 8-character password minimum itself.

## One-time tokens

Issuance must follow a verification `keyd` performed itself; the link is a token, so there is no
path to an `issue_*` operation without a completed verification.

| Token | Created by | Redeemed by | What `keyd` keeps behind it |
|---|---|---|---|
| exchange id (`AuthnProof`) | `verify_preauth` | `issue_as_rep` | client principal, authtime, reply encryption type and key version, the armor if any |
| TGS context id | `open_and_verify_tgt` | `issue_tgs_rep` or `seal_fast_error` | the TGT's client and times, the reply key (TGT session key or subkey), the armor key if armored, the request's nonce and service name |
| armor id | `open_fast_armor` | `issue_as_rep` or `seal_fast_error` | armor key; the inner request's nonce, realm, client name and encryption types |
| change-password context id | `open_change_password_request` | `complete_change_password` or `seal_change_password_error` | session key, subkey, the new password (only for an acceptable request) |

- Each id is 128 random bits, bound to the calling process and the principal, and lives
  `token_lifetime_secs` (default 30 seconds, at most 300). It is consumed on first presentation; one
  presented by another caller is treated as leaked and destroyed; expired entries are wiped. The FAST
  armor and an armored TGS context are consumed only by a successful issuance or by sealing the
  error, so a refusal can still be answered armored.
- Tables are bounded and refuse new tokens when full rather than evict a live one. The one replay
  cache covers every AP-REQ `keyd` verifies and behaves the same way (RFC 4120 §3.2.3).

## Pre-authentication throttle

- A per-principal failure window inside `keyd` (`FailureWindowThrottle`), checked after admission
  and before any key is touched, for every caller, the KDC included. Default: 5 failures per 300
  seconds, 4096 principals tracked; when full, an untracked principal is refused, so flooding the
  table does not escape it.
- Only a failed cryptographic check counts; both paths (encrypted timestamp, encrypted challenge)
  share one count, and a success clears it. A throttled attempt is the uniform `Denied`, recorded as
  `Throttled`. Under FAST each guess also costs a fresh armor from a valid computer TGT.
- Trade-offs: anyone who can send AS requests can lock a principal out for one window, and the
  counters reset when `keyd` restarts. Open design question: whether every principal should start
  after a restart as if one failure were already counted.

## FAST armor inside keyd

FAST (RFC 6113) is mandatory; the policy and the one bootstrap exception are in
[PROTOCOLS.md](PROTOCOLS.md#kerberos). Every FAST step that needs a key runs in `keyd`; the KDC only
frames messages and applies policy to the inner request. The armor key must stay inside: the FAST
reply carries the strengthen key, so a KDC holding the armor key could open the reply.

- **`open_fast_armor`** opens the armor TGT (through the `krbtgt` door) and its authenticator (subkey
  mandatory, RFC 6113 §5.4.1.1), derives the armor key, verifies the checksum over the outer request
  and decrypts the inner request (§5.4.2). It returns the armor id, the armor client's name and
  authtime, and the inner request; the KDC checks that the armor client is an enabled, unrevoked
  computer account (`keyd` holds no account kind).
- **No decryption oracle:** `keyd` decrypts only under an armor key derived in the same call from a
  verified AP-REQ, with one key usage, and returns only a decoded `KrbFastReq` — what the client
  sends the KDC anyway, its secret padata still encrypted under other keys.
- **Armored pre-authentication** accepts only the encrypted challenge (§5.4.6), one attempt per
  armor; a replayed challenge fails because its key depends on an armor already in the replay cache.
- **Armored issuance** binds the inner request's client name and nonce, always strengthens the reply
  key (§5.4.3) and adds the finished checksum, so a passive observer cannot attack the password
  offline through the reply.
- **TGS** uses implicit armor only — the PA-TGS-REQ subkey (mandatory) and the TGT session key
  (§5.4.2); an explicit armor field is refused, and the strengthen key is mandatory.
- **Armored errors.** `seal_fast_error` lets a compromised KDC have only an *error* sealed, bound to
  the request being answered: no e-data or e-text, a non-zero code, the inner request's realm and
  names, padata from a short allow-list, no strengthen key or finished field, the stored nonce
  (§5.4.4). It consumes the token. Refusals before an armor exists go out unarmored.
- **Planned: `keyd` stamps the error time.** Today the error's time must equal `keyd`'s own second;
  when the two processes' clock reads straddle a second, `keyd` refuses and the KDC sends the same
  code unarmored — fail-safe, but without FAST protection for that error.

## Start hold-down

- The replay cache and token tables are empty after every start, and RFC 4120 §3.2.3 requires a
  server that lost track of authenticators to reject requests until the skew interval passed. So
  `keyd` answers `Unavailable` while `now ≤ start + 2 × clock_skew_secs` to every operation of the
  Kerberos exchanges: the `Kdc` row except `describe_config` and `ping`, the two service-ticket
  verifications and the three change-password operations (`startup_hold_down_applies`).
- **Why two intervals** (`STARTUP_HOLD_DOWN_SKEW_INTERVALS`): an authenticator accepted just before a
  restart at server time S may carry a client time up to S + skew and stays acceptable until
  S + 2·skew. At the default skew of 5 minutes (RFC 4120 §8.2) that is 10 minutes without Kerberos.
- It is decided from the time, the start time and the operation alone, before any secret-dependent
  work, so it reveals nothing; a time before the start, or an overflow, holds. Both times come from
  `keyd`'s own clock; no request carries a time.
- Not held: `Directory`, `Admin` and decision operations, `describe_config`, `ping`. The ceremony
  runs at once; the administration plane waits (its tickets are verified by a held operation).

## Key ceremony

`keyd` starts in `Provisioning` only when its key store is empty — today, at every start.

1. **`provision domain`** (offline) draws the attestation key from the system's secure random
   source, writes it to `dird`'s key file and to a copy for `keyadm` (both mode 0400), and writes a
   non-secret manifest of identifiers, name bindings and the first administrators' salts. Then
   `audit-daemon` and `keyd` start; `keyd` logs a fixed warning about the development store.
2. **`keyadm ceremony`** (role `Admin`; stops at the first failure, never repeats a request):
   - `create_key` for `krbtgt/<REALM>` (`Krbtgt`), `ldap/<fqdn>` (`Service`), `admind/<fqdn>`
     (`AdminService`) and `kadmin/changepw` (`ChangePasswordService`); `keyd` draws each key from the
     kernel's random source, chooses the key version and never overwrites a set;
   - `install_attestation_key`, once per start;
   - `grant_set_secret` per first administrator: an initial secret only, bound to the manifest's
     binding and salt, valid at most 15 minutes;
   - `seal_ceremony`, refused without an attestation key. Afterwards `create_key`,
     `grant_set_secret` and `install_attestation_key` do not exist.
3. **`provision first-admin-secret`** runs under the administration daemon's account and calls
   `set_secret` within the grants' lifetime; passwords come from a terminal or a protected file,
   never from the command line or the environment. Then `dird`, the KDC and the fronts start.

**Residual.** The ceremony state follows from "the store was empty at start", so with the development
store every restart reopens the ceremony and requires repeating it (a new `krbtgt` invalidates every
TGT; other accounts need a password reset). In the sealed-store design the state comes only from the
backend's positive "never initialised" fact or an authenticated header, never from a missing file.

## Audit of keyd's own decisions

The pipeline is in [ARCHITECTURE.md](ARCHITECTURE.md#the-audit-pipeline); specific to `keyd`:

- **One record per call**, with no secret: time, caller role and user id, operation, principal,
  purpose, key version, a second key reference, up to two approvers, decision id, outcome, reason.
  The caller sees the uniform `Denied`; the specific reason goes only to the log.
- **Gated:** for every operation except `describe_config` and `ping`, an audit slot is reserved
  before `keyd` runs, or the caller gets `Busy` and `keyd` is not called.
- **Intent first** (`requires_acknowledged_intent`) for the key-state changes — `set_secret`,
  `create_key`, `rotate_key`, `rotate_krbtgt`, `retire_kvno`, `destroy_key_set`,
  `complete_change_password`, `install_attestation_key` — and for `grant_set_secret` and
  `register_decision`, which loosen `keyd`'s authorisation. Without the audit daemon's
  acknowledgement of the intent within one second, `keyd` does not run the operation and answers
  `Unavailable`, which for these operations always means "not done". A decided operation's intent is
  built from `keyd`'s own decision table, not from the request. A refusal is one record, no intent.

## A compromised KDC process

| It can | It cannot |
|---|---|
| Skip every policy decision (the policy decision point runs in the KDC process): for a client that really authenticated, or presented a valid TGT, have a ticket issued that the policy would refuse. This matters most when the attacker also controls an account. | Read, export or derive any key — long-term, session or FAST. No offline forgery, no lasting "golden ticket". |
| Choose lifetimes and flags inside the realm's ticket policy, which `keyd` enforces | Issue anything without a fresh token from a verification `keyd` performed, bound to the KDC process and consumed on use |
| Replay a genuine name resolution within its 30-second window: a mapping `dird` changed in the last 30 seconds can still be used | Choose which key set a name maps to: that needs `dird`'s tag, and the KDC daemon links neither the attestation code nor any HMAC |
| Run throttled password checks against any user or computer key set it can name by identifier, including a deleted account awaiting destruction. Nothing can be issued from such a check alone. Planned fix: pre-authentication by resolution. | Put a name in a ticket other than the resolution's, or seal one service's ticket under another service's key |
| See what passes through it: names, times, flags, the decrypted inner FAST request | Change the service name or nonce of the request it answers (for TGS, the body the client's authenticator checksum covers, or the inner FAST request); use the tickets it gets issued, whose session keys are sealed only to the requesting client |
| Deny service: drop requests, seal errors for live conversations, trigger throttle lock-outs | Turn an error into a success; get a change-password ticket without armor or beyond its 300-second profile; set `keyd`'s time (end the hold-down early, revive an expired ticket); call anything outside the `Kdc` row |

The compromise ends when the process is restored. Tickets issued during it stay valid until they
expire, unless their key is rotated and its old version retired (`krbtgt`: twice, then retire).

## Key storage: the main gap before deployment

**Today.** `keyd-daemon` uses `InMemoryKeyStore`: keys in process memory, wiped on drop, lost when
`keyd` stops. `InMemoryKeyStore::new` refuses `krbtgt` keys; only the explicitly named
`InMemoryKeyStore::new_insecure_development_allowing_krbtgt` holds them, and the configuration
accepts only `key_store = insecure-development`.

**Designed, not built: the sealed store.**

- One sealed record per key set under a store wrapping key held by a custody backend (TPM or HSM).
  Its authenticated data binds the format, sealing suite, store id, handle, name binding and, per key
  version, its number, source (drawn by `keyd` or password-derived) and encryption types: a record
  cannot move to another handle or store, and a password-derived version cannot pass as a drawn one.
- A header with a generation counter and a digest over all records detects rollback or deletion of
  one record; a monotonic counter in the backend, outside the file, refuses a whole old file.
- Loading rebuilds every key set through today's constructors and doors; any failure stops `keyd`.
  Executed decision results are stored in the same commit, so a lost reply cannot cause a second
  `krbtgt` rotation after a restart.

**Built so far:** the record and header format with its strict codec (`sealed_store` in
`keyd-types`, no sealing suite assigned), and the custody-backend interface with its start-up probe
and a declared insecure development backend (`CustodyBackend`, `InsecureDevelopmentCustody`), not yet
used by the daemon. **Waiting on:** approval of an authenticated-encryption algorithm for the sealing
suite, the TPM 2.0 specification and a TPM library, and an HSM interface specification. The format
has no record for the attestation key yet. A TPM-sealed store protects the file at rest, not a
running `keyd`'s memory. Open design question: whether a domain controller with a TPM but no HSM may
hold `krbtgt`, given the project rule that critical signing keys need an HSM.

## Residual risks

| Risk | Status |
|---|---|
| **Development key store** — in memory only, lost on restart, not sealed by hardware | Main gap; the sealed store is designed, partly built, and waiting on the decisions above |
| **Reading `keyd`'s memory** (the superuser on the domain controller) yields every key | Memory locked, not dumpable, no core dumps; only an HSM computing inside would remove it |
| **A compromised KDC** can bypass policy for clients that authenticate while it lasts | Contained as described above: no key leaves, short lifetimes, rotation, audit |
| **A compromised `dird`** can sign false name resolutions and register decisions | `dird` is equivalent to tier 0; the creation rule and `bound_by`'s binding check narrow what a false resolution can map to |
| **Pre-authentication names the client key set by handle** | Planned: pre-authentication by resolution |
| **Armored errors can fall back to unarmored** when two clock reads straddle a second | Planned: `keyd` stamps the time |
| **State lost at a restart:** the ceremony reopens (development store) and throttle counters reset | Ceremony: closed by the sealed-store design. Throttle: open design question |
| **Full token tables or replay cache refuse new work** | Deliberate fail-closed trade-off; capacities are configurable |
| **The attestation key is on disk** in `dird`'s file and `keyadm`'s copy, so the ceremony can be repeated | Both mode 0400; `keyadm`'s copy stays until the sealed store exists |
| **Token lookup timing** uses an ordinary hash map | Could inform only the caller a token is bound to; tokens are random, short-lived and single-use |

System-wide residual risks are in [SECURITY-MODEL.md](SECURITY-MODEL.md#residual-risks). To report a
vulnerability, see [SECURITY.md](../SECURITY.md).
