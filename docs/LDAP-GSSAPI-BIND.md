# LDAP Kerberos bind: SASL GSSAPI over TLS 1.3 with channel binding

> **Status: designed, not implemented.** The only part that exists in code is the token-framing
> crate `gss-token` (see [Implementation status](#implementation-status)). Today the LDAP engine
> answers a GSSAPI bind over TLS with `authMethodNotSupported` (7), answers a GSSAPI bind without
> TLS with `confidentialityRequired` (13), and the rootDSE lists no SASL mechanism. Names below
> that do not exist in the code yet are design names and may change.

This document describes the Kerberos bind to LDAP for Domainfort's own (native) clients in the
first phase. The later Windows-facing bind (GSS-SPNEGO, a SASL security layer, other binding
types) is not covered; see [PROTOCOLS.md](PROTOCOLS.md). The process model is in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Profile

| Property | Choice | Source |
|---|---|---|
| Mechanism | SASL `GSSAPI`, Kerberos V5 only, client sends first | RFC 4752 §3; RFC 4422 §5 |
| Transport | TLS 1.3 only: LDAPS on 636, or 389 after StartTLS. GSSAPI on a clear connection is refused before `keyd` is asked. | RFC 4513 §6.1 |
| SASL security layer | None. The server offers only the "no security layer" bit with maximum size 0, and accepts only that selection. | RFC 4752 §3.2, §3.3 |
| Mutual authentication | Required: the GSS mutual flag and the Kerberos `MUTUAL-REQUIRED` AP option | RFC 4121 §4.1.1.1; RFC 4120 §5.5.1 |
| Integrity flag | Required | RFC 4121 §4.1.1.1 |
| Delegation | Refused (there is no path for forwarded credentials) | RFC 4121 §4.1.1 |
| Channel binding | Mandatory, type `tls-exporter`. This deviates from RFC 4752 §5, which requires empty bindings ([open question](#open-design-questions)). | RFC 9266 |
| Mechanism OID | Exactly 1.2.840.113554.1.2.2; the truncated variant is refused | [MS-KILE] 1.9.1, 3.1.1.7 |
| Exchanges per connection | One GSSAPI exchange per TLS connection | RFC 9266 §4.1 |
| Authorization identity | Empty only | RFC 4422 §3.4.1 |
| Service principal | `ldap/<dc-fqdn>`, two components only | RFC 4513 §5.2.1.1; RFC 4752 §3.2 |
| Bounds (project choices) | Initial token ≤ 64 KiB; selection token ≤ 1 KiB; authorization identity ≤ 256 octets; exchange state in `keyd` ≤ 30 s | — |

## Message flow

At most three challenges. `ldap-front` relays each message to `dird` in canonical form; SASL
credentials are opaque to it.

```text
client             ldap-front            dird (LDAP engine)               keyd
  |-- TLS 1.3 ------>| check version and suite
  |                  | EKM := TLS exporter
  |                  |-- Open{Ldaps, EKM} or ->| keep EKM in a one-shot slot
  |                  |   TlsEstablished{EKM}   |
  |-- 1 Bind GSSAPI, initial token ----------->| TLS? slot unused? take it
  |                  |                         | digest := Bnd(EKM)
  |                  |                         | service := ldap/<dc-fqdn>
  |                  |                         |-- AcceptSecContext -------->| framing, AP-REQ chain,
  |                  |                         |   (service, token, digest) | checksum, Bnd == digest,
  |                  |                         |                            | replay cache, AP-REP,
  |                  |                         |<- facts, AP-REP, offer ----| offer Wrap
  |<- saslBindInProgress, AP-REP token --------|
  |-- 2 Bind GSSAPI, empty ------------------->|
  |<- saslBindInProgress, offer token ---------|
  |-- 3 Bind GSSAPI, selection Wrap ---------->|-- CompleteSaslNegotiation ->| consume state, unwrap,
  |                  |                         |   (ctx, token)             | layer = 1, max = 0
  |                  |                         |<- authorization identity --|
  |                  |                         | empty? look up the ticket's client;
  |                  |                         | usable and not revoked: bound until endtime
  |<- success, no serverSaslCreds -------------|
```

- A first BindRequest without credentials gets an empty challenge (RFC 4422 §5, item 2a). The
  `name` field of a SASL BindRequest is ignored (RFC 4513 §5.2.1.2) and kept for audit only.
- A non-bind request mid-exchange cancels it with `operationsError` (1) and a close. A bind with
  another mechanism cancels it and is processed normally; the channel-binding slot stays consumed.

## Channel binding

### Why `tls-exporter`

| Type | Assessment |
|---|---|
| `tls-unique` (RFC 5929 §3) | Not defined for TLS 1.3 (RFC 8446 App. C.5; RFC 9266 §3). Rejected. |
| `tls-server-end-point` (RFC 5929 §4) | An *end-point* binding: it names the server certificate, not the connection. After the TLS private key is stolen from `ldap-front`, an attacker presenting the same certificate gets the same value, so relay still works after the front is restored. Rejected for this profile. |
| **`tls-exporter` (RFC 9266)** | **Chosen.** Defined for TLS 1.3 (§2), *unique* to the connection (§5.1), not secret (§4, §5.1), and mandatory for implementations that bind TLS 1.3 channels (§3). After a compromised front is restored, an AP-REQ bound to an attacker's connection fails on the real connection. |

[MS-ADTS] 5.1.2.2 requires a domain controller to support `tls-server-end-point`. That belongs to
the later Windows-facing bind; this profile has no code path for it.

### Why the TLS front computes it

The value is the RFC 8446 §7.5 exporter of the connection, with the label
`EXPORTER-Channel-Binding`, an empty context and 32 octets (RFC 9266 §2). Only the process that
holds the TLS state can compute it, and that is `ldap-front`. Running TLS inside `dird` would put a
network parser and the TLS library into the directory process; moving TLS secrets to `keyd` would
need secret extraction, which stays off (`enable_secret_extraction = false`). Both were rejected.

`ldap-front` calls the exporter once, right after `check_negotiated` has accepted TLS 1.3 and an
allowed suite, and sends the value to `dird` exactly once: in `Open { listener: Ldaps, … }` on 636
(an LDAPS open cannot exist without it) or in `TlsEstablished` on 389 after StartTLS. A second such
message closes the connection. The front reports a fact about its own connection; it never asserts
that a binding matched. No "binding verified" field exists on the wire. Only `keyd` decides.

### How the value reaches keyd

1. `dird` keeps the 32 octets in a one-shot slot on the connection (`ChannelBindingSlot`), as a
   value that cannot be copied. The slot exists only on a TLS connection.
2. The first GSSAPI BindRequest with an initial token takes the slot. `dird` builds the GSS-API
   channel-bindings structure (RFC 2744 §3.11): both addresses omitted with type
   `GSS_C_AF_NULLADDR` (255), and application data = `tls-exporter:` followed by the 32 octets
   (RFC 5056 §2.1 prefix; RFC 9266 §5.1). It hashes the structure as RFC 4121 §4.1.1.2 defines,
   giving the 16-octet `Bnd` value.
3. `dird` passes it to `keyd` as a `ChannelBindingDigest`, whose constructor refuses 16 zero octets
   (which RFC 4121 §4.1.1.2 defines as "no bindings").
4. `keyd` compares it in constant time with the `Bnd` inside the decrypted authenticator.

The hash is MD5. It will live in one function of one planned leaf crate (`gss-channel-bindings`)
linked only by `dird`; `keyd` does not link MD5. No trust is lost: the input comes from the front
anyway, and `dird` is the enforcement point. Until the MD5 question is decided, nothing can
produce the digest, so no bind can succeed and GSSAPI stays unadvertised.

### One exchange per TLS connection

RFC 9266 §4.1 forbids using one binding for more than one authentication on a TLS connection. A
successful exchange leaves the connection bound. Any failure, and any GSSAPI bind after the slot
was consumed, answers `invalidCredentials` (49) and closes the connection (RFC 4511 §5.3). To
re-bind, for example after the ticket expires, a client opens a new connection. Every attempt
thus costs a TLS handshake, and the front's per-source connection limits throttle attempts
before `keyd` is reached.

## The two keyd operations

All Kerberos and GSS cryptography stays in `keyd`. The AP-REP and both Wrap tokens are built and
checked there. Only the directory-service role (`dird`) may call these operations:

```text
AcceptSecContext(service: PrincipalId, initial_context_token: ≤ 64 KiB,
                 channel: ChannelBindingDigest)
    -> GssAcceptance { ctx, crealm, cname, authtime, endtime, flags, ap_rep_token, offer_token }
CompleteSaslNegotiation(ctx: ServiceCtxId, response_token: ≤ 1 KiB)
    -> SaslSelection { authorization_identity (≤ 256 octets) }
```

There is **no general wrap or unwrap**: `keyd` builds the offer plaintext (`01 00 00 00`) and checks
the selection format itself, so `dird` never gets a MAC oracle over the exchange key.

**`AcceptSecContext`**, in order; every failure is one uniform denial with a reason for audit:

1. Authorization: the caller's role, and the key handle `(service, LdapService)`.
2. Framing (`gss-token`): tag 0x60, minimal length encoding, the exact OID, TOK_ID `01 00`, then a
   strictly decoded AP-REQ with no trailing octets. An unknown TOK_ID is refused, not answered with
   a KRB-ERROR token (a deliberate deviation from RFC 4121 §4.1).
3. The existing service AP-REQ chain of RFC 4120 §3.2.3, shared with the change-password service:
   ticket opened only under a key version `keyd` drew itself; the ticket's server name checked
   through the key store's single acceptor entry point (`accepting`).
4. The RFC 4121 §4.1.1 checksum: present; type 0x8003; at least 24 octets; `Lgth` = 16; integrity
   and mutual flags set; delegation refused; unknown flags and extensions ignored; `Bnd` not all
   zero and equal to `channel`; a sequence number present; `MUTUAL-REQUIRED` set. All of this runs
   before the replay cache, so a channel mismatch leaves no replay entry.
5. The client subkey check, then the shared replay cache.
6. `keyd` draws an acceptor subkey and an acceptor sequence number, stores the exchange state,
   builds the AP-REP (one builder, shared with the change-password service) and the offer Wrap
   token (`SentByAcceptor` and `AcceptorSubkey` set, key usage 22 — RFC 4121 §2, §4.2.6.2).

**`CompleteSaslNegotiation`** first finds the state (bound to the caller, unexpired) and removes
it, so it is consumed on every outcome. It then checks the Wrap token: TOK_ID `05 04`;
`SentByAcceptor` clear; `Sealed` clear; `AcceptorSubkey` set; the rotation undone for any RRC
(RFC 4121 §4.2.5); `SND_SEQ` equal to the authenticator's sequence number; the MIC verified
with key usage 24; octet 0 exactly `0x01`; octets 1–3 zero; the rest is the authorization
identity, which `keyd` returns to the enforcement point without judging it.

| Boundary | Crosses | Never crosses |
|---|---|---|
| `ldap-front` → `dird` | once per connection, the 32-octet exporter value; the canonical LDAP messages | any "binding verified" flag, any identity |
| `dird` → `keyd` | the service principal id, the tokens, the 16-octet digest | the exporter value, any key |
| `keyd` → `dird` | non-secret facts and tokens | the service key, the ticket's session key, either subkey, sequence state |
| `dird` → audit | one LDAP event per request, with the internal reason | tokens, the digest, the exporter value |

## Where identity comes from

1. `keyd` returns `crealm` and `cname` from the decrypted ticket: the bind's **only** identity.
2. On the completing request, `dird` resolves it through the one principal-name lookup path
   (`TicketSubjects::ticket_subject`, context `LookupCtx::TicketClient`; see
   [PRINCIPAL-NAMESPACE.md](PRINCIPAL-NAMESPACE.md)), on that request's fresh directory view.
3. The account must exist, be usable now, and satisfy `authtime ≥ revoked_before`. Otherwise 49.
4. The bound identity (principal, SID, `authtime`, `endtime`) is built only from the consumed
   completion results, which exist only after `keyd` compared `Bnd`. In the design it has no
   `channel_bound` flag: the policy derives "channel bound" and "sealed" from the bound state.
5. Every later request rechecks. Past `endtime` (no skew allowance) the connection is dropped with
   a Notice of Disconnection ([MS-ADTS] 5.1.1.6); so is a connection whose account is gone,
   unusable, revoked or has another SID. Groups and tier are recomputed per request.

A non-empty authorization identity is refused with 49; nothing maps one to a subject.

## The dedicated service-key purpose

The LDAP service key set gets its own purpose, `KeyPurpose::LdapService`, like the existing
`AdminService` and `ChangePasswordService`:

- it is derived from the service name by the one purpose-derivation function (`of_service_name`);
- only the provisioning claim of the LDAP service object carries it, and `keyd` accepts it only
  for an LDAP service name;
- its key is only ever drawn inside `keyd`; no operation sets or grants a secret for it, or
  destroys it;
- it is opened **only** by `AcceptSecContext`. A ticket for the administration or change-password
  service cannot be opened by the LDAP operation, and the reverse.

The existing `open_and_verify_service_ticket` (`AppBinding::Unbound`) refuses any checksum,
which RFC 4121 §4.1.1 requires, so it serves no GSS client. It is removed and its message kind
refused on the wire.

## Errors

| Situation | Answer |
|---|---|
| GSSAPI on a connection without TLS | `confidentialityRequired` (13), before `keyd` (implemented) |
| Path not complete (no digest producer yet) | `authMethodNotSupported` (7) (implemented) |
| Any failure inside the exchange: framing, OID, TOK_ID, any RFC 4120 §3.2.3 step, checksum, flags, `Bnd`, sequence, skew, expiry, replay, Wrap, layer, size, non-empty authorization identity, account missing, unusable or revoked, slot consumed | `invalidCredentials` (49), empty `diagnosticMessage`, no `serverSaslCreds`, then close |
| A non-bind request mid-exchange | `operationsError` (1), then close |
| `keyd` unavailable, busy or in its start hold-down, decided **before** the chain runs | `unavailable` (52) or `busy` (51), then close |
| Internal failure in `dird` | `other` (80), then close |

The uniform 49 means a wrong credential and an unknown account look the same (RFC 4422 §3.6). No
KRB-ERROR is ever put in a token, not even for clock-skew recovery. The detailed reason goes to the
audit log only; once `keyd` accepted the ticket, the principal is recorded even on a later failure.
No token, digest or exporter value is logged.

## rootDSE advertisement

RFC 4752 §3.2 forbids advertising GSSAPI without an acceptor credential. RFC 4513 §5.2.1.5 says
`supportedSASLMechanisms` lists the mechanisms supported in the connection's current state. The
value `GSSAPI` will appear only when all three hold:

1. the full path is built, including a digest producer (today there is none);
2. `dird` confirmed at start, and at each reconnect to `keyd`, that an `LdapService` key set with a
   drawn key version exists;
3. the connection is TLS-protected and its channel-binding slot is unused.

Otherwise the attribute is absent (RFC 4512 §5.1.7). The native client requires TLS and does not
trust a rootDSE read in clear.

## Attack classes ruled out by construction

| Class | What makes it impossible | Residual |
|---|---|---|
| A bind accepted without channel binding | The planned binding type `AppBinding::GssKrb5(ChannelBindingDigest)` has no variant without a digest, and the digest cannot be zero; the bound identity exists only after `keyd` compared `Bnd`; the slot exists only on TLS | — |
| One binding used for two authentications | A non-copyable value taken once; a second exporter message closes; a second exchange gets 49 and a close | — |
| A key leaving `keyd` | AP-REP, wrap and unwrap happen in `keyd`; no reply type has a key field | — |
| A general MAC oracle over the exchange key | No "wrap these bytes" or "unwrap these bytes" operation | — |
| Identity taken from a client claim | Subject only from `keyd`'s ticket facts; BindRequest `name` not read; no authorization-identity mapping | — |
| A channel fact asserted by a component that does not own it | The front reports only its own exporter value; only `keyd` decides a match | the front is the TLS endpoint |
| A ticket for another service or channel accepted | Dedicated purpose; binding decides purpose and operation; single acceptor entry point; only drawn keys | — |
| One security rule implemented twice | One RFC 4120 §3.2.3 chain; one AP-REP builder; framing in one crate; `Bnd` in one function | — |
| A weak primitive spreading | MD5, if approved, in one function of one leaf crate with one dependent, pinned by a guard test; never in `keyd` | open question |
| An error that reveals the cause | Uniform 49; structural and binding checks inside the chain; unavailability decided before it | response time |
| A capability without a consumer | The unbound operation removed; exchange state consumed on every outcome | abandoned state lives ≤ 30 s |
| Reflected or replayed negotiation tokens | Direction flag and separate key usages (an echoed offer fails as a selection); exact `SND_SEQ`; one-shot state | — |
| A weaker option chosen by the client | Only "no layer" offered; delegation refused; mutual and integrity required; empty authorization identity; `Sealed` refused | — |
| Restart losing state into a weaker mode | Replay-cache loss: the start hold-down covers both operations; lost exchange state: in-progress exchanges fail closed | — |

## Trust analysis per process

| Process | Holds | If compromised, it gains | It does not gain |
|---|---|---|---|
| `ldap-front` | TLS state and private key; each connection's exporter value; all LDAP plaintext | What it already has as TLS endpoint: man-in-the-middle and relay on connections it terminates (a false exporter value adds nothing). **And:** it can inject requests into any bound connection through it, as the bound identity, until `endtime` (in phase 1, reads only, under the policy). | Any Kerberos key; authentication of a user who did not send it a fresh AP-REQ; AP-REQ reuse (replay cache); a ticket for another service; a connection beyond `endtime`; skipping the per-request recheck; relay with the stolen key after it is restored |
| `dird` | Connections, identities, the directory; the `Bnd` function | The LDAP identity and authorization decisions (it is the enforcement point and the directory owner) | Any key; verifying an AP-REQ it does not have; forging a ticket; a `keyd` answer without a valid AP-REQ |
| `keyd` | The `LdapService` key, the ticket's session key, the acceptor subkey, the replay cache | Everything, as for every other key operation | — |

## Residual risks

- **Binding strength equals the front's integrity at the time of compromise**, since it computes
  the exporter value. With `tls-exporter`, relay stops once the front is restored.
- **MD5 in `Bnd`**, if approved, is not hash-agile. It sits inside an encrypted, integrity-protected
  authenticator, and its input is TLS exporter output the attacker does not choose.
- **Clients that follow RFC 4752 strictly** (empty bindings) are refused. A client with a wrong
  clock gets **no skew hint**, because no KRB-ERROR is sent.
- **`dird`'s LDAP engine thread waits on `keyd`** (two calls per bind). Bounded by the TLS handshake
  per attempt, the front's connection limits and a busy answer.
- **A name reused after deletion** is covered by `revoked_before` until the PAC arrives.
- **No test vectors** exist for these tokens, so a reading error shared by Domainfort's client and
  server would pass every test. A lab capture from a third-party client is checked before enabling.

## Open design questions

- **MD5 in the channel-binding digest.** RFC 4121 §4.1.1.2 defines `Bnd` as an MD5 hash. Domainfort
  otherwise refuses MD5: no crate provides it, and a guard test fails if one enters the dependency
  lock. Using it needs an exception and a new dependency. Related: binding at all deviates from
  RFC 4752 §5, and how to fill the GSS-API channel-bindings structure for a TLS channel is defined
  in a document not yet among the project's allowed sources. Until decided, no bind can succeed.
- **The TLS front in the integrity path of bound connections.** TLS ends in `ldap-front` and there
  is no SASL layer, so the front can send requests as any identity bound through it, until
  `endtime`. Phase 1 is read-only. This must be decided before LDAP writes are enabled, together
  with whether "TLS plus channel binding" may count as sealed.
- **Whether LDAP keeps TLS at all**, or moves to SASL-layer protection only. If TLS is dropped, the
  channel-binding part of this design is dropped with it.

## Implementation status

| Part | Status |
|---|---|
| `gss-token`: RFC 2743 §3.1 framing (`ContextEstablishmentToken`, `TokId`), the RFC 4121 §4.1.1 checksum (`AuthenticatorChecksum`, `Bnd`, `ContextFlags`), the Wrap token without confidentiality (`WrapHeader`, `ReceivedWrapToken`, `OutgoingWrapToken`, `WrapExpectation`), bounds `MAX_CONTEXT_TOKEN_LEN` (64 KiB) and `MAX_WRAP_TOKEN_LEN` (1 KiB) | **Implemented.** Zero dependencies and no cryptography, pinned by a test of its dependency graph; three fuzz targets (`initial_context_token`, `wrap_token`, `authenticator_checksum`). No crate links it yet. |
| GSSAPI refusals in the engine (`SaslGssapiNotAvailable`), no `supportedSASLMechanisms` | Implemented (the current answers above) |
| TLS 1.3 front, `check_negotiated`, `enable_secret_extraction = false`; `Open`, `Listener::Ldaps`, `TlsEstablished` | Implemented; the exporter value and its wire field are planned |
| Service AP-REQ chain `verify_service_ap_req`, acceptor entry point `accepting`, replay cache, start hold-down | Implemented; the GSS checksum step is planned |
| `open_and_verify_service_ticket` with `AppBinding::Unbound` (the LDAP key set uses `KeyPurpose::Service` today) | Implemented; planned for removal |
| Ticket-subject lookup, per-request `recheck`, `revoked_before`, `BoundIdentity` | Implemented; today `BoundIdentity` still carries a `channel_bound` field that the design removes |
| `AcceptSecContext`, `CompleteSaslNegotiation`, `GssAcceptance`, `SaslSelection`, `ChannelBindingDigest`, `AppBinding::GssKrb5`, `KeyPurpose::LdapService`, `ChannelBindingSlot`, the engine's GSSAPI state machine, the rootDSE rule | Planned |
| `gss-channel-bindings` (the MD5 digest) | Planned; blocked on the MD5 question |

**Tests** come only from statements in the specifications, the rotation example of RFC 4121 §4.2.5,
the constants of RFC 2744 App. A, and (in `gss-token`) Wrap headers from a capture in the project's
own lab. GSSAPI is enabled only after the digest producer, an end-to-end test and the lab check.
