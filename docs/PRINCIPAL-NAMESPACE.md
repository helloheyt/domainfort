# Principal namespace

This document explains how Domainfort maps a principal name to exactly one directory object and one
key set, and why the name-confusion attacks known from Active Directory have no representation in
it. It is written for security reviewers. See also [ARCHITECTURE.md](ARCHITECTURE.md),
[KEY-CUSTODY.md](KEY-CUSTODY.md) and [AD-ATTACK-CLASSES.md](AD-ATTACK-CLASSES.md). Each mechanism
is marked **implemented** (present in `crates/` and covered by tests) or **planned**.

| Mechanism | Status |
|---|---|
| One fold and one key form for every kind of principal name (crate `principal-names`) | implemented |
| One unique index over all names (`PRINCIPAL_NAME_KEY`), written only by the one write checker | implemented |
| One lookup path with one probe (`canonical_principal`); reserved names judged case-folded | implemented |
| `dird` attests every name resolution it hands the KDC; `keyd` verifies it before any key | implemented |
| `keyd` finds the key set it issues for only from the verified resolution | implemented |
| Four doors to a stored key, pinned by a source-scan test; end-to-end attack tests | implemented |
| Pre-authentication that takes the client's resolution instead of a key handle | planned |
| `keyd` stamps the time of an armored error itself | planned |
| Wider name acceptance (case variants, the "$" form, UPN and enterprise names) | planned, gated |

## The problem

Active Directory resolves a Kerberos name through chains of lookups in separate name spaces and
keeps names unique per attribute. Four classes of flaw follow; each is the root of known attacks.

1. **Identity lookup through a fallback chain.** The client lookup of [MS-KILE] 3.3.5.6.1 tries the
   name as a sAMAccountName, then with "$" appended, then as a UPN built from the name and the
   realm, then through name cracking. The server lookup of [MS-KILE] 3.3.5.1.1 maps `krbtgt/X` to
   the sAMAccountName X, tries a joined multi-component name against userPrincipalName, and tries a
   one-component name as a sAMAccountName, then with "$" appended. [MS-ADTS] 3.1.1.13.7 tries a UPN,
   then a sAMAccountName, then the user name parsed out of the UPN. When an early step finds
   nothing, a later step can match a *different* object: a name without the final "$" reaches a
   computer account, such as the domain controller's, once the object that held it is gone.
2. **Uniqueness per attribute, not over the union.** Two objects hold "the same name" in different
   attributes: a user `dc` beside a computer `dc$`, a UPN beside another object's sAMAccountName,
   one SPN in two spellings, two computers with one host name. [MS-SAMR] 3.1.1.6 item 11 even lets
   a domain administrator give a computer account a name without the final "$".
3. **Name equivalence computed by more than one function.** [MS-KILE] 3.1.5.7 requires
   case-insensitive comparison. If the writer folds case while the lookup, the reserved-name check,
   the policy or the key holder compares octets, "the same name" for one component is a different
   name for the next: `KRBTGT/host` passes an octet check against a reserved name.
4. **The KDC asserts which key set a name maps to.** If the key holder takes the KDC's word for
   "name N is key set K", a compromised KDC can issue a ticket for one name under another key.

The goal: no string names two objects — in any name kind, case or name-type — and no component
decides "this name is this object" on its own. The attacks are then not detected but inexpressible.

## One namespace

### One fold and one key form

The crate `principal-names` is the only definition of name equivalence (no store, I/O, clock or
secret); the writer, the lookup and `keyd` all call it.

- **The fold** (`fold`): only printable ASCII (0x20–0x7E) can form a key; A–Z fold to a–z, every
  other octet is kept. Any other octet is refused on write and "no such principal" on lookup — an
  interim rule until a Unicode case-mapping specification is available.
- **The key** (`PrincipalKey`, at most `MAX_KEY_OCTETS` = 2048 octets, built only in the crate):
  one to three folded, non-empty components joined by "/", none containing "/" or an at sign.
  Joining is injective, "/" separates the SPN form from all others, and no key holds an at sign.
- **The kind is metadata, not part of the key** (`NameKind`). As RFC 4120 §6.2 states, the name
  type does not partition the name space. All kinds share one key space; the kinds a key carries
  are re-derived from the object after the lookup.

| Kind | Source | Carried by |
|---|---|---|
| `SamAccountName` | sAMAccountName | user, computer, group |
| `ComputerBase` | a computer's sAMAccountName without the final "$" | computer |
| `UpnLocal` | the local part of a userPrincipalName whose suffix is a realm alias | user, computer |
| `ServicePrincipalName` | servicePrincipalName (`service/host`) | computer |
| `HostName` | dNSHostName | computer, except the provisioned service objects |
| `RealmAlias` | configuration (phase 1: the realm's DNS name only) | the krbtgt account |

A group occupies its name but no lookup accepts it, nor a `HostName` or `RealmAlias` key.
`key_of_request` turns a request's realm and name into **at most one** probe, ignoring name-type:

| Request | Result |
|---|---|
| a realm that is not a realm alias (compared folded) | `RequestKey::Foreign`: no such principal |
| two components, the first `krbtgt` in any case | `LocalTgs` if the second is a realm alias, else `Foreign`; never reaches the index |
| one component without an at sign | `Key` of that component |
| one component with exactly one at sign | `Key` of the local part if the suffix is a realm alias, else no such principal |
| two or three non-empty components without "/" or an at sign | `Key` of the components joined by "/" |
| anything else, or a key that begins with `krbtgt` or equals a realm alias | `NoSuchPrincipal` |

A UPN with a foreign suffix names nothing — deliberately stricter than the last step of [MS-ADTS]
3.1.1.13.7. Realms compare case-insensitively per [MS-KILE] 3.1.5.7, a documented deviation from
RFC 4120 §6.1; the phase-1 acceptance below still requires the configured realm octet for octet.

### One unique index

An object's keys are the values of one internal attribute, `PRINCIPAL_NAME_KEY` (ATTRTYP
`0xFFFF0001`, in the range [MS-ADTS] 3.1.1.2.6 reserves for internal use; OctetString,
multi-valued, unique). The store's existing unique index refuses, at every commit, a key another
live object holds, whichever name it was cut from — uniqueness over the union of all names, as
[MS-SAMR] 3.1.1.8.4 item 2 already does for account names. The attribute is in none of the Active
Directory tables, so no LDAP request, policy rule or wire format can name it. A deleted object
releases its keys with its tombstone. The per-attribute indexes stay for LDAP's attribute-equality
fast path only; a source-scan test pins that no principal lookup uses them.

### One checker that derives and writes all keys

`keys_of_names` computes the keys; only the one checked write path in `directory-admin` writes
them, online and at provisioning. The attribute is refused in every caller's input and is never
modifiable. The checker refuses, never corrects, a name that breaks a rule:

- every key of every object is distinct (the unique index);
- a sAMAccountName has no "/" and no at sign; a computer's ends with a single "$" and no other
  account's ends with "$", with no administrator exception; the krbtgt account's is `krbtgt`;
- a userPrincipalName has exactly one at sign, a non-empty local part without "/" not ending in
  "$", and a realm alias as suffix;
- a servicePrincipalName has exactly two non-empty parts in phase 1, no at sign, no
  `:instancename` ([MS-ADTS] 2.2.21, 3.1.1.5.3.1.1.4), and a lower-case host part (RFC 4120
  §6.2.1) equal to the object's own dNSHostName; at most one per object
  (`MAX_SERVICE_PRINCIPAL_NAMES` = 1);
- a computer's dNSHostName is exactly `<computer name>.<realm DNS name>` ([MS-ADTS]
  3.1.1.5.3.1.1.2), unique because the base name is; the provisioned service objects carry the
  domain controller's host name without holding its key;
- no object but the krbtgt account holds a key that begins with `krbtgt` or equals a realm alias.

There is no rename in phase 1; later name-changing writes must derive keys in the same checker and
transaction (planned). `dird` refuses to open a store without the `principal-namespace` marker
written at provisioning (`principal_namespace_marked`); there is no migration tool, as it would be
a second path that computes keys. A `Delete`'s effect plan lists the keys it releases
(`NamesReleased`), so approvers see which names become free.

### One lookup path

`DirectoryView::canonical_principal` in `directory-pip` is the only code that turns a requested name
into an object: the KDC's lookups, the ticket-subject checks (administration plane, change
password, DNS updates, LDAP) and `dird`'s service-object checks all pass through it. It:

1. computes the one request key and probes `PRINCIPAL_NAME_KEY` once — no second probe elsewhere;
2. classifies the object from authoritative data and filters by context (`LookupCtx::AsClient`,
   `TicketClient`, `TgsServer`, `ServiceObject`): never a group or the krbtgt account; a service is
   a computer;
3. re-derives the object's keys and fails closed if the probed key is not among them;
4. derives the key purpose from the stored canonical name, never from the request's spelling;
5. returns a `ResolvedPrincipal`, which no other code can build.

**Phase-1 acceptance (implemented):** the realm, a client name and a service name must equal the
configured realm, a stored sAMAccountName and a stored servicePrincipalName, octet for octet. A UPN
local part or a computer's base name is not a client name. **Wider acceptance (planned, gated):**
case variants, base names and UPN local parts as client names, enterprise names, every realm alias
and one-component service names. It waits on the canonicalization specification (RFC 6806) being
pinned and on interoperability observations; the binding by resolution it needs is in place.

## Reserved names

`reserved_name_of` judges a key on its folded form, so every spelling is reserved:

| Reserved name | Reserved for |
|---|---|
| any name whose first component is `krbtgt` | the ticket-granting service (RFC 4120 §6.2, §7.3) |
| `admind/<host>` | the administration service |
| `kadmin/changepw` | the change-password service (RFC 3244 §2) |

Only the provisioning claim that owns a reserved name may carry it, by an exhaustive match (see
[SECURITY-MODEL.md](SECURITY-MODEL.md#reserved-service-names-belong-to-their-provisioned-object)).
`keyd`'s creation rule for a key set's name binding (`check_new_binding`) reads the binding with the
same functions (`key_of_stored_name`, `reserved_name_of`), so a reserved spelling is never bound to
an ordinary key set and a spelling no object can store is bound to none. The KDC takes the server
kind and the policy resource of a service ticket from the resolution, never from the request.

## Attested resolutions: dird states, keyd verifies

For every account record it hands the KDC, `dird` turns the `ResolvedPrincipal` into a
`NameResolution`: the realm and name as sent, the canonical realm and name (the stored
sAMAccountName or SPN), the `principal` and `key_purpose` of the key set, a `snapshot` (the change
sequence of the write that bound the probed key), and `issued_at` from `dird`'s clock.

`dird`'s signer (`ResolutionSigner`) tags it with HMAC-SHA256 under the attestation key (the full
32 octets) over one length-prefixed encoding, defined once in `keyd-types` for signer and verifier,
that begins with the label `principal-name-resolution.v1` — so a tag for another use of the key is
never valid here. The signer accepts only a `ResolvedPrincipal`, and `name-attestation` has no
function that tags arbitrary bytes. `dird` hands resolutions out only on its KDC channel; the KDC
forwards them to `keyd` and links no MAC code. Guard tests check both.

`Keyd::verify_name_resolution` yields a `VerifiedNameResolution` only after, in order:

1. an attestation key is installed (otherwise `AttestationKeyMissing`);
2. the tag verifies in constant time, **before any field is read** (`NameResolutionInvalid`);
3. the canonical realm is `keyd`'s realm, octet for octet (`WrongRealm`);
4. `|now − issued_at| ≤ 30 s` (`NAME_RESOLUTION_WINDOW_SECS`) on `keyd`'s own clock, never a
   request field (`NameResolutionStale`).

The caller sees only the uniform `Denied`; the reason goes to the audit log. The verified type has
private fields and is built only from the proof the tag check returns.

**Issuance from the resolution alone.** `issue_as_rep` and `issue_tgs_rep` take attested
resolutions, not key handles. `keyd` looks the key set up by the verified resolution's own
`(principal, key_purpose)` and checks that purpose against the capability table
(`PurposeMismatch`), so a request cannot name a key set beside its resolution. The client's
pre-authentication proof must belong to the key set the client's resolution names
(`TokenPrincipalMismatch`).

**The attestation key.** `provision domain` draws it (32 octets, never all zero) and writes
`dird`'s protected key file and an input file for `keyadm`. The ceremony installs it in `keyd`
through `InstallAttestationKey`: key-administration role only, ceremony only, once, with its audit
intent acknowledged first; `seal_ceremony` refuses to seal without it. `keyd` keeps it in its key
store, never returns it and never tags with it (pinned by a test). `AttestationKey` has no
accessor, `Debug` or `Clone`, and wipes itself on drop.

## The four key doors

Inside `keyd`, a stored key set's keys are reachable only through `BoundKeys`, a proof type that
exactly four functions build, each after its check:

| Door | Used for | Check |
|---|---|---|
| `store::bound_by` | AS: the client's and the change-password service's key sets; TGS: the service key set | the set stored under the verified resolution's `(principal, key_purpose)`; not a krbtgt set; its bound name and the canonical name give the same namespace key; the ticket carries one of the resolution's two names, exactly |
| `StoredKeySet::ticket_granting` | sealing a TGT; opening a TGT or armor ticket | a krbtgt set bound exactly to `krbtgt/<REALM>`, the name the KDC always writes ([MS-KILE] 3.3.5.1.2) |
| `StoredKeySet::accepting` | service AP-REQs (LDAP front, administration channel, change password) | not a krbtgt set; the ticket's realm and sname and the binding give the same namespace key |
| `StoredKeySet::bound_to` | `set_secret` on an existing set (`dird`'s install path) | bound exactly to the request's own binding; never issuance |

Uses with no name input go through `unbound_current` with a closed `UnboundUse`:
`Preauthentication` (`verify_preauth`, which issues nothing; its proof redeems only through
`bound_by`) and `SecretComparison` (`verify_secret`, which no role may call). The raw accessors are
private to the store module, so an operation that skips a check does not compile.

Which file uses which door is pinned by `crates/keyd/tests/key_access_inventory.rs`. It scans
`keyd`'s product source outside the store module (test modules and comment lines skipped), counts
every call form of each door (method, path or plain call, not an identifier that merely ends with
the name) and requires exactly: `as_exchange.rs` — `bound_by` twice (client, change-password
service), `ticket_granting` once; `tgs_exchange.rs` — `bound_by` once (service),
`ticket_granting` once; `service_ticket.rs` — `accepting` once; `directory.rs` — `bound_to` once.
The unbound uses are pinned the same way (two pre-authentication sites, one secret comparison).
Both scans have a positive control, so neither passes vacuously; a new door or use must be added to
the test's table, where review sees it.

## Attacks tested end to end

`crates/e2e-tests/tests/principal_namespace.rs` provisions a domain, runs the ceremony and starts
the real daemons over real sockets. **Issuance rests on dird's resolutions:** AS and TGS succeed
while resolutions verify. With `keyd`'s clock more than 30 s ahead of `dird`'s, every resolution is
stale and both are refused; a `dird` attesting with a key the ceremony did not give `keyd` gets
nothing issued. Each time the fault is removed, the login works again. The audit log holds every
issuance and refusal with `keyd`'s reason; the attestation key appears in no log or file left.

**A compromised KDC on keyd's socket.** The test takes the KDC's role, reads `dird`'s genuine
resolutions as the KDC does, and misapplies them. Each attempt is `Denied` and audited with its
reason; the legitimate login works afterwards.

| Exchange | Attempt | Refused because |
|---|---|---|
| AS, TGS | a resolution with a flipped tag | the tag does not verify |
| AS | another user's genuine resolution with the first user's pre-authentication proof | the proof belongs to another key set |
| AS, TGS | a genuine resolution, the ticket template naming another principal | the name is not in the resolution |
| TGS | the administration service's resolution for a request naming the LDAP service | the name is not in the resolution |
| TGS | the LDAP service object's account-name resolution, for a service ticket | a long-term purpose is not a service's |
| AS, TGS | a genuine resolution after the window | stale on `keyd`'s clock |

**Name shapes through the administration plane,** to `dird`'s write checker; nothing is written:

| Attempt | Result |
|---|---|
| a computer `dc` (account `dc$`) beside a user `dc`, in either order and any case | conflict |
| a user or computer named like the domain controller's base name, including a case variant | conflict |
| a user named `srv2$` | invalid account name |
| a UPN local part equal to another object's sAMAccountName, in either order and any case | conflict |
| a UPN with a foreign suffix | invalid value |
| one SPN in two cases on two objects | conflict under the same computer name, else invalid value (the host must be the object's own) |
| `admind/…`, `krbtgt/…`, `kadmin/changepw` in any case without the owning claim; a user `krbtgt` | invalid |

Afterwards the user `dc` logs in as itself, while `dc$`, a computer's base name and a UPN local part
are unknown clients. Library tests cover what no running wire can carry: a caller-supplied
`PRINCIPAL_NAME_KEY`, a tag under another label, and the exact window edges, a foreign realm and a
resolution aimed at the krbtgt.

## Residual risks

| Risk | Status |
|---|---|
| A compromised KDC can replay a true, fresh resolution within the 30 s window. | It cannot invent a mapping; short window, per-issuance audit; a unit test documents it. |
| A compromised `dird` can sign a false resolution. | `dird` owns the fact and is equivalent to tier 0; `keyd`'s creation rule and binding compare still require the key set's own bound name as canonical. |
| Pre-authentication still takes a key handle from the KDC, so a compromised KDC can run throttled password checks against any long-term key set it can identify, without a `dird` statement. | Nothing can be issued that way; pre-authentication by resolution is planned. |
| An armored refusal can go out without FAST protection when the KDC and `keyd` read different seconds, because `keyd` seals only errors stamped with its own time. | Fails safe (an error, never a success); `keyd` stamping the time itself is planned. |
| A name reused after deletion: phase-1 tickets carry names, not security identifiers. | The one revocation rule refuses tickets authenticated at or before the second the current account was created (see [SECURITY-MODEL.md](SECURITY-MODEL.md#revocation-at-one-second-resolution-in-one-place)); deletion plans show released names. |
| One key set behind several service names allows service substitution: sname is outside the ticket's encrypted part (RFC 4120 §5.3). | One SPN per object in phase 1. |
| The fold is defined twice: in `principal-names` and in the store's comparison key. | A test pins the two equal on all 95 printable octets. |
| A foreign UPN suffix, a flat realm name or a non-ASCII name cannot log on. | Fails closed. |
| Development custody of the attestation key: a root-only file for `dird`, an input copy for `keyadm`, `keyd`'s in-memory store, reinstalled at each ceremony. | The sealed store has no record for it yet; a `keyd` started over a persisted store holds none and refuses every resolution. Persistent custody is planned. |

## Open design questions

- Whether the domain's flat (NetBIOS-style) name may be a realm alias, given that NetBIOS has no
  code path, and whether more UPN suffixes may be accepted. Until then only the DNS name is one.
- Whether every `kadmin/` name should be reserved, or only `kadmin/changepw`.
- Whether the domain controller's services keep one service object each, or become several SPNs on
  its account with one key purpose per service class. This also decides multi-valued
  servicePrincipalName and three-part SPNs.
- Service-name aliasing is not implemented; every SPN is literal until interoperability
  observations show what Windows clients request.
- Changing the realm aliases after provisioning would be a planned migration of the krbtgt's keys.

## Specifications

RFC 4120 §5.3, §6.1, §6.2, §6.2.1, §7.3; RFC 3244 §2; [MS-KILE] 3.1.5.7, 3.3.5.1.1, 3.3.5.1.2,
3.3.5.6.1; [MS-ADTS] 2.2.21, 3.1.1.2.6, 3.1.1.5.3.1.1.2, 3.1.1.5.3.1.1.4, 3.1.1.13.7; [MS-SAMR]
3.1.1.6, 3.1.1.8.4; FIPS 198-1. The full list is in [STANDARDS.md](STANDARDS.md).
