# Clean-room development

Domainfort re-implements protocols that Windows requires, and its standing rests on one promise:
**every line of code is this project's own, derived only from published specifications.** No
existing implementation of these protocols is copied, adapted, translated, consulted or recalled.

This document describes the method, how it is enforced, and what contributors must not send.

## The rule

Code, tests, schemas and specifications in this repository are written **only from the allowed
written sources below, opened and read while the work is done** — never from memory of an existing
implementation.

"From memory" includes reproducing, from recollection of any existing product or project — open
source or proprietary, under any licence, including permissive ones:

- code, code structure or control flow;
- names of functions, types, variables or files;
- comments, error messages or log strings;
- constant tables, lookup tables or magic numbers;
- test cases, test vectors or fixtures.

This applies even to a "small helper", and even when the result would plausibly have been written
the same way anyway. It also applies to the specifications themselves: a section is cited only after
it has been opened and read, not from recollection of what it says.

## Allowed sources

| Source | Where |
|---|---|
| Microsoft Open Specifications (Windows Protocols), including their IDL and examples | learn.microsoft.com and the official PDF download hosts |
| IETF RFCs and Internet-Drafts | rfc-editor.org, datatracker.ietf.org |
| DCE 1.1: Remote Procedure Call (C706) | The Open Group, pubs.opengroup.org |
| ASN.1 and its encoding rules (X.680 series, X.690 series) | ITU-T, itu.int |
| Cryptographic algorithm definitions (FIPS and SP publications) | NIST, csrc.nist.gov |
| This project's own design documents | the project itself |
| Black-box observations from the project's own isolated lab | observed bytes and behaviour only — never code |
| API documentation of approved dependencies | how to call them — never their source |

The specific documents in use are listed in [STANDARDS.md](STANDARDS.md).

## Forbidden sources

- Source code, patches, diffs, commit history, and code in issue trackers or mailing lists of **any
  existing implementation** of the protocols this project implements — Kerberos, LDAP, SMB,
  DCE/RPC, NDR, DNS servers, directory services — in any language and under any licence, including
  the well-known open-source suites, client libraries, protocol dissectors and test suites.
- Leaked, decompiled, disassembled or debug-symbol-derived Microsoft material. No reverse
  engineering of Windows binaries, drivers or libraries.
- Code hosting and code search sites, except for a specific URL that the project has explicitly
  listed as an allowed source.
- Code snippets from forums, blogs or gists.
- Test vectors or fixtures taken from another implementation's test suite.

When it is unclear whether a source is allowed, it is not. Questions about the boundary are
resolved before any code is written.

## The workflow

1. **Find the governing specification sections and open them.** Record the document identifier,
   its revision and the section numbers that were read.
2. **If a specification is missing, ambiguous or unreachable, stop.** The gap is written down as an
   open question and decided explicitly. It is never filled from knowledge of how another
   implementation behaves. Where Windows' behaviour on the wire must be known and the
   specifications are silent, the answer comes from black-box observation in the project's own lab.
3. **Write the code with a specification reference on every non-trivial item**, for example:

   ```rust
   // Spec: [MS-KILE] 3.3.5.7.1; RFC 4120 5.4.2
   ```

4. **Name things with the specification's terminology** — the abstract data model, message and field
   names it uses — never with another implementation's internal names.
5. **Write tests only from allowed sources:** examples in the specifications, RFC and FIPS test
   vectors, or the project's own lab observations. Each test names its source.
6. **Commit with the required trailers** (below).

Keep the scope minimal: implement only the subset of a specification that is needed, and give weak
or legacy options no code path at all.

## Recall

If code that is recognisably from an existing project comes to mind while writing:

1. Stop writing that unit. Do not try to rephrase or restructure it.
2. Discard what was drafted for that unit.
3. Report it in the pull request description under a **Recall flag** heading, naming the unit and
   the specification section.
4. Leave the unit to be implemented afresh from the specification, with review.

A recall flag is not a failure; it is the process working. Hiding one is the failure.

## Enforcement

### Pinned specifications

The specification documents the code is written from are pinned in
[`tools/spec-pin/manifest.json`](../tools/spec-pin/manifest.json): for each document, its official
URL, its revision and the **SHA-256** of the exact file. [`scripts/pin-specs.sh`](../scripts/pin-specs.sh)
downloads only from the allowed hosts and records the hash of a document that is not pinned yet. A
document that is already pinned and whose content has changed is **not** re-pinned silently: the
new download is kept aside as unreviewed and the script fails, so a new revision is adopted only
after its changes have been read. CI re-verifies every pinned hash with `--verify`. The
specification files themselves are not committed to the repository.

### Commit trailers

Every commit carries a `Clean-Room:` trailer, and every commit that touches product code (`crates/`
or `src/`) also carries a `Spec-Ref:` trailer naming the specification sections it was written from:

```text
Spec-Ref: MS-KILE r49.0 3.3.5.7; RFC 4120 5.4.2
Clean-Room: Written only from the Spec-Ref sources; no other implementation consulted or recalled.
```

- A commit-message hook in [`.githooks/commit-msg`](../.githooks/commit-msg) rejects a commit without
  them. Enable it once per clone with `bash scripts/install-hooks.sh`.
- CI runs the same rule over every commit in a pull request
  ([`scripts/check-provenance.sh`](../scripts/check-provenance.sh)), so a commit made without the hook
  is caught too.

### Contamination scan

[`scripts/check-no-vendor.sh`](../scripts/check-no-vendor.sh) runs in CI on every pull request. It does
**not** compare the code against other implementations — that would require holding the forbidden
material. Instead it looks in this repository for signs of contamination that need no external
corpus:

- vendored third-party code (`vendor/`, `third_party/` and similar directories), or paths named
  after an existing implementation;
- licence headers in code files from licences outside the dependency allow-list — a copied file
  usually carries its original header;
- comments that admit copying ("copied from", "adapted from", "ported from" and similar);
- committed specification files.

### Dependencies

Approved dependencies are **linked**, never copied into the repository, and their source is never
read in order to reproduce it. Only their API documentation is used. Libraries that implement
Kerberos, LDAP, SMB, DCE/RPC, NDR, DNS-server or directory logic are not allowed as dependencies;
that logic is this project's own work. See
[SECURITY-MODEL.md](SECURITY-MODEL.md#dependencies) for the full dependency policy.

### Review

Every change is reviewed before it is merged. The review checks the specification references and
the trailers and looks for signs that a unit was not derived from its cited sections.

## For contributors

Please **do not send**:

- code, patches or proof-of-concept code taken from, adapted from or written from memory of another
  implementation of these protocols;
- excerpts of another implementation's source code, or descriptions of how it does something, even
  as background;
- test vectors or fixtures from another implementation's test suite;
- decompiled, disassembled or leaked material;
- code snippets from forums, blogs or answers sites.

Contributions of that kind cannot be accepted, and receiving them can contaminate the work of
whoever reads them.

**Welcome:** bug reports and reproductions against this project's own code; references to the
section of a public specification that the code gets wrong; observations of a real system's
on-the-wire behaviour described as bytes and behaviour; and changes written from the allowed
sources, with their `Spec-Ref:` and `Clean-Room:` trailers.
