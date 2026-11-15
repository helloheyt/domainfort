# Security policy

## Status

This project is **pre-alpha** and has no released version. Nothing here should be deployed to protect
real systems yet.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** through GitHub's private vulnerability
reporting for this repository (the "Report a vulnerability" button under the *Security* tab). Do not
open a public issue.

Helpful details: the affected crate or document, the class of weakness, and a minimal reproduction
against this project's own code.

## What we do with a report

Every finding is handled **root cause first** (see [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md)): we name the class of the
weakness, look for an infrastructure change that makes the whole class impossible by construction,
and apply it everywhere the class can occur — a local patch only when that is impossible, with the
residual recorded.

## Out of scope

- Weak protocol options (NTLM, RC4/DES, SMB1, cleartext LDAP simple bind and others listed in the
  README) are deliberately not implemented; requests to add them are declined.
- Please do not send code, patches or proof-of-concept code taken from other implementations — this
  is a clean-room project and we cannot accept it (see [docs/CLEAN-ROOM.md](docs/CLEAN-ROOM.md)).

There is no bug bounty.
