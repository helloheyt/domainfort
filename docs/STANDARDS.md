# Standards

These are the standards Domainfort implements, implements a subset of, or reads for reference. Code is
written only from documents of these kinds (see [CLEAN-ROOM.md](CLEAN-ROOM.md)).

**Pinned copies.** Documents marked **pinned** are recorded in
[`tools/spec-pin/manifest.json`](../tools/spec-pin/manifest.json) with their official URL, their
revision and the SHA-256 of the exact file; [`scripts/pin-specs.sh --verify`](../scripts/pin-specs.sh)
checks that the files still match. Code citing a pinned document was written from that exact
revision. Further documents are pinned as the work that needs them begins. The documents
themselves are not redistributed in this repository.

**Use:**

- **implement** — implemented (or to be implemented) in full for the project's purpose;
- **subset** — only a secure subset is implemented; everything else is refused;
- **reference** — read to understand or to know what to refuse; **never implemented**.

"Phase" refers to the roadmap in [STATUS.md](STATUS.md).

## Microsoft Open Specifications

### Directory and schema

| Document | Title | Use | Phase | Pinned revision |
|---|---|---|---|---|
| [MS-ADTS] | Active Directory Technical Specification | subset | 1–2 | v20261026 |
| [MS-ADSC] | Active Directory Schema Classes | subset | 1–2 | v20240423 |
| [MS-ADA1] | Active Directory Schema Attributes A-L | subset | 1–2 | v20180912 |
| [MS-ADA2] | Active Directory Schema Attributes M | subset | 1–2 | v20240423 |
| [MS-ADA3] | Active Directory Schema Attributes N-Z | subset | 1–2 | v20180912 |
| [MS-DTYP] | Windows Data Types | implement | 1 | v20241119 |
| [MS-ADOD] | Active Directory Protocols Overview | reference | — | — |

### Authentication

| Document | Title | Use | Phase | Pinned revision |
|---|---|---|---|---|
| [MS-KILE] | Kerberos Protocol Extensions | subset | 1–2 | v20261110 |
| [MS-PAC] | Privilege Attribute Certificate Data Structure | implement | 2 | v20240610 |
| [MS-SPNG] | Simple and Protected GSS-API Negotiation Mechanism (SPNEGO) Extension | subset (Kerberos only) | 2 | v20261026 |
| [MS-SFU] | Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol | subset | 3 | — |
| [MS-PKCA] | Public Key Cryptography for Initial Authentication (PKINIT) in Kerberos Protocol | subset | 3, 6 | — |
| [MS-KKDCP] | Kerberos Key Distribution Center (KDC) Proxy Protocol | implement | 3 | — |
| [MS-APDS] | Authentication Protocol Domain Support | subset | 2 | — |
| [MS-NLMP] | NT LAN Manager (NTLM) Authentication Protocol | **reference — never implemented** | — | — |
| [MS-CTA] | Claims Transformation Algorithm | reference | later | — |
| [MS-KPP] | Key Provisioning Protocol | reference | later | — |

### RPC services used by domain members

| Document | Title | Use | Phase | Pinned revision |
|---|---|---|---|---|
| [MS-RPCE] | Remote Procedure Call Protocol Extensions | subset | 2 | v20240916 |
| [MS-NRPC] | Netlogon Remote Protocol | subset (Kerberos-based secure channel only) | 2 | v20261026 |
| [MS-SAMR] | Security Account Manager (SAM) Remote Protocol (Client-to-Server) | subset | 2 | v20260427 |
| [MS-LSAD] | Local Security Authority (Domain Policy) Remote Protocol | subset | 2 | v20250610 |
| [MS-LSAT] | Local Security Authority (Translation Methods) Remote Protocol | subset | 2 | v20240501 |
| [MS-DSSP] | Directory Services Setup Remote Protocol | subset | 2 | — |
| [MS-SRVS] | Server Service Remote Protocol | subset | 2 | — |
| [MS-WKST] | Workstation Service Remote Protocol | reference | later | — |
| [MS-BKRP] | BackupKey Remote Protocol | subset | 3 | v20240423 |
| [MS-GKDI] | Group Key Distribution Protocol | implement | 3 | v20240423 |

### File access (SYSVOL, NETLOGON, named pipes)

| Document | Title | Use | Phase | Pinned revision |
|---|---|---|---|---|
| [MS-SMB2] | Server Message Block (SMB) Protocol Versions 2 and 3 | subset (3.1.1 only) | 2 | v20260928 |
| [MS-DFSC] | Distributed File System (DFS): Referral Protocol | subset | 2 | — |
| [MS-SMB] | Server Message Block (SMB) Protocol — the SMB 1 protocol | **reference — never implemented** | — | — |

### Group Policy

| Document | Title | Use | Phase |
|---|---|---|---|
| [MS-GPOL] | Group Policy: Core Protocol | implement | 3 |
| [MS-GPREG] | Group Policy: Registry Extension Encoding | implement | 3 |
| [MS-GPSB] | Group Policy: Security Protocol Extension | subset | 3 |
| [MS-GPSCR] | Group Policy: Scripts Extension Encoding | subset | 3 |
| [MS-GPPREF] | Group Policy: Preferences Extension Data Structure | subset (no stored passwords) | later |

### DNS and time

| Document | Title | Use | Phase | Pinned revision |
|---|---|---|---|---|
| [MS-GSSA] | Generic Security Service Algorithm for Secret Key Transaction Authentication for DNS (GSS-TSIG) Protocol Extension | implement | 1 | — |
| [MS-SNTP] | Network Time Protocol (NTP) Authentication Extensions | subset | 2 | v20240423 |
| [MS-DNSP] | Domain Name Service (DNS) Server Management Protocol | subset | 5 | — |

### Coexistence with Windows domain controllers (only if decided)

| Document | Title | Use | Phase | Pinned revision |
|---|---|---|---|---|
| [MS-DRSR] | Directory Replication Service (DRS) Remote Protocol | subset | 7 | v20260309 |
| [MS-FRS2] | Distributed File System Replication Protocol | subset | 7 | — |
| [MS-SAMS] | Security Account Manager (SAM) Remote Protocol (Server-to-Server) | reference | 7 | — |

### Management tool compatibility

| Document | Title | Use | Phase |
|---|---|---|---|
| [MS-ADDM] | Active Directory Web Services: Data Model and Common Elements | subset | 5 |
| [MS-WSDS] | WS-Enumeration: Directory Services Protocol Extensions | subset | 5 |
| [MS-WSPELD] | WS-Transfer and WS-Enumeration Protocol Extension for Lightweight Directory Access Protocol v3 Controls | subset | 5 |
| [MS-WSTIM] | WS-Transfer: Identity Management Operations for Directory Access Extensions | subset | 5 |
| [MS-ADCAP] | Active Directory Web Services: Custom Action Protocol | subset | 5 |

### Certificate services

| Document | Title | Use | Phase |
|---|---|---|---|
| [MS-WCCE] | Windows Client Certificate Enrollment Protocol | subset | 6 |
| [MS-ICPR] | ICertPassage Remote Protocol | subset | 6 |
| [MS-XCEP] | X.509 Certificate Enrollment Policy Protocol | subset | 6 |
| [MS-WSTEP] | WS-Trust X.509v3 Token Enrollment Extensions | subset | 6 |

## IETF RFCs

Titles of pinned documents are given as recorded in the manifest; for documents not pinned yet,
the subject is given.

### Kerberos and GSS-API

| RFC | Title or subject | Pinned |
|---|---|---|
| RFC 4120 | The Kerberos Network Authentication Service (V5) | pinned |
| RFC 3961 | Encryption and Checksum Specifications for Kerberos 5 | pinned |
| RFC 3962 | AES Encryption for Kerberos 5 | pinned |
| RFC 8009 | AES Encryption with HMAC-SHA2 for Kerberos 5 | pinned |
| RFC 6113 | A Generalized Framework for Kerberos Pre-Authentication (FAST) | pinned |
| RFC 3244 | Microsoft Windows 2000 Kerberos Change Password and Set Password Protocols | pinned |
| RFC 4121 | The Kerberos Version 5 GSS-API Mechanism: Version 2 | pinned |
| RFC 4178 | The Simple and Protected GSS-API Negotiation Mechanism | pinned |
| RFC 4556 | Public Key Cryptography for Initial Authentication in Kerberos (PKINIT) | pinned |
| RFC 6806 | Kerberos name canonicalization and referrals (read to know what is refused) | — |
| RFC 6112 | Anonymous PKINIT and the anonymous principal (read to know what is refused) | — |

### LDAP and SASL

| RFC | Title or subject | Pinned |
|---|---|---|
| RFC 4511 | LDAP: The Protocol | pinned |
| RFC 4512 | LDAP: Directory Information Models | pinned |
| RFC 4513 | LDAP: Authentication Methods and Security Mechanisms | pinned |
| RFC 4514 | LDAP: String Representation of Distinguished Names | pinned |
| RFC 4517 | LDAP: Syntaxes and Matching Rules | pinned |
| RFC 4518 | LDAP: Internationalized String Preparation | pinned |
| RFC 4510, 4515, 4516, 4519 | The remaining documents of the LDAPv3 series | — |
| RFC 2696 | LDAP Control Extension for Simple Paged Results Manipulation | pinned |
| RFC 2891 | LDAP server-side sorting control | — |
| RFC 4422 | Simple Authentication and Security Layer (SASL) | pinned |
| RFC 4752 | The Kerberos V5 ("GSSAPI") SASL Mechanism | pinned |
| RFC 5929 | Channel Bindings for TLS | pinned |

### TLS and X.509

| RFC | Title or subject | Pinned |
|---|---|---|
| RFC 8446 | The Transport Layer Security (TLS) Protocol Version 1.3 | pinned |
| RFC 5246 | TLS 1.2 — AEAD suites only, and only if ever required for Windows members | — |
| RFC 5280 | Internet X.509 Public Key Infrastructure Certificate and CRL Profile | pinned |
| RFC 2986 | PKCS #10 certification requests | — |
| RFC 5652 | Cryptographic Message Syntax (CMS) | — |
| RFC 7030 | Enrollment over Secure Transport (EST) | — |

### DNS

| RFC | Title or subject | Pinned |
|---|---|---|
| RFC 1034 | Domain names - concepts and facilities | pinned |
| RFC 1035 | Domain names - implementation and specification | pinned |
| RFC 2782 | A DNS RR for specifying the location of services (DNS SRV) | pinned |
| RFC 2136 | Dynamic Updates in the Domain Name System (DNS UPDATE) | pinned |
| RFC 3645 | GSS Algorithm for TSIG (GSS-TSIG) | pinned |
| RFC 8945 | Secret Key Transaction Authentication for DNS (TSIG) | pinned |
| RFC 4033, 4034, 4035 | DNS Security Extensions (DNSSEC) | — |
| RFC 7858 | DNS over TLS | — |
| RFC 8484 | DNS over HTTPS | — |

### Time

| RFC | Title or subject | Pinned |
|---|---|---|
| RFC 5905 | Network Time Protocol Version 4: Protocol and Algorithms Specification | pinned |
| RFC 8915 | Network Time Security for NTP | pinned |

## Other standards

| Standard | Title | Pinned |
|---|---|---|
| The Open Group C706 | DCE 1.1: Remote Procedure Call | — |
| ITU-T X.680 (02/2021) | Abstract Syntax Notation One (ASN.1): Specification of basic notation | pinned |
| ITU-T X.690 (02/2021) | ASN.1 encoding rules: Specification of BER, CER and DER | pinned |

## Referenced definitions

These are cited where another standard depends on them. Cryptographic primitives themselves come
from approved libraries; the project never implements them.

| Document | Where it is used |
|---|---|
| FIPS 197 (AES), FIPS 180-4 (SHA-1, SHA-2), NIST SP 800-38A (CBC mode), NIST SP 800-108 (key derivation) | Definitions behind the Kerberos encryption profiles of RFC 3962 and RFC 8009, and the hashes used by the directory store and the audit log |
| RFC 2040 §8 | The ciphertext-stealing steps that RFC 3962 references |
| RFC 5234 | The ABNF notation used by [MS-DTYP] |
| RFC 5737 | Documentation address ranges, used for values in tests |
