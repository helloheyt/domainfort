#!/usr/bin/env bash
# Clean-room enforcement layer 3 (see docs/CLEAN-ROOM.md, "Contamination scan").
#
# Important: this check does **not** compare against the code of other implementations — holding or
# fetching a forbidden corpus is not allowed (docs/CLEAN-ROOM.md, "Forbidden sources"). Instead it scans
# *our own tree* for three signs of contamination that need no corpus:
#   (1) third-party code brought into the repository (vendor/, third_party/, or a directory named after a forbidden project)
#   (2) a foreign licence header in a code file (a copied file usually carries its own header)
#   (3) a source comment that admits copying ("copied from", "based on <forbidden project>")
# Runs on every PR, in an environment separate from the implementers.
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"
rc=0
fail() { echo "  ✖ $1" >&2; rc=1; }

# Git-tracked code files only (not docs/ — there the forbidden names may be mentioned as "do not use").
code_files() { git ls-files -- 'crates/**' 'src/**' '*.rs' 2>/dev/null || true; }

echo "== 1. No embedded third-party code =="
# Common vendoring directories
for d in vendor third_party third-party external deps/vendor; do
  if git ls-files -- "$d/**" | grep -q .; then fail "tracked vendoring directory: $d/"; fi
done
# A directory that carries the name of a forbidden implementation (a heuristic on path names, not on content)
forbidden='samba|krb5|heimdal|freeipa|389-?ds|openldap|sssd|realmd|adcli|winbind|impacket|wireshark|reactos|wine|apacheds'
if git ls-files | grep -iEa "(^|/)($forbidden)(/|\.)" ; then
  fail "a tracked path carries the name of a forbidden implementation (see above)"
fi

echo "== 2. No foreign licence header in code =="
# Licences that are not on the allow-list (MIT/Apache-2.0/BSD/ISC/Zlib/Unicode-3.0 — deny.toml)
bad_lic='GNU General Public|GPL-[23]|LGPL|AGPL|Mozilla Public License|MPL-2\.0|Server Side Public|SSPL|PROPRIETARY|All rights reserved, Microsoft'
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if grep -IlEa "$bad_lic" -- "$f" >/dev/null 2>&1; then
    fail "foreign licence header in: $f"
  fi
done < <(code_files)

echo "== 3. No source comment that admits copying =="
copied='copied from|adapted from|based on (the )?(samba|mit|heimdal|freeipa|openldap|impacket|reactos|wine)|(^|[^[:alnum:]-])ported from|taken from .*(kerberos|ldap|smb|netlogon)'
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if grep -InEa "$copied" -- "$f" >/dev/null 2>&1; then
    fail "suspicious source comment in: $f"
  fi
done < <(code_files)

echo "== 4. The specification PDF files are not tracked (consistent with OD-1 L-5) =="
if git ls-files -- 'tools/spec-pin/cache/**' | grep -q .; then
  fail "specification files committed to git — only hash+URL in manifest.json are needed"
fi

if [ "$rc" -eq 0 ]; then echo "✓ no clean-room contamination signs."; fi
exit "$rc"
