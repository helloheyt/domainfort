#!/usr/bin/env bash
# מוריד כל מסמך ב-tools/spec-pin/manifest.json, מחשב sha256, וממלא במניפסט.
# מוריד רק מ-hosts שב-agent-sandbox/egress-allowlist.txt (אכיפת SOURCES.md).
# דורש: jq, curl, sha256sum (או shasum).
# שימוש:  scripts/pin-specs.sh [--verify]
#   ברירת מחדל: ממלא sha256/revision חסרים ושומר ל-cache.
#   --verify:   בודק שה-sha256 הקיים עדיין תואם (ל-CI), בלי לשנות את המניפסט.
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
manifest="$root/tools/spec-pin/manifest.json"
cache="$root/tools/spec-pin/cache"
allow="$root/agent-sandbox/egress-allowlist.txt"
mode="${1:-pin}"
mkdir -p "$cache"

command -v jq >/dev/null || { echo "דרוש jq." >&2; exit 2; }
sha() { if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }

host_allowed() {
  local h="$1"
  grep -vE '^\s*#|^\s*$' "$allow" | grep -qxF "$h"
}

tmp="$(mktemp)"
cp "$manifest" "$tmp"
rc=0

count="$(jq '.documents | length' "$manifest")"
for i in $(seq 0 $((count-1))); do
  id="$(jq -r ".documents[$i].id" "$manifest")"
  url="$(jq -r ".documents[$i].url" "$manifest")"
  host="$(printf '%s' "$url" | sed -E 's#^https?://([^/]+)/.*#\1#')"

  if ! host_allowed "$host"; then
    echo "✖ $id: host '$host' אינו ב-egress-allowlist — מדלג." >&2; rc=1; continue
  fi

  out="$cache/$id"
  echo "• $id ← $host"
  if ! curl -fsSL "$url" -o "$out"; then
    echo "  ✖ הורדה נכשלה" >&2; rc=1; continue
  fi
  digest="$(sha < "$out")"
  have="$(jq -r ".documents[$i].sha256 // empty" "$manifest")"

  if [ "$mode" = "--verify" ]; then
    if [ -n "$have" ] && [ "$have" != "$digest" ]; then
      echo "  ✖ sha256 השתנה! מוצמד=$have נוכחי=$digest" >&2; rc=1
    else
      echo "  ✓ תואם"
    fi
  else
    tmp2="$(mktemp)"
    jq --arg d "$digest" ".documents[$i].sha256 = \$d" "$tmp" > "$tmp2" && mv "$tmp2" "$tmp"
    echo "  sha256=$digest"
  fi
done

if [ "$mode" != "--verify" ]; then
  jq --arg t "$(date -u +%FT%TZ)" '.generated_at = $t' "$tmp" > "$manifest"
  echo "✓ המניפסט עודכן. סקור והצמד (commit) את tools/spec-pin/manifest.json."
fi
rm -f "$tmp"
exit "$rc"
