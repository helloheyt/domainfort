#!/usr/bin/env bash
# מוריד כל מסמך ב-tools/spec-pin/manifest.json, מחשב sha256, וממלא במניפסט.
# מוריד רק מ-hosts שב-agent-sandbox/egress-allowlist.txt (אכיפת SOURCES.md).
# דורש: jq, curl, sha256sum (או shasum).
# שימוש:  scripts/pin-specs.sh [--verify]
#   ברירת מחדל: ממלא sha256 **רק למסמך שעדיין לא הוצמד** ושומר ל-cache. מסמך שכבר
#              הוצמד ותוכנו השתנה — לא מוצמד מחדש: ה-sha256 המוצמד נשאר, ה-cache לא
#              נדרס, ההורדה החדשה נשמרת כ-<id>.unreviewed-<sha8> והסקריפט נכשל
#              (הצמדה-מחדש = החלטה מתועדת אחרי קריאת ה-Change Tracking; 2026-11-15). שדה revision נעוץ ידנית מעמוד
#              השער של המפרט (מזהה vYYYYMMDD) — ראו docs/17 SV; sha256 הוא עוגן
#              השלמות האמיתי, ושינוי גרסה ממילא משנה sha256 וייתפס ב---verify.
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
  dl="$(mktemp)"
  echo "• $id ← $host"
  if ! curl -fsSL "$url" -o "$dl"; then
    echo "  ✖ הורדה נכשלה" >&2; rc=1; rm -f "$dl"; continue
  fi
  digest="$(sha < "$dl")"
  have="$(jq -r ".documents[$i].sha256 // empty" "$manifest")"

  if [ -n "$have" ] && [ "$have" != "$digest" ]; then
    # Pinned and changed upstream: never re-pin silently, never overwrite the
    # pinned copy in the cache (both modes).
    keep="$cache/$id.unreviewed-${digest:0:8}"
    mv "$dl" "$keep"
    echo "  ✖ sha256 השתנה! מוצמד=$have נוכחי=$digest — נשמר ל-$keep לסקירה; ההצמדה לא שונתה" >&2
    rc=1; continue
  fi
  mv "$dl" "$out"
  if [ "$mode" = "--verify" ]; then
    echo "  ✓ תואם"
  elif [ -z "$have" ]; then
    tmp2="$(mktemp)"
    jq --arg d "$digest" ".documents[$i].sha256 = \$d" "$tmp" > "$tmp2" && mv "$tmp2" "$tmp"
    echo "  sha256=$digest (הוצמד לראשונה)"
  else
    echo "  ✓ תואם"
  fi
done

if [ "$mode" != "--verify" ]; then
  jq --arg t "$(date -u +%FT%TZ)" '.generated_at = $t' "$tmp" > "$manifest"
  echo "✓ המניפסט עודכן. סקור והצמד (commit) את tools/spec-pin/manifest.json."
fi
rm -f "$tmp"
exit "$rc"
