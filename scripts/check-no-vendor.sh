#!/usr/bin/env bash
# שכבת-אכיפה 3 של ה-clean-room (ראו 01-cleanroom.md §אכיפה, 22 R14).
#
# חשוב: הבדיקה הזו **אינה** משווה מול קוד של מימושים אחרים — אסור להחזיק או
# להביא קורפוס אסור ([AGENTS.md] §2). במקום זה היא סורקת את *העץ שלנו* לשלושה
# סימני-זיהום שאינם דורשים קורפוס:
#   (1) קוד צד-שלישי שהוכנס לריפו (vendor/third_party/ או ספרייה ע"ש פרויקט אסור)
#   (2) כותרת-רישיון זרה בקובץ קוד (קובץ מועתק נושא בד"כ את הכותרת שלו)
#   (3) הערת-מקור שמודה בהעתקה ("copied from", "based on <פרויקט אסור>")
# מריצים על כל PR בסביבה נפרדת מהמממשים.
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"
rc=0
fail() { echo "  ✖ $1" >&2; rc=1; }

# קבצי קוד מעקב-git בלבד (לא docs/ — שם מותר לנקוב בשמות האסורים כ"אין להשתמש").
code_files() { git ls-files -- 'crates/**' 'src/**' '*.rs' 2>/dev/null || true; }

echo "== 1. אין קוד צד-שלישי מוטמע =="
# ספריות vendoring נפוצות
for d in vendor third_party third-party external deps/vendor; do
  if git ls-files -- "$d/**" | grep -q .; then fail "ספריית vendoring במעקב: $d/"; fi
done
# ספרייה שנושאת שם של מימוש אסור (heuristic על שמות נתיב, לא על תוכן)
forbidden='samba|krb5|heimdal|freeipa|389-?ds|openldap|sssd|realmd|adcli|winbind|impacket|wireshark|reactos|wine|apacheds'
if git ls-files | grep -iEa "(^|/)($forbidden)(/|\.)" ; then
  fail "נתיב במעקב נושא שם של מימוש אסור (ראו לעיל)"
fi

echo "== 2. אין כותרת-רישיון זרה בקוד =="
# רישיונות שאינם ב-allowlist (MIT/Apache-2.0/BSD/ISC/Zlib/Unicode-3.0 — deny.toml)
bad_lic='GNU General Public|GPL-[23]|LGPL|AGPL|Mozilla Public License|MPL-2\.0|Server Side Public|SSPL|PROPRIETARY|All rights reserved, Microsoft'
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if grep -IlEa "$bad_lic" -- "$f" >/dev/null 2>&1; then
    fail "כותרת-רישיון זרה ב: $f"
  fi
done < <(code_files)

echo "== 3. אין הערת-מקור שמודה בהעתקה =="
copied='copied from|adapted from|based on (the )?(samba|mit|heimdal|freeipa|openldap|impacket|reactos|wine)|ported from|taken from .*(kerberos|ldap|smb|netlogon)'
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if grep -InEa "$copied" -- "$f" >/dev/null 2>&1; then
    fail "הערת-מקור חשודה ב: $f"
  fi
done < <(code_files)

echo "== 4. קובצי ה-PDF של המפרטים אינם במעקב (עקבי עם OD-1 L-5) =="
if git ls-files -- 'tools/spec-pin/cache/**' | grep -q .; then
  fail "קובצי מפרט נעוצים ב-git — צריך רק hash+URL ב-manifest.json"
fi

if [ "$rc" -eq 0 ]; then echo "✓ אין סימני זיהום clean-room."; fi
exit "$rc"
