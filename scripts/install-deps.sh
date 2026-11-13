#!/usr/bin/env bash
# install-deps.sh — מתקין את התלויות של הפרויקט על המכונה של מי שבונה אותו.
#
# זה המקבילה של `npm install` מול package.json:
#   Cargo.toml   ≈ package.json       — רשימת התלויות (שם + טווח-גרסה), בלי הקוד שלהן
#   Cargo.lock   ≈ package-lock.json  — הגרסאות המדויקות + checksum לכל חבילה
#   cargo fetch  ≈ npm install        — מוריד את החבילות מ-crates.io אל המטמון של המשתמש
#
# המאגר הזה לא מכיל ולא יכיל קוד של צד-שלישי (AGENTS.md §7: "Never copy its code into
# this repo"). כל תלות יורדת אצל מי שבונה, מהמקור הרשמי, בגרסה הנעוצה ב-Cargo.lock.
#
# מה הסקריפט עושה:
#   1. בודק ש-rustup/cargo מותקנים (לא מוריד ולא מריץ סקריפט-התקנה בעצמו).
#   2. מתקין את גרסת ה-Rust הנעוצה ב-rust-toolchain.toml (דרך rustup), ובודק שיש מהדר C
#      (aws-lc-sys מקמפל C; P-21) — נכשל עם הוראות אם חסר, לא מתקין דבר. CMake — רק אזהרה (A-71).
#   3. מוריד את התלויות בדיוק לפי Cargo.lock (`cargo fetch --locked`).
#   4. מאמת שכל תלות של צד-שלישי ברישיון מהרשימה המותרת (AGENTS.md §7), ונכשל אם לא.
#   5. מריץ `cargo deny check` אם הכלי מותקן (בדיקה מלאה: רישיונות, חבילות אסורות, פגיעויות).
#
# שימוש:
#   bash scripts/install-deps.sh               התקנה מלאה + בדיקת רישיונות
#   bash scripts/install-deps.sh --check-only  בדיקת toolchain של C + רישיונות (בלי הורדה)
#   bash scripts/install-deps.sh --help
#
# לא כלול: תלויות ה-fuzzing (workspaces נפרדים תחת crates/*/fuzz) — ממתינות לאישור P-1.
set -euo pipefail
cd "$(dirname "$0")/.."

# רשימת הרישיונות המותרים — זהה ל-deny.toml ול-AGENTS.md §7. שינוי = החלטת-בעלים (D70).
ALLOWED_LICENSES="MIT Apache-2.0 BSD-2-Clause BSD-3-Clause ISC Zlib Unicode-3.0"

check_only=0
case "${1:-}" in
  "") ;;
  --check-only) check_only=1 ;;
  -h|--help)
    sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  *) echo "אפשרות לא מוכרת: $1 (ראו --help)" >&2; exit 2 ;;
esac

# --- 1. rustup / cargo ---------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1 || ! command -v rustup >/dev/null 2>&1; then
  cat >&2 <<'MSG'
rustup / cargo לא נמצאו.
התקינו את Rust דרך מנהל-החבילות של המערכת או לפי ההוראות הרשמיות ב-https://rustup.rs
ואז הריצו שוב את הסקריפט. (הסקריפט לא מוריד ולא מריץ סקריפט-התקנה בעצמו.)
MSG
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 לא נמצא — נדרש לבדיקת הרישיונות." >&2
  exit 1
fi

# --- 2. toolchain --------------------------------------------------------------
# הרצת cargo בתוך המאגר גורמת ל-rustup להתקין את הגרסה הנעוצה ב-rust-toolchain.toml.
echo "==> toolchain (rust-toolchain.toml)"
cargo --version
rustc --version

# --- 2b. ‏toolchain של C (aws-lc-sys מקמפל קוד C) ----------------------------------
# ספק-הקריפטו שמתחת ל-rustls ‏(aws-lc-rs, ‏OD-9; ‏docs/50 R50-11) בונה את ספריית AWS-LC
# ב-C דרך aws-lc-sys. דרישות-הבנייה כפי שהן כתובות בדף docs.rs של aws-lc-rs 1.19.0 (פרק Build):
#   "Consuming projects will need a C/C++ compiler to build."
#   "Non-FIPS builds (default): CMake is never required; Bindgen is never required
#    (pre-generated bindings are provided); Go is never required."
# ובדף docs.rs של rustls 0.23.46 (ה-feature aws_lc_rs):
#   "Note that aws-lc-rs has additional build-time dependencies like cmake."
# הכרעת-הבעלים P-21: לבדוק שיש מהדר C ו-CMake, ולהיכשל עם הוראות אם לא.
# (CMake נבדק כהכרעת P-21 אף שדף aws-lc-rs אומר שאינו נדרש בבנייה הלא-FIPS —
# docs/questions/Q-285 פריט 11.) הסקריפט לעולם לא מתקין דבר בעצמו.
# נבדק גם ב---check-only: בלי מהדר C אין בנייה, וטוב לדעת לפני שמגיעים אליה.
echo "==> toolchain של C (aws-lc-sys): מהדר C"
cc_command="${CC:-cc}"
cc_command="${cc_command%% *}"
missing_tools=""
if ! command -v "$cc_command" >/dev/null 2>&1; then
  missing_tools="$missing_tools $cc_command"
fi
if [ -n "$missing_tools" ]; then
  cat >&2 <<MSG
חסרים כלי-בנייה:${missing_tools}
ספק-הקריפטו של TLS ‏(aws-lc-rs → aws-lc-sys) מקמפל קוד C בזמן הבנייה:
  - מהדר C/C++ (הפקודה \`cc\`, או זו שבמשתנה CC) — "Consuming projects will need a C/C++
    compiler to build" (docs.rs aws-lc-rs 1.19.0);
התקינו אותו דרך מנהל-החבילות של המערכת והריצו שוב.
(הסקריפט לא מתקין דבר בעצמו.)
MSG
  exit 1
fi
"$cc_command" --version 2>&1 | sed -n 1p
# CMake לא נדרש לבנייה הרגילה (לא-FIPS) — "Non-FIPS builds (default): CMake is never required"
# (docs.rs aws-lc-rs 1.19.0). הכרעה A-71 (Q-285 פריט 11): רק אזהרה אם חסר.
if command -v cmake >/dev/null 2>&1; then
  cmake --version 2>&1 | sed -n 1p
else
  echo "   (CMake לא נמצא — לא נדרש לבנייה הרגילה; נדרש רק לגרסת FIPS, שחסומה ב-P-15)"
fi

# --- 3. הורדת התלויות -----------------------------------------------------------
if [ "$check_only" -eq 0 ]; then
  echo "==> הורדת התלויות לפי Cargo.lock (cargo fetch --locked)"
  # --locked: נכשל אם Cargo.lock לא תואם ל-Cargo.toml — אף גרסה לא "מתעדכנת" בשקט.
  cargo fetch --locked
fi

# --- 4. בדיקת רישיונות ------------------------------------------------------------
echo "==> בדיקת רישיונות מול הרשימה המותרת: $ALLOWED_LICENSES"
# (בלי מערך ריק: bash 3.2 של macOS מתייחס אליו כמשתנה לא-מוגדר תחת set -u.)
if [ "$check_only" -eq 1 ]; then
  metadata_cmd=(cargo metadata --locked --offline --format-version 1)
else
  metadata_cmd=(cargo metadata --locked --format-version 1)
fi
"${metadata_cmd[@]}" \
  | ALLOWED_LICENSES="$ALLOWED_LICENSES" python3 -I -c '
import json, os, sys

allowed = set(os.environ["ALLOWED_LICENSES"].split())
meta = json.load(sys.stdin)

def tokens(expr):
    out, word = [], ""
    for ch in expr:
        if ch in "()":
            if word: out.append(word); word = ""
            out.append(ch)
        elif ch.isspace():
            if word: out.append(word); word = ""
        else:
            word += ch
    if word: out.append(word)
    return out

# דקדוק SPDX מצומצם: expr := term ("OR" term)* ; term := factor ("AND" factor)* ;
# factor := "(" expr ")" | ID ["WITH" ID]. תוספת WITH נחשבת לא-מותרת (מחמיר):
# החבילה עוברת רק אם יש לה חלופה אחרת שכולה ברשימה.
def parse(toks):
    pos = 0
    def peek():
        return toks[pos] if pos < len(toks) else None
    def take():
        nonlocal pos
        t = peek(); pos += 1; return t
    def factor():
        t = take()
        if t == "(":
            v = expr()
            if take() != ")": raise ValueError("unbalanced")
            return v
        if t is None or t in (")", "AND", "OR", "WITH"): raise ValueError("bad token")
        if peek() == "WITH":
            take(); take()
            return False
        return t in allowed
    def term():
        v = factor()
        while peek() == "AND":
            take(); v = factor() and v
        return v
    def expr():
        v = term()
        while peek() == "OR":
            take(); v = term() or v
        return v
    v = expr()
    if peek() is not None: raise ValueError("trailing")
    return v

third_party, bad = [], []
for p in meta["packages"]:
    if p.get("source") is None:   # crate של המאגר עצמו (path)
        continue
    lic = p.get("license")
    ok = False
    if lic:
        try:
            ok = parse(tokens(lic))
        except ValueError:
            ok = False
    third_party.append((p["name"], p["version"], lic or "UNKNOWN"))
    if not ok:
        bad.append((p["name"], p["version"], lic or "UNKNOWN"))

for name, ver, lic in sorted(third_party):
    print(f"   {name} {ver}  [{lic}]")
print(f"   סה\"כ חבילות צד-שלישי: {len(third_party)}")
if bad:
    print("נכשל: רישיון מחוץ לרשימה המותרת (AGENTS.md §7):", file=sys.stderr)
    for name, ver, lic in bad:
        print(f"   {name} {ver}  [{lic}]", file=sys.stderr)
    sys.exit(1)
print("   ✓ כל התלויות ברישיון מהרשימה המותרת.")
'

# --- 5. cargo-deny (אופציונלי) ---------------------------------------------------
if cargo deny --version >/dev/null 2>&1; then
  echo "==> cargo deny check (רישיונות, חבילות אסורות, פגיעויות ידועות)"
  cargo deny check
else
  echo "==> cargo-deny לא מותקן — דילוג (ב-CI הוא רץ תמיד). להתקנה: cargo install cargo-deny"
fi

echo "==> מוכן. התלויות במטמון של cargo על המכונה הזו — לא בתוך המאגר."
