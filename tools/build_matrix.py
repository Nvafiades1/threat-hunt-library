#!/usr/bin/env python3
"""
Static MITRE ATT&CK matrix generator
───────────────────────────────────
• Looks in techniques/ for folders/files that start with T####
• Reads mitre_ttp_mapping.json (dict OR list-of-dicts)
• Writes docs/index.html
    – pill = clickable link to the technique folder
    – pill gets class 'filled' when that folder/file contains ≥ 1 non-README file
"""

import html, json, pathlib, sys

# ── repo info for hyperlinks ────────────────────────────────────────────────
OWNER      = "Nvafiades1"
REPO       = "threat-hunt-library"
BRANCH     = "main"
TECH_PATH  = "techniques"          # ← location of the T#### folders
# ────────────────────────────────────────────────────────────────────────────

TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command And Control",
    "Exfiltration", "Impact"
]

ROOT      = pathlib.Path(__file__).resolve().parents[1]
TECH_DIR  = ROOT / TECH_PATH
MAP_FILE  = ROOT / "mitre_ttp_mapping.json"
DOCS_DIR  = ROOT / "docs"
OUTPUT    = DOCS_DIR / "index.html"

# ── load & normalise mapping ────────────────────────────────────────────────
try:
    raw = json.loads(MAP_FILE.read_text())
except Exception as e:
    print(f"❌  Cannot read {MAP_FILE}: {e}", file=sys.stderr)
    raw = {}

mapping = (
    {o["technique_id"]: o["tactic"].title().replace("-", " ")
     for o in raw} if isinstance(raw, list)
    else {k: v.title().replace("-", " ") for k, v in raw.items()}
)
print(f"[DEBUG] Mapping entries: {len(mapping)}")

# ── scan techniques ─────────────────────────────────────────────────────────
if not TECH_DIR.exists():
    print(f"❌  {TECH_DIR} not found!", file=sys.stderr)
    sys.exit(1)

tech_items = sorted([p for p in TECH_DIR.iterdir() if p.name.startswith("T")],
                    key=lambda p: p.name.lower())
print(f"[DEBUG] Items in TECH_DIR: {len(tech_items)} "
      f"(first five: {[p.name for p in tech_items[:5]]})")

# build matrix ⇢ tactic → list[(tech_id, has_content)]
matrix: dict[str, list[tuple[str, bool]]] = {t: [] for t in TACTICS}

def has_real_content(path: pathlib.Path) -> bool:
    """Return True if the technique dir/file contains something beyond README."""
    # file → always content (it *is* the MD)
    if path.is_file():
        return True
    # dir with any file that isn't README.md / .DS_Store etc.
    for f in path.iterdir():
        if f.is_file() and f.name.lower() not in {"readme.md", ".ds_store"}:
            return True
    return False

for item in tech_items:
    tid_full = item.name.split("_")[0]      # cut any slug after '_'
    tid_base = tid_full.split(".")[0]       # parent technique of sub-tech
    tid      = tid_full if tid_full in mapping else tid_base
    tactic   = mapping.get(tid, "Unmapped")
    matrix.setdefault(tactic, []).append((item.name, has_real_content(item)))

print("[DEBUG] Counts per tactic:",
      {t: len(v) for t, v in matrix.items() if v})

# ── HTML helpers ────────────────────────────────────────────────────────────
def esc(s: str) -> str:
    return html.escape(s.replace("_", " "))

cells, headers = [], []

# header row
for tact in TACTICS:
    headers.append(f'<div class="tactic">{esc(tact)}</div>')

# data columns
for tact in TACTICS:
    entries = matrix.get(tact, [])
    if not entries:
        cells.append('<div class="blank">(none)</div>')
        continue

    inner = []
    for tech, filled in entries:
        indent = "&nbsp;"*4 if "." in tech else ""
        url = f"https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{TECH_PATH}/{tech}"
        cls = "filled" if filled else "empty"
        inner.append(
            f'<div class="technique {cls}">{indent}'
            f'<a href="{url}" target="_blank" '
            f'style="color:inherit;text-decoration:none;">{esc(tech)}</a></div>'
        )
    cells.append('<div class="col">' + "".join(inner) + '</div>')

# Unmapped column (if any)
if matrix.get("Unmapped"):
    headers.insert(0, '<div class="tactic" style="background:#800">Unmapped</div>')
    inner = "".join(
        f'<div class="technique empty"><a href="https://github.com/{OWNER}/{REPO}/tree/'
        f'{BRANCH}/{TECH_PATH}/{tech}" target="_blank" '
        f'style="color:inherit;text-decoration:none;">{esc(tech)}</a></div>'
        for tech, _ in matrix["Unmapped"]
    )
    cells.insert(0, '<div class="col">' + inner + '</div>')

num_cols = len(headers)

# ── write HTML ──────────────────────────────────────────────────────────────
HTML = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>MITRE ATT&CK Matrix</title>
<style>
body{{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif}}
h1{{text-align:center;margin:1rem 0 .5rem}}
.grid{{display:grid;grid-template-columns:repeat({num_cols},minmax(12rem,1fr));
      gap:.5rem;padding:1rem}}
.tactic{{background:#333;font-weight:600;text-align:center;padding:.5rem}}
.col{{display:flex;flex-direction:column;gap:.25rem}}
.technique{{border:1px solid #444;border-radius:4px;
           padding:.25rem .5rem;font-size:.85rem}}
.technique.filled{{background:#235820}}      /* ← has real content  */
.technique.empty{{background:#1a1a1a}}       /* ← empty placeholder */
.technique a:hover{{text-decoration:underline}}
.blank{{color:#666;text-align:center;padding:1rem 0}}
</style></head><body>
<h1>MITRE ATT&CK Matrix</h1>
<div class="grid">{''.join(headers + cells)}</div>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"✅  {OUTPUT} rebuilt")
