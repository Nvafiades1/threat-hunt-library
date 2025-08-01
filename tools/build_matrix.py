#!/usr/bin/env python3
"""
Static MITRE ATT&CK matrix generator
-----------------------------------
• Scans techniques/ for T#### folders or files.
• Reads mitre_ttp_mapping.json (dict OR list-of-dicts, kebab- or space-case).
• Builds docs/index.html with clickable technique pills.
"""

import html, json, pathlib, sys

# ──────────────────────────── repo info for links ────────────────────────────
OWNER  = "Nvafiades1"             # GitHub user / org
REPO   = "threat-hunt-library"    # repository name
BRANCH = "main"                   # branch that holds the folders
# ─────────────────────────────────────────────────────────────────────────────

TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command And Control",
    "Exfiltration", "Impact"
]

ROOT      = pathlib.Path(__file__).resolve().parents[1]     # repo root
TECH_DIR  = ROOT / "techniques"                             # <- correct path
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
    {obj["technique_id"]: obj["tactic"].title().replace("-", " ")
     for obj in raw}
    if isinstance(raw, list)
    else {k: v.title().replace("-", " ") for k, v in raw.items()}
)

print(f"[DEBUG] Mapping entries: {len(mapping)}")

# ── scan techniques directory ───────────────────────────────────────────────
if not TECH_DIR.exists():
    print(f"❌  {TECH_DIR} not found!", file=sys.stderr)
    sys.exit(1)

tech_items = sorted([p for p in TECH_DIR.iterdir() if p.name.startswith("T")],
                    key=lambda p: p.name.lower())
print(f"[DEBUG] Items in TECH_DIR: {len(tech_items)} "
      f"(first five: {[p.name for p in tech_items[:5]]})")

matrix = {t: [] for t in TACTICS}
for item in tech_items:
    tid_full = item.name.split("_")[0]      # strip slug
    tid_base = tid_full.split(".")[0]       # parent ID for sub-tech
    tid      = tid_full if tid_full in mapping else tid_base
    tactic   = mapping.get(tid, "Unmapped")
    matrix.setdefault(tactic, []).append(item.name)

print("[DEBUG] Counts per tactic:",
      {t: len(v) for t, v in matrix.items() if v})

# ── build HTML ──────────────────────────────────────────────────────────────
def esc(s: str) -> str:
    return html.escape(s.replace("_", " "))

cells = []
# header row
cells.extend(f'<div class="tactic">{esc(t)}</div>' for t in TACTICS)

# data columns
for tact in TACTICS:
    techs = matrix.get(tact, [])
    if not techs:
        cells.append('<div class="blank">(none)</div>')
        continue

    inner = []
    for tech in techs:
        indent = "&nbsp;"*4 if "." in tech else ""
        url = f"https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{tech}"
        inner.append(
            f'<div class="technique">{indent}'
            f'<a href="{url}" target="_blank" '
            f'style="color:inherit;text-decoration:none;">{esc(tech)}</a></div>'
        )
    cells.append('<div class="col">' + "".join(inner) + '</div>')

# add visible Unmapped column if needed
if matrix.get("Unmapped"):
    cells.insert(0, '<div class="tactic" style="background:#800">Unmapped</div>')
    unmapped_inner = "".join(
        f'<div class="technique"><a href="https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{t}" '
        f'target="_blank" style="color:inherit;text-decoration:none;">{esc(t)}</a></div>'
        for t in matrix["Unmapped"]
    )
    cells.insert(1, '<div class="col">' + unmapped_inner + '</div>')

# number of tactic columns now
num_cols = int(len([c for c in cells if 'tactic' in c]) / 1)  # one cell per header

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
.technique{{background:#1a1a1a;border:1px solid #444;border-radius:4px;
           padding:.25rem .5rem;font-size:.85rem}}
.technique a:hover{{text-decoration:underline}}
.blank{{color:#666;text-align:center;padding:1rem 0}}
</style></head><body>
<h1>MITRE ATT&CK Matrix</h1>
<div class="grid">{''.join(cells)}</div>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"✅  {OUTPUT} rebuilt")
