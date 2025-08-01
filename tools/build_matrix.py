#!/usr/bin/env python3
"""
Static MITRE ATT&CK matrix generator
-----------------------------------
• Looks for T#### folders/files in the repository root.
• Maps each ID to a tactic via mitre_ttp_mapping.json (list or dict).
• Writes docs/index.html with clickable pills that open the folder on GitHub.
"""

import html
import json
import pathlib
import sys

# ---------- CONFIG ----------------------------------------------------------
OWNER  = "Nvafiades1"             # GitHub user / org
REPO   = "threat-hunt-library"    # repo name
BRANCH = "main"                   # branch that holds the folders

TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command And Control",
    "Exfiltration", "Impact"
]

ROOT      = pathlib.Path(__file__).resolve().parents[1]   # repo root
TECH_DIR  = ROOT                                          # scan root (change to ROOT / "techniques" if you move them)
MAP_FILE  = ROOT / "mitre_ttp_mapping.json"
DOCS_DIR  = ROOT / "docs"
OUTPUT    = DOCS_DIR / "index.html"

# ---------- LOAD + NORMALISE MAPPING ----------------------------------------
try:
    raw = json.loads(MAP_FILE.read_text())
except Exception as e:
    print(f"❌  Cannot read {MAP_FILE}: {e}", file=sys.stderr)
    sys.exit(1)

if isinstance(raw, list):                            # list[dict] → dict
    mapping = {
        obj["technique_id"]: obj["tactic"].title().replace("-", " ")
        for obj in raw if "technique_id" in obj and "tactic" in obj
    }
else:                                                # already dict
    mapping = {k: v.title().replace("-", " ") for k, v in raw.items()}

print(f"[DEBUG] Mapping entries: {len(mapping)}")

# ---------- SCAN TECHNIQUES --------------------------------------------------
if not TECH_DIR.exists():
    print(f"❌  {TECH_DIR} not found!", file=sys.stderr)
    sys.exit(1)

tech_items = sorted([p for p in TECH_DIR.iterdir() if p.name.startswith("T")],
                    key=lambda p: p.name.lower())
print(f"[DEBUG] Items in TECH_DIR: {len(tech_items)} "
      f"(first five: {[p.name for p in tech_items[:5]]})")

matrix = {t: [] for t in TACTICS}

for item in tech_items:
    tid_full = item.name.split("_")[0]   # strip anything after first underscore
    tid_base = tid_full.split(".")[0]    # convert sub-tech e.g. T1003.001 → T1003
    tid      = tid_full if tid_full in mapping else tid_base
    tactic   = mapping.get(tid, "Unmapped")
    matrix.setdefault(tactic, []).append(item.name)

print("[DEBUG] Counts per tactic:",
      {t: len(v) for t, v in matrix.items() if v})

# ---------- BUILD HTML -------------------------------------------------------
def esc(txt: str) -> str:
    return html.escape(txt.replace("_", " "))

cells = []
# Header row
cells.extend(f'<div class="tactic">{esc(t)}</div>' for t in TACTICS)

# Data row
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
            f'style="color:inherit;text-decoration:none;">{esc(tech)}</a>'
            f'</div>'
        )
    cells.append('<div class="col">' + "".join(inner) + '</div>')

HTML = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>MITRE ATT&CK Matrix</title>
<style>
body{{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif}}
h1{{text-align:center;margin:1rem 0 .5rem}}
.grid{{display:grid;grid-template-columns:repeat({len(TACTICS)},minmax(12rem,1fr));
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
