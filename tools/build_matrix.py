#!/usr/bin/env python3
"""
Rebuilds docs/index.html as a static MITRE ATT&CK matrix.

Assumptions
-----------
repo_root/
├─ techniques/               # every technique = folder or file named T####[…]
│    ├─ T1001/
│    └─ T1003.001/
├─ mitre_ttp_mapping.json    # either:
│      • dict  {"T1001": "Command-and-control", ...}
│      • list  [{"technique_id":"T1001","tactic":"Command-and-control"}, ...]
└─ tools/build_matrix.py     # ← this script

Result
------
Generates docs/index.html → pure HTML/CSS, no JS, no API calls.
"""

import json, html, pathlib

# ---------------------------------------------------------------------------
# CONFIG – adjust if ATT&CK adds / renames tactics
# ---------------------------------------------------------------------------
TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command And Control",
    "Exfiltration", "Impact"
]

ROOT       = pathlib.Path(__file__).resolve().parents[1]
TECH_DIR   = ROOT / "techniques"
MAP_FILE   = ROOT / "mitre_ttp_mapping.json"
DOCS_DIR   = ROOT / "docs"
OUTPUT     = DOCS_DIR / "index.html"

# ---------------------------------------------------------------------------
# LOAD & NORMALISE MAPPING
# ---------------------------------------------------------------------------
try:
    raw = json.loads(MAP_FILE.read_text())
except Exception as e:
    raise RuntimeError(f"❌ Cannot read {MAP_FILE}: {e}")

# Accept both formats and normalise tactic labels
if isinstance(raw, list):
    mapping = {
        obj["technique_id"]: obj["tactic"].title().replace("-", " ")
        for obj in raw
        if "technique_id" in obj and "tactic" in obj
    }
else:  # already a dict
    mapping = {k: v.title().replace("-", " ") for k, v in raw.items()}

# ---------------------------------------------------------------------------
# SCAN TECHNIQUES AND BUCKET BY TACTIC
# ---------------------------------------------------------------------------
matrix = {t: [] for t in TACTICS}

for item in sorted(TECH_DIR.iterdir(), key=lambda p: p.name.lower()):
    if not item.name.startswith("T"):
        continue

    # Strip optional underscore tail; collapse sub-tech (dot suffix) to base ID
    tid_full = item.name.split("_")[0]          # e.g. T1003.001
    tid_base = tid_full.split(".")[0]           # e.g. T1003
    tid      = tid_full if tid_full in mapping else tid_base

    tactic   = mapping.get(tid, "Unmapped")
    matrix.setdefault(tactic, []).append(item.name)

# ---------------------------------------------------------------------------
# BUILD HTML
# ---------------------------------------------------------------------------
def esc(s: str) -> str:
    return html.escape(s.replace("_", " "))

cells = []
# header row
cells.extend(f'<div class="tactic">{esc(t)}</div>' for t in TACTICS)
# data row
for tact in TACTICS:
    techs = matrix.get(tact, [])
    if not techs:
        cells.append('<div class="blank">(none)</div>')
        continue
    inner = []
    for tech in techs:
        indent = "&nbsp;&nbsp;&nbsp;&nbsp;" if "." in tech else ""
        inner.append(f'<div class="technique">{indent}{esc(tech)}</div>')
    cells.append('<div class="col">' + "".join(inner) + '</div>')

HTML = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><title>Threat-Hunt Library – MITRE ATT&CK Matrix</title>
<style>
body{{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif}}
h1{{text-align:center;margin:1rem 0 0.5rem}}
.grid{{display:grid;grid-template-columns:repeat({len(TACTICS)},minmax(12rem,1fr));
      gap:.5rem;padding:1rem}}
.tactic{{background:#333;font-weight:600;text-align:center;padding:.5rem}}
.col{{display:flex;flex-direction:column;gap:.25rem}}
.technique{{background:#1a1a1a;border:1px solid #444;border-radius:4px;
           padding:.25rem .5rem;font-size:.85rem}}
.blank{{color:#666;text-align:center;padding:1rem 0}}
</style></head><body>
<h1>Threat-Hunt Library<br/>MITRE ATT&CK Matrix</h1>
<div class="grid">{''.join(cells)}</div>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"✅ {OUTPUT} rebuilt")
