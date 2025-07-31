#!/usr/bin/env python3
"""
Rebuilds docs/index.html as a static MITRE ATT&CK matrix.

Assumptions
-----------
• The repository has:
    ├─ techniques/                # each technique is a file or folder
    │    ├─ T1001/
    │    ├─ T1001.001/
    │    └─ T1059_CommandExec.md
    └─ mitre_ttp_mapping.json     # {"T1001": "Exfiltration", ...}

• Technique names may include:
    * A sub-technique suffix after a dot  (e.g. T1001.001)
    * A human-readable tail after an underscore (e.g. T1059_CommandExec)

Result
------
Generates docs/index.html containing a fully rendered matrix—no JS, no API.
"""

import json
import os
import pathlib
import html

# --------------------------------------------------------------------------
# Config – tweak if the ATT&CK framework changes
# --------------------------------------------------------------------------

TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command And Control",
    "Exfiltration", "Impact"
]

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TECH_DIR   = REPO_ROOT / "techniques"
MAPPING_FN = REPO_ROOT / "mitre_ttp_mapping.json"
DOCS_DIR   = REPO_ROOT / "docs"
OUTPUT_FN  = DOCS_DIR / "index.html"

# --------------------------------------------------------------------------
# Load mapping file
# --------------------------------------------------------------------------

try:
    mapping = json.loads(MAPPING_FN.read_text())
except Exception as e:
    raise RuntimeError(f"❌  Cannot read {MAPPING_FN}: {e}")

# --------------------------------------------------------------------------
# Scan techniques directory
# --------------------------------------------------------------------------

matrix = {t: [] for t in TACTICS}            # tactic -> list of display strings

for item in sorted(TECH_DIR.iterdir(), key=lambda p: p.name.lower()):
    name = item.name

    # Must start with a technique ID like T1234
    if not name.startswith("T"):
        continue

    # Extract IDs
    tid_full = name.split("_")[0]            # "T1001.001" or "T1001"
    tid_base = tid_full.split(".")[0]        # "T1001"
    tid      = tid_full if tid_full in mapping else tid_base

    tactic = mapping.get(tid, "Unmapped")
    matrix.setdefault(tactic, []).append(name)

# --------------------------------------------------------------------------
# Build HTML
# --------------------------------------------------------------------------

def esc(txt: str) -> str:
    """HTML-escape and make underscores look nicer."""
    return html.escape(txt.replace("_", " "))

rows = []

# Header row
for tact in TACTICS:
    rows.append(f'<div class="tactic">{esc(tact)}</div>')

# Data row – each column stacked vertically
for tact in TACTICS:
    techs = matrix.get(tact, [])
    if not techs:
        rows.append('<div class="blank">(none)</div>')
        continue

    inner = []
    for tech in techs:
        indent = "&nbsp;&nbsp;&nbsp;&nbsp;" if "." in tech else ""
        inner.append(f'<div class="technique">{indent}{esc(tech)}</div>')
    rows.append('<div class="col">' + "".join(inner) + '</div>')

html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Threat-Hunt Library – MITRE ATT&CK Matrix</title>
<style>
body{{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif}}
h1{{text-align:center;margin:1rem 0}}
.grid{{
  display:grid;
  grid-template-columns:repeat({len(TACTICS)},minmax(12rem,1fr));
  gap:.5rem; padding:1rem;
}}
.tactic{{
  background:#333; font-weight:600; text-align:center; padding:.5rem;
}}
.col{{display:flex;flex-direction:column;gap:.25rem}}
.technique{{
  background:#1a1a1a; border:1px solid #444; border-radius:4px;
  padding:.25rem .5rem; font-size:.85rem;
}}
.blank{{color:#666;text-align:center;padding:1rem 0}}
</style>
</head>
<body>
<h1>MITRE ATT&CK Matrix</h1>
<div class="grid">
{''.join(rows)}
</div>
</body>
</html>"""

# --------------------------------------------------------------------------
# Write output
# --------------------------------------------------------------------------

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT_FN.write_text(html_out, encoding="utf-8")
print("✅  docs/index.html rebuilt")
