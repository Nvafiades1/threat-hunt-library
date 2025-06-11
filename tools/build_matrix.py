#!/usr/bin/env python3
"""
Read MITRE's STIX bundle + every *.ipynb in hunts/,
produce docs/matrix.md with an ATT&CK Enterprise matrix
where each technique cell links to all notebooks that
claim that mitre_id.  Run in CI or locally.
"""
import json, pathlib, textwrap, requests, stix2

BUNDLE_URL = ("https://raw.githubusercontent.com/mitre-attack/"
              "attack-stix-data/master/enterprise-attack/enterprise-attack.json")  # :contentReference[oaicite:0]{index=0}
bundle = stix2.parse(requests.get(BUNDLE_URL, timeout=30).text, allow_custom=True)

# --- 1.  Build {tech_id: (name, tactic_shortname)} lookup -------------
tech = {}
for obj in bundle.attack_patterns:
    if obj.revoked or obj.x_mitre_deprecated:
        continue
    ext = next(x for x in obj.external_references
               if x.get("source_name") == "mitre-attack")
    tid = ext["external_id"]            # e.g. T1059.003
    tactic = obj.kill_chain_phases[0]["phase_name"]  # initial-access
    tech[tid] = (obj.name, tactic)

# --- 2.  Find notebooks and map tid → list[file] ----------------------
notebooks = pathlib.Path("hunts").glob("*.ipynb")
links = {tid: [] for tid in tech}
for nb in notebooks:
    meta = json.loads(nb.read_bytes()).get("metadata", {})
    tid = meta.get("mitre_id")
    if tid in links:
        url = f"../hunts/{nb.name}"
        links[tid].append(f"[📓]({url})")

# --- 3.  Build Markdown matrix (techniques grouped by tactic) --------
tactics = ["initial-access","execution","persistence","privilege-escalation",
           "defense-evasion","credential-access","discovery",
           "lateral-movement","collection","command-and-control",
           "exfiltration","impact"]

rows = []
for tid, (name, tac) in tech.items():
    md = " ".join(links[tid]) if links[tid] else ""
    cell = f"**{tid}**<br>{name}<br>{md}" if md else ""
    rows.append((tac, cell))

# Convert to Markdown table
from collections import defaultdict
cols = defaultdict(list)
for tac, cell in rows:
    cols[tac].append(cell)

header = "| " + " | ".join(tac.title().replace('-',' ') for tac in tactics) + " |"
sep    = "|" + " --- |"*len(tactics)
body   = []
for i in range(max(map(len, cols.values()))):
    body.append("| " + " | ".join(cols[tac][i] if i < len(cols[tac]) else "" for tac in tactics) + " |")

matrix_md = "\n".join([header, sep, *body])

path = pathlib.Path("docs/matrix.md")
path.write_text(textwrap.dedent(f"""
    # ATT&CK Enterprise Matrix – Auto-generated

    _(Each 📓 links to one or more hunt notebooks)_

    {matrix_md}
""").lstrip())
print("[+] wrote docs/matrix.md")
