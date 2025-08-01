#!/usr/bin/env python3
"""
Static MITRE ATT&CK matrix generator
───────────────────────────────────
• Scans techniques/ for T#### folders/files
• Uses mitre_ttp_mapping.json for tactic mapping
• Builds docs/index.html with:
    – sticky header (title + search box)
    – live keyword filter (client-side JS, no external deps)
    – coloured pills: green=content, grey=placeholder, red column=Unmapped
"""

import html, json, pathlib, sys

# ── repo info for links ────────────────────────────────────────────────
OWNER, REPO, BRANCH, TECH_PATH = "Nvafiades1", "threat-hunt-library", "main", "techniques"
# ──────────────────────────────────────────────────────────────────────

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

# ── load & normalise mapping ──────────────────────────────────────────
try:
    raw = json.loads(MAP_FILE.read_text())
except Exception as e:
    print(f"❌  Cannot read {MAP_FILE}: {e}", file=sys.stderr)
    raw = {}

mapping = ({o["technique_id"]: o["tactic"].title().replace("-", " ") for o in raw}
           if isinstance(raw, list)
           else {k: v.title().replace("-", " ") for k, v in raw.items()})
print(f"[DEBUG] Mapping entries: {len(mapping)}")

# ── scan techniques ──────────────────────────────────────────────────
if not TECH_DIR.exists():
    print(f"❌  {TECH_DIR} not found!", file=sys.stderr)
    sys.exit(1)

tech_items = sorted([p for p in TECH_DIR.iterdir() if p.name.startswith("T")],
                    key=lambda p: p.name.lower())
print(f"[DEBUG] Items in TECH_DIR: {len(tech_items)} "
      f"(first five: {[p.name for p in tech_items[:5]]})")

def has_content(path: pathlib.Path) -> bool:
    if path.is_file():
        return True
    for f in path.iterdir():
        if f.is_file() and f.name.lower() not in {"readme.md", ".ds_store"}:
            return True
    return False

matrix: dict[str, list[tuple[str, bool]]] = {t: [] for t in TACTICS}
for item in tech_items:
    tid_full = item.name.split("_")[0]
    tid_base = tid_full.split(".")[0]
    tid      = tid_full if tid_full in mapping else tid_base
    tactic   = mapping.get(tid, "Unmapped")
    matrix.setdefault(tactic, []).append((item.name, has_content(item)))

print("[DEBUG] Counts per tactic:",
      {t: len(v) for t, v in matrix.items() if v})

# ── HTML helpers ──────────────────────────────────────────────────────
def esc(s: str) -> str: return html.escape(s.replace("_", " "))

headers, columns = [], []
for tact in TACTICS:
    headers.append(f'<div class="tactic">{esc(tact)}</div>')
    entries = matrix.get(tact, [])
    if not entries:
        columns.append('<div class="blank">(none)</div>')
        continue
    inner = []
    for tech, filled in entries:
        url  = f"https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{TECH_PATH}/{tech}"
        cls  = "filled" if filled else "empty"
        indent = "&nbsp;"*4 if "." in tech else ""
        inner.append(
            f'<div class="technique {cls}">{indent}'
            f'<a href="{url}" target="_blank">{esc(tech)}</a></div>')
    columns.append('<div class="col">' + "".join(inner) + '</div>')

# prepend Unmapped column if necessary
if matrix.get("Unmapped"):
    headers.insert(0, '<div class="tactic unmapped-h">Unmapped</div>')
    unmapped_inner = "".join(
        f'<div class="technique empty"><a href="https://github.com/{OWNER}/{REPO}/tree/'
        f'{BRANCH}/{TECH_PATH}/{tech}" target="_blank">{esc(tech)}</a></div>'
        for tech, _ in matrix["Unmapped"])
    columns.insert(0, '<div class="col">' + unmapped_inner + '</div>')

num_cols = len(headers)

# ── assemble HTML ────────────────────────────────────────────────────
HTML = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>MITRE ATT&CK Matrix</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif}}
header{{position:sticky;top:0;z-index:999;padding:.5rem 1rem;background:#111;
        display:flex;align-items:center;gap:1rem;border-bottom:1px solid #333}}
h1{{flex:1;text-align:center;margin:0;font-size:1.5rem}}
input[type=search]{{padding:.4rem .6rem;border-radius:4px;border:1px solid #444;
                   background:#1a1a1a;color:#eee}}
.grid{{display:grid;grid-template-columns:repeat({num_cols},minmax(12rem,1fr));
      gap:.5rem;padding:1rem}}
.tactic{{background:#333;font-weight:600;text-align:center;padding:.5rem}}
.unmapped-h{{background:#800}}
.col{{display:flex;flex-direction:column;gap:.25rem}}
.technique{{border:1px solid #444;border-radius:4px;padding:.25rem .5rem;
           font-size:.85rem;transition:opacity .2s}}
.technique a{{color:inherit;text-decoration:none}}
.technique.filled{{background:#235820}}
.technique.empty{{background:#1a1a1a}}
.technique a:hover{{text-decoration:underline}}
.blank{{color:#666;text-align:center;padding:1rem 0}}
</style>
</head><body>
<header>
  <h1>MITRE&nbsp;ATT&CK&nbsp;Matrix</h1>
  <input id="search" type="search" placeholder="Search…" autocomplete="off">
</header>
<div class="grid" id="matrix">{''.join(headers + columns)}</div>
<script>
const q=document.getElementById('search'), pills=[...document.querySelectorAll('.technique')];
q.addEventListener('input', e=>{ const val=e.target.value.toLowerCase();
  pills.forEach(p=>p.style.opacity = !val || p.textContent.toLowerCase().includes(val)?'1':'0.15');});
</script>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"✅  {OUTPUT} rebuilt")
