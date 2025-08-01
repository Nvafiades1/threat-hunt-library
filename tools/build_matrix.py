#!/usr/bin/env python3
"""
Generate docs/index.html – static MITRE ATT&CK matrix
with nested sub-techniques, sticky header & live search.
"""

import html, json, pathlib, sys
from collections import defaultdict

# ── repo specifics ───────────────────────────────────────────────────────────
OWNER, REPO, BRANCH, TECH_PATH = (
    "Nvafiades1",            # GitHub user / org
    "threat-hunt-library",   # repository name
    "main",                  # branch
    "techniques",            # folder holding T#### directories
)

TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command And Control",
    "Exfiltration", "Impact",
]

ROOT      = pathlib.Path(__file__).resolve().parents[1]
TECH_DIR  = ROOT / TECH_PATH
MAP_FILE  = ROOT / "mitre_ttp_mapping.json"
DOCS_DIR  = ROOT / "docs"
OUTPUT    = DOCS_DIR / "index.html"

# ── load mapping ─────────────────────────────────────────────────────────────
try:
    raw = json.loads(MAP_FILE.read_text())
except Exception as e:
    print(f"❌  Cannot read {MAP_FILE}: {e}", file=sys.stderr)
    raw = {}

mapping = (
    {o["technique_id"]: o["tactic"].title().replace("-", " ") for o in raw}
    if isinstance(raw, list)
    else {k: v.title().replace("-", " ") for k, v in raw.items()}
)
print(f"[DEBUG] Mapping entries: {len(mapping)}")

# ── scan techniques ──────────────────────────────────────────────────────────
if not TECH_DIR.exists():
    print(f"❌  {TECH_DIR} not found!", file=sys.stderr)
    sys.exit(1)

tech_items = sorted(
    [p for p in TECH_DIR.iterdir() if p.name.startswith("T")],
    key=lambda p: p.name.lower(),
)
print(
    f"[DEBUG] Items in TECH_DIR: {len(tech_items)} "
    f"(first five: {[p.name for p in tech_items[:5]]})"
)

def has_content(path: pathlib.Path) -> bool:
    if path.is_file():
        return True
    for f in path.iterdir():
        if f.is_file() and f.name.lower() not in {"readme.md", ".ds_store"}:
            return True
    return False

# tactic → parent_id → (parent_info, [sub_items])
matrix: dict[str, dict[str, tuple[tuple[str, bool], list[tuple[str, bool]]]]] = {
    t: defaultdict(lambda: [None, []]) for t in TACTICS
}

for item in tech_items:
    tech_name = item.name
    tid_full  = tech_name.split("_")[0]
    tid_base  = tid_full.split(".")[0]
    tactic    = mapping.get(tid_base, "Unmapped")  # map by parent ID
    filled    = has_content(item)

    parent_bucket = matrix.setdefault(tactic, defaultdict(lambda: [None, []]))
    if "." in tid_full:  # sub-technique
        parent_bucket[tid_base][1].append((tech_name, filled))
    else:                # parent technique
        parent_bucket[tid_base][0] = (tech_name, filled)

print(
    "[DEBUG] Counts per tactic:",
    {t: sum(len(v[1]) + (1 if v[0] else 0) for v in bucket.values())
     for t, bucket in matrix.items() if bucket},
)

# ── build HTML cells ─────────────────────────────────────────────────────────
def esc(s: str) -> str:
    return html.escape(s.replace("_", " "))

headers, columns = [], []
for tact in TACTICS:
    headers.append(f'<div class="tactic">{esc(tact)}</div>')
    bucket = matrix.get(tact, {})
    if not bucket:
        columns.append('<div class="blank">(none)</div>')
        continue

    inner = []
    for parent_id in sorted(bucket.keys()):
        parent_info, subs = bucket[parent_id]
        # if a parent folder is missing (rare), create a placeholder
        if parent_info is None:
            parent_info = (parent_id, False)
        parent_name, parent_filled = parent_info
        p_cls = "filled" if parent_filled else "empty"
        p_url = (f"https://github.com/{OWNER}/{REPO}/tree/"
                 f"{BRANCH}/{TECH_PATH}/{parent_name}")
        # build sub-technique list
        if subs:
            sub_html = "".join(
                f'<div class="sub"><a href="https://github.com/{OWNER}/{REPO}/tree/'
                f'{BRANCH}/{TECH_PATH}/{s}" target="_blank">{esc(s)}</a></div>'
                for s, _ in sorted(subs, key=lambda x: x[0].lower())
            )
            inner.append(
                f'<details class="technique {p_cls}"><summary>'
                f'<a href="{p_url}" target="_blank">{esc(parent_name)}</a>'
                f'</summary>{sub_html}</details>'
            )
        else:
            inner.append(
                f'<div class="technique {p_cls}"><a href="{p_url}" '
                f'target="_blank">{esc(parent_name)}</a></div>'
            )

    columns.append('<div class="col">' + "".join(inner) + "</div>")

# Prepend Unmapped column if present
if matrix.get("Unmapped"):
    headers.insert(0, '<div class="tactic unmapped-h">Unmapped</div>')
    unmapped_cols = "".join(columns.pop(TACTICS.index("Unmapped")))
    columns.insert(0, unmapped_cols)

num_cols = len(headers)

# ── write HTML ───────────────────────────────────────────────────────────────
HTML = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>MITRE ATT&CK Matrix</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif}}
/* Sticky header */
header{{position:sticky;top:0;left:0;right:0;z-index:999;
        padding:.5rem 1rem;background:#111;border-bottom:1px solid #333;
        display:flex;align-items:center;gap:1rem}}
h1{{flex:1;text-align:center;margin:0;font-size:1.5rem}}
input[type=search]{{padding:.4rem .6rem;border-radius:4px;border:1px solid #444;
                   background:#1a1a1a;color:#eee}}
/* Horizontal scroll container */
.scroll-x{{overflow-x:auto}}
.grid{{display:grid;grid-template-columns:repeat({num_cols},minmax(12rem,1fr));
      gap:.5rem;padding:1rem min(1rem,50vw) 1rem 1rem;}}
/* Cells */
.tactic{{background:#333;font-weight:600;text-align:center;padding:.5rem}}
.unmapped-h{{background:#800}}
.col{{display:flex;flex-direction:column;gap:.25rem}}
.technique{{border:1px solid #444;border-radius:4px;font-size:.85rem}}
.technique > summary{{cursor:pointer;list-style:none;padding:.25rem .5rem}}
.technique > summary::-webkit-details-marker{{display:none}}
.technique > summary::after{{content:'▸';float:right}}
details[open] > summary::after{{content:'▾'}}
.technique.filled{{background:#235820}}
.technique.empty{{background:#1a1a1a}}
.technique a{{color:inherit;text-decoration:none}}
.technique a:hover{{text-decoration:underline}}
.sub{{padding:.2rem .75rem .2rem 1.5rem;border-top:1px solid #333}}
.blank{{color:#666;text-align:center;padding:1rem 0}}
</style>
</head><body>
<header>
  <h1>MITRE&nbsp;ATT&CK&nbsp;Matrix</h1>
  <input id="search" type="search" placeholder="Search…" autocomplete="off">
</header>

<div class="scroll-x">
  <div class="grid" id="matrix">{''.join(headers + columns)}</div>
</div>

<script>
const q = document.getElementById('search'),
      pills = [...document.querySelectorAll('.technique, .sub')];

q.addEventListener('input', e => {{
  const val = e.target.value.toLowerCase();
  pills.forEach(p => p.style.opacity =
      !val || p.textContent.toLowerCase().includes(val) ? '1' : '0.15');
}});
</script>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"✅  {OUTPUT} rebuilt")
