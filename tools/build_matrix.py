#!/usr/bin/env python3
"""
Generate docs/index.html – MITRE ATT&CK matrix (dark skin)

Features
────────
• Collapsible sub-techniques
• Sticky header + search (auto-expand matches)
• Click a tactic header → dim the rest (Esc to reset)
• Tooltip: first 2 lines of README.md on hover
• Horizontal scroll

Drop this file at  tools/build_matrix.py
"""

import html, json, pathlib, sys
from collections import defaultdict

# ── repo specifics ───────────────────────────────────────────────────────────
OWNER, REPO, BRANCH, TECH_PATH = (
    "Nvafiades1", "threat-hunt-library", "main", "techniques",
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

# ── load tactic mapping ──────────────────────────────────────────────────────
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

# ── helpers ──────────────────────────────────────────────────────────────────
def has_content(path: pathlib.Path) -> bool:
    if path.is_file():
        return True
    return any(f.is_file() and f.name.lower() not in {"readme.md", ".ds_store"}
               for f in path.iterdir())

def read_snippet(folder: pathlib.Path, n=2) -> str:
    """Return first n non-blank lines of README.md (stripped of md syntax)."""
    md = folder / "README.md"
    if not md.exists():
        return ""
    out = []
    for line in md.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip().lstrip("#").strip()
        if not line or line.startswith("```") or line.startswith("!["):
            continue
        out.append(line)
        if len(out) >= n:
            break
    return " &#10; ".join(out)            # '&#10;' renders as newline in title

def esc(txt: str) -> str:
    return html.escape(txt.replace("_", " "))

# ── scan technique folders ───────────────────────────────────────────────────
if not TECH_DIR.exists():
    sys.exit(f"❌  {TECH_DIR} not found")

tech_items = sorted([p for p in TECH_DIR.iterdir() if p.name.startswith("T")],
                    key=lambda p: p.name.lower())

# tactic → parent_id → (parent_info, [sub_items])
matrix: dict[str, dict[str, tuple[tuple[str, bool] | None,
                                  list[tuple[str, bool]]]]] = {
    t: defaultdict(lambda: [None, []]) for t in TACTICS
}

for item in tech_items:
    tech   = item.name
    tid    = tech.split("_")[0]
    parent = tid.split(".")[0]
    tactic = mapping.get(parent, "Unmapped")
    filled = has_content(item)

    bucket = matrix.setdefault(tactic, defaultdict(lambda: [None, []]))
    if "." in tid:                       # sub-technique
        bucket[parent][1].append((tech, filled))
    else:                               # parent technique
        bucket[parent][0] = (tech, filled)

# ── build HTML ───────────────────────────────────────────────────────────────
headers, columns = [], []
for idx, tact in enumerate(TACTICS):
    headers.append(f'<div class="tactic" data-idx="{idx}">{esc(tact)}</div>')
    bucket = matrix.get(tact, {})
    if not bucket:
        columns.append(f'<div class="blank col" data-idx="{idx}">(none)</div>')
        continue

    inner = []
    for parent_id in sorted(bucket):
        p_info, subs = bucket[parent_id]
        if p_info is None:
            p_info = (parent_id, False)
        p_name, p_filled = p_info
        p_cls  = "filled" if p_filled else "empty"
        p_url  = f"https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{TECH_PATH}/{p_name}"
        p_tip  = html.escape(read_snippet(TECH_DIR / p_name))
        p_title= f' title="{p_tip}"' if p_tip else ""

        if subs:
            sub_html = ""
            for s_name, s_filled in sorted(subs, key=lambda x: x[0]):
                s_url   = f"https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{TECH_PATH}/{s_name}"
                s_tip   = html.escape(read_snippet(TECH_DIR / s_name))
                s_title = f' title="{s_tip}"' if s_tip else ""
                sub_html += (
                    f'<div class="sub"{s_title}><a href="{s_url}" '
                    f'target="_blank">{esc(s_name)}</a></div>'
                )
            inner.append(
                f'<details class="technique {p_cls}"{p_title}>'
                f'<summary><a href="{p_url}" target="_blank">{esc(p_name)}</a></summary>'
                f'{sub_html}</details>'
            )
        else:
            inner.append(
                f'<div class="technique {p_cls}"{p_title}>'
                f'<a href="{p_url}" target="_blank">{esc(p_name)}</a></div>'
            )
    columns.append(f'<div class="col" data-idx="{idx}">' + "".join(inner) + '</div>')

# prepend unmapped column if present
if matrix.get("Unmapped"):
    headers.insert(0, '<div class="tactic unmapped-h" data-idx="-1">Unmapped</div>')
    columns.insert(0, columns.pop())

num_cols = len(headers)

# ── HTML doc ─────────────────────────────────────────────────────────────────
HTML = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>MITRE ATT&CK Matrix</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif}}
body.focus .col.dim{{opacity:.15}}
header{{position:sticky;top:0;z-index:999;
        padding:.5rem 1rem;background:#111;border-bottom:1px solid #333;
        display:flex;align-items:center;gap:1rem}}
h1{{flex:1;text-align:center;margin:0;font-size:1.5rem}}
input[type=search]{{padding:.4rem .6rem;border-radius:4px;border:1px solid #444;
                   background:#1a1a1a;color:#eee}}
.scroll-x{{overflow-x:auto}}
.grid{{display:grid;grid-template-columns:repeat({num_cols},minmax(12rem,1fr));
      gap:.5rem;padding:1rem min(1rem,50vw) 1rem 1rem}}
.tactic{{background:#333;font-weight:600;text-align:center;padding:.5rem;cursor:pointer}}
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
.sub{{display:none;padding:.2rem .75rem .2rem 1.5rem;border-top:1px solid #333}}
details[open] .sub{{display:block}}
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
const q       = document.getElementById('search'),
      pills   = [...document.querySelectorAll('.technique, .sub')],
      details = [...document.querySelectorAll('details.technique')],
      tactics = [...document.querySelectorAll('.tactic')],
      cols    = [...document.querySelectorAll('.col')],
      body    = document.body;

let focused = null;
function setFocus(idx) {{
  focused = idx;
  body.classList.toggle('focus', idx !== null);
  cols.forEach(c => c.classList.toggle('dim', idx !== null && c.dataset.idx !== String(idx)));
}}
tactics.forEach(t => t.onclick = () => {{
  const idx = t.dataset.idx;
  setFocus(focused === idx ? null : idx);
}});
document.addEventListener('keydown', e => e.key === 'Escape' && setFocus(null));

q.addEventListener('input', e => {{
  const val = e.target.value.toLowerCase().trim();
  pills.forEach(p => p.style.opacity = (!val || p.textContent.toLowerCase().includes(val)) ? '1' : '0.15');
  details.forEach(d => {{
    const match = [...d.querySelectorAll('.sub')].some(
      s => s.textContent.toLowerCase().includes(val));
    d.open = val ? match : false;
  }});
}});
</script>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"✅  {OUTPUT} rebuilt → {OUTPUT}")
