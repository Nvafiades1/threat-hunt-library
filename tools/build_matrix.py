#!/usr/bin/env python3
"""
Static MITRE ATT&CK matrix generator
────────────────────────────────────
Adds:
• sticky header, horizontal scroll
• live search with highlight + auto-expand
• tactic quick-filter pills
• copy-to-clipboard icon
• deep-link (#T1059.003) expansion + flash
• colour-coded columns
• last-updated badge (git log)
"""

import html, json, subprocess, pathlib, sys
from collections import defaultdict
from datetime import datetime

# ─── Repo config ────────────────────────────────────────────────────────────
OWNER, REPO, BRANCH, TECH_PATH = (
    "Nvafiades1", "threat-hunt-library", "main", "techniques"
)

TACTICS_COLOURS = {
    "Reconnaissance":        "#5b6cda",
    "Resource Development":  "#546de5",
    "Initial Access":        "#3d7ef0",
    "Execution":             "#f79f24",
    "Persistence":           "#f8c42f",
    "Privilege Escalation":  "#f7d055",
    "Defense Evasion":       "#e67e22",
    "Credential Access":     "#e15f41",
    "Discovery":             "#9b59b6",
    "Lateral Movement":      "#8e44ad",
    "Collection":            "#3498db",
    "Command And Control":   "#16a085",
    "Exfiltration":          "#27ae60",
    "Impact":                "#c0392b",
}

TACTICS = list(TACTICS_COLOURS.keys())

ROOT      = pathlib.Path(__file__).resolve().parents[1]
TECH_DIR  = ROOT / TECH_PATH
MAP_FILE  = ROOT / "mitre_ttp_mapping.json"
DOCS_DIR  = ROOT / "docs"
OUTPUT    = DOCS_DIR / "index.html"

# ─── Helpers ────────────────────────────────────────────────────────────────
def esc(txt: str) -> str:
    return html.escape(txt.replace("_", " "))

def badge_date(path: pathlib.Path) -> str:
    """Return last-commit date (YYYY-MM-DD) touching this path."""
    try:
        ts = subprocess.check_output(
            ["git", "log", "-1", "--format=%cs", "--", str(path)],
            cwd=ROOT, text=True
        ).strip()
        datetime.strptime(ts, "%Y-%m-%d")  # validate
        return ts
    except Exception:
        return "n/a"

def has_content(path: pathlib.Path) -> bool:
    if path.is_file():
        return True
    return any(f.is_file() and f.name.lower() not in {"readme.md", ".ds_store"}
               for f in path.iterdir())

# ─── Load mapping ───────────────────────────────────────────────────────────
try:
    raw = json.loads(MAP_FILE.read_text())
except Exception as e:
    print(f"❌  Cannot read {MAP_FILE}: {e}", file=sys.stderr)
    raw = {}

mapping = ({o["technique_id"]: o["tactic"].title().replace("-", " ") for o in raw}
           if isinstance(raw, list)
           else {k: v.title().replace("-", " ") for k, v in raw.items()})

# ─── Scan techniques & build matrix data ────────────────────────────────────
tech_items = sorted(
    [p for p in TECH_DIR.iterdir() if p.name.startswith("T")],
    key=lambda p: p.name.lower()
)

# tactic → parent → (parent_info, [subs])
matrix: dict[str, dict[str, tuple[tuple, list]]] = {
    t: defaultdict(lambda: [None, []]) for t in TACTICS
}

for item in tech_items:
    tech   = item.name
    tid    = tech.split("_")[0]
    parent = tid.split(".")[0]
    tactic = mapping.get(parent, "Unmapped")
    filled = has_content(item)
    date   = badge_date(item)
    bucket = matrix.setdefault(tactic, defaultdict(lambda: [None, []]))

    info_tuple = (tech, filled, date)
    if "." in tid:
        bucket[parent][1].append(info_tuple)
    else:
        bucket[parent][0] = info_tuple

# ─── Build HTML columns ─────────────────────────────────────────────────────
headers, columns = [], []
for tact in TACTICS:
    colour = TACTICS_COLOURS[tact]
    headers.append(f'<div class="tactic" style="background:{colour}">{esc(tact)}</div>')
    bucket = matrix.get(tact, {})
    if not bucket:
        columns.append('<div class="blank">(none)</div>')
        continue

    cell_inner = []
    for parent_id in sorted(bucket):
        p_info, subs = bucket[parent_id]
        if p_info is None:
            p_info = (parent_id, False, "n/a")
        p_name, p_filled, p_date = p_info
        p_cls = "filled" if p_filled else "empty"
        p_url = f"https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{TECH_PATH}/{p_name}"
        badge = f'<span class="date">{p_date}</span>'

        if subs:
            sub_html = "".join(
                f'<div class="sub"><a href="https://github.com/{OWNER}/{REPO}/tree/'
                f'{BRANCH}/{TECH_PATH}/{s}" target="_blank">{esc(s)}</a></div>'
                for s, _, _ in sorted(subs, key=lambda x: x[0])
            )
            cell_inner.append(
                f'<details class="technique {p_cls}" data-id="{p_name}">'
                f'<summary><a href="{p_url}" target="_blank">{esc(p_name)}</a>{badge}</summary>'
                f'{sub_html}</details>'
            )
        else:
            cell_inner.append(
                f'<div class="technique {p_cls}" data-id="{p_name}">'
                f'<a href="{p_url}" target="_blank">{esc(p_name)}</a>{badge}</div>'
            )

    columns.append('<div class="col">' + "".join(cell_inner) + "</div>")

num_cols = len(headers)

# ─── Template ───────────────────────────────────────────────────────────────
HTML = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>MITRE ATT&CK Matrix</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif}}
header{{position:sticky;top:0;left:0;right:0;z-index:999;background:#111;
        padding:.5rem 1rem;border-bottom:1px solid #333;
        display:flex;align-items:center;gap:.75rem}}
h1{{flex:1;text-align:center;margin:0;font-size:1.4rem}}
input[type=search]{{padding:.35rem .6rem;border-radius:4px;border:1px solid #444;
                   background:#1a1a1a;color:#eee;min-width:12rem}}
.filter-pill{{padding:.25rem .55rem;border-radius:50rem;font-size:.75rem;
             cursor:pointer;border:1px solid #555;user-select:none}}
.filter-pill.active{{background:#3498db;border-color:#3498db}}
.scroll-x{{overflow-x:auto}}
.grid{{display:grid;grid-template-columns:repeat({num_cols},minmax(12rem,1fr));
      gap:.5rem;padding:1rem min(1rem,50vw) 1rem 1rem}}
.tactic{{font-weight:600;text-align:center;padding:.5rem}}
.col{{display:flex;flex-direction:column;gap:.25rem}}
.technique{{border:1px solid #444;border-radius:4px;font-size:.85rem;
           position:relative;}}
.technique>summary, .technique>a{{display:flex;align-items:center;
           gap:.35rem;cursor:pointer;padding:.25rem .55rem}}
.technique.empty{{background:#1a1a1a}}
.technique.filled{{background:#235820}}
.date{{margin-left:auto;font-size:.65rem;color:#bbb}}
.clip{{opacity:0;transition:.2s;cursor:pointer}}
.technique:hover .clip{{opacity:1}}
.clip.done{{color:#2ecc71}}
.sub{{display:none;padding:.2rem .75rem .2rem 1.7rem;border-top:1px solid #333}}
details[open] .sub{{display:block}}
.sub a{{display:block}}
.blank{{color:#666;text-align:center;padding:1rem 0}}
mark{{background:#ffee58;color:#111}}
@media(max-width:600px) {{
  .grid{{grid-template-columns:repeat({num_cols},75vw)}}
}}
</style>
</head><body>

<header>
  <div id="filterBar"></div>
  <h1>MITRE&nbsp;ATT&CK&nbsp;Matrix</h1>
  <input id="search" type="search" placeholder="Search…" autocomplete="off">
</header>

<div class="scroll-x">
  <div class="grid" id="matrix">{''.join(headers + columns)}</div>
</div>

<script>
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

const pills   = $$('#matrix .technique, .sub');
const parents = $$('details.technique');
const search  = $('#search');

/* ── Copy to clipboard ─────────────────────────── */
pills.filter(p=>p.dataset.id = p.dataset.id || p.textContent.trim())
     .forEach(p=>{{
  const icon = document.createElement('span');
  icon.innerHTML = '📋';
  icon.className = 'clip';
  icon.title = 'Copy ID';
  icon.onclick = e => {{
    e.stopPropagation();
    navigator.clipboard.writeText(p.dataset.id);
    icon.classList.add('done'); icon.innerHTML='✓';
    setTimeout(()=>{{icon.classList.remove('done');icon.innerHTML='📋'}},900);
  }};
  (p.querySelector('summary')||p).append(icon);
}});

/* ── Quick tactic filter pills ─────────────────── */
const filterBar = $('#filterBar');
$$('.tactic').forEach((t,i)=>{{
  const pill=document.createElement('span');
  pill.className='filter-pill';
  pill.textContent=t.textContent;
  pill.style.borderColor=t.style.background;
  pill.onclick = ()=>{{
    pill.classList.toggle('active');
    const actives=$$('.filter-pill.active').map(p=>p.textContent);
    $$('.tactic').forEach((col,j)=>{{
      col.style.display = !actives.length||actives.includes(col.textContent)
                        ? '' : 'none';
      // mirror same for data column
      document.querySelectorAll('.col')[j].style.display=col.style.display;
    }});
  }};
  filterBar.append(pill);
}});

/* ── Search with highlight & auto-expand ───────── */
let lastMarks=[];
function clearMarks(){{lastMarks.forEach(m=>m.replaceWith(m.textContent));lastMarks=[]}}
search.addEventListener('input',e=>{{
  const q=e.target.value.toLowerCase().trim();
  clearMarks();
  pills.forEach(p=>p.style.opacity='1');
  parents.forEach(d=>d.open=false);
  if(!q) return;

  pills.forEach(p=>{{
    const txt=p.textContent.toLowerCase();
    if(!txt.includes(q)) p.style.opacity='0.15';
    else {{
      // highlight
      const inner=p.innerHTML;
      const mark=inner.replace(new RegExp(q,'gi'),m=>`<mark>${{m}}</mark>`);
      p.innerHTML=mark;
      lastMarks.push(...p.querySelectorAll('mark'));
      // ensure parent open
      const par=p.closest('details.technique');
      if(par) par.open=true;
    }}
  }});
}});

/* ── Deep-link support (#T####) ─────────────────── */
if(location.hash) {{
  const id=location.hash.slice(1);
  const target = document.querySelector(`[data-id="${{id}}"]`);
  if(target){{
    const par=target.closest('details.technique'); if(par) par.open=true;
    target.scrollIntoView({{behavior:'smooth',block:'center',inline:'center'}});
    target.style.boxShadow='0 0 0 3px #f1c40f';
    setTimeout(()=>target.style.boxShadow='',1500);
  }}
}}
</script>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"✅  {OUTPUT} rebuilt")
