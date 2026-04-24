#!/usr/bin/env python3
"""
Generate docs/index.html – Threat Hunt Matrix (MITRE ATT&CK-based)

Features
────────
• MITRE ATT&CK-style matrix layout (tactic columns, technique cards)
• Technique names parsed from each technique's README.md heading
• Per-tactic technique count badges
• Subtle left-border accent on techniques with hunt coverage
• Collapsible sub-techniques with sub-count indicator
• Sticky header + live search (auto-expand matches)
• Click a tactic header → dim other columns (Esc to reset)
• Dark / Light mode toggle (persisted)
"""

import html, json, pathlib, re, sys
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

IMPACT_IDS = {
    "T1485", "T1486", "T1489", "T1490", "T1491", "T1492", "T1493",
    "T1494", "T1495", "T1496", "T1498", "T1499",
    "T1529", "T1561", "T1565", "T1646", "T1657",
}

ROOT      = pathlib.Path(__file__).resolve().parents[1]
TECH_DIR  = ROOT / TECH_PATH
MAP_FILE  = ROOT / "mitre_ttp_mapping.json"
DOCS_DIR  = ROOT / "docs"
OUTPUT    = DOCS_DIR / "index.html"

# ── load tactic mapping ──────────────────────────────────────────────────────
try:
    raw = json.loads(MAP_FILE.read_text())
except Exception as e:
    print(f"Cannot read {MAP_FILE}: {e}", file=sys.stderr)
    raw = {}

mapping = (
    {o["technique_id"]: o["tactic"].title().replace("-", " ") for o in raw}
    if isinstance(raw, list)
    else {k: v.title().replace("-", " ") for k, v in raw.items()}
)

# ── helpers ──────────────────────────────────────────────────────────────────
def has_content(path: pathlib.Path) -> bool:
    """True if the technique folder contains a hunt file (anything besides README)."""
    if path.is_file():
        return True
    return any(f.is_file() and f.name.lower() not in {"readme.md", ".ds_store"}
               for f in path.iterdir())

_heading_re = re.compile(r"^\s*#+\s*(.+?)\s*$")

def read_name(folder: pathlib.Path) -> str:
    """Return the first markdown heading from README.md as the technique name."""
    md = folder / "README.md"
    if not md.exists():
        return ""
    try:
        for ln in md.read_text("utf-8", "ignore").splitlines():
            m = _heading_re.match(ln)
            if m:
                name = m.group(1).strip()
                name = re.sub(r"\s*\(T\d{4}(?:\.\d{3})?\)\s*$", "", name)
                return name
    except Exception:
        pass
    return ""

def read_snippet(folder: pathlib.Path, n: int = 2) -> str:
    """First n non-trivial lines from README.md (for hover tooltip)."""
    md = folder / "README.md"
    if not md.exists():
        return ""
    out = []
    for ln in md.read_text("utf-8", "ignore").splitlines():
        ln = ln.strip().lstrip("#").strip()
        if not ln or ln.startswith("```") or ln.startswith("!["):
            continue
        out.append(ln)
        if len(out) >= n:
            break
    return " \u2014 ".join(out)

def esc(txt: str) -> str:
    return html.escape(txt.replace("_", " "))

# ── scan technique folders ───────────────────────────────────────────────────
if not TECH_DIR.exists():
    sys.exit(f"{TECH_DIR} not found")

tech_items = sorted([p for p in TECH_DIR.iterdir() if p.name.startswith("T")],
                    key=lambda p: p.name.lower())

# tactic -> parent_id -> {"parent": (id, name, filled)|None, "subs": [(id,name,filled)]}
matrix: dict[str, dict[str, dict]] = {t: defaultdict(lambda: {"parent": None, "subs": []})
                                      for t in TACTICS}
unmapped_ids: set[str] = set()

for item in tech_items:
    tech   = item.name
    tid    = tech.split("_")[0]
    parent = tid.split(".")[0]
    tactic = mapping.get(parent)
    if tactic is None:
        tactic = "Impact" if parent in IMPACT_IDS else "Unmapped"
        if tactic == "Unmapped":
            unmapped_ids.add(parent)

    filled = has_content(item)
    name   = read_name(item)
    bucket = matrix.setdefault(tactic, defaultdict(lambda: {"parent": None, "subs": []}))
    if "." in tid:
        bucket[parent]["subs"].append((tech, name, filled))
    else:
        bucket[parent]["parent"] = (tech, name, filled)

if unmapped_ids:
    print("Still unmapped:", ", ".join(sorted(unmapped_ids)))

# ── build HTML ───────────────────────────────────────────────────────────────
headers, columns = [], []

def tactic_parent_count(tact: str) -> int:
    return len([p for p in matrix.get(tact, {}).values() if p["parent"]])

for idx, tact in enumerate(TACTICS):
    count = tactic_parent_count(tact)
    headers.append(
        f'<div class="tactic" data-idx="{idx}">'
        f'<div class="tactic-name">{esc(tact)}</div>'
        f'<div class="tactic-count">{count} techniques</div>'
        f'</div>'
    )
    bucket = matrix.get(tact, {})
    if not bucket:
        columns.append(f'<div class="col blank" data-idx="{idx}">&mdash;</div>')
        continue

    inner = []
    for parent_id in sorted(bucket):
        info = bucket[parent_id]
        p_info = info["parent"] or (parent_id, "", False)
        subs   = info["subs"]
        p_id, p_name, p_filled = p_info
        p_cls  = "filled" if p_filled else ""
        p_url  = f"https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{TECH_PATH}/{p_id}"
        p_tip  = html.escape(read_snippet(TECH_DIR / p_id))
        p_title= f' title="{p_tip}"' if p_tip else ""
        name_html = f'<span class="t-name">{esc(p_name)}</span>' if p_name else ''

        if subs:
            sub_html = ""
            for s_id, s_name, s_filled in sorted(subs, key=lambda x: x[0]):
                s_cls  = "filled" if s_filled else ""
                s_url  = f"https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{TECH_PATH}/{s_id}"
                s_tip  = html.escape(read_snippet(TECH_DIR / s_id))
                s_title= f' title="{s_tip}"' if s_tip else ""
                s_name_html = f'<span class="t-name">{esc(s_name)}</span>' if s_name else ''
                s_short = s_id.split(".", 1)[1] if "." in s_id else s_id
                sub_html += (
                    f'<a class="sub {s_cls}"{s_title} href="{s_url}" target="_blank">'
                    f'<span class="t-id">.{esc(s_short)}</span>'
                    f'{s_name_html}</a>'
                )
            inner.append(
                f'<details class="technique {p_cls}"{p_title}>'
                f'<summary>'
                f'<a class="t-link" href="{p_url}" target="_blank">'
                f'<span class="t-id">{esc(p_id)}</span>{name_html}</a>'
                f'<span class="sub-count">{len(subs)}</span>'
                f'</summary>'
                f'<div class="subs">{sub_html}</div>'
                f'</details>'
            )
        else:
            inner.append(
                f'<a class="technique {p_cls}"{p_title} href="{p_url}" target="_blank">'
                f'<span class="t-id">{esc(p_id)}</span>{name_html}</a>'
            )
    columns.append(f'<div class="col" data-idx="{idx}">' + "".join(inner) + '</div>')

if "Unmapped" in matrix and matrix["Unmapped"]:
    count = tactic_parent_count("Unmapped")
    headers.insert(0,
        '<div class="tactic unmapped-h" data-idx="-1">'
        '<div class="tactic-name">Unmapped</div>'
        f'<div class="tactic-count">{count} techniques</div>'
        '</div>')
    columns.insert(0, columns.pop())

num_cols = len(headers)

total_parents = sum(tactic_parent_count(t) for t in TACTICS)
total_filled  = sum(1 for t in TACTICS for p in matrix.get(t, {}).values()
                    if p["parent"] and p["parent"][2])
pct = round(100 * total_filled / total_parents) if total_parents else 0

# ── HTML document ────────────────────────────────────────────────────────────
HTML = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Threat Hunt Matrix</title>
<style>
/* ── tokens ──────────────────────────────────────────────────────────────── */
:root {{
  --bg:          #0f1620;
  --surface:     #17202c;
  --surface-2:   #1e2833;
  --border:      #2a3644;
  --text:        #e6ecf2;
  --text-dim:    #8a97a8;
  --tactic-bg:   #1b2736;
  --tactic-fg:   #e6ecf2;
  --accent:      #e87722;
  --coverage:    #2fbf71;
  --chip-bg:     #243142;
  --chip-fg:     #a9b4c2;
  --unmapped:    #7a1f1f;
  --input-bg:    #17202c;
  --input-border:#33425a;
  --focus-dim:   .18;
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               "Helvetica Neue", Arial, sans-serif;
}}
body.light {{
  --bg:          #f6f6f6;
  --surface:     #ffffff;
  --surface-2:   #ffffff;
  --border:      #dfe3e8;
  --text:        #23394a;
  --text-dim:    #5b6a7a;
  --tactic-bg:   #23394a;
  --tactic-fg:   #ffffff;
  --accent:      #c75f11;
  --coverage:    #17905a;
  --chip-bg:     #eef1f5;
  --chip-fg:     #4a5a6c;
  --unmapped:    #a02020;
  --input-bg:    #ffffff;
  --input-border:#cfd6de;
}}

/* ── base ────────────────────────────────────────────────────────────────── */
*{{box-sizing:border-box}}
html,body{{height:100%}}
body{{
  margin:0; background:var(--bg); color:var(--text);
  font-family:var(--font-sans); font-size:14px; line-height:1.35;
  -webkit-font-smoothing:antialiased;
}}

/* ── header ──────────────────────────────────────────────────────────────── */
header{{
  position:sticky; top:0; z-index:999;
  display:flex; align-items:center; gap:.75rem;
  padding:.6rem 1rem;
  background:var(--surface); border-bottom:1px solid var(--border);
}}
.brand{{
  display:flex; align-items:baseline; gap:.5rem; margin-right:auto;
  font-weight:600; font-size:1.05rem; letter-spacing:.2px;
}}
.brand .accent{{color:var(--accent)}}
.stats{{color:var(--text-dim); font-size:.82rem; margin-right:.5rem}}
.stats b{{color:var(--text)}}
#search{{
  padding:.4rem .65rem; border-radius:4px;
  border:1px solid var(--input-border);
  background:var(--input-bg); color:var(--text);
  min-width:14rem; font-family:inherit; font-size:.85rem;
}}
#search:focus{{outline:2px solid var(--accent); outline-offset:-1px}}
#modeToggle{{
  cursor:pointer; font-size:1rem; background:none; color:var(--text);
  border:1px solid var(--input-border); border-radius:4px;
  padding:.3rem .55rem;
}}
#modeToggle:hover{{border-color:var(--accent)}}
.nav-link{{
  color:var(--text-dim); text-decoration:none; font-size:.82rem;
  padding:.3rem .55rem; border:1px solid var(--input-border); border-radius:4px;
}}
.nav-link:hover{{color:var(--accent); border-color:var(--accent)}}

/* ── grid ─────────────────────────────────────────────────────────────────── */
.scroll-x{{overflow-x:auto}}
.grid{{
  display:grid;
  grid-template-columns:repeat({num_cols}, 11rem);
  gap:1px;
  padding:1rem;
  background:var(--border);
  min-width:min-content;
}}

/* ── tactic header ──────────────────────────────────────────────────────── */
.tactic{{
  background:var(--tactic-bg); color:var(--tactic-fg);
  padding:.55rem .5rem .5rem; text-align:center; cursor:pointer;
  border-bottom:2px solid transparent; user-select:none;
}}
.tactic:hover{{border-bottom-color:var(--accent)}}
.tactic-name{{font-size:.82rem; font-weight:600; letter-spacing:.02em}}
.tactic-count{{
  margin-top:.15rem; font-size:.7rem; opacity:.75;
  font-variant-numeric:tabular-nums;
}}
.tactic.active{{border-bottom-color:var(--accent)}}
.unmapped-h{{background:var(--unmapped); color:#fff}}

/* ── column ──────────────────────────────────────────────────────────────── */
.col{{
  display:flex; flex-direction:column; gap:1px;
  background:var(--border); min-width:0;
}}
body.focus .col.dim{{opacity:var(--focus-dim)}}
body.focus .col.dim .technique{{pointer-events:none}}
.col.blank{{
  background:var(--surface); color:var(--text-dim);
  display:flex; align-items:center; justify-content:center;
  padding:.5rem; font-size:.8rem;
}}

/* ── technique card ──────────────────────────────────────────────────────── */
.technique{{
  display:block; background:var(--surface); color:inherit;
  text-decoration:none; padding:.4rem .55rem .45rem;
  font-size:.78rem; line-height:1.25;
  border-left:3px solid transparent;
  transition:background .15s, border-color .15s;
}}
.technique:hover{{background:var(--surface-2)}}
.technique.filled{{border-left-color:var(--coverage)}}
.t-id{{
  display:inline-block; color:var(--chip-fg);
  font-family: "SF Mono", "Menlo", "Consolas", monospace;
  font-size:.72rem; font-weight:500;
  padding:.05rem .3rem; border-radius:3px;
  background:var(--chip-bg);
  margin-right:.35rem; vertical-align:middle;
}}
.t-name{{color:var(--text); font-weight:500}}

/* ── details (parent with sub-techniques) ───────────────────────────────── */
details.technique{{padding:0}}
details.technique > summary{{
  list-style:none; cursor:pointer;
  padding:.4rem .55rem .45rem; display:flex; align-items:center; gap:.4rem;
}}
details.technique > summary::-webkit-details-marker{{display:none}}
.t-link{{color:inherit; text-decoration:none; flex:1; min-width:0;
        overflow:hidden; text-overflow:ellipsis}}
.t-link:hover .t-name{{text-decoration:underline}}
.sub-count{{
  flex:none; font-size:.68rem; color:var(--text-dim);
  background:var(--chip-bg); padding:.05rem .35rem; border-radius:3px;
  font-variant-numeric:tabular-nums;
}}
details[open] > summary .sub-count::before{{content:"\u25BE "; color:var(--accent)}}
details:not([open]) > summary .sub-count::before{{content:"\u25B8 "; color:var(--text-dim)}}
.subs{{
  background:var(--bg); border-top:1px solid var(--border);
  display:flex; flex-direction:column;
}}
.sub{{
  display:block; padding:.3rem .55rem .35rem 1.1rem;
  color:var(--text); text-decoration:none;
  font-size:.74rem; line-height:1.25;
  border-left:3px solid transparent;
  border-top:1px solid var(--border);
}}
.sub:first-child{{border-top:none}}
.sub:hover{{background:var(--surface-2)}}
.sub.filled{{border-left-color:var(--coverage)}}
.sub .t-id{{font-size:.68rem}}

/* ── search highlights ──────────────────────────────────────────────────── */
.search-active .technique:not(.match),
.search-active .sub:not(.match){{opacity:.2}}

@media (max-width:600px){{
  .brand{{font-size:.95rem}}
  .stats{{display:none}}
  #search{{min-width:8rem}}
}}
</style>
</head><body>
<header>
  <div class="brand">Threat Hunt <span class="accent">Matrix</span></div>
  <div class="stats"><b>{total_filled}</b> / {total_parents} techniques covered &middot; <b>{pct}%</b></div>
  <a class="nav-link" href="./metrics.html">Metrics &rarr;</a>
  <input id="search" type="search" placeholder="Search techniques&hellip;" autocomplete="off">
  <button id="modeToggle" title="Toggle light/dark (Alt+D)" aria-label="Toggle theme">\u263C</button>
</header>

<div class="scroll-x">
  <div class="grid" id="matrix">{''.join(headers + columns)}</div>
</div>

<script>
(() => {{
  const q       = document.getElementById('search');
  const details = [...document.querySelectorAll('details.technique')];
  const allTech = [...document.querySelectorAll('.technique, .sub')];
  const tactics = [...document.querySelectorAll('.tactic')];
  const cols    = [...document.querySelectorAll('.col')];
  const body    = document.body;
  const toggle  = document.getElementById('modeToggle');

  let focused = null;
  function setFocus(idx) {{
    focused = idx;
    body.classList.toggle('focus', idx !== null);
    cols.forEach(c => c.classList.toggle('dim',
      idx !== null && c.dataset.idx !== String(idx)));
    tactics.forEach(t => t.classList.toggle('active',
      idx !== null && t.dataset.idx === String(idx)));
  }}
  tactics.forEach(t => t.addEventListener('click', () => {{
    const idx = t.dataset.idx;
    setFocus(focused === idx ? null : idx);
  }}));
  document.addEventListener('keydown', e => {{
    if (e.key === 'Escape') {{ setFocus(null); q.value=''; q.dispatchEvent(new Event('input')); }}
    if (e.key.toLowerCase() === 'd' && e.altKey) toggle.click();
    if (e.key === '/' && document.activeElement !== q) {{ e.preventDefault(); q.focus(); }}
  }});

  q.addEventListener('input', e => {{
    const val = e.target.value.toLowerCase().trim();
    if (!val) {{
      body.classList.remove('search-active');
      allTech.forEach(el => el.classList.remove('match'));
      details.forEach(d => d.open = false);
      return;
    }}
    body.classList.add('search-active');
    allTech.forEach(el => {{
      const hit = el.textContent.toLowerCase().includes(val);
      el.classList.toggle('match', hit);
    }});
    details.forEach(d => {{
      const parentHit = d.querySelector('summary').textContent.toLowerCase().includes(val);
      const subHit = [...d.querySelectorAll('.sub')].some(
        s => s.textContent.toLowerCase().includes(val));
      d.open = parentHit || subHit;
      if (parentHit) d.classList.add('match');
    }});
  }});

  function applyMode(light) {{
    body.classList.toggle('light', light);
    toggle.textContent = light ? '\u263D' : '\u263C';
  }}
  applyMode(localStorage.getItem('prefersLight') === 'true');
  toggle.addEventListener('click', () => {{
    const toLight = !body.classList.contains('light');
    applyMode(toLight);
    localStorage.setItem('prefersLight', toLight);
  }});
}})();
</script>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"{OUTPUT} rebuilt ({total_filled}/{total_parents} covered, {pct}%)")
