#!/usr/bin/env python3
"""
MITRE ATT&CK static matrix ─ Navigator-style
Features
• Side-scroll grid (toggleable wrap)
• Global “show / hide sub-techniques” buttons
• Live search with highlight & auto-expand parents
• Copy-ID clipboard icon
• Deep-link (#T1059.003) expansion + flash
"""

import html, json, pathlib, subprocess, sys
from collections import defaultdict
from datetime import datetime

# ─── repository paths ────────────────────────────────────────────────────────
OWNER, REPO, BRANCH, TECH_DIR = (
    "Nvafiades1",          # change if your username/org differs
    "threat-hunt-library",
    "main",
    "techniques",          # folder that holds Txxxx directories
)

ROOT      = pathlib.Path(__file__).resolve().parents[1]
TECH_PATH = ROOT / TECH_DIR
MAP_FILE  = ROOT / "mitre_ttp_mapping.json"
DOCS_DIR  = ROOT / "docs"
OUTPUT    = DOCS_DIR / "index.html"

TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command And Control",
    "Exfiltration", "Impact",
]

# ─── helpers ─────────────────────────────────────────────────────────────────
def esc(txt: str) -> str:
    return html.escape(txt.replace("_", " "))

def has_content(p: pathlib.Path) -> bool:
    if p.is_file():
        return True
    return any(f.is_file() and f.name.lower() not in {"readme.md", ".ds_store"}
               for f in p.iterdir())

def git_date(p: pathlib.Path) -> str:
    """last commit date (YYYY-MM-DD) touching this path; blank if git not there"""
    try:
        ts = subprocess.check_output(
            ["git", "log", "-1", "--format=%cs", "--", str(p)],
            cwd=ROOT, text=True
        ).strip()
        datetime.strptime(ts, "%Y-%m-%d")  # validate
        return ts
    except Exception:
        return ""

# ─── mapping file ───────────────────────────────────────────────────────────
try:
    raw = json.loads(MAP_FILE.read_text())
except Exception as e:
    print(f"⚠️  cannot read {MAP_FILE}: {e}", file=sys.stderr)
    raw = []

mapping = {o["technique_id"]: o["tactic"].title().replace("-", " ")
           for o in raw} if isinstance(raw, list) else {
           k: v.title().replace("-", " ") for k, v in raw.items()}

# ─── scan technique folders ─────────────────────────────────────────────────
if not TECH_PATH.exists():
    sys.exit(f"❌  '{TECH_PATH}' not found – update TECH_DIR variable?")

folders = sorted([p for p in TECH_PATH.iterdir() if p.name.startswith("T")],
                 key=lambda p: p.name.lower())

# tactic ➜ parent_id ➜ (parent_tuple, [sub_tuples])
matrix: dict[str, dict[str, tuple[tuple, list]]] = {
    t: defaultdict(lambda: [None, []]) for t in TACTICS
}

for item in folders:
    name   = item.name                    # e.g. T1003.001
    tid    = name.split("_")[0]
    parent = tid.split(".")[0]
    tactic = mapping.get(parent, "Unmapped")
    info   = (name, has_content(item), git_date(item))  # (id, filled?, date)

    bucket = matrix.setdefault(tactic, defaultdict(lambda: [None, []]))
    if "." in tid:
        bucket[parent][1].append(info)            # sub-technique
    else:
        bucket[parent][0] = info                  # parent

# ─── build HTML grid ─────────────────────────────────────────────────────────
heads, cols = [], []
for tact in TACTICS:
    heads.append(f'<div class="colHead">{esc(tact)}</div>')
    bucket = matrix.get(tact, {})
    body   = []
    for pid in sorted(bucket):
        pinfo, subs = bucket[pid]
        if pinfo is None:                         # folder missing
            pinfo = (pid, False, "")
        pid_txt, filled, date = pinfo
        cls  = "filled" if filled else "empty"
        url  = f"https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{TECH_DIR}/{pid_txt}"
        date_badge = f'<span class="date">{date}</span>' if date else ""
        if subs:
            sub_html = "".join(
                f'<div class="sub hide"><a href="https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{TECH_DIR}/{s}" '
                f'target="_blank">{esc(s)}</a></div>'
                for s, _, _ in sorted(subs, key=lambda x: x[0])
            )
            body.append(
                f'<details class="tech {cls}" data-id="{pid_txt}">'
                f'<summary><a href="{url}" target="_blank">{esc(pid_txt)}</a>{date_badge}</summary>'
                f'{sub_html}</details>')
        else:
            body.append(
                f'<div class="tech {cls}" data-id="{pid_txt}">'
                f'<a href="{url}" target="_blank">{esc(pid_txt)}</a>{date_badge}</div>')
    cols.append('<div class="colBody">' + "".join(body) + "</div>")

# ─── HTML template ──────────────────────────────────────────────────────────
HTML = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>MITRE ATT&CK Matrix</title>
<style>
:root{{--grey:#d0d7de;--blue:#1565c0;--bg:#f7f9fc}}
*{{box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
body{{margin:0;background:var(--bg)}}
/* toolbar */
.toolbar{{position:sticky;top:0;z-index:999;background:#fff;border-bottom:1px solid var(--grey);
         display:flex;align-items:center;gap:.6rem;padding:.45rem .8rem}}
h1{{margin:0 auto;font-size:1.2rem;color:var(--blue)}}
button{{padding:.3rem .65rem;border:1px solid var(--grey);border-radius:4px;background:#fff;
        cursor:pointer;font-size:.8rem}}
button.active{{background:#e8f0fe;border-color:#7aa7ff}}
input[type=search]{{padding:.3rem .6rem;border:1px solid var(--grey);border-radius:4px}}
/* grid */
.matrixWrap.side{{overflow-x:auto;white-space:nowrap}}
.matrix{{display:inline-grid;grid-auto-flow:column;grid-gap:2px}}
.colHead{{background:#fff;border:1px solid var(--grey);padding:.65rem .85rem;font-weight:700;
         color:var(--blue);text-align:center}}
.colBody{{display:flex;flex-direction:column}}
.tech,.sub{{border:1px solid var(--grey);background:#fff;position:relative}}
.tech summary,.tech>a{{display:flex;align-items:center;gap:.25rem;padding:.42rem .55rem;margin:0;cursor:pointer}}
.tech summary::-webkit-details-marker{{display:none}}
.tech summary:after{{content:'▸';margin-left:auto;color:var(--blue)}}
details[open] summary:after{{content:'▾'}}
.sub a{{display:block;padding:.38rem .9rem .38rem 1.75rem}}
.hide{{display:none}}
.filled{{border-left:4px solid #2e7d32}}
.date{{margin-left:auto;font-size:.7rem;color:#697085}}
/* clipboard */
.clip{{position:absolute;right:6px;top:6px;font-size:.8rem;opacity:0;cursor:pointer}}
.tech:hover .clip,.sub:hover .clip{{opacity:.7}}
.clip.done{{color:#2ecc71;opacity:1}}
mark{{background:#ffe066}}
.blank{{padding:1rem;text-align:center;color:#666}}
@media(max-width:800px){{button{{font-size:.7rem}}}}
</style></head><body>

<div class="toolbar">
  <button id="layoutBtn">layout: side ▾</button>
  <button id="showBtn">show sub-techniques</button>
  <button id="hideBtn" style="display:none">hide sub-techniques</button>
  <input id="search" placeholder="search…">
  <h1>MITRE&nbsp;ATT&CK&nbsp;Matrix</h1>
</div>

<div id="wrap" class="matrixWrap side">
  <div class="matrix">{''.join(heads+cols)}</div>
</div>

<script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const wrap=$("#wrap"),layoutBtn=$("#layoutBtn"),showBtn=$("#showBtn"),hideBtn=$("#hideBtn");
const subs=$$('.sub'),parents=$$('details.tech'),pills=$$('.tech,.sub');

/* layout toggle */
layoutBtn.onclick=()=>{wrap.classList.toggle('side');
  layoutBtn.textContent=wrap.classList.contains('side')?'layout: side ▾':'layout: wrap ▾'}

/* show / hide subs */
showBtn.onclick=()=>{subs.forEach(s=>s.classList.remove('hide'));parents.forEach(d=>d.open=true);
  showBtn.style.display='none';hideBtn.style.display='inline-block'}
hideBtn.onclick=()=>{subs.forEach(s=>s.classList.add('hide'));parents.forEach(d=>d.open=false);
  hideBtn.style.display='none';showBtn.style.display='inline-block'}

/* clipboard icons */
pills.forEach(p=>{
  p.dataset.id=p.dataset.id||p.textContent.trim();
  const c=document.createElement('span');c.textContent='📋';c.className='clip';
  c.onclick=e=>{e.stopPropagation();
    navigator.clipboard.writeText(p.dataset.id);
    c.textContent='✓';c.classList.add('done');
    setTimeout(()=>{c.textContent='📋';c.classList.remove('done')},900)};
  (p.querySelector('summary')||p).append(c);
});

/* live search */
const search=$("#search");let marks=[];
function clear(){marks.forEach(m=>m.replaceWith(m.textContent));marks=[]}
search.oninput=e=>{
  const q=e.target.value.toLowerCase().trim();clear();
  pills.forEach(p=>p.style.opacity='1');parents.forEach(d=>d.open=false);
  if(!q)return;
  pills.forEach(p=>{
    const txt=p.textContent.toLowerCase();
    if(!txt.includes(q)){p.style.opacity='0.2';return;}
    p.innerHTML=p.innerHTML.replace(new RegExp(q,'gi'),m=>`<mark>${m}</mark>`);marks.push(...p.querySelectorAll('mark'));
    const par=p.closest('details.tech');if(par)par.open=true;
  });
};

/* deep link (#T####) */
if(location.hash){
  const id=location.hash.slice(1);const tgt=$(`[data-id="${id}"]`);
  if(tgt){const par=tgt.closest('details.tech');if(par)par.open=true;
    setTimeout(()=>tgt.scrollIntoView({behavior:'smooth',block:'center',inline:'center'}),200);
    tgt.style.background='#ffe066';setTimeout(()=>tgt.style.background='',1600);}
}
</script>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"✅  matrix rebuilt → {OUTPUT}")
