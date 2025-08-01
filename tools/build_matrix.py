#!/usr/bin/env python3
"""
MITRE ATT&CK matrix generator – Navigator-style layout
──────────────────────────────────────────────────────
• Blue column headers on white canvas
• Side-scroll layout (can toggle “wrap”)
• Global “show / hide sub-techniques” button
• Live search with highlight, auto-expand & deep-link
• Copy-ID clipboard icon per technique
"""

import html, json, pathlib, subprocess, sys
from collections import defaultdict
from datetime import datetime

# ── repo specifics ───────────────────────────────────────────────────────────
OWNER, REPO, BRANCH, TECH_PATH = (
    "Nvafiades1", "threat-hunt-library", "main", "techniques"
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

# ── helpers ──────────────────────────────────────────────────────────────────
def esc(s: str) -> str:
    return html.escape(s.replace("_", " "))

def has_content(path: pathlib.Path) -> bool:
    if path.is_file():
        return True
    return any(f.is_file() and f.name.lower() not in {"readme.md", ".ds_store"} for f in path.iterdir())

def last_date(path: pathlib.Path) -> str:
    try:
        ts = subprocess.check_output(
            ["git", "log", "-1", "--format=%cs", "--", str(path)],
            cwd=ROOT, text=True
        ).strip()
        datetime.strptime(ts, "%Y-%m-%d")
        return ts
    except Exception:
        return ""

# ── load mapping ────────────────────────────────────────────────────────────
try:
    raw = json.loads(MAP_FILE.read_text())
except Exception as e:
    print(f"Cannot read {MAP_FILE}: {e}", file=sys.stderr)
    raw = {}

mapping = ({o["technique_id"]: o["tactic"].title().replace("-", " ") for o in raw}
           if isinstance(raw, list)
           else {k: v.title().replace("-", " ") for k, v in raw.items()})

# ── scan technique folders ───────────────────────────────────────────────────
tech_items = sorted([p for p in TECH_DIR.iterdir() if p.name.startswith("T")],
                    key=lambda p: p.name.lower())

# tactic → parent_id → (parent_info, [subs])
matrix: dict[str, dict[str, tuple[tuple[str,bool,str]|None, list[tuple[str,bool,str]]]]] = {
    t: defaultdict(lambda:[None,[]]) for t in TACTICS
}

for item in tech_items:
    tech   = item.name
    tid    = tech.split("_")[0]
    parent = tid.split(".")[0]
    tactic = mapping.get(parent, "Unmapped")
    info   = (tech, has_content(item), last_date(item))

    bucket = matrix.setdefault(tactic, defaultdict(lambda:[None,[]]))
    (bucket[parent][1] if "." in tid else bucket[parent].__setitem__)(0, info) if "." not in tid else bucket[parent][1].append(info)

# ── build HTML ───────────────────────────────────────────────────────────────
headers, cols = [], []
for tact in TACTICS:
    headers.append(f'<div class="colHead">{esc(tact)}</div>')
    bucket = matrix.get(tact,{})
    if not bucket:
        cols.append('<div class="colBody"><div class="blank">—</div></div>')
        continue

    body=[]
    for pid in sorted(bucket):
        pinfo, subs = bucket[pid]
        if pinfo is None: pinfo = (pid,False,"")
        pname, pf, pdate = pinfo
        purl = f"https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{TECH_PATH}/{pname}"
        cls  = "filled" if pf else "empty"
        badge= f'<span class="date">{pdate}</span>' if pdate else ""
        if subs:
            sub_html="".join(
                f'<div class="sub hide"><a href="https://github.com/{OWNER}/{REPO}/tree/{BRANCH}/{TECH_PATH}/{s}" target="_blank">{esc(s)}</a></div>'
                for s,_,_ in sorted(subs,key=lambda x:x[0])
            )
            body.append(
              f'<details class="tech {cls}" data-id="{pname}"><summary>'
              f'<a href="{purl}" target="_blank">{esc(pname)}</a>{badge}</summary>{sub_html}</details>')
        else:
            body.append(
              f'<div class="tech {cls}" data-id="{pname}"><a href="{purl}" target="_blank">{esc(pname)}</a>{badge}</div>')
    cols.append('<div class="colBody">'+"".join(body)+'</div>')

HTML=f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>MITRE ATT&CK Matrix</title>
<style>
:root{{--bg:#f7f9fc;--grey:#d1d5da;--blue:#1f448c;--clip:#444}}
*{{box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
body{{margin:0;background:var(--bg);}}
/* toolbar */
.toolbar{{position:sticky;top:0;z-index:999;background:#fff;border-bottom:1px solid var(--grey);
          display:flex;align-items:center;padding:.4rem .8rem;gap:.5rem}}
h1{{margin:0 auto;font-size:1.25rem;color:var(--blue);}}
button{{padding:.35rem .7rem;border:1px solid var(--grey);background:#fff;border-radius:4px;
        cursor:pointer;font-size:.8rem}}
button.active{{background:#e6f0ff;border-color:#7aa7ff}}
/* grid */
.matrixWrap.side{{overflow-x:auto;white-space:nowrap}}
.matrix{{display:inline-grid;grid-auto-flow:column;grid-gap:2px}}
.colHead{{background:#fff;border:1px solid var(--grey);padding:.6rem .8rem;
          font-weight:700;color:var(--blue);text-align:center}}
.colBody{{display:flex;flex-direction:column}}
.tech,.sub{{border:1px solid var(--grey);background:#fff;position:relative}}
.tech summary,.tech>a{{display:flex;align-items:center;gap:.25rem;
                      padding:.45rem .55rem;margin:0;cursor:pointer;list-style:none}}
.tech summary::-webkit-details-marker{{display:none}}
.tech summary:after{{content:'▸';margin-left:auto;color:var(--blue)}}
details[open] summary:after{{content:'▾'}}
.sub a{{display:block;padding:.4rem .9rem .4rem 1.7rem}}
.hide{{display:none}}
.filled{{border-left:4px solid #2ecc71}}
.date{{margin-left:auto;font-size:.7rem;color:#586069}}
/* copy icon */
.clip{{position:absolute;right:6px;top:6px;font-size:.8rem;opacity:0;cursor:pointer}}
.tech:hover .clip,.sub:hover .clip{{opacity:0.7}}
.clip.done{{color:#2ecc71;opacity:1}}
/* highlight */
mark{{background:#ffe066}}
.blank{{padding:1rem .5rem;text-align:center;color:#666}}
@media(max-width:800px){{button{{font-size:.7rem}}}}
</style></head><body>

<div class="toolbar">
  <button id="layoutBtn" data-state="side">layout: side ▾</button>
  <button id="showBtn">show sub-techniques</button>
  <button id="hideBtn" style="display:none">hide sub-techniques</button>
  <input id="search" placeholder="search…">
  <h1>MITRE&nbsp;ATT&CK&nbsp;Matrix</h1>
</div>

<div class="matrixWrap side" id="wrap">
  <div class="matrix">{''.join(headers+cols)}</div>
</div>

<script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const wrap=$("#wrap"), layoutBtn=$("#layoutBtn"), showBtn=$("#showBtn"), hideBtn=$("#hideBtn");
const subs=$$('.sub'), parents=$$('details.tech'), pills=$$('.tech,.sub');

function copyID(el){navigator.clipboard.writeText(el.parentElement.dataset.id);
  el.textContent='✓';el.classList.add('done');setTimeout(()=>{el.textContent='📋';el.classList.remove('done')},800)}
pills.forEach(p=>{p.dataset.id||(p.dataset.id=p.textContent.trim());
  const c=document.createElement('span');c.textContent='📋';c.className='clip';c.onclick=e=>{e.stopPropagation();copyID(c)};
  (p.querySelector('summary')||p).append(c)});

layoutBtn.onclick=()=>{wrap.classList.toggle('side');layoutBtn.textContent=wrap.classList.contains('side')?'layout: side ▾':'layout: wrap ▾'}
showBtn.onclick=()=>{subs.forEach(s=>s.classList.remove('hide'));parents.forEach(d=>d.open=true);showBtn.style.display='none';hideBtn.style.display='inline-block'}
hideBtn.onclick=()=>{subs.forEach(s=>s.classList.add('hide'));parents.forEach(d=>d.open=false);hideBtn.style.display='none';showBtn.style.display='inline-block'}

const search=$("#search");
let marks=[];
function clearMarks(){marks.forEach(m=>m.replaceWith(m.textContent));marks=[]}
search.oninput=e=>{
 const q=e.target.value.toLowerCase().trim();clearMarks();
 pills.forEach(p=>p.style.opacity='1');parents.forEach(d=>d.open=false);
 if(!q)return;
 pills.forEach(p=>{
   const t=p.textContent.toLowerCase();
   if(!t.includes(q)){p.style.opacity='0.2';return;}
   // highlight
   p.innerHTML=p.innerHTML.replace(new RegExp(q,'gi'),m=>`<mark>${m}</mark>`);marks.push(...p.querySelectorAll('mark'));
   const par=p.closest('details.tech');if(par)par.open=true;
 });
};

// deep-link
if(location.hash){
  const id=location.hash.slice(1);
  const target=document.querySelector(`[data-id="${id}"]`);
  if(target){const par=target.closest('details.tech');if(par)par.open=true;
    setTimeout(()=>target.scrollIntoView({behavior:'smooth',block:'center',inline:'center'}),200);
    target.style.background='#ffe066';setTimeout(()=>target.style.background='',1500);}
}
</script>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML,encoding="utf-8")
print(f"✅  {OUTPUT} rebuilt → {OUTPUT}")
