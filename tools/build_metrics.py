#!/usr/bin/env python3
"""
Generate docs/metrics.html – Threat Hunt Library metrics dashboard.

Reads every hunt markdown file under techniques/ (any file that isn't the
per-technique README.md), parses its template fields, pairs it with the
git-added timestamp, and emits a Chart.js-powered dashboard tailored for
executive audiences.

Charts produced
───────────────
• KPI tiles: total hunts, techniques covered, unique threat actors, coverage %
• Hunts over time (monthly + cumulative)
• Coverage by tactic (horizontal bar)
• Top threat actors (horizontal bar)
• Severity distribution (donut)
• Confidence distribution (donut)
• Top techniques by hunt count (horizontal bar)
• Hunt platforms (horizontal bar)
"""

from __future__ import annotations

import html, json, pathlib, re, subprocess, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

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

ROOT     = pathlib.Path(__file__).resolve().parents[1]
TECH_DIR = ROOT / TECH_PATH
MAP_FILE = ROOT / "mitre_ttp_mapping.json"
DOCS_DIR = ROOT / "docs"
OUTPUT   = DOCS_DIR / "metrics.html"

# ── load tactic mapping ──────────────────────────────────────────────────────
try:
    raw = json.loads(MAP_FILE.read_text())
except Exception as e:
    print(f"Cannot read {MAP_FILE}: {e}", file=sys.stderr)
    raw = {}

tactic_for = (
    {o["technique_id"]: o["tactic"].title().replace("-", " ") for o in raw}
    if isinstance(raw, list)
    else {k: v.title().replace("-", " ") for k, v in raw.items()}
)

def tactic_of(parent_id: str) -> str:
    t = tactic_for.get(parent_id)
    if t:
        return t
    return "Impact" if parent_id in IMPACT_IDS else "Unmapped"

# ── hunt parser ──────────────────────────────────────────────────────────────
_section_re = re.compile(r"^###\s+(.+?)\s*$")
# Bold-meta lines (**Technique:**, **Status:**, **Details:**) — legacy wrapper format
_meta_re = re.compile(r"^\*\*[^*:]+:\*\*")
# Horizontal rule lines — used as section dividers in the current archive format
_hr_re = re.compile(r"^[-=_*]{3,}\s*$")
# Checkbox rows from issue-form checkboxes blocks
_checkbox_re = re.compile(r"^\s*-\s*\[(x|X| )\]\s*(.+?)\s*$")
_none_values = {"", "_no response_", "n/a", "none", "tbd"}

def parse_hunt(md_text: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in md_text.splitlines():
        m = _section_re.match(line)
        if m:
            current = m.group(1).strip()
            sections.setdefault(current, [])
            continue
        if _meta_re.match(line) or _hr_re.match(line):
            # Sentinel / divider; stop gathering until the next ### header.
            current = None
            continue
        if current is not None:
            sections[current].append(line)
    out: dict[str, str] = {}
    for k, lines in sections.items():
        v = "\n".join(lines).strip()
        if v.lower() in _none_values:
            continue
        out[k] = v
    return out

def parse_checked(text: str) -> list[str]:
    """Return checked items from a GitHub issue-form checkboxes block body."""
    return [m.group(2).strip() for line in text.splitlines()
            if (m := _checkbox_re.match(line)) and m.group(1).lower() == "x"]

def normalize_level(val: str) -> str | None:
    """Map free-text severity/confidence to canonical buckets."""
    if not val:
        return None
    v = val.strip().lower()
    if "%" in v:
        try:
            n = int(re.search(r"\d+", v).group(0))
            if n >= 85: return "High"
            if n >= 60: return "Medium"
            return "Low"
        except Exception:
            return None
    for canon in ("critical", "high", "medium", "low", "informational"):
        if canon in v:
            return canon.title()
    return None

def extract_techniques_from_text(t: str) -> list[str]:
    return [m.group(0).upper() for m in re.finditer(r"\bT\d{4}(?:\.\d{3})?\b", t or "", re.I)]

# ── scan all hunt files ──────────────────────────────────────────────────────
if not TECH_DIR.exists():
    sys.exit(f"{TECH_DIR} not found")

hunt_files: list[pathlib.Path] = []
for sub in sorted(TECH_DIR.iterdir()):
    if not sub.is_dir():
        continue
    for f in sub.iterdir():
        if f.is_file() and f.suffix.lower() == ".md" and f.name.lower() != "readme.md":
            hunt_files.append(f)

# Pull git-added timestamps for all files in one shot (faster than per-file)
def git_added_dates(paths: list[pathlib.Path]) -> dict[pathlib.Path, datetime]:
    result: dict[pathlib.Path, datetime] = {}
    if not paths:
        return result
    try:
        # Walk the full log once; last commit date per file is the add-date.
        out = subprocess.check_output(
            ["git", "log", "--diff-filter=A", "--name-only",
             "--format=__COMMIT__%aI", "--reverse", "--", str(TECH_DIR)],
            cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
        )
    except Exception:
        return result
    current_ts: datetime | None = None
    want = {str(p.relative_to(ROOT)): p for p in paths}
    for line in out.splitlines():
        if line.startswith("__COMMIT__"):
            try:
                current_ts = datetime.fromisoformat(line[len("__COMMIT__"):])
            except Exception:
                current_ts = None
        elif current_ts is not None and line in want and want[line] not in result:
            result[want[line]] = current_ts
    return result

added = git_added_dates(hunt_files)

# ── parse each hunt into a record ────────────────────────────────────────────
records: list[dict] = []
for path in hunt_files:
    try:
        text = path.read_text("utf-8", "ignore")
    except Exception:
        continue
    parent_folder = path.parent.name  # T1003
    fields = parse_hunt(text)

    # Technique: folder is authoritative, fall back to body mentions
    tech_ids = [parent_folder]
    body_hits = extract_techniques_from_text(text)
    for t in body_hits:
        if t not in tech_ids:
            tech_ids.append(t)
    primary = tech_ids[0]
    parent_id = primary.split(".")[0]

    # Date: git add-date, else "Created" field, else file mtime
    dt: datetime | None = added.get(path)
    if dt is None:
        try:
            dt = datetime.fromisoformat(fields.get("Created", "").replace("Z", "+00:00"))
        except Exception:
            dt = None
    if dt is None:
        dt = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

    severity   = normalize_level(fields.get("Severity", ""))
    confidence = normalize_level(fields.get("Confidence", ""))
    fidelity   = normalize_level(fields.get("Query Fidelity", ""))
    platform   = fields.get("Hunt Platform", "").strip() or None
    actor_raw  = fields.get("Threat Actor", "").strip()
    actors     = [a.strip() for a in re.split(r"[,;/]", actor_raw) if a.strip()]

    records.append({
        "path":      str(path.relative_to(ROOT)),
        "technique": primary,
        "parent":    parent_id,
        "tactic":    tactic_of(parent_id),
        "title":     fields.get(next(iter(fields)), "") if fields else "",
        "date":      dt.date().isoformat(),
        "month":     dt.strftime("%Y-%m"),
        "severity":  severity,
        "confidence": confidence,
        "fidelity":  fidelity,
        "platform":  platform,
        "actors":    actors,
    })

# ── aggregate metrics ────────────────────────────────────────────────────────
total_hunts       = len(records)
unique_techniques = sorted({r["parent"] for r in records})
unique_actors     = sorted({a for r in records for a in r["actors"]},
                           key=str.casefold)

total_parent_universe = sum(
    1 for pid in tactic_for if "." not in pid
) or 343  # sensible default

coverage_pct = round(100 * len(unique_techniques) / total_parent_universe) if total_parent_universe else 0

# Hunts per month (chronologically sorted)
months = sorted({r["month"] for r in records})
hunts_per_month = [sum(1 for r in records if r["month"] == m) for m in months]
cumulative = []
acc = 0
for n in hunts_per_month:
    acc += n
    cumulative.append(acc)

# Tactic coverage: unique parent techniques per tactic that have ≥1 hunt
tactic_hunted_parents: dict[str, set[str]] = defaultdict(set)
for r in records:
    tactic_hunted_parents[r["tactic"]].add(r["parent"])
tactic_hunt_counts = Counter(r["tactic"] for r in records)
tactics_ordered = [t for t in (TACTICS + ["Unmapped"]) if tactic_hunt_counts.get(t, 0) > 0]

# Top threat actors
actor_counts = Counter(a for r in records for a in r["actors"]).most_common(10)

# Severity / Confidence distributions
sev_counts  = Counter(r["severity"]  for r in records if r["severity"])
conf_counts = Counter(r["confidence"] for r in records if r["confidence"])

# Top techniques
tech_counts = Counter(r["parent"] for r in records).most_common(10)

# Platforms
plat_counts = Counter(r["platform"] for r in records if r["platform"]).most_common(10)

# Freshest hunt date (for "last updated" in header)
last_hunt_date = max((r["date"] for r in records), default=None)

payload = {
    "totals": {
        "hunts":      total_hunts,
        "techniques": len(unique_techniques),
        "actors":     len(unique_actors),
        "coverage":   coverage_pct,
        "universe":   total_parent_universe,
        "last_hunt":  last_hunt_date,
    },
    "timeline": {
        "labels":     months,
        "monthly":    hunts_per_month,
        "cumulative": cumulative,
    },
    "tactics": {
        "labels": tactics_ordered,
        "hunts":  [tactic_hunt_counts.get(t, 0) for t in tactics_ordered],
        "covered":[len(tactic_hunted_parents.get(t, set())) for t in tactics_ordered],
    },
    "actors":     {"labels":[a for a,_ in actor_counts], "values":[n for _,n in actor_counts]},
    "severity":   {"labels":list(sev_counts.keys()),  "values":list(sev_counts.values())},
    "confidence": {"labels":list(conf_counts.keys()), "values":list(conf_counts.values())},
    "techniques": {"labels":[t for t,_ in tech_counts], "values":[n for _,n in tech_counts]},
    "platforms":  {"labels":[p for p,_ in plat_counts], "values":[n for _,n in plat_counts]},
}

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# ── HTML ─────────────────────────────────────────────────────────────────────
HTML = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Threat Hunt Metrics</title>
<style>
:root {{
  --bg:#0f1620; --surface:#17202c; --surface-2:#1e2833;
  --border:#2a3644; --text:#e6ecf2; --text-dim:#8a97a8;
  --accent:#e87722; --coverage:#2fbf71; --danger:#e04848; --info:#3a9cd8;
  --chip-bg:#243142; --chip-fg:#a9b4c2;
  --font-sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
}}
body.light {{
  --bg:#f6f6f6; --surface:#ffffff; --surface-2:#ffffff;
  --border:#dfe3e8; --text:#23394a; --text-dim:#5b6a7a;
  --accent:#c75f11; --coverage:#17905a; --danger:#b8302e; --info:#1c77b0;
  --chip-bg:#eef1f5; --chip-fg:#4a5a6c;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);
     font-family:var(--font-sans);font-size:14px;line-height:1.4;
     -webkit-font-smoothing:antialiased}}
header{{position:sticky;top:0;z-index:999;display:flex;align-items:center;gap:.75rem;
       padding:.6rem 1rem;background:var(--surface);border-bottom:1px solid var(--border)}}
.brand{{display:flex;align-items:baseline;gap:.5rem;margin-right:auto;font-weight:600;font-size:1.05rem}}
.brand .accent{{color:var(--accent)}}
.nav-link{{color:var(--text-dim);text-decoration:none;font-size:.82rem;
          padding:.3rem .55rem;border:1px solid var(--border);border-radius:4px}}
.nav-link:hover{{color:var(--accent);border-color:var(--accent)}}
.nav-link.active{{color:var(--text);border-color:var(--text-dim)}}
.meta{{color:var(--text-dim);font-size:.78rem;margin-right:.5rem}}
#modeToggle{{cursor:pointer;font-size:1rem;background:none;color:var(--text);
            border:1px solid var(--border);border-radius:4px;padding:.3rem .55rem}}
#modeToggle:hover{{border-color:var(--accent)}}

main{{max-width:1280px;margin:0 auto;padding:1.5rem 1rem 3rem}}
h2{{font-size:.95rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;
   color:var(--text-dim);margin:2rem 0 .75rem}}

/* ── KPI tiles ─────────────────────────────────────────────────────────── */
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:1rem}}
.kpi{{background:var(--surface);border:1px solid var(--border);border-radius:8px;
     padding:1.1rem 1.25rem;position:relative;overflow:hidden}}
.kpi::before{{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent)}}
.kpi.green::before{{background:var(--coverage)}}
.kpi.blue::before{{background:var(--info)}}
.kpi.orange::before{{background:var(--accent)}}
.kpi.red::before{{background:var(--danger)}}
.kpi-label{{font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-dim)}}
.kpi-value{{font-size:2.25rem;font-weight:700;line-height:1.1;margin-top:.35rem;
           font-variant-numeric:tabular-nums}}
.kpi-sub{{font-size:.75rem;color:var(--text-dim);margin-top:.2rem}}

/* ── chart cards ───────────────────────────────────────────────────────── */
.grid{{display:grid;grid-template-columns:repeat(12,1fr);gap:1rem}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;
       padding:1.1rem 1.25rem}}
.card h3{{margin:0 0 .75rem;font-size:.85rem;font-weight:600;letter-spacing:.03em;color:var(--text)}}
.card .sub-label{{font-size:.72rem;color:var(--text-dim);margin-bottom:.75rem}}
.card canvas{{max-width:100%}}
.span-6{{grid-column:span 6}}
.span-4{{grid-column:span 4}}
.span-8{{grid-column:span 8}}
.span-12{{grid-column:span 12}}
@media (max-width:900px) {{
  .span-6,.span-4,.span-8{{grid-column:span 12}}
}}

.empty{{padding:2rem;text-align:center;color:var(--text-dim);
       border:1px dashed var(--border);border-radius:8px;background:var(--surface)}}
.empty-title{{font-size:1rem;color:var(--text);margin-bottom:.25rem}}
</style>
</head><body>
<header>
  <div class="brand">Threat Hunt <span class="accent">Metrics</span></div>
  <span class="meta">Generated {html.escape(generated_at)}</span>
  <a class="nav-link" href="./index.html">Matrix &rarr;</a>
  <button id="modeToggle" title="Toggle light/dark">\u263C</button>
</header>

<main>
<section class="kpis">
  <div class="kpi orange">
    <div class="kpi-label">Total Hunts</div>
    <div class="kpi-value">{total_hunts:,}</div>
    <div class="kpi-sub">{"last hunt " + html.escape(last_hunt_date) if last_hunt_date else "awaiting first hunt"}</div>
  </div>
  <div class="kpi green">
    <div class="kpi-label">Techniques Covered</div>
    <div class="kpi-value">{len(unique_techniques):,}</div>
    <div class="kpi-sub">of {total_parent_universe:,} mapped techniques</div>
  </div>
  <div class="kpi blue">
    <div class="kpi-label">Threat Actors Tracked</div>
    <div class="kpi-value">{len(unique_actors):,}</div>
    <div class="kpi-sub">{"unique, referenced in hunts" if unique_actors else "none referenced yet"}</div>
  </div>
  <div class="kpi red">
    <div class="kpi-label">Coverage</div>
    <div class="kpi-value">{coverage_pct}%</div>
    <div class="kpi-sub">of MITRE ATT&amp;CK Enterprise</div>
  </div>
</section>

{"" if total_hunts else '''
<div class="empty" style="margin-top:2rem">
  <div class="empty-title">No hunts archived yet.</div>
  <div>Open a Threat Hunt issue, move it to <b>Completed</b> on the project board, and this dashboard will populate automatically.</div>
</div>
'''}

<div id="charts" style="{'display:none' if not total_hunts else ''}">
<h2>Activity</h2>
<div class="grid">
  <div class="card span-8">
    <h3>Hunts Over Time</h3>
    <div class="sub-label">Monthly volume (bars) and cumulative total (line)</div>
    <canvas id="chart-timeline" height="110"></canvas>
  </div>
  <div class="card span-4">
    <h3>Severity</h3>
    <div class="sub-label">Distribution of completed hunts</div>
    <canvas id="chart-severity" height="180"></canvas>
  </div>
</div>

<h2>Coverage</h2>
<div class="grid">
  <div class="card span-8">
    <h3>Coverage by Tactic</h3>
    <div class="sub-label">Unique techniques covered (dark) and total hunts (light) per MITRE tactic</div>
    <canvas id="chart-tactics" height="220"></canvas>
  </div>
  <div class="card span-4">
    <h3>Confidence</h3>
    <div class="sub-label">Hunter confidence in findings</div>
    <canvas id="chart-confidence" height="180"></canvas>
  </div>
</div>

<h2>Top Lists</h2>
<div class="grid">
  <div class="card span-6">
    <h3>Top Threat Actors</h3>
    <div class="sub-label">Most-referenced in completed hunts</div>
    <canvas id="chart-actors" height="200"></canvas>
  </div>
  <div class="card span-6">
    <h3>Top Techniques</h3>
    <div class="sub-label">Most-hunted MITRE techniques</div>
    <canvas id="chart-techniques" height="200"></canvas>
  </div>
  <div class="card span-12">
    <h3>Hunt Platforms</h3>
    <div class="sub-label">Tools used across hunts</div>
    <canvas id="chart-platforms" height="100"></canvas>
  </div>
</div>
</div>
</main>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<script>
const DATA = {json.dumps(payload)};

function cssVar(name) {{
  return getComputedStyle(document.body).getPropertyValue(name).trim();
}}
function applyMode(light) {{
  document.body.classList.toggle('light', light);
  document.getElementById('modeToggle').textContent = light ? '\u263D' : '\u263C';
  renderAll();
}}
applyMode(localStorage.getItem('prefersLight') === 'true');
document.getElementById('modeToggle').addEventListener('click', () => {{
  const toLight = !document.body.classList.contains('light');
  localStorage.setItem('prefersLight', toLight);
  applyMode(toLight);
}});

Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;

const charts = {{}};
function destroyAll() {{ for (const k in charts) charts[k]?.destroy(); }}

function palette() {{
  return {{
    text:     cssVar('--text'),
    dim:      cssVar('--text-dim'),
    grid:     cssVar('--border'),
    accent:   cssVar('--accent'),
    coverage: cssVar('--coverage'),
    info:     cssVar('--info'),
    danger:   cssVar('--danger'),
    sev: {{
      'Critical':     cssVar('--danger'),
      'High':         cssVar('--accent'),
      'Medium':       cssVar('--info'),
      'Low':          cssVar('--coverage'),
      'Informational':cssVar('--text-dim'),
    }},
  }};
}}

function baseOpts(p) {{
  return {{
    responsive: true,
    maintainAspectRatio: false,
    plugins: {{
      legend: {{ labels: {{ color: p.text, boxWidth: 10, font: {{ size: 11 }} }} }},
      tooltip: {{ enabled: true }},
    }},
    scales: {{}},
  }};
}}

function renderAll() {{
  destroyAll();
  if (!DATA.totals.hunts) return;
  const p = palette();

  // ── Timeline ───────────────────────────────────────────────────────────
  charts.timeline = new Chart(document.getElementById('chart-timeline'), {{
    data: {{
      labels: DATA.timeline.labels,
      datasets: [
        {{ type:'bar', label:'Hunts per month',
          data:DATA.timeline.monthly, backgroundColor:p.accent, yAxisID:'y' }},
        {{ type:'line', label:'Cumulative',
          data:DATA.timeline.cumulative, borderColor:p.coverage,
          backgroundColor:'transparent', tension:.25, pointRadius:3, yAxisID:'y1' }},
      ],
    }},
    options: {{
      ...baseOpts(p),
      scales: {{
        x:  {{ ticks:{{color:p.dim}}, grid:{{color:p.grid}} }},
        y:  {{ beginAtZero:true, ticks:{{color:p.dim, precision:0}}, grid:{{color:p.grid}} }},
        y1: {{ position:'right', beginAtZero:true, ticks:{{color:p.dim, precision:0}}, grid:{{drawOnChartArea:false}} }},
      }},
    }},
  }});

  // ── Severity donut ─────────────────────────────────────────────────────
  charts.severity = new Chart(document.getElementById('chart-severity'), {{
    type:'doughnut',
    data: {{
      labels: DATA.severity.labels,
      datasets: [{{
        data: DATA.severity.values,
        backgroundColor: DATA.severity.labels.map(l => p.sev[l] || p.info),
        borderWidth: 2, borderColor: cssVar('--surface'),
      }}],
    }},
    options: {{ ...baseOpts(p), cutout:'62%' }},
  }});

  // ── Confidence donut ───────────────────────────────────────────────────
  charts.confidence = new Chart(document.getElementById('chart-confidence'), {{
    type:'doughnut',
    data: {{
      labels: DATA.confidence.labels,
      datasets: [{{
        data: DATA.confidence.values,
        backgroundColor: DATA.confidence.labels.map(l =>
          l==='High'?p.coverage : l==='Medium'?p.info : l==='Low'?p.danger : p.dim),
        borderWidth: 2, borderColor: cssVar('--surface'),
      }}],
    }},
    options: {{ ...baseOpts(p), cutout:'62%' }},
  }});

  // ── Tactics ────────────────────────────────────────────────────────────
  charts.tactics = new Chart(document.getElementById('chart-tactics'), {{
    type:'bar',
    data: {{
      labels: DATA.tactics.labels,
      datasets: [
        {{ label:'Techniques covered', data:DATA.tactics.covered, backgroundColor:p.coverage }},
        {{ label:'Total hunts',        data:DATA.tactics.hunts,   backgroundColor:p.accent }},
      ],
    }},
    options: {{
      ...baseOpts(p),
      indexAxis:'y',
      scales: {{
        x: {{ beginAtZero:true, ticks:{{color:p.dim, precision:0}}, grid:{{color:p.grid}} }},
        y: {{ ticks:{{color:p.text}}, grid:{{display:false}} }},
      }},
    }},
  }});

  // ── Top actors ─────────────────────────────────────────────────────────
  charts.actors = new Chart(document.getElementById('chart-actors'), {{
    type:'bar',
    data: {{
      labels: DATA.actors.labels,
      datasets: [{{ data: DATA.actors.values, backgroundColor: p.info }}],
    }},
    options: {{
      ...baseOpts(p), indexAxis:'y',
      plugins:{{ ...baseOpts(p).plugins, legend:{{display:false}} }},
      scales: {{
        x: {{ beginAtZero:true, ticks:{{color:p.dim, precision:0}}, grid:{{color:p.grid}} }},
        y: {{ ticks:{{color:p.text}}, grid:{{display:false}} }},
      }},
    }},
  }});

  // ── Top techniques ─────────────────────────────────────────────────────
  charts.techniques = new Chart(document.getElementById('chart-techniques'), {{
    type:'bar',
    data: {{
      labels: DATA.techniques.labels,
      datasets: [{{ data: DATA.techniques.values, backgroundColor: p.accent }}],
    }},
    options: {{
      ...baseOpts(p), indexAxis:'y',
      plugins:{{ ...baseOpts(p).plugins, legend:{{display:false}} }},
      scales: {{
        x: {{ beginAtZero:true, ticks:{{color:p.dim, precision:0}}, grid:{{color:p.grid}} }},
        y: {{ ticks:{{color:p.text}}, grid:{{display:false}} }},
      }},
    }},
  }});

  // ── Platforms ──────────────────────────────────────────────────────────
  charts.platforms = new Chart(document.getElementById('chart-platforms'), {{
    type:'bar',
    data: {{
      labels: DATA.platforms.labels,
      datasets: [{{ data: DATA.platforms.values, backgroundColor: p.coverage }}],
    }},
    options: {{
      ...baseOpts(p), indexAxis:'y',
      plugins:{{ ...baseOpts(p).plugins, legend:{{display:false}} }},
      scales: {{
        x: {{ beginAtZero:true, ticks:{{color:p.dim, precision:0}}, grid:{{color:p.grid}} }},
        y: {{ ticks:{{color:p.text}}, grid:{{display:false}} }},
      }},
    }},
  }});
}}

renderAll();
</script>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"{OUTPUT} rebuilt ({total_hunts} hunts, {len(unique_techniques)} techniques, {len(unique_actors)} actors)")
