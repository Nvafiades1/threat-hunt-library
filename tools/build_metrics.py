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

_STATUS_BUCKETS = ("completed", "false positive", "inconclusive", "in progress")

def normalize_status(val: str) -> str | None:
    if not val:
        return None
    v = val.strip().lower()
    for canon in _STATUS_BUCKETS:
        if canon in v:
            return "False Positive" if canon == "false positive" else canon.title()
    return val.strip()

def parse_iso_dt(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except Exception:
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
    for f in sub.rglob("*.md"):
        if f.is_file() and f.name.lower() != "readme.md":
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
    status     = normalize_status(fields.get("Status", ""))
    platform   = fields.get("Hunt Platform", "").strip() or None
    actor_raw  = fields.get("Threat Actor", "").strip()
    actors     = [a.strip() for a in re.split(r"[,;/]", actor_raw) if a.strip()]

    # Hunt duration: Created field → file added date in the repo.
    created_dt = parse_iso_dt(fields.get("Created", ""))
    duration_days = None
    if created_dt:
        delta = (dt.date() - created_dt.date()).days
        if delta >= 0:
            duration_days = delta

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
        "status":    status,
        "platform":  platform,
        "actors":    actors,
        "duration_days": duration_days,
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

# ── new KPIs ────────────────────────────────────────────────────────────────
# Hunt duration: avg + median (days)
import datetime as _dt
durations = [r["duration_days"] for r in records if r["duration_days"] is not None]
if durations:
    avg_duration = round(sum(durations) / len(durations), 1)
    sd = sorted(durations)
    median_duration = sd[len(sd) // 2] if len(sd) % 2 else round((sd[len(sd) // 2 - 1] + sd[len(sd) // 2]) / 2, 1)
else:
    avg_duration = None
    median_duration = None

# Throughput rolling windows (anchored to today at build-time)
today = _dt.date.today()
def days_old(rec): return (today - _dt.date.fromisoformat(rec["date"])).days
throughput_30 = sum(1 for r in records if days_old(r) <= 30)
throughput_90 = sum(1 for r in records if days_old(r) <= 90)
throughput_30_prev = sum(1 for r in records if 31 <= days_old(r) <= 60)

# Coverage growth: new techniques per month
techs_seen: set = set()
new_techs_per_month: list[int] = []
for m in months:
    delta = 0
    for r in records:
        if r["month"] == m and r["parent"] not in techs_seen:
            techs_seen.add(r["parent"])
            delta += 1
    new_techs_per_month.append(delta)
new_this_month = new_techs_per_month[-1] if new_techs_per_month else 0
new_prev_month = new_techs_per_month[-2] if len(new_techs_per_month) > 1 else 0

# Outcome / Status mix
outcome_counts = Counter(r["status"] for r in records if r["status"])

# Tactic gaps (zero-coverage tactics, excluding 'Unmapped' which is historical)
tactic_gaps = [t for t in TACTICS if tactic_hunt_counts.get(t, 0) == 0]

payload = {
    "totals": {
        "hunts":      total_hunts,
        "techniques": len(unique_techniques),
        "actors":     len(unique_actors),
        "coverage":   coverage_pct,
        "universe":   total_parent_universe,
        "last_hunt":  last_hunt_date,
        "tactic_gap_count": len(tactic_gaps),
    },
    "duration": {
        "avg_days":    avg_duration,
        "median_days": median_duration,
        "measured":    len(durations),
        "total":       total_hunts,
    },
    "throughput": {
        "last_30":  throughput_30,
        "last_90":  throughput_90,
        "prev_30":  throughput_30_prev,
    },
    "growth": {
        "labels":          months,
        "new_techniques":  new_techs_per_month,
        "this_month":      new_this_month,
        "prev_month":      new_prev_month,
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
    "outcomes":   {"labels":list(outcome_counts.keys()), "values":list(outcome_counts.values())},
    "actors":     {"labels":[a for a,_ in actor_counts], "values":[n for _,n in actor_counts]},
    "severity":   {"labels":list(sev_counts.keys()),  "values":list(sev_counts.values())},
    "confidence": {"labels":list(conf_counts.keys()), "values":list(conf_counts.values())},
    "techniques": {"labels":[t for t,_ in tech_counts], "values":[n for _,n in tech_counts]},
    "platforms":  {"labels":[p for p,_ in plat_counts], "values":[n for _,n in plat_counts]},
    "gaps":       {"tactics": tactic_gaps, "total_tactics": len(TACTICS)},
}

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# KPI sub-line strings (precomputed for f-string clarity)
def _trend_pair(curr: int, prev: int):
    if curr == 0 and prev == 0:
        return "no recent activity", "trend-flat"
    if prev == 0:
        return "first 30-day window", "trend-flat"
    delta = curr - prev
    sign = "+" if delta > 0 else ""
    return f"{sign}{delta} vs prior 30d", ("trend-up" if delta > 0 else "trend-down" if delta < 0 else "trend-flat")

throughput_sub, throughput_cls = _trend_pair(throughput_30, throughput_30_prev)
growth_sub = (
    f"{'+' if new_this_month - new_prev_month >= 0 else ''}{new_this_month - new_prev_month} vs prior month"
    if (new_this_month or new_prev_month) else "awaiting first additions"
)
growth_cls = ("trend-up" if new_this_month > new_prev_month else "trend-down" if new_this_month < new_prev_month else "trend-flat")
duration_sub = (
    f"median {median_duration}d \u00B7 n={len(durations)}/{total_hunts}"
    if avg_duration is not None else "needs Created field on hunts"
)

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
.kpi-trend{{font-size:.7rem;font-weight:600;margin-left:.3rem;font-variant-numeric:tabular-nums}}
.trend-up{{color:var(--coverage)}}
.trend-down{{color:var(--danger)}}
.trend-flat{{color:var(--text-dim)}}

/* ── chart action footer ─────────────────────────────────────────────── */
.chart-actions{{
  display:flex;gap:.5rem;justify-content:flex-end;margin-top:.6rem;
  padding-top:.5rem;border-top:1px dashed var(--border);
}}
.chart-action{{
  font-size:.72rem;color:var(--text-dim);text-decoration:none;cursor:pointer;
  background:none;border:none;padding:.15rem .35rem;border-radius:3px;font-family:inherit;
}}
.chart-action:hover{{color:var(--accent);background:var(--surface-2)}}
.chart-action.flash{{color:var(--coverage)}}

/* ── master report button ────────────────────────────────────────────── */
.report-btn{{
  font-size:.82rem;background:var(--accent);color:#fff;border:none;border-radius:4px;
  padding:.4rem .75rem;cursor:pointer;font-family:inherit;font-weight:500;
}}
.report-btn:hover{{filter:brightness(1.1)}}
body.light .report-btn{{color:#fff}}
.report-btn-secondary{{
  font-size:.78rem;background:transparent;color:var(--text-dim);
  border:1px solid var(--border);border-radius:4px;
  padding:.4rem .65rem;cursor:pointer;font-family:inherit;
}}
.report-btn-secondary:hover{{color:var(--accent);border-color:var(--accent)}}

/* ── tactic-gaps panel ───────────────────────────────────────────────── */
.gaps-list{{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.5rem}}
.gaps-chip{{
  background:var(--chip-bg);color:var(--chip-fg);
  padding:.25rem .55rem;border-radius:12px;font-size:.78rem;
  border:1px dashed var(--border);
}}
.gaps-empty{{color:var(--coverage);font-size:.85rem;font-weight:500;margin-top:.5rem}}

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
  <button id="reportWordBtn" class="report-btn" title="Download a Word document of every chart and KPI — opens directly in Microsoft Word">Generate Report (Word) &darr;</button>
  <button id="reportMdBtn" class="report-btn-secondary" title="Download the same report as plain Markdown">MD</button>
  <a class="nav-link" href="./index.html">Matrix &rarr;</a>
  <a class="nav-link" href="./cti.html">CTI Hub &rarr;</a>
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
  <div class="kpi orange">
    <div class="kpi-label">Avg Hunt Duration</div>
    <div class="kpi-value">{f"{avg_duration} d" if avg_duration is not None else "&mdash;"}</div>
    <div class="kpi-sub">{html.escape(duration_sub)}</div>
  </div>
  <div class="kpi blue">
    <div class="kpi-label">Throughput &middot; 30 days</div>
    <div class="kpi-value">{throughput_30:,}</div>
    <div class="kpi-sub"><span class="kpi-trend {throughput_cls}">{html.escape(throughput_sub)}</span></div>
  </div>
  <div class="kpi blue">
    <div class="kpi-label">Throughput &middot; 90 days</div>
    <div class="kpi-value">{throughput_90:,}</div>
    <div class="kpi-sub">{"hunts completed in last 90 days" if throughput_90 else "no completions in last 90 days"}</div>
  </div>
  <div class="kpi green">
    <div class="kpi-label">New Coverage &middot; this month</div>
    <div class="kpi-value">+{new_this_month}</div>
    <div class="kpi-sub"><span class="kpi-trend {growth_cls}">{html.escape(growth_sub)}</span></div>
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
  <div class="card span-8" data-chart="timeline">
    <h3>Hunts Over Time</h3>
    <div class="sub-label">Monthly volume (bars) and cumulative total (line)</div>
    <canvas id="chart-timeline" height="110"></canvas>
    <div class="chart-actions">
      <button class="chart-action" data-export="timeline" data-format="csv">CSV &darr;</button>
      <button class="chart-action" data-export="timeline" data-format="md">Copy MD</button>
    </div>
  </div>
  <div class="card span-4" data-chart="severity">
    <h3>Severity</h3>
    <div class="sub-label">Distribution of completed hunts</div>
    <canvas id="chart-severity" height="180"></canvas>
    <div class="chart-actions">
      <button class="chart-action" data-export="severity" data-format="csv">CSV &darr;</button>
      <button class="chart-action" data-export="severity" data-format="md">Copy MD</button>
    </div>
  </div>
</div>

<h2>Outcomes</h2>
<div class="grid">
  <div class="card span-4" data-chart="outcomes">
    <h3>Outcome Mix</h3>
    <div class="sub-label">Status field across all hunts</div>
    <canvas id="chart-outcomes" height="180"></canvas>
    <div class="chart-actions">
      <button class="chart-action" data-export="outcomes" data-format="csv">CSV &darr;</button>
      <button class="chart-action" data-export="outcomes" data-format="md">Copy MD</button>
    </div>
  </div>
  <div class="card span-4" data-chart="confidence">
    <h3>Confidence</h3>
    <div class="sub-label">Hunter confidence in findings</div>
    <canvas id="chart-confidence" height="180"></canvas>
    <div class="chart-actions">
      <button class="chart-action" data-export="confidence" data-format="csv">CSV &darr;</button>
      <button class="chart-action" data-export="confidence" data-format="md">Copy MD</button>
    </div>
  </div>
  <div class="card span-4" data-chart="growth">
    <h3>Coverage Growth</h3>
    <div class="sub-label">New techniques covered each month</div>
    <canvas id="chart-growth" height="180"></canvas>
    <div class="chart-actions">
      <button class="chart-action" data-export="growth" data-format="csv">CSV &darr;</button>
      <button class="chart-action" data-export="growth" data-format="md">Copy MD</button>
    </div>
  </div>
</div>

<h2>Coverage</h2>
<div class="grid">
  <div class="card span-8" data-chart="tactics">
    <h3>Coverage by Tactic</h3>
    <div class="sub-label">Unique techniques covered (dark) and total hunts (light) per MITRE tactic</div>
    <canvas id="chart-tactics" height="220"></canvas>
    <div class="chart-actions">
      <button class="chart-action" data-export="tactics" data-format="csv">CSV &darr;</button>
      <button class="chart-action" data-export="tactics" data-format="md">Copy MD</button>
    </div>
  </div>
  <div class="card span-4" data-chart="gaps">
    <h3>Tactic Gaps</h3>
    <div class="sub-label">MITRE tactics with no completed hunts yet &mdash; potential next investments.</div>
    <div id="gaps-content"></div>
    <div class="chart-actions">
      <button class="chart-action" data-export="gaps" data-format="csv">CSV &darr;</button>
      <button class="chart-action" data-export="gaps" data-format="md">Copy MD</button>
    </div>
  </div>
</div>

<h2>Top Lists</h2>
<div class="grid">
  <div class="card span-6" data-chart="actors">
    <h3>Top Threat Actors</h3>
    <div class="sub-label">Most-referenced in completed hunts</div>
    <canvas id="chart-actors" height="200"></canvas>
    <div class="chart-actions">
      <button class="chart-action" data-export="actors" data-format="csv">CSV &darr;</button>
      <button class="chart-action" data-export="actors" data-format="md">Copy MD</button>
    </div>
  </div>
  <div class="card span-6" data-chart="techniques">
    <h3>Top Techniques</h3>
    <div class="sub-label">Most-hunted MITRE techniques</div>
    <canvas id="chart-techniques" height="200"></canvas>
    <div class="chart-actions">
      <button class="chart-action" data-export="techniques" data-format="csv">CSV &darr;</button>
      <button class="chart-action" data-export="techniques" data-format="md">Copy MD</button>
    </div>
  </div>
  <div class="card span-12" data-chart="platforms">
    <h3>Hunt Platforms</h3>
    <div class="sub-label">Tools used across hunts</div>
    <canvas id="chart-platforms" height="100"></canvas>
    <div class="chart-actions">
      <button class="chart-action" data-export="platforms" data-format="csv">CSV &darr;</button>
      <button class="chart-action" data-export="platforms" data-format="md">Copy MD</button>
    </div>
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
Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;

const charts = {{}};
function destroyAll() {{ for (const k in charts) charts[k]?.destroy(); }}
// Initial render is deferred to the end of the script so all helper
// declarations (palette, baseOpts, renderAll, etc.) are initialized first.
document.getElementById('modeToggle').addEventListener('click', () => {{
  const toLight = !document.body.classList.contains('light');
  localStorage.setItem('prefersLight', toLight);
  applyMode(toLight);
}});

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

  // ── Outcome mix donut ─────────────────────────────────────────────────
  const outcomeColor = l =>
    l === 'Completed'      ? p.coverage :
    l === 'False Positive' ? p.danger   :
    l === 'In Progress'    ? p.info     :
    l === 'Inconclusive'   ? p.accent   : p.dim;
  charts.outcomes = new Chart(document.getElementById('chart-outcomes'), {{
    type:'doughnut',
    data: {{
      labels: DATA.outcomes.labels,
      datasets: [{{
        data: DATA.outcomes.values,
        backgroundColor: DATA.outcomes.labels.map(outcomeColor),
        borderWidth: 2, borderColor: cssVar('--surface'),
      }}],
    }},
    options: {{ ...baseOpts(p), cutout:'62%' }},
  }});

  // ── Coverage growth line ──────────────────────────────────────────────
  charts.growth = new Chart(document.getElementById('chart-growth'), {{
    type:'bar',
    data: {{
      labels: DATA.growth.labels,
      datasets: [{{
        label:'New techniques',
        data: DATA.growth.new_techniques,
        backgroundColor: p.coverage,
      }}],
    }},
    options: {{
      ...baseOpts(p),
      plugins:{{ ...baseOpts(p).plugins, legend:{{display:false}} }},
      scales:{{
        x:{{ ticks:{{color:p.dim}}, grid:{{color:p.grid}} }},
        y:{{ beginAtZero:true, ticks:{{color:p.dim, precision:0}}, grid:{{color:p.grid}} }},
      }},
    }},
  }});

  // ── Tactic gaps panel (HTML, not Chart.js) ────────────────────────────
  const gapsEl = document.getElementById('gaps-content');
  if (gapsEl) {{
    if (DATA.gaps.tactics.length === 0) {{
      gapsEl.innerHTML = '<div class="gaps-empty">No tactic gaps &mdash; every ATT&amp;CK tactic has at least one hunt.</div>';
    }} else {{
      gapsEl.innerHTML = '<div class="gaps-list">' +
        DATA.gaps.tactics.map(t => `<span class="gaps-chip">${{t}}</span>`).join('') +
        `</div><div class="kpi-sub" style="margin-top:.6rem">${{DATA.gaps.tactics.length}} of ${{DATA.gaps.total_tactics}} tactics still uncovered.</div>`;
    }}
  }}
}}

// ── per-chart export helpers ───────────────────────────────────────────
function csvEscape(v) {{
  const s = String(v ?? '');
  return /[",\\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}}

const CHART_EXPORTERS = {{
  timeline: () => ({{
    headers: ['Month','Hunts','Cumulative'],
    rows: DATA.timeline.labels.map((l,i) => [l, DATA.timeline.monthly[i], DATA.timeline.cumulative[i]]),
  }}),
  growth: () => ({{
    headers: ['Month','New techniques'],
    rows: DATA.growth.labels.map((l,i) => [l, DATA.growth.new_techniques[i]]),
  }}),
  tactics: () => ({{
    headers: ['Tactic','Techniques covered','Total hunts'],
    rows: DATA.tactics.labels.map((l,i) => [l, DATA.tactics.covered[i], DATA.tactics.hunts[i]]),
  }}),
  gaps: () => ({{
    headers: ['Tactic','Status'],
    rows: DATA.gaps.tactics.length
      ? DATA.gaps.tactics.map(t => [t, 'No coverage'])
      : [['(all tactics covered)', '—']],
  }}),
  severity:   () => simplePair('severity'),
  confidence: () => simplePair('confidence'),
  outcomes:   () => simplePair('outcomes'),
  actors:     () => simplePair('actors'),
  techniques: () => simplePair('techniques'),
  platforms:  () => simplePair('platforms'),
}};

function simplePair(id) {{
  const d = DATA[id];
  return {{
    headers: ['Label','Count'],
    rows: d.labels.map((l,i) => [l, d.values[i]]),
  }};
}}

function chartCSV(id) {{
  const ex = CHART_EXPORTERS[id]?.(); if (!ex) return '';
  const lines = [ex.headers.map(csvEscape).join(',')];
  for (const r of ex.rows) lines.push(r.map(csvEscape).join(','));
  return lines.join('\\n') + '\\n';
}}

function chartMD(id) {{
  const ex = CHART_EXPORTERS[id]?.(); if (!ex) return '';
  const lines = ['| ' + ex.headers.join(' | ') + ' |'];
  lines.push('|' + ex.headers.map(() => '---').join('|') + '|');
  for (const r of ex.rows) lines.push('| ' + r.join(' | ') + ' |');
  return lines.join('\\n');
}}

function downloadFile(content, filename, mime) {{
  const blob = new Blob([content], {{ type: mime }});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {{ document.body.removeChild(a); URL.revokeObjectURL(a.href); }}, 100);
}}

async function copyToClipboard(text) {{
  try {{ await navigator.clipboard.writeText(text); return true; }}
  catch (_) {{ return false; }}
}}

function flashButton(btn, text, ms = 1200) {{
  const orig = btn.textContent;
  btn.textContent = text;
  btn.classList.add('flash');
  setTimeout(() => {{ btn.textContent = orig; btn.classList.remove('flash'); }}, ms);
}}

document.addEventListener('click', e => {{
  const btn = e.target.closest('[data-export]');
  if (!btn) return;
  const id = btn.dataset.export;
  const fmt = btn.dataset.format;
  if (fmt === 'csv') {{
    downloadFile(chartCSV(id), `${{id}}.csv`, 'text/csv');
    flashButton(btn, 'Saved');
  }} else if (fmt === 'md') {{
    copyToClipboard(chartMD(id)).then(ok => flashButton(btn, ok ? 'Copied' : 'Copy failed'));
  }}
}});

// ── master monthly report ──────────────────────────────────────────────
function pct(curr, prev) {{
  if (prev === 0) return curr === 0 ? '0%' : 'new';
  const d = ((curr - prev) / prev) * 100;
  const sign = d > 0 ? '+' : '';
  return `${{sign}}${{Math.round(d)}}%`;
}}

const NARRATIVES = {{
  timeline: () => {{
    const t = DATA.timeline;
    if (!t.labels.length) return 'No hunts archived yet.';
    const last = t.monthly.at(-1) ?? 0;
    const prev = t.monthly.at(-2) ?? 0;
    const total = t.cumulative.at(-1) ?? 0;
    return `${{total}} hunts archived to date across ${{t.labels.length}} month(s). Most recent month (${{t.labels.at(-1)}}) saw ${{last}} hunt(s) — ${{pct(last, prev)}} vs prior month.`;
  }},
  severity: () => describeMix('severity', 'severity'),
  confidence: () => describeMix('confidence', 'confidence rating'),
  outcomes: () => {{
    const d = DATA.outcomes;
    if (!d.labels.length) return 'No status field has been populated.';
    const total = d.values.reduce((a,b) => a+b, 0);
    const completed = d.labels.indexOf('Completed') >= 0 ? d.values[d.labels.indexOf('Completed')] : 0;
    return `${{total}} hunts categorised by outcome; ${{completed}} (${{pct(completed, total)}}) marked Completed.`;
  }},
  growth: () => {{
    const g = DATA.growth;
    if (!g.labels.length) return 'No coverage growth data yet.';
    const last = g.new_techniques.at(-1) ?? 0;
    const prev = g.new_techniques.at(-2) ?? 0;
    return `Added ${{last}} new technique(s) this month vs ${{prev}} the prior month (${{pct(last, prev)}}). Cumulative coverage: ${{DATA.totals.techniques}} of ${{DATA.totals.universe}}.`;
  }},
  tactics: () => {{
    const t = DATA.tactics;
    if (!t.labels.length) return 'No tactic coverage yet.';
    const top = t.labels[0];
    const topHunts = t.hunts[0];
    return `Most-hunted tactic: ${{top}} (${{topHunts}} hunts). ${{DATA.gaps.tactics.length}} of ${{DATA.gaps.total_tactics}} tactics have zero coverage.`;
  }},
  gaps: () => {{
    if (DATA.gaps.tactics.length === 0) return 'Every MITRE tactic has at least one completed hunt.';
    return `Uncovered tactics: ${{DATA.gaps.tactics.join(', ')}}. Consider scheduling at least one hunt per tactic.`;
  }},
  actors: () => {{
    const a = DATA.actors;
    if (!a.labels.length) return 'No threat actors named in hunts yet.';
    return `${{a.labels.length}} unique actor(s) referenced. Most-referenced: ${{a.labels[0]}} (${{a.values[0]}} hunt${{a.values[0] === 1 ? '' : 's'}}).`;
  }},
  techniques: () => {{
    const t = DATA.techniques;
    if (!t.labels.length) return 'No techniques hunted yet.';
    return `Most-hunted technique: ${{t.labels[0]}} (${{t.values[0]}} hunt${{t.values[0] === 1 ? '' : 's'}}).`;
  }},
  platforms: () => {{
    const p = DATA.platforms;
    if (!p.labels.length) return 'Hunt platform field is empty across all hunts.';
    return `${{p.labels.length}} platform(s) in use. Primary: ${{p.labels[0]}} (${{p.values[0]}} hunts).`;
  }},
}};

function describeMix(key, label) {{
  const d = DATA[key];
  if (!d.labels.length) return `No ${{label}} data populated.`;
  const total = d.values.reduce((a,b) => a+b, 0);
  const top = d.labels[0];
  const topVal = d.values[0];
  return `${{total}} hunts rated for ${{label}}; most common: ${{top}} (${{topVal}}, ${{pct(topVal, total)}}).`;
}}

function buildReportSections() {{
  const t = DATA.totals;
  const dur = DATA.duration;
  const thru = DATA.throughput;
  const grw = DATA.growth;
  const today = new Date().toISOString().slice(0, 10);
  const snapshot = [
    ['Total Hunts',                    String(t.hunts)],
    ['Techniques Covered',             `${{t.techniques}} of ${{t.universe}} (${{t.coverage}}%)`],
    ['Threat Actors Tracked',          String(t.actors)],
    ['Avg Hunt Duration',              dur.avg_days != null ? `${{dur.avg_days}} days (median ${{dur.median_days}})` : '\u2014'],
    ['Throughput \u00B7 last 30 days', `${{thru.last_30}} hunts (${{pct(thru.last_30, thru.prev_30)}} vs prior 30)`],
    ['Throughput \u00B7 last 90 days', `${{thru.last_90}} hunts`],
    ['New Coverage \u00B7 this month', `+${{grw.this_month}} techniques (vs +${{grw.prev_month}} prior)`],
    ['Tactic Gaps',                    `${{DATA.gaps.tactics.length}} of ${{DATA.gaps.total_tactics}} tactics uncovered`],
  ];
  const charts = [
    ['Hunts Over Time',     'timeline'],
    ['Coverage Growth',     'growth'],
    ['Outcome Mix',         'outcomes'],
    ['Severity',            'severity'],
    ['Confidence',          'confidence'],
    ['Coverage by Tactic',  'tactics'],
    ['Tactic Gaps',         'gaps'],
    ['Top Threat Actors',   'actors'],
    ['Top Techniques',      'techniques'],
    ['Hunt Platforms',      'platforms'],
  ];
  return {{ today, snapshot, charts }};
}}

function generateReportMarkdown() {{
  const {{ today, snapshot, charts }} = buildReportSections();
  const lines = [
    `# Threat Hunt Library \u2014 Monthly Report`,
    ``,
    `_Generated ${{today}}_`,
    ``,
    `## Snapshot`,
    ``,
    `| KPI | Value |`,
    `|---|---|`,
    ...snapshot.map(([k, v]) => `| ${{k}} | ${{v}} |`),
    ``,
  ];
  for (const [title, id] of charts) {{
    lines.push(`## ${{title}}`);
    lines.push('');
    lines.push(chartMD(id));
    lines.push('');
    const narrative = NARRATIVES[id] && NARRATIVES[id]();
    if (narrative) {{
      lines.push(`**Insight.** ${{narrative}}`);
      lines.push('');
    }}
  }}
  lines.push('---');
  lines.push('');
  lines.push(`_Source: Threat Hunt Library \u00B7 https://github.com/{OWNER}/{REPO}_`);
  downloadFile(lines.join('\\n'), `threat-hunt-report-${{today}}.md`, 'text/markdown');
}}

function escHtml(s) {{
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}}

function chartHTMLTable(id) {{
  const ex = CHART_EXPORTERS[id]?.(); if (!ex) return '';
  const head = `<tr>${{ex.headers.map(h => `<th>${{escHtml(h)}}</th>`).join('')}}</tr>`;
  const body = ex.rows.map(r =>
    `<tr>${{r.map(c => `<td>${{escHtml(c)}}</td>`).join('')}}</tr>`
  ).join('');
  return `<table>${{head}}${{body}}</table>`;
}}

function generateReportWord() {{
  const {{ today, snapshot, charts }} = buildReportSections();
  let body = '';
  body += `<h1>Threat Hunt Library &mdash; Monthly Report</h1>`;
  body += `<p class="meta">Generated ${{escHtml(today)}}</p>`;
  body += `<h2>Snapshot</h2>`;
  body += `<table><tr><th>KPI</th><th>Value</th></tr>`;
  for (const [k, v] of snapshot) {{
    body += `<tr><td><b>${{escHtml(k)}}</b></td><td>${{escHtml(v)}}</td></tr>`;
  }}
  body += `</table>`;
  for (const [title, id] of charts) {{
    body += `<h2>${{escHtml(title)}}</h2>`;
    body += chartHTMLTable(id);
    const narrative = NARRATIVES[id] && NARRATIVES[id]();
    if (narrative) {{
      body += `<p><b>Insight.</b> ${{escHtml(narrative)}}</p>`;
    }}
  }}
  body += `<p class="footer"><i>Source: Threat Hunt Library &middot; https://github.com/{OWNER}/{REPO}</i></p>`;

  const html =
`<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">
<head>
<meta charset="utf-8">
<title>Threat Hunt Library Monthly Report</title>
<!--[if gte mso 9]>
<xml>
<w:WordDocument>
<w:View>Print</w:View>
<w:Zoom>100</w:Zoom>
<w:DoNotOptimizeForBrowser/>
</w:WordDocument>
</xml>
<![endif]-->
<style>
@page Section1 {{ size: 8.5in 11in; margin: 0.75in; }}
div.Section1 {{ page: Section1; }}
body {{ font-family: Calibri, "Segoe UI", Arial, sans-serif; font-size: 11pt; color: #23394a; }}
h1 {{ color: #23394a; border-bottom: 3px solid #e87722; padding-bottom: 6px; font-size: 22pt; margin-bottom: 4pt; }}
h2 {{ color: #23394a; margin-top: 22pt; margin-bottom: 6pt; font-size: 14pt; border-bottom: 1px solid #ccc; padding-bottom: 3px; }}
p {{ margin: 6pt 0; }}
p.meta {{ color: #5b6a7a; font-style: italic; margin-top: 0; }}
p.footer {{ color: #5b6a7a; font-size: 9pt; margin-top: 24pt; border-top: 1px solid #ccc; padding-top: 6pt; }}
table {{ border-collapse: collapse; margin: 8pt 0 14pt; width: 100%; }}
th {{ background-color: #23394a; color: #ffffff; font-weight: bold; padding: 5pt 8pt; text-align: left; border: 1px solid #1b2736; }}
td {{ padding: 5pt 8pt; border: 1px solid #ccc; vertical-align: top; }}
tr:nth-child(even) td {{ background-color: #f4f6f8; }}
b {{ font-weight: 600; }}
</style>
</head>
<body>
<div class="Section1">
${{body}}
</div>
</body>
</html>`;
  downloadFile(html, `threat-hunt-report-${{today}}.doc`, 'application/msword');
}}

document.getElementById('reportWordBtn')?.addEventListener('click', generateReportWord);
document.getElementById('reportMdBtn')?.addEventListener('click', generateReportMarkdown);

applyMode(localStorage.getItem('prefersLight') === 'true');
</script>
</body></html>"""

DOCS_DIR.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"{OUTPUT} rebuilt ({total_hunts} hunts, {len(unique_techniques)} techniques, {len(unique_actors)} actors)")
