#!/usr/bin/env python3
"""
Generate docs/threat-actors.html — HHS / NIH Threat Actor Priority + Heatmap.

Reads:
  • tools/threat_actors_hhs.json — curated list of actors with aliases, origin,
    motivation, sector-fit (0-3), MITRE id, and a one-line note.
  • tools/cti_state.json         — rolling CTI Hub feed window.

Computes:
  • Per-actor mention counts bucketed by YYYY-MM over the last 12 months.
  • Composite priority score:  recency · 0.5 + severity · 0.25 + sector_fit · 0.25
    where recency ≈ (last-30d × 3) + (last-90d × 1), severity is motivation-based,
    and sector_fit comes from the curated YAML (0-3).

Renders a single static HTML page with:
  • KPI strip
  • Priority table (sorted by score desc)
  • Actor × Month heatmap (top-N by score, color intensity = mention count)
  • Light/dark theme toggle
"""
from __future__ import annotations

import html
import json
import pathlib
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# ── config ──────────────────────────────────────────────────────────────────

ROOT          = pathlib.Path(__file__).resolve().parent.parent
ACTORS_FILE   = ROOT / "tools" / "threat_actors_hhs.json"
CTI_STATE     = ROOT / "tools" / "cti_state.json"
ACTOR_STATE   = ROOT / "tools" / "threat_actors_state.json"
PROFILES_DIR  = ROOT / "threat-actor-profiles"
OUTPUT        = ROOT / "docs" / "threat-actors.html"

OWNER, REPO, BRANCH = "Nvafiades1", "threat-hunt-library", "main"

HEATMAP_MONTHS = 12          # columns
HEATMAP_TOP_N  = 30          # rows in the heatmap (full table is unbounded)

# Severity weight by motivation tag.
SEVERITY = {
    "ransomware":  3.0,
    "destructive": 3.0,
    "iab":         2.5,
    "financial":   2.0,
    "espionage":   2.0,
    "hacktivism":  1.0,
}

# ── helpers ─────────────────────────────────────────────────────────────────

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def month_keys(n: int) -> list[str]:
    """Last n calendar months as YYYY-MM, oldest → newest."""
    out = []
    cur = now_utc().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    for _ in range(n):
        out.append(cur.strftime("%Y-%m"))
        # Step back one month.
        prev_last = cur - timedelta(days=1)
        cur = prev_last.replace(day=1)
    return list(reversed(out))

def parse_pub(item: dict) -> datetime | None:
    raw = item.get("published") or item.get("first_seen")
    if not raw:
        return None
    s = str(raw).strip().replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None

def esc(s: str) -> str:
    return html.escape(s or "")

def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")

# ── load inputs ─────────────────────────────────────────────────────────────

actors = json.loads(ACTORS_FILE.read_text())
state  = json.loads(CTI_STATE.read_text())
items  = state.get("items", [])

# Build per-actor matcher: \b(alias1|alias2|...)\b, case-insensitive.
for a in actors:
    aliases = sorted({x for x in a.get("aliases", []) if x}, key=len, reverse=True)
    a["_re"] = re.compile(
        r"\b(?:" + "|".join(re.escape(x) for x in aliases) + r")\b",
        re.IGNORECASE,
    ) if aliases else None

# Discover any markdown profile files in threat-actor-profiles/.
profile_index: dict[str, str] = {}
if PROFILES_DIR.exists():
    for p in PROFILES_DIR.glob("*.md"):
        # heuristic: filename usually contains MITRE id or alias
        profile_index[p.stem.lower()] = p.name

months = month_keys(HEATMAP_MONTHS)
month_set = set(months)
oldest_cutoff = datetime.strptime(months[0] + "-01", "%Y-%m-%d").replace(tzinfo=timezone.utc)
now = now_utc()

# Persistent per-actor monthly history — accumulates across builds because the
# CTI state file is a 90-day rolling window. Each monthly run recomputes the
# months currently visible in cti_state and overwrites those entries; older
# months (no longer in the rolling window) stay frozen at their last value.
try:
    actor_state = json.loads(ACTOR_STATE.read_text())
except Exception:
    actor_state = {"by_actor": {}}
historic = actor_state.setdefault("by_actor", {})

# ── tally mentions per actor per month ──────────────────────────────────────

mentions: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
sample_titles: dict[str, list[tuple[str, str, str]]] = defaultdict(list)  # actor -> [(date, source, title)]

for item in items:
    # IOC feeds (URLhaus / MalwareBazaar / ThreatFox) tag every infrastructure
    # row with the malware family / actor name and would drown the priority
    # list in mechanical entries. Surface them via the CTI Hub IOC tab; the
    # priority list focuses on news / vendor / gov reporting.
    if item.get("category") == "ioc":
        continue
    pub = parse_pub(item)
    if not pub or pub < oldest_cutoff:
        continue
    mk = pub.strftime("%Y-%m")
    if mk not in month_set:
        continue
    text = " ".join([
        item.get("title", "") or "",
        item.get("summary", "") or "",
        " ".join(item.get("tags", []) or []),
        item.get("source", "") or "",
    ])
    for a in actors:
        if a["_re"] and a["_re"].search(text):
            mentions[a["name"]][mk] += 1
            if len(sample_titles[a["name"]]) < 3:
                sample_titles[a["name"]].append((
                    pub.strftime("%Y-%m-%d"),
                    item.get("source", "?"),
                    (item.get("title", "") or "")[:140],
                ))

# ── compute scores ──────────────────────────────────────────────────────────

cutoff_30 = now - timedelta(days=30)
cutoff_90 = now - timedelta(days=90)

def actor_metrics(a: dict) -> dict:
    name = a["name"]
    counts = mentions.get(name, {})
    last_1m = counts.get(months[-1], 0)
    total_3m = sum(counts.get(m, 0) for m in months[-3:])
    total_12m = sum(counts.values())
    recency = last_1m * 3 + total_3m * 1
    sev = SEVERITY.get(a.get("motivation", "").lower(), 1.5)
    score = recency * 0.5 + sev * 0.25 + a.get("sector_fit", 0) * 0.75
    return {
        "name": name,
        "last_1m": last_1m,
        "last_3m": total_3m,
        "total_12m": total_12m,
        "recency": recency,
        "severity": sev,
        "sector_fit": a.get("sector_fit", 0),
        "score": round(score, 2),
        "monthly": [counts.get(m, 0) for m in months],
        "origin": a.get("origin", "?"),
        "motivation": a.get("motivation", "?"),
        "mitre_id": a.get("mitre_id", ""),
        "notes": a.get("notes", ""),
    }

scored = [actor_metrics(a) for a in actors]
scored.sort(key=lambda r: (-r["score"], -r["last_3m"], r["name"]))

# Persist current run's mention counts into accumulating state, then re-read so
# the heatmap can show months that have rolled off the CTI window.
for name, monthly in mentions.items():
    bucket = historic.setdefault(name, {})
    for mk, count in monthly.items():
        bucket[mk] = count
actor_state["last_built"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
ACTOR_STATE.write_text(json.dumps(actor_state, indent=2, sort_keys=True) + "\n")

# Rebuild monthly arrays for rendering using the persistent state.
for r in scored:
    persisted = historic.get(r["name"], {})
    r["monthly"] = [persisted.get(m, 0) for m in months]
    r["total_12m"] = sum(r["monthly"])

# ── KPIs ────────────────────────────────────────────────────────────────────

active_30d   = sum(1 for r in scored if r["last_1m"] > 0)
active_90d   = sum(1 for r in scored if r["last_3m"] > 0)
high_sev     = sum(1 for r in scored if r["severity"] >= 3.0)
total_mentions_3m = sum(r["last_3m"] for r in scored)

# ── HTML rendering ──────────────────────────────────────────────────────────

def heat_class(n: int) -> str:
    if n == 0:  return "h0"
    if n <= 2:  return "h1"
    if n <= 5:  return "h2"
    if n <= 10: return "h3"
    if n <= 20: return "h4"
    return "h5"

def actor_link(r: dict) -> str:
    """Return a URL: prefer threat-actor-profiles file, else MITRE Groups, else Google search."""
    slug = slugify(r["name"])
    for stem, fname in profile_index.items():
        if stem.startswith(slug.split("-")[0][:6]) or slug in stem or stem in slug:
            return f"https://github.com/{OWNER}/{REPO}/blob/{BRANCH}/threat-actor-profiles/{fname}"
    if r["mitre_id"]:
        return f"https://attack.mitre.org/groups/{r['mitre_id']}/"
    return f"https://attack.mitre.org/groups/"

def render_priority_row(idx: int, r: dict) -> str:
    title_attr = ""
    if sample_titles.get(r["name"]):
        bullets_raw = "\n".join(
            f"• {d} — {s}: {t}" for d, s, t in sample_titles[r["name"]][:3]
        )
        title_attr = f' title="{esc(bullets_raw)}"'
    sev_label = r["motivation"].title() if r["motivation"] else "?"
    mid_html = f' <span class="mid">{esc(r["mitre_id"])}</span>' if r["mitre_id"] else ""
    last_1m_disp = r["last_1m"] if r["last_1m"] else "—"
    last_3m_disp = r["last_3m"] if r["last_3m"] else "—"
    total_12m_disp = r["total_12m"] if r["total_12m"] else "—"
    return (
        f'<tr{title_attr}>'
        f'<td class="rank">{idx}</td>'
        f'<td><a href="{actor_link(r)}" target="_blank" rel="noopener">{esc(r["name"])}</a>{mid_html}</td>'
        f'<td>{esc(r["origin"])}</td>'
        f'<td><span class="motivation mot-{esc(slugify(r["motivation"]))}">{esc(sev_label)}</span></td>'
        f'<td class="num">{r["sector_fit"]}</td>'
        f'<td class="num emph">{last_1m_disp}</td>'
        f'<td class="num">{last_3m_disp}</td>'
        f'<td class="num">{total_12m_disp}</td>'
        f'<td class="num score">{r["score"]:.1f}</td>'
        f'<td class="notes">{esc(r["notes"])}</td>'
        f'</tr>'
    )

priority_rows_html = "\n".join(render_priority_row(i + 1, r) for i, r in enumerate(scored))

# Heatmap: top N by score, but only those with at least one mention in 12m
heat_rows = [r for r in scored if r["total_12m"] > 0][:HEATMAP_TOP_N]

heat_header_cells = "".join(
    f'<div class="heat-mh">{m[5:]}<br><span class="yr">{m[:4]}</span></div>'
    for m in months
)
heat_body_html = ""
for r in heat_rows:
    cells = "".join(
        f'<div class="heat-cell {heat_class(c)}" title="{esc(r["name"])} · {months[i]} · {c} mentions">{c if c else ""}</div>'
        for i, c in enumerate(r["monthly"])
    )
    heat_body_html += (
        f'<div class="heat-row">'
        f'<div class="heat-label" title="{esc(r["notes"])}">'
        f'<a href="{actor_link(r)}" target="_blank" rel="noopener">{esc(r["name"])}</a></div>'
        f'<div class="heat-cells">{cells}</div>'
        f'</div>'
    )

build_time_iso = now.strftime("%Y-%m-%d %H:%M UTC")

HTML = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HHS / NIH Threat Actor Priority</title>
<style>
:root {{
  --bg:#0f1620; --surface:#17202c; --surface-2:#1e2833; --border:#2a3644;
  --text:#e6ecf2; --text-dim:#8a97a8; --accent:#e87722; --good:#2fbf71;
  --chip-bg:#243142; --chip-fg:#a9b4c2;
  --h0:#1a2231; --h1:#2c3a52; --h2:#3a5379; --h3:#5b75a0; --h4:#9b6a3c; --h5:#e87722;
  --mot-ransomware:#dc2626; --mot-destructive:#b91c1c; --mot-espionage:#7c3aed;
  --mot-financial:#0891b2; --mot-hacktivism:#65a30d; --mot-iab:#a16207;
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}}
body.light {{
  --bg:#f6f6f6; --surface:#ffffff; --surface-2:#fafbfc; --border:#dfe3e8;
  --text:#23394a; --text-dim:#5b6a7a; --accent:#c75f11; --good:#17905a;
  --chip-bg:#eef1f5; --chip-fg:#4a5a6c;
  --h0:#eaecef; --h1:#cdd9e5; --h2:#a4bedb; --h3:#719ec7; --h4:#dd8a3a; --h5:#c75f11;
}}
*{{box-sizing:border-box}} html,body{{margin:0;height:100%}}
body{{background:var(--bg);color:var(--text);font-family:var(--font-sans);font-size:14px;line-height:1.4;-webkit-font-smoothing:antialiased}}
header{{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:.75rem;
  padding:.6rem 1rem;background:var(--surface);border-bottom:1px solid var(--border)}}
.brand{{font-weight:600;font-size:1.05rem;margin-right:auto;letter-spacing:.2px}}
.brand .accent{{color:var(--accent)}}
.brand .sub{{color:var(--text-dim);font-size:.78rem;font-weight:400;margin-left:.4rem}}
.nav-link{{color:var(--text-dim);text-decoration:none;font-size:.82rem;
  padding:.3rem .55rem;border:1px solid var(--border);border-radius:4px}}
.nav-link:hover{{color:var(--accent);border-color:var(--accent)}}
#modeToggle{{cursor:pointer;font-size:1rem;background:none;color:var(--text);
  border:1px solid var(--border);border-radius:4px;padding:.3rem .55rem}}
#modeToggle:hover{{border-color:var(--accent)}}
main{{max-width:1500px;margin:0 auto;padding:1rem 1.25rem 4rem}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:.75rem;margin:.75rem 0 1.25rem}}
.kpi{{background:var(--surface);border:1px solid var(--border);
  border-radius:8px;padding:.75rem .9rem}}
.kpi .num{{font-size:1.75rem;font-weight:600;line-height:1.1}}
.kpi .lbl{{font-size:.72rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-top:.25rem}}
h2{{font-size:1.05rem;margin:1.5rem 0 .6rem}}
h2 .hint{{font-weight:400;color:var(--text-dim);font-size:.8rem;margin-left:.5rem}}
table{{width:100%;border-collapse:collapse;background:var(--surface);
  border:1px solid var(--border);border-radius:6px;overflow:hidden;font-size:.85rem}}
thead th{{position:sticky;top:42px;background:var(--surface-2);
  text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;
  color:var(--text-dim);padding:.55rem .65rem;border-bottom:1px solid var(--border)}}
tbody td{{padding:.55rem .65rem;border-bottom:1px solid var(--border);vertical-align:top}}
tbody tr:hover{{background:var(--surface-2)}}
td.rank{{color:var(--text-dim);font-variant-numeric:tabular-nums;width:2rem}}
td.num{{font-variant-numeric:tabular-nums;text-align:right;width:4rem;color:var(--text-dim)}}
td.num.emph{{color:var(--text);font-weight:600}}
td.num.score{{color:var(--accent);font-weight:600}}
td.notes{{color:var(--text-dim);font-size:.78rem;max-width:38rem}}
td a{{color:var(--text);text-decoration:none}}
td a:hover{{color:var(--accent);text-decoration:underline}}
.mid{{font-size:.7rem;color:var(--text-dim);margin-left:.3rem;
  background:var(--chip-bg);padding:.05rem .35rem;border-radius:3px}}
.motivation{{font-size:.7rem;font-weight:600;padding:.15rem .4rem;border-radius:3px;
  letter-spacing:.04em;color:#fff;text-transform:uppercase}}
.mot-ransomware{{background:var(--mot-ransomware)}}
.mot-destructive{{background:var(--mot-destructive)}}
.mot-espionage{{background:var(--mot-espionage)}}
.mot-financial{{background:var(--mot-financial)}}
.mot-hacktivism{{background:var(--mot-hacktivism)}}
.mot-iab{{background:var(--mot-iab)}}

.heat{{background:var(--surface);border:1px solid var(--border);border-radius:6px;
  padding:.6rem .75rem;overflow-x:auto}}
.heat-header{{display:grid;grid-template-columns:14rem repeat({HEATMAP_MONTHS}, minmax(2.6rem, 1fr));
  gap:2px;align-items:end;color:var(--text-dim);font-size:.7rem;
  margin-bottom:.35rem;padding-bottom:.35rem;border-bottom:1px solid var(--border)}}
.heat-header .h-spacer{{}}
.heat-mh{{text-align:center;line-height:1.2}}
.heat-mh .yr{{color:var(--text-dim);opacity:.7}}
.heat-row{{display:grid;grid-template-columns:14rem 1fr;gap:.5rem;
  align-items:center;padding:.15rem 0}}
.heat-label{{font-size:.78rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--text)}}
.heat-label a{{color:inherit;text-decoration:none}}
.heat-label a:hover{{color:var(--accent);text-decoration:underline}}
.heat-cells{{display:grid;grid-template-columns:repeat({HEATMAP_MONTHS}, minmax(2.6rem, 1fr));gap:2px}}
.heat-cell{{height:1.85rem;display:flex;align-items:center;justify-content:center;
  font-size:.74rem;font-weight:600;border-radius:3px;color:#0d141d;
  font-variant-numeric:tabular-nums}}
.heat-cell.h0{{background:var(--h0);color:transparent}}
.heat-cell.h1{{background:var(--h1);color:#dde6f0}}
.heat-cell.h2{{background:var(--h2);color:#fff}}
.heat-cell.h3{{background:var(--h3);color:#fff}}
.heat-cell.h4{{background:var(--h4);color:#fff}}
.heat-cell.h5{{background:var(--h5);color:#fff}}
.legend{{margin-top:.6rem;display:flex;align-items:center;gap:.4rem;
  font-size:.72rem;color:var(--text-dim)}}
.legend .swatch{{width:1.2rem;height:.9rem;border-radius:2px;display:inline-block}}
.foot{{color:var(--text-dim);font-size:.72rem;margin-top:1rem}}
.foot a{{color:var(--text-dim)}}
@media (max-width:760px){{
  .heat-header,.heat-cells{{grid-template-columns:repeat({HEATMAP_MONTHS}, minmax(2.1rem, 1fr))}}
  .heat-row{{grid-template-columns:9rem 1fr}}
  td.notes{{display:none}}
}}
</style>
</head>
<body>
<header>
  <div class="brand">HHS / NIH <span class="accent">Threat Actor Priority</span>
    <span class="sub">{len(actors)} actors tracked · last build {build_time_iso}</span>
  </div>
  <a class="nav-link" href="./index.html">&larr; Matrix</a>
  <a class="nav-link" href="./metrics.html">Metrics</a>
  <a class="nav-link" href="./cti.html">CTI Hub</a>
  <button id="modeToggle" title="Toggle theme">☼</button>
</header>

<main>
  <div class="kpis">
    <div class="kpi"><div class="num">{len(actors)}</div><div class="lbl">Actors tracked</div></div>
    <div class="kpi"><div class="num">{active_30d}</div><div class="lbl">Active last 30d</div></div>
    <div class="kpi"><div class="num">{active_90d}</div><div class="lbl">Active last 90d</div></div>
    <div class="kpi"><div class="num">{high_sev}</div><div class="lbl">High-severity tracked</div></div>
    <div class="kpi"><div class="num">{total_mentions_3m}</div><div class="lbl">Mentions last 90d</div></div>
  </div>

  <h2>Priority list <span class="hint">— sorted by composite score (recency · severity · sector fit)</span></h2>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Actor</th><th>Origin</th><th>Motivation</th>
        <th class="num" title="Curated 0–3 fit to HHS / NIH targeting">Fit</th>
        <th class="num" title="Mentions in current month">30d</th>
        <th class="num" title="Mentions last 90 days">90d</th>
        <th class="num" title="Mentions last 12 months">12m</th>
        <th class="num">Score</th>
        <th>Notes</th>
      </tr>
    </thead>
    <tbody>
      {priority_rows_html}
    </tbody>
  </table>

  <h2>Activity heatmap <span class="hint">— top {min(HEATMAP_TOP_N, len(heat_rows))} actors with mentions over the last {HEATMAP_MONTHS} months</span></h2>
  <div class="heat">
    <div class="heat-header">
      <div class="h-spacer"></div>
      {heat_header_cells}
    </div>
    {heat_body_html or '<div style="padding:1rem;color:var(--text-dim)">No mention data yet — the CTI feed window may be sparse, or the curated alias list may need tuning.</div>'}
    <div class="legend">
      <span>Mentions:</span>
      <span class="swatch h0"></span>0
      <span class="swatch h1"></span>1–2
      <span class="swatch h2"></span>3–5
      <span class="swatch h3"></span>6–10
      <span class="swatch h4"></span>11–20
      <span class="swatch h5"></span>21+
    </div>
  </div>

  <div class="foot">
    Built {build_time_iso} from <code>tools/threat_actors_hhs.json</code> ({len(actors)} entries) and
    the rolling CTI Hub state. Scoring: <code>recency·0.5 + severity·0.25 + sector_fit·0.75</code>
    where recency = (last 30d × 3) + (last 90d × 1), severity is motivation-based
    (ransomware/destructive = 3.0, IAB = 2.5, financial/espionage = 2.0, hacktivism = 1.0),
    and sector_fit is a 0–3 curated fit-to-HHS/NIH score. Edit
    <a href="https://github.com/{OWNER}/{REPO}/blob/{BRANCH}/tools/threat_actors_hhs.json" target="_blank" rel="noopener">the actor list</a>
    to tune.
  </div>
</main>

<script>
(() => {{
  const body = document.body, toggle = document.getElementById('modeToggle');
  function applyMode(light) {{
    body.classList.toggle('light', light);
    toggle.textContent = light ? '☽' : '☼';
  }}
  applyMode(localStorage.getItem('prefersLight') === 'true');
  toggle.addEventListener('click', () => {{
    const toLight = !body.classList.contains('light');
    applyMode(toLight);
    localStorage.setItem('prefersLight', toLight);
  }});
}})();
</script>
</body></html>
"""

OUTPUT.parent.mkdir(exist_ok=True)
OUTPUT.write_text(HTML, encoding="utf-8")
print(f"{OUTPUT} rebuilt — {len(actors)} actors, {sum(r['total_12m'] for r in scored)} mentions in 12m window, {active_30d} active in last 30d")
