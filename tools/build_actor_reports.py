#!/usr/bin/env python3
"""
Generate per-actor HTML reports for any actor that's ever appeared in the top 10
of the priority list. Refreshable independently of the monthly priority build,
so the "Recent activity" section stays current as new feed items arrive.

Reads:
  • tools/threat_actors_hhs.json — curated actor metadata.
  • tools/threat_actors_state.json — top10_history (set) and per-month mention
    counts written by build_threat_actors.py.
  • tools/cti_state.json — rolling CTI Hub state for recent-items section.
  • MITRE ATT&CK Enterprise STIX (downloaded; 24h on-disk cache) for techniques
    and software attributed to each actor's MITRE Group id.

Writes one HTML page per actor: docs/actors/<slug>.html.

Cadence: invoked by .github/workflows/build_actor_reports.yml on a daily cron,
and chained off build_threat_actors.yml on the monthly priority refresh so any
new top-10 entrants get their report on first appearance.
"""
from __future__ import annotations

import html
import json
import pathlib
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import requests

# ── config ──────────────────────────────────────────────────────────────────

ROOT          = pathlib.Path(__file__).resolve().parent.parent
ACTORS_FILE   = ROOT / "tools" / "threat_actors_hhs.json"
ACTOR_STATE   = ROOT / "tools" / "threat_actors_state.json"
CTI_STATE     = ROOT / "tools" / "cti_state.json"
OUT_DIR       = ROOT / "docs" / "actors"
STIX_URL      = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
STIX_CACHE    = ROOT / "tools" / ".stix-cache.json"
CACHE_MAX_AGE = 86400  # 24 h

OWNER, REPO, BRANCH = "Nvafiades1", "threat-hunt-library", "main"

HEATMAP_MONTHS    = 12
RECENT_DAYS       = 90
RECENT_ITEM_LIMIT = 50      # cap the recent-items table

# ── helpers ─────────────────────────────────────────────────────────────────

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

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

def month_keys(n: int) -> list[str]:
    out = []
    cur = now_utc().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    for _ in range(n):
        out.append(cur.strftime("%Y-%m"))
        cur = (cur - timedelta(days=1)).replace(day=1)
    return list(reversed(out))

def fmt_relative(dt: datetime, now: datetime) -> str:
    delta = now - dt
    if delta.total_seconds() < 0:
        return dt.strftime("%Y-%m-%d")
    if delta.days < 1:
        h = int(delta.total_seconds() // 3600)
        return f"{h}h ago" if h >= 1 else "just now"
    if delta.days < 30:
        return f"{delta.days}d ago"
    if delta.days < 365:
        return f"{delta.days // 30}mo ago"
    return dt.strftime("%Y-%m-%d")

# ── STIX loading ────────────────────────────────────────────────────────────

def load_stix() -> dict:
    """Return STIX bundle, using on-disk cache when fresh."""
    try:
        if STIX_CACHE.exists() and (time.time() - STIX_CACHE.stat().st_mtime) < CACHE_MAX_AGE:
            return json.loads(STIX_CACHE.read_text())
    except Exception:
        pass
    print(f"  fetching STIX bundle from MITRE ...", file=sys.stderr)
    try:
        r = requests.get(STIX_URL, timeout=120)
        r.raise_for_status()
        data = r.json()
        STIX_CACHE.parent.mkdir(parents=True, exist_ok=True)
        STIX_CACHE.write_text(json.dumps(data))
        return data
    except Exception as e:
        print(f"  STIX fetch failed: {e} — TTP / software sections will be empty", file=sys.stderr)
        return {"objects": []}

def index_stix(stix: dict) -> dict:
    """Map MITRE Group id (G####) -> {techniques: [...], software: [...]}."""
    objects = stix.get("objects", [])
    by_id = {o.get("id"): o for o in objects if o.get("id")}

    set_to_gid: dict[str, str] = {}
    for o in objects:
        if o.get("type") != "intrusion-set":
            continue
        for ref in (o.get("external_references") or []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                set_to_gid[o["id"]] = ref["external_id"]
                break

    out: dict[str, dict] = defaultdict(lambda: {"techniques": [], "software": []})
    for o in objects:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses":
            continue
        gid = set_to_gid.get(o.get("source_ref"))
        if not gid:
            continue
        tgt = by_id.get(o.get("target_ref"))
        if not tgt:
            continue
        if tgt.get("type") == "attack-pattern":
            tid = None
            for ref in (tgt.get("external_references") or []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id")
                    break
            if not tid:
                continue
            tactics = [
                (p.get("phase_name") or "").replace("-", " ").title()
                for p in (tgt.get("kill_chain_phases") or [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]
            out[gid]["techniques"].append({
                "id":      tid,
                "name":    tgt.get("name", ""),
                "tactics": tactics,
            })
        elif tgt.get("type") in ("malware", "tool"):
            out[gid]["software"].append({
                "name": tgt.get("name", ""),
                "type": tgt.get("type"),
            })

    # Dedup + sort
    for gid, d in out.items():
        seen = set()
        d["techniques"] = [t for t in sorted(d["techniques"], key=lambda x: x["id"])
                           if not (t["id"] in seen or seen.add(t["id"]))]
        seen = set()
        d["software"] = [s for s in sorted(d["software"], key=lambda x: x["name"].lower())
                         if not (s["name"].lower() in seen or seen.add(s["name"].lower()))]
    return dict(out)

# ── HTML rendering ──────────────────────────────────────────────────────────

CSS = """
:root {
  --bg:#0f1620; --surface:#17202c; --surface-2:#1e2833; --border:#2a3644;
  --text:#e6ecf2; --text-dim:#8a97a8; --accent:#e87722; --good:#2fbf71;
  --chip-bg:#243142; --chip-fg:#a9b4c2;
  --bar:#5b75a0; --bar-now:#e87722;
  --mot-ransomware:#dc2626; --mot-destructive:#b91c1c; --mot-espionage:#7c3aed;
  --mot-financial:#0891b2; --mot-hacktivism:#65a30d; --mot-iab:#a16207;
  --cat-vendor:#1e7ad6; --cat-news:#7c3aed; --cat-gov:#0891b2;
  --cat-vuln:#b45309; --cat-ioc:#65a30d;
  --font-sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
}
body.light {
  --bg:#f6f6f6; --surface:#ffffff; --surface-2:#fafbfc; --border:#dfe3e8;
  --text:#23394a; --text-dim:#5b6a7a; --accent:#c75f11; --good:#17905a;
  --chip-bg:#eef1f5; --chip-fg:#4a5a6c;
  --bar:#719ec7; --bar-now:#c75f11;
}
*{box-sizing:border-box} html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--text);font-family:var(--font-sans);font-size:14px;line-height:1.45;-webkit-font-smoothing:antialiased}
header{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:.75rem;
  padding:.6rem 1rem;background:var(--surface);border-bottom:1px solid var(--border)}
.brand{font-weight:600;font-size:1.05rem;margin-right:auto}
.brand .accent{color:var(--accent)}
.brand .sub{color:var(--text-dim);font-size:.78rem;font-weight:400;margin-left:.5rem}
.nav-link{color:var(--text-dim);text-decoration:none;font-size:.82rem;
  padding:.3rem .55rem;border:1px solid var(--border);border-radius:4px}
.nav-link:hover{color:var(--accent);border-color:var(--accent)}
#modeToggle{cursor:pointer;font-size:1rem;background:none;color:var(--text);
  border:1px solid var(--border);border-radius:4px;padding:.3rem .55rem}
main{max-width:1200px;margin:0 auto;padding:1.5rem 1.25rem 4rem}
.hero h1{font-size:1.6rem;margin:0 0 .35rem}
.hero .aliases{color:var(--text-dim);font-size:.8rem}
.hero .aliases .chip{display:inline-block;background:var(--chip-bg);color:var(--chip-fg);
  padding:.1rem .45rem;border-radius:3px;margin:.1rem .25rem .1rem 0;font-size:.72rem}
.metagrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
  gap:.75rem;margin:1rem 0 1.4rem}
.meta{background:var(--surface);border:1px solid var(--border);
  border-radius:8px;padding:.7rem .85rem}
.meta .lbl{font-size:.7rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px}
.meta .val{font-size:1.1rem;margin-top:.2rem}
.fit-dots{display:inline-flex;gap:3px;vertical-align:middle;margin-left:.5rem}
.fit-dot{width:.55rem;height:.55rem;border-radius:50%;background:var(--border)}
.fit-dot.on{background:var(--accent)}
.motivation{font-size:.7rem;font-weight:600;padding:.15rem .45rem;border-radius:3px;
  letter-spacing:.04em;color:#fff;text-transform:uppercase;display:inline-block}
.mot-ransomware{background:var(--mot-ransomware)}
.mot-destructive{background:var(--mot-destructive)}
.mot-espionage{background:var(--mot-espionage)}
.mot-financial{background:var(--mot-financial)}
.mot-hacktivism{background:var(--mot-hacktivism)}
.mot-iab{background:var(--mot-iab)}
h2{font-size:1.05rem;margin:1.6rem 0 .55rem;display:flex;align-items:baseline;gap:.4rem}
h2 .hint{color:var(--text-dim);font-size:.78rem;font-weight:400}
.note{background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:.85rem 1rem;color:var(--text)}
.spark-wrap{background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:.85rem 1rem;display:flex;flex-direction:column;gap:.6rem}
.spark{display:flex;align-items:flex-end;gap:3px;height:64px}
.spark .bar{flex:1;background:var(--bar);border-radius:2px 2px 0 0;min-height:1px;
  transition:opacity .15s}
.spark .bar:hover{opacity:.7}
.spark .bar.now{background:var(--bar-now)}
.spark-axis{display:flex;gap:3px;font-size:.65rem;color:var(--text-dim);font-variant-numeric:tabular-nums}
.spark-axis div{flex:1;text-align:center}
.totals{display:flex;gap:1.2rem;font-size:.85rem;color:var(--text-dim)}
.totals b{color:var(--text);font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--surface);
  border:1px solid var(--border);border-radius:6px;overflow:hidden;font-size:.85rem}
thead th{background:var(--surface-2);text-align:left;font-size:.7rem;
  text-transform:uppercase;letter-spacing:.04em;color:var(--text-dim);
  padding:.5rem .65rem;border-bottom:1px solid var(--border)}
tbody td{padding:.5rem .65rem;border-bottom:1px solid var(--border);vertical-align:top}
tbody tr:hover{background:var(--surface-2)}
td.date{color:var(--text-dim);white-space:nowrap;font-variant-numeric:tabular-nums;width:6rem}
td.src{color:var(--text-dim);white-space:nowrap;width:11rem}
td.title a{color:var(--text);text-decoration:none}
td.title a:hover{color:var(--accent);text-decoration:underline}
.cat{font-size:.65rem;font-weight:600;padding:.1rem .35rem;border-radius:3px;
  text-transform:uppercase;letter-spacing:.04em;color:#fff;display:inline-block}
.cat-vendor{background:var(--cat-vendor)} .cat-news{background:var(--cat-news)}
.cat-gov{background:var(--cat-gov)} .cat-vuln{background:var(--cat-vuln)}
.cat-ioc{background:var(--cat-ioc)}
.empty{padding:1rem;color:var(--text-dim);background:var(--surface);
  border:1px solid var(--border);border-radius:8px;font-size:.85rem}
.tags{display:flex;flex-wrap:wrap;gap:.3rem;background:var(--surface);
  border:1px solid var(--border);border-radius:8px;padding:.7rem 1rem}
.tags .tag{font-size:.72rem;padding:.15rem .5rem;background:var(--chip-bg);
  color:var(--chip-fg);border-radius:3px;font-family:"SF Mono","Menlo",Consolas,monospace}
.tags .tag.tool{font-family:var(--font-sans);font-size:.74rem}
.foot{color:var(--text-dim);font-size:.72rem;margin-top:1.5rem;line-height:1.55}
.foot a{color:var(--text-dim)}
@media (max-width:680px){.metagrid{grid-template-columns:1fr 1fr}}
"""

THEME_JS = """
(() => {
  const body = document.body, toggle = document.getElementById('modeToggle');
  function applyMode(light) {
    body.classList.toggle('light', light);
    toggle.textContent = light ? '☽' : '☼';
  }
  applyMode(localStorage.getItem('prefersLight') === 'true');
  toggle.addEventListener('click', () => {
    const toLight = !body.classList.contains('light');
    applyMode(toLight);
    localStorage.setItem('prefersLight', toLight);
  });
})();
"""

def render_sparkline(monthly: list[int], months: list[str]) -> str:
    if not monthly:
        return ""
    mx = max(monthly) or 1
    bars = []
    for i, c in enumerate(monthly):
        h = max(2, round(c / mx * 56)) if c else 1
        cls = "bar now" if i == len(monthly) - 1 else "bar"
        bars.append(f'<div class="{cls}" style="height:{h}px" title="{months[i]}: {c} mention{"s" if c != 1 else ""}"></div>')
    axis = "".join(f'<div>{m[5:7]}</div>' for m in months)
    return (
        f'<div class="spark">{"".join(bars)}</div>'
        f'<div class="spark-axis">{axis}</div>'
    )

def render_recent_items(items: list[dict], now: datetime) -> str:
    if not items:
        return f'<div class="empty">No feed items in the last {RECENT_DAYS} days mention this actor.</div>'
    rows = []
    for it in items[:RECENT_ITEM_LIMIT]:
        pub = parse_pub(it)
        date_str = fmt_relative(pub, now) if pub else "?"
        cat = it.get("category", "")
        cat_html = f'<span class="cat cat-{esc(cat)}">{esc(cat)}</span>' if cat else ""
        title = (it.get("title") or "").strip() or "(untitled)"
        url = it.get("url", "")
        link = f'<a href="{esc(url)}" target="_blank" rel="noopener">{esc(title)}</a>' if url else esc(title)
        rows.append(
            f'<tr><td class="date">{esc(date_str)}</td>'
            f'<td class="src">{esc(it.get("source", "?"))}</td>'
            f'<td>{cat_html}</td>'
            f'<td class="title">{link}</td></tr>'
        )
    cap_note = ""
    if len(items) > RECENT_ITEM_LIMIT:
        cap_note = f'<div class="foot" style="margin-top:.5rem">Showing {RECENT_ITEM_LIMIT} of {len(items)} matching items.</div>'
    return (
        f'<table>'
        f'<thead><tr><th>When</th><th>Source</th><th>Cat.</th><th>Title</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        f'</table>{cap_note}'
    )

def render_ttps(ttps: list[dict]) -> str:
    if not ttps:
        return f'<div class="empty">No MITRE-attributed techniques (actor has no MITRE Group id, or STIX returned no relationships).</div>'
    chips = []
    for t in ttps:
        tactic = t["tactics"][0] if t.get("tactics") else ""
        chips.append(
            f'<a class="tag" href="https://attack.mitre.org/techniques/{esc(t["id"].replace(".", "/"))}/" '
            f'target="_blank" rel="noopener" title="{esc(tactic)}">{esc(t["id"])} {esc(t["name"])}</a>'
        )
    return f'<div class="tags">{"".join(chips)}</div>'

def render_software(software: list[dict]) -> str:
    if not software:
        return f'<div class="empty">No MITRE-attributed software.</div>'
    chips = []
    for s in software:
        chips.append(
            f'<span class="tag tool" title="{esc(s["type"])}">{esc(s["name"])}</span>'
        )
    return f'<div class="tags">{"".join(chips)}</div>'

def render_report(actor: dict, monthly: list[int], months: list[str],
                  recent: list[dict], ioc_count: int,
                  ttps: list[dict], software: list[dict],
                  build_time: datetime) -> str:
    name = actor["name"]
    aliases = [a for a in actor.get("aliases", []) if a and a != name]
    aliases_html = "".join(f'<span class="chip">{esc(a)}</span>' for a in aliases)
    motivation = (actor.get("motivation") or "").lower()
    mot_label = motivation.title() if motivation else "?"
    fit = actor.get("sector_fit", 0)
    fit_dots = "".join(
        f'<span class="fit-dot{" on" if i < fit else ""}"></span>' for i in range(3)
    )
    mid = actor.get("mitre_id", "")
    mid_html = (
        f'<a href="https://attack.mitre.org/groups/{esc(mid)}/" target="_blank" rel="noopener">{esc(mid)}</a>'
        if mid else '<span style="color:var(--text-dim)">—</span>'
    )
    last_30d = sum(1 for it in recent if (parse_pub(it) or build_time) > build_time - timedelta(days=30))
    last_90d = len(recent)
    total_12m = sum(monthly)
    sparkline = render_sparkline(monthly, months)
    recent_table = render_recent_items(recent, build_time)
    ttps_html = render_ttps(ttps)
    software_html = render_software(software)

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(name)} — HHS / NIH Threat Actor Report</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <div class="brand">{esc(name)} <span class="accent">·</span>
    <span class="sub">Threat Actor Report — built {esc(build_time.strftime("%Y-%m-%d %H:%M UTC"))}</span>
  </div>
  <a class="nav-link" href="../threat-actors.html">&larr; Priority list</a>
  <a class="nav-link" href="../cti.html">CTI Hub</a>
  <a class="nav-link" href="../index.html">Matrix</a>
  <button id="modeToggle" title="Toggle theme">☼</button>
</header>

<main>
  <section class="hero">
    <h1>{esc(name)}</h1>
    <div class="aliases">{aliases_html or '<span style="color:var(--text-dim)">No additional aliases tracked.</span>'}</div>
  </section>

  <div class="metagrid">
    <div class="meta">
      <div class="lbl">Origin</div>
      <div class="val">{esc(actor.get("origin", "?"))}</div>
    </div>
    <div class="meta">
      <div class="lbl">Motivation</div>
      <div class="val"><span class="motivation mot-{esc(slugify(motivation))}">{esc(mot_label)}</span></div>
    </div>
    <div class="meta">
      <div class="lbl">Sector fit (HHS / NIH)</div>
      <div class="val">{fit} / 3 <span class="fit-dots">{fit_dots}</span></div>
    </div>
    <div class="meta">
      <div class="lbl">MITRE Group</div>
      <div class="val">{mid_html}</div>
    </div>
    <div class="meta">
      <div class="lbl">Mentions last 30d</div>
      <div class="val">{last_30d}</div>
    </div>
    <div class="meta">
      <div class="lbl">Mentions last 90d</div>
      <div class="val">{last_90d}</div>
    </div>
    <div class="meta">
      <div class="lbl">IOC indicators last 90d</div>
      <div class="val">{ioc_count}</div>
    </div>
  </div>

  <h2>Summary <span class="hint">— curated</span></h2>
  <div class="note">{esc(actor.get("notes", "No curated note."))}</div>

  <h2>Mention timeline <span class="hint">— last {HEATMAP_MONTHS} months · current month highlighted</span></h2>
  <div class="spark-wrap">
    {sparkline}
    <div class="totals">
      <span>30d <b>{last_30d}</b></span>
      <span>90d <b>{last_90d}</b></span>
      <span>12m <b>{total_12m}</b></span>
    </div>
  </div>

  <h2>Recent activity <span class="hint">— feed items in last {RECENT_DAYS} days</span></h2>
  {recent_table}

  <h2>MITRE techniques <span class="hint">— attributed to this group in ATT&CK</span></h2>
  {ttps_html}

  <h2>Software <span class="hint">— malware &amp; tools attributed to this group</span></h2>
  {software_html}

  <div class="foot">
    Auto-generated from <code>tools/threat_actors_hhs.json</code>, the rolling CTI Hub state,
    and MITRE ATT&amp;CK Enterprise STIX. Recent-activity refreshes daily;
    summary metadata + sector fit are curated and update only when
    <a href="https://github.com/{OWNER}/{REPO}/blob/{BRANCH}/tools/threat_actors_hhs.json" target="_blank" rel="noopener">the JSON</a>
    changes. Built {esc(build_time.strftime("%Y-%m-%d %H:%M UTC"))}.
  </div>
</main>

<script>{THEME_JS}</script>
</body></html>
"""

# ── main ────────────────────────────────────────────────────────────────────

def main() -> int:
    actors_list = json.loads(ACTORS_FILE.read_text())
    actors_by_name = {a["name"]: a for a in actors_list}
    state = json.loads(ACTOR_STATE.read_text()) if ACTOR_STATE.exists() else {}
    items = json.loads(CTI_STATE.read_text()).get("items", []) if CTI_STATE.exists() else []

    top10_history = sorted(set(state.get("top10_history") or []))
    if not top10_history:
        print("No actors in top10_history yet — run build_threat_actors.py first.", file=sys.stderr)
        return 0

    historic = state.get("by_actor", {})
    months = month_keys(HEATMAP_MONTHS)
    build_time = now_utc()

    # Pre-compile per-actor regex.
    for a in actors_list:
        aliases = sorted({x for x in a.get("aliases", []) if x}, key=len, reverse=True)
        a["_re"] = re.compile(
            r"\b(?:" + "|".join(re.escape(x) for x in aliases) + r")\b",
            re.IGNORECASE,
        ) if aliases else None

    # Pre-bucket recent items per actor (for actors in top10_history only).
    # IOC-category items go to a separate count: ThreatFox / URLhaus rows are
    # tagged with the malware family and would otherwise drown the table in
    # mechanical infrastructure entries. The narrative "Recent activity"
    # table holds vendor / news / gov / vuln items only.
    cutoff = build_time - timedelta(days=RECENT_DAYS)
    recent_by_actor: dict[str, list[dict]] = defaultdict(list)
    ioc_count_by_actor: dict[str, int] = defaultdict(int)
    in_scope = {a["name"]: a for a in actors_list if a["name"] in set(top10_history)}
    for it in items:
        pub = parse_pub(it)
        if not pub or pub < cutoff:
            continue
        text = " ".join([
            it.get("title", "") or "",
            it.get("summary", "") or "",
            " ".join(it.get("tags", []) or []),
            it.get("source", "") or "",
        ])
        for name, a in in_scope.items():
            if a["_re"] and a["_re"].search(text):
                if it.get("category") == "ioc":
                    ioc_count_by_actor[name] += 1
                else:
                    recent_by_actor[name].append(it)

    # MITRE STIX
    print("Loading MITRE STIX ...")
    stix = load_stix()
    stix_index = index_stix(stix)
    print(f"  STIX indexed: {len(stix_index)} groups")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for name in top10_history:
        actor = actors_by_name.get(name)
        if not actor:
            print(f"  warning: '{name}' is in top10_history but missing from threat_actors_hhs.json — skipping", file=sys.stderr)
            continue

        slug = slugify(name)
        monthly = [historic.get(name, {}).get(m, 0) for m in months]

        # Dedup recent items by URL (or id), preserve newest
        seen, deduped = set(), []
        for it in sorted(
            recent_by_actor.get(name, []),
            key=lambda x: parse_pub(x) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        ):
            key = it.get("url") or it.get("id")
            if key in seen:
                continue
            seen.add(key)
            deduped.append(it)

        gid = (actor.get("mitre_id") or "").strip()
        ttps = stix_index.get(gid, {}).get("techniques", []) if gid else []
        sw   = stix_index.get(gid, {}).get("software", [])   if gid else []

        ioc_n = ioc_count_by_actor.get(name, 0)
        out_file = OUT_DIR / f"{slug}.html"
        out_file.write_text(render_report(actor, monthly, months, deduped, ioc_n, ttps, sw, build_time))
        written += 1
        print(f"  {out_file.relative_to(ROOT)}: {len(deduped)} recent items, {ioc_n} IOC, {len(ttps)} TTPs, {len(sw)} software")

    print(f"Done. {written} actor reports written to {OUT_DIR.relative_to(ROOT)}/.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
