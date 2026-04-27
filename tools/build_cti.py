#!/usr/bin/env python3
"""
Generate docs/cti.html — Open-source CTI Hub.

Pulls RSS / JSON / CSV from a curated list of public threat-intel sources,
normalizes everything to a common schema, merges into a rolling 30-day state
file, and renders a single static HTML dashboard.

Sources require no API keys. Any single source failure is logged and skipped;
the build succeeds as long as one source returns data.
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import pathlib
import re
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import feedparser
import requests

# ── config ───────────────────────────────────────────────────────────────────

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE_PATH = ROOT / "tools" / "cti_state.json"
OUT_PATH = ROOT / "docs" / "cti.html"

ROLLING_DAYS = 30
HTTP_TIMEOUT = 25
MAX_WORKERS = 10
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 "
    "threat-hunt-library-cti-bot/1.0 (+https://github.com/Nvafiades1/threat-hunt-library)"
)

# (display name, category, fetcher key, url)
# categories: vendor | news | gov | vuln | ioc
SOURCES = [
    # Vendor research
    ("CrowdStrike",             "vendor", "rss",  "https://www.crowdstrike.com/blog/feed/"),
    ("Microsoft Security Blog", "vendor", "rss",  "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Cisco Talos",             "vendor", "rss",  "https://feeds.feedburner.com/feedburner/Talos"),
    ("Unit 42 (Palo Alto)",     "vendor", "rss",  "https://feeds.feedburner.com/Unit42"),
    ("SentinelOne Labs",        "vendor", "rss",  "https://www.sentinelone.com/labs/feed/"),
    ("Trend Micro Research",    "vendor", "rss",  "https://news.trendmicro.com/feed/"),
    ("Securelist (Kaspersky)",  "vendor", "rss",  "https://securelist.com/feed/"),
    ("ESET WeLiveSecurity",     "vendor", "rss",  "https://www.welivesecurity.com/en/rss/feed/"),

    # News & industry
    ("BleepingComputer",        "news",   "rss",  "https://www.bleepingcomputer.com/feed/"),
    ("The Record",              "news",   "rss",  "https://therecord.media/feed/"),
    ("Krebs on Security",       "news",   "rss",  "https://krebsonsecurity.com/feed/"),
    ("The Hacker News",         "news",   "rss",  "https://feeds.feedburner.com/TheHackersNews"),
    ("Dark Reading",            "news",   "rss",  "https://www.darkreading.com/rss.xml"),
    ("SecurityWeek",            "news",   "rss",  "https://feeds.feedburner.com/securityweek"),

    # Government / advisories
    ("CISA Advisories",         "gov",    "rss",  "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("NCSC-UK",                 "gov",    "rss",  "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"),

    # Vulnerabilities (JSON)
    ("CISA KEV Catalog",        "vuln",   "kev",  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),

    # IOCs (CSV)
    ("abuse.ch URLhaus",        "ioc",    "urlhaus",       "https://urlhaus.abuse.ch/downloads/csv_recent/"),
    ("abuse.ch MalwareBazaar",  "ioc",    "malwarebazaar", "https://bazaar.abuse.ch/export/csv/recent/"),
    ("abuse.ch ThreatFox",      "ioc",    "threatfox",     "https://threatfox.abuse.ch/export/csv/recent/"),
]

# ── helpers ──────────────────────────────────────────────────────────────────

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_dt(value) -> datetime | None:
    """Best-effort datetime parser for whatever feeds throw at us."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, time.struct_time):
        return datetime.fromtimestamp(time.mktime(value), tz=timezone.utc)
    s = str(value).strip()
    for parser in (parsedate_to_datetime,):
        try:
            dt = parser(s)
            if dt:
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None

def make_id(source: str, url: str) -> str:
    return hashlib.sha256(f"{source}|{url}".encode()).hexdigest()[:16]

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

def strip_html(s: str, limit: int = 320) -> str:
    if not s:
        return ""
    text = _TAG_RE.sub(" ", s)
    text = html.unescape(text)
    text = _WS_RE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text

def http_get(url: str, accept: str = "*/*") -> bytes:
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    r = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT, allow_redirects=True)
    r.raise_for_status()
    return r.content

# ── fetchers ─────────────────────────────────────────────────────────────────

def fetch_rss(name: str, category: str, url: str) -> list[dict]:
    raw = http_get(url, accept="application/rss+xml, application/atom+xml, application/xml, text/xml, */*")
    feed = feedparser.parse(raw)
    items = []
    for entry in feed.entries[:50]:  # cap per source to keep state manageable
        link = entry.get("link") or entry.get("id") or ""
        if not link:
            continue
        title = strip_html(entry.get("title") or "(untitled)", limit=300)
        summary = strip_html(entry.get("summary") or entry.get("description") or "", limit=320)
        published = (
            parse_dt(entry.get("published_parsed"))
            or parse_dt(entry.get("updated_parsed"))
            or parse_dt(entry.get("published"))
            or parse_dt(entry.get("updated"))
        )
        tags = []
        for tag in entry.get("tags", []) or []:
            term = (tag.get("term") or "").strip()
            if term and len(term) <= 40 and len(tags) < 6:
                tags.append(term)
        items.append({
            "id": make_id(name, link),
            "source": name,
            "category": category,
            "title": title,
            "url": link,
            "published": iso(published) if published else None,
            "summary": summary,
            "tags": tags,
        })
    return items

def fetch_kev(name: str, category: str, url: str) -> list[dict]:
    data = json.loads(http_get(url, accept="application/json"))
    items = []
    for v in (data.get("vulnerabilities") or [])[:200]:
        cve = v.get("cveID") or ""
        if not cve:
            continue
        link = f"https://nvd.nist.gov/vuln/detail/{cve}"
        title = f"{cve} — {v.get('vulnerabilityName') or v.get('product') or 'Known Exploited Vulnerability'}"
        summary = strip_html(v.get("shortDescription") or "", limit=320)
        published = parse_dt(v.get("dateAdded"))
        vendor = v.get("vendorProject") or ""
        product = v.get("product") or ""
        tags = [t for t in [vendor, product, "KEV"] if t][:5]
        items.append({
            "id": make_id(name, cve),
            "source": name,
            "category": category,
            "title": strip_html(title, limit=300),
            "url": link,
            "published": iso(published) if published else None,
            "summary": summary,
            "tags": tags,
        })
    return items

def _read_abuse_csv(raw: bytes) -> list[list[str]]:
    text = raw.decode("utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    return list(csv.reader(lines, quotechar='"', skipinitialspace=True))

def fetch_urlhaus(name: str, category: str, url: str) -> list[dict]:
    rows = _read_abuse_csv(http_get(url, accept="text/csv"))
    items = []
    for row in rows[:300]:
        # id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        if len(row) < 8:
            continue
        ioc_url = row[2]
        date_added = row[1]
        threat = row[5]
        tag_field = row[6]
        urlhaus_link = row[7]
        reporter = row[8] if len(row) > 8 else ""
        tags = [t for t in [threat, *[s for s in tag_field.split(",") if s][:3]] if t][:5]
        items.append({
            "id": make_id(name, urlhaus_link or ioc_url),
            "source": name,
            "category": category,
            "title": f"Malicious URL: {ioc_url[:140]}",
            "url": urlhaus_link or ioc_url,
            "published": iso(parse_dt(date_added)) if parse_dt(date_added) else None,
            "summary": f"Threat: {threat or 'unknown'}. Reporter: {reporter or 'n/a'}.",
            "tags": tags,
        })
    return items

def fetch_malwarebazaar(name: str, category: str, url: str) -> list[dict]:
    rows = _read_abuse_csv(http_get(url, accept="text/csv"))
    items = []
    for row in rows[:300]:
        # first_seen_utc, sha256, md5, sha1, reporter, file_name, file_type_guess,
        # mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh
        if len(row) < 9:
            continue
        first_seen = row[0]
        sha256 = row[1]
        file_name = row[5]
        file_type = row[6]
        signature = row[8] or "unknown"
        link = f"https://bazaar.abuse.ch/sample/{sha256}/"
        tags = [t for t in [signature, file_type] if t][:4]
        items.append({
            "id": make_id(name, sha256),
            "source": name,
            "category": category,
            "title": f"Sample: {signature} ({file_name[:80] or 'unnamed'})",
            "url": link,
            "published": iso(parse_dt(first_seen)) if parse_dt(first_seen) else None,
            "summary": f"SHA256 {sha256[:24]}…  Type: {file_type or 'unknown'}.",
            "tags": tags,
        })
    return items

def fetch_threatfox(name: str, category: str, url: str) -> list[dict]:
    rows = _read_abuse_csv(http_get(url, accept="text/csv"))
    items = []
    for row in rows[:300]:
        # first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, fk_malware,
        # malware_alias, malware_printable, last_seen_utc, confidence_level,
        # reference, tags, anonymous, reporter
        if len(row) < 11:
            continue
        first_seen = row[0]
        ioc_id = row[1]
        ioc_value = row[2]
        ioc_type = row[3]
        malware = row[7] or row[5] or "unknown"
        link = f"https://threatfox.abuse.ch/ioc/{ioc_id}/"
        tag_field = row[11] if len(row) > 11 else ""
        tags = [t for t in [malware, ioc_type, *[s for s in tag_field.split(",") if s][:2]] if t][:5]
        items.append({
            "id": make_id(name, ioc_id),
            "source": name,
            "category": category,
            "title": f"{ioc_type}: {ioc_value[:120]} ({malware})",
            "url": link,
            "published": iso(parse_dt(first_seen)) if parse_dt(first_seen) else None,
            "summary": f"Malware: {malware}. IOC type: {ioc_type}.",
            "tags": tags,
        })
    return items

FETCHERS = {
    "rss":            fetch_rss,
    "kev":            fetch_kev,
    "urlhaus":        fetch_urlhaus,
    "malwarebazaar":  fetch_malwarebazaar,
    "threatfox":      fetch_threatfox,
}

# ── orchestration ────────────────────────────────────────────────────────────

def fetch_all() -> tuple[list[dict], list[dict]]:
    """Returns (items, source_status[])."""
    items: list[dict] = []
    statuses: list[dict] = []

    def _one(src):
        name, category, kind, url = src
        fetcher = FETCHERS[kind]
        t0 = time.time()
        try:
            got = fetcher(name, category, url)
            return name, category, "ok", len(got), got, round(time.time() - t0, 2), None
        except Exception as exc:
            return name, category, "error", 0, [], round(time.time() - t0, 2), f"{type(exc).__name__}: {exc}"

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(_one, src) for src in SOURCES]
        for f in as_completed(futures):
            name, category, status, count, got, took, err = f.result()
            statuses.append({
                "source": name, "category": category, "status": status,
                "count": count, "took_s": took, "error": err,
            })
            if got:
                items.extend(got)
            print(f"  [{status:5}] {name:28} {count:>4} items  ({took}s)" + (f"  — {err}" if err else ""))
    return items, statuses

def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except Exception:
            print("WARN: state file unreadable, starting fresh", file=sys.stderr)
    return {"items": [], "first_seen": {}}

def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True))

def merge(new_items: list[dict], state: dict, build_time: datetime) -> tuple[list[dict], set[str]]:
    """Merge new items into rolling state. Returns (all_items, ids_first_seen_this_build)."""
    cutoff = build_time - timedelta(days=ROLLING_DAYS)
    first_seen: dict[str, str] = state.get("first_seen", {})
    by_id: dict[str, dict] = {it["id"]: it for it in state.get("items", []) if it.get("id")}

    new_ids: set[str] = set()
    for item in new_items:
        iid = item["id"]
        if iid not in first_seen:
            first_seen[iid] = iso(build_time)
            new_ids.add(iid)
        item["first_seen"] = first_seen[iid]
        by_id[iid] = item  # newest copy wins

    pruned: list[dict] = []
    for iid, item in by_id.items():
        keep_dt = parse_dt(item.get("published")) or parse_dt(item.get("first_seen"))
        if keep_dt and keep_dt >= cutoff:
            pruned.append(item)
        elif not keep_dt:
            pruned.append(item)

    pruned.sort(
        key=lambda it: parse_dt(it.get("published")) or parse_dt(it.get("first_seen")) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    kept_ids = {it["id"] for it in pruned}
    first_seen = {k: v for k, v in first_seen.items() if k in kept_ids}

    state["items"] = pruned
    state["first_seen"] = first_seen
    return pruned, new_ids

# ── HTML rendering ───────────────────────────────────────────────────────────

NAV_HTML = """\
<nav class="thl-nav">
  <a href="index.html">Matrix</a>
  <a href="metrics.html">Metrics</a>
  <a href="cti.html" class="active">CTI Hub</a>
  <a href="https://github.com/Nvafiades1/threat-hunt-library" target="_blank" rel="noopener">GitHub ↗</a>
</nav>"""

def render_html(items: list[dict], statuses: list[dict], new_ids: set[str], build_time: datetime) -> str:
    payload = {
        "items": items,
        "statuses": statuses,
        "new_ids": sorted(new_ids),
        "build_time": iso(build_time),
        "rolling_days": ROLLING_DAYS,
    }
    payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    payload_json = payload_json.replace("</", "<\\/")  # safe inside <script>

    sources_total = len(statuses)
    sources_ok = sum(1 for s in statuses if s["status"] == "ok")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<title>CTI Hub — Threat Hunt Library</title>
<link rel="icon" href="favicon.ico">
<style>
:root {{
  --bg: #0e1117;
  --panel: #161b22;
  --panel-2: #1c2230;
  --border: #2a3140;
  --fg: #e6edf3;
  --fg-dim: #8b949e;
  --accent: #58a6ff;
  --accent-2: #79c0ff;
  --vendor: #a371f7;
  --news: #58a6ff;
  --gov: #f78166;
  --vuln: #f85149;
  --ioc: #3fb950;
  --new: #d29922;
  --shadow: 0 1px 3px rgba(0,0,0,.3);
}}
:root[data-theme="light"] {{
  --bg: #f6f8fa; --panel: #ffffff; --panel-2: #f0f3f6;
  --border: #d0d7de; --fg: #1f2328; --fg-dim: #57606a;
  --accent: #0969da; --accent-2: #0550ae;
  --vendor: #8250df; --news: #0969da; --gov: #bc4c00;
  --vuln: #cf222e; --ioc: #1a7f37; --new: #9a6700;
  --shadow: 0 1px 3px rgba(0,0,0,.08);
}}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; background: var(--bg); color: var(--fg); font: 14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; }}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.thl-nav {{
  display: flex; gap: 4px; padding: 10px 20px;
  background: var(--panel); border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 50;
}}
.thl-nav a {{
  padding: 6px 14px; border-radius: 6px; color: var(--fg-dim);
  font-weight: 500; font-size: 13px;
}}
.thl-nav a:hover {{ background: var(--panel-2); color: var(--fg); text-decoration: none; }}
.thl-nav a.active {{ background: var(--accent); color: #fff; }}
header.cti-header {{
  padding: 22px 20px 14px; border-bottom: 1px solid var(--border); background: var(--panel);
}}
header.cti-header h1 {{ margin: 0 0 4px; font-size: 22px; font-weight: 600; }}
header.cti-header .sub {{ color: var(--fg-dim); font-size: 13px; }}
.stats {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px; padding: 14px 20px; background: var(--panel);
  border-bottom: 1px solid var(--border);
}}
.stat {{
  background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px;
  padding: 10px 14px;
}}
.stat .num {{ font-size: 20px; font-weight: 600; }}
.stat .lbl {{ font-size: 11px; color: var(--fg-dim); text-transform: uppercase; letter-spacing: .5px; }}
.controls {{
  display: flex; flex-wrap: wrap; gap: 8px; padding: 12px 20px;
  background: var(--panel); border-bottom: 1px solid var(--border);
  position: sticky; top: 41px; z-index: 49;
}}
.tab {{
  padding: 6px 14px; border: 1px solid var(--border); border-radius: 999px;
  background: var(--panel-2); color: var(--fg); cursor: pointer; font-size: 12px;
  font-weight: 500;
}}
.tab.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
.controls input[type="search"], .controls select {{
  background: var(--panel-2); color: var(--fg); border: 1px solid var(--border);
  border-radius: 6px; padding: 6px 10px; font-size: 13px; min-width: 200px;
}}
.controls .spacer {{ flex: 1; }}
.theme-btn {{
  background: var(--panel-2); color: var(--fg); border: 1px solid var(--border);
  border-radius: 6px; padding: 6px 10px; cursor: pointer; font-size: 13px;
}}
main {{ padding: 16px 20px 60px; max-width: 1400px; margin: 0 auto; }}
.card {{
  background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 12px 14px; margin-bottom: 10px; box-shadow: var(--shadow);
  display: grid; grid-template-columns: auto 1fr; gap: 10px 14px;
}}
.card .badge-col {{ display: flex; flex-direction: column; gap: 4px; align-items: flex-start; min-width: 90px; }}
.cat-badge {{
  font-size: 10px; font-weight: 700; padding: 3px 7px; border-radius: 4px;
  text-transform: uppercase; letter-spacing: .5px; color: #fff;
}}
.cat-vendor {{ background: var(--vendor); }}
.cat-news   {{ background: var(--news); }}
.cat-gov    {{ background: var(--gov); }}
.cat-vuln   {{ background: var(--vuln); }}
.cat-ioc    {{ background: var(--ioc); }}
.new-badge {{
  font-size: 10px; font-weight: 700; padding: 3px 7px; border-radius: 4px;
  background: var(--new); color: #fff;
}}
.card h3 {{
  margin: 0 0 4px; font-size: 14px; font-weight: 600; line-height: 1.35;
}}
.card .meta {{ font-size: 12px; color: var(--fg-dim); margin-bottom: 4px; }}
.card .summary {{ font-size: 13px; color: var(--fg); }}
.card .tags {{ margin-top: 6px; display: flex; gap: 4px; flex-wrap: wrap; }}
.tag {{
  font-size: 11px; padding: 2px 7px; border-radius: 4px;
  background: var(--panel-2); border: 1px solid var(--border); color: var(--fg-dim);
}}
.empty {{ padding: 40px 20px; text-align: center; color: var(--fg-dim); }}
.source-status {{ font-size: 11px; color: var(--fg-dim); padding: 6px 20px; }}
.source-status .err {{ color: var(--vuln); }}
.load-more {{
  display: block; margin: 20px auto; padding: 8px 20px; background: var(--panel);
  border: 1px solid var(--border); color: var(--fg); border-radius: 6px; cursor: pointer;
}}
@media (max-width: 600px) {{
  .card {{ grid-template-columns: 1fr; }}
  .card .badge-col {{ flex-direction: row; min-width: 0; }}
  .controls {{ position: static; }}
}}
</style>
</head>
<body>
{NAV_HTML}
<header class="cti-header">
  <h1>CTI Hub</h1>
  <div class="sub">
    Aggregated threat intelligence from <strong>{sources_ok}/{sources_total}</strong> open-source feeds.
    Last built: <span id="build-time"></span>. Rolling {ROLLING_DAYS}-day window.
    All items link to original sources.
  </div>
</header>

<div class="stats">
  <div class="stat"><div class="num" id="stat-total">–</div><div class="lbl">Total items</div></div>
  <div class="stat"><div class="num" id="stat-24h">–</div><div class="lbl">Last 24h</div></div>
  <div class="stat"><div class="num" id="stat-7d">–</div><div class="lbl">Last 7d</div></div>
  <div class="stat"><div class="num" id="stat-new">–</div><div class="lbl">New this build</div></div>
  <div class="stat"><div class="num" id="stat-sources">{sources_ok}</div><div class="lbl">Sources online</div></div>
</div>

<div class="controls">
  <button class="tab active" data-cat="all">All</button>
  <button class="tab" data-cat="vendor">Vendor research</button>
  <button class="tab" data-cat="news">News</button>
  <button class="tab" data-cat="gov">Government</button>
  <button class="tab" data-cat="vuln">Vulnerabilities</button>
  <button class="tab" data-cat="ioc">IOCs</button>
  <select id="time-range">
    <option value="1">Last 24h</option>
    <option value="7" selected>Last 7d</option>
    <option value="30">Last 30d</option>
  </select>
  <select id="source-filter"><option value="">All sources</option></select>
  <input type="search" id="search" placeholder="Search title, summary, tags…">
  <div class="spacer"></div>
  <button class="theme-btn" id="theme-toggle">Theme</button>
</div>

<div class="source-status" id="source-status"></div>

<main id="list"></main>

<script id="cti-data" type="application/json">{payload_json}</script>
<script>
(function() {{
  const data = JSON.parse(document.getElementById("cti-data").textContent);
  const items = data.items;
  const newIds = new Set(data.new_ids);
  const buildTime = new Date(data.build_time);

  // theme
  const root = document.documentElement;
  const saved = localStorage.getItem("thl-theme");
  if (saved === "light") root.setAttribute("data-theme", "light");
  document.getElementById("theme-toggle").addEventListener("click", () => {{
    const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    if (next === "light") root.setAttribute("data-theme", "light");
    else root.removeAttribute("data-theme");
    localStorage.setItem("thl-theme", next);
  }});

  // build-time formatting
  document.getElementById("build-time").textContent = buildTime.toLocaleString();

  // populate source filter
  const sourceFilter = document.getElementById("source-filter");
  const sources = [...new Set(items.map(i => i.source))].sort();
  for (const s of sources) {{
    const o = document.createElement("option");
    o.value = s; o.textContent = s;
    sourceFilter.appendChild(o);
  }}

  // status line
  const statusEl = document.getElementById("source-status");
  const errs = data.statuses.filter(s => s.status !== "ok");
  if (errs.length) {{
    statusEl.innerHTML = "Sources with errors this build: " + errs.map(e =>
      `<span class="err">${{e.source}}</span>`).join(", ");
  }}

  // stats
  const now = Date.now();
  const dayMs = 86400000;
  const within = (it, days) => {{
    const d = it.published || it.first_seen;
    if (!d) return false;
    return (now - new Date(d).getTime()) <= days * dayMs;
  }};
  document.getElementById("stat-total").textContent = items.length.toLocaleString();
  document.getElementById("stat-24h").textContent = items.filter(i => within(i, 1)).length.toLocaleString();
  document.getElementById("stat-7d").textContent = items.filter(i => within(i, 7)).length.toLocaleString();
  document.getElementById("stat-new").textContent = newIds.size.toLocaleString();

  // filter state
  let activeCat = "all";
  let activeDays = 7;
  let activeSource = "";
  let activeQuery = "";
  let renderedCount = 0;
  const PAGE = 50;

  document.querySelectorAll(".tab").forEach(b => {{
    b.addEventListener("click", () => {{
      document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
      b.classList.add("active");
      activeCat = b.dataset.cat;
      rerender();
    }});
  }});
  document.getElementById("time-range").addEventListener("change", e => {{
    activeDays = parseInt(e.target.value, 10);
    rerender();
  }});
  sourceFilter.addEventListener("change", e => {{
    activeSource = e.target.value;
    rerender();
  }});
  document.getElementById("search").addEventListener("input", e => {{
    activeQuery = e.target.value.toLowerCase().trim();
    rerender();
  }});

  function fmtTime(iso) {{
    if (!iso) return "(undated)";
    const d = new Date(iso);
    const diffMs = now - d.getTime();
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return mins + "m ago";
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + "h ago";
    const days = Math.floor(hrs / 24);
    if (days < 30) return days + "d ago";
    return d.toLocaleDateString();
  }}

  function escape(s) {{
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }}

  function filtered() {{
    return items.filter(it => {{
      if (activeCat !== "all" && it.category !== activeCat) return false;
      if (!within(it, activeDays)) return false;
      if (activeSource && it.source !== activeSource) return false;
      if (activeQuery) {{
        const hay = (it.title + " " + (it.summary||"") + " " + (it.tags||[]).join(" ") + " " + it.source).toLowerCase();
        if (!hay.includes(activeQuery)) return false;
      }}
      return true;
    }});
  }}

  function cardHtml(it) {{
    const isNew = newIds.has(it.id);
    const tags = (it.tags || []).slice(0, 5).map(t => `<span class="tag">${{escape(t)}}</span>`).join("");
    return `<article class="card">
      <div class="badge-col">
        <span class="cat-badge cat-${{escape(it.category)}}">${{escape(it.category)}}</span>
        ${{isNew ? '<span class="new-badge">NEW</span>' : ''}}
      </div>
      <div>
        <h3><a href="${{escape(it.url)}}" target="_blank" rel="noopener">${{escape(it.title)}}</a></h3>
        <div class="meta">${{escape(it.source)}} · ${{escape(fmtTime(it.published || it.first_seen))}}</div>
        ${{it.summary ? `<div class="summary">${{escape(it.summary)}}</div>` : ''}}
        ${{tags ? `<div class="tags">${{tags}}</div>` : ''}}
      </div>
    </article>`;
  }}

  function rerender() {{
    const list = document.getElementById("list");
    const all = filtered();
    renderedCount = Math.min(PAGE, all.length);
    if (all.length === 0) {{
      list.innerHTML = '<div class="empty">No items match your filters.</div>';
      return;
    }}
    list.innerHTML = all.slice(0, renderedCount).map(cardHtml).join("") +
      (all.length > renderedCount ? `<button class="load-more" id="load-more">Load ${{Math.min(PAGE, all.length - renderedCount)}} more (${{all.length - renderedCount}} remaining)</button>` : "");
    const more = document.getElementById("load-more");
    if (more) more.addEventListener("click", () => {{
      renderedCount = Math.min(renderedCount + PAGE, all.length);
      rerender_append(all);
    }});
  }}

  function rerender_append(all) {{
    const list = document.getElementById("list");
    list.innerHTML = all.slice(0, renderedCount).map(cardHtml).join("") +
      (all.length > renderedCount ? `<button class="load-more" id="load-more">Load ${{Math.min(PAGE, all.length - renderedCount)}} more (${{all.length - renderedCount}} remaining)</button>` : "");
    const more = document.getElementById("load-more");
    if (more) more.addEventListener("click", () => {{
      renderedCount = Math.min(renderedCount + PAGE, all.length);
      rerender_append(all);
    }});
  }}

  rerender();
}})();
</script>
</body>
</html>
"""

# ── main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    build_time = now_utc()
    print(f"CTI build @ {iso(build_time)}")
    print(f"Sources configured: {len(SOURCES)}")
    print()

    print("Fetching sources…")
    new_items, statuses = fetch_all()
    ok_count = sum(1 for s in statuses if s["status"] == "ok")
    print(f"\nFetched {len(new_items)} items from {ok_count}/{len(statuses)} sources")

    if ok_count == 0:
        print("ERROR: every source failed; refusing to overwrite output.", file=sys.stderr)
        return 1

    print("Loading state…")
    state = load_state()
    print(f"  state has {len(state.get('items', []))} items")

    print("Merging…")
    all_items, new_ids = merge(new_items, state, build_time)
    print(f"  total {len(all_items)} items in rolling window; {len(new_ids)} new this build")

    print("Saving state…")
    save_state(state)

    print("Rendering HTML…")
    html_out = render_html(all_items, statuses, new_ids, build_time)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(html_out)
    print(f"  wrote {OUT_PATH} ({len(html_out):,} bytes)")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
