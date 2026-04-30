#!/usr/bin/env python3
"""Push threat hunts from this repo to Splunk via HTTP Event Collector (HEC).

Reads every markdown file under techniques/ (excluding READMEs), parses the
`### Section` blocks the same way build_metrics.py does, and POSTs one event
per hunt to the configured HEC endpoint.

Environment / CLI:
  SPLUNK_HEC_URL    e.g. https://localhost:8088 (no trailing path)
  SPLUNK_HEC_TOKEN  HEC token (Splunk admin → Data inputs → HTTP Event Collector)
  SPLUNK_INDEX      target index name (default: threat_hunts)
  SPLUNK_VERIFY_TLS "true" / "false" (default: false for local self-signed)

Run with --dry-run to print the payloads that *would* be sent without contacting
Splunk. Use this for review before pointing at a real endpoint.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from datetime import datetime, timezone
from urllib import request, error

ROOT      = pathlib.Path(__file__).resolve().parents[1]
TECH_DIR  = ROOT / "techniques"

_section_re = re.compile(r"^###\s+(.+?)\s*$")
_hr_re      = re.compile(r"^[-=_*]{3,}\s*$")
_meta_re    = re.compile(r"^\*\*[^*:]+:\*\*")
_none_values = {"", "_no response_", "n/a", "none", "tbd"}


def parse_hunt(text: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        m = _section_re.match(line)
        if m:
            current = m.group(1).strip()
            sections.setdefault(current, [])
            continue
        if _hr_re.match(line) or _meta_re.match(line):
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


def parse_iso(s: str) -> str | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def collect_hunts() -> list[pathlib.Path]:
    if not TECH_DIR.exists():
        sys.exit(f"techniques/ not found at {TECH_DIR}")
    out: list[pathlib.Path] = []
    for sub in sorted(TECH_DIR.iterdir()):
        if not sub.is_dir() or not sub.name.startswith("T"):
            continue
        for f in sub.rglob("*.md"):
            if f.is_file() and f.name.lower() != "readme.md":
                out.append(f)
    return out


def hunt_to_event(path: pathlib.Path, source_url: str) -> dict:
    text   = path.read_text("utf-8", "ignore")
    fields = parse_hunt(text)
    parent_folder = path.relative_to(TECH_DIR).parts[0]
    body_techs = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)
    primary = (fields.get("MITRE Technique ID", "").strip().splitlines() or [parent_folder])[0]
    actor_raw = fields.get("Threat Actor", "").strip()
    actors = [a.strip() for a in re.split(r"[,;/]", actor_raw) if a.strip()]
    rel_path = str(path.relative_to(ROOT))

    event = {
        "hunt_id":      fields.get("Threat Hunt ID", path.stem),
        "title":        path.stem,
        "technique_id": primary or parent_folder,
        "all_technique_ids": sorted(set([primary] + body_techs)) if primary else sorted(set(body_techs)),
        "tactic_checked": fields.get("Applicable ATT&CK Tactic(s)", "").strip(),
        "hypothesis":   fields.get("Hypothesis", ""),
        "data_sources": fields.get("Data Sources", ""),
        "platform":     fields.get("Hunt Platform", ""),
        "spl_query":    fields.get("Hunt Query", ""),
        "severity":     fields.get("Severity", ""),
        "confidence":   fields.get("Confidence", ""),
        "fidelity":     fields.get("Query Fidelity", ""),
        "status":       fields.get("Status", ""),
        "actors":       actors,
        "indicators":   fields.get("Observed Indicators (IOCs)", ""),
        "recommended_actions": fields.get("Recommended Actions", ""),
        "next_steps":   fields.get("Next Steps", ""),
        "tags":         fields.get("Additional Tags", ""),
        "created":      parse_iso(fields.get("Created", "")),
        "last_modified":parse_iso(fields.get("Last Modified", "")),
        "repo_path":    rel_path,
        "url":          f"{source_url}/blob/main/{rel_path}",
    }
    return {k: v for k, v in event.items() if v not in (None, "", [], {})}


def post_event(url: str, token: str, index: str, event: dict, verify_tls: bool) -> None:
    payload = json.dumps({
        "event":      event,
        "sourcetype": "threat_hunt:metadata",
        "source":     "threat-hunt-library",
        "index":      index,
        "host":       "github-threat-hunt-library",
    }).encode()
    req = request.Request(
        url.rstrip("/") + "/services/collector/event",
        data=payload, method="POST",
    )
    req.add_header("Authorization", f"Splunk {token}")
    req.add_header("Content-Type", "application/json")
    if not verify_tls:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with request.urlopen(req, context=ctx, timeout=15) as r:
            return json.loads(r.read())
    else:
        with request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Print payloads instead of POSTing.")
    ap.add_argument("--limit", type=int, default=None,
                    help="Cap the number of hunts pushed (useful for first run).")
    args = ap.parse_args()

    hec_url   = os.environ.get("SPLUNK_HEC_URL", "").strip()
    hec_token = os.environ.get("SPLUNK_HEC_TOKEN", "").strip()
    index     = os.environ.get("SPLUNK_INDEX", "threat_hunts").strip()
    verify    = os.environ.get("SPLUNK_VERIFY_TLS", "false").lower() == "true"
    source_url = os.environ.get("REPO_URL", "https://github.com/Nvafiades1/threat-hunt-library")

    if not args.dry_run and (not hec_url or not hec_token):
        sys.exit("Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN, or use --dry-run.")

    paths = collect_hunts()
    if args.limit:
        paths = paths[: args.limit]
    print(f"[push] hunts found: {len(paths)} (dry_run={args.dry_run})")

    sent = 0
    failed = 0
    for p in paths:
        try:
            event = hunt_to_event(p, source_url)
        except Exception as e:
            print(f"  [skip] {p}: {type(e).__name__}: {e}")
            failed += 1
            continue
        if args.dry_run:
            print(json.dumps(event, indent=2))
            continue
        try:
            post_event(hec_url, hec_token, index, event, verify)
            sent += 1
        except error.HTTPError as e:
            print(f"  [err] {p.name}: HTTP {e.code} {e.read().decode()[:200]}")
            failed += 1
        except Exception as e:
            print(f"  [err] {p.name}: {type(e).__name__}: {e}")
            failed += 1
    print(f"[push] done. sent={sent} failed={failed}")


if __name__ == "__main__":
    main()
