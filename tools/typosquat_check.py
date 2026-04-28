#!/usr/bin/env python3
"""Detect typosquatting candidates against NIH-related seed domains.

Sources:
  1. dnstwist  — generates typo permutations and DNS-resolves them
  2. NRD list  — newly-registered-domains (cenk/nrd, last 10 days)
  3. crt.sh    — Certificate Transparency log search

State persists in tools/typosquat_state.json so we track first_seen per finding.
"""
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

SEEDS = [
    "nih.gov",
    "nlm.nih.gov",
    "cc.nih.gov",
    "niaid.nih.gov",
    "cancer.gov",
    "clinicaltrials.gov",
]

NRD_URL = "https://raw.githubusercontent.com/cenk/nrd/main/nrd-last-10-days.txt"
CRT_URL = "https://crt.sh/?q={q}&output=json"
STATE_PATH = Path("tools/typosquat_state.json")
USER_AGENT = "threat-hunt-library-bot/1.0 (+https://github.com/Nvafiades1/threat-hunt-library)"

DNSTWIST_THREADS = 30
DNSTWIST_TIMEOUT = 600
CRT_TIMEOUT = 45
CRT_RATE_DELAY = 0.4
RETENTION_DAYS = 60

# Known-legitimate US government / sibling domains that share letters with NIH-family
# seeds and consistently surface as false positives. Anything matching is dropped
# from candidate output AND retroactively pruned from existing state.
ALLOWLIST = {
    "neh.gov",        # National Endowment for the Humanities
    "nh.gov",         # State of New Hampshire
    "nij.gov",        # National Institute of Justice
    "nsf.gov",        # National Science Foundation
    "noaa.gov",       # NOAA
    "nara.gov",       # National Archives
    "nasa.gov",       # NASA
    "usa.gov",        # USA.gov
    "dol.gov",        # Department of Labor
    "doi.gov",        # Department of the Interior
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except json.JSONDecodeError:
            pass
    return {"items": {}, "last_run": None}


def save_state(state: dict):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True))


def run_dnstwist(seed: str) -> list[dict]:
    """Run dnstwist with DNS resolution enabled. Returns list of permutation dicts.
    Each dict has at minimum 'domain'; registered ones also have 'dns_a', 'dns_mx', etc.
    """
    try:
        r = subprocess.run(
            ["dnstwist", "--format", "json", "--threads", str(DNSTWIST_THREADS), seed],
            capture_output=True, text=True, timeout=DNSTWIST_TIMEOUT,
        )
        if r.returncode != 0:
            print(f"  [warn] dnstwist failed for {seed} (rc={r.returncode}): "
                  f"{r.stderr[:300]}", file=sys.stderr)
            return []
        return json.loads(r.stdout) if r.stdout.strip() else []
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"  [warn] dnstwist error for {seed}: {type(e).__name__}: {e}", file=sys.stderr)
        return []


def fetch_nrd() -> set[str]:
    """Download cenk/nrd 10-day NRD list as a set of lowercased domains."""
    try:
        r = requests.get(NRD_URL, timeout=60, headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        return {
            line.strip().lower()
            for line in r.text.splitlines()
            if line and not line.startswith("#") and "." in line
        }
    except requests.RequestException as e:
        print(f"  [warn] NRD fetch failed: {e}", file=sys.stderr)
        return set()


def crt_query(domain: str) -> list[dict]:
    """Query crt.sh for a domain. Returns list of cert records (may be empty)."""
    try:
        r = requests.get(
            CRT_URL.format(q=domain),
            timeout=CRT_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        if r.status_code != 200 or not r.text.strip():
            return []
        try:
            return r.json()
        except json.JSONDecodeError:
            return []
    except requests.RequestException:
        return []


def main():
    print(f"[{now_iso()}] Typosquat check starting (seeds: {len(SEEDS)})")

    state = load_state()
    items: dict[str, dict] = state.get("items", {})

    # Retroactively drop any allowlisted false positives that landed in state
    # before the allowlist existed.
    pre_allow = len(items)
    items = {p: it for p, it in items.items() if p not in ALLOWLIST}
    if len(items) < pre_allow:
        print(f"  removed {pre_allow - len(items)} allowlisted entries from existing state")

    # 1. Run dnstwist for each seed (generates perms + DNS resolves)
    all_perms: dict[str, str] = {}        # permutation -> originating seed
    dns_results: dict[str, dict] = {}     # permutation -> {a, mx}
    for seed in SEEDS:
        t0 = time.time()
        rows = run_dnstwist(seed)
        for row in rows:
            d = (row.get("domain") or "").lower().strip()
            if not d or d == seed.lower() or d in ALLOWLIST:
                continue
            if d not in all_perms:
                all_perms[d] = seed
            a = row.get("dns_a") or []
            mx = bool(row.get("dns_mx"))
            if a:
                dns_results[d] = {"a": a[:5], "mx": mx}
        print(f"  [perm] {seed}: {len(rows)} permutations, "
              f"{sum(1 for r in rows if r.get('dns_a'))} resolved, took {time.time()-t0:.1f}s")
    print(f"[{now_iso()}] total unique permutations: {len(all_perms)}, "
          f"DNS-active: {len(dns_results)}")
    if not all_perms:
        print("  no permutations — aborting", file=sys.stderr)
        sys.exit(1)

    # 2. NRD intersection
    print(f"[{now_iso()}] fetching NRD list…")
    nrd_set = fetch_nrd()
    nrd_hits = {p for p in all_perms if p in nrd_set}
    print(f"  NRD set size: {len(nrd_set)}, intersect: {len(nrd_hits)}")

    # 3. crt.sh — only for candidates we have other reason to investigate.
    candidates = set(dns_results) | nrd_hits
    print(f"[{now_iso()}] querying crt.sh for {len(candidates)} candidates "
          f"(rate-limit {CRT_RATE_DELAY}s/req)…")
    ct_results: dict[str, dict] = {}
    for i, p in enumerate(sorted(candidates), 1):
        certs = crt_query(p)
        if certs:
            certs_sorted = sorted(certs, key=lambda c: c.get("not_before", ""))
            ct_results[p] = {
                "issuer": certs_sorted[0].get("issuer_name", "")[:80],
                "first_issued": certs_sorted[0].get("not_before"),
                "cert_count": len(certs),
            }
        if i % 25 == 0:
            print(f"  …crt.sh progress {i}/{len(candidates)}")
        time.sleep(CRT_RATE_DELAY)
    print(f"  CT hits: {len(ct_results)}")

    # 4. Merge into persistent state
    now = now_iso()
    for p in candidates:
        seed = all_perms[p]
        existing = items.get(p, {})
        sources = set(existing.get("sources", []))
        if p in dns_results:
            sources.add("dnstwist")
        if p in nrd_hits:
            sources.add("nrd")
        if p in ct_results:
            sources.add("crt.sh")
        items[p] = {
            "domain": p,
            "seed": seed,
            "sources": sorted(sources),
            "first_seen": existing.get("first_seen") or now,
            "last_seen": now,
            "dns": dns_results.get(p) or existing.get("dns"),
            "nrd": p in nrd_hits or existing.get("nrd", False),
            "ct": ct_results.get(p) or existing.get("ct"),
        }

    # 5. Prune entries last_seen older than RETENTION_DAYS
    cutoff = datetime.now(timezone.utc).timestamp() - RETENTION_DAYS * 86400
    pruned = {
        p: it for p, it in items.items()
        if (parse_iso(it.get("last_seen")) or datetime.now(timezone.utc)).timestamp() >= cutoff
    }
    dropped = len(items) - len(pruned)
    if dropped:
        print(f"  pruned {dropped} stale entries (>{RETENTION_DAYS}d since last_seen)")

    state["items"] = pruned
    state["last_run"] = now
    state["seeds"] = SEEDS
    save_state(state)
    print(f"[{now_iso()}] done. {len(pruned)} active typosquat candidates.")


if __name__ == "__main__":
    main()
