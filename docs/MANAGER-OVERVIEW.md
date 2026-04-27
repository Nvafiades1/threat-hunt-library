# Threat Hunt Library — Manager Overview

> **A single, MITRE ATT&CK-aligned home for every threat hunt the team runs.**
> Hunters work in GitHub. Findings archive themselves. You watch progress on a Kanban board and KPIs on a live dashboard.

---

## What it gives the team

- **One source of truth.** Every completed hunt is committed as a versioned markdown file under the technique it covers — searchable, auditable, timestamped.
- **No knowledge decay.** Findings don't live in chat threads or personal notebooks. The next time someone hunts T1059 (PowerShell), prior hunts and threat-actor context are already there.
- **Coverage at a glance.** A live MITRE ATT&CK matrix shows which techniques the team has hunted vs. not, lighting up green as work completes.
- **Auto-enriched intelligence.** When a hunt names a threat actor (APT29, Midnight Blizzard, FIN7, UNC5221, etc.), automation pulls a full MITRE / MISP profile — TTPs, attributed campaigns, recommended mitigations, primary research reports as IOC sources — and attaches it to the issue. Hunters don't waste time on manual lookups.

## How the team uses it

1. **Propose** — analyst opens a Threat Hunt issue (technique ID, hypothesis, query, severity).
2. **Triage** — issue lands on the Project board, **Backlog** column.
3. **Execute** — analyst moves the card to **In Progress**, runs the hunt in the SIEM/EDR.
4. **Review** — moves to **Peer Review**, second analyst validates.
5. **Archive** — moving to **Completed** closes the issue. Automation files the hunt under `techniques/T####/`, rebuilds the matrix, and updates the metrics dashboard.

No separate paperwork. The Kanban card *is* the hunt.

## What you'll want to look at

| Where | What it shows | When |
|---|---|---|
| **[Project Board](https://github.com/users/Nvafiades1/projects/3)** | Live status of every hunt (Backlog / Ready / In Progress / Peer Review / Completed) | Daily — throughput, who owns what, what's stuck |
| **[Metrics Dashboard](https://nvafiades1.github.io/threat-hunt-library/metrics.html)** | KPIs: total hunts, techniques covered, threat actors tracked, coverage %, monthly trend, top techniques, severity / confidence mix | Weekly or monthly review |
| **[Live MITRE Matrix](https://nvafiades1.github.io/threat-hunt-library/)** | All 14 ATT&CK tactics; techniques marked green where we have coverage | Audit prep, gap analysis, planning |
| **[Repository](https://github.com/Nvafiades1/threat-hunt-library)** | Every committed hunt + threat-actor profiles + automation source | Drill-down on a specific finding or campaign |

## KPIs worth tracking

- **Coverage %** — fraction of MITRE ATT&CK techniques with at least one hunt. Shown live in the matrix and metrics page header.
- **Hunts per month** — throughput trend. Climbing = healthy program.
- **Top threat actors** — what the team is paying attention to.
- **Severity distribution** — quality of findings (Critical/High/Medium/Low/Informational).
- **Visibility gaps** — every hunt captures what the team *couldn't* see. Aggregated, this surfaces telemetry investments worth making.

## What "good" looks like

- Coverage % climbs steadily, even slowly. Even 1–2 new techniques per month compounds.
- Backlog is non-empty (someone always proposing) but doesn't grow unbounded.
- Hunts in **Peer Review** turn over within a few days — review is happening.
- Severity isn't 100% Informational; the team is finding things worth investigating.

## Where to ask questions

- **For status / process** → the Threat Hunt Library owner.
- **For a specific hunt** → the corresponding issue on the Project board.
- **For technical questions about the automation** → the [repository README](https://github.com/Nvafiades1/threat-hunt-library#readme).

---

*Auto-generated documentation. Last rebuilt with this commit; see the repo's commit history for changes.*
