### MITRE Technique ID
T1587

### Threat Hunt ID
TH-SYNTH-004

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Threat actors stage second-stage payloads on legitimate CDNs (GitHub Releases, jsDelivr, Discord CDN) to bypass network filtering.

### Applicable ATT&CK Tactic(s)
- [x] Resource Development

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
CrowdStrike

### Data Sources
EDR DNS telemetry, proxy URL logs

### Hunt Query
```
event_simpleName=DnsRequest
| search DomainName IN ("cdn.discordapp.com","raw.githubusercontent.com","cdn.jsdelivr.net")
| stats count BY ComputerName DomainName user_name
| where count >= 5
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT41

### Observed Indicators (IOCs)
Endpoint requests to public-CDN URLs ending in .ps1/.exe/.dll/.scr.

### Supporting Evidence / Screenshots
_no response_

### Severity
Medium

### Confidence
Low

### Query Fidelity
Medium

### Status
Inconclusive

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Block direct binary downloads from public CDNs at the proxy unless explicitly whitelisted per business unit.

### Next Steps
Pivot to T1059 (Command Interpreter) for any matched downloads that executed.

### Additional Tags
synthetic, demo, resource-development
