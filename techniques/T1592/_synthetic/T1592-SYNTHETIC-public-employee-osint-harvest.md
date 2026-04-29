### MITRE Technique ID
T1592

### Threat Hunt ID
TH-SYNTH-002

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Threat actors are scraping public-facing employee data (LinkedIn, GitHub, conference talks) to seed phishing pretext. APT29 has used targeted spearphishing keyed to recent presentations and posts.

### Applicable ATT&CK Tactic(s)
- [x] Reconnaissance

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Sentinel

### Data Sources
Microsoft Sentinel SigninLogs, Defender for Office EmailEvents

### Hunt Query
```
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| join kind=leftouter (
    EmailEvents | where Subject has_any ("conference","speaker","interview")
) on $left.UserPrincipalName == $right.RecipientEmailAddress
| project UserPrincipalName, IPAddress, Subject, SenderFromAddress
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT29 (Cozy Bear)

### Observed Indicators (IOCs)
External email referencing recent public talks/posts, sender domains registered <30 days, lookalike employer domains.

### Supporting Evidence / Screenshots
_no response_

### Severity
Low

### Confidence
Low

### Query Fidelity
Low

### Status
In Progress

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Run targeted phish-resilience drill for employees with public conference appearances in last 90 days.

### Next Steps
Cross-reference with T1566 (Phishing) hunt findings.

### Additional Tags
synthetic, demo, reconnaissance
