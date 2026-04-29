### MITRE Technique ID
T1053

### Threat Hunt ID
TH-SYNTH-010

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Adversaries register scheduled tasks with non-administrative authors or NULL author fields to blend in. Most legit tasks are authored by Microsoft, vendor agents, or local admins.

### Applicable ATT&CK Tactic(s)
- [x] Execution

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Windows Task Scheduler operational log (EID 4698, 4702), Sysmon EID 4.

### Hunt Query
```
index=wineventlog EventCode=4698
| rex field=Message "Task Name:\s+(?<task_name>[^\n]+)"
| rex field=Message "Subject:\s+Account Name:\s+(?<author>[^\n]+)"
| where NOT match(author, "(?i)(SYSTEM|Administrator|svc-)")
| stats count BY ComputerName task_name author
| where count >= 1
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT41

### Observed Indicators (IOCs)
Tasks running at odd times (3am), task actions invoking powershell or rundll32, NULL author or random-string author names.

### Supporting Evidence / Screenshots
_no response_

### Severity
Medium

### Confidence
High

### Query Fidelity
High

### Status
Completed

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Disable + remove suspicious tasks; forensically image host for persistence triage.

### Next Steps
Pivot to T1547 (Boot/Logon Autostart) for additional persistence on same host.

### Additional Tags
synthetic, demo, execution
