### MITRE Technique ID
T1070

### Threat Hunt ID
TH-SYNTH-019

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Event log clearing is a high-fidelity post-compromise signal; legitimate clears are rare and almost always from a known admin during maintenance.

### Applicable ATT&CK Tactic(s)
- [x] Defense Evasion

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Windows Security log EID 1102, System log EID 104.

### Hunt Query
```
index=wineventlog EventCode=1102 OR EventCode=104
| stats values(user) AS users count BY ComputerName _time
| sort - _time
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Sandworm

### Observed Indicators (IOCs)
Log clear by non-admin user; clear immediately preceded by an interactive logon from outside the admin baseline.

### Supporting Evidence / Screenshots
_no response_

### Severity
Critical

### Confidence
High

### Query Fidelity
High

### Status
Completed

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Treat host as compromised; image + isolate; restore log forwarding from backup if SIEM forwarding active.

### Next Steps
Hunt T1486 (Data Encrypted for Impact) — log clearing is often pre-ransomware.

### Additional Tags
synthetic, demo, defense-evasion
