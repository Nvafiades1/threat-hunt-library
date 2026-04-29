### MITRE Technique ID
T1486

### Threat Hunt ID
TH-SYNTH-039

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Ransomware encryption produces a burst of file rename + write events with new extensions across a single host or share.

### Applicable ATT&CK Tactic(s)
- [x] Impact

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
CrowdStrike

### Data Sources
EDR file-rename events, Sysmon EID 11, file-server audit.

### Hunt Query
```
event_simpleName=FileRenameInfo
| eval new_ext=mvindex(split(NewFileName, "."), -1)
| where len(new_ext) IN (4,5,6,7,8) AND match(new_ext, "[a-z0-9]{5,}")
| stats dc(NewFileName) AS files BY ComputerName new_ext _time
| where files >= 200
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
LockBit

### Observed Indicators (IOCs)
>200 file renames with same extension within 5min; ransom note files (README.txt, !!!HELP!!!.txt) appearing in many directories; volume shadow copy deletion immediately preceding.

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
Isolate host immediately; trigger IR; restore from immutable backup; rotate all admin creds.

### Next Steps
Hunt T1490 (Inhibit Recovery), T1070 (Indicator Removal) on same host.

### Additional Tags
synthetic, demo, impact
