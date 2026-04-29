### MITRE Technique ID
T1136

### Threat Hunt ID
TH-SYNTH-014

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Adversaries create new domain accounts after hours to maintain access. Account creation outside of HR onboarding windows or by non-IT principals is highly suspicious.

### Applicable ATT&CK Tactic(s)
- [x] Persistence

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Windows security event log EID 4720, AD audit logs.

### Hunt Query
```
index=wineventlog EventCode=4720
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 20
| stats count BY src_user new_user ComputerName _time
| sort - _time
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT28 (Fancy Bear)

### Observed Indicators (IOCs)
Account creation at unusual hours, by non-IT-team members, account name convention deviating from corporate standard.

### Supporting Evidence / Screenshots
_no response_

### Severity
High

### Confidence
High

### Query Fidelity
High

### Status
Completed

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Disable + audit account; check if added to privileged groups (4728/4732); review creator's session for compromise.

### Next Steps
Hunt T1078 (Valid Accounts) for use of the new account.

### Additional Tags
synthetic, demo, persistence
