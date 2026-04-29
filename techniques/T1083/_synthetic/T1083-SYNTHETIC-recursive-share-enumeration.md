### MITRE Technique ID
T1083

### Threat Hunt ID
TH-SYNTH-025

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Pre-encryption and pre-exfil, ransomware operators enumerate file shares looking for valuable data — this produces a burst of file-system discovery.

### Applicable ATT&CK Tactic(s)
- [x] Discovery

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Windows file-share access events (EID 5140/5145), file-server audit logs.

### Hunt Query
```
index=wineventlog EventCode=5145
| stats dc(ShareName) AS shares dc(RelativeTargetName) AS files BY src_user src_ip _time
| where files >= 1000
| sort - files
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
LockBit

### Observed Indicators (IOCs)
Single user enumerating thousands of files across shares in <1h; access patterns matching tools like SoftPerfect Network Scanner or Lazagne.

### Supporting Evidence / Screenshots
_no response_

### Severity
Medium

### Confidence
Medium

### Query Fidelity
Medium

### Status
Completed

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Disable user; image source host; review file-server access logs for exfil-staged files.

### Next Steps
Hunt T1567 (Exfil Over Web Service) for upload of staged data.

### Additional Tags
synthetic, demo, discovery
