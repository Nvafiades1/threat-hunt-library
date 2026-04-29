### MITRE Technique ID
T1570

### Threat Hunt ID
TH-SYNTH-029

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Adversaries often copy follow-on tooling via SMB to admin$/c$ shares of a target host. Writes from non-admin source workstations are suspicious.

### Applicable ATT&CK Tactic(s)
- [x] Lateral Movement

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Windows file-share audit logs (5140/5145), EDR network connection events.

### Hunt Query
```
index=wineventlog EventCode=5145 ShareName IN ("\\\\*\\ADMIN$","\\\\*\\C$")
| where Accesses="*WriteData*"
| stats count BY src_ip src_user ShareName RelativeTargetName _time
| sort - _time
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT29 (Cozy Bear)

### Observed Indicators (IOCs)
Writes to ADMIN$/C$ from user workstations; .exe/.dll/.ps1 dropped to remote system32 path.

### Supporting Evidence / Screenshots
_no response_

### Severity
Medium

### Confidence
Medium

### Query Fidelity
Medium

### Status
In Progress

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Block SMB host-to-host across user segments; review SMB auth logs for source.

### Next Steps
Hunt T1543 (Service Creation) on the destination for service-based exec.

### Additional Tags
synthetic, demo, lateral-movement
