### MITRE Technique ID
T1056

### Threat Hunt ID
TH-SYNTH-031

### Created
2026-04-06T12:00:00Z

### Last Modified
2026-04-06T12:00:00Z

### Hypothesis
Keyloggers register via the SetWindowsHookEx API or as low-level keyboard drivers. Installation often coincides with Run-key persistence.

### Applicable ATT&CK Tactic(s)
- [x] Collection

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
CrowdStrike

### Data Sources
EDR process-creation events, ETW WindowsKernel hook telemetry.

### Hunt Query
```
event_simpleName=ProcessRollup2
| search CommandLine="*SetWindowsHookEx*" OR CommandLine="*WH_KEYBOARD*"
| stats count BY ComputerName ImageFileName CommandLine
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Charming Kitten (APT35)

### Observed Indicators (IOCs)
API call sequences SetWindowsHookEx + WH_KEYBOARD; new keyboard-class driver loads; persistence + low-level network in same session.

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
Image host; rotate all credentials typed since hook install (timestamp from EDR).

### Next Steps
Hunt T1041 (Exfil over C2 Channel) for keylog upload.

### Additional Tags
synthetic, demo, collection
