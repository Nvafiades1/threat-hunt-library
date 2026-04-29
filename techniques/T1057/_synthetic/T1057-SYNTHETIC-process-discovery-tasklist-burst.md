### MITRE Technique ID
T1057

### Threat Hunt ID
TH-SYNTH-026

### Created
2026-03-25T12:00:00Z

### Last Modified
2026-03-25T12:00:00Z

### Hypothesis
Adversaries enumerate running processes via tasklist.exe / Get-Process to identify AV/EDR. Bursts of these from a single user are a hunt seed.

### Applicable ATT&CK Tactic(s)
- [x] Discovery

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Sentinel

### Data Sources
Defender for Endpoint, Sysmon EID 1.

### Hunt Query
```
DeviceProcessEvents
| where FileName in~ ("tasklist.exe","qprocess.exe") or
       (FileName =~ "powershell.exe" and ProcessCommandLine has "Get-Process")
| summarize execs=count() by AccountName, DeviceName, bin(Timestamp, 5m)
| where execs >= 3
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
MuddyWater

### Observed Indicators (IOCs)
Multiple process-discovery binaries within 5min, often paired with systeminfo / whoami / net commands.

### Supporting Evidence / Screenshots
_no response_

### Severity
Low

### Confidence
Medium

### Query Fidelity
Low

### Status
Completed

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Investigate originating user session; check parent process chain; review subsequent commands.

### Next Steps
Hunt T1018 (Remote System Discovery) on same session.

### Additional Tags
synthetic, demo, discovery
