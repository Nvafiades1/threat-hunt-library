### MITRE Technique ID
T1218

### Threat Hunt ID
TH-SYNTH-020

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
rundll32.exe loading DLLs from user-writable paths or with unusual export names is a frequent LOLBin technique. Mustang Panda uses sideloading via rundll32 frequently.

### Applicable ATT&CK Tactic(s)
- [x] Defense Evasion

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Defender XDR

### Data Sources
Defender for Endpoint, Sysmon EID 1, Windows Application log.

### Hunt Query
```
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine matches regex "(?i)(AppData|Temp|Public|ProgramData)\\\\.+\\.dll"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Mustang Panda

### Observed Indicators (IOCs)
rundll32 with full path to user-writable DLL, exports named DllRegisterServer or random strings, no parent process auth.

### Supporting Evidence / Screenshots
_no response_

### Severity
High

### Confidence
Medium

### Query Fidelity
Medium

### Status
Completed

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Quarantine DLL; image host; rotate cred for invoking user.

### Next Steps
Hunt T1071 (App Layer Protocol) for outbound C2 from spawned thread.

### Additional Tags
synthetic, demo, defense-evasion
