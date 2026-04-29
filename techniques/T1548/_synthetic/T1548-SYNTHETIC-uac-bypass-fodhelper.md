### MITRE Technique ID
T1548

### Threat Hunt ID
TH-SYNTH-017

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
UAC bypass via fodhelper / computerdefaults / sdclt registry hijack is a stable technique used by Kimsuky and others.

### Applicable ATT&CK Tactic(s)
- [x] Privilege Escalation

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Sentinel

### Data Sources
Defender for Endpoint DeviceRegistryEvents.

### Hunt Query
```
DeviceRegistryEvents
| where RegistryKey has_any (
    "\\Software\\Classes\\ms-settings\\Shell\\Open\\command",
    "\\Software\\Classes\\Folder\\Shell\\Open\\command",
    "\\Software\\Classes\\exefile\\Shell\\runas\\command")
| where RegistryValueName == "DelegateExecute" or RegistryValueData has_any (".exe",".ps1",".bat")
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Kimsuky

### Observed Indicators (IOCs)
Modification of HKCU\Software\Classes for ms-settings, exefile, Folder; DelegateExecute value cleared then set; subsequent fodhelper.exe spawn.

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
Remove rogue registry entries; image host; rotate user credentials.

### Next Steps
Hunt T1059 (Command and Scripting Interpreter) for spawned payload.

### Additional Tags
synthetic, demo, privilege-escalation
