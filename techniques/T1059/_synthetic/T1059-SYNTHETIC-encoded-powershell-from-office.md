### MITRE Technique ID
T1059

### Threat Hunt ID
TH-SYNTH-009

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
MuddyWater spawns base64-encoded PowerShell from Office processes (WINWORD/EXCEL/OUTLOOK) — a high-fidelity phishing-execution chain.

### Applicable ATT&CK Tactic(s)
- [x] Execution

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Defender XDR

### Data Sources
Defender for Endpoint DeviceProcessEvents, Sysmon EID 1.

### Hunt Query
```
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc","-encodedcommand","-e ")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
MuddyWater

### Observed Indicators (IOCs)
Office app → powershell.exe with -enc; nested cmd.exe → powershell.exe spawn from explorer.exe via macro.

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
Block child-process creation from Office via ASR rule; quarantine endpoint; decode and analyze script.

### Next Steps
Pivot to T1071 (Application Layer Protocol) for C2 callouts from decoded script.

### Additional Tags
synthetic, demo, execution
