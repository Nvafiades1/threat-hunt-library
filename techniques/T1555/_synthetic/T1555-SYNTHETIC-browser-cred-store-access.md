### MITRE Technique ID
T1555

### Threat Hunt ID
TH-SYNTH-024

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Browser-stored credentials (Chrome Login Data, Edge / Brave SQLite stores) are commonly stolen by infostealers and FIN7 droppers.

### Applicable ATT&CK Tactic(s)
- [x] Credential Access

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
CrowdStrike

### Data Sources
EDR file-open telemetry, Sysmon EID 11.

### Hunt Query
```
event_simpleName=FileOpenInfo
| search TargetFileName IN ("*\\Login Data","*\\Cookies","*\\Web Data")
| search NOT ImageFileName=("*chrome.exe","*msedge.exe","*brave.exe","*firefox.exe")
| stats count BY ComputerName ImageFileName TargetFileName
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
FIN7

### Observed Indicators (IOCs)
Non-browser process opening browser SQLite; SELECT against Login Data from cmd.exe-spawned processes; staging of decrypted creds in Temp.

### Supporting Evidence / Screenshots
_no response_

### Severity
High

### Confidence
Medium

### Query Fidelity
Medium

### Status
In Progress

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Image host; force pwd reset for any creds in browser store; block AppLocker on suspicious binary.

### Next Steps
Hunt T1567 (Exfil Over Web Service) for stolen-cred upload.

### Additional Tags
synthetic, demo, credential-access
