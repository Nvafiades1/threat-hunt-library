### MITRE Technique ID
T1003

### Threat Hunt ID
TH-SYNTH-022

### Created
2026-03-10T12:00:00Z

### Last Modified
2026-03-10T12:00:00Z

### Hypothesis
LSASS handle/memory access by processes other than antivirus or lsm.exe/wininit.exe is a high-fidelity dumping signal.

### Applicable ATT&CK Tactic(s)
- [x] Credential Access

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Defender XDR

### Data Sources
Defender for Endpoint DeviceEvents (OpenProcess), Sysmon EID 10.

### Hunt Query
```
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where TargetProcessFileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","MsSense.exe","wininit.exe","lsm.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT29 (Cozy Bear)

### Observed Indicators (IOCs)
comsvcs.dll MiniDump, rundll32 → lsass, mimikatz signatures, ProcDump command line targeting lsass.

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
Image host; rotate all interactive-cred passwords used on host in last 7d; revoke Kerberos tickets via krbtgt rotation if domain controller.

### Next Steps
Hunt T1550 (Use Alt Auth Material) — pass-the-hash/ticket downstream.

### Additional Tags
synthetic, demo, credential-access
