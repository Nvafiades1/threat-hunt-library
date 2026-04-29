### MITRE Technique ID
T1490

### Threat Hunt ID
TH-SYNTH-040

### Created
2026-04-28T12:00:00Z

### Last Modified
2026-04-28T12:00:00Z

### Hypothesis
Volume Shadow Copy deletion is a near-universal ransomware precursor. vssadmin / wbadmin / wmic shadowcopy commands are very high-fidelity.

### Applicable ATT&CK Tactic(s)
- [x] Impact

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Sentinel

### Data Sources
Defender for Endpoint, Sysmon EID 1, Windows Application log.

### Hunt Query
```
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "vssadmin delete shadows","vssadmin resize shadowstorage",
    "wbadmin delete catalog","wmic shadowcopy delete",
    "bcdedit /set bootstatuspolicy","bcdedit /set recoveryenabled no")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
BlackBasta

### Observed Indicators (IOCs)
vssadmin delete shadows /all /quiet; wbadmin delete catalog -quiet; bcdedit recovery disable.

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
Treat host as imminent ransomware; isolate; image; trigger IR; rotate creds.

### Next Steps
Hunt T1486 (Data Encrypted) and T1112 (Modify Registry, AV tamper).

### Additional Tags
synthetic, demo, impact
