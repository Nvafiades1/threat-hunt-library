### MITRE Technique ID
T1112

### Threat Hunt ID
TH-SYNTH-021

### Created
2026-03-06T12:00:00Z

### Last Modified
2026-03-06T12:00:00Z

### Hypothesis
Ransomware operators (Conti, BlackBasta) disable AV/EDR via registry tampering before payload deploy. Modifications to HKLM\SOFTWARE\Policies\Microsoft\Windows Defender are a strong signal.

### Applicable ATT&CK Tactic(s)
- [x] Defense Evasion

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Sentinel

### Data Sources
Defender for Endpoint DeviceRegistryEvents, Sysmon EID 13.

### Hunt Query
```
DeviceRegistryEvents
| where RegistryKey has_any (
    "\\Microsoft\\Windows Defender",
    "\\Policies\\Microsoft\\Windows Defender",
    "\\CrowdStrike", "\\SentinelOne")
| where ActionType == "RegistryValueSet"
| where RegistryValueData == "1" and RegistryValueName has_any ("DisableAntiSpyware","DisableRealtimeMonitoring")
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Conti

### Observed Indicators (IOCs)
Registry sets disabling Defender / EDR; service stops on EDR services; tamper-protection alert events.

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
Treat host as imminent ransomware risk; isolate; revert registry; image; page IR.

### Next Steps
Hunt T1486 (Data Encrypted for Impact) on host and lateral peers.

### Additional Tags
synthetic, demo, defense-evasion
