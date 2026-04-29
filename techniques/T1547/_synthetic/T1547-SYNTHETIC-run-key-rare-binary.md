### MITRE Technique ID
T1547

### Threat Hunt ID
TH-SYNTH-012

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
New entries in HKCU/HKLM Run/RunOnce keys pointing to binaries outside Program Files, Windows, or known vendor paths are likely persistence.

### Applicable ATT&CK Tactic(s)
- [x] Persistence

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
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    "\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce")
| where RegistryValueData !startswith "C:\\Program Files" and
        RegistryValueData !startswith "C:\\Windows" and
        RegistryValueData !startswith "\"C:\\Program Files"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Turla

### Observed Indicators (IOCs)
Run-key values in user-writable paths (AppData, Temp, Public), random filenames, references to scripting interpreters.

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
Validate against software install records; remove if unauthorized; image host for forensics.

### Next Steps
Hunt T1027 (Obfuscated Files) on the dropped binary.

### Additional Tags
synthetic, demo, persistence
