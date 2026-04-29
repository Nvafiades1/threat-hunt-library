### MITRE Technique ID
T1543

### Threat Hunt ID
TH-SYNTH-013

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Malicious actors install Windows services (e.g. fake-named like WindowsUpdateSvc, OneDriveSync) that point to user-writable paths or non-vendor binaries. Sandworm has used this for backdoor persistence.

### Applicable ATT&CK Tactic(s)
- [x] Persistence

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Windows System log EID 7045, Sysmon EID 1 with parent=services.exe.

### Hunt Query
```
index=wineventlog EventCode=7045
| rex field=Message "Service Name:\s+(?<svc_name>[^\n]+)"
| rex field=Message "Service File Name:\s+(?<svc_path>[^\n]+)"
| where match(svc_path, "(?i)(\\AppData\\|\\Temp\\|\\PerfLogs\\|\\Users\\Public)") OR
        match(svc_path, "(?i)\.(ps1|bat|vbs|js)$")
| stats count earliest(_time) AS first BY ComputerName svc_name svc_path
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Sandworm

### Observed Indicators (IOCs)
New services with binary paths in user-writable directories, scripts as ImagePath, services that don't appear on standard image baseline.

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
Stop + remove unauthorized service; rotate creds for the install user; image for forensics; check for additional persistence (T1547, T1053).

### Next Steps
Pivot to T1003 (Credential Dumping) on the install host.

### Additional Tags
synthetic, demo, persistence
