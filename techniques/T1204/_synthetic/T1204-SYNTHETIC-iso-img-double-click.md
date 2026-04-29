### MITRE Technique ID
T1204

### Threat Hunt ID
TH-SYNTH-011

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
ISO/IMG containers bypass MOTW and are mounted by users from email — a common APT29 technique. Mount events on user workstations are rare.

### Applicable ATT&CK Tactic(s)
- [x] Execution

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Defender XDR

### Data Sources
Defender for Endpoint DeviceFileEvents/DeviceProcessEvents.

### Hunt Query
```
DeviceFileEvents
| where FileName endswith ".iso" or FileName endswith ".img" or FileName endswith ".vhd"
| where InitiatingProcessFileName in~ ("explorer.exe","outlook.exe","chrome.exe","msedge.exe")
| join kind=inner DeviceProcessEvents on DeviceId
| where InitiatingProcessFolderPath has "Volume{" or InitiatingProcessFolderPath matches regex "[A-Z]:\\\\.*\\\\.*\\.iso"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT29 (Cozy Bear)

### Observed Indicators (IOCs)
ISO mount followed by LNK execution → DLL sideload (e.g., wabmig.exe + evil DLL), HTA execution, or signed-binary proxy.

### Supporting Evidence / Screenshots
_no response_

### Severity
High

### Confidence
High

### Query Fidelity
Medium

### Status
Completed

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Group Policy: block ISO/IMG/VHD mounting via file-association GPO; quarantine endpoint; collect mounted-image contents.

### Next Steps
Pivot to T1218 (System Binary Proxy Execution) for sideloaded DLL hunt.

### Additional Tags
synthetic, demo, execution
