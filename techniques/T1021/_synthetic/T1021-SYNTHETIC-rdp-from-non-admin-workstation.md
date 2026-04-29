### MITRE Technique ID
T1021

### Threat Hunt ID
TH-SYNTH-028

### Created
2026-03-30T12:00:00Z

### Last Modified
2026-03-30T12:00:00Z

### Hypothesis
RDP from regular user workstations to servers (or between non-admin endpoints) is rare in well-segmented environments. UNC3944 uses RDP extensively post-foothold.

### Applicable ATT&CK Tactic(s)
- [x] Lateral Movement

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Sentinel

### Data Sources
Windows EID 4624 LogonType 10, EID 4778, Sysmon network telemetry.

### Hunt Query
```
DeviceLogonEvents
| where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess"
| join kind=inner (DeviceInfo | summarize arg_max(Timestamp, *) by DeviceName)
       on DeviceName
| where DeviceCategory != "Server" and InitiatingProcessAccountName !contains "admin"
| project Timestamp, DeviceName, RemoteDeviceName, AccountName
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Scattered Spider (UNC3944)

### Observed Indicators (IOCs)
RDP between two user-class workstations; RDP from user-class to server outside change window; new-device certificates on RDP server.

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
Block RDP host-to-host with firewall rule; require RDP only from PAW; rotate user creds.

### Next Steps
Hunt T1003 (Credential Dumping) on the RDP source host.

### Additional Tags
synthetic, demo, lateral-movement
