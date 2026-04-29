### MITRE Technique ID
T1567

### Threat Hunt ID
TH-SYNTH-037

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Adversaries use legit cloud storage (mega.nz, anonfiles, tmpfiles) for exfil to bypass DLP. Endpoint connections to those domains warrant review.

### Applicable ATT&CK Tactic(s)
- [x] Exfiltration

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Defender XDR

### Data Sources
Defender for Endpoint DeviceNetworkEvents, web proxy logs.

### Hunt Query
```
DeviceNetworkEvents
| where RemoteUrl has_any (
    "mega.nz","anonfiles.com","tmpfiles.org","transfer.sh","filebin.net","gofile.io")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, BytesSent
| where BytesSent > 1000000
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Lazarus Group

### Observed Indicators (IOCs)
Outbound to file-sharing services from non-browser process; large POST (>1MB) to those domains; staged archives in Temp before connection.

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
Block file-sharing domains at proxy; image host; review files in process working dir.

### Next Steps
Hunt T1560 for archives; T1003 if creds were in scope.

### Additional Tags
synthetic, demo, exfiltration
