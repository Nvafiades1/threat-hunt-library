### MITRE Technique ID
T1566

### Threat Hunt ID
TH-SYNTH-005

### Created
2025-12-11T12:00:00Z

### Last Modified
2025-12-11T12:00:00Z

### Hypothesis
APT29 has shifted to HTML smuggling — embedding encoded payloads in HTML attachments that decode and write a file client-side, evading gateway scanning.

### Applicable ATT&CK Tactic(s)
- [x] Initial Access

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Defender XDR

### Data Sources
Defender for Office 365 EmailEvents/EmailAttachmentInfo, endpoint DeviceFileEvents.

### Hunt Query
```
EmailAttachmentInfo
| where FileName endswith ".html" or FileName endswith ".htm"
| join kind=inner EmailEvents on NetworkMessageId
| where DeliveryAction == "Delivered"
| project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, FileName, FileSize
| where FileSize > 50000
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT29 (Cozy Bear)

### Observed Indicators (IOCs)
HTML attachments >50KB, base64 blobs in body, JavaScript Blob() / msSaveBlob() invocation client-side.

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
Quarantine HTML attachments by policy; require gateway extraction of embedded blobs.

### Next Steps
Pivot to T1204 (User Execution) for any extracted payload that ran.

### Additional Tags
synthetic, demo, initial-access
