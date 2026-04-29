### MITRE Technique ID
T1113

### Threat Hunt ID
TH-SYNTH-032

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Screen-capture APIs called from binaries that aren't conferencing / screen-recording tools (Teams, Zoom, OBS) suggest covert collection.

### Applicable ATT&CK Tactic(s)
- [x] Collection

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Defender XDR

### Data Sources
Defender for Endpoint DeviceImageLoadEvents, Sysmon EID 7.

### Hunt Query
```
DeviceImageLoadEvents
| where FileName == "gdi32.dll"
| where InitiatingProcessFileName !in~ ("teams.exe","zoom.exe","obs64.exe","msedge.exe","chrome.exe")
| join kind=inner (DeviceProcessEvents | where ProcessCommandLine has_any ("BitBlt","CaptureBitmap"))
       on DeviceId
| project Timestamp, DeviceName, InitiatingProcessFileName
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT28 (Fancy Bear)

### Observed Indicators (IOCs)
Non-conferencing app loading gdi32 + invoking BitBlt; PNG/JPEG file writes to Temp from those processes.

### Supporting Evidence / Screenshots
_no response_

### Severity
Medium

### Confidence
Low

### Query Fidelity
Low

### Status
Inconclusive

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Sandbox-analyze the binary; review for related collection (clipboard, audio).

### Next Steps
Hunt T1056 (Input Capture) on same host.

### Additional Tags
synthetic, demo, collection
