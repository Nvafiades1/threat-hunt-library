### MITRE Technique ID
T1068

### Threat Hunt ID
TH-SYNTH-015

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Lazarus and similar actors load vulnerable signed drivers (BYOVD) for kernel-level priv-esc. New driver loads from non-vendor paths warrant investigation.

### Applicable ATT&CK Tactic(s)
- [x] Privilege Escalation

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
CrowdStrike

### Data Sources
EDR driver-load telemetry, Sysmon EID 6, Windows code-integrity log.

### Hunt Query
```
event_simpleName=DriverLoad
| search NOT ImageFileName="*\\Windows\\System32\\drivers\\*"
| stats count earliest(timestamp) AS first BY ComputerName ImageFileName SHA256HashData
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Lazarus Group

### Observed Indicators (IOCs)
Drivers loaded from user-writable paths, drivers signed by unusual or revoked certs, drivers matching public BYOVD lists (loldrivers.io).

### Supporting Evidence / Screenshots
_no response_

### Severity
Critical

### Confidence
High

### Query Fidelity
Medium

### Status
Completed

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Block driver hash globally via WDAC; reboot affected host; check for kernel-loaded rootkit artifacts.

### Next Steps
Hunt T1027 (Obfuscated Files) for related dropper.

### Additional Tags
synthetic, demo, privilege-escalation
