### MITRE Technique ID
T1134

### Threat Hunt ID
TH-SYNTH-016

### Created
2026-02-16T12:00:00Z

### Last Modified
2026-02-16T12:00:00Z

### Hypothesis
Token impersonation/duplication is common in post-exploitation. While lsass interaction is heavily monitored, less-watched processes (e.g., spoolsv, taskhostw) abusing tokens are a hunt opportunity.

### Applicable ATT&CK Tactic(s)
- [x] Privilege Escalation

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Defender XDR

### Data Sources
Defender for Endpoint, Sysmon, ETW SecurityAuditing provider.

### Hunt Query
```
DeviceProcessEvents
| where ProcessCommandLine has_any ("ImpersonateLoggedOnUser","DuplicateTokenEx")
| where InitiatingProcessFileName !in~ ("svchost.exe","services.exe","lsass.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT29 (Cozy Bear)

### Observed Indicators (IOCs)
API call sequences DuplicateTokenEx → CreateProcessWithToken from non-system contexts, SeImpersonatePrivilege use by unusual procs.

### Supporting Evidence / Screenshots
_no response_

### Severity
High

### Confidence
Medium

### Query Fidelity
Medium

### Status
In Progress

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Image host; analyze invoking binary; audit privileged group memberships.

### Next Steps
Hunt T1003 (Credential Dumping) on related processes.

### Additional Tags
synthetic, demo, privilege-escalation
