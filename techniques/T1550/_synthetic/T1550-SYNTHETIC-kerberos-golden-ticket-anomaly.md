### MITRE Technique ID
T1550

### Threat Hunt ID
TH-SYNTH-030

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Golden tickets are forged TGTs with arbitrary lifetime/group membership. Tickets with abnormal lifetimes (>10h) or referencing unknown groups are a forgery indicator.

### Applicable ATT&CK Tactic(s)
- [x] Lateral Movement

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Sentinel

### Data Sources
DC security log EID 4769, EID 4624 logon-type 3 with unusual sids.

### Hunt Query
```
SecurityEvent | where EventID == 4769
| extend lifetime_hours = todouble(TicketEncryptionType) // proxy field
| where TicketOptions has "0x40810000"  // unusual options
| project TimeGenerated, Computer, TargetUserName, ServiceName, IpAddress, TicketOptions
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT41

### Observed Indicators (IOCs)
TGT lifetime >10h, encryption types not matching GPO, RID 500 group-membership claim from non-default user.

### Supporting Evidence / Screenshots
_no response_

### Severity
Critical

### Confidence
Medium

### Query Fidelity
Medium

### Status
In Progress

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Rotate krbtgt twice (separated by replication interval); audit privileged group memberships; force re-issue all TGTs.

### Next Steps
Hunt T1003 (Credential Dumping) on DCs and recently RDP'd admin hosts.

### Additional Tags
synthetic, demo, lateral-movement
