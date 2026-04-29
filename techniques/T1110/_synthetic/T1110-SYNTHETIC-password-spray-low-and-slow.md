### MITRE Technique ID
T1110

### Threat Hunt ID
TH-SYNTH-023

### Created
2026-03-14T12:00:00Z

### Last Modified
2026-03-14T12:00:00Z

### Hypothesis
Password spray (1-2 attempts/account, many accounts) evades classic lockout-based detection. Low-and-slow spray is APT33 / APT28 staple.

### Applicable ATT&CK Tactic(s)
- [x] Credential Access

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Sentinel

### Data Sources
Azure AD SigninLogs, Okta system logs, Windows EID 4625.

### Hunt Query
```
SigninLogs
| where ResultType in ("50053","50056","50126")
| summarize attempts=count(), users=dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)
| where users >= 20 and attempts < 80
| sort by users desc
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT33

### Observed Indicators (IOCs)
Single source IP failing auth across many distinct users with low per-user attempt counts, common spray-friendly passwords (Spring2026!), consistent UA string.

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
Block source IP; force MFA reset on any successful logon from same IP; audit recent ResultType=0 from same IP.

### Next Steps
Hunt T1078 (Valid Accounts) for any successful sign-ins from spray IPs.

### Additional Tags
synthetic, demo, credential-access
