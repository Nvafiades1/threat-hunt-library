### MITRE Technique ID
T1078

### Threat Hunt ID
TH-SYNTH-008

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Adversaries enumerate AD for stale service accounts (no logon in >180d) and use compromised credentials, banking on accounts not being monitored.

### Applicable ATT&CK Tactic(s)
- [x] Initial Access

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Windows security event logs (4624), AD audit, password-last-set attribute.

### Hunt Query
```
index=wineventlog EventCode=4624 LogonType IN (3,5,7)
| eval is_svc=if(match(user, "(?i)(svc|service|sql|app)_"), 1, 0)
| where is_svc=1
| stats latest(_time) AS last_logon BY user
| eval idle_days=round((now() - last_logon)/86400, 0)
| where idle_days > 180
| sort - idle_days
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT41

### Observed Indicators (IOCs)
Service-named accounts going from idle to active, especially with logon type 10 (interactive) which they should never use.

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
Disable confirmed-stale service accounts; rotate creds on revived accounts; add interactive-logon audit rule.

### Next Steps
Hunt T1003 (Credential Dumping) on hosts that received the dormant logons.

### Additional Tags
synthetic, demo, initial-access
