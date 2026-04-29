### MITRE Technique ID
T1133

### Threat Hunt ID
TH-SYNTH-007

### Created
2025-12-28T12:00:00Z

### Last Modified
2025-12-28T12:00:00Z

### Hypothesis
UNC3944 obtains valid creds via help-desk social engineering and uses them over VPN/SSO from non-baseline geos within a short window of a legitimate logon.

### Applicable ATT&CK Tactic(s)
- [x] Initial Access

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Sentinel

### Data Sources
Azure AD SigninLogs, VPN concentrator logs, Okta system logs.

### Hunt Query
```
SigninLogs
| where ResultType == 0 and AppDisplayName has_any ("VPN","Citrix","Okta")
| extend country = tostring(LocationDetails.countryOrRegion)
| sort by UserPrincipalName, TimeGenerated
| extend prev_country = prev(country, 1), prev_time = prev(TimeGenerated, 1),
         prev_user = prev(UserPrincipalName, 1)
| where prev_user == UserPrincipalName and prev_country != country
         and TimeGenerated - prev_time < 2h
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Scattered Spider (UNC3944)

### Observed Indicators (IOCs)
Same user authenticating from two countries within 2h; new device IDs; MFA reset event in preceding 24h.

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
Force re-auth + MFA reset; review help-desk ticket history for the user; block sign-in from high-risk countries.

### Next Steps
Pivot to T1078 (Valid Accounts) hunt for downstream activity.

### Additional Tags
synthetic, demo, initial-access
