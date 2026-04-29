### MITRE Technique ID
T1018

### Threat Hunt ID
TH-SYNTH-027

### Created
2026-03-28T12:00:00Z

### Last Modified
2026-03-28T12:00:00Z

### Hypothesis
BloodHound / SharpHound / AdFind collection produces distinctive LDAP queries against AD — heavy LDAP from a single non-admin host is a strong hunt signal.

### Applicable ATT&CK Tactic(s)
- [x] Discovery

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
DC security log EID 4662, Sysmon EID 22 (DNS), endpoint EDR.

### Hunt Query
```
index=wineventlog EventCode=4662 ObjectType="user"
| stats count BY src_user ComputerName _time
| where count > 200
| sort - count
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT28 (Fancy Bear)

### Observed Indicators (IOCs)
LDAP search rates >200/hr from non-admin host; SharpHound binary on disk; AdFind / nltest exec.

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
Audit LDAP filter strings (BloodHound has signature filters); rotate creds for the executing user; image host.

### Next Steps
Hunt T1110 (Brute Force) — recon often precedes spray.

### Additional Tags
synthetic, demo, discovery
