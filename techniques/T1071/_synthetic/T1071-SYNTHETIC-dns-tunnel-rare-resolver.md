### MITRE Technique ID
T1071

### Threat Hunt ID
TH-SYNTH-033

### Created
2026-04-12T12:00:00Z

### Last Modified
2026-04-12T12:00:00Z

### Hypothesis
DNS tunneling produces high query rates with unusually long subdomain labels. APT41 has used iodine-style tunnels for backup C2.

### Applicable ATT&CK Tactic(s)
- [x] Command and Control

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Recursive DNS resolver logs, passive DNS, EDR DNS telemetry.

### Hunt Query
```
index=dns
| eval label_len=len(query)
| where label_len > 50
| stats count avg(label_len) AS avg_len BY src_ip dest_domain
| where count > 100
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT41

### Observed Indicators (IOCs)
Subdomain labels >50 chars; high query rate to single second-level domain; TXT/NULL record queries from endpoints.

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
Sinkhole the second-level domain; block at DNS firewall; image source host.

### Next Steps
Hunt T1041 (Exfil Over C2) for staged data egress patterns.

### Additional Tags
synthetic, demo, command-and-control
