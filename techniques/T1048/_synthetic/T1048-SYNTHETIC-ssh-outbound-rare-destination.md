### MITRE Technique ID
T1048

### Threat Hunt ID
TH-SYNTH-038

### Created
2026-04-25T12:00:00Z

### Last Modified
2026-04-25T12:00:00Z

### Hypothesis
Outbound SSH from corporate hosts to non-vendor IPs is rare in most enterprises. Adversaries use SSH for tunneling and exfil.

### Applicable ATT&CK Tactic(s)
- [x] Exfiltration

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Firewall / NetFlow application-aware logs, EDR network telemetry.

### Hunt Query
```
index=firewall app=ssh dest_port=22 dest_ip!=10.0.0.0/8
| iplocation dest_ip
| stats count earliest(_time) AS first BY src_ip dest_ip Country
| where count >= 5
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT28 (Fancy Bear)

### Observed Indicators (IOCs)
SSH outbound to country / ASN not on baseline; long-running SSH sessions; high outbound bytes ratio.

### Supporting Evidence / Screenshots
_no response_

### Severity
Medium

### Confidence
Medium

### Query Fidelity
Medium

### Status
In Progress

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Block egress SSH from non-engineering segments; require jump-host for any outbound SSH.

### Next Steps
Hunt T1090 (Proxy) for tunneling traffic patterns.

### Additional Tags
synthetic, demo, exfiltration
