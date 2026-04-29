### MITRE Technique ID
T1573

### Threat Hunt ID
TH-SYNTH-034

### Created
2026-04-15T12:00:00Z

### Last Modified
2026-04-15T12:00:00Z

### Hypothesis
JARM fingerprints of Cobalt Strike teamservers are well-documented. Outbound TLS to destinations with known-malicious JARM is high-fidelity.

### Applicable ATT&CK Tactic(s)
- [x] Command and Control

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Zeek SSL logs with JARM enrichment, threat-intel JARM blocklist.

### Hunt Query
```
index=zeek sourcetype=ssl
| lookup malicious_jarm.csv jarm_fp AS jarm OUTPUT family
| where isnotnull(family)
| stats count earliest(_time) AS first BY src_ip dest_ip jarm family
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Cobalt Strike Operators

### Observed Indicators (IOCs)
JARM matching CS / Brute Ratel / Sliver public fingerprints; outbound to VPS ASNs; certificate Subject mismatched with hostname.

### Supporting Evidence / Screenshots
_no response_

### Severity
Medium

### Confidence
Medium

### Query Fidelity
High

### Status
Completed

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Block destination at egress; image source; rotate creds on host.

### Next Steps
Hunt T1090 (Proxy) for relay infrastructure.

### Additional Tags
synthetic, demo, command-and-control
