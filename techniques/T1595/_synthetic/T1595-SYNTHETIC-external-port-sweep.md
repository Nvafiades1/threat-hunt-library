### MITRE Technique ID
T1595

### Threat Hunt ID
TH-SYNTH-001

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
External actors are conducting reconnaissance scans against our edge infrastructure prior to exploitation attempts. APT28 is known to enumerate exposed services at a low-and-slow rate to avoid IDS thresholds.

### Applicable ATT&CK Tactic(s)
- [x] Reconnaissance

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Perimeter firewall logs, IDS alerts, Zeek conn.log

### Hunt Query
```
index=firewall action=denied src_ip!=10.0.0.0/8 src_ip!=192.168.0.0/16
| bucket _time span=1h
| stats dc(dest_port) AS unique_ports values(dest_port) AS ports BY src_ip _time
| where unique_ports >= 15
| sort - unique_ports
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT28 (Fancy Bear)

### Observed Indicators (IOCs)
Suspicious source ASNs, contiguous port enumeration, scan signatures

### Supporting Evidence / Screenshots
_no response_

### Severity
Medium

### Confidence
Medium

### Query Fidelity
Medium

### Status
Completed

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Block ASN at edge if scan persists; correlate with auth-failure spikes; feed source IPs into reputation block list.

### Next Steps
Pivot to T1190 hunt for any successful exploitation from same source IPs.

### Additional Tags
synthetic, demo, reconnaissance
