### MITRE Technique ID
T1041

### Threat Hunt ID
TH-SYNTH-036

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
When data leaves over an established C2 channel, byte-out >> byte-in asymmetry per session is a hallmark of exfil.

### Applicable ATT&CK Tactic(s)
- [x] Exfiltration

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Zeek conn.log, NetFlow with byte counts, EDR network events.

### Hunt Query
```
index=zeek sourcetype=conn
| where orig_bytes > 50000000 and resp_bytes < orig_bytes/10
| stats sum(orig_bytes) AS bytes_out BY src_ip dest_ip dest_port
| sort - bytes_out
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT41

### Observed Indicators (IOCs)
Single host >50MB outbound to one destination with low inbound; destination ASN = VPS / hosting / cloud-storage.

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
Block destination; image host; review for compressed staging artifacts (.7z, .zip).

### Next Steps
Hunt T1560 (Archive Collected Data) on host.

### Additional Tags
synthetic, demo, exfiltration
