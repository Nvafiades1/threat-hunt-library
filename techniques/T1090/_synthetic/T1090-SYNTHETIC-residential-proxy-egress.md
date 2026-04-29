### MITRE Technique ID
T1090

### Threat Hunt ID
TH-SYNTH-035

### Created
2026-04-18T12:00:00Z

### Last Modified
2026-04-18T12:00:00Z

### Hypothesis
Adversaries route C2 through residential proxy networks (911 S5, BrightData) to defeat geographic detections. Outbound to known residential proxy ranges from corporate endpoints is anomalous.

### Applicable ATT&CK Tactic(s)
- [x] Command and Control

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Sentinel

### Data Sources
Sentinel SigninLogs, NetFlow / firewall egress, residential-proxy IoC feed.

### Hunt Query
```
SigninLogs
| where ResultType == 0
| extend asn = tostring(parse_json(NetworkLocationDetails)[0].networkType)
| where asn == "namedNetwork" and IPAddress in (
    // residential proxy IP feed import
    "203.0.113.0", "198.51.100.5"
)
| project TimeGenerated, UserPrincipalName, IPAddress
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Scattered Spider (UNC3944)

### Observed Indicators (IOCs)
Auth from known residential proxy ranges; rapidly rotating IPs across auth attempts; matches against Spamhaus / Spur.us residential intel.

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
Block IP at edge; force MFA + session reset; review user help-desk history.

### Next Steps
Hunt T1133 (External Remote Services) for prior VPN access from same IPs.

### Additional Tags
synthetic, demo, command-and-control
