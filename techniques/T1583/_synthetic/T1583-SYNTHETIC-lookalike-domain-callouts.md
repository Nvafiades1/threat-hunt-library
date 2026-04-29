### MITRE Technique ID
T1583

### Threat Hunt ID
TH-SYNTH-003

### Created
2025-11-23T12:00:00Z

### Last Modified
2025-11-23T12:00:00Z

### Hypothesis
Adversaries register typosquat domains of our brand for phishing or C2. DNS resolution from internal hosts to those domains indicates a lure has reached an endpoint.

### Applicable ATT&CK Tactic(s)
- [x] Resource Development

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
Splunk

### Data Sources
Internal recursive DNS, web proxy access logs

### Hunt Query
```
index=dns sourcetype=dns_query
| eval domain=lower(query)
| where like(domain, "%corp-portal%") AND domain!="corp-portal.example.com"
| stats count earliest(_time) AS first_seen latest(_time) AS last_seen BY domain src_ip
| sort - count
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
Lazarus Group

### Observed Indicators (IOCs)
Lookalike of brand domain in DNS query, recently registered (<14d), Let's Encrypt cert.

### Supporting Evidence / Screenshots
_no response_

### Severity
High

### Confidence
Medium

### Query Fidelity
Medium

### Status
Completed

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Sinkhole confirmed lookalikes; submit takedowns; alert recipients of any outbound mail to those domains.

### Next Steps
Feed confirmed lookalikes into URL blocklist and email filter.

### Additional Tags
synthetic, demo, resource-development
