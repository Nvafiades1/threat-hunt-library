### MITRE Technique ID
T1027

### Threat Hunt ID
TH-SYNTH-018

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
Packed/obfuscated binaries often have abnormally few imports or unusually high entropy. While not definitive, the combination is a useful hunt seed.

### Applicable ATT&CK Tactic(s)
- [x] Defense Evasion

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
CrowdStrike

### Data Sources
EDR static-analysis fields, VirusTotal hash lookups.

### Hunt Query
```
event_simpleName=ProcessRollup2 AND PE_HighEntropyHeuristic=1
| stats count BY ComputerName ImageFileName SHA256HashData
| where count <= 3
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
APT41

### Observed Indicators (IOCs)
High entropy across multiple sections; imports list <10 functions; InternalName mismatched with FileName.

### Supporting Evidence / Screenshots
_no response_

### Severity
Medium

### Confidence
Low

### Query Fidelity
Low

### Status
Inconclusive

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
Submit hash to VT; run binary in sandbox; alert if matched against known packer signatures.

### Next Steps
Hunt T1218 (Signed Binary Proxy) for execution chain.

### Additional Tags
synthetic, demo, defense-evasion
