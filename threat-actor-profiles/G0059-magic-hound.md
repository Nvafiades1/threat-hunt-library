# Magic Hound

**Type:** Threat Group  
**MITRE ID:** `G0059`  
**Aliases:** `TA453`, `COBALT ILLUSION`, `Charming Kitten`, `ITG18`, `Phosphorus`, `Newscaster`, `APT35`, `Mint Sandstorm`  
**MITRE Reference:** [https://attack.mitre.org/groups/G0059](https://attack.mitre.org/groups/G0059)  

## Overview

[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group that conducts long term, resource-intensive cyber espionage operations, likely on behalf of the Islamic Revolutionary Guard Corps. They have targeted European, U.S., and Middle Eastern government and military personnel, academics, journalists, and organizations such as the World Health Organization (WHO), via complex social engineering campaigns since at least 2014.

## Tools & Software (13)

- [CharmPower](https://attack.mitre.org/software/S0674) — `S0674` _(malware)_
- [DownPaper](https://attack.mitre.org/software/S0186) — `S0186` _(malware)_
- [FRP](https://attack.mitre.org/software/S1144) — `S1144` _(tool)_
- [Impacket](https://attack.mitre.org/software/S0357) — `S0357` _(tool)_
- [ipconfig](https://attack.mitre.org/software/S0100) — `S0100` _(tool)_
- [Mimikatz](https://attack.mitre.org/software/S0002) — `S0002` _(tool)_
- [Net](https://attack.mitre.org/software/S0039) — `S0039` _(tool)_
- [netsh](https://attack.mitre.org/software/S0108) — `S0108` _(tool)_
- [Ping](https://attack.mitre.org/software/S0097) — `S0097` _(tool)_
- [PowerLess](https://attack.mitre.org/software/S1012) — `S1012` _(malware)_
- [PsExec](https://attack.mitre.org/software/S0029) — `S0029` _(tool)_
- [Pupy](https://attack.mitre.org/software/S0192) — `S0192` _(tool)_
- [Systeminfo](https://attack.mitre.org/software/S0096) — `S0096` _(tool)_

## Techniques (79 TTPs)

### Reconnaissance

- `T1589` — Gather Victim Identity Information
- `T1589.001` — Credentials
- `T1589.002` — Email Addresses
- `T1590.005` — IP Addresses
- `T1591.001` — Determine Physical Locations
- `T1592.002` — Software
- `T1595.002` — Vulnerability Scanning
- `T1598.003` — Spearphishing Link

### Resource Development

- `T1583.001` — Domains
- `T1583.006` — Web Services
- `T1584.001` — Domains
- `T1585.001` — Social Media Accounts
- `T1585.002` — Email Accounts
- `T1586.002` — Email Accounts
- `T1588.002` — Tool

### Initial Access

- `T1078.001` — Default Accounts
- `T1078.002` — Domain Accounts
- `T1189` — Drive-by Compromise
- `T1190` — Exploit Public-Facing Application
- `T1566.002` — Spearphishing Link
- `T1566.003` — Spearphishing via Service

### Execution

- `T1047` — Windows Management Instrumentation
- `T1053.005` — Scheduled Task
- `T1059.001` — PowerShell
- `T1059.003` — Windows Command Shell
- `T1059.005` — Visual Basic
- `T1204.001` — Malicious Link
- `T1204.002` — Malicious File

### Persistence

- `T1053.005` — Scheduled Task
- `T1078.001` — Default Accounts
- `T1078.002` — Domain Accounts
- `T1098.002` — Additional Email Delegate Permissions
- `T1098.007` — Additional Local or Domain Groups
- `T1112` — Modify Registry
- `T1136.001` — Local Account
- `T1505.003` — Web Shell
- `T1547.001` — Registry Run Keys / Startup Folder

### Privilege Escalation

- `T1053.005` — Scheduled Task
- `T1078.001` — Default Accounts
- `T1078.002` — Domain Accounts
- `T1098.002` — Additional Email Delegate Permissions
- `T1098.007` — Additional Local or Domain Groups
- `T1547.001` — Registry Run Keys / Startup Folder

### Defense Evasion

- `T1027.010` — Command Obfuscation
- `T1027.013` — Encrypted/Encoded File
- `T1036.004` — Masquerade Task or Service
- `T1036.005` — Match Legitimate Resource Name or Location
- `T1036.010` — Masquerade Account Name
- `T1070.003` — Clear Command History
- `T1070.004` — File Deletion
- `T1078.001` — Default Accounts
- `T1078.002` — Domain Accounts
- `T1112` — Modify Registry
- `T1218.011` — Rundll32
- `T1562` — Impair Defenses
- `T1562.001` — Disable or Modify Tools
- `T1562.002` — Disable Windows Event Logging
- `T1562.004` — Disable or Modify System Firewall
- `T1564.003` — Hidden Window

### Credential Access

- `T1003.001` — LSASS Memory
- `T1056.001` — Keylogging

### Discovery

- `T1016` — System Network Configuration Discovery
- `T1016.001` — Internet Connection Discovery
- `T1016.002` — Wi-Fi Discovery
- `T1018` — Remote System Discovery
- `T1033` — System Owner/User Discovery
- `T1046` — Network Service Discovery
- `T1049` — System Network Connections Discovery
- `T1057` — Process Discovery
- `T1082` — System Information Discovery
- `T1083` — File and Directory Discovery
- `T1087.003` — Email Account
- `T1482` — Domain Trust Discovery

### Lateral Movement

- `T1021.001` — Remote Desktop Protocol
- `T1570` — Lateral Tool Transfer

### Collection

- `T1005` — Data from Local System
- `T1056.001` — Keylogging
- `T1113` — Screen Capture
- `T1114` — Email Collection
- `T1114.001` — Local Email Collection
- `T1114.002` — Remote Email Collection
- `T1560.001` — Archive via Utility

### Command And Control

- `T1071` — Application Layer Protocol
- `T1071.001` — Web Protocols
- `T1090` — Proxy
- `T1102.002` — Bidirectional Communication
- `T1105` — Ingress Tool Transfer
- `T1571` — Non-Standard Port
- `T1572` — Protocol Tunneling
- `T1573` — Encrypted Channel

### Exfiltration

- `T1567` — Exfiltration Over Web Service

### Impact

- `T1486` — Data Encrypted for Impact

---

_Auto-generated from MITRE ATT&CK Enterprise v18.1 on 2026-04-27. Regenerated when MITRE updates this group's data._
