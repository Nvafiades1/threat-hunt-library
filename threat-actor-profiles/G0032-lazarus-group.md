# Lazarus Group

**Type:** Threat Group  
**MITRE ID:** `G0032`  
**Aliases:** `Labyrinth Chollima`, `HIDDEN COBRA`, `Guardians of Peace`, `ZINC`, `NICKEL ACADEMY`, `Diamond Sleet`  
**MITRE Reference:** [https://attack.mitre.org/groups/G0032](https://attack.mitre.org/groups/G0032)  

## Overview

[Lazarus Group](https://attack.mitre.org/groups/G0032) is a North Korean state-sponsored cyber threat group attributed to the Reconnaissance General Bureau (RGB). [Lazarus Group](https://attack.mitre.org/groups/G0032) has been active since at least 2009 and is reportedly responsible for the November 2014 destructive wiper attack on Sony Pictures Entertainment, identified by Novetta as part of Operation Blockbuster. Malware used by [Lazarus Group](https://attack.mitre.org/groups/G0032) correlates to other reported campaigns, including Operation Flame, Operation 1Mission, Operation Troy, DarkSeoul, and Ten Days of Rain.

North Korea’s cyber operations have shown a consistent pattern of adaptation, forming and reorganizing units as national priorities shift. These units frequently share personnel, infrastructure, malware, and tradecraft, making it difficult to attribute specific operations with high confidence. Public reporting often uses “Lazarus Group” as an umbrella term for multiple North Korean cyber operators conducting espionage, destructive attacks, and financially motivated campaigns.

## Tools & Software (26)

- [AppleJeus](https://attack.mitre.org/software/S0584) — `S0584` _(malware)_
- [AuditCred](https://attack.mitre.org/software/S0347) — `S0347` _(malware)_
- [BADCALL](https://attack.mitre.org/software/S0245) — `S0245` _(malware)_
- [Bankshot](https://attack.mitre.org/software/S0239) — `S0239` _(malware)_
- [BLINDINGCAN](https://attack.mitre.org/software/S0520) — `S0520` _(malware)_
- [Cryptoistic](https://attack.mitre.org/software/S0498) — `S0498` _(malware)_
- [Dacls](https://attack.mitre.org/software/S0497) — `S0497` _(malware)_
- [Dtrack](https://attack.mitre.org/software/S0567) — `S0567` _(malware)_
- [ECCENTRICBANDWAGON](https://attack.mitre.org/software/S0593) — `S0593` _(malware)_
- [FALLCHILL](https://attack.mitre.org/software/S0181) — `S0181` _(malware)_
- [HARDRAIN](https://attack.mitre.org/software/S0246) — `S0246` _(malware)_
- [HOPLIGHT](https://attack.mitre.org/software/S0376) — `S0376` _(malware)_
- [HotCroissant](https://attack.mitre.org/software/S0431) — `S0431` _(malware)_
- [KEYMARBLE](https://attack.mitre.org/software/S0271) — `S0271` _(malware)_
- [MagicRAT](https://attack.mitre.org/software/S1182) — `S1182` _(malware)_
- [netsh](https://attack.mitre.org/software/S0108) — `S0108` _(tool)_
- [Proxysvc](https://attack.mitre.org/software/S0238) — `S0238` _(malware)_
- [RATANKBA](https://attack.mitre.org/software/S0241) — `S0241` _(malware)_
- [RawDisk](https://attack.mitre.org/software/S0364) — `S0364` _(tool)_
- [Responder](https://attack.mitre.org/software/S0174) — `S0174` _(tool)_
- [route](https://attack.mitre.org/software/S0103) — `S0103` _(tool)_
- [TAINTEDSCRIBE](https://attack.mitre.org/software/S0586) — `S0586` _(malware)_
- [ThreatNeedle](https://attack.mitre.org/software/S0665) — `S0665` _(malware)_
- [TYPEFRAME](https://attack.mitre.org/software/S0263) — `S0263` _(malware)_
- [Volgmer](https://attack.mitre.org/software/S0180) — `S0180` _(malware)_
- [WannaCry](https://attack.mitre.org/software/S0366) — `S0366` _(malware)_

## Techniques (93 TTPs)

### Reconnaissance

- `T1589.002` — Email Addresses
- `T1591` — Gather Victim Org Information

### Resource Development

- `T1583.001` — Domains
- `T1583.006` — Web Services
- `T1584.004` — Server
- `T1585.001` — Social Media Accounts
- `T1585.002` — Email Accounts
- `T1587.001` — Malware
- `T1588.002` — Tool
- `T1588.004` — Digital Certificates

### Initial Access

- `T1078` — Valid Accounts
- `T1189` — Drive-by Compromise
- `T1566.001` — Spearphishing Attachment
- `T1566.002` — Spearphishing Link
- `T1566.003` — Spearphishing via Service

### Execution

- `T1047` — Windows Management Instrumentation
- `T1053.005` — Scheduled Task
- `T1059.001` — PowerShell
- `T1059.003` — Windows Command Shell
- `T1059.005` — Visual Basic
- `T1106` — Native API
- `T1203` — Exploitation for Client Execution
- `T1204.002` — Malicious File

### Persistence

- `T1053.005` — Scheduled Task
- `T1078` — Valid Accounts
- `T1098` — Account Manipulation
- `T1542.003` — Bootkit
- `T1543.003` — Windows Service
- `T1547.001` — Registry Run Keys / Startup Folder
- `T1547.009` — Shortcut Modification
- `T1574.001` — DLL
- `T1574.013` — KernelCallbackTable

### Privilege Escalation

- `T1053.005` — Scheduled Task
- `T1055.001` — Dynamic-link Library Injection
- `T1078` — Valid Accounts
- `T1098` — Account Manipulation
- `T1134.002` — Create Process with Token
- `T1543.003` — Windows Service
- `T1547.001` — Registry Run Keys / Startup Folder
- `T1547.009` — Shortcut Modification
- `T1574.001` — DLL
- `T1574.013` — KernelCallbackTable

### Defense Evasion

- `T1027.007` — Dynamic API Resolution
- `T1027.009` — Embedded Payloads
- `T1027.013` — Encrypted/Encoded File
- `T1036.003` — Rename Legitimate Utilities
- `T1036.004` — Masquerade Task or Service
- `T1036.005` — Match Legitimate Resource Name or Location
- `T1055.001` — Dynamic-link Library Injection
- `T1070` — Indicator Removal
- `T1070.003` — Clear Command History
- `T1070.004` — File Deletion
- `T1070.006` — Timestomp
- `T1078` — Valid Accounts
- `T1134.002` — Create Process with Token
- `T1140` — Deobfuscate/Decode Files or Information
- `T1202` — Indirect Command Execution
- `T1218` — System Binary Proxy Execution
- `T1218.005` — Mshta
- `T1218.011` — Rundll32
- `T1542.003` — Bootkit
- `T1553.002` — Code Signing
- `T1562.001` — Disable or Modify Tools
- `T1562.004` — Disable or Modify System Firewall
- `T1564.001` — Hidden Files and Directories
- `T1574.001` — DLL
- `T1574.013` — KernelCallbackTable
- `T1620` — Reflective Code Loading

### Credential Access

- `T1056.001` — Keylogging
- `T1110.003` — Password Spraying
- `T1557.001` — LLMNR/NBT-NS Poisoning and SMB Relay

### Discovery

- `T1010` — Application Window Discovery
- `T1012` — Query Registry
- `T1016` — System Network Configuration Discovery
- `T1033` — System Owner/User Discovery
- `T1046` — Network Service Discovery
- `T1049` — System Network Connections Discovery
- `T1057` — Process Discovery
- `T1082` — System Information Discovery
- `T1083` — File and Directory Discovery
- `T1124` — System Time Discovery
- `T1680` — Local Storage Discovery

### Lateral Movement

- `T1021.001` — Remote Desktop Protocol
- `T1021.002` — SMB/Windows Admin Shares
- `T1021.004` — SSH

### Collection

- `T1005` — Data from Local System
- `T1056.001` — Keylogging
- `T1074.001` — Local Data Staging
- `T1557.001` — LLMNR/NBT-NS Poisoning and SMB Relay
- `T1560` — Archive Collected Data
- `T1560.002` — Archive via Library
- `T1560.003` — Archive via Custom Method

### Command And Control

- `T1001.003` — Protocol or Service Impersonation
- `T1008` — Fallback Channels
- `T1071.001` — Web Protocols
- `T1090.001` — Internal Proxy
- `T1090.002` — External Proxy
- `T1102.002` — Bidirectional Communication
- `T1104` — Multi-Stage Channels
- `T1105` — Ingress Tool Transfer
- `T1132.001` — Standard Encoding
- `T1571` — Non-Standard Port
- `T1573.001` — Symmetric Cryptography

### Exfiltration

- `T1041` — Exfiltration Over C2 Channel
- `T1048.003` — Exfiltration Over Unencrypted Non-C2 Protocol

### Impact

- `T1485` — Data Destruction
- `T1489` — Service Stop
- `T1491.001` — Internal Defacement
- `T1529` — System Shutdown/Reboot
- `T1561.001` — Disk Content Wipe
- `T1561.002` — Disk Structure Wipe

---

_Auto-generated from MITRE ATT&CK Enterprise v18.1 on 2026-04-27. Regenerated when MITRE updates this group's data._
