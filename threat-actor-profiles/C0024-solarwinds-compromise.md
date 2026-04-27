# SolarWinds Compromise

**Type:** Campaign  
**MITRE ID:** `C0024`  
**First seen:** 2019-08-01T05:00:00.000Z  
**Last seen:** 2021-01-01T06:00:00.000Z  
**Attributed to:** [APT29](https://attack.mitre.org/groups/G0016) (`G0016`)  
**MITRE Reference:** [https://attack.mitre.org/campaigns/C0024](https://attack.mitre.org/campaigns/C0024)

## Overview

The [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) was a sophisticated supply chain cyber operation conducted by [APT29](https://attack.mitre.org/groups/G0016) that was discovered in mid-December 2020. [APT29](https://attack.mitre.org/groups/G0016) used customized malware to inject malicious code into the SolarWinds Orion software build process that was later distributed through a normal software update; they also used password spraying, token theft, API abuse, spear phishing, and other supply chain attacks to compromise user accounts and leverage their associated access. Victims of this campaign included government, consulting, technology, telecom, and other organizations in North America, Europe, Asia, and the Middle East. This activity has been labled the StellarParticle campaign in industry reporting. Industry reporting also initially referred to the actors involved in this campaign as UNC2452, NOBELIUM, Dark Halo, and SolarStorm. 

In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to Russia's Foreign Intelligence Service (SVR); public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes. The US government assessed that of the approximately 18,000 affected public and private sector customers of Solar Winds’ Orion product, a much smaller number were compromised by follow-on [APT29](https://attack.mitre.org/groups/G0016) activity on their systems.

## Tools & Software (11)

- [AdFind](https://attack.mitre.org/software/S0552) — `S0552` _(tool)_
- [Cobalt Strike](https://attack.mitre.org/software/S0154) — `S0154` _(malware)_
- [GoldFinder](https://attack.mitre.org/software/S0597) — `S0597` _(malware)_
- [GoldMax](https://attack.mitre.org/software/S0588) — `S0588` _(malware)_
- [Mimikatz](https://attack.mitre.org/software/S0002) — `S0002` _(tool)_
- [Raindrop](https://attack.mitre.org/software/S0565) — `S0565` _(malware)_
- [Sibot](https://attack.mitre.org/software/S0589) — `S0589` _(malware)_
- [SUNBURST](https://attack.mitre.org/software/S0559) — `S0559` _(malware)_
- [SUNSPOT](https://attack.mitre.org/software/S0562) — `S0562` _(malware)_
- [TEARDROP](https://attack.mitre.org/software/S0560) — `S0560` _(malware)_
- [TrailBlazer](https://attack.mitre.org/software/S0682) — `S0682` _(malware)_

## Techniques (71 TTPs)

### Reconnaissance

- `T1589.001` — Credentials

### Resource Development

- `T1583.001` — Domains
- `T1584.001` — Domains
- `T1587.001` — Malware

### Initial Access

- `T1078` — Valid Accounts
- `T1078.002` — Domain Accounts
- `T1078.003` — Local Accounts
- `T1078.004` — Cloud Accounts
- `T1133` — External Remote Services
- `T1190` — Exploit Public-Facing Application
- `T1195.002` — Compromise Software Supply Chain
- `T1199` — Trusted Relationship

### Execution

- `T1047` — Windows Management Instrumentation
- `T1053.005` — Scheduled Task
- `T1059.001` — PowerShell
- `T1059.003` — Windows Command Shell
- `T1059.005` — Visual Basic

### Persistence

- `T1053.005` — Scheduled Task
- `T1078` — Valid Accounts
- `T1078.002` — Domain Accounts
- `T1078.003` — Local Accounts
- `T1078.004` — Cloud Accounts
- `T1098.001` — Additional Cloud Credentials
- `T1098.002` — Additional Email Delegate Permissions
- `T1098.003` — Additional Cloud Roles
- `T1098.005` — Device Registration
- `T1133` — External Remote Services
- `T1546.003` — Windows Management Instrumentation Event Subscription

### Privilege Escalation

- `T1053.005` — Scheduled Task
- `T1078` — Valid Accounts
- `T1078.002` — Domain Accounts
- `T1078.003` — Local Accounts
- `T1078.004` — Cloud Accounts
- `T1098.001` — Additional Cloud Credentials
- `T1098.002` — Additional Email Delegate Permissions
- `T1098.003` — Additional Cloud Roles
- `T1098.005` — Device Registration
- `T1484.002` — Trust Modification
- `T1546.003` — Windows Management Instrumentation Event Subscription

### Defense Evasion

- `T1036.004` — Masquerade Task or Service
- `T1036.005` — Match Legitimate Resource Name or Location
- `T1070` — Indicator Removal
- `T1070.004` — File Deletion
- `T1070.006` — Timestomp
- `T1070.008` — Clear Mailbox Data
- `T1078` — Valid Accounts
- `T1078.002` — Domain Accounts
- `T1078.003` — Local Accounts
- `T1078.004` — Cloud Accounts
- `T1140` — Deobfuscate/Decode Files or Information
- `T1218.011` — Rundll32
- `T1484.002` — Trust Modification
- `T1550` — Use Alternate Authentication Material
- `T1550.001` — Application Access Token
- `T1550.004` — Web Session Cookie
- `T1553.002` — Code Signing
- `T1562.001` — Disable or Modify Tools
- `T1562.002` — Disable Windows Event Logging
- `T1562.004` — Disable or Modify System Firewall

### Credential Access

- `T1003.006` — DCSync
- `T1539` — Steal Web Session Cookie
- `T1552.004` — Private Keys
- `T1555` — Credentials from Password Stores
- `T1555.003` — Credentials from Web Browsers
- `T1558.003` — Kerberoasting
- `T1606.001` — Web Cookies
- `T1606.002` — SAML Tokens

### Discovery

- `T1016.001` — Internet Connection Discovery
- `T1018` — Remote System Discovery
- `T1057` — Process Discovery
- `T1069` — Permission Groups Discovery
- `T1069.002` — Domain Groups
- `T1083` — File and Directory Discovery
- `T1087` — Account Discovery
- `T1087.002` — Domain Account
- `T1482` — Domain Trust Discovery
- `T1680` — Local Storage Discovery

### Lateral Movement

- `T1021.001` — Remote Desktop Protocol
- `T1021.002` — SMB/Windows Admin Shares
- `T1021.006` — Windows Remote Management
- `T1550` — Use Alternate Authentication Material
- `T1550.001` — Application Access Token
- `T1550.004` — Web Session Cookie

### Collection

- `T1005` — Data from Local System
- `T1074.002` — Remote Data Staging
- `T1114.002` — Remote Email Collection
- `T1213` — Data from Information Repositories
- `T1213.003` — Code Repositories
- `T1560.001` — Archive via Utility

### Command And Control

- `T1071.001` — Web Protocols
- `T1090.001` — Internal Proxy
- `T1105` — Ingress Tool Transfer
- `T1568` — Dynamic Resolution
- `T1665` — Hide Infrastructure

### Exfiltration

- `T1048.002` — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

---

_Auto-generated from MITRE ATT&CK Enterprise v18.1 on 2026-04-27._
