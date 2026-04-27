# UTA0178

## Snapshot

**Type:** Threat Actor (MISP-only — not in MITRE ATT&CK)  
**MISP UUID:** `f288f686-b5b3-4c86-9960-5f8fb18709a3`  
**Aliases:** `UNC5221`, `Red Dev 61`  
**Country:** `CN`  
**Suspected victims:** Germany  

## Overview

While Volexity largely observed the attacker essentially living off the land, they still deployed a handful of malware files and tools during the course of the incident which primarily consisted of webshells, proxy utilities, and file modifications to allow credential harvesting. Once UTA0178 had access into the network via the ICS VPN appliance, their general approach was to pivot from system to system using compromised credentials. They would then further compromise credentials of users on any new system that was breached, and use these credentials to log into additional systems via RDP. Volexity observed the attacker obtaining credentials in a variety of ways.

## References & IOC Sources (8)

This actor isn't tracked by MITRE ATT&CK, so no TTPs are available. The references below are the primary sources MISP cites — **start here for IOCs and TTP descriptions**:

- https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/
- https://www.rewterz.com/rewterz-news/rewterz-threat-advisory-ivanti-vpn-zero-days-weaponized-by-unc5221-threat-actors-to-deploy-multiple-malware-families-active-iocs/
- https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day
- https://quointelligence.eu/2024/01/unc5221-unreported-and-undetected-wirefire-web-shell-variant/
- https://www.volexity.com/blog/2024/01/18/ivanti-connect-secure-vpn-exploitation-new-observations/
- https://www.mandiant.com/resources/blog/investigating-ivanti-zero-day-exploitation
- https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage/Analysen-und-Prognosen/Threat-Intelligence/Aktive_APT-Gruppen/aktive-apt-gruppen_node.html
- https://cloud.google.com/blog/topics/threat-intelligence/ivanti-post-exploitation-lateral-movement

---

_Auto-generated from the MISP threat-actor galaxy on 2026-04-27._
