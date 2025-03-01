# Application or System Exploitation

**Technique ID:** T1499.004

**Description:**
Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. (Citation: Sucuri BIND9 August 2015) Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent denial of service (DoS) condition.

Adversaries may exploit known or zero-day vulnerabilities to crash applications and/or systems, which may also lead to dependent applications and/or systems to be in a DoS condition. Crashed or restarted applications or systems may also have other effects such as [Data Destruction](https://attack.mitre.org/techniques/T1485), [Firmware Corruption](https://attack.mitre.org/techniques/T1495), [Service Stop](https://attack.mitre.org/techniques/T1489) etc. which may further cause a DoS condition and deny availability to critical information, applications and/or systems. 
