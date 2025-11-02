# Disable or Modify Network Device Firewall

**Technique ID:** T1562.013

**Description:**
Adversaries may disable network device-based firewall mechanisms entirely or add, delete, or modify particular rules in order to bypass controls limiting network usage. 
 
Modifying or disabling a network firewall may enable adversary C2 communications, lateral movement, and/or data exfiltration that would otherwise not be allowed. For example, adversaries may add new network firewall rules to allow access to all internal network subnets without restrictions.(Citation: Exposed Fortinet Fortigate firewall interface leads to LockBit Ransomware)

Adversaries may gain access to the firewall management console via [Valid Accounts](https://attack.mitre.org/techniques/T1078) or by exploiting a vulnerability. In some cases, threat actors may target firewalls that have been exposed to the internet [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190).(Citation: CVE-2024-55591 Detail)
