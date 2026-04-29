#!/usr/bin/env python3
"""Generate synthetic threat hunt markdown files for matrix/metrics demo.

Output: techniques/<TID>/_synthetic/<TID>-SYNTHETIC-<slug>.md

The leading underscore on the directory and the SYNTHETIC infix in the filename
make these obvious in code review and bulk-deletable with:
    rm -rf techniques/*/_synthetic/
"""
from __future__ import annotations

import os
import textwrap
from pathlib import Path

OUT_ROOT = Path(os.environ.get("OUT_ROOT", "techniques"))

# Each tuple: (TID, slug, tactic, threat_actor, platform, severity, confidence,
#              fidelity, status, hypothesis, query, data_sources, indicators,
#              recommended_actions, next_steps)
HUNTS: list[dict] = [
    # ── Reconnaissance ────────────────────────────────────────────────────────
    dict(
        tid="T1595", tactic="Reconnaissance", slug="external-port-sweep",
        actor="APT28 (Fancy Bear)", platform="Splunk",
        severity="Medium", confidence="Medium", fidelity="Medium", status="Completed",
        hypothesis="External actors are conducting reconnaissance scans against our edge "
                   "infrastructure prior to exploitation attempts. APT28 is known to enumerate "
                   "exposed services at a low-and-slow rate to avoid IDS thresholds.",
        query='index=firewall action=denied src_ip!=10.0.0.0/8 src_ip!=192.168.0.0/16\n'
              '| bucket _time span=1h\n'
              '| stats dc(dest_port) AS unique_ports values(dest_port) AS ports BY src_ip _time\n'
              '| where unique_ports >= 15\n'
              '| sort - unique_ports',
        data_sources="Perimeter firewall logs, IDS alerts, Zeek conn.log",
        indicators="Suspicious source ASNs, contiguous port enumeration, scan signatures",
        actions="Block ASN at edge if scan persists; correlate with auth-failure spikes; "
                "feed source IPs into reputation block list.",
        nextsteps="Pivot to T1190 hunt for any successful exploitation from same source IPs.",
    ),
    dict(
        tid="T1592", tactic="Reconnaissance", slug="public-employee-osint-harvest",
        actor="APT29 (Cozy Bear)", platform="Sentinel",
        severity="Low", confidence="Low", fidelity="Low", status="In Progress",
        hypothesis="Threat actors are scraping public-facing employee data (LinkedIn, GitHub, "
                   "conference talks) to seed phishing pretext. APT29 has used targeted "
                   "spearphishing keyed to recent presentations and posts.",
        query='SigninLogs\n'
              '| where TimeGenerated > ago(30d)\n'
              '| where ResultType == 0\n'
              '| join kind=leftouter (\n'
              '    EmailEvents | where Subject has_any ("conference","speaker","interview")\n'
              ') on $left.UserPrincipalName == $right.RecipientEmailAddress\n'
              '| project UserPrincipalName, IPAddress, Subject, SenderFromAddress',
        data_sources="Microsoft Sentinel SigninLogs, Defender for Office EmailEvents",
        indicators="External email referencing recent public talks/posts, sender domains "
                   "registered <30 days, lookalike employer domains.",
        actions="Run targeted phish-resilience drill for employees with public conference "
                "appearances in last 90 days.",
        nextsteps="Cross-reference with T1566 (Phishing) hunt findings.",
    ),
    # ── Resource Development ──────────────────────────────────────────────────
    dict(
        tid="T1583", tactic="Resource Development", slug="lookalike-domain-callouts",
        actor="Lazarus Group", platform="Splunk",
        severity="High", confidence="Medium", fidelity="Medium", status="Completed",
        hypothesis="Adversaries register typosquat domains of our brand for phishing or "
                   "C2. DNS resolution from internal hosts to those domains indicates a "
                   "lure has reached an endpoint.",
        query='index=dns sourcetype=dns_query\n'
              '| eval domain=lower(query)\n'
              '| where like(domain, "%corp-portal%") AND domain!="corp-portal.example.com"\n'
              '| stats count earliest(_time) AS first_seen latest(_time) AS last_seen BY domain src_ip\n'
              '| sort - count',
        data_sources="Internal recursive DNS, web proxy access logs",
        indicators="Lookalike of brand domain in DNS query, recently registered (<14d), "
                   "Let's Encrypt cert.",
        actions="Sinkhole confirmed lookalikes; submit takedowns; alert recipients of any "
                "outbound mail to those domains.",
        nextsteps="Feed confirmed lookalikes into URL blocklist and email filter.",
    ),
    dict(
        tid="T1587", tactic="Resource Development", slug="adversary-tool-staging-on-cdn",
        actor="APT41", platform="CrowdStrike",
        severity="Medium", confidence="Low", fidelity="Medium", status="Inconclusive",
        hypothesis="Threat actors stage second-stage payloads on legitimate CDNs "
                   "(GitHub Releases, jsDelivr, Discord CDN) to bypass network filtering.",
        query='event_simpleName=DnsRequest\n'
              '| search DomainName IN ("cdn.discordapp.com","raw.githubusercontent.com","cdn.jsdelivr.net")\n'
              '| stats count BY ComputerName DomainName user_name\n'
              '| where count >= 5',
        data_sources="EDR DNS telemetry, proxy URL logs",
        indicators="Endpoint requests to public-CDN URLs ending in .ps1/.exe/.dll/.scr.",
        actions="Block direct binary downloads from public CDNs at the proxy unless "
                "explicitly whitelisted per business unit.",
        nextsteps="Pivot to T1059 (Command Interpreter) for any matched downloads that executed.",
    ),
    # ── Initial Access ────────────────────────────────────────────────────────
    dict(
        tid="T1566", tactic="Initial Access", slug="html-smuggling-attachments",
        actor="APT29 (Cozy Bear)", platform="Defender XDR",
        severity="High", confidence="High", fidelity="High", status="Completed",
        hypothesis="APT29 has shifted to HTML smuggling — embedding encoded payloads in "
                   "HTML attachments that decode and write a file client-side, evading "
                   "gateway scanning.",
        query='EmailAttachmentInfo\n'
              '| where FileName endswith ".html" or FileName endswith ".htm"\n'
              '| join kind=inner EmailEvents on NetworkMessageId\n'
              '| where DeliveryAction == "Delivered"\n'
              '| project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, FileName, FileSize\n'
              '| where FileSize > 50000',
        data_sources="Defender for Office 365 EmailEvents/EmailAttachmentInfo, endpoint "
                     "DeviceFileEvents.",
        indicators="HTML attachments >50KB, base64 blobs in body, JavaScript Blob() / "
                   "msSaveBlob() invocation client-side.",
        actions="Quarantine HTML attachments by policy; require gateway extraction of "
                "embedded blobs.",
        nextsteps="Pivot to T1204 (User Execution) for any extracted payload that ran.",
    ),
    dict(
        tid="T1190", tactic="Initial Access", slug="edge-vpn-cve-exploitation",
        actor="Volt Typhoon", platform="Splunk",
        severity="Critical", confidence="High", fidelity="High", status="Completed",
        hypothesis="Volt Typhoon and similar actors target n-day vulnerabilities in edge "
                   "appliances (Ivanti, Fortinet, Citrix, F5) to gain footholds. Exploit "
                   "attempts often produce signature-detectable URI patterns.",
        query='index=web sourcetype=ivanti OR sourcetype=fortinet OR sourcetype=citrix\n'
              '| regex uri="(?i)(\\.\\./|cgi-bin/|/totp/|aaa_portal|portal/scripts/)"\n'
              '| where status<400\n'
              '| stats count earliest(_time) AS first_seen BY src_ip uri\n'
              '| sort - first_seen',
        data_sources="Edge appliance access logs, WAF logs, EDR on appliance management hosts.",
        indicators="Successful POST to known-vulnerable paths, web shell artifacts "
                   "(getuid.cgi, w.cgi), unusual outbound from appliance.",
        actions="Patch + isolate compromised appliance; rotate all admin creds; pull "
                "appliance config for backdoor persistence (cron, init scripts).",
        nextsteps="Pivot to T1133 (External Remote Services) for follow-on access.",
    ),
    dict(
        tid="T1133", tactic="Initial Access", slug="impossible-travel-vpn-logon",
        actor="Scattered Spider (UNC3944)", platform="Sentinel",
        severity="High", confidence="High", fidelity="Medium", status="Completed",
        hypothesis="UNC3944 obtains valid creds via help-desk social engineering and uses "
                   "them over VPN/SSO from non-baseline geos within a short window of a "
                   "legitimate logon.",
        query='SigninLogs\n'
              '| where ResultType == 0 and AppDisplayName has_any ("VPN","Citrix","Okta")\n'
              '| extend country = tostring(LocationDetails.countryOrRegion)\n'
              '| sort by UserPrincipalName, TimeGenerated\n'
              '| extend prev_country = prev(country, 1), prev_time = prev(TimeGenerated, 1),\n'
              '         prev_user = prev(UserPrincipalName, 1)\n'
              '| where prev_user == UserPrincipalName and prev_country != country\n'
              '         and TimeGenerated - prev_time < 2h',
        data_sources="Azure AD SigninLogs, VPN concentrator logs, Okta system logs.",
        indicators="Same user authenticating from two countries within 2h; new device IDs; "
                   "MFA reset event in preceding 24h.",
        actions="Force re-auth + MFA reset; review help-desk ticket history for the user; "
                "block sign-in from high-risk countries.",
        nextsteps="Pivot to T1078 (Valid Accounts) hunt for downstream activity.",
    ),
    dict(
        tid="T1078", tactic="Initial Access", slug="dormant-service-account-revival",
        actor="APT41", platform="Splunk",
        severity="High", confidence="Medium", fidelity="Medium", status="In Progress",
        hypothesis="Adversaries enumerate AD for stale service accounts (no logon in >180d) "
                   "and use compromised credentials, banking on accounts not being monitored.",
        query='index=wineventlog EventCode=4624 LogonType IN (3,5,7)\n'
              '| eval is_svc=if(match(user, "(?i)(svc|service|sql|app)_"), 1, 0)\n'
              '| where is_svc=1\n'
              '| stats latest(_time) AS last_logon BY user\n'
              '| eval idle_days=round((now() - last_logon)/86400, 0)\n'
              '| where idle_days > 180\n'
              '| sort - idle_days',
        data_sources="Windows security event logs (4624), AD audit, password-last-set attribute.",
        indicators="Service-named accounts going from idle to active, especially with logon "
                   "type 10 (interactive) which they should never use.",
        actions="Disable confirmed-stale service accounts; rotate creds on revived accounts; "
                "add interactive-logon audit rule.",
        nextsteps="Hunt T1003 (Credential Dumping) on hosts that received the dormant logons.",
    ),
    # ── Execution ─────────────────────────────────────────────────────────────
    dict(
        tid="T1059", tactic="Execution", slug="encoded-powershell-from-office",
        actor="MuddyWater", platform="Defender XDR",
        severity="High", confidence="High", fidelity="High", status="Completed",
        hypothesis="MuddyWater spawns base64-encoded PowerShell from Office processes "
                   "(WINWORD/EXCEL/OUTLOOK) — a high-fidelity phishing-execution chain.",
        query='DeviceProcessEvents\n'
              '| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")\n'
              '| where FileName =~ "powershell.exe"\n'
              '| where ProcessCommandLine has_any ("-enc","-encodedcommand","-e ")\n'
              '| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine',
        data_sources="Defender for Endpoint DeviceProcessEvents, Sysmon EID 1.",
        indicators="Office app → powershell.exe with -enc; nested cmd.exe → powershell.exe "
                   "spawn from explorer.exe via macro.",
        actions="Block child-process creation from Office via ASR rule; quarantine endpoint; "
                "decode and analyze script.",
        nextsteps="Pivot to T1071 (Application Layer Protocol) for C2 callouts from decoded script.",
    ),
    dict(
        tid="T1053", tactic="Execution", slug="scheduled-task-suspicious-author",
        actor="APT41", platform="Splunk",
        severity="Medium", confidence="High", fidelity="High", status="Completed",
        hypothesis="Adversaries register scheduled tasks with non-administrative authors "
                   "or NULL author fields to blend in. Most legit tasks are authored by "
                   "Microsoft, vendor agents, or local admins.",
        query='index=wineventlog EventCode=4698\n'
              '| rex field=Message "Task Name:\\s+(?<task_name>[^\\n]+)"\n'
              '| rex field=Message "Subject:\\s+Account Name:\\s+(?<author>[^\\n]+)"\n'
              '| where NOT match(author, "(?i)(SYSTEM|Administrator|svc-)")\n'
              '| stats count BY ComputerName task_name author\n'
              '| where count >= 1',
        data_sources="Windows Task Scheduler operational log (EID 4698, 4702), Sysmon EID 4.",
        indicators="Tasks running at odd times (3am), task actions invoking powershell or "
                   "rundll32, NULL author or random-string author names.",
        actions="Disable + remove suspicious tasks; forensically image host for persistence triage.",
        nextsteps="Pivot to T1547 (Boot/Logon Autostart) for additional persistence on same host.",
    ),
    dict(
        tid="T1204", tactic="Execution", slug="iso-img-double-click",
        actor="APT29 (Cozy Bear)", platform="Defender XDR",
        severity="High", confidence="High", fidelity="Medium", status="Completed",
        hypothesis="ISO/IMG containers bypass MOTW and are mounted by users from email — a "
                   "common APT29 technique. Mount events on user workstations are rare.",
        query='DeviceFileEvents\n'
              '| where FileName endswith ".iso" or FileName endswith ".img" or FileName endswith ".vhd"\n'
              '| where InitiatingProcessFileName in~ ("explorer.exe","outlook.exe","chrome.exe","msedge.exe")\n'
              '| join kind=inner DeviceProcessEvents on DeviceId\n'
              '| where InitiatingProcessFolderPath has "Volume{" or InitiatingProcessFolderPath matches regex "[A-Z]:\\\\\\\\.*\\\\\\\\.*\\\\.iso"\n'
              '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine',
        data_sources="Defender for Endpoint DeviceFileEvents/DeviceProcessEvents.",
        indicators="ISO mount followed by LNK execution → DLL sideload (e.g., wabmig.exe + "
                   "evil DLL), HTA execution, or signed-binary proxy.",
        actions="Group Policy: block ISO/IMG/VHD mounting via file-association GPO; quarantine "
                "endpoint; collect mounted-image contents.",
        nextsteps="Pivot to T1218 (System Binary Proxy Execution) for sideloaded DLL hunt.",
    ),
    # ── Persistence ───────────────────────────────────────────────────────────
    dict(
        tid="T1547", tactic="Persistence", slug="run-key-rare-binary",
        actor="Turla", platform="Sentinel",
        severity="Medium", confidence="Medium", fidelity="Medium", status="Completed",
        hypothesis="New entries in HKCU/HKLM Run/RunOnce keys pointing to binaries outside "
                   "Program Files, Windows, or known vendor paths are likely persistence.",
        query='DeviceRegistryEvents\n'
              '| where ActionType == "RegistryValueSet"\n'
              '| where RegistryKey has_any (\n'
              '    "\\\\CurrentVersion\\\\Run", "\\\\CurrentVersion\\\\RunOnce")\n'
              '| where RegistryValueData !startswith "C:\\\\Program Files" and\n'
              '        RegistryValueData !startswith "C:\\\\Windows" and\n'
              '        RegistryValueData !startswith "\\"C:\\\\Program Files"\n'
              '| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName',
        data_sources="Defender for Endpoint DeviceRegistryEvents, Sysmon EID 13.",
        indicators="Run-key values in user-writable paths (AppData, Temp, Public), random "
                   "filenames, references to scripting interpreters.",
        actions="Validate against software install records; remove if unauthorized; image "
                "host for forensics.",
        nextsteps="Hunt T1027 (Obfuscated Files) on the dropped binary.",
    ),
    dict(
        tid="T1543", tactic="Persistence", slug="suspicious-service-creation",
        actor="Sandworm", platform="Splunk",
        severity="High", confidence="High", fidelity="High", status="Completed",
        hypothesis="Malicious actors install Windows services (e.g. fake-named like "
                   "WindowsUpdateSvc, OneDriveSync) that point to user-writable paths or "
                   "non-vendor binaries. Sandworm has used this for backdoor persistence.",
        query='index=wineventlog EventCode=7045\n'
              '| rex field=Message "Service Name:\\s+(?<svc_name>[^\\n]+)"\n'
              '| rex field=Message "Service File Name:\\s+(?<svc_path>[^\\n]+)"\n'
              '| where match(svc_path, "(?i)(\\\\AppData\\\\|\\\\Temp\\\\|\\\\PerfLogs\\\\|\\\\Users\\\\Public)") OR\n'
              '        match(svc_path, "(?i)\\.(ps1|bat|vbs|js)$")\n'
              '| stats count earliest(_time) AS first BY ComputerName svc_name svc_path',
        data_sources="Windows System log EID 7045, Sysmon EID 1 with parent=services.exe.",
        indicators="New services with binary paths in user-writable directories, scripts as "
                   "ImagePath, services that don't appear on standard image baseline.",
        actions="Stop + remove unauthorized service; rotate creds for the install user; image "
                "for forensics; check for additional persistence (T1547, T1053).",
        nextsteps="Pivot to T1003 (Credential Dumping) on the install host.",
    ),
    dict(
        tid="T1136", tactic="Persistence", slug="new-domain-account-off-hours",
        actor="APT28 (Fancy Bear)", platform="Splunk",
        severity="High", confidence="High", fidelity="High", status="Completed",
        hypothesis="Adversaries create new domain accounts after hours to maintain access. "
                   "Account creation outside of HR onboarding windows or by non-IT principals "
                   "is highly suspicious.",
        query='index=wineventlog EventCode=4720\n'
              '| eval hour=strftime(_time, "%H")\n'
              '| where hour < 6 OR hour > 20\n'
              '| stats count BY src_user new_user ComputerName _time\n'
              '| sort - _time',
        data_sources="Windows security event log EID 4720, AD audit logs.",
        indicators="Account creation at unusual hours, by non-IT-team members, account name "
                   "convention deviating from corporate standard.",
        actions="Disable + audit account; check if added to privileged groups (4728/4732); "
                "review creator's session for compromise.",
        nextsteps="Hunt T1078 (Valid Accounts) for use of the new account.",
    ),
    # ── Privilege Escalation ──────────────────────────────────────────────────
    dict(
        tid="T1068", tactic="Privilege Escalation", slug="kernel-driver-load-unsigned",
        actor="Lazarus Group", platform="CrowdStrike",
        severity="Critical", confidence="High", fidelity="Medium", status="Completed",
        hypothesis="Lazarus and similar actors load vulnerable signed drivers (BYOVD) for "
                   "kernel-level priv-esc. New driver loads from non-vendor paths warrant "
                   "investigation.",
        query='event_simpleName=DriverLoad\n'
              '| search NOT ImageFileName="*\\\\Windows\\\\System32\\\\drivers\\\\*"\n'
              '| stats count earliest(timestamp) AS first BY ComputerName ImageFileName SHA256HashData',
        data_sources="EDR driver-load telemetry, Sysmon EID 6, Windows code-integrity log.",
        indicators="Drivers loaded from user-writable paths, drivers signed by unusual or "
                   "revoked certs, drivers matching public BYOVD lists "
                   "(loldrivers.io).",
        actions="Block driver hash globally via WDAC; reboot affected host; check for kernel-"
                "loaded rootkit artifacts.",
        nextsteps="Hunt T1027 (Obfuscated Files) for related dropper.",
    ),
    dict(
        tid="T1134", tactic="Privilege Escalation", slug="token-impersonation-rare-process",
        actor="APT29 (Cozy Bear)", platform="Defender XDR",
        severity="High", confidence="Medium", fidelity="Medium", status="In Progress",
        hypothesis="Token impersonation/duplication is common in post-exploitation. While "
                   "lsass interaction is heavily monitored, less-watched processes (e.g., "
                   "spoolsv, taskhostw) abusing tokens are a hunt opportunity.",
        query='DeviceProcessEvents\n'
              '| where ProcessCommandLine has_any ("ImpersonateLoggedOnUser","DuplicateTokenEx")\n'
              '| where InitiatingProcessFileName !in~ ("svchost.exe","services.exe","lsass.exe")\n'
              '| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName',
        data_sources="Defender for Endpoint, Sysmon, ETW SecurityAuditing provider.",
        indicators="API call sequences DuplicateTokenEx → CreateProcessWithToken from "
                   "non-system contexts, SeImpersonatePrivilege use by unusual procs.",
        actions="Image host; analyze invoking binary; audit privileged group memberships.",
        nextsteps="Hunt T1003 (Credential Dumping) on related processes.",
    ),
    dict(
        tid="T1548", tactic="Privilege Escalation", slug="uac-bypass-fodhelper",
        actor="Kimsuky", platform="Sentinel",
        severity="Medium", confidence="High", fidelity="High", status="Completed",
        hypothesis="UAC bypass via fodhelper / computerdefaults / sdclt registry hijack is a "
                   "stable technique used by Kimsuky and others.",
        query='DeviceRegistryEvents\n'
              '| where RegistryKey has_any (\n'
              '    "\\\\Software\\\\Classes\\\\ms-settings\\\\Shell\\\\Open\\\\command",\n'
              '    "\\\\Software\\\\Classes\\\\Folder\\\\Shell\\\\Open\\\\command",\n'
              '    "\\\\Software\\\\Classes\\\\exefile\\\\Shell\\\\runas\\\\command")\n'
              '| where RegistryValueName == "DelegateExecute" or RegistryValueData has_any (".exe",".ps1",".bat")',
        data_sources="Defender for Endpoint DeviceRegistryEvents.",
        indicators="Modification of HKCU\\Software\\Classes for ms-settings, exefile, Folder; "
                   "DelegateExecute value cleared then set; subsequent fodhelper.exe spawn.",
        actions="Remove rogue registry entries; image host; rotate user credentials.",
        nextsteps="Hunt T1059 (Command and Scripting Interpreter) for spawned payload.",
    ),
    # ── Defense Evasion ───────────────────────────────────────────────────────
    dict(
        tid="T1027", tactic="Defense Evasion", slug="binaries-with-low-entropy-imports",
        actor="APT41", platform="CrowdStrike",
        severity="Medium", confidence="Low", fidelity="Low", status="Inconclusive",
        hypothesis="Packed/obfuscated binaries often have abnormally few imports or unusually "
                   "high entropy. While not definitive, the combination is a useful hunt seed.",
        query='event_simpleName=ProcessRollup2 AND PE_HighEntropyHeuristic=1\n'
              '| stats count BY ComputerName ImageFileName SHA256HashData\n'
              '| where count <= 3',
        data_sources="EDR static-analysis fields, VirusTotal hash lookups.",
        indicators="High entropy across multiple sections; imports list <10 functions; "
                   "InternalName mismatched with FileName.",
        actions="Submit hash to VT; run binary in sandbox; alert if matched against known "
                "packer signatures.",
        nextsteps="Hunt T1218 (Signed Binary Proxy) for execution chain.",
    ),
    dict(
        tid="T1070", tactic="Defense Evasion", slug="event-log-clear-non-admin",
        actor="Sandworm", platform="Splunk",
        severity="Critical", confidence="High", fidelity="High", status="Completed",
        hypothesis="Event log clearing is a high-fidelity post-compromise signal; legitimate "
                   "clears are rare and almost always from a known admin during maintenance.",
        query='index=wineventlog EventCode=1102 OR EventCode=104\n'
              '| stats values(user) AS users count BY ComputerName _time\n'
              '| sort - _time',
        data_sources="Windows Security log EID 1102, System log EID 104.",
        indicators="Log clear by non-admin user; clear immediately preceded by an "
                   "interactive logon from outside the admin baseline.",
        actions="Treat host as compromised; image + isolate; restore log forwarding from "
                "backup if SIEM forwarding active.",
        nextsteps="Hunt T1486 (Data Encrypted for Impact) — log clearing is often pre-ransomware.",
    ),
    dict(
        tid="T1218", tactic="Defense Evasion", slug="rundll32-suspicious-dll",
        actor="Mustang Panda", platform="Defender XDR",
        severity="High", confidence="Medium", fidelity="Medium", status="Completed",
        hypothesis="rundll32.exe loading DLLs from user-writable paths or with unusual export "
                   "names is a frequent LOLBin technique. Mustang Panda uses sideloading via "
                   "rundll32 frequently.",
        query='DeviceProcessEvents\n'
              '| where FileName =~ "rundll32.exe"\n'
              '| where ProcessCommandLine matches regex "(?i)(AppData|Temp|Public|ProgramData)\\\\\\\\.+\\\\.dll"\n'
              '| project Timestamp, DeviceName, AccountName, ProcessCommandLine',
        data_sources="Defender for Endpoint, Sysmon EID 1, Windows Application log.",
        indicators="rundll32 with full path to user-writable DLL, exports named "
                   "DllRegisterServer or random strings, no parent process auth.",
        actions="Quarantine DLL; image host; rotate cred for invoking user.",
        nextsteps="Hunt T1071 (App Layer Protocol) for outbound C2 from spawned thread.",
    ),
    dict(
        tid="T1112", tactic="Defense Evasion", slug="security-product-tamper-registry",
        actor="Conti", platform="Sentinel",
        severity="High", confidence="High", fidelity="High", status="Completed",
        hypothesis="Ransomware operators (Conti, BlackBasta) disable AV/EDR via registry "
                   "tampering before payload deploy. Modifications to "
                   "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender are a strong signal.",
        query='DeviceRegistryEvents\n'
              '| where RegistryKey has_any (\n'
              '    "\\\\Microsoft\\\\Windows Defender",\n'
              '    "\\\\Policies\\\\Microsoft\\\\Windows Defender",\n'
              '    "\\\\CrowdStrike", "\\\\SentinelOne")\n'
              '| where ActionType == "RegistryValueSet"\n'
              '| where RegistryValueData == "1" and RegistryValueName has_any ("DisableAntiSpyware","DisableRealtimeMonitoring")',
        data_sources="Defender for Endpoint DeviceRegistryEvents, Sysmon EID 13.",
        indicators="Registry sets disabling Defender / EDR; service stops on EDR services; "
                   "tamper-protection alert events.",
        actions="Treat host as imminent ransomware risk; isolate; revert registry; image; "
                "page IR.",
        nextsteps="Hunt T1486 (Data Encrypted for Impact) on host and lateral peers.",
    ),
    # ── Credential Access ─────────────────────────────────────────────────────
    dict(
        tid="T1003", tactic="Credential Access", slug="lsass-access-non-standard-process",
        actor="APT29 (Cozy Bear)", platform="Defender XDR",
        severity="Critical", confidence="High", fidelity="High", status="Completed",
        hypothesis="LSASS handle/memory access by processes other than antivirus or "
                   "lsm.exe/wininit.exe is a high-fidelity dumping signal.",
        query='DeviceEvents\n'
              '| where ActionType == "OpenProcessApiCall"\n'
              '| where TargetProcessFileName =~ "lsass.exe"\n'
              '| where InitiatingProcessFileName !in~ ("MsMpEng.exe","MsSense.exe","wininit.exe","lsm.exe")\n'
              '| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine',
        data_sources="Defender for Endpoint DeviceEvents (OpenProcess), Sysmon EID 10.",
        indicators="comsvcs.dll MiniDump, rundll32 → lsass, mimikatz signatures, ProcDump "
                   "command line targeting lsass.",
        actions="Image host; rotate all interactive-cred passwords used on host in last 7d; "
                "revoke Kerberos tickets via krbtgt rotation if domain controller.",
        nextsteps="Hunt T1550 (Use Alt Auth Material) — pass-the-hash/ticket downstream.",
    ),
    dict(
        tid="T1110", tactic="Credential Access", slug="password-spray-low-and-slow",
        actor="APT33", platform="Sentinel",
        severity="High", confidence="High", fidelity="High", status="Completed",
        hypothesis="Password spray (1-2 attempts/account, many accounts) evades classic "
                   "lockout-based detection. Low-and-slow spray is APT33 / APT28 staple.",
        query='SigninLogs\n'
              '| where ResultType in ("50053","50056","50126")\n'
              '| summarize attempts=count(), users=dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)\n'
              '| where users >= 20 and attempts < 80\n'
              '| sort by users desc',
        data_sources="Azure AD SigninLogs, Okta system logs, Windows EID 4625.",
        indicators="Single source IP failing auth across many distinct users with low "
                   "per-user attempt counts, common spray-friendly passwords (Spring2026!), "
                   "consistent UA string.",
        actions="Block source IP; force MFA reset on any successful logon from same IP; "
                "audit recent ResultType=0 from same IP.",
        nextsteps="Hunt T1078 (Valid Accounts) for any successful sign-ins from spray IPs.",
    ),
    dict(
        tid="T1555", tactic="Credential Access", slug="browser-cred-store-access",
        actor="FIN7", platform="CrowdStrike",
        severity="High", confidence="Medium", fidelity="Medium", status="In Progress",
        hypothesis="Browser-stored credentials (Chrome Login Data, Edge / Brave SQLite "
                   "stores) are commonly stolen by infostealers and FIN7 droppers.",
        query='event_simpleName=FileOpenInfo\n'
              '| search TargetFileName IN ("*\\\\Login Data","*\\\\Cookies","*\\\\Web Data")\n'
              '| search NOT ImageFileName=("*chrome.exe","*msedge.exe","*brave.exe","*firefox.exe")\n'
              '| stats count BY ComputerName ImageFileName TargetFileName',
        data_sources="EDR file-open telemetry, Sysmon EID 11.",
        indicators="Non-browser process opening browser SQLite; SELECT against Login Data "
                   "from cmd.exe-spawned processes; staging of decrypted creds in Temp.",
        actions="Image host; force pwd reset for any creds in browser store; block AppLocker "
                "on suspicious binary.",
        nextsteps="Hunt T1567 (Exfil Over Web Service) for stolen-cred upload.",
    ),
    # ── Discovery ─────────────────────────────────────────────────────────────
    dict(
        tid="T1083", tactic="Discovery", slug="recursive-share-enumeration",
        actor="LockBit", platform="Splunk",
        severity="Medium", confidence="Medium", fidelity="Medium", status="Completed",
        hypothesis="Pre-encryption and pre-exfil, ransomware operators enumerate file shares "
                   "looking for valuable data — this produces a burst of file-system discovery.",
        query='index=wineventlog EventCode=5145\n'
              '| stats dc(ShareName) AS shares dc(RelativeTargetName) AS files BY src_user src_ip _time\n'
              '| where files >= 1000\n'
              '| sort - files',
        data_sources="Windows file-share access events (EID 5140/5145), file-server audit logs.",
        indicators="Single user enumerating thousands of files across shares in <1h; access "
                   "patterns matching tools like SoftPerfect Network Scanner or Lazagne.",
        actions="Disable user; image source host; review file-server access logs for "
                "exfil-staged files.",
        nextsteps="Hunt T1567 (Exfil Over Web Service) for upload of staged data.",
    ),
    dict(
        tid="T1057", tactic="Discovery", slug="process-discovery-tasklist-burst",
        actor="MuddyWater", platform="Sentinel",
        severity="Low", confidence="Medium", fidelity="Low", status="Completed",
        hypothesis="Adversaries enumerate running processes via tasklist.exe / Get-Process "
                   "to identify AV/EDR. Bursts of these from a single user are a hunt seed.",
        query='DeviceProcessEvents\n'
              '| where FileName in~ ("tasklist.exe","qprocess.exe") or\n'
              '       (FileName =~ "powershell.exe" and ProcessCommandLine has "Get-Process")\n'
              '| summarize execs=count() by AccountName, DeviceName, bin(Timestamp, 5m)\n'
              '| where execs >= 3',
        data_sources="Defender for Endpoint, Sysmon EID 1.",
        indicators="Multiple process-discovery binaries within 5min, often paired with "
                   "systeminfo / whoami / net commands.",
        actions="Investigate originating user session; check parent process chain; review "
                "subsequent commands.",
        nextsteps="Hunt T1018 (Remote System Discovery) on same session.",
    ),
    dict(
        tid="T1018", tactic="Discovery", slug="ad-recon-bloodhound-collector",
        actor="APT28 (Fancy Bear)", platform="Splunk",
        severity="High", confidence="High", fidelity="High", status="Completed",
        hypothesis="BloodHound / SharpHound / AdFind collection produces distinctive LDAP "
                   "queries against AD — heavy LDAP from a single non-admin host is a strong "
                   "hunt signal.",
        query='index=wineventlog EventCode=4662 ObjectType="user"\n'
              '| stats count BY src_user ComputerName _time\n'
              '| where count > 200\n'
              '| sort - count',
        data_sources="DC security log EID 4662, Sysmon EID 22 (DNS), endpoint EDR.",
        indicators="LDAP search rates >200/hr from non-admin host; SharpHound binary on disk; "
                   "AdFind / nltest exec.",
        actions="Audit LDAP filter strings (BloodHound has signature filters); rotate creds "
                "for the executing user; image host.",
        nextsteps="Hunt T1110 (Brute Force) — recon often precedes spray.",
    ),
    # ── Lateral Movement ──────────────────────────────────────────────────────
    dict(
        tid="T1021", tactic="Lateral Movement", slug="rdp-from-non-admin-workstation",
        actor="Scattered Spider (UNC3944)", platform="Sentinel",
        severity="High", confidence="High", fidelity="High", status="Completed",
        hypothesis="RDP from regular user workstations to servers (or between non-admin "
                   "endpoints) is rare in well-segmented environments. UNC3944 uses RDP "
                   "extensively post-foothold.",
        query='DeviceLogonEvents\n'
              '| where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess"\n'
              '| join kind=inner (DeviceInfo | summarize arg_max(Timestamp, *) by DeviceName)\n'
              '       on DeviceName\n'
              '| where DeviceCategory != "Server" and InitiatingProcessAccountName !contains "admin"\n'
              '| project Timestamp, DeviceName, RemoteDeviceName, AccountName',
        data_sources="Windows EID 4624 LogonType 10, EID 4778, Sysmon network telemetry.",
        indicators="RDP between two user-class workstations; RDP from user-class to server "
                   "outside change window; new-device certificates on RDP server.",
        actions="Block RDP host-to-host with firewall rule; require RDP only from PAW; "
                "rotate user creds.",
        nextsteps="Hunt T1003 (Credential Dumping) on the RDP source host.",
    ),
    dict(
        tid="T1570", tactic="Lateral Movement", slug="smb-tool-transfer-rare-share",
        actor="APT29 (Cozy Bear)", platform="Splunk",
        severity="Medium", confidence="Medium", fidelity="Medium", status="In Progress",
        hypothesis="Adversaries often copy follow-on tooling via SMB to admin$/c$ shares of "
                   "a target host. Writes from non-admin source workstations are suspicious.",
        query='index=wineventlog EventCode=5145 ShareName IN ("\\\\\\\\*\\\\ADMIN$","\\\\\\\\*\\\\C$")\n'
              '| where Accesses="*WriteData*"\n'
              '| stats count BY src_ip src_user ShareName RelativeTargetName _time\n'
              '| sort - _time',
        data_sources="Windows file-share audit logs (5140/5145), EDR network connection events.",
        indicators="Writes to ADMIN$/C$ from user workstations; .exe/.dll/.ps1 dropped to "
                   "remote system32 path.",
        actions="Block SMB host-to-host across user segments; review SMB auth logs for source.",
        nextsteps="Hunt T1543 (Service Creation) on the destination for service-based exec.",
    ),
    dict(
        tid="T1550", tactic="Lateral Movement", slug="kerberos-golden-ticket-anomaly",
        actor="APT41", platform="Sentinel",
        severity="Critical", confidence="Medium", fidelity="Medium", status="In Progress",
        hypothesis="Golden tickets are forged TGTs with arbitrary lifetime/group membership. "
                   "Tickets with abnormal lifetimes (>10h) or referencing unknown groups are "
                   "a forgery indicator.",
        query='SecurityEvent | where EventID == 4769\n'
              '| extend lifetime_hours = todouble(TicketEncryptionType) // proxy field\n'
              '| where TicketOptions has "0x40810000"  // unusual options\n'
              '| project TimeGenerated, Computer, TargetUserName, ServiceName, IpAddress, TicketOptions',
        data_sources="DC security log EID 4769, EID 4624 logon-type 3 with unusual sids.",
        indicators="TGT lifetime >10h, encryption types not matching GPO, RID 500 group-"
                   "membership claim from non-default user.",
        actions="Rotate krbtgt twice (separated by replication interval); audit privileged "
                "group memberships; force re-issue all TGTs.",
        nextsteps="Hunt T1003 (Credential Dumping) on DCs and recently RDP'd admin hosts.",
    ),
    # ── Collection ────────────────────────────────────────────────────────────
    dict(
        tid="T1056", tactic="Collection", slug="keylogger-installation-via-startup",
        actor="Charming Kitten (APT35)", platform="CrowdStrike",
        severity="Medium", confidence="Medium", fidelity="Medium", status="Completed",
        hypothesis="Keyloggers register via the SetWindowsHookEx API or as low-level keyboard "
                   "drivers. Installation often coincides with Run-key persistence.",
        query='event_simpleName=ProcessRollup2\n'
              '| search CommandLine="*SetWindowsHookEx*" OR CommandLine="*WH_KEYBOARD*"\n'
              '| stats count BY ComputerName ImageFileName CommandLine',
        data_sources="EDR process-creation events, ETW WindowsKernel hook telemetry.",
        indicators="API call sequences SetWindowsHookEx + WH_KEYBOARD; new keyboard-class "
                   "driver loads; persistence + low-level network in same session.",
        actions="Image host; rotate all credentials typed since hook install (timestamp "
                "from EDR).",
        nextsteps="Hunt T1041 (Exfil over C2 Channel) for keylog upload.",
    ),
    dict(
        tid="T1113", tactic="Collection", slug="screen-capture-non-conferencing-process",
        actor="APT28 (Fancy Bear)", platform="Defender XDR",
        severity="Medium", confidence="Low", fidelity="Low", status="Inconclusive",
        hypothesis="Screen-capture APIs called from binaries that aren't conferencing / "
                   "screen-recording tools (Teams, Zoom, OBS) suggest covert collection.",
        query='DeviceImageLoadEvents\n'
              '| where FileName == "gdi32.dll"\n'
              '| where InitiatingProcessFileName !in~ ("teams.exe","zoom.exe","obs64.exe","msedge.exe","chrome.exe")\n'
              '| join kind=inner (DeviceProcessEvents | where ProcessCommandLine has_any ("BitBlt","CaptureBitmap"))\n'
              '       on DeviceId\n'
              '| project Timestamp, DeviceName, InitiatingProcessFileName',
        data_sources="Defender for Endpoint DeviceImageLoadEvents, Sysmon EID 7.",
        indicators="Non-conferencing app loading gdi32 + invoking BitBlt; PNG/JPEG file "
                   "writes to Temp from those processes.",
        actions="Sandbox-analyze the binary; review for related collection (clipboard, "
                "audio).",
        nextsteps="Hunt T1056 (Input Capture) on same host.",
    ),
    # ── Command and Control ───────────────────────────────────────────────────
    dict(
        tid="T1071", tactic="Command and Control", slug="dns-tunnel-rare-resolver",
        actor="APT41", platform="Splunk",
        severity="High", confidence="High", fidelity="Medium", status="Completed",
        hypothesis="DNS tunneling produces high query rates with unusually long subdomain "
                   "labels. APT41 has used iodine-style tunnels for backup C2.",
        query='index=dns\n'
              '| eval label_len=len(query)\n'
              '| where label_len > 50\n'
              '| stats count avg(label_len) AS avg_len BY src_ip dest_domain\n'
              '| where count > 100',
        data_sources="Recursive DNS resolver logs, passive DNS, EDR DNS telemetry.",
        indicators="Subdomain labels >50 chars; high query rate to single second-level "
                   "domain; TXT/NULL record queries from endpoints.",
        actions="Sinkhole the second-level domain; block at DNS firewall; image source host.",
        nextsteps="Hunt T1041 (Exfil Over C2) for staged data egress patterns.",
    ),
    dict(
        tid="T1573", tactic="Command and Control", slug="tls-jarm-anomaly",
        actor="Cobalt Strike Operators", platform="Splunk",
        severity="Medium", confidence="Medium", fidelity="High", status="Completed",
        hypothesis="JARM fingerprints of Cobalt Strike teamservers are well-documented. "
                   "Outbound TLS to destinations with known-malicious JARM is high-fidelity.",
        query='index=zeek sourcetype=ssl\n'
              '| lookup malicious_jarm.csv jarm_fp AS jarm OUTPUT family\n'
              '| where isnotnull(family)\n'
              '| stats count earliest(_time) AS first BY src_ip dest_ip jarm family',
        data_sources="Zeek SSL logs with JARM enrichment, threat-intel JARM blocklist.",
        indicators="JARM matching CS / Brute Ratel / Sliver public fingerprints; outbound to "
                   "VPS ASNs; certificate Subject mismatched with hostname.",
        actions="Block destination at egress; image source; rotate creds on host.",
        nextsteps="Hunt T1090 (Proxy) for relay infrastructure.",
    ),
    dict(
        tid="T1090", tactic="Command and Control", slug="residential-proxy-egress",
        actor="Scattered Spider (UNC3944)", platform="Sentinel",
        severity="High", confidence="Medium", fidelity="Medium", status="In Progress",
        hypothesis="Adversaries route C2 through residential proxy networks (911 S5, "
                   "BrightData) to defeat geographic detections. Outbound to known "
                   "residential proxy ranges from corporate endpoints is anomalous.",
        query='SigninLogs\n'
              '| where ResultType == 0\n'
              '| extend asn = tostring(parse_json(NetworkLocationDetails)[0].networkType)\n'
              '| where asn == "namedNetwork" and IPAddress in (\n'
              '    // residential proxy IP feed import\n'
              '    "203.0.113.0", "198.51.100.5"\n'
              ')\n'
              '| project TimeGenerated, UserPrincipalName, IPAddress',
        data_sources="Sentinel SigninLogs, NetFlow / firewall egress, residential-proxy IoC feed.",
        indicators="Auth from known residential proxy ranges; rapidly rotating IPs across "
                   "auth attempts; matches against Spamhaus / Spur.us residential intel.",
        actions="Block IP at edge; force MFA + session reset; review user help-desk history.",
        nextsteps="Hunt T1133 (External Remote Services) for prior VPN access from same IPs.",
    ),
    # ── Exfiltration ──────────────────────────────────────────────────────────
    dict(
        tid="T1041", tactic="Exfiltration", slug="c2-channel-large-uploads",
        actor="APT41", platform="Splunk",
        severity="High", confidence="High", fidelity="Medium", status="Completed",
        hypothesis="When data leaves over an established C2 channel, byte-out >> byte-in "
                   "asymmetry per session is a hallmark of exfil.",
        query='index=zeek sourcetype=conn\n'
              '| where orig_bytes > 50000000 and resp_bytes < orig_bytes/10\n'
              '| stats sum(orig_bytes) AS bytes_out BY src_ip dest_ip dest_port\n'
              '| sort - bytes_out',
        data_sources="Zeek conn.log, NetFlow with byte counts, EDR network events.",
        indicators="Single host >50MB outbound to one destination with low inbound; "
                   "destination ASN = VPS / hosting / cloud-storage.",
        actions="Block destination; image host; review for compressed staging artifacts (.7z, .zip).",
        nextsteps="Hunt T1560 (Archive Collected Data) on host.",
    ),
    dict(
        tid="T1567", tactic="Exfiltration", slug="cloud-storage-uploads",
        actor="Lazarus Group", platform="Defender XDR",
        severity="High", confidence="High", fidelity="High", status="Completed",
        hypothesis="Adversaries use legit cloud storage (mega.nz, anonfiles, tmpfiles) for "
                   "exfil to bypass DLP. Endpoint connections to those domains warrant review.",
        query='DeviceNetworkEvents\n'
              '| where RemoteUrl has_any (\n'
              '    "mega.nz","anonfiles.com","tmpfiles.org","transfer.sh","filebin.net","gofile.io")\n'
              '| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, BytesSent\n'
              '| where BytesSent > 1000000',
        data_sources="Defender for Endpoint DeviceNetworkEvents, web proxy logs.",
        indicators="Outbound to file-sharing services from non-browser process; large POST "
                   "(>1MB) to those domains; staged archives in Temp before connection.",
        actions="Block file-sharing domains at proxy; image host; review files in process "
                "working dir.",
        nextsteps="Hunt T1560 for archives; T1003 if creds were in scope.",
    ),
    dict(
        tid="T1048", tactic="Exfiltration", slug="ssh-outbound-rare-destination",
        actor="APT28 (Fancy Bear)", platform="Splunk",
        severity="Medium", confidence="Medium", fidelity="Medium", status="In Progress",
        hypothesis="Outbound SSH from corporate hosts to non-vendor IPs is rare in most "
                   "enterprises. Adversaries use SSH for tunneling and exfil.",
        query='index=firewall app=ssh dest_port=22 dest_ip!=10.0.0.0/8\n'
              '| iplocation dest_ip\n'
              '| stats count earliest(_time) AS first BY src_ip dest_ip Country\n'
              '| where count >= 5',
        data_sources="Firewall / NetFlow application-aware logs, EDR network telemetry.",
        indicators="SSH outbound to country / ASN not on baseline; long-running SSH sessions; "
                   "high outbound bytes ratio.",
        actions="Block egress SSH from non-engineering segments; require jump-host for any "
                "outbound SSH.",
        nextsteps="Hunt T1090 (Proxy) for tunneling traffic patterns.",
    ),
    # ── Impact ────────────────────────────────────────────────────────────────
    dict(
        tid="T1486", tactic="Impact", slug="ransomware-mass-rename",
        actor="LockBit", platform="CrowdStrike",
        severity="Critical", confidence="High", fidelity="High", status="Completed",
        hypothesis="Ransomware encryption produces a burst of file rename + write events "
                   "with new extensions across a single host or share.",
        query='event_simpleName=FileRenameInfo\n'
              '| eval new_ext=mvindex(split(NewFileName, "."), -1)\n'
              '| where len(new_ext) IN (4,5,6,7,8) AND match(new_ext, "[a-z0-9]{5,}")\n'
              '| stats dc(NewFileName) AS files BY ComputerName new_ext _time\n'
              '| where files >= 200',
        data_sources="EDR file-rename events, Sysmon EID 11, file-server audit.",
        indicators=">200 file renames with same extension within 5min; ransom note files "
                   "(README.txt, !!!HELP!!!.txt) appearing in many directories; volume "
                   "shadow copy deletion immediately preceding.",
        actions="Isolate host immediately; trigger IR; restore from immutable backup; rotate "
                "all admin creds.",
        nextsteps="Hunt T1490 (Inhibit Recovery), T1070 (Indicator Removal) on same host.",
    ),
    dict(
        tid="T1490", tactic="Impact", slug="vss-shadow-copy-deletion",
        actor="BlackBasta", platform="Sentinel",
        severity="Critical", confidence="High", fidelity="High", status="Completed",
        hypothesis="Volume Shadow Copy deletion is a near-universal ransomware precursor. "
                   "vssadmin / wbadmin / wmic shadowcopy commands are very high-fidelity.",
        query='DeviceProcessEvents\n'
              '| where ProcessCommandLine has_any (\n'
              '    "vssadmin delete shadows","vssadmin resize shadowstorage",\n'
              '    "wbadmin delete catalog","wmic shadowcopy delete",\n'
              '    "bcdedit /set bootstatuspolicy","bcdedit /set recoveryenabled no")\n'
              '| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
        data_sources="Defender for Endpoint, Sysmon EID 1, Windows Application log.",
        indicators="vssadmin delete shadows /all /quiet; wbadmin delete catalog -quiet; "
                   "bcdedit recovery disable.",
        actions="Treat host as imminent ransomware; isolate; image; trigger IR; rotate creds.",
        nextsteps="Hunt T1486 (Data Encrypted) and T1112 (Modify Registry, AV tamper).",
    ),
]


# ── Renderer ─────────────────────────────────────────────────────────────────

TEMPLATE = """### MITRE Technique ID
{tid}

### Threat Hunt ID
TH-SYNTH-{idx:03d}

### Created
2026-04-29T12:00:00Z

### Last Modified
2026-04-29T12:00:00Z

### Hypothesis
{hypothesis}

### Applicable ATT&CK Tactic(s)
- [x] {tactic}

### Impacted Systems
Generic enterprise endpoints, domain controllers, and edge appliances.

### Detection Window
Last 30 days, rolling.

### Hunt Platform
{platform}

### Data Sources
{data_sources}

### Hunt Query
```
{query}
```

### Hunter Notes
Synthetic hunt for matrix coverage / metrics demo. Do not use as production guidance.

### Findings Summary
Synthetic data — no actual findings.

### Threat Actor
{actor}

### Observed Indicators (IOCs)
{indicators}

### Supporting Evidence / Screenshots
_no response_

### Severity
{severity}

### Confidence
{confidence}

### Query Fidelity
{fidelity}

### Status
{status}

### Visibility Gaps
None identified — synthetic.

### Recommended Actions
{actions}

### Next Steps
{nextsteps}

### Additional Tags
synthetic, demo, {tactic_tag}
"""


def render(idx: int, h: dict) -> str:
    return TEMPLATE.format(
        idx=idx,
        tid=h["tid"],
        hypothesis=h["hypothesis"],
        tactic=h["tactic"],
        platform=h["platform"],
        data_sources=h["data_sources"],
        query=h["query"],
        actor=h["actor"],
        indicators=h["indicators"],
        severity=h["severity"],
        confidence=h["confidence"],
        fidelity=h["fidelity"],
        status=h["status"],
        actions=h["actions"],
        nextsteps=h["nextsteps"],
        tactic_tag=h["tactic"].lower().replace(" ", "-").replace("&", "and"),
    )


def main():
    out_files = []
    for idx, h in enumerate(HUNTS, start=1):
        body = render(idx, h)
        relpath = Path(h["tid"]) / "_synthetic" / f"{h['tid']}-SYNTHETIC-{h['slug']}.md"
        full = OUT_ROOT / relpath
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(body)
        out_files.append(full)
    print(f"Wrote {len(out_files)} synthetic hunts under {OUT_ROOT}/")
    for f in out_files:
        print(f"  {f}")


if __name__ == "__main__":
    main()
