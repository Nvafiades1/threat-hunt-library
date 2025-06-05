// ─────────  File-open events that touch the SAM / SECURITY / SYSTEM hives  ─────────
database('Endpoint').CrowdStrikeFDR
| where TimeGenerated >= ago(14d)                                  // look-back
| where event_simpleName == "FileOpenInfo"
| project ActingProcessID = tolong(ContextProcessId),
          TimeGenerated,
          TargetFile   = tolower(tostring(TargetFileName))
// cheap string tests instead of regex
| where TargetFile has @"\windows\system32\config\"
      and (TargetFile has "sam" or TargetFile has "security" or TargetFile has "system")
      and (TargetFile endswith ".log" or TargetFile endswith ".sav"
           or TargetFile endswith ".bak" or TargetFile endswith ".hiv")
// keep newest row per process ⇒ huge row reduction
| summarize arg_max(TimeGenerated, TargetFile) by ActingProcessID

// ─────────  JOIN to the matching ProcessRollup2 row  ─────────
| join kind=innerunique (
    database('Endpoint').CrowdStrikeFDR
    | where TimeGenerated >= ago(14d)
    | where event_simpleName == "ProcessRollup2"
    | project  pid_target   = tolong(TargetProcessId),
               TimeGenerated,
               ComputerName,
               proc_image   = tolower(ImageFileName),
               parent_image = tolower(ParentBaseFileName),
               cmdline      = tostring(CommandLine)
    | summarize arg_max(TimeGenerated, ComputerName,
                        proc_image, parent_image, cmdline) by pid_target
) on $left.ActingProcessID == $right.pid_target

// ─────────  Lightweight scoring & noise-gate  ─────────
| extend is_whitelisted = proc_image in (dynamic([
        @"c:\windows\system32\lsass.exe",
        @"c:\windows\system32\services.exe",
        @"c:\windows\system32\winlogon.exe",
        @"c:\windows\system32\svchost.exe",
        @"c:\windows\system32\taskhostw.exe"
    ])),
         bad_parent  = parent_image in (dynamic([
        "cmd.exe","powershell.exe","wscript.exe","explorer.exe"
    ])),
         masquerade  = proc_image endswith "lsass.exe"
                       and not proc_image startswith @"c:\windows\system32"
| extend file_score  = 1,
         proc_score  = iff(is_whitelisted, 0, 2),
         evade_score = iff(bad_parent or masquerade, 3, 0),
         total_score = file_score + proc_score + evade_score
| where total_score >= 3                                            // alert threshold

| project-reorder TimeGenerated, ComputerName,
                   proc_image, parent_image, cmdline,
                   TargetFile, total_score
