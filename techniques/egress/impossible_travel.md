//  █████████████  Impossible-Sender / Anomalous Outbound Geo  █████████████
//
//  Purpose :  Alert when the **same internal UPN** sends OUTBOUND mail
//             from ≥3 DIFFERENT geo-locations inside a 6-hour burst
//             and at least one message in that burst carries
//             ≥ 0.1 MB of attachments.
//
//  CHANGES vs. original draft
//  ────────────────────────────────────────────────────────────
//    1.  NEW per-message attachment MB calculation (lines marked ★).
//    2.  Removed service-suffix filter (you asked to drop it).
//    3.  VPN allow-list kept.
//    4.  Burst summary now uses **MaxMB** instead of MaxAttach.
//    5.  All timespan math now numeric (ImpossibleGapM, etc.).
//  ────────────────────────────────────────────────────────────


//────────────────────────  PARAMETERS  ────────────────────────
let Lookback        = 24h;           // historical search window
let BurstWindow     = 6h;            // window to count distinct geos
let ImpossibleGap   = 2h;
let ImpossibleGapM  = toint(ImpossibleGap / 1m);  // 120  ← numeric
let MinGeos         = 3;
let MinAttachMB     = 0.1;           // fire only if ≥0.1 MB in burst
let VpnLocations    = dynamic(["US-VPN-NY","US-VPN-LA","UK-VPN-LON"]);

// (★)  If each attachment object carries a file-size property, list it here
let SizeField = "fileSizeBytes";     // change to "sizeBytes", etc.


//────────────────────────  BASE TABLE  ────────────────────────
let Base =
    EgressLog
    | where TimeGenerated >= ago(Lookback)
    | where LogSource == "egress"
    // | where direction == "Outbound"          // uncomment if present
    | mv-expand attachments
    | extend
          upn        = tostring(identities[0].upn),
          senderLoc  = tostring(senderLocation),
          // (★) derive per-file size in MB
          fileMB     = iif(isnull(todouble(attachments[SizeField])),
                           0.25,                              // fallback size
                           todouble(attachments[SizeField]) / 1048576.0)
    // collapse to one row per message with total MB
    | summarize msgMB = sum(fileMB)
          by upn, senderLoc, TimeGenerated
    | where isnotempty(upn) and isnotempty(senderLoc)
    | where senderLoc !in (VpnLocations);



//────────────────────  IMPOSSIBLE HOPS (<2 h)  ─────────────────
let Hops =
    Base
    | project upn, TimeGenerated, senderLoc
    | join kind=inner (
          Base
          | project upn, Time2 = TimeGenerated, loc2 = senderLoc
      ) on upn
    | where senderLoc != loc2
    | extend gapM = abs(datetime_diff('minute', TimeGenerated, Time2))
    | where gapM < ImpossibleGapM
    | project upn, HopTime = min(TimeGenerated, Time2);



//───────────────────  BURST (≥3 geos in 6 h)  ──────────────────
Hops
| join kind=inner (Base) on upn
| where TimeGenerated between (HopTime .. HopTime + BurstWindow)
| summarize
      FirstSeen = min(TimeGenerated),
      LastSeen  = max(TimeGenerated),
      Geos      = make_set(senderLoc, 5),
      MaxMB     = max(msgMB)                              // (★)
    by upn
| extend GeoCount = array_length(Geos)
| where GeoCount >= MinGeos
      and MaxMB    >= MinAttachMB                        // (★)



//────────────────────────  ALERT  ──────────────────────────────
| project
      TimeGenerated = FirstSeen,
      upn,
      Geos,
      GeoCount,
      FirstSeen,
      LastSeen,
      MaxAttachMB = round(MaxMB, 2),
      severity   = "High",
      tactic     = "Initial Access",
      technique  = "Valid Accounts (T1078)",
      alertTitle = strcat("🚨 Impossible sender burst for ",
                          upn, " – ", GeoCount, " geos in ",
                          toduration(LastSeen - FirstSeen))
