// ───────── PARAMETERS ─────────
let Lookback       = 24h;
let BurstWindow    = 6h;
let ImpossibleGap  = 2h;
let ImpossibleGapM = toint(ImpossibleGap / 1m);
let MinGeos        = 3;
let MinAttachMB    = 0.1;
let VpnLocations   = dynamic(["US-VPN-NY","US-VPN-LA"]);
let SizeField      = "fileSizeBytes";   // change if different

// ───────── PREP: per-message attachment MB & basic filters ─────────
let Mail =
    EgressLog
    | where TimeGenerated >= ago(Lookback)
    | where LogSource == "egress"
    // | where direction == "Outbound"
    | mv-expand attachments
    | extend  upn        = tostring(identities[0].upn),
              senderLoc  = tostring(senderLocation),
              fileMB     = iif(isnull(todouble(attachments[SizeField])),
                               0.25,
                               todouble(attachments[SizeField]) / 1048576.0)
    | summarize msgMB = sum(fileMB)            // one row per message
          by upn, senderLoc, TimeGenerated
    | where isnotempty(upn) and isnotempty(senderLoc)
    | where senderLoc !in (VpnLocations);

// ───────── PASS 1: find all “impossible hops” (<2 h, diff geo) ──────
let Hops =
    Mail
    | sort by upn, TimeGenerated
    | serialize                          // guarantees sequential prev()
    | extend prevTime = prev(TimeGenerated),
             prevLoc  = prev(senderLoc),
             gapM     = iff(isnull(prevTime), 999999,
                            abs(datetime_diff('minute', TimeGenerated, prevTime)))
    | where upn == prev(upn)             // same user as previous row
          and senderLoc != prevLoc       // geo changed
          and gapM < ImpossibleGapM
    | project upn, HopTime = TimeGenerated;

// ───────── PASS 2: build 6-hour bursts around each hop ──────────────
Hops
| join kind=inner (Mail) on upn
| where TimeGenerated between (HopTime .. HopTime + BurstWindow)
| summarize
      FirstSeen = min(TimeGenerated),
      LastSeen  = max(TimeGenerated),
      Geos      = make_set(senderLoc, 5),
      MaxMB     = max(msgMB)
    by upn
| extend GeoCount = array_length(Geos)
| where GeoCount >= MinGeos
      and MaxMB    >= MinAttachMB

// ───────── ALERT PAYLOAD ────────────────────────────────────────────
| project
      TimeGenerated = FirstSeen,
      upn,
      Geos,
      GeoCount,
      FirstSeen,
      LastSeen,
      MaxAttachMB = round(MaxMB,2),
      severity   = "High",
      tactic     = "Initial Access",
      technique  = "Valid Accounts (T1078)",
      alertTitle = strcat("🚨 Impossible-sender burst for ", upn,
                          " – ", GeoCount, " geos over ",
                          tostring(LastSeen - FirstSeen))
