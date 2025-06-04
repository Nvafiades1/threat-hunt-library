//  Impossible-Sender / Anomalous Outbound Geo  – FIXED
//------------------------------------------------------------------
//  • No heavyweight self-join (uses prev())
//  • Works even if attachments lack explicit size (default 0.25 MB)
//  • VPN allow-list, ≥3 geos in 6 h, ≥0.1 MB attachments
//------------------------------------------------------------------

// ─── PARAMETERS ───────────────────────────────────────────────
let Lookback        = 24h;
let BurstWindow     = 6h;
let ImpossibleGapM  = 120;        // 2 h → 120 minutes
let MinGeos         = 3;
let MinAttachMB     = 0.1;
let VpnLocations    = dynamic(["US-VPN-NY","US-VPN-LA"]);
let SizeField       = "fileSizeBytes";   // change if different

// ─── BASE table: one row per outbound e-mail ─────────────────
let Base =
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
    | summarize msgMB = sum(fileMB)
          by upn, senderLoc, TimeGenerated
    | where isnotempty(upn) and isnotempty(senderLoc)
          and senderLoc !in (VpnLocations);

// ─── PASS 1: detect “impossible” hops (< 2 h, diff geo) ──────
let Hops =
    Base
    | sort by upn, TimeGenerated
    | serialize                            // prev()/next() now reliable
    | extend
          prevTime = prev(TimeGenerated),
          prevLoc  = prev(senderLoc),
          prevUpn  = prev(upn)
    | extend
          sameUser = upn == prevUpn,
          gapM     = iff(sameUser,
                         abs(datetime_diff('minute', TimeGenerated, prevTime)),
                         999999)
    | where sameUser
          and senderLoc != prevLoc
          and gapM < ImpossibleGapM
    | project upn, HopTime = TimeGenerated;

// ─── PASS 2: burst analysis (≥3 geos in 6 h) ─────────────────
Hops
| join kind=inner (Base) on upn
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

// ─── ALERT PAYLOAD ───────────────────────────────────────────
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
      alertTitle = strcat("🚨 Impossible-sender burst for ",
                          upn, " – ", GeoCount,
                          " geos over ",
                          tostring(LastSeen - FirstSeen))
