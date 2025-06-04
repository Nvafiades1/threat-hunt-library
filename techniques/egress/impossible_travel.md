//  █████  Impossible-Sender / Anomalous Outbound Geo  █████
//  • Whitelists exact VPN IPs  ➟  VpnIPs   (dynamic list)
//  • Whitelists VPN/SWG CIDRs  ➟  VpnCIDRs (dynamic list)
//  • Flags a user when:                                          │
//        – same UPN uses ≥3 different geos inside 6 h            │
//        – the hop between any two geos was <2 h (impossible)    │
//        – at least one mail in the burst carries ≥0.1 MB        │
//  • No heavyweight self-join → memory-safe
//  • Drop/adjust any field-name that differs in your schema
//  -------------------------------------------------------------

//────────  PARAMETERS  ──────────────────────────────────────────
let Lookback        = 24h;          // how far back to search
let BurstWindow     = 6h;
let ImpossibleGapM  = 120;          // 2 h → 120 min
let MinGeos         = 3;            // require ≥3 locations in burst
let MinAttachMB     = 0.1;          // at least 0.1 MB attachments
let SizeField       = "fileSizeBytes";   // name inside attachments[*]

//────────  CORPORATE VPN / SWG ALLOW-LIST  ──────────────────────
let VpnIPs   = dynamic([            // exact POP IPs
    "104.1.2.3", "104.1.2.4"
]);
let VpnCIDRs = dynamic([            // full blocks
    "203.0.113.0/24", "198.51.100.128/25"
]);

//────────  BASE: one row per outbound mail  ─────────────────────
let Base =
    EgressLog
    | where TimeGenerated >= ago(Lookback)
    | where LogSource == "egress"
    // | where direction == "Outbound"           // ← uncomment if present
    | mv-expand attachments
    | extend
          upn        = tostring(identities[0].upn),
          senderLoc  = tostring(senderLocation),
          senderIP   = tostring(senderIp),        // ← adjust if field differs
          fileMB     = iif(isnull(todouble(attachments[SizeField])),
                           0.25,
                           todouble(attachments[SizeField]) / 1048576.0)
    | summarize msgMB = sum(fileMB)
          by upn, senderLoc, senderIP, TimeGenerated
    | where isnotempty(upn) and isnotempty(senderLoc)

    //──── VPN IP / CIDR allow-list  ─────────────────────────────
    | where senderIP !in (VpnIPs)
          and not array_any(
                  VpnCIDRs,
                  (cidr:string) => ipv4_is_in_range(senderIP, cidr)
              );

//────────  PASS 1: “impossible hops” (<2 h, diff geo)  ──────────
let Hops =
    Base
    | sort by upn, TimeGenerated
    | serialize
    | extend
          prevTime = prev(TimeGenerated),
          prevLoc  = prev(senderLoc),
          prevUpn  = prev(upn)
    | extend
          gapM = iff(upn == prevUpn,
                     abs(datetime_diff('minute',
                                        TimeGenerated, prevTime)),
                     999999)
    | where upn == prevUpn
          and senderLoc != prevLoc
          and gapM < ImpossibleGapM
    | project upn, HopTime = TimeGenerated;

//────────  PASS 2: 6-hour burst around each hop  ────────────────
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

//────────  ALERT PAYLOAD  ───────────────────────────────────────
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
      alertTitle = strcat(
                     "🚨 Impossible-sender burst for ",
                     upn, " – ", GeoCount, " geos over ",
                     tostring(LastSeen - FirstSeen))
