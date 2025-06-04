// ─────────────────────────  PARAMETERS  ─────────────────────────────
let Lookback        = 24h;           // how far back to scan
let BurstWindow     = 6h;            // sliding window for ≥3 geos
let ImpossibleGap   = 2h;            // geo switch faster than this = impossible
let ImpossibleGapM  = toint(ImpossibleGap / 1m);    // numeric minutes
let MinGeos         = 3;             // require ≥ this many distinct locations
let MinAttachMB     = 0.1;           // alert only if any msg had >0.1 MB attachments
let Mode            = "Enforce";     // "Audit" or "Enforce"

// ── allow-lists ─────────────────────────────────────────────────────
let VpnLocations    = dynamic(["US-VPN-NY","US-VPN-LA","UK-VPN-LON"]);
let ServiceSuffixes = dynamic(["-svc@bank.com","-bot@bank.com"]);

// ── Fetch outbound mail & flatten sender identities ─────────────────
let Base =
    EgressLog
    | where TimeGenerated >= ago(Lookback)
    | where LogSource == "egress"
    // | where direction == "Outbound"               // uncomment if you have it
    | mv-expand identities
    | extend
          upn        = tostring(identities.upn),
          senderLoc  = tostring(senderLocation),
          attachMB   = todouble(attachmentTotalMb)   // may be null
    | where isnotempty(upn) and isnotempty(senderLoc)
    // service-account allow-list
    | where array_index_of(ServiceSuffixes,
               suffix -> upn endswith suffix) == -1
    // VPN allow-list
    | where senderLoc !in (VpnLocations);

// ── Identify impossible hops (<2 h apart, different geo) ────────────
let Hops =
    Base
    | project upn, TimeGenerated, senderLoc, attachMB
    | join kind=inner
        (
            Base
            | project upn, Time2 = TimeGenerated, loc2 = senderLoc
        ) on upn
    | where senderLoc != loc2
    | extend gapM = abs(datetime_diff('minute', TimeGenerated, Time2))
    | where gapM < ImpossibleGapM
    // keep earliest of the hop pair
    | project upn, HopTime=min(TimeGenerated, Time2);

// ── Burst analysis: slide 6-hour window around each hop ─────────────
Hops
| join kind=inner (Base) on upn
| where TimeGenerated between (HopTime .. HopTime + BurstWindow)
| summarize
      FirstSeen  = min(TimeGenerated),
      LastSeen   = max(TimeGenerated),
      Geos       = make_set(senderLoc, 5),
      MaxAttach  = max(attachMB)
    by upn
| extend GeoCount = array_length(Geos)

// ── Final gating logic ───────────────────────────────────────────────
| where GeoCount >= MinGeos
      and MaxAttach >= MinAttachMB

// ── Audit vs. Enforce toggle ────────────────────────────────────────
| extend verdict = iff(Mode == "Audit", "Audit-Log-Only", "Alert")
| project
      TimeGenerated = FirstSeen,
      upn,
      Geos,
      GeoCount,
      FirstSeen,
      LastSeen,
      MaxAttachMB = round(MaxAttach,2),
      verdict,
      severity    = "High",
      tactic      = "Initial Access",
      technique   = "Valid Accounts (T1078)",
      alertTitle  = strcat("🚨 Impossible sender burst for ", upn,
                           " – ", GeoCount, " geos in ",
                           toduration(LastSeen-FirstSeen))
