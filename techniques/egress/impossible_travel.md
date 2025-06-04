// █████  Impossible-Sender / Anomalous Outbound **Country**  █████
//
//  Change-set vs. last version
//  ────────────────────────────────────────────────────────────
//   1.  **No VPN IP / CIDR lists** – entire allow-list section removed.
//   2.  Derive country code with geo_info_from_ip_address(senderIp).
//   3.  Use **country** (ISO-2) as the “location” string.
//   4.  “Impossible hop” = same UPN, different **country**, <2 h apart.
//   5.  ≥3 distinct countries in a 6 h burst + ≥0.1 MB attachments.
//  ────────────────────────────────────────────────────────────


//──────── PARAMETERS ───────────────────────────────────────────
let Lookback        = 24h;
let BurstWindow     = 6h;
let ImpossibleGapM  = 120;           // 2 h  → 120 minutes
let MinCountries    = 3;             // need at least 3 different countries
let MinAttachMB     = 0.1;
let SizeField       = "fileSizeBytes";  // attachment size property
// Optional: countries we EXPECT (HQ + branches).  Remove if you want all.
let HomeCountries   = dynamic(["US","GB","CA"]);


//──────── BASE – one row per outbound e-mail ──────────────────
let Base =
    EgressLog
    | where TimeGenerated >= ago(Lookback)
    | where LogSource == "egress"
    // | where direction == "Outbound"
    | mv-expand attachments
    | extend
          upn       = tostring(identities[0].upn),
          senderIP  = tostring(senderIp),
          geo       = geo_info_from_ip_address(senderIP),
          country   = tostring(geo.Country),                 // NEW
          fileMB    = iif(isnull(todouble(attachments[SizeField])),
                          0.25,
                          todouble(attachments[SizeField]) / 1048576.0)
    | summarize msgMB = sum(fileMB)
          by upn, country, TimeGenerated
    | where isnotempty(upn) and isnotempty(country)
          and country !in (HomeCountries);   // ignore routine corporate geo


//──────── PASS 1 – detect “impossible hops” (<2 h, diff country) ─────
let Hops =
    Base
    | sort by upn, TimeGenerated
    | serialize
    | extend
          prevTime = prev(TimeGenerated),
          prevCtry = prev(country),
          prevUpn  = prev(upn)
    | extend
          gapM = iff(upn == prevUpn,
                     abs(datetime_diff('minute',
                                        TimeGenerated, prevTime)),
                     999999)
    | where upn == prevUpn
          and country != prevCtry
          and gapM < ImpossibleGapM
    | project upn, HopTime = TimeGenerated;


//──────── PASS 2 – 6 h burst around each hop ──────────────────────────
Hops
| join kind=inner (Base) on upn
| where TimeGenerated between (HopTime .. HopTime + BurstWindow)
| summarize
      FirstSeen = min(TimeGenerated),
      LastSeen  = max(TimeGenerated),
      Countries = make_set(country, 5),
      MaxMB     = max(msgMB)
    by upn
| extend CountryCount = array_length(Countries)
| where CountryCount >= MinCountries
      and MaxMB       >= MinAttachMB


//──────── ALERT PAYLOAD ───────────────────────────────────────────────
| project
      TimeGenerated = FirstSeen,
      upn,
      Countries,
      CountryCount,
      FirstSeen,
      LastSeen,
      MaxAttachMB = round(MaxMB,2),
      severity   = "High",
      tactic     = "Initial Access",
      technique  = "Valid Accounts (T1078)",
      alertTitle = strcat("🚨 Impossible-sender burst for ",
                          upn, " – ", CountryCount,
                          " countries over ",
                          tostring(LastSeen - FirstSeen))
