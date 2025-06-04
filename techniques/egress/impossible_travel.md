// ───────────────── PARAMETERS ───────────────────────────────────────
let Lookback       = 24h;   // how far back we search
let MaxGap         = 2h;    // “impossible” if two mails < 2 h apart
let MaxGapMinutes  = toint(MaxGap / 1m);   // 2 h ⇒ 120 (pure integer)

// ────── Pull outbound mail & flatten identities ─────────────────────
let Outbound =
    EgressLog
    | where TimeGenerated >= ago(Lookback)
    | where LogSource == "egress"
    // | where direction == "Outbound"     // uncomment if you have the flag
    | mv-expand identities
    | extend upn = tostring(identities.upn)
    | where isnotempty(upn)
    | extend senderLoc = tostring(senderLocation)
    | where isnotempty(senderLoc);

// ────── Self-join on same UPN, different geo within MaxGap ──────────
Outbound
| join kind=inner
    (
        Outbound
        | project  upn,
                 TimeGenerated2 = TimeGenerated,
                 senderLoc2     = senderLoc
    ) on upn
| where senderLoc  != senderLoc2
| extend gapMinutes = abs(datetime_diff('minute',
                                        TimeGenerated, TimeGenerated2))
| where gapMinutes < MaxGapMinutes      // numeric-vs-numeric → no type clash

// ────── Summarise one alert per user per day ────────────────────────
| summarize
      FirstSeen = min(TimeGenerated),
      LastSeen  = max(TimeGenerated2),
      Locations = make_set(senderLoc, 3),
      Samples   = take_any(pack_array(TimeGenerated, senderLoc,
                                      TimeGenerated2, senderLoc2))
    by upn
| project
      TimeGenerated = FirstSeen,
      upn,
      Locations,
      FirstSeen,
      LastSeen,
      Samples,
      severity   = "High",
      tactic     = "Initial Access",
      technique  = "Valid Accounts (T1078)",
      alertTitle = strcat("🚨 Impossible Sender Behaviour for ", upn)
