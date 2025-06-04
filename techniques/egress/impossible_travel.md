# Detection: **Impossible-Sender / Anomalous Outbound Geo**

> *Purpose*: alert when the **same internal user (UPN)** sends two outbound
> e-mails from **different geo‐locations** within a short window (default = 2 h).
> In a financial institution this is a classic indicator of:
> * account takeover (phish → attacker in foreign country)
> * unsanctioned personal device / VPN abuse
> * insider forwarding from home ISP right after office hours

---

## 1 · Fields used (all exist in your Egress JSON)

| Field                         | Example                        | Notes                          |
|-------------------------------|--------------------------------|--------------------------------|
| `TimeGenerated`               | `2025-05-03T22:54:38.110Z`     | Event timestamp                |
| `identities[*].upn`           | `alice@bank.com`               | Internal sender identity       |
| `senderLocation`              | `US-NY` / `DE-BERLIN` / `CN`   | Egress geo string (any format) |
| `LogSource`                   | `egress`                       | Confirms record type           |
| `direction` *(if present)*    | `Outbound`                     | Some feeds include it          |

---

## 2 · Kusto Query (ADX)

```kusto
// ───── Define window ───────────────────────────────────────────────
let Lookback = 24h;
let MaxGap   = 2h;         // “impossible” if two mails < 2 h apart

// ───── Pull outbound e-mails and normalise fields ────────────────
let Outbound =
    EgressLog
    | where TimeGenerated >= ago(Lookback)
    | where LogSource == "egress"
    // If you have a direction flag, uncomment the next line
    // | where direction == "Outbound"
    | mv-expand identities                    // flatten array
    | extend  upn = tostring(identities.upn)
    | where isnotempty(upn)                   // ignore system msgs
    | extend  senderLoc = tostring(senderLocation)
    | where isnotempty(senderLoc);

// ───── Self-join on same UPN, different geo within MaxGap ─────────
Outbound
| join kind=inner
    (
        Outbound
        | project upn, TimeGenerated2 = TimeGenerated, senderLoc2 = senderLoc
    ) on upn
| where senderLoc != senderLoc2                       // geo differs
| extend gap = abs(datetime_diff('minute', TimeGenerated, TimeGenerated2))
| where gap < todouble(MaxGap)/1m                     // convert to minutes

// ───── Summarise one alert per user per day ───────────────────────
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
