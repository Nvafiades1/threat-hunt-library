# Detection: **Unusual Outbound Encrypted-ZIP Spike**

> *Purpose* Raise a **High** alert when an internal user suddenly sends far
> more **password-protected ZIP / 7-Zip** attachments than they normally do.
> In finance this often precedes data exfil, ransomware staging, or wire-fraud
> docs exfiltration.

---

## 1 · Assumptions / Field Map  
| Your field (Egress JSON) | What it means | Type |
|--------------------------|---------------|------|
| `attachments` (array)    | Each object has `type` (`"zip"` / `"7z"` / …) and `encrypted` (`true/false`) | dynamic |
| `identities[*].upn`      | Authenticated internal sender | string |
| `TimeGenerated`          | Event time | datetime |
| `LogSource`              | `"egress"` | string |

*(If your schema differs, tweak the `mv-expand` and field names.)*

---

## 2 · Kusto Query (ADX)

```kusto
// ===== PARAMETERS ===================================================
let LookbackData   = 30d;   // historical baseline window
let LookbackAlert  = 24h;   // period we evaluate for spikes
let SpikeFactor    = 3.0;   // alert if ≥ 3 × baseline rate
let MinSuspicious  = 5;     // and at least 5 encrypted-zips in Alert window
// ====================================================================

// 0 ── Pull attachment rows & normalise  ─────────────────────────────
let Attach =
    EgressLog
    | where LogSource == "egress"
    | mv-expand attachments           // → one row per attachment
    | extend
        upn        = tostring(identities[0].upn),   // first identity
        attType    = trim(" ", tolower(tostring(attachments.type))),
        isEncrypted= tobool(attachments.encrypted);

// 1 ── HISTORICAL per-user baseline (avg per day) ────────────────────
let Baseline =
    Attach
    | where TimeGenerated between (ago(LookbackData) .. ago(LookbackAlert))
    | where attType in ("zip","7z") and isEncrypted
    | summarize baseline_per_day = todouble(count()) / todouble(LookbackData/1d)
        by upn;

// 2 ── ACTUAL counts in the last 24 h  ───────────────────────────────
let Current =
    Attach
    | where TimeGenerated >= ago(LookbackAlert)
    | where attType in ("zip","7z") and isEncrypted
    | summarize count_24h = count(),
                firstSeen = min(TimeGenerated),
                lastSeen  = max(TimeGenerated)
        by upn;

// 3 ── JOIN + spike detection  ───────────────────────────────────────
Baseline
| join kind=inner Current on upn
| extend spikeRatio = count_24h / baseline_per_day
| where count_24h >= MinSuspicious
      and spikeRatio >= SpikeFactor

// 4 ── Build alert  ─────────────────────────────────────────────────
| project
    TimeGenerated = lastSeen,
    upn,
    firstSeen,
    lastSeen,
    baseline_per_day,
    count_24h,
    spikeRatio,
    severity   = "High",
    tactic     = "Exfiltration",
    technique  = "Exfiltration Over Web Mail (T1567.002)",
    alertTitle = strcat("🚨 Encrypted-ZIP spike for ", upn,
                        " – ", count_24h, " files (", round(spikeRatio,1),
                        "× baseline)")
