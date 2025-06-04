# Detection: **OAuth-Consent Credential Harvest**

> **Purpose**  Catch phishing e-mails that abuse Microsoft / Google OAuth
> consent pages to harvest credentials or gain mailbox-read scope.
>  
> **Why it’s high-fidelity**  
> 1. Links match the *exact* OAuth-authorize endpoints attackers use.  
> 2. Fires only on first-contact or Egress’s own **Dangerous** verdict.  
> 3. Optional SPF/DKIM/DMARC fail gate removes the bulk marketing noise.

---

## 1 · Core signals

| Signal | Field(s) in Egress | Rationale |
|--------|-------------------|-----------|
| **OAuth link** | `links[].link` contains:<br>• `accounts.google.com/o/oauth2`<br>• `login.microsoftonline.com/common/oauth2` | Only appears in credential-harvest or SaaS-fraud phish. |
| **Cold sender or Egress AI** | `relationshipHistory == "FirstTimeSender"` **OR** `threatscore == "Dangerous"` | Brand-new contact or Egress already thinks it’s risky. |
| **Phish classifier** | `phishTypes` ∈ { `technical`, `socialEngineering` } | Ensures Egress ML agrees it’s a phish. |
| *(Optional)* **Auth failure** | `spf != "Pass"` **OR** `dkim != "Pass"` **OR** `dmarc == "Fail"` | Tightens fidelity in noisy inboxes. |

---

## 2 · ADX (Kusto) query

```kusto
// █████  OAuth-Consent Credential Harvest  █████

//──── PARAMETERS (tweak as needed) ─────────────────────
let Lookback      = 48h;            // scan window
let OAuthHosts    = dynamic([       // keep list short & precise
    "accounts.google.com/o/oauth2",
    "login.microsoftonline.com/common/oauth2",
    "login.microsoftonline.com/consumers/oauth2"
]);
let GoodBrandDomains = dynamic(["@microsoft.com", "@google.com"]);  // optional allow-list

//──── Pull inbound mail & normalise -----------------------------------------------------------------------------------
EgressLog
| where TimeGenerated >= ago(Lookback)
| where LogSource == "egress"
| where direction   == "Inbound"                       // Defend = inbound only
| extend
      senderEmail  = tostring(from[0].emailAddress),
      senderDomain = strcat("@", substring(senderEmail, index_of(senderEmail,"@")+1)),
      coldSender   = relationshipHistory == "FirstTimeSender",
      riskAI       = threatscore       == "Dangerous",
      authFail     = (spf != "Pass" or dkim != "Pass" or dmarc == "Fail"),
      phishingML   = array_any(phishTypes,
                       (p) => p in~ ("technical","socialengineering")),

      // link hit – any link starts with OAuth host
      oauthHit     = array_any(
                       links,
                       (l) =>
                         array_any(OAuthHosts,
                                   (h) => startswith(tolower(l.link), h)) )

//──── Apply gates ------------------------------------------------------------------------------------------------------
| where oauthHit
      and ( coldSender or riskAI )
      and phishingML
      // ---- uncomment next line if you want auth failures too ----
      // and authFail
      and senderDomain !in (GoodBrandDomains)

//──── Alert output -----------------------------------------------------------------------------------------------------
| project
      TimeGenerated,
      senderEmail,
      senderDomain,
      subject,
      phishTypes,
      threatscore,
      spf, dkim, dmarc,
      links,
      severity   = "High",
      tactic     = "Credential Access",
      technique  = "Phishing via OAuth Consent (T1556.007)",
      alertTitle = strcat("🚨 OAuth-Consent phish from ", senderEmail)
