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

// █████  OAuth-Consent Credential Harvest  –  array_any-free  █████

// 1.  PARAMETERS
let Lookback   = 48h;
let OAuthHosts = dynamic([
  "https://accounts.google.com/o/oauth2",
  "https://login.microsoftonline.com/common/oauth2",
  "https://login.microsoftonline.com/consumers/oauth2",
  "https://login.microsoftonline.com/",                // catches tenant-ID paths
  "https://*.okta.com/oauth2/v1/authorize",
  "https://*.auth0.com/authorize",
  "https://*.amazoncognito.com/oauth2/authorize",
  "https://www.dropbox.com/oauth2/authorize",
  "https://slack.com/oauth/v2/authorize",
  "https://github.com/login/oauth/authorize",
  "https://zoom.us/oauth/authorize",
  "https://account.box.com/api/oauth2/authorize",
  "https://ims-na1.adobelogin.com/ims/authorize",
  "https://appleid.apple.com/auth/authorize",
  "https://login.salesforce.com/services/oauth2/authorize",
  "https://*.my.salesforce.com/services/oauth2/authorize",
  "https://account.docusign.com/oauth/auth",
  "https://www.linkedin.com/oauth/v2/authorization",
  "https://auth.atlassian.com/authorize",
  "https://app.hubspot.com/oauth/authorize"
]);
]);
let GoodBrandDomains = dynamic(["@microsoft.com","@google.com"]);

// 2.  INBOUND MAIL – basic flags
let Core =
    EgressLog
    | where TimeGenerated >= ago(Lookback)
    | where LogSource == "egress"
    | where direction   == "Inbound"
    | extend
          senderEmail  = tostring(from[0].emailAddress),
          senderDomain = strcat("@", substring(senderEmail, index_of(senderEmail, "@")+1)),
          coldSender   = (relationshipHistory == "FirstTimeSender"),
          riskAI       = (threatscore       == "Dangerous"),
          authFail     = (spf != "Pass" or dkim != "Pass" or dmarc == "Fail");

// 3.  FIND MESSAGES WITH AN OAUTH-CONSENT LINK  (mv-expand links)
let WithOAuth =
    Core
    | mv-expand linkObj = links
    | extend linkLower = tolower(tostring(linkObj.link))
    | where
          linkLower startswith OAuthHosts[0]
          or linkLower startswith OAuthHosts[1]
          or linkLower startswith OAuthHosts[2]
    | summarize anyOauth = anytrue(1) by _EventId   // keep unique msg

// 4.  FIND MESSAGES TAGGED TECHNICAL / SOCIALENGINEERING (mv-expand phishTypes)
let WithPhishTag =
    Core
    | mv-expand pt = phishTypes
    | where tolower(pt) in ("technical","socialengineering")
    | summarize anyTag = anytrue(1) by _EventId;

// 5.  MERGE & APPLY FINAL GATES
Core
| summarize args = make_any(*) by _EventId     // re-uniquify
| join kind=inner (WithOAuth)   on _EventId
| join kind=inner (WithPhishTag) on _EventId
| where (coldSender or riskAI)
      and senderDomain !in (GoodBrandDomains)

// 6.  ALERT FIELDS
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
      alertTitle = strcat("🚨 OAuth-consent phish from ", senderEmail)

