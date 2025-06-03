/* ──────────────────────────────────────────────────────────────────────────
   Suspicious Inbound Mail – v6
   • Fixes “authFailed always TRUE”   → now triggers only on **explicit FAILS**
   • Removes any hit driven solely by cloud bulk-mailer
   • Excludes phishTypes = grayMail (case-insensitive)
────────────────────────────────────────────────────────────────────────── */

source = egress
| where TimeGenerated >= ago(7d)                     // never run on the full archive
| extend
    /* ── primitive fields ─────────────────────────────────────────────── */
    senderEmail  = tolower(from[0].emailAddress),
    senderDomain = substring(senderEmail, index_of(senderEmail, "@")),
    bounceDomain = substring(tostring(mailFrom), index_of(tostring(mailFrom), "@")),

    /* normalise auth strings (strip spaces + lower-case) */
    spfStatus   = trim(" ", tolower(tostring(spf))),      // "pass" / "fail" / "none"
    dkimStatus  = trim(" ", tolower(tostring(dkim))),
    dmarcStatus = trim(" ", tolower(tostring(dmarc))),

    /* ── red-flag booleans ────────────────────────────────────────────── */
    isFirstTime    = (relationshipHistory == "FirstTimeSender"),

    /* strict auth failure: DMARC FAIL + (SPF FAIL OR DKIM FAIL) */
    authFailed     = (dmarcStatus == "fail"
                      and (spfStatus == "fail" or dkimStatus == "fail")),

    domainMismatch = (bounceDomain != senderDomain),

    /* build a single lower-case string of phishTypes (array → “;”-joined) */
    pt             = trim(" ", tolower(array_strcat(phishTypes, ";"))),

    /* TRUE if any non-grayMail phishing category present                    */
    phishClassifier = pt matches regex
        "(technical|brandimpersonator|companyimpersonator|spear|\
          socialengineering|scouting|scam419|mailfraud)",

    /* ── composite decision (HIGH risk) ───────────────────────────────── */
    highRisk = ( isFirstTime
                 and authFailed
                 and domainMismatch           // add link-mismatch here if desired
                 and phishClassifier )        // cloudMailer removed

| where highRisk
| project
      TimeGenerated,
      senderEmail,
      senderDomain,
      bounceDomain,
      subject,
      spfStatus, dkimStatus, dmarcStatus,
      phishTypes,
      relationshipHistory,
      severity   = "High",
      tactic     = "Initial Access",
      technique  = "Phishing (T1566)",
      alertTitle = strcat("🚨 Suspicious inbound email from ", senderEmail)
