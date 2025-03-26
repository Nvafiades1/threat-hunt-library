# Threat Actor Profile: Scattered Spider

Scattered Spider is a financially-motivated threat actor (TA) known for using social engineering and credential-focused attacks. Different security vendors track this group under various names, often leading to confusion in the industry. Below is a compiled profile based on publicly available information.



## Alias/Nicknames
- **Scattered Spider** (commonly used by CrowdStrike and other vendors)
- **UNC3944** (Mandiant)
- **0ktapus / Roasted 0ktapus** (Group-IB attribution to a large-scale phishing campaign)
- **Muddled Libra** (mentioned in some reports)
- There may be additional or overlapping names depending on the source.



## Known Targets / Victims
- **Telecommunications**: Multiple telcos, including T-Mobile
- **Technology Companies**: Okta, Twilio, and other SaaS providers
- **Business Process Outsourcing (BPO) & Call Centers**
- **Retail**
- **Hospitality & Gaming**: Allegedly involved in the MGM Resorts breach (September 2023)
- **Potential Overlaps**: Some sources link Scattered Spider to targeting similar victims as Lapsus$-related groups



## Common Tactics, Techniques, and Procedures (TTPs)

1. **Initial Access**  
   - **Social Engineering**: Phone-based (vishing) campaigns targeting employees or call centers  
   - **SIM Swapping**: Hijacking phone numbers to bypass Multi-Factor Authentication (MFA)  
   - **Phishing & MFA Fatigue**: Sending repeated MFA push requests to coerce accidental acceptance

2. **Credential Access**  
   - **Phishing Pages**: Spoofing Okta or other identity providers  
   - **Harvesting Credentials**: Stolen from compromised employees/customers

3. **Privilege Escalation & Lateral Movement**  
   - **Stolen Session Tokens**: Accessing internal systems (e.g., Okta administrative portals)  
   - **Living Off the Land**: Using built-in OS tools and admin privileges

4. **Persistence**  
   - **RMM Tools**: ScreenConnect, TeamViewer, or similar solutions to maintain foothold

5. **Exfiltration & Extortion**  
   - **Data Theft**: Exfiltrating sensitive data or intellectual property  
   - **Double/Triple Extortion**: Threatening data leaks, or launching denial-of-service if demands are not met



## Recent TTPs & Activity
- **Continued Use of Social Engineering**: Targeting employees and help desks to gain credentials  
- **MFA Bypass Techniques**: MFA fatigue (bombing) remains a favored method  
- **Collaboration with Other Groups**: Some research points to occasional collaboration with ransomware operators (e.g., ALPHV/BlackCat)

**Last Known Significant Activity**  
- **MGM Resorts Attack (September 2023)**: Widely attributed in part to Scattered Spider for the initial access vectors  
- They remain **active through 2023**, focusing on telecom, gaming, and enterprise services industries



## Tools & Infrastructure

- **Remote Monitoring & Management (RMM) Software**  
  - ScreenConnect, AnyDesk, TeamViewer, and Zoho-based solutions  
  - Used for persistence and stealthy access
- **Phishing Infrastructure**  
  - Spoofed domains mimicking Okta logins or corporate portals  
  - URL shorteners and cloned landing pages

- **Attack Infrastructure**  
  - Rapidly changing bulletproof hosting providers  
  - Compromised servers as proxies for staging malicious tools



## Other Notable Points
- **Likely Fluent in English**: Social engineering success suggests strong language skills and US/UK-based phone numbers.  
- **Overlap with 0ktapus**: The large-scale phishing campaign that compromised over 130 organizations in 2022 has been linked to the same TTP patterns.  
- **Financially Motivated**: Primary aim is monetary gain (through extortion, ransomware facilitation, or selling stolen data).  
- **Involvement of Younger Actors**: Multiple reports suggest teenage or young adult membership, reminiscent of the Lapsus$ group demographic.



## References & Further Reading
Because this profile draws from public reporting across various security vendors, consult:
- **Mandiant** (UNC3944 blog posts)
- **CrowdStrike** (Scattered Spider threat briefs)
- **Group-IB** (Reports on 0ktapus phishing campaign)
- **News Outlets** (Coverage on MGM Resorts, T-Mobile, Okta, Twilio breaches)



