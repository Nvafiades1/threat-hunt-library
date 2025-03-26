FIN4

**Aliases**  
- Sometimes referred to as a financially motivated espionage actor focused on publicly traded companies.  
- Tracked by FireEye/Mandiant as “FIN4.”

**Overview**  
- **Motivation**: Financial gain via insider trading or front-running stock prices.  
- **Targets**: Primarily US-based healthcare, pharmaceutical, and financial firms (including investment bankers, attorneys, advisors).  
- **Geography**: While strongly North America-focused, may extend globally if a firm deals with U.S. markets.

### TTPs
1. **Initial Access**
   - Highly targeted phishing and spear phishing, often using stolen legitimate email threads.
   - Compromises of O365 or Exchange accounts using credential phishing.

2. **Credential Harvesting**
   - Malware-light or malware-free approach, focusing on user credentials (especially OWA/Office 365).

3. **Information Gathering**
   - Access to confidential emails regarding mergers & acquisitions (M&A), earnings reports, or other market-moving details.

4. **Persistence**
   - Creating forwarding rules in compromised mailboxes for continuous data access.

5. **Exfiltration**
   - Collecting sensitive corporate communications to potentially trade on insider information.

### Last Known Activity
- **Publicly Noted Campaigns**: Late 2014-2015 activity widely reported, with sporadic references through subsequent years.
- No widely publicized major campaigns in recent times, but likely ongoing in stealth form.

### Tools & Infrastructure
- **Minimal Malware**: Often rely on stolen legitimate credentials and existing email systems.
- **Phishing Kits**: Tailored phishing kits disguised as Outlook or Microsoft login pages.

### References
- [FireEye/Mandiant: FIN4 Report](https://www.fireeye.com)
