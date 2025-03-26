FIN6

**Aliases**  
- Often associated with e-commerce and Point-of-Sale (POS) malware campaigns.  
- Sometimes referred to as **Skeleton Spider** by other vendors.

**Overview**  
- **Motivation**: Purely financial, focusing on credit card data theft and resale.  
- **Targets**: Retailers, hospitality, e-commerce platforms, and financial institutions.  
- **Geography**: Global, with emphasis on the U.S. and Europe.

### TTPs
1. **Initial Access**
   - Phishing emails with macro-laden documents.  
   - Exploit known web application vulnerabilities to pivot into the environment.

2. **Lateral Movement**
   - Use of **PowerShell**, **Mimikatz** for credential dumping.
   - **Domain admin** compromise to access payment card environment or e-commerce servers.

3. **Data Theft**
   - Skimming or scraping of POS or e-commerce transaction data.
   - Stolen card dumps sold on dark web marketplaces.

4. **Ransomware Deployment**
   - Also credited with occasional use of **Ryuk** or **LockerGoga** after card data theft.

### Last Known Activity
- **Continued** campaigns through 2020-2023 focusing on POS malware and e-skimming.
- Possibly pivoted to new tooling or partnered with other FIN groups.

### Tools & Infrastructure
- **FrameworkPOS** or similar POS-malware variants.
- **Cobalt Strike** for post-exploitation.

### References
- [Mandiant FIN6 Insights](https://www.mandiant.com)
