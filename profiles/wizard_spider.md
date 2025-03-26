Wizard Spider

### Aliases / Other Names
- **TrickBot Group**: Named for their initial association with the TrickBot banking malware.
- **UNC1878**: Mandiant designation in some reports.

### Known Targets / Victims
- **Financial Sector**: Originally targeted banks and payment processors.
- **Healthcare & Other Industries**: Particularly in the U.S. and Europe, with data exfiltration and ransomware operations.

### Common TTPs
1. **Initial Access**
   - Malicious email campaigns (phishing, macro-laden documents).
   - Exploit kits and spam botnets.

2. **Malware Deployment**
   - **TrickBot**: A modular banking Trojan turned multi-purpose backdoor.
   - **BazarLoader**: Malware loader providing remote access.
   - **Ryuk/Conti Ransomware**: Known to deploy or affiliate with these ransomware families.

3. **Persistence & Lateral Movement**
   - Use of stolen credentials, admin tools (e.g., PowerShell, RDP).

4. **Exfiltration & Extortion**
   - Double extortion tactics with data leaks.
   - “Big-game hunting” approach focusing on large ransom payouts.

### Recent Activity
- **Ongoing**: Shifts toward BazarLoader and remote administrative tools.
- **Last Significant Campaign**: Multiple campaigns in 2022-2023 tied to TrickBot-based initial infections leading to Conti or Diavol ransomware.

### Tools & Infrastructure
- **TrickBot Botnet**: For distribution, reconnaissance, and lateral movement.
- **Cobalt Strike**: Frequent use as a post-exploitation framework.
- **Fast-Flux or Bulletproof Hosting**: To obfuscate command-and-control (C2).
