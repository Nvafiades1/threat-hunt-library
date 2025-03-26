Gootkit Gang (a.k.a. Gootloader Operators)

**Aliases**  
- **Gootkit**, sometimes correlated with **Keksec** or other malvertising networks.

**Overview**  
- **Motivation**: Initially banking trojan developers, pivoting to loader-as-a-service.  
- **Targets**: Financial institutions, plus wide net for initial infections that are sold to other threat actors.  
- **Geography**: Worldwide distribution, with a spike in English-speaking regions.

### TTPs
1. **Compromised Websites & SEO Poisoning**
   - **Gootloader** technique: Infects legitimate sites, modifies SEO for topical queries, leads to malicious downloads.

2. **Banking Trojan**
   - Original **Gootkit** capable of credential theft from banking portals.

3. **Payload Delivery**
   - Partnerships with ransomware affiliates to deliver second-stage threats (e.g., REvil, Black Basta).

### Last Known Activity
- **Active** with SEO poisoning campaigns into 2023.

### Tools & Infrastructure
- **Gootloader**: Trojan downloader that serves various payloads.  
- **Dynamic Web Injection**: Tied to banking credentials theft.

### References
- [Sophos Gootloader Reports](https://news.sophos.com)
