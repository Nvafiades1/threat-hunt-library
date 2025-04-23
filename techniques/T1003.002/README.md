# TRR0000: OS Credential Dumping – Security Account Manager

## Metadata

| Key               | Value                                       |
|-------------------|---------------------------------------------|
| **ID**            | TRR0000                                |
| **External IDs**  | [T1003.002](https://attack.mitre.org/techniques/T1003/002/) |
| **Tactics**       | Credential Access |
| **Platforms**     | Windows                                     |
| **Contributors**  | Nick Vafiades  |



## Technique Overview

This Technique Research Report (TRR) describes methods adversaries use to access and extract credential information, specifically password hashes for local user accounts, from the Windows Security Account Manager (SAM) database. The SAM is a critical component of the Windows operating system, acting as the primary store for local user account definitions and their associated authentication data.

**Core Objective:** The fundamental goal is to obtain the NTLM (and potentially legacy LM) hashes of local user passwords stored within the SAM. Once obtained, these hashes serve several malicious purposes:
*   **Offline Password Cracking:** Adversaries can use specialized password cracking software and computing resources (CPUs, GPUs) to attempt to reverse the hashing process and recover the original plaintext passwords, particularly if users have chosen weak or common passwords.
*   **Pass-the-Hash (PtH) Attacks:** The NTLM hash itself can often be used directly for authentication against remote Windows systems and services (like SMB, WMI) without needing the plaintext password. If a local account (especially the built-in Administrator account, RID 500) shares the same password hash across multiple machines, compromising it on one system allows lateral movement to others using the hash alone.
*   **Persistence:** Gaining knowledge of valid local account credentials provides a reliable method for maintaining access to a compromised system, potentially surviving reboots or the removal of other persistence mechanisms.

**Prerequisites and Challenges:** Accessing the SAM database is not trivial. It requires elevated privileges, typically Administrator or, more often, the highly privileged SYSTEM account. Furthermore, the live SAM database file (`%SystemRoot%\System32\config\SAM`) is protected by exclusive operating system locks while Windows is running, preventing direct copying or reading through standard means. Adversaries must therefore employ specialized techniques based on fundamental mechanisms to bypass these protections.

**Key Components:** Successful execution usually involves obtaining not only the SAM hive but also the SYSTEM hive (`%SystemRoot%\System32\config\SYSTEM`). The SYSTEM hive contains the necessary cryptographic key material (the "boot key" or "syskey") required to decrypt the password hashes stored within the SAM. Without the corresponding SYSTEM hive, the extracted SAM data is largely unusable for hash recovery.

**Core Mechanisms Employed:** Adversaries fundamentally rely on a handful of core mechanisms to acquire the locked SAM and SYSTEM hives or their contents, often implemented within custom tooling, offensive security frameworks, or using built-in system capabilities:
*   **Direct Registry API Interaction:** Interacting with the live, loaded registry hives in memory using Windows APIs to read content or save a copy to disk.
*   **Volume Shadow Copy (VSS) Interaction:** Leveraging VSS to create snapshots containing accessible (unlocked) copies of the hive files.
*   **Raw Disk Access:** Reading the hive data directly from the disk device, bypassing the file system layer and its locks.
*   **Memory Dump Analysis:** Extracting hive data from a system memory dump (crash dump or live capture).
*   **Offline Hive File Access:** Accessing hive files when the operating system is not running or from backup sources.

This technique is distinct from, but often performed alongside, dumping LSASS memory (T1003.001, targeting active session credentials) and extracting LSA Secrets (T1003.004, targeting other stored secrets like service account passwords). Successfully dumping the SAM provides adversaries with persistent local credentials, significantly furthering their objectives within a compromised environment.



## Technical Background

*   **Registry Hives:** The Security Account Manager (SAM), SYSTEM, and SECURITY databases are core components of the Windows registry, stored as distinct files known as hives. A hive represents a logical section of the registry backed by one or more files on disk, allowing it to be loaded into and unloaded from memory.
    *   **SAM Hive:** Located at `%SystemRoot%\System32\config\SAM`, this hive stores crucial information about local users and groups defined on the machine. This includes usernames, Relative Identifiers (RIDs) used internally by Windows, group memberships, account settings (like lockout policies), and most importantly for attackers, the encrypted password hashes (typically NTLM) for local accounts.
    *   **SYSTEM Hive:** Residing at `%SystemRoot%\System32\config\SYSTEM`, this hive contains a vast amount of system configuration data. This includes hardware configurations, device driver loading information, service definitions and settings, and critically, the system boot key (historically associated with Syskey). This boot key is indispensable for decrypting the password hashes stored within the SAM hive.
    *   **SECURITY Hive:** Found at `%SystemRoot%\System32\config\SECURITY`, this hive holds system-wide security policies and Local Security Authority (LSA) Secrets. LSA Secrets can encompass a variety of sensitive data, such as cached domain credentials (hashes of domain users who have logged onto the machine), stored service account passwords, network passwords saved by users, and the computer's own domain account password. Accessing this often requires the boot key from the SYSTEM hive as well.

*   **Loading into Registry:** During the Windows boot process, the Configuration Manager (a kernel component) maps these hive files into the kernel's address space and makes them accessible via the registry API under the `HKEY_LOCAL_MACHINE` (HKLM) root key: `HKLM\SAM`, `HKLM\SYSTEM`, `HKLM\SECURITY`. However, the default Access Control Lists (ACLs) applied to the `HKLM\SAM` and `HKLM\SECURITY` keys are highly restrictive, preventing even members of the Administrators group from directly reading their contents using standard registry viewing tools or standard API calls without specific privileges, typically requiring `SeBackupPrivilege` or running as the `SYSTEM` account.

*   **File Locking:** To maintain integrity and prevent corruption, the Windows operating system places exclusive, mandatory locks on the active registry hive files (`SAM`, `SYSTEM`, `SECURITY`, etc. in `%SystemRoot%\System32\config`) while the system is running. These locks are managed at the kernel level and prevent any standard user-mode process, regardless of privilege level (including Administrator), from opening these files for read or write access using conventional file I/O functions (e.g., `CreateFile`, `ReadFile`). This necessitates the use of specific techniques that circumvent these locks, such as interacting with the Volume Shadow Copy Service, accessing the raw disk device below the file system driver, or interacting directly with the loaded hives via specific registry APIs.

*   **Password Hashes (LM and NTLM):** Windows historically stored two forms of password hashes for backward compatibility:
    *   **LM Hash (LAN Manager Hash):** An outdated and cryptographically weak algorithm based on DES. It suffered from several flaws: case-insensitivity (passwords were converted to uppercase), splitting passwords longer than 7 characters into two independent halves (making cracking much faster), and fixed salt usage. Due to its weaknesses, storage of LM hashes is disabled by default in modern Windows versions (since Vista/Server 2008) via the `NoLMHash` registry setting. If found, they are trivial to crack.
    *   **NTLM Hash (NT LAN Manager Hash):** The standard hash function used in modern Windows for local accounts. It's based on the MD4 message digest algorithm applied to the user's password encoded in UTF-16 Little Endian. While significantly stronger than LM hash, NTLM is susceptible to offline dictionary and brute-force attacks (especially for weak passwords) and rainbow table attacks. Crucially, NTLM hashes can be used directly in Pass-the-Hash (PtH) attacks to authenticate to remote systems without needing the original plaintext password.
    *   **Storage Format:** Within the SAM hive structure (specifically the `F` and `V` binary values under user-specific keys), hashes are typically stored. Credential dumping activities often result in output formatted as `RID:LMHash:NTHash:::`, where RID is the User's Relative ID.

*   **SAM Encryption and the Boot Key (Syskey):** The NTLM (and LM, if present) hashes within the SAM hive's user data fields (specifically the `V` value under `HKLM\SAM\SAM\Domains\Account\Users\<RID>`) are not stored directly as the raw MD4 output. They undergo an additional layer of encryption using a key derived from the system's boot key (also known historically as the "Syskey").
    *   This boot key is not a single value but is derived from several pieces of data obfuscated within the `SYSTEM` hive, primarily under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`. These pieces are often found in keys named `JD`, `Skew1`, `GBG`, and `Data`.
    *   Extracting the boot key involves reading these specific registry values from the `SYSTEM` hive and processing them through a defined algorithm (involving permutations, MD5 hashing, and RC4 encryption/decryption cycles) to reconstruct the 16-byte key.
    *   This reconstructed boot key is then used, typically with RC4, to decrypt the relevant sections of the user's `V` data blob in the SAM hive, finally revealing the NTLM and LM hashes.
    *   This dependency mandates that an attacker must acquire *both* the SAM hive (containing the encrypted hashes) *and* the SYSTEM hive (containing the boot key components) to perform successful offline credential recovery.
    *   **Historical Note (Syskey Utility):** A previous Windows utility allowed for further encrypting the boot key itself with a user-defined password or storing it on external media. While the utility is gone, the underlying mechanism of deriving the boot key from the SYSTEM hive persists.

*   **Relationship to LSA, LSASS, and LSA Secrets:** Understanding the roles of these related components is important:
    *   **LSA (Local Security Authority):** A core Windows security subsystem responsible for local security policy enforcement, user authentication (handling logon requests), access token generation, and managing security auditing.
    *   **LSASS (Local Security Authority Subsystem Service):** The user-mode process (`lsass.exe`) that implements much of the LSA functionality. LSASS caches credentials for *currently active logon sessions* in its memory space. This can include NTLM hashes, Kerberos tickets (TGTs, service tickets), and potentially plaintext passwords if certain configurations allow (e.g., WDigest). Dumping LSASS memory (T1003.001) targets these volatile, runtime credentials, which may include domain accounts not present in the local SAM.
    *   **LSA Secrets:** Sensitive data stored persistently within the `SECURITY` hive (`HKLM\SECURITY\Policy\Secrets`). These are distinct from local user hashes in SAM and can include items like service account passwords used to run services, cached domain credentials (NTLM hashes of domain users who previously logged on, allowing offline logon), the machine's own domain account password, stored network passwords, and other system secrets. These secrets are also typically encrypted using keys derived from the boot key in the `SYSTEM` hive. Dumping LSA Secrets (T1003.004) targets this specific persistent data, often using the same hive access techniques as SAM dumping.



## Procedures (Core Mechanisms)

The following procedures detail the core mechanisms adversaries use to access and dump the SAM and SYSTEM hives, bypassing standard OS protections. Any tool implementing this technique will ultimately rely on one or more of these underlying mechanisms.

| ID                      | Title                                          | Common APIs & Implementations                                      | Key Artifacts / Observables                                                                |
| :---------------------- | :--------------------------------------------- | :------------------------------------------------------------------- | :----------------------------------------------------------------------------------------- |
| **TRR1003.002.WIN.A**   | Direct Registry API Interaction (Live Hives) | `RegSaveKeyExW`, `NtSaveKeyEx`, `RegQueryValueExW`, `NtQueryValueKey`, Command-line execution saving hives, Remote Registry RPC calls, Malicious Driver API calls | Process execution with command line saving hives (`save HKLM\SAM`, `save HKLM\SYSTEM`), File creation (`.hiv`, `.sav`, `.bak`), Direct API calls targeting SAM/SYSTEM keys/values by non-standard processes, Network connections (`\pipe\winreg`), Use of `SeDebugPrivilege` or `SeBackupPrivilege` |
| **TRR1003.002.WIN.B**   | Volume Shadow Copy (VSS) Interaction        | WMI (`Win32_ShadowCopy`), VSS Admin command execution, PowerShell VSS cmdlets, Remote VSS trigger/access via RPC/WMI | VSS creation/deletion events/logs (Event Log: `VSS`, `volsnap`), File reads/copies from `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\...` path targeting hives, VSS admin command execution, WMI activity related to `Win32_ShadowCopy` by non-backup processes |
| **TRR1003.002.WIN.C**   | Raw Disk Access                                | `CreateFile` (`\\.\PhysicalDriveX`), Raw disk read APIs, Malicious drivers (`.sys`) | Raw disk read activity, Processes accessing `\Device\HarddiskX\DRX` or `\Device\HarddiskVolumeX`, Loading of suspicious/unsigned drivers, High disk I/O from non-standard processes |
| **TRR1003.002.WIN.D**   | Memory Dump Analysis                           | Crash-inducing APIs/actions, Memory analysis library usage, Hypervisor memory snapshots | System crash events (BugCheck, Event ID 6008), Memory dump file creation (`MEMORY.DMP`, minidumps), VM snapshot activity, Debugger attachment to kernel, Rapid reboot + physical access events, Access/Exfiltration of dump files |
| **TRR1003.002.WIN.E**   | Offline Hive File Access                     | File system APIs (on offline/external media), Backup system interaction APIs/protocols, Hypervisor disk access APIs | Access to `RegBack`, Backup server/console logs (unusual access/restores), External boot events, Mounting of drives/images (Event ID 6416), Physical access logs/alerts, File access on non-booted system drives |



### Procedure A: Direct Registry API Interaction (Live Hives)

*   **ID**: TRR1003.002.WIN.A
*   **Core Mechanism**: This mechanism involves interacting directly with the loaded SAM and SYSTEM registry hives residing in kernel memory via Windows APIs. This bypasses the file locks on the hive files stored on disk (`%SystemRoot%\System32\config`). It typically requires SYSTEM privileges due to restrictive ACLs, especially on `HKLM\SAM`.
*   **Implementations & Description**:
    *   **Saving Hives to File:** Adversaries can instruct the registry subsystem to serialize a live hive's content from memory to a file on disk. This can be achieved through:
        *   Executing built-in command-line utilities or scripts with arguments specifying the save operation for `HKLM\SAM` or `HKLM\SYSTEM` to a target file path.
        *   Direct Win32 API calls like **`RegSaveKeyW` / `RegSaveKeyExW`** or lower-level Native API calls like **`NtSaveKey` / `NtSaveKeyEx`** within custom code or offensive frameworks.
    *   **Reading Hive Content In-Memory:** Adversaries can use APIs to directly query the values within the loaded hives without saving them to disk first. This involves opening handles to keys (e.g., **`RegOpenKeyExW`**, **`NtOpenKeyEx`** targeting `HKLM\SAM\SAM` or `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`) and then recursively reading subkeys and values (**`RegEnumValueW`**, **`RegQueryValueExW`**, **`NtEnumerateValueKey`**, **`NtQueryValueKey`**) to extract boot key components and encrypted hashes. This approach can be stealthier as it minimizes file I/O artifacts.
    *   **Remote Interaction:** Adversaries can perform this remotely by connecting to the target's **Remote Registry service** (via RPC over SMB, usually targeting the named pipe `\pipe\winreg`) and issuing RPC calls that translate to these registry API functions on the remote host.
    *   **Enablers:** Malicious drivers operating in kernel mode (Ring 0) can invoke these APIs with elevated privileges, bypassing user-mode restrictions.
*   **Key Artifacts / Observables**: Process execution events where the command line indicates saving the `HKLM\SAM` or `HKLM\SYSTEM` hive. File creation events for hive copies (often with extensions **`.hiv`, `.save`, `.bak`, `.tmp`** or random names) in temporary or staging directories. API monitoring showing non-standard processes (outside core OS components or backup agents) calling **`RegSaveKeyExW`**, **`NtSaveKeyEx`**, **`RegQueryValueExW`**, etc., on sensitive hive paths. Use of privileges like **`SeDebugPrivilege`** or **`SeBackupPrivilege`**. Network connections to **`\pipe\winreg`** from unexpected sources or involving suspicious RPC calls.

### Procedure B: Volume Shadow Copy (VSS) Interaction

*   **ID**: TRR1003.002.WIN.B
*   **Core Mechanism**: This mechanism leverages the legitimate Windows Volume Shadow Copy Service (VSS) framework. VSS creates point-in-time snapshots (shadow copies) of volumes, and files within these snapshots are accessible for reading even if locked by the live OS.
*   **Implementations & Description**: Adversaries abuse VSS to get readable copies of the SAM and SYSTEM hives:
    1.  **Trigger Snapshot Creation**: Initiate VSS snapshot creation for the system volume (typically `C:`), usually requiring Administrator privileges. This can be done via:
        *   Executing built-in VSS administration command-line utilities.
        *   Using scripting interfaces for VSS administration.
        *   Making **WMI** calls (e.g., using the `Win32_ShadowCopy` class **`.Create()`** method locally or remotely).
        *   Executing **PowerShell VSS cmdlets**.
    2.  **Copy Hives from Snapshot**: Access the created snapshot via its unique device path (e.g., **`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX`**, where `X` is a number) and copy the SAM and SYSTEM files (`\Windows\System32\config\SAM`, `\Windows\System32\config\SYSTEM`) from within the snapshot path to a staging location using standard file copy utilities or file access APIs.
    3.  **Remote Interaction**: Adversaries may attempt to remotely trigger VSS snapshot creation (e.g., via WMI) and then access the snapshot path (often via administrative shares like `C$`) to copy the hives.
    4.  **(Optional) Cleanup**: Adversaries may delete the created shadow copy using VSS administration utilities or APIs to minimize forensic traces.
    *   **Legitimate Use**: Note that legitimate backup software heavily relies on VSS. Detections must differentiate malicious use (often by unexpected processes like command shells, scripting engines, or custom executables) from normal backup agent activity.
*   **Key Artifacts / Observables**: Execution of VSS administration utilities or scripts. Windows Event Logs related to VSS snapshot creation and deletion (Source: **`volsnap`**, **`VSS`**). File read/copy operations (`FileOpenInfo`, `FileRead`, etc.) where the source **`TargetFilePath`** starts with **`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy`** and targets `\Windows\System32\config\SAM` or `\Windows\System32\config\SYSTEM`, especially if performed by non-backup processes. Creation of hive file copies in temporary locations potentially correlated with VSS activity. WMI activity related to the **`Win32_ShadowCopy`** class originating from non-standard processes.

### Procedure C: Raw Disk Access

*   **ID**: TRR1003.002.WIN.C
*   **Core Mechanism**: This advanced mechanism bypasses the file system entirely by reading data directly from the raw disk device sectors where the SAM and SYSTEM hive file content resides.
*   **Implementations & Description**: This requires high privileges (typically SYSTEM) and often intricate knowledge of file system structures (like NTFS MFT):
    1.  **Obtain Raw Device Handle**: Use APIs like **`CreateFile`** to open a handle to the raw physical disk (e.g., **`\\.\PhysicalDriveX`**) or logical volume (e.g., **`\\.\C:`**).
    2.  **Locate File Data**: Parse file system metadata (e.g., MFT records for NTFS) to find the physical disk locations (sectors/clusters) corresponding to the SAM and SYSTEM hive files' data runs.
    3.  **Read Raw Sectors**: Use low-level disk I/O functions (**`ReadFile`** on the raw handle, potentially with `FILE_FLAG_NO_BUFFERING`) to read the identified sectors directly from the storage device.
    4.  **Reconstruct Files**: Assemble the raw sector data into usable hive file copies.
    *   **Enablers & Tools:** This technique is complex and often implemented within:
        *   Custom code or malware.
        *   **Malicious kernel drivers (`.sys`)** loaded by the attacker, which operate in Ring 0 and can perform raw disk I/O without user-mode restrictions.
        *   Legitimate forensic or disk imaging utilities used inappropriately in a live environment.
*   **Key Artifacts / Observables**: Processes obtaining handles to raw device objects (paths like **`\Device\HarddiskX\DRX`**, **`\Device\HarddiskVolumeX`**). Direct read operations targeting these raw device objects (**Sysmon Event ID 9: RawAccessRead**). Execution of disk imaging utilities outside of approved maintenance or forensic activities. Loading of suspicious, unsigned, or known-vulnerable kernel drivers. Potentially high disk I/O activity from non-standard processes.

### Procedure D: Memory Dump Analysis

*   **ID**: TRR1003.002.WIN.D
*   **Core Mechanism**: This mechanism involves extracting the SAM and SYSTEM hive contents from a snapshot of the system's physical memory (RAM), where the loaded hives reside within the kernel's address space, rather than accessing the disk files directly.
*   **Implementations & Description**:
    *   **Forced Crash Dumps**: Adversaries trigger a deliberate system crash (Blue Screen of Death), which causes the Windows crash handler to write the contents of physical memory to a configured dump file (typically **`%SystemRoot%\MEMORY.DMP`** or a minidump). This requires Administrator/SYSTEM privileges.
        *   **Crash Inducement**: Common methods include using specialized executables designed to cause crashes, exploiting a kernel vulnerability, or configuring and triggering a manual crash via the **`CrashOnCtrlScroll`** registry setting and keyboard shortcut.
        *   **Offline Analysis**: The dump file (often large) is retrieved by the attacker. Memory forensics analysis software is used offline to parse the memory image, locate the kernel data structures for loaded hives (e.g., `_CMHIVE` structures), and extract the necessary data (boot key components, encrypted hashes).
    *   **Live Memory Acquisition / Kernel Debugging**: While less common specifically for SAM/SYSTEM compared to LSASS (T1003.001), obtaining a live memory dump or attaching a kernel debugger could theoretically allow access to the same in-memory hive structures.
    *   **Hypervisor Memory Snapshots**: In virtualized environments (VMware, Hyper-V), compromising the hypervisor allows creating a snapshot of a running VM's memory state (files like **`.vmsn`, `.vmss`**). This memory snapshot file can then be analyzed offline using memory forensics software, similar to analyzing a crash dump.
    *   **Cold Boot Attacks**: A specialized physical access technique exploiting DRAM data remanence for seconds to minutes after power loss. Requires specialized hardware/software to quickly read residual memory contents after a reboot, potentially recovering sensitive data including fragments of hives or encryption keys.
*   **Key Artifacts / Observables**: Execution of executables known to induce system crashes. Modifications to registry keys controlling crash behavior (`HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\CrashOnCtrlScroll`, `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl`). Unexpected system halt events (BugCheck, Event ID 6008). Creation of large **`.DMP`** files. Hypervisor logs showing VM memory snapshot creation or export. Evidence of debugger attachment to the kernel. System reboot events followed by physical access alerts (for Cold Boot). Subsequent access, copying, or exfiltration of memory dump files.

### Procedure E: Offline Hive File Access

*   **ID**: TRR1003.002.WIN.E
*   **Core Mechanism**: This mechanism involves accessing copies of the SAM and SYSTEM hive files when the primary operating system is not running and enforcing file locks, or by targeting existing backup copies where locks aren't relevant.
*   **Implementations & Description**:
    *   **Using Pre-existing Backup Copies:**
        *   **`RegBack` Folder:** Copying hive files directly from **`%SystemRoot%\System32\config\RegBack`**. This folder contains automatic registry backups, but this feature is *disabled by default* in modern Windows (Win 10 1803+ / Server 2016+). If enabled, accessing it requires file system privileges (Admin/SYSTEM).
        *   **System Restore Points:** Potentially accessing hive copies within System Restore snapshots stored under **`\System Volume Information`**, though direct access is typically restricted.
        *   **Enterprise Backup Solutions:** Targeting stored backups created by enterprise backup software. This could involve compromising backup server credentials, accessing backup storage (shares, SAN, NAS, cloud), exploiting backup software vulnerabilities, or performing unauthorized restore operations targeting the SAM/SYSTEM files. Accessing physical backup media (tapes, disks) is also possible.
    *   **Physical/Offline Disk Access:** Gaining physical access to the machine's storage allows bypassing all live OS protections:
        *   **Booting from External Media:** Booting the target machine using **WinPE**, a **Linux live distribution**, or other bootable media. The external OS can then mount the internal system drive and copy the hives directly from `%SystemRoot%\System32\config`.
        *   **Mounting Drive Externally:** Removing the physical storage drive (HDD/SSD) and connecting it as a secondary drive to another computer ("attacker machine") to copy the files. **Full Disk Encryption (BitLocker)** is the primary countermeasure against these offline disk access methods.
    *   **Hypervisor Disk Access:** In virtualized environments, compromising the hypervisor (ESXi, Hyper-V) allows direct access to the VM's virtual disk file (**`.vmdk`, `.vhdx`**) on the datastore. Mounting this virtual disk file offline on another system allows direct copying of the hive files.
*   **Key Artifacts / Observables**: File access targeting the **`RegBack`** folder or **`\System Volume Information`**. Unusual access patterns, administrative logins, or restore jobs on **backup servers/consoles**. Large data transfers from backup repositories. System boot logs indicating boot from **external/non-standard devices**. Physical security logs/alerts. Event logs showing drives being mounted/dismounted (e.g., Windows Event ID 6416 for external drive connection). Hypervisor logs indicating direct datastore access, VM export, or offline mounting of virtual disks. File access on system drives when the host OS is not booted (requires correlating offline/external access logs).



## References

*   [MITRE ATT&CK: T1003.002 - OS Credential Dumping: Security Account Manager](https://attack.mitre.org/techniques/T1003/002/)
*   [Microsoft Docs: Reg command](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg) (*Note: While the command is mentioned, the focus is on the action*)
*   [Microsoft Docs: Vssadmin command](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin) (*Note: Documents the utility often used*)
*   [Microsoft Docs: Diskshadow command](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) (*Note: Documents the utility often used*)
*   [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/) (*Note: Relevant for understanding Sysmon events and potential crash tools*)
*   [Harmj0y: Invoke-NinjaCopy](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) (*Note: Example script using API calls*)
*   [Impacket `secretsdump.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) (*Note: Example tool implementing remote methods*)
*   [Mimikatz Wiki](https://github.com/gentilkiwi/mimikatz/wiki) (*Note: Example framework with relevant modules*)
*   [Wikipedia: Security Account Manager](https://en.wikipedia.org/wiki/Security_Account_Manager)
*   [Wikipedia: LM hash](https://en.wikipedia.org/wiki/LM_hash)
*   [Wikipedia: NTLM](https://en.wikipedia.org/wiki/NT_LAN_Manager#NTLM_hash_(NT_hash))
*   [Passcape Blog: SAM Secrets](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28) (Detailed explanation of SAM/SYSTEM encryption)
*   [Microsoft Blog: Syskey removal in Windows 10 Fall Creators Update](https://techcommunity.microsoft.com/t5/windows-blog-archive/syskey-exe-utility-is-no-longer-supported-in-windows-10-rs3/ba-p/118867)
*   [Volatility Framework](https://github.com/volatilityfoundation/volatility) (*Note: Example memory analysis framework*)

