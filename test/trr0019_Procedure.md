Alright, here’s the procedure I’m going to use in my lab environment:



## 1. Preparation

1. **Set Up a Lab VM**  
   - I’ll use a clean Windows virtual machine with admin privileges so I can simulate the malicious SSP technique safely.

2. **Obtain Process Monitor**  
   - I’ll download [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) from Microsoft’s Sysinternals suite.
   - I’ll also have **Procdot** available to visualize the Procmon logs later.

3. **Decide on a DLL**  
   - I might just rename a simple test DLL to “evilssp.dll,” as long as it can be copied to `System32`.



## 2. Configure Process Monitor

1. **Launch Procmon**  
   - Double-click `Procmon.exe`.

2. **Set Filters**  
   - I’m going to capture these operations:
     - **File Write** (`WriteFile`, `CreateFile`) specifically targeting `C:\Windows\System32\evilssp.dll`.
     - **Registry Set** (`RegSetValue`, `RegCreateKey`) under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.
     - (Optional) **Load Image** if I want to see the DLL actually load into `lsass.exe`.
   - This keeps the log manageable instead of capturing everything.

3. **Advanced Options**  
   - Under **`Options → Advanced Output`**, I’ll make sure I’m not dropping filtered events, so I can adjust filters later if needed.

4. **Start Capture**  
   - I’ll click the “magnifying glass” icon to begin capturing events in Procmon.



## 3. Simulate the Malicious SSP Procedure

1. **Copy the “evil” DLL**  
   - From an elevated command prompt or PowerShell session, for instance:
     ```powershell
     copy benignDLL.dll C:\Windows\System32\evilssp.dll
     ```
   - This should trigger file-write events in Procmon.

2. **Modify the Registry**  
   - I can append the DLL name to `Security Packages` via PowerShell:
     ```powershell
     $packages = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")."Security Packages"
     $new = $packages + "evilssp"
     Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" -Value $new
     ```
   - This should trigger registry-set events in Procmon.

3. **(Optional) Restart LSASS or Reboot**  
   - By default, LSASS loads new SSPs at system startup, so I might reboot the machine.  
   - If I do reboot, I may need to relaunch Procmon (and set it to capture at boot if I want to see the DLL load in real-time).



## 4. Review & Export Procmon Data

1. **Stop Capture**  
   - I’ll click the magnifying glass again to stop capturing events.

2. **Analyze Events**  
   - Check for **WriteFile** to `C:\Windows\System32\evilssp.dll`.
   - Check for **RegSetValue** to `Security Packages` in the LSA key.

3. **Save Log**  
   - **File → Save** → choose `.PML` or `.CSV`.  
   - I’ll likely pick “All Events” or “Events Displayed Using Current Filter.”



## 5. Load Into Procdot

1. **Launch Procdot**  
   - On the same VM or a separate analysis machine.

2. **Import the Procmon Output**  
   - If using `.pml` directly doesn’t work, I’ll export to `.csv` from Procmon and then import that into Procdot.

3. **Generate Graph**  
   - Procdot will parse the sequence of events (file writes, registry changes, process starts).

4. **Examine Flow**  
   - I should see how the DLL got placed into `System32` and how the registry got modified.



## 6. Interpretation

- If I rebooted, I might see **LoadLibrary** calls or some “Image Load” event referencing `evilssp.dll` by LSASS.
- If I didn’t reboot, I’ll at least see the file system and registry modifications from my test scripts/commands.



## 7. Cleanup

1. **Undo Registry Changes**  
   - Remove `evilssp` from the `Security Packages` multi-string value.
2. **Delete the DLL**  
   - Delete `C:\Windows\System32\evilssp.dll`.
3. **Reboot** (Optional)  
   - To confirm LSASS no longer attempts to load the malicious SSP.



**That’s it!** This sequence should produce a clear event trail in Procmon and a nice process flow visualization in Procdot, illustrating how an attacker might register a malicious SSP in LSASS.
