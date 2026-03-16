# Threat Hunt Report: The Buyer
### Ashford Sterling Recruitment - Akira Ransomware Investigation

**Analyst:** Sana Jafferi
**Date Completed:** 2026-03-16
**Environment Investigated:** AS-PC1, AS-PC2, AS-SRV
**Timeframe:** January 15 - January 28, 2026
**Platform:** Microsoft Defender for Endpoint + Microsoft Sentinel

---

## 🧠 Scenario Overview

Following the initial compromise investigated in *"The Broker"*, a ransomware affiliate returned to the environment using pre-staged access. The threat actor leveraged dormant persistence mechanisms from the first intrusion specifically a pre-installed AnyDesk instance and re-entered the network through a compromised user account. The attacker deployed a new C2 beacon, disabled security controls, harvested credentials, performed network reconnaissance, moved laterally to the file server, exfiltrated compressed data, and ultimately deployed **Akira ransomware** across two hosts.

> ⚠️ All queries are written for **Microsoft Sentinel** using `TimeGenerated`. For MDE Advanced Hunting, replace `TimeGenerated` with `Timestamp`.

---

## 🎯 Executive Summary

The investigation revealed a multi-stage intrusion spanning two weeks. The threat actor re-entered the environment via pre-staged **AnyDesk** remote access installed during the prior "The Broker" compromise. Using a compromised account on **AS-PC2**, the attacker deployed a new C2 implant, disabled Windows Defender via script and registry tampering, dumped LSASS credentials, scanned the internal network, moved laterally to **AS-SRV**, exfiltrated compressed data archives, and finally deployed **Akira ransomware**. After encryption, the ransomware binary was deleted via a cleanup script to hinder forensic recovery.

---

## ✅ Completed Flags

| Flag # | Section | Objective | Answer |
|--------|---------|-----------|--------|
| Q1 | Ransom Note | Ransomware group | `Akira` |
| Q2 | Ransom Note | TOR negotiation address | `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` |
| Q3 | Ransom Note | Victim unique ID | `813R-QWJM-XKIJ` |
| Q4 | Ransom Note | Encrypted file extension | `.akira` |
| Q5 | Infrastructure | Payload domain | `sync.cloud-endpoint.net` |
| Q6 | Infrastructure | Ransomware staging domain | `cdn.cloud-endpoint.net` |
| Q7 | Infrastructure | C2 IP addresses | `104.21.30.237, 172.67.174.46` |
| Q8 | Infrastructure | Remote tool relay domain | `relay-0b975d23.net.anydesk.com` |
| Q9 | Defense Evasion | Evasion script | `kill.bat` |
| Q10 | Defense Evasion | Evasion script SHA256 | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` |
| Q11 | Defense Evasion | Registry value | `DisableAntiSpyware` |
| Q12 | Defense Evasion | Registry modification time | `21:03:42` |
| Q13 | Credential Access | Process hunt command | `tasklist \| findstr lsass` |
| Q14 | Credential Access | Named pipe accessed | `\Device\NamedPipe\lsass` |
| Q15 | Initial Access | Remote access tool | `AnyDesk` |
| Q16 | Initial Access | Suspicious execution path | `C:\Users\Public` |
| Q17 | Initial Access | Attacker external IP | `88.97.164.155` |
| Q18 | Initial Access | Compromised user | `david.mitchell` |
| Q19 | Command & Control | C2 beacon filename | `wsync.exe` |
| Q20 | Command & Control | Beacon deployment path | `C:\ProgramData` |
| Q21 | Command & Control | Original beacon SHA256 | `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` |
| Q22 | Command & Control | Replacement beacon SHA256 | `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` |
| Q23 | Reconnaissance | Scanner tool | `scan.exe` |
| Q24 | Reconnaissance | Scanner SHA256 | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` |
| Q25 | Reconnaissance | Scanner arguments | `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us` |
| Q26 | Reconnaissance | Enumerated IPs | `10.1.0.154, 10.1.0.183` |
| Q27 | Lateral Movement | Lateral account | `as.srv.administrator` |
| Q28 | Tool Transfer | First download LOLBIN | `bitsadmin.exe` |
| Q29 | Tool Transfer | Fallback PowerShell cmdlet | `Invoke-WebRequest` |
| Q30 | Exfiltration | Staging tool | `st.exe` |
| Q31 | Exfiltration | Staging tool SHA256 | `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` |
| Q32 | Exfiltration | Exfil archive | `exfil_data.zip` |
| Q33 | Ransomware | Ransomware filename | `updater.exe` |
| Q34 | Ransomware | Ransomware SHA256 | `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` |
| Q35 | Ransomware | Staging process on AS-SRV | `powershell.exe` |
| Q36 | Ransomware | Recovery prevention command | `wmic shadowcopy delete` |
| Q37 | Ransomware | Ransom note origin | `updater.exe` |
| Q38 | Ransomware | Encryption start time (UTC) | `22:18:33` |
| Q39 | Anti-Forensics | Cleanup script | `clean.bat` |
| Q40 | Anti-Forensics | Affected hosts | `as-pc2, as-srv` |

---

## Flag by Flag

---

### 🔴 SECTION 1: Ransom Note Analysis

#### Q1 - Threat Actor
**Objective:** Identify the ransomware group from the ransom note.

**Identified Group:** `Akira`

**Why It Matters:** The ransom note dropped on the file server explicitly identified the ransomware group. Akira is a ransomware-as-a-service (RaaS) operation known for double extortion - encrypting files while threatening to publish stolen data if the ransom is not paid.

```kql
// Find the ransom note dropped on the file server - answers to Q1, Q2, Q3 and Q4 are inside the file
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FileName contains "readme"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc
```

---

#### Q2 - Negotiation Portal
**Objective:** Find the TOR address from the ransom note.

**Why It Matters:** The TOR onion address provides the victim a channel to communicate and negotiate with the attacker. Documenting this is critical for threat intelligence sharing and law enforcement reporting.

> ⚠️ Note: TOR addresses often contain lowercase `l` characters that visually resemble the number `1` - always copy-paste rather than retyping.

---

#### Q3 - Victim ID
**Objective:** Find the unique victim identifier assigned by the ransomware group.

**Why It Matters:** Each victim receives a unique ID used to identify them in the attacker's negotiation portal. This confirms the specific ransomware campaign and can be used to correlate intelligence with other victims.

> 💡 The victim ID is found in the ransom note - look for the "Your personal ID" field.

---

#### Q4 - Encrypted Extension
**Objective:** Identify the file extension appended to encrypted files.

**Why It Matters:** Identifying the encrypted extension confirms the ransomware variant and enables scope assessment of impacted files across the environment.

> 💡 The extension is stated in the ransom note found via the Q1 query. 

---

### 🌐 SECTION 2: Infrastructure

#### Q5 - Payload Domain
**Objective:** Find the domain that hosted attacker tools.

**Why It Matters:** Identifying the payload domain allows defenders to block it at the perimeter and correlate it with other threat intelligence. The attacker used multiple obfuscated PowerShell download cradles to evade string-based detection.

```kql
// Look for PowerShell download activity and extract the domain
DeviceEvents
| where ActionType == "PowerShellCommand"
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where AdditionalFields contains "IWR" or AdditionalFields contains "WebRequest"
| project TimeGenerated, DeviceName, AdditionalFields
| order by TimeGenerated asc
```

---

#### Q6 - Ransomware Staging Domain
**Objective:** Find the separate domain used to stage the ransomware.

**Why It Matters:** The attacker used a separate subdomain for ransomware staging, demonstrating disciplined infrastructure separation - a hallmark of organized ransomware affiliates.

```kql
// Find outbound connections from the C2 implant
DeviceNetworkEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where RemoteUrl != ""
| where InitiatingProcessFolderPath contains "ProgramData"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

#### Q7 - C2 IP Addresses
**Objective:** Find the two IPs resolving to attacker infrastructure.

**Why It Matters:** Both IPs are Cloudflare-fronted proxies used to mask the real origin server. Identifying them enables firewall blocking and threat intelligence correlation.

```kql
// Summarize IPs contacted by the C2 implant
DeviceNetworkEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where RemoteUrl contains "cloud-endpoint"
| summarize Domains=make_set(RemoteUrl) by RemoteIP
```

---

#### Q8 - Remote Tool Relay Domain
**Objective:** Find the specific relay domain used by the remote access tool.

**Why It Matters:** The specific relay domain confirms which session was active during the intrusion window and enables blocking of that specific relay infrastructure.

```kql
// Find relay connections made by the remote access tool
DeviceNetworkEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where RemoteUrl contains "relay"
| where RemoteUrl != ""
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

### 🛡️ SECTION 3: Defense Evasion

#### Q9 - Evasion Script
**Objective:** Identify the script used to disable security controls.

**Why It Matters:** The evasion script disabled multiple Windows Defender components and modified the registry — clearing the path for ransomware deployment. It was created by the C2 implant in a staging directory.

```kql
// Find script files created by suspicious processes in staging directories
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

#### Q10 - Evasion Script Hash
**Objective:** Get the SHA256 of the evasion script.

**Why It Matters:** The hash enables threat intelligence correlation and supports detection rule creation across security tools.

```kql
// Use the filename from Q9 to retrieve its hash
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

> 💡 The SHA256 column on the same row as your Q9 answer is your Q10 answer.

---

#### Q11 - Registry Tampering
**Objective:** Find the registry value used to disable Windows Defender.

**Why It Matters:** The attacker modified the Windows Defender policy registry key — a persistent change that survives process restarts and reboots, ensuring security controls remain disabled.

```kql
// Find registry modifications to Windows Defender policy keys
DeviceRegistryEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where RegistryKey contains "Windows Defender"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

---

#### Q12 - Registry Modification Timestamp
**Objective:** Determine the exact UTC time the registry was modified.

**Why It Matters:** This timestamp anchors the defense evasion phase in the attack timeline, confirming the deliberate sequencing of disabling defenses before ransomware deployment.

```kql
// Find the exact timestamp of the Defender registry modification
DeviceRegistryEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where RegistryKey contains "Windows Defender"
| where RegistryKey contains "Policies"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName
| order by TimeGenerated asc
```

---

### 🔑 SECTION 4: Credential Access

#### Q13 - Process Hunt
**Objective:** Find the command used to enumerate processes for credential theft.

**Why It Matters:** The attacker enumerated running processes to locate `lsass.exe` before dumping its memory — a classic pre-credential-dump reconnaissance step.

```kql
// Find process enumeration commands targeting lsass
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ProcessCommandLine contains "lsass"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q14 - Credential Pipe
**Objective:** Find the named pipe accessed during credential theft activity.

**Why It Matters:** Named pipes are used internally by credential dumping tools during LSASS memory reads. Identifying the pipe confirms the credential theft method used.

```kql
// Find named pipe events related to credential access
DeviceEvents
| where ActionType == "NamedPipeEvent"
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
| where PipeName != ""
| project TimeGenerated, DeviceName, PipeName, InitiatingProcessFileName, AdditionalFields
| order by TimeGenerated asc
```

---

### 🚪 SECTION 5: Initial Access

#### Q15 - Remote Access Tool
**Objective:** Identify the remote access tool used to re-enter the environment.

**Why It Matters:** The remote access tool was pre-staged during the prior "The Broker" intrusion and left running from an unusual path. This highlights the risk of incomplete remediation after an initial breach.

```kql
// Find remote access tools running on attack day
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FolderPath contains "Public"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q16 - Suspicious Execution Path
**Objective:** Identify the unusual directory the remote access tool was running from.

**Why It Matters:** The tool was deliberately placed in a world-writable location accessible to all users — no admin privileges required for execution — making it an ideal persistence staging path.

```kql
// Find where the remote access tool was installed
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-16))
| where ActionType == "FileCreated"
| where FileName contains "AnyDesk"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

#### Q17 – Attacker External IP
**Objective:** Identify the attacker's real external IP address.

**Why It Matters:** The attacker's external IP can be blocked at the perimeter and shared with threat intelligence platforms to identify other potential victims.

```kql
// Find external IPs connecting through the remote access tool
DeviceNetworkEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where InitiatingProcessFileName =~ "anydesk.exe"
| where RemoteIP != ""
| where RemoteUrl == ""
| summarize count() by RemoteIP
| order by count_ desc
```

---

#### Q18 – Compromised User
**Objective:** Identify the user account that was compromised on AS-PC2.

**Why It Matters:** Identifying the compromised account enables immediate credential reset and scope assessment of what data and systems the attacker could access using that account's privileges.

```kql
// Find successful logons to AS-PC2 on attack day
DeviceLogonEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
| order by TimeGenerated asc
```

---

### 📡 SECTION 6: Command & Control

#### Q19 – Primary C2 Beacon
**Objective:** Identify the new C2 beacon deployed after the previous one failed.

**Why It Matters:** The C2 beacon is the attacker's primary persistence and control mechanism — establishing outbound communications that blend in with normal HTTPS traffic.

```kql
// Find suspicious executables created in staging directories
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

#### Q20 – Beacon Deployment Location
**Objective:** Identify where the C2 beacon was deployed.

**Why It Matters:** The deployment location reveals the attacker's staging preference — a directory accessible to all users that blends with legitimate application data.

> 💡 The `FolderPath` column from Q19 contains your answer.

---

#### Q21 – Original Beacon Hash
**Objective:** Find the SHA256 of the first version of the C2 beacon.

**Why It Matters:** The original beacon hash allows defenders to create detection signatures and correlate this binary with other ransomware affiliate intrusions.

```kql
// Find all versions of the C2 beacon created on AS-PC2
DeviceFileEvents
| where DeviceName == "as-pc2"
| where ActionType == "FileCreated"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

> 💡 The **first row** returned is the original beacon — its SHA256 is your Q21 answer.

---

#### Q22 – Replacement Beacon Hash
**Objective:** Find the SHA256 of the replacement C2 beacon.

**Why It Matters:** A second version was deployed after the first failed, confirming the attacker actively managed their C2 infrastructure — potentially deploying a more stable variant.

> 💡 Using the same query as Q21 — the **second row** returned is the replacement beacon. Check `DeviceFileEvents` with `ActionType == "FileModified"` if a second `FileCreated` event is not visible.

```kql
// Find modified versions of the C2 beacon
DeviceFileEvents
| where DeviceName == "as-pc2"
| where ActionType == "FileModified"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

### 🔭 SECTION 7: Reconnaissance

#### Q23 – Scanner Tool
**Objective:** Identify the network scanner deployed by the attacker.

**Why It Matters:** The scanner was used to map the internal network and identify live hosts — feeding the attacker intelligence for lateral movement targeting.

```kql
// Find scanning tools downloaded or created on attack day
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FolderPath contains "Downloads"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

#### Q24 – Scanner Hash
**Objective:** Get the SHA256 of the scanner tool.

> 💡 The `SHA256` column from the Q23 query result is your Q24 answer.

---

#### Q25 – Scanner Execution Arguments
**Objective:** Find the arguments passed to the scanner on execution.

**Why It Matters:** The arguments reveal the attacker's intent — running in portable mode leaves no installation footprint, making forensic recovery more difficult.

```kql
// Find how the scanner was executed and what arguments were passed
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FolderPath contains "Downloads"
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q26 – Network Share Enumeration
**Objective:** Find the two internal IPs where network shares were enumerated.

**Why It Matters:** Share enumeration confirms deliberate, goal-oriented lateral reconnaissance — the attacker was identifying specific data targets rather than performing opportunistic scanning.

```kql
// Find net view commands used to enumerate shares
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName == "net.exe"
| where ProcessCommandLine contains "view"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🔀 SECTION 8: Lateral Movement

#### Q27 – Lateral Movement Account
**Objective:** Find the account used to authenticate to AS-SRV.

**Why It Matters:** The account used for lateral movement was likely obtained from the LSASS memory dump — demonstrating the cascading impact of credential theft earlier in the attack chain.

```kql
// Find successful remote logons to AS-SRV
DeviceLogonEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
| order by TimeGenerated asc
```

---

### ⬇️ SECTION 9: Tool Transfer

#### Q28 – First Download Method (LOLBIN)
**Objective:** Find the first living-off-the-land binary used to download tools.

**Why It Matters:** LOLBins are native Windows tools abused by attackers to download payloads while avoiding detection by security tools that may not flag trusted system binaries.

```kql
// Find LOLBin download activity
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName has_any ("bitsadmin.exe", "certutil.exe", "mshta.exe", "wscript.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q29 – Fallback Download Method
**Objective:** Find the PowerShell cmdlet used as a fallback when the first method failed.

**Why It Matters:** Three different obfuscation techniques were used — base64 encoding, string concatenation, and variable splitting — demonstrating the attacker's adaptability when initial methods encounter issues.

```kql
// Find PowerShell download commands used as fallback
DeviceEvents
| where ActionType == "PowerShellCommand"
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where AdditionalFields contains "Uri"
| project TimeGenerated, DeviceName, AdditionalFields
| order by TimeGenerated asc
```

---

### 📦 SECTION 10: Exfiltration

#### Q30 – Staging Tool
**Objective:** Find the tool used to compress data before exfiltration.

**Why It Matters:** Data compression before exfiltration is a hallmark of double-extortion ransomware — stolen data gives the attacker two points of leverage over the victim.

```kql
// Find tools created in staging directories around exfiltration time
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

#### Q31 – Staging Tool Hash
**Objective:** Get the SHA256 of the staging tool.

> 💡 The `SHA256` column from the Q30 query result is your Q31 answer.

---

#### Q32 – Exfiltration Archive
**Objective:** Find the archive file created for exfiltration.

**Why It Matters:** Identifying the archive filename and hash enables recovery teams to assess the full scope of data loss and potentially recover the archive if found on network storage.

```kql
// Find archive files created on attack day
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ActionType == "FileCreated"
| where FileName has_any (".zip", ".7z", ".rar", ".tar")
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

### 💣 SECTION 11: Ransomware Deployment

#### Q33 – Ransomware Filename
**Objective:** Find the ransomware binary disguised as a legitimate process.

**Why It Matters:** The ransomware was masqueraded as a common system utility — a technique used to avoid suspicion from users and automated monitoring tools.

```kql
// Find suspicious executables staged on AS-SRV before encryption
DeviceFileEvents
| where DeviceName == "as-srv"
| where ActionType == "FileCreated"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

#### Q34 – Ransomware Hash
**Objective:** Get the SHA256 of the ransomware binary.

> 💡 The `SHA256` column from the Q33 query result is your Q34 answer.

---

#### Q35 – Ransomware Staging Process
**Objective:** Find the process that staged the ransomware on AS-SRV.

**Why It Matters:** Identifying the staging process confirms how the C2 implant delivered the ransomware and provides a detection opportunity for similar future attacks.

```kql
// Find what process created the ransomware binary on AS-SRV
DeviceFileEvents
| where DeviceName == "as-srv"
| where ActionType == "FileCreated"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

> 💡 The `InitiatingProcessFileName` column on the ransomware row is your Q35 answer.

---

#### Q36 – Recovery Prevention
**Objective:** Find the command used to delete Volume Shadow Copies.

**Why It Matters:** Deleting VSS prevents victims from restoring encrypted files without paying the ransom — a standard pre-encryption step in modern ransomware deployments.

```kql
// Find shadow copy deletion commands
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName has_any ("wmic.exe", "vssadmin.exe", "wbadmin.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q37 – Ransom Note Origin
**Objective:** Find the process that dropped the ransom note.

**Why It Matters:** The process that drops the ransom note is the ransomware binary itself executing its encryption and notification routine — confirming the exact binary responsible for impact.

```kql
// Find what process created the ransom note files
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FileName contains "readme"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

> 💡 The `InitiatingProcessFileName` column is your Q37 answer.

---

#### Q38 – Encryption Start Time
**Objective:** Determine when encryption began.

**Why It Matters:** The first ransom note drop timestamp marks the precise start of encryption — the critical anchor point for the impact phase and recovery team prioritization.

> 💡 The `TimeGenerated` value of the **first** ransom note created (from Q37 query) is your Q38 answer. Format as `HH:MM:SS` UTC.

---

### 🧹 SECTION 12: Anti-Forensics & Scope

#### Q39 – Cleanup Script
**Objective:** Find the script that deleted the ransomware binary after execution.

**Why It Matters:** Deleting the ransomware binary after encryption is a deliberate anti-forensics measure designed to prevent incident responders from recovering and analyzing the ransomware sample.

```kql
// Find what deleted the ransomware binary
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileDeleted"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

> 💡 The `InitiatingProcessCommandLine` column reveals the cleanup script name.

---

#### Q40 – Affected Hosts
**Objective:** Determine the full scope of compromised hosts.

**Why It Matters:** Understanding the full scope of encryption enables recovery teams to prioritize restoration efforts and ensures no affected systems are missed during remediation.

```kql
// Find all hosts where ransomware activity occurred
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName contains "readme"
| summarize count() by DeviceName
| order by count_ desc
```

---

## 🔍 Attack Timeline

| Timestamp (UTC) | Event | Device | Details |
|----------------|-------|--------|---------|
| 2026-01-15 04:08 | AnyDesk downloaded | AS-PC1 | Downloaded via `certutil` from AnyDesk CDN |
| 2026-01-15 04:10 | AnyDesk installed & password set | AS-PC1 | Placed at `C:\Users\Public\AnyDesk.exe` |
| 2026-01-15 04:41 | AnyDesk deployed to AS-PC2 | AS-PC2 | Lateral deployment via WMI/PsExec |
| 2026-01-15 04:57 | AnyDesk deployed to AS-SRV | AS-SRV | Full environment coverage achieved |
| 2026-01-15 04:52 | Credentials dumped (The Broker) | AS-PC2 | SAM/SYSTEM hives saved to `C:\Users\Public\` |
| 2026-01-27 19:14 | Attacker re-enters via AnyDesk | AS-PC2 | `david.mitchell` logon from Guacamole relay |
| 2026-01-27 19:15 | AnyDesk session established | AS-PC2 | Relay: `relay-0b975d23.net.anydesk.com` |
| 2026-01-27 20:17 | Scanner downloaded and executed | AS-PC2 | Network scanner run from Downloads folder |
| 2026-01-27 20:22 | Original C2 beacon deployed | AS-PC2 | First `wsync.exe` dropped to `C:\ProgramData\` |
| 2026-01-27 20:42 | C2 beacon re-downloaded (obfuscated) | AS-PC2 | Three obfuscated PowerShell download attempts |
| 2026-01-27 20:44 | Replacement C2 beacon deployed | AS-PC2 | Second `wsync.exe` with different hash |
| 2026-01-27 20:45 | LSASS memory dumped | AS-PC2 | Credential extraction via named pipe |
| 2026-01-27 21:00 | Process enumeration for LSASS | AS-PC2 | `tasklist \| findstr lsass` |
| 2026-01-27 21:03 | Defender disabled via evasion script | AS-PC2 | `kill.bat` — `Set-MpPreference` + registry |
| 2026-01-27 21:03 | VSS deleted | AS-PC2 | Shadow copies removed to prevent recovery |
| 2026-01-27 21:17 | Network scan performed | AS-PC2 | Internal range mapped for lateral targets |
| 2026-01-27 22:07 | Lateral movement to AS-SRV | AS-SRV | Administrator RDP from relay IP |
| 2026-01-27 22:14 | C2 beacon deployed on AS-SRV | AS-SRV | Implant dropped via PowerShell |
| 2026-01-27 22:15 | Ransomware staged on AS-SRV | AS-SRV | Disguised binary written by PowerShell |
| 2026-01-27 22:17 | Share enumeration from AS-SRV | AS-SRV | `net view` against internal workstations |
| 2026-01-27 22:18 | Data compressed for exfiltration | AS-SRV | Archive created from sensitive shares |
| 2026-01-27 22:18:33 | Encryption begins | AS-SRV | Ransomware executes, drops ransom notes |
| 2026-01-27 22:20 | Ransomware binary deleted | AS-SRV | Cleanup script removes evidence |

---

## 🔑 Key IOCs

| Type | Value |
|------|-------|
| Malicious Domain | `sync.cloud-endpoint.net` |
| Malicious Domain | `cdn.cloud-endpoint.net` |
| C2 IP | `104.21.30.237` |
| C2 IP | `172.67.174.46` |
| Attacker External IP | `88.97.164.155` |
| C2 Implant (original) | `wsync.exe` — SHA256: `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` |
| C2 Implant (replacement) | `wsync.exe` — SHA256: `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` |
| Ransomware Binary | `updater.exe` — SHA256: `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` |
| Initial Payload | `daniel_richardson_cv.pdf.exe` |
| Persistence Tool | `AnyDesk.exe` — `C:\Users\Public\AnyDesk.exe` |
| AnyDesk Relay | `relay-0b975d23.net.anydesk.com` |
| Evasion Script | `kill.bat` — SHA256: `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` |
| Cleanup Script | `clean.bat` — `C:\ProgramData\clean.bat` |
| Staging Tool | `st.exe` — SHA256: `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` |
| Exfil Archive | `exfil_data.zip` |
| Scanner Tool | `scan.exe` — SHA256: `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` |
| Compromised Account | `david.mitchell` |
| Compromised Account | `as.srv.administrator` |
| Scheduled Task | `MicrosoftEdgeUpdateCheck` (The Broker persistence) |
| TOR Address | `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` |
| Victim ID | `813R-QWJM-XKIJ` |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | Tool/Method |
|--------|-----------|-------------|
| Initial Access | T1204 – User Execution | Double extension payload from prior intrusion |
| Persistence | T1219 – Remote Access Software | AnyDesk pre-staged at `C:\Users\Public\` |
| Persistence | T1053.005 – Scheduled Task | `MicrosoftEdgeUpdateCheck` from prior intrusion |
| Execution | T1059.001 – PowerShell | Obfuscated download cradles (base64, string concat, variable split) |
| Execution | T1105 – Ingress Tool Transfer | `bitsadmin.exe` LOLBin for tool download |
| Defense Evasion | T1562.001 – Disable Security Tools | Evasion script disabling multiple Defender components |
| Defense Evasion | T1112 – Modify Registry | `DisableAntiSpyware` registry key modification |
| Defense Evasion | T1036 – Masquerading | Ransomware disguised as software updater |
| Defense Evasion | T1027 – Obfuscated Files | Multiple obfuscation techniques for downloads |
| Credential Access | T1003.001 – LSASS Memory | LSASS memory dump via named pipe |
| Discovery | T1046 – Network Service Scanning | Internal network scanner mapping `10.1.x.x` range |
| Discovery | T1135 – Network Share Discovery | `net view` enumerating shares on internal hosts |
| Lateral Movement | T1021.001 – Remote Desktop | RDP using harvested administrator credentials |
| Collection | T1560 – Archive Collected Data | Staging tool compressing sensitive share data |
| Exfiltration | T1041 – Exfiltration Over C2 | Data exfiltrated via C2 implant channel |
| Impact | T1486 – Data Encrypted for Impact | Akira ransomware with `.akira` extension |
| Impact | T1490 – Inhibit System Recovery | VSS deletion preventing file restoration |
| Impact | T1485 – Data Destruction | Cleanup script deletes ransomware binary post-encryption |

---

## 💠 Diamond Model Summary

| Feature | Details |
|---------|---------|
| **Adversary** | Akira ransomware affiliate — hands-on-keyboard operator demonstrating patient, multi-phase methodology. Re-used pre-staged access from a prior intrusion, showing operational maturity and deep awareness of the victim environment. |
| **Infrastructure** | Attacker-controlled: `sync.cloud-endpoint.net`, `cdn.cloud-endpoint.net` (Cloudflare-fronted). Remote access relay: `relay-0b975d23.net.anydesk.com`. Guacamole RDP gateways: `10.0.8.5`, `10.0.8.6`, `10.0.8.8`. Attacker external IP: `88.97.164.155`. |
| **Capability** | C2 beacon (`wsync.exe`), AnyDesk for persistent remote access, LSASS credential dumping via named pipe, network scanning, defense evasion scripts, data staging and compression, Akira ransomware, anti-forensics cleanup. |
| **Victim** | Primary: AS-PC2 (entry point). Lateral target: AS-SRV (file server). Encrypted hosts: AS-PC2 and AS-SRV. Targeted shares: `C:\Shares\` — Clients, Payroll, Compliance, Contractors, Backups. |

---

## ✅ Conclusion

The Ashford Sterling Recruitment intrusion represents a sophisticated, patient, multi-phase ransomware attack by an Akira affiliate. The threat actor demonstrated operational maturity by returning to a previously compromised environment using pre-staged tools, executing with precision against high-value targets, and covering their tracks with cleanup scripts.

The attack chain progressed methodically: re-entry via AnyDesk → C2 establishment → credential theft → network reconnaissance → lateral movement → data exfiltration → ransomware deployment → anti-forensics cleanup — all within a few hours on January 27, 2026.

The most critical lesson: **incomplete remediation after the initial "The Broker" compromise directly enabled this attack.** Had AnyDesk been removed and all credentials reset, the attacker would have had no pre-staged access to leverage.

---

## 🧠 Lessons Learned

**Pre-Staged Access Is the Hardest Threat to Detect**
The attacker returned months later using pre-installed tooling — highlighting the critical risk of incomplete post-incident remediation.

**Obfuscated Download Cradles Evade Simple Detection**
Three different obfuscation methods were used for a single download — behavioral detection is essential, not just signature-based.

**Legitimate Tools Are the Preferred Attack Vector**
Every major stage used legitimate software: AnyDesk, bitsadmin, net.exe, wmic. LOLBin behavioral monitoring is non-negotiable.

**Speed of Execution Limits Response Time**
From re-entry to encryption took approximately 3 hours — leaving a narrow window for detection and containment.

**Credential Theft Has Long-Term Consequences**
Credentials harvested in the prior intrusion were reused for lateral movement — demonstrating the cascading impact of uncontained credential compromise.

**Double Extortion Increases Victim Pressure**
Data was exfiltrated before encryption, giving the attacker two points of leverage: file recovery and threat of data publication.

---

## 🛡️ Remediation Actions

**Immediate:**
- Isolate AS-PC2 and AS-SRV from the network
- Reset all credentials for compromised accounts
- Remove `C:\Users\Public\AnyDesk.exe` from all hosts
- Delete scheduled task `MicrosoftEdgeUpdateCheck` on all hosts
- Block `sync.cloud-endpoint.net` and `cdn.cloud-endpoint.net` at firewall/proxy
- Block attacker external IP at perimeter firewall

**Short Term:**
- Enforce policy restricting remote tools to IT-approved applications only
- Enable PowerShell Script Block Logging and AMSI on all endpoints
- Alert on LOLBin network activity (`bitsadmin.exe`, `certutil.exe`)
- Monitor for `Set-MpPreference` and Windows Defender registry modifications
- Implement privileged account monitoring for all local administrator accounts
- Hunt for unknown executables in `C:\ProgramData\` across all endpoints

**Long Term:**
- Enforce MFA for all RDP and remote access sessions
- Implement network segmentation to limit lateral movement
- Deploy honeypot files in share directories to detect early ransomware activity
- Conduct full forensic review of "The Broker" intrusion to ensure complete remediation
- Establish immutable off-site backups to enable recovery without ransom payment
- Implement application allowlisting to prevent unauthorized executable deployment

---

*Investigation completed on the SancLogic Cyber Range — The Buyer scenario.*
*Platform: Microsoft Defender for Endpoint + Microsoft Sentinel (KQL)*
