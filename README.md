# Threat Hunt Report: THE BUYER
### Ashford Sterling Recruitment - Akira Ransomware Investigation

**Analyst:** Sana Jafferi  
**Date Completed:** 2026-03-16  
**Environment Investigated:** AS-PC1, AS-PC2, AS-SRV  
**Timeframe:** January 15 – January 31, 2026  
**Platform:** Microsoft Defender for Endpoint + Microsoft Sentinel  

> ⚠️ All queries use `TimeGenerated` for Sentinel. For MDE Advanced Hunting replace with `Timestamp`.

---

## INCIDENT_BRIEF

Following the initial compromise in *"The Broker"*, a ransomware affiliate returned using pre-staged AnyDesk access. The attacker deployed a new C2 beacon, disabled security controls, dumped credentials, moved laterally to the file server, exfiltrated data, and deployed **Akira ransomware** across two hosts - all within a 3-hour window on January 27, 2026.

---

## TARGET_ENVIRONMENT

| System | Role | OS | Status |
|--------|------|----|--------|
| `AS-PC1` | IT Workstation | Windows 10 | COMPROMISED |
| `AS-PC2` | User Workstation | Windows 10 | COMPROMISED |
| `AS-SRV` | File Server | Windows Server | COMPROMISED |

---

## ATTACK_CHAIN

```
Jan 15  ──► AnyDesk staged on all hosts (The Broker)
             Credentials dumped to C:\Users\Public\

Jan 27  ──► 19:14  Re-entry via AnyDesk (david.mitchell / AS-PC2)
             20:17  scan.exe → network mapped
             20:22  wsync.exe deployed (C2 beacon)
             20:45  LSASS dumped via named pipe
             21:00  tasklist | findstr lsass
             21:03  kill.bat → Defender disabled → VSS deleted
             22:07  Lateral move → AS-SRV (as.srv.administrator)
             22:15  updater.exe staged via PowerShell
             22:18  st.exe → exfil_data.zip
         22:18:33  🔴 Encryption starts → akira_readme.txt dropped
             22:20  clean.bat → updater.exe deleted
```

---

## INVESTIGATION_CHAPTERS

| Chapter | Name | Flags | Focus |
|---------|------|-------|-------|
| 1 | Ransom Note Analysis | Q1–Q4 | Ransomware identification and victim details |
| 2 | Infrastructure | Q5–Q8 | C2 domains, IPs, and remote access relay |
| 3 | Defense Evasion | Q9–Q12 | Security bypass and registry tampering |
| 4 | Credential Access | Q13–Q14 | LSASS dumping and named pipe access |
| 5 | Initial Access | Q15–Q18 | Re-entry via pre-staged remote tool |
| 6 | Command & Control | Q19–Q22 | C2 beacon deployment and versioning |
| 7 | Reconnaissance | Q23–Q26 | Network scanning and share enumeration |
| 8 | Lateral Movement | Q27 | Credential-based pivot to file server |
| 9 | Tool Transfer | Q28–Q29 | LOLBin abuse and PowerShell downloads |
| 10 | Exfiltration | Q30–Q32 | Data staging and archive creation |
| 11 | Ransomware Deployment | Q33–Q38 | Execution, encryption, and ransom note |
| 12 | Anti-Forensics & Scope | Q39–Q40 | Cleanup and compromised host scope |

---

## MITRE_ATT&CK_COVERAGE

| Tactic | Techniques |
|--------|-----------|
| Initial Access | T1204 User Execution, T1219 Remote Access Software |
| Execution | T1059.001 PowerShell, T1105 Ingress Tool Transfer |
| Persistence | T1219 Remote Access Software, T1053.005 Scheduled Task |
| Defense Evasion | T1562.001 Impair Defenses, T1112 Modify Registry, T1036 Masquerading, T1027 Obfuscation |
| Credential Access | T1003.001 LSASS Memory |
| Discovery | T1046 Network Scanning, T1135 Network Share Discovery |
| Lateral Movement | T1021.001 Remote Desktop |
| Collection | T1560 Archive Collected Data |
| Exfiltration | T1041 Exfil Over C2 |
| Impact | T1486 Data Encrypted, T1490 Inhibit Recovery, T1485 Data Destruction |

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

**Why It Matters:** Akira is a RaaS operation known for double extortion - encrypting files while threatening to publish stolen data.

`T1486 Data Encrypted` `DeviceFileEvents` `Ransom Note Analysis`

```kql
// Find the ransom note - answers to Q1, Q2, Q3 and Q4 are inside the file
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FileName contains "readme"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc
```

> 💡 Open the file at the path shown in `FolderPath` - Q1 through Q4 are all answered by reading the ransom note.

---

#### Q2 - Negotiation Portal
**Objective:** Find the TOR address from the ransom note.

**Why It Matters:** Documents the attacker's communication channel for threat intelligence and law enforcement reporting.

`T1486 Data Encrypted` `Ransom Note Analysis`

> 💡 No query needed - open the ransom note from Q1 and find the **Contact** section.
> ⚠️ Always copy-paste TOR addresses - lowercase `l` and number `1` look identical.

---

#### Q3 - Victim ID
**Objective:** Find the unique victim identifier.

**Why It Matters:** Confirms the specific campaign and enables intelligence correlation with other Akira victims.

`T1486 Data Encrypted` `Ransom Note Analysis`

> 💡 No query needed - find the **Your personal ID:** field in the ransom note from Q1.

---

#### Q4 - Encrypted Extension
**Objective:** Identify the extension appended to encrypted files.

**Why It Matters:** Confirms the ransomware variant and enables scope assessment across the environment.

`T1486 Data Encrypted` `DeviceFileEvents` `Impact Analysis`

> 💡 Stated in the ransom note. Use the query below to confirm in the logs.

```kql
// Compare FileName (encrypted) with PreviousFileName (original) to identify the extension
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileRenamed"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, PreviousFileName, FolderPath
| order by TimeGenerated asc
```

---

### 🌐 SECTION 2: Infrastructure

#### Q5 - Payload Domain
**Objective:** Find the domain that hosted attacker tools.

**Why It Matters:** Enables perimeter blocking and threat intelligence correlation. The attacker used three obfuscated PowerShell download methods to evade detection.

`T1105 Ingress Tool Transfer` `DeviceProcessEvents` `Infrastructure Analysis`

> ⚠️ DO NOT browse to this domain directly.

```kql
// Find download commands revealing the payload domain
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ProcessCommandLine contains "http"
| where FileName has_any ("bitsadmin.exe", "powershell.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

> 💡 The domain appears in the `ProcessCommandLine` column download URLs.

---

#### Q6 - Ransomware Staging Domain
**Objective:** Find the separate domain used to stage the ransomware.

**Why It Matters:** Separate staging infrastructure demonstrates disciplined tradecraft - a hallmark of organized ransomware affiliates.

`T1071 Application Layer Protocol` `DeviceNetworkEvents` `Infrastructure Analysis`

> ⚠️ DO NOT browse to this domain directly.

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

> 💡 Two subdomains appear - the staging domain is separate from the Q5 payload domain.

---

#### Q7 - C2 IP Addresses
**Objective:** Find the two IPs resolving to attacker infrastructure.

**Why It Matters:** Both are Cloudflare-fronted proxies masking the real origin. Enables firewall blocking and intelligence correlation.

`T1071 Application Layer Protocol` `DeviceNetworkEvents` `Network Analysis`

```kql
// Summarize IPs contacted by the C2 implant
DeviceNetworkEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where RemoteUrl contains "cloud-endpoint"
| summarize Domains=make_set(RemoteUrl) by RemoteIP
```

> 💡 Two IPs appear - submit comma separated in any order.

---

#### Q8 - Remote Tool Relay Domain
**Objective:** Find the specific AnyDesk relay domain used during the attack.

**Why It Matters:** Confirms which session was active during the intrusion and enables blocking of that specific relay.

`T1219 Remote Access Software` `DeviceNetworkEvents` `Infrastructure Analysis`

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

> 💡 Multiple relay subdomains appear - find the one active on `as-srv` during the attack window.

---

### 🛡️ SECTION 3: Defense Evasion

#### Q9 - Evasion Script
**Objective:** Identify the script used to disable security controls.

**Why It Matters:** The script disabled multiple Defender components and modified the registry - created by the C2 implant before ransomware deployment.

`T1562.001 Impair Defenses` `DeviceFileEvents` `Defense Evasion`

```kql
// Find script files created by suspicious processes in ProgramData
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by TimeGenerated asc
```

> 💡 The evasion script was created on the initial workstation, not the server. Look at `InitiatingProcessFileName` - scripts created by suspicious processes stand out.

---

#### Q10 - Evasion Script Hash
**Objective:** Get the SHA256 of the evasion script.

**Why It Matters:** Enables threat intelligence correlation and detection rule creation.

`T1562.001 Impair Defenses` `DeviceFileEvents` `Malware Identification`

> 💡 Same query as Q9 - the `SHA256` column on the `kill.bat` row is your answer.

---

#### Q11 - Registry Tampering
**Objective:** Find the registry value used to disable Windows Defender.

**Why It Matters:** A policy registry change that survives reboots - more persistent than a process-level disable.

`T1112 Modify Registry` `DeviceRegistryEvents` `Defense Evasion`

```kql
// Find registry modifications to Windows Defender policy keys
DeviceRegistryEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where RegistryKey contains "Windows Defender"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

> 💡 The `RegistryValueName` column is your answer.

---

#### Q12 - Registry Timestamp
**Objective:** Find the exact UTC time the registry was modified.

**Why It Matters:** Anchors the defense evasion phase - this timestamp also helps find Q36.

`T1112 Modify Registry` `DeviceRegistryEvents` `Timeline Analysis`

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

> 💡 Format `TimeGenerated` as `HH:MM:SS` UTC - drop the date and milliseconds.

---

### 🔑 SECTION 4: Credential Access

#### Q13 - Process Hunt
**Objective:** Find the command used to enumerate processes for credential theft.

**Why It Matters:** Classic pre-dump step - attacker locates `lsass.exe` before memory extraction.

`T1003.001 LSASS Memory` `DeviceProcessEvents` `Credential Access`

```kql
// Find process enumeration commands targeting lsass
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ProcessCommandLine contains "lsass"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

> 💡 Submit the exact command shown in `ProcessCommandLine`.

---

#### Q14 - Credential Pipe
**Objective:** Find the named pipe accessed during credential theft.

**Why It Matters:** Identifies the credential dumping method and provides a detection opportunity.

`T1003.001 LSASS Memory` `DeviceEvents` `Credential Access`

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

> 💡 The `PipeName` field contains the full pipe path. Submit the exact value.

---

### 🚪 SECTION 5: Initial Access

#### Q15 - Remote Access Tool
**Objective:** Identify the remote access tool used to re-enter the environment.

**Why It Matters:** Pre-staged during "The Broker" - the attacker returned months later using this foothold, demonstrating the risk of incomplete remediation.

`T1219 Remote Access Software` `DeviceProcessEvents` `Initial Access`

```kql
// Find remote access tools running from unusual locations on attack day
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FolderPath contains "Public"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```

> 💡 The unusual `FolderPath` is the red flag - the `FileName` is your answer.

---

#### Q16 - Suspicious Execution Path
**Objective:** Identify the unusual directory the tool ran from.

**Why It Matters:** World-writable location - no admin privileges required, ideal for persistence.

`T1219 Remote Access Software` `DeviceFileEvents` `Persistence Analysis`

```kql
// Find where the remote access tool was installed during The Broker
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-16))
| where ActionType == "FileCreated"
| where FileName contains "AnyDesk"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

> 💡 The `FolderPath` column minus the filename is your answer.

---

#### Q17 - Attacker External IP
**Objective:** Identify the attacker's real external IP.

**Why It Matters:** Enables perimeter blocking and threat intelligence sharing.

`T1219 Remote Access Software` `DeviceNetworkEvents` `Network Analysis`

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

> 💡 The IP appearing most consistently is the attacker's real external IP.

---

#### Q18 - Compromised User
**Objective:** Identify the compromised account on AS-PC2.

**Why It Matters:** Enables immediate credential reset and scope assessment.

`T1078 Valid Accounts` `DeviceLogonEvents` `Identity Analysis`

```kql
// Find successful remote logons to AS-PC2 on attack day
DeviceLogonEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
| order by TimeGenerated asc
```

> 💡 The `AccountName` column is your answer.

---

### 📡 SECTION 6: Command & Control

#### Q19 - Primary C2 Beacon
**Objective:** Identify the C2 beacon deployed after the previous one failed.

**Why It Matters:** Primary implant establishing C2 communications blending in with normal HTTPS traffic.

`T1071 Application Layer Protocol` `DeviceFileEvents` `Malware Identification`

```kql
// Find suspicious executables created in ProgramData
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by TimeGenerated asc
```

> 💡 The beacon appears multiple times - created, stopped, recreated. The `FileName` is your answer.

---

#### Q20 - Beacon Deployment Location
**Objective:** Identify where the beacon was deployed.

`T1071 Application Layer Protocol` `DeviceFileEvents` `Malware Identification`

> 💡 Same query as Q19 - the `FolderPath` column minus the filename is your answer.

---

#### Q21 - Original Beacon Hash
**Objective:** Find the SHA256 of the first beacon deployment.

**Why It Matters:** Enables detection signature creation and correlation with other Akira campaigns.

`T1071 Application Layer Protocol` `DeviceFileEvents` `Malware Identification`

```kql
// Find all versions of the beacon created on AS-PC2
DeviceFileEvents
| where DeviceName == "as-pc2"
| where ActionType == "FileCreated"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

> 💡 The **first row** is the original beacon - its `SHA256` is your answer.

---

#### Q22 - Replacement Beacon Hash
**Objective:** Find the SHA256 of the replacement beacon.

**Why It Matters:** Different hash confirms the attacker actively managed C2 - deploying a more stable variant.

`T1071 Application Layer Protocol` `DeviceFileEvents` `Malware Identification`

```kql
// Find the replacement beacon
DeviceFileEvents
| where DeviceName == "as-pc2"
| where ActionType == "FileModified"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

> 💡 The replacement appears as a `FileModified` event - its `SHA256` is your answer.

---

### 🔭 SECTION 7: Reconnaissance

#### Q23 - Scanner Tool
**Objective:** Identify the network scanner deployed.

**Why It Matters:** Used to map internal hosts for lateral movement targeting.

`T1046 Network Service Scanning` `DeviceFileEvents` `Discovery`

```kql
// Find scanning tools downloaded on attack day
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FolderPath contains "Downloads"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

> 💡 The `FileName` column is your answer.

---

#### Q24 - Scanner Hash
**Objective:** Get the SHA256 of the scanner.

`T1046 Network Service Scanning` `DeviceFileEvents` `Malware Identification`

> 💡 Same query as Q23 - the `SHA256` column on the scanner row is your answer.

---

#### Q25 - Scanner Execution Arguments
**Objective:** Find the arguments passed to the scanner.

**Why It Matters:** Portable mode leaves no installation footprint - deliberate evasion.

`T1046 Network Service Scanning` `DeviceProcessEvents` `Discovery`

```kql
// Find how the scanner was executed
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName == "scan.exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

> 💡 Everything in `ProcessCommandLine` after the filename is your answer.

---

#### Q26 - Network Share Enumeration
**Objective:** Find the two internal IPs where shares were enumerated.

**Why It Matters:** Goal-oriented data targeting - attacker identifying specific exfiltration targets.

`T1135 Network Share Discovery` `DeviceProcessEvents` `Discovery`

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

> 💡 The `ProcessCommandLine` shows the targeted IPs - submit both comma separated.

---

### 🔀 SECTION 8: Lateral Movement

#### Q27 - Lateral Account
**Objective:** Find the account used to access AS-SRV.

**Why It Matters:** Account was obtained from the LSASS dump - demonstrating the cascading impact of credential theft.

`T1021.001 Remote Desktop` `DeviceLogonEvents` `Lateral Movement`

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

> 💡 The `AccountName` column is your answer.

---

### ⬇️ SECTION 9: Tool Transfer

#### Q28 - First Download Method
**Objective:** Find the first LOLBin used to download tools.

**Why It Matters:** Native Windows binary abused to bypass security tools that trust system binaries.

`T1105 Ingress Tool Transfer` `DeviceProcessEvents` `Tool Transfer`

```kql
// Find LOLBin download activity
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName has_any ("bitsadmin.exe", "certutil.exe", "mshta.exe", "wscript.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

> 💡 The `FileName` at the earliest timestamp is your answer.

---

#### Q29 - Fallback Download Method
**Objective:** Find the PowerShell cmdlet used when the first method failed.

**Why It Matters:** Three obfuscation techniques used - base64, string concat, variable splitting - showing attacker adaptability.

`T1059.001 PowerShell` `DeviceEvents` `Tool Transfer`

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

> 💡 The alias `IWR` in `AdditionalFields` stands for the full cmdlet name - that's your answer.

---

### 📦 SECTION 10: Exfiltration

#### Q30 - Staging Tool
**Objective:** Find the tool used to compress data before exfiltration.

**Why It Matters:** Double-extortion tactic - stolen data gives the attacker two points of leverage.

`T1560 Archive Collected Data` `DeviceFileEvents` `Exfiltration`

```kql
// Find compression tools created in ProgramData
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FolderPath contains "ProgramData"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by TimeGenerated asc
```

> 💡 Look for a short, non-descriptive executable - that's the staging tool.

---

#### Q31 - Staging Tool Hash
**Objective:** Get the SHA256 of the staging tool.

`T1560 Archive Collected Data` `DeviceFileEvents` `Malware Identification`

> 💡 Same query as Q30 - the `SHA256` on the staging tool row is your answer.

---

#### Q32 - Exfiltration Archive
**Objective:** Find the archive created for exfiltration.

**Why It Matters:** Identifying the archive enables scope assessment of stolen data.

`T1560 Archive Collected Data` `DeviceFileEvents` `Exfiltration`

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

> 💡 The `FileName` column is your answer.

---

### 💣 SECTION 11: Ransomware Deployment

#### Q33 - Ransomware Filename
**Objective:** Find the ransomware binary disguised as a legitimate process.

**Why It Matters:** Masquerading as a system utility avoids suspicion from users and monitoring tools.

`T1036 Masquerading` `DeviceFileEvents` `Impact Analysis`

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

> 💡 Look for an executable mimicking a legitimate Windows process name.

---

#### Q34 - Ransomware Hash
**Objective:** Get the SHA256 of the ransomware binary.

`T1486 Data Encrypted` `DeviceFileEvents` `Malware Identification`

> 💡 Same query as Q33 - the `SHA256` on the ransomware row is your answer.

---

#### Q35 - Ransomware Staging Process
**Objective:** Find the process that staged the ransomware on AS-SRV.

**Why It Matters:** Confirms the C2 delivery method and provides a future detection opportunity.

`T1059.001 PowerShell` `DeviceFileEvents` `Impact Analysis`

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

> 💡 The `InitiatingProcessFileName` on the ransomware row is your answer.

---

#### Q36 - Recovery Prevention
**Objective:** Find the command used to delete Volume Shadow Copies.

**Why It Matters:** Prevents file restoration without paying ransom - standard pre-encryption step.

`T1490 Inhibit System Recovery` `DeviceProcessEvents` `Impact Analysis`

```kql
// Look at what ran in the defense evasion window (use Q12 timestamp as anchor)
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27T21:00:00Z) .. datetime(2026-01-27T21:15:00Z))
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

> 💡 The recovery prevention command stands out in the `ProcessCommandLine` column.

---

#### Q37 - Ransom Note Origin
**Objective:** Find the process that dropped the ransom note.

**Why It Matters:** Confirms the exact binary responsible for encryption and notification.

`T1486 Data Encrypted` `DeviceFileEvents` `Impact Analysis`

```kql
// Find what process created the ransom note files
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FileName contains "akira"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by TimeGenerated asc
```

> 💡 The `InitiatingProcessFileName` column is your Q37 answer.

---

#### Q38 - Encryption Start Time
**Objective:** Determine when encryption began.

**Why It Matters:** Anchors the impact phase - critical for recovery team prioritization.

`T1486 Data Encrypted` `DeviceFileEvents` `Timeline Analysis`

> 💡 Same query as Q37 - `TimeGenerated` of the **first row** is your answer. Format as `HH:MM:SS` UTC.

---

### 🧹 SECTION 12: Anti-Forensics & Scope

#### Q39 - Cleanup Script
**Objective:** Find the script that deleted the ransomware binary.

**Why It Matters:** Deliberate anti-forensics - prevents recovery and analysis of the ransomware sample.

`T1485 Data Destruction` `DeviceFileEvents` `Anti-Forensics`

```kql
// Find what deleted files after encryption
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileDeleted"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where InitiatingProcessCommandLine contains ".bat"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

> 💡 The `InitiatingProcessCommandLine` reveals the cleanup script name.

---

#### Q40 - Affected Hosts
**Objective:** Determine the full scope of compromised hosts.

**Why It Matters:** Ensures no affected systems are missed during remediation.

`T1486 Data Encrypted` `DeviceFileEvents` `Scope Analysis`

```kql
// Find all hosts where ransom notes were dropped
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName contains "readme"
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| summarize count() by DeviceName
| order by count_ desc
```

> 💡 Every host with a ransom note was encrypted. Submit all hostnames comma separated.

---

## 🔑 Key IOCs

| Type | Value |
|------|-------|
| Malicious Domain | `sync.cloud-endpoint.net` |
| Malicious Domain | `cdn.cloud-endpoint.net` |
| C2 IP | `104.21.30.237` |
| C2 IP | `172.67.174.46` |
| Attacker External IP | `88.97.164.155` |
| C2 Beacon (original) | `wsync.exe` - `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` |
| C2 Beacon (replacement) | `wsync.exe` - `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` |
| Ransomware Binary | `updater.exe` - `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` |
| Persistence Tool | `AnyDesk.exe` - `C:\Users\Public\AnyDesk.exe` |
| AnyDesk Relay | `relay-0b975d23.net.anydesk.com` |
| Evasion Script | `kill.bat` - `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` |
| Cleanup Script | `clean.bat` - `C:\ProgramData\clean.bat` |
| Staging Tool | `st.exe` - `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` |
| Exfil Archive | `exfil_data.zip` |
| Scanner Tool | `scan.exe` - `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` |
| Compromised Account | `david.mitchell` |
| Compromised Account | `as.srv.administrator` |
| TOR Address | `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` |
| Victim ID | `813R-QWJM-XKIJ` |

---

## 💠 Diamond Model

| Feature | Details |
|---------|---------|
| **Adversary** | Akira ransomware affiliate - hands-on-keyboard, patient, multi-phase. Re-used pre-staged access from a prior intrusion. |
| **Infrastructure** | `sync.cloud-endpoint.net`, `cdn.cloud-endpoint.net` (Cloudflare-fronted). Relay: `relay-0b975d23.net.anydesk.com`. Attacker IP: `88.97.164.155`. |
| **Capability** | `wsync.exe` C2, AnyDesk persistence, LSASS dumping, network scanning, defense evasion, data staging, Akira ransomware, anti-forensics cleanup. |
| **Victim** | Entry: AS-PC2 (`david.mitchell`). Lateral: AS-SRV (`as.srv.administrator`). Encrypted: AS-PC2, AS-SRV. Shares: Clients, Payroll, Compliance, Contractors, Backups. |

---

## LESSONS_LEARNED

**Incomplete Remediation Enables Return Attacks** - Pre-staged AnyDesk from "The Broker" directly enabled this intrusion months later.

**Obfuscation Defeats Signature Detection** - Three download methods for a single payload; behavioral monitoring is essential.

**Legitimate Tools Are the Weapon** - AnyDesk, bitsadmin, net.exe, wmic. LOLBin monitoring is non-negotiable.

**3-Hour Window from Entry to Encryption** - Speed of execution leaves minimal time for detection and response.

**Credential Theft Has Long-Term Consequences** - Harvested credentials reused for lateral movement weeks later.

---

## REMEDIATION_ACTIONS

**Immediate** - Isolate AS-PC2 and AS-SRV · Reset `david.mitchell` and `as.srv.administrator` credentials · Remove `C:\Users\Public\AnyDesk.exe` · Block `sync.cloud-endpoint.net`, `cdn.cloud-endpoint.net`, `88.97.164.155`

**Short Term** - Restrict remote tools to approved list · Enable PowerShell Script Block Logging · Alert on LOLBin network activity · Monitor Defender registry keys · Hunt for unknown executables in `C:\ProgramData\`

**Long Term** - MFA for all RDP · Network segmentation · Honeypot files in shares · Full remediation review of "The Broker" · Immutable off-site backups · Application allowlisting

---

*SancLogic Cyber Range - The Buyer | MDE + Sentinel (KQL)*
