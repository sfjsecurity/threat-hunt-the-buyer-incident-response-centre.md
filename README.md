# Threat Hunt Report: The Buyer
### Ashford Sterling Recruitment — Akira Ransomware Investigation

**Analyst:** Sana Jafferi
**Date Completed:** 2026-03-16
**Environment Investigated:** AS-PC1, AS-PC2, AS-SRV
**Timeframe:** January 15 – January 28, 2026
**Platform:** Microsoft Defender for Endpoint + Microsoft Sentinel

---

## 🧠 Scenario Overview

Following the initial compromise investigated in *"The Broker"*, a ransomware affiliate returned to the environment using pre-staged access. The threat actor leveraged dormant persistence mechanisms from the first intrusion — specifically a pre-installed AnyDesk instance — and re-entered the network through a compromised user account. The attacker deployed a new C2 beacon, disabled security controls, harvested credentials, performed network reconnaissance, moved laterally to the file server, exfiltrated compressed data, and ultimately deployed **Akira ransomware** across two hosts.

> ⚠️ All queries are written for **Microsoft Sentinel** using `TimeGenerated`. For MDE Advanced Hunting, replace `TimeGenerated` with `Timestamp`.

---

## 🎯 Executive Summary

The investigation revealed a multi-stage intrusion spanning two weeks. The threat actor re-entered the environment via pre-staged **AnyDesk** remote access (password: `intrud3r!`) installed during the prior "The Broker" compromise. Using the account `david.mitchell` on **AS-PC2**, the attacker deployed a new C2 implant (`wsync.exe`), disabled Windows Defender via script and registry tampering, dumped LSASS credentials, scanned the internal network, moved laterally to **AS-SRV**, exfiltrated compressed data archives, and finally deployed **Akira ransomware** (`updater.exe`). After encryption, the ransomware binary was deleted via a cleanup script to hinder forensic recovery.

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

#### Q1 – Threat Actor
**Objective:** Identify the ransomware group from the ransom note.

**Identified Group:** `Akira`

**Why It Matters:** The ransom note (`akira_readme.txt`) dropped on the file server explicitly identified the Akira ransomware group. Akira is a ransomware-as-a-service (RaaS) operation known for double extortion — encrypting files while threatening to publish stolen data if the ransom is not paid.

```kql
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where FileName contains "akira"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc
```

---

#### Q2 – Negotiation Portal
**Objective:** Find the TOR address from the ransom note.

**Identified Address:** `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`

**Why It Matters:** The TOR onion address provides the victim a channel to communicate and negotiate with the attacker. Documenting this is critical for threat intelligence sharing, law enforcement reporting, and tracking the specific Akira affiliate responsible.

> ⚠️ Note: The address contains lowercase `l` characters that visually resemble the number `1` — always copy-paste TOR addresses rather than retyping them.

---

#### Q3 – Victim ID
**Objective:** Find the unique victim identifier assigned by Akira.

**Identified ID:** `813R-QWJM-XKIJ`

**Why It Matters:** Each victim receives a unique ID used to identify them in the attacker's negotiation portal. This ID confirms the specific ransomware campaign and can be used to correlate intelligence with other Akira victims.

---

#### Q4 – Encrypted Extension
**Objective:** Identify the file extension appended to encrypted files.

**Identified Extension:** `.akira`

**Why It Matters:** All encrypted files received the `.akira` extension, confirming the ransomware variant and enabling scope assessment of impacted files across the environment.

```kql
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FileName endswith ".akira"
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc
```

---

### 🌐 SECTION 2: Infrastructure

#### Q5 – Payload Domain
**Objective:** Find the domain that hosted attacker tools.

**Identified Domain:** `sync.cloud-endpoint.net`

**Why It Matters:** This attacker-controlled domain hosted all major tooling including `wsync.exe`, `scan.exe`, and `kill.bat`. The attacker used multiple obfuscated PowerShell download cradles — base64 encoding, string concatenation, and variable splitting — to evade string-based detection while downloading from this domain.

```kql
search in (DeviceProcessEvents) "sync.cloud-endpoint.net"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q6 – Ransomware Staging Domain
**Objective:** Find the separate domain used to stage the ransomware.

**Identified Domain:** `cdn.cloud-endpoint.net`

**Why It Matters:** The attacker used a separate subdomain for ransomware staging, demonstrating disciplined infrastructure separation — a hallmark of organized ransomware affiliates. This separation makes attribution and blocking more complex.

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "wsync.exe"
| where RemoteUrl != ""
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, RemotePort
| order by TimeGenerated asc
```

---

#### Q7 – C2 IP Addresses
**Objective:** Find the two IPs resolving to attacker infrastructure.

**Identified IPs:** `104.21.30.237, 172.67.174.46`

**Why It Matters:** Both IPs are Cloudflare-fronted proxies used to mask the real origin server. Both `sync.cloud-endpoint.net` and `cdn.cloud-endpoint.net` resolved to these same IPs, confirming shared backend attacker infrastructure.

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "wsync.exe"
| where RemoteIP != ""
| summarize Domains=make_set(RemoteUrl) by RemoteIP
```

---

#### Q8 – Remote Tool Relay Domain
**Objective:** Find the specific AnyDesk relay domain used during the attack.

**Identified Domain:** `relay-0b975d23.net.anydesk.com`

**Why It Matters:** AnyDesk was pre-staged during "The Broker" intrusion and reused here for persistent remote access. The specific relay domain was identified by filtering `DeviceNetworkEvents` for AnyDesk process connections on the attack date, confirming which session was active during the intrusion window.

```kql
DeviceNetworkEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where InitiatingProcessFileName =~ "anydesk.exe"
| where RemoteUrl contains "relay"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP
| order by TimeGenerated asc
```

---

### 🛡️ SECTION 3: Defense Evasion

#### Q9 – Evasion Script
**Objective:** Identify the script used to disable security controls.

**Identified Script:** `kill.bat`

**Why It Matters:** `kill.bat` was created by `wsync.exe` at `C:\ProgramData\kill.bat` and executed via `cmd.exe`. The script disabled multiple Windows Defender components using `Set-MpPreference` commands and modified the registry to permanently disable antivirus protection — clearing the path for ransomware deployment.

```kql
DeviceFileEvents
| where FileName == "kill.bat"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

#### Q10 – Evasion Script Hash
**Objective:** Get the SHA256 of `kill.bat`.

**Identified Hash:** `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`

**Why It Matters:** The hash enables threat intelligence correlation with other Akira affiliate campaigns and supports the creation of detection rules across security tools.

---

#### Q11 – Registry Tampering
**Objective:** Find the registry value used to disable Windows Defender.

**Identified Value:** `DisableAntiSpyware`

**Why It Matters:** The attacker modified `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` to value `1`, fully disabling antivirus protection via Group Policy registry override — a persistent change that survives process restarts and reboots.

```kql
DeviceRegistryEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where RegistryKey contains "Windows Defender"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

---

#### Q12 – Registry Modification Timestamp
**Objective:** Determine the exact UTC time the registry was modified.

**Identified Time:** `21:03:42`

**Why It Matters:** This timestamp anchors the defense evasion phase in the attack timeline, occurring approximately one hour before ransomware deployment — confirming the deliberate sequencing of the attack.

```kql
DeviceRegistryEvents
| where DeviceName == "as-pc2"
| where RegistryValueName == "DisableAntiSpyware"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName
| order by TimeGenerated asc
```

---

### 🔑 SECTION 4: Credential Access

#### Q13 – Process Hunt
**Objective:** Find the command used to enumerate processes for credential theft.

**Identified Command:** `tasklist | findstr lsass`

**Why It Matters:** The attacker used `tasklist | findstr lsass` via `cmd.exe` to enumerate running processes and locate `lsass.exe` — the Windows Local Security Authority Subsystem Service. This is a classic pre-credential-dump reconnaissance step to confirm LSASS is running and identify its process ID before memory extraction.

```kql
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ProcessCommandLine contains "lsass"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q14 – Credential Pipe
**Objective:** Find the named pipe accessed during credential theft activity.

**Identified Pipe:** `\Device\NamedPipe\lsass`

**Why It Matters:** The named pipe `\Device\NamedPipe\lsass` was accessed during LSASS memory extraction. Named pipes are used internally by credential dumping tools to communicate between processes during memory reads. This confirms the attacker used a tool to extract credential material from LSASS.

```kql
DeviceEvents
| where ActionType == "NamedPipeEvent"
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
| where PipeName contains "lsass"
| project TimeGenerated, DeviceName, PipeName, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

### 🚪 SECTION 5: Initial Access

#### Q15 – Remote Access Tool
**Objective:** Identify the remote access tool used to re-enter the environment.

**Identified Tool:** `AnyDesk`

**Why It Matters:** AnyDesk was pre-staged during "The Broker" intrusion and left running at `C:\Users\Public\AnyDesk.exe` with the password `intrud3r!`. The attacker leveraged this pre-staged access to re-enter the environment weeks later without needing to re-exploit — demonstrating the risk of incomplete remediation after an initial breach.

```kql
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where FileName == "AnyDesk.exe"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q16 – Suspicious Execution Path
**Objective:** Identify the unusual directory AnyDesk was running from.

**Identified Path:** `C:\Users\Public`

**Why It Matters:** AnyDesk was deliberately placed in `C:\Users\Public\` rather than its standard installation directory. This location is world-writable and accessible to all users, making it an ideal staging location for persistence tools — no admin privileges required to execute from this path.

```kql
DeviceFileEvents
| where FileName == "AnyDesk.exe"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

#### Q17 – Attacker External IP
**Objective:** Identify the attacker's external IP address.

**Identified IP:** `88.97.164.155`

**Why It Matters:** This IP appeared consistently in AnyDesk network connections from AS-PC2 during the attack window — including multiple connections at 7:29 PM and 8:12 PM on January 27. This represents the attacker's real external IP routing through the AnyDesk relay infrastructure.

```kql
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName =~ "anydesk.exe"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl
| order by TimeGenerated asc
```

---

#### Q18 – Compromised User
**Objective:** Identify the user account that was compromised on AS-PC2.

**Identified User:** `david.mitchell`

**Why It Matters:** `david.mitchell` was the active user session on AS-PC2 during the intrusion. This account was used for all attacker activity on the primary attack host, including downloading tools, disabling security controls, and dumping credentials. The account was likely compromised via credential theft during "The Broker" intrusion.

```kql
DeviceLogonEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
| order by TimeGenerated asc
```

---

### 📡 SECTION 6: Command & Control

#### Q19 – Primary C2 Beacon
**Objective:** Identify the new C2 beacon deployed after the previous one failed.

**Identified Beacon:** `wsync.exe`

**Why It Matters:** `wsync.exe` was the primary C2 implant for this intrusion, deployed to `C:\ProgramData\wsync.exe`. It established persistent outbound communications to `sync.cloud-endpoint.net` on ports 443 and 80 — blending in with normal HTTPS/HTTP traffic. The original beacon from "The Broker" (`RuntimeBroker.exe`) had failed to maintain stable communications, prompting the attacker to deploy this replacement.

```kql
DeviceFileEvents
| where FileName == "wsync.exe"
| where ActionType == "FileCreated"
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

#### Q20 – Beacon Deployment Location
**Objective:** Identify where the C2 beacon was deployed.

**Identified Path:** `C:\ProgramData`

**Why It Matters:** `C:\ProgramData` is a common attacker staging location — it is accessible to all users, not typically monitored by default, and blends in with legitimate application data. Placing malware here reduces suspicion compared to user-specific directories.

---

#### Q21 – Original Beacon Hash
**Objective:** Find the SHA256 of the original `wsync.exe` deployment.

**Identified Hash:** `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`

**Why It Matters:** The first version of `wsync.exe` was deployed at 8:22 PM but failed or was replaced. Having the original hash allows defenders to create detection signatures and correlate this binary with other Akira affiliate intrusions.

```kql
DeviceFileEvents
| where FileName == "wsync.exe"
| where DeviceName == "as-pc2"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

#### Q22 – Replacement Beacon Hash
**Objective:** Find the SHA256 of the replacement `wsync.exe`.

**Identified Hash:** `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`

**Why It Matters:** A second version of `wsync.exe` was deployed at 8:44 PM to replace the failed original. The different hash confirms the attacker actively managed their C2 infrastructure — potentially deploying a more stable or updated implant variant.

```kql
DeviceFileEvents
| where FileName == "wsync.exe"
| where DeviceName == "as-pc2"
| where ActionType in ("FileCreated", "FileModified")
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

### 🔭 SECTION 7: Reconnaissance

#### Q23 – Scanner Tool
**Objective:** Identify the network scanner deployed by the attacker.

**Identified Tool:** `scan.exe`

**Why It Matters:** `scan.exe` was downloaded from `sync.cloud-endpoint.net` via bitsadmin and placed in `C:\Users\David.Mitchell\Downloads\`. It was used to map the internal network and identify live hosts — feeding the attacker intelligence for lateral movement targeting.

```kql
DeviceFileEvents
| where SHA256 == "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

#### Q24 – Scanner Hash
**Objective:** Get the SHA256 of the scanner tool.

**Identified Hash:** `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`

---

#### Q25 – Scanner Execution Arguments
**Objective:** Find the arguments passed to the scanner on execution.

**Identified Arguments:** `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`

**Why It Matters:** The scanner was executed in portable mode from David Mitchell's Downloads folder. Running in portable mode leaves no installation footprint — no registry entries, no start menu shortcuts — making detection and forensic recovery more difficult.

```kql
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where FileName == "scan.exe"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q26 – Network Share Enumeration
**Objective:** Find the two internal IPs where network shares were enumerated.

**Identified IPs:** `10.1.0.154, 10.1.0.183`

**Why It Matters:** From AS-SRV, the attacker ran `net view` against AS-PC1 (`10.1.0.154`) and AS-PC2 (`10.1.0.183`) to enumerate accessible network shares — identifying data targets for exfiltration. This confirms deliberate, goal-oriented lateral reconnaissance rather than opportunistic scanning.

```kql
search in (DeviceProcessEvents) "\\\\10.1.0"
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🔀 SECTION 8: Lateral Movement

#### Q27 – Lateral Movement Account
**Objective:** Find the account used to access AS-SRV.

**Identified Account:** `as.srv.administrator`

**Why It Matters:** The attacker authenticated to AS-SRV using the local administrator account via RemoteInteractive (RDP) from relay IP `10.0.8.6`. These credentials were almost certainly obtained from the LSASS memory dump performed on AS-PC2 earlier in the attack chain — demonstrating the cascading impact of credential theft.

```kql
DeviceLogonEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
| order by TimeGenerated asc
```

---

### ⬇️ SECTION 9: Tool Transfer

#### Q28 – First Download Method (LOLBIN)
**Objective:** Find the first living-off-the-land binary used to download tools.

**Identified Tool:** `bitsadmin.exe`

**Why It Matters:** `bitsadmin.exe` is a native Windows binary that leverages the Background Intelligent Transfer Service (BITS) to silently download files. The attacker used it to download `scan.exe`, `wsync.exe`, and `kill.bat` from `sync.cloud-endpoint.net`. However, `bitsadmin` encountered issues downloading `wsync.exe`, prompting a fallback to PowerShell.

```kql
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FileName == "bitsadmin.exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q29 – Fallback Download Method
**Objective:** Find the PowerShell cmdlet used as a fallback download method.

**Identified Cmdlet:** `Invoke-WebRequest`

**Why It Matters:** When `bitsadmin` failed, the attacker switched to PowerShell's `Invoke-WebRequest` (aliased as `IWR`). Three different obfuscation techniques were used to evade detection: base64 encoding, string concatenation, and variable splitting — all resolving to the same download URL.

```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where AdditionalFields contains "WebRequest"
| project TimeGenerated, DeviceName, AdditionalFields
| order by TimeGenerated asc
```

---

### 📦 SECTION 10: Exfiltration

#### Q30 – Staging Tool
**Objective:** Find the tool used to compress data for exfiltration.

**Identified Tool:** `st.exe`

**Why It Matters:** `st.exe` was deployed by `wsync.exe` to `C:\ProgramData\st.exe` and used to create a compressed archive of sensitive data prior to exfiltration. This staging step is common in double-extortion ransomware attacks — data is stolen and compressed before encryption to maximize leverage over the victim.

```kql
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FolderPath contains "ProgramData"
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

#### Q31 – Staging Tool Hash
**Identified Hash:** `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`

---

#### Q32 – Exfiltration Archive
**Identified Archive:** `exfil_data.zip`

**Why It Matters:** The archive consolidated stolen data — including files from `C:\Shares\` (Clients, Payroll, Compliance, Contractors) — before transmission. Identifying the filename and hash enables recovery teams to assess the full scope of data loss.

```kql
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ActionType == "FileCreated"
| where FileName has_any (".zip", ".7z", ".rar")
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

---

### 💣 SECTION 11: Ransomware Deployment

#### Q33 – Ransomware Filename
**Objective:** Find the ransomware binary disguised as a legitimate process.

**Identified File:** `updater.exe`

**Why It Matters:** The Akira ransomware binary was disguised as a software updater — a common masquerading technique to avoid suspicion from users and automated monitoring tools. It was deployed to `C:\ProgramData\updater.exe` on AS-SRV via PowerShell.

```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where ActionType == "FileCreated"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where FolderPath contains "ProgramData"
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

#### Q34 – Ransomware Hash
**Identified Hash:** `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`

---

#### Q35 – Ransomware Staging Process
**Objective:** Find the process that staged the ransomware on AS-SRV.

**Identified Process:** `powershell.exe`

**Why It Matters:** PowerShell was used to download and write `updater.exe` to disk on AS-SRV, confirming the C2 implant (`wsync.exe`) used PowerShell as its execution engine for staging and deploying the ransomware binary.

```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where FileName == "updater.exe"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q36 – Recovery Prevention
**Objective:** Find the command used to delete Volume Shadow Copies.

**Identified Command:** `wmic shadowcopy delete`

**Why It Matters:** Deleting Volume Shadow Copies prevents victims from restoring encrypted files without paying the ransom. This is standard pre-encryption activity in modern ransomware deployments and is executed as part of `kill.bat` prior to encryption.

```kql
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-01-28))
| where ProcessCommandLine contains "shadowcopy"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q37 – Ransom Note Origin
**Objective:** Find the process that dropped the ransom note.

**Identified Process:** `updater.exe`

**Why It Matters:** The ransomware binary itself dropped `akira_readme.txt` across multiple directories simultaneously as part of the encryption routine. This confirms automated note deployment and anchors the encryption start time.

```kql
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where FileName contains "akira_readme"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

#### Q38 – Encryption Start Time
**Objective:** Determine when encryption began.

**Identified Time (UTC):** `22:18:33`

**Why It Matters:** The first `akira_readme.txt` was dropped at 22:18:33 UTC on January 27, 2026 — marking the precise start of encryption. This timestamp is the critical anchor point for the impact phase of the incident timeline and informs recovery team prioritization.

---

### 🧹 SECTION 12: Anti-Forensics & Scope

#### Q39 – Cleanup Script
**Objective:** Find the script that deleted the ransomware binary after execution.

**Identified Script:** `clean.bat`

**Why It Matters:** After encryption completed, `cmd.exe /c C:\ProgramData\clean.bat` deleted `updater.exe` to remove the ransomware binary from disk. This deliberate anti-forensics measure was designed to hinder incident responders from recovering and analyzing the ransomware sample.

```kql
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where FileName == "updater.exe"
| where ActionType == "FileDeleted"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

#### Q40 – Affected Hosts
**Objective:** Determine the full scope of compromised hosts.

**Identified Hosts:** `as-pc2, as-srv`

**Why It Matters:** Ransomware was deployed and executed on two hosts. AS-PC2 was the primary attack host (initial access and credential theft) while AS-SRV was the high-value target (file server with sensitive share data). AS-PC1 was used for initial AnyDesk staging but was not encrypted.

```kql
DeviceFileEvents
| where FileName contains "akira"
| where ActionType == "FileCreated"
| summarize count() by DeviceName
| order by count_ desc
```

---

## 🔍 Attack Timeline

| Timestamp (UTC) | Event | Device | Details |
|----------------|-------|--------|---------|
| 2026-01-15 04:08 | AnyDesk downloaded | AS-PC1 | `certutil` downloads from `download.anydesk.com` |
| 2026-01-15 04:10 | AnyDesk installed & password set | AS-PC1 | Password: `intrud3r!`, path: `C:\Users\Public\AnyDesk.exe` |
| 2026-01-15 04:41 | AnyDesk deployed to AS-PC2 | AS-PC2 | Lateral deployment via WMI/PsExec |
| 2026-01-15 04:57 | AnyDesk deployed to AS-SRV | AS-SRV | Full environment coverage |
| 2026-01-15 04:52 | Credentials dumped (The Broker) | AS-PC2 | SAM/SYSTEM hives saved to `C:\Users\Public\` |
| 2026-01-27 19:14 | Attacker re-enters via AnyDesk | AS-PC2 | `david.mitchell` logon from `10.0.8.5` |
| 2026-01-27 19:15 | AnyDesk session established | AS-PC2 | Relay: `relay-0b975d23.net.anydesk.com`, attacker IP: `88.97.164.155` |
| 2026-01-27 20:17 | `scan.exe` downloaded and executed | AS-PC2 | Network scanner run from Downloads folder |
| 2026-01-27 20:22 | Original `wsync.exe` deployed | AS-PC2 | C2 implant dropped to `C:\ProgramData\` |
| 2026-01-27 20:42 | `wsync.exe` re-downloaded (obfuscated) | AS-PC2 | Three obfuscated PowerShell download attempts |
| 2026-01-27 20:44 | Replacement `wsync.exe` deployed | AS-PC2 | New beacon hash deployed |
| 2026-01-27 20:45 | LSASS memory dumped | AS-PC2 | `powershell.exe` reads LSASS — 25,864 bytes |
| 2026-01-27 21:00 | `tasklist \| findstr lsass` run | AS-PC2 | Process enumeration confirming LSASS target |
| 2026-01-27 21:03 | Defender disabled via `kill.bat` | AS-PC2 | Multiple `Set-MpPreference` + registry tampering |
| 2026-01-27 21:03 | VSS deleted | AS-PC2 | `wmic shadowcopy delete` prevents recovery |
| 2026-01-27 21:17 | Network scan performed | AS-PC2 | `scan.exe` maps `10.1.x.x` range |
| 2026-01-27 22:07 | Lateral movement to AS-SRV | AS-SRV | `as.srv.administrator` RDP from `10.0.8.6` |
| 2026-01-27 22:14 | `wsync.exe` deployed on AS-SRV | AS-SRV | C2 implant dropped via PowerShell |
| 2026-01-27 22:15 | `updater.exe` staged on AS-SRV | AS-SRV | Ransomware binary written by `powershell.exe` |
| 2026-01-27 22:17 | Share enumeration from AS-SRV | AS-SRV | `net view \\10.1.0.154` and `net view \\10.1.0.183` |
| 2026-01-27 22:18 | `st.exe` compresses data | AS-SRV | `exfil_data.zip` created for exfiltration |
| 2026-01-27 22:18:33 | Encryption begins | AS-SRV | `updater.exe` executes, drops `akira_readme.txt` |
| 2026-01-27 22:20 | Ransomware binary deleted | AS-SRV | `clean.bat` deletes `updater.exe` |

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
| AnyDesk Password | `intrud3r!` |
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
| Initial Access | T1204 – User Execution | `daniel_richardson_cv.pdf.exe` double extension payload |
| Persistence | T1219 – Remote Access Software | AnyDesk pre-staged at `C:\Users\Public\` with password |
| Persistence | T1053.005 – Scheduled Task | `MicrosoftEdgeUpdateCheck` running `RuntimeBroker.exe` |
| Execution | T1059.001 – PowerShell | Download cradles with bypass flags and obfuscation |
| Execution | T1105 – Ingress Tool Transfer | `bitsadmin.exe` for LOLBin tool download |
| Defense Evasion | T1562.001 – Disable Security Tools | `kill.bat` — multiple `Set-MpPreference` + registry |
| Defense Evasion | T1112 – Modify Registry | `DisableAntiSpyware` registry key modification |
| Defense Evasion | T1036 – Masquerading | `updater.exe` disguised as software updater |
| Defense Evasion | T1027 – Obfuscated Files | Base64, string concat, variable splitting for downloads |
| Credential Access | T1003.001 – LSASS Memory | `powershell.exe` reads LSASS — `\Device\NamedPipe\lsass` |
| Discovery | T1046 – Network Service Scanning | `scan.exe` maps internal `10.1.x.x` range |
| Discovery | T1135 – Network Share Discovery | `net view \\10.1.0.154`, `net view \\10.1.0.183` |
| Lateral Movement | T1021.001 – Remote Desktop | `as.srv.administrator` RDP to AS-SRV |
| Collection | T1560 – Archive Collected Data | `st.exe` → `exfil_data.zip` |
| Exfiltration | T1041 – Exfiltration Over C2 | Data exfiltrated via `wsync.exe` C2 channel |
| Impact | T1486 – Data Encrypted for Impact | Akira ransomware — `.akira` extension |
| Impact | T1490 – Inhibit System Recovery | `wmic shadowcopy delete` removes VSS copies |
| Impact | T1485 – Data Destruction | `clean.bat` deletes ransomware binary post-encryption |

---

## 💠 Diamond Model Summary

| Feature | Details |
|---------|---------|
| **Adversary** | Akira ransomware affiliate — hands-on-keyboard operator demonstrating patient, multi-phase methodology. Re-used pre-staged access from a prior intrusion ("The Broker"), showing operational maturity and awareness of the victim environment. |
| **Infrastructure** | Attacker-controlled: `sync.cloud-endpoint.net`, `cdn.cloud-endpoint.net` (Cloudflare-fronted, IPs: `104.21.30.237`, `172.67.174.46`). Remote access relay: `relay-0b975d23.net.anydesk.com`. Guacamole RDP gateways: `10.0.8.5`, `10.0.8.6`, `10.0.8.8`. Attacker external IP: `88.97.164.155`. |
| **Capability** | C2 beacon (`wsync.exe`), AnyDesk for persistent remote access (pre-staged), credential dumping via LSASS named pipe, network scanning (`scan.exe`), defense evasion scripts (`kill.bat`), data staging (`st.exe`), Akira ransomware (`updater.exe`), cleanup script (`clean.bat`). |
| **Victim** | Primary: AS-PC2 (entry point via `david.mitchell`). Lateral target: AS-SRV (via `as.srv.administrator`). Encrypted: AS-PC2 and AS-SRV. Targeted shares: `C:\Shares\` — Clients, Payroll, Compliance, Contractors, Backups. |

---

## ✅ Conclusion

The Ashford Sterling Recruitment intrusion represents a sophisticated, patient, multi-phase ransomware attack by an Akira affiliate. The threat actor demonstrated operational maturity by returning to a previously compromised environment using pre-staged tools, executing with precision against high-value targets, and covering their tracks with cleanup scripts.

The attack chain progressed methodically: re-entry via AnyDesk → C2 establishment → credential theft → network reconnaissance → lateral movement → data exfiltration → ransomware deployment → anti-forensics cleanup — all within a few hours on January 27, 2026.

The most critical lesson from this incident is that **incomplete remediation after the initial "The Broker" compromise directly enabled this attack**. Had AnyDesk been removed and all credentials reset after the first intrusion, the attacker would have had no pre-staged access to leverage.

---

## 🧠 Lessons Learned

**Pre-Staged Access Is the Hardest Threat to Detect**
The attacker's ability to return months later using pre-installed AnyDesk highlights the critical risk of incomplete post-incident remediation.

**Obfuscated Download Cradles Evade Simple Detection**
Three different obfuscation methods were used for a single download — emphasizing the need for behavioral rather than signature-based detection.

**Legitimate Tools Are the Preferred Attack Vector**
Every major stage used legitimate software: AnyDesk, bitsadmin, scan.exe, wmic. LOLBin behavioral monitoring is essential.

**Speed of Execution Limits Response Time**
From re-entry to encryption took approximately 3 hours — leaving a narrow window for detection and containment.

**Credential Theft Has Long-Term Consequences**
Credentials harvested during "The Broker" were reused in this attack for lateral movement — demonstrating the cascading impact of uncontained credential compromise.

**Double Extortion Increases Victim Pressure**
Data was exfiltrated before encryption, giving the attacker two points of leverage: file recovery and threat of data publication.

---

## 🛡️ Remediation Actions

**Immediate:**
- Isolate AS-PC2 and AS-SRV from the network
- Reset credentials for `david.mitchell` and `as.srv.administrator`
- Remove `C:\Users\Public\AnyDesk.exe` from all hosts
- Delete scheduled task `MicrosoftEdgeUpdateCheck` on all hosts
- Block `sync.cloud-endpoint.net` and `cdn.cloud-endpoint.net` at firewall/proxy
- Block `88.97.164.155` at perimeter firewall

**Short Term:**
- Enforce AnyDesk block policy — restrict to IT-approved remote tools only
- Enable PowerShell Script Block Logging and AMSI on all endpoints
- Alert on `bitsadmin.exe` and `certutil.exe` making network connections
- Monitor for `Set-MpPreference` and registry modifications to Windows Defender keys
- Implement privileged account monitoring for local administrator accounts
- Hunt for `wsync.exe` or unknown executables in `C:\ProgramData\` across all endpoints

**Long Term:**
- Enforce MFA for all RDP and remote access sessions
- Implement network segmentation to limit lateral movement from workstations to servers
- Deploy honeypot files in share directories to detect early ransomware activity
- Conduct full forensic review of "The Broker" intrusion to ensure complete remediation
- Establish immutable off-site backups to enable recovery without ransom payment
- Implement application allowlisting to prevent unauthorized executable deployment

---

*Investigation completed on the SancLogic Cyber Range — The Buyer scenario.*
*Platform: Microsoft Defender for Endpoint + Microsoft Sentinel (KQL)*
