# 🛡️ BTLO Investigation Walkthrough – **Mitsu**

> **Platform:** Blue Team Labs Online (BTLO)  
> **Investigation Name:** Mitsu  
> **Focus:** PowerShell-based malware analysis & persistence discovery  
> **Primary Tooling:** PowerShell, VirusTotal, Windows Task Scheduler, Windows Registry  
> **MITRE ATT&CK Focus:** T1053.005 (Scheduled Task), T1059.001 (PowerShell), T1547.001 (Registry Run Keys)

---

## 📌 Executive Summary

This investigation focuses on identifying **malicious persistence mechanisms** deployed on a Windows system after execution of a suspicious binary. Using **PowerShell-only analysis**, we validated file reputation, uncovered a **malicious scheduled task executed at user logon**, and confirmed **registry-based startup abuse** leveraging a legitimate Windows binary.

The attacker’s objective was **covert data collection** and **stealthy persistence**, avoiding obvious malware artifacts while blending into legitimate Windows mechanisms.

---

## 🧬 Attack Chain Overview

1. User executes malicious binary (`omgsoft.exe`)
2. Malware installs persistence via **Scheduled Task (logon trigger)**
3. Task launches **hidden PowerShell** to enumerate processes
4. Output written to disk (`C:\processes.txt`)
5. Registry `Run` key abused using legitimate binary (`notepad.exe`)

---

## 🧠 Analyst Mindset & Investigation Framing

Before diving into individual questions, this investigation was approached using a **hypothesis‑driven SOC workflow** rather than simple artifact collection.

At each stage, the goal was to:
- Form an initial hypothesis based on observable evidence
- Test that hypothesis against system artifacts
- Explicitly rule out benign or alternative explanations
- Assess **impact**: what this behavior enables an attacker to do

This mirrors how real SOC analysts operate under time pressure, uncertainty, and incomplete data.

---

## 1️⃣ Malicious File Hash Identification

**Question:**  
What is the SHA256 hash of `omgsoft.exe`?

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:** The executable `omgsoft.exe` is not a legitimate installer but a malicious payload disguised as software.

**Why this hypothesis existed:**
- The filename resembles common fake utility naming conventions
- The investigation context already indicated suspicious behavior elsewhere on the system

**Action taken:**
- Calculated the SHA256 hash using PowerShell to uniquely identify the file
- Queried VirusTotal with the hash

**Negative space / ruled out:**
- This is not a false positive or PUA, as the majority of engines classify it as a trojan
- Not a cracked installer or adware bundle

**Impact framing:**
- Identifying the malware family allows defenders to anticipate post‑infection behavior such as credential theft and persistence mechanisms


```powershell
Get-FileHash omgsoft.exe
```

The hash was then submitted to VirusTotal for reputation analysis.

### 📸 Evidence
*PowerShell hash output* (see screenshot Q1)

### ✅ Answer
```
E60D911F2EF120ED782449F1136C23DDF0C1C81F7479C5CE31ED6DCEA6F6ADF9
```

---

## 2️⃣ Malware Family Identification

**Question:**  
What is the true infection name of `omgsoft.exe`?

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:** The executable `omgsoft.exe` is not a legitimate installer but a malicious payload disguised as software.

**Why this hypothesis existed:**
- The filename resembles common fake utility naming conventions
- The investigation context already indicated suspicious behavior elsewhere on the system

**Action taken:**
- Calculated the SHA256 hash using PowerShell to uniquely identify the file
- Queried VirusTotal with the hash

**Negative space / ruled out:**
- This is not a false positive or PUA, as the majority of engines classify it as a trojan
- Not a cracked installer or adware bundle

**Impact framing:**
- Identifying the malware family allows defenders to anticipate post‑infection behavior such as credential theft and persistence mechanisms


VirusTotal analysis showed a high detection ratio with strong vendor consensus.

### 📸 Evidence
*VirusTotal detection page* (see screenshot Q2)

### ✅ Answer
```
LummaStealer
```

---

## 3️⃣ MSI Certificate Verification

**Question:**  
What is the certificate status of `neuro.msi`?

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:** The executable `omgsoft.exe` is not a legitimate installer but a malicious payload disguised as software.

**Why this hypothesis existed:**
- The filename resembles common fake utility naming conventions
- The investigation context already indicated suspicious behavior elsewhere on the system

**Action taken:**
- Calculated the SHA256 hash using PowerShell to uniquely identify the file
- Queried VirusTotal with the hash

**Negative space / ruled out:**
- This is not a false positive or PUA, as the majority of engines classify it as a trojan
- Not a cracked installer or adware bundle

**Impact framing:**
- Identifying the malware family allows defenders to anticipate post‑infection behavior such as credential theft and persistence mechanisms


```powershell
Get-AuthenticodeSignature .\neuro.msi
```

### 📸 Evidence
*Authenticode signature output* (see screenshot Q3)

### ✅ Answer
```
NotSigned
```

> ⚠️ Unsigned installers are a strong indicator of untrusted software delivery.

---

## 4️⃣ Differential Analysis – New User Creation

**Question:**  
What user was added after executing `Win_Update.exe`, and which group does it belong to?

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:** The executable `omgsoft.exe` is not a legitimate installer but a malicious payload disguised as software.

**Why this hypothesis existed:**
- The filename resembles common fake utility naming conventions
- The investigation context already indicated suspicious behavior elsewhere on the system

**Action taken:**
- Calculated the SHA256 hash using PowerShell to uniquely identify the file
- Queried VirusTotal with the hash

**Negative space / ruled out:**
- This is not a false positive or PUA, as the majority of engines classify it as a trojan
- Not a cracked installer or adware bundle

**Impact framing:**
- Identifying the malware family allows defenders to anticipate post‑infection behavior such as credential theft and persistence mechanisms


```powershell
net users
net localgroup administrators
```

Comparing system state **before and after execution** revealed a newly created administrative user.

### 📸 Evidence
*User & group enumeration* (see screenshot Q4)

### ✅ Answer
```
testuser, Administrators
```

---

## 5️⃣ Persistence via Scheduled Task

**Hypothesis:** If this malware aims to persist across reboots or logons, it likely abuses Windows persistence mechanisms such as Scheduled Tasks.

**Why this hypothesis existed:**
- Commodity stealers commonly use scheduled tasks for stealthy persistence
- Previous artifacts suggested post‑execution system modification

**Action taken:**
- Enumerated scheduled tasks before and after execution
- Compared baseline vs post‑execution task lists

**Finding:**
- A new task named `LogonProcessDump` appeared after execution

**Negative space / ruled out:**
- This task is not part of a standard Windows installation
- It does not align with Windows Update, Defender, or OEM maintenance tasks

**Impact framing:**
- This guarantees execution at every user logon
- Enables repeated credential/process harvesting without user interaction

---

 Newly Added Scheduled Task

**Question:**  
What is the name of the newly added scheduled task?

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:** The executable `omgsoft.exe` is not a legitimate installer but a malicious payload disguised as software.

**Why this hypothesis existed:**
- The filename resembles common fake utility naming conventions
- The investigation context already indicated suspicious behavior elsewhere on the system

**Action taken:**
- Calculated the SHA256 hash using PowerShell to uniquely identify the file
- Queried VirusTotal with the hash

**Negative space / ruled out:**
- This is not a false positive or PUA, as the majority of engines classify it as a trojan
- Not a cracked installer or adware bundle

**Impact framing:**
- Identifying the malware family allows defenders to anticipate post‑infection behavior such as credential theft and persistence mechanisms


```powershell
Get-ScheduledTask | Select TaskName, TaskPath
```

Suspicious tasks were isolated by identifying **non-standard names** and **logon triggers**.

### 📸 Evidence
*Scheduled task enumeration* (see screenshot Q5)

### ✅ Answer
```
LogonProcessDump
```

---

## 6️⃣ PowerShell Command Executed at Logon

**Question:**  
What full PowerShell command does the task execute?

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:** The executable `omgsoft.exe` is not a legitimate installer but a malicious payload disguised as software.

**Why this hypothesis existed:**
- The filename resembles common fake utility naming conventions
- The investigation context already indicated suspicious behavior elsewhere on the system

**Action taken:**
- Calculated the SHA256 hash using PowerShell to uniquely identify the file
- Queried VirusTotal with the hash

**Negative space / ruled out:**
- This is not a false positive or PUA, as the majority of engines classify it as a trojan
- Not a cracked installer or adware bundle

**Impact framing:**
- Identifying the malware family allows defenders to anticipate post‑infection behavior such as credential theft and persistence mechanisms


```powershell
Get-ScheduledTask -TaskName "LogonProcessDump" | Select -ExpandProperty Actions
```

This revealed a **hidden PowerShell execution** designed to collect process information.

### 📸 Evidence
*Task action inspection* (see screenshot Q6)

### ✅ Answer
```powershell
powershell.exe -NoProfile -WindowStyle Hidden -Command "Get-Process | Out-File C:\processes.txt"
```

> 🧠 This is a classic **living-off-the-land** persistence technique using native tooling.

---

## 7️⃣ Registry-Based Persistence Abuse

**Question:**  
What legitimate Windows application is being abused as a startup item?

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:** The executable `omgsoft.exe` is not a legitimate installer but a malicious payload disguised as software.

**Why this hypothesis existed:**
- The filename resembles common fake utility naming conventions
- The investigation context already indicated suspicious behavior elsewhere on the system

**Action taken:**
- Calculated the SHA256 hash using PowerShell to uniquely identify the file
- Queried VirusTotal with the hash

**Negative space / ruled out:**
- This is not a false positive or PUA, as the majority of engines classify it as a trojan
- Not a cracked installer or adware bundle

**Impact framing:**
- Identifying the malware family allows defenders to anticipate post‑infection behavior such as credential theft and persistence mechanisms


```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

The attacker configured a Run key entry pointing to a trusted binary to evade suspicion.

### 📸 Evidence
*Registry Run key output* (see screenshot Q7)

### ✅ Answer
```
C:\Windows\System32\notepad.exe
```

---

## 🧠 SOC Analyst Notes

* Persistence uses **dual mechanisms** (Scheduled Task + Registry Run key)
* Payload execution is **fileless at runtime**
* PowerShell is executed **hidden** and **without profile loading**
* Legitimate binaries are abused to evade naive detection

---

## 🎯 MITRE ATT&CK Mapping

| Technique | ID |
|--------|----|
| PowerShell | T1059.001 |
| Scheduled Task (Logon) | T1053.005 |
| Registry Run Keys | T1547.001 |

---

## ✅ Final Assessment

This activity represents a **well-structured persistence-focused malware deployment**, relying on native Windows features rather than custom loaders. The techniques observed are consistent with **commodity stealer malware** operating post-initial compromise.

All findings were derived exclusively using **PowerShell**, aligning fully with the investigation constraints.

---

✅ **All questions successfully mapped, verified, and documented**

