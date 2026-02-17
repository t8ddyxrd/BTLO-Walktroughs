# 🛰️ BTLO Investigation Walkthrough – **Frontier Space Station**

> **Platform:** Blue Team Labs Online (BTLO)  
> **Investigation Name:** Frontier Space Station  
> **Focus:** Network forensics, IOC extraction, beacon detection  
> **Primary Tooling:** Linux CLI (strings, grep, awk), custom beacon detection script  
> **MITRE ATT&CK Focus:** T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel)

---

## 📌 Executive Summary

This investigation focuses on identifying **malicious network activity** originating from within the Frontier Space Station environment following the discovery of a suspicious image file on Luis Harrold’s workstation.

Through structured file analysis, IOC extraction, and access log review, we identified **external attacker infrastructure**, confirmed **command-and-control (C2) beaconing**, and mapped **multiple compromised internal hosts** communicating with the same malicious domain.

The attacker’s objective was likely **covert data exfiltration** and **persistent command-and-control**, leveraging benign-looking files and regular outbound web traffic to evade detection.

---

## 🧬 Attack Chain Overview

1. User downloads a disguised image file from external infrastructure  
2. File is revealed to be a PDF containing embedded malicious URLs  
3. Malicious infrastructure is contacted by the compromised host  
4. Periodic beaconing occurs at fixed 5-second intervals  
5. Additional internal hosts exhibit the same beaconing behavior  

---

## 🧠 Analyst Mindset & Investigation Framing

This investigation was approached using a **hypothesis-driven SOC workflow**, prioritizing validation over assumptions.

At each stage, the goal was to:
- Form a hypothesis based on observed artifacts
- Validate it using logs and file analysis
- Rule out benign explanations
- Assess **impact** to the wider environment

This mirrors real-world SOC investigations, where analysts must move from a single suspicious artifact to identifying **enterprise-wide compromise**.

---

## 1️⃣ True File Type Identification

**Question:**  
Luis Harrold mentioned a strange image on his device. Looking into it further, what is the true *file type* of this image?

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:**  
The file may not be a genuine image and could be masquerading as another file type.

**Why this hypothesis existed:**
- Attackers commonly disguise malicious documents as images
- File extensions alone are not reliable indicators of content

**Action taken:**
- Inspected the file structure to determine its real format

**Negative space / ruled out:**
- This is not a corrupted image
- Not a simple misnamed PNG or JPG

**Impact framing:**
- Identifying the true file type determines how embedded content should be analyzed

### 📸 Evidence  
![Q1]<img width="763" height="318" alt="q1" src="https://github.com/user-attachments/assets/d8451254-3620-498f-9ad7-517247da9ac4" />
<img width="763" height="318" alt="q1" src="https://github.com/user-attachments/assets/d8451254-3620-498f-9ad7-517247da9ac4" />


### ✅ Answer
```
PDF
```

---

## 2️⃣ Suspicious URL Extraction

**Question:**  
What are the three suspicious URLs within the file in respective order — defanged?

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:**  
If the file is malicious, it likely contains embedded URLs pointing to attacker infrastructure.

**Why this hypothesis existed:**
- PDFs are frequently abused as delivery mechanisms
- Embedded URLs enable secondary payload delivery

**Action taken:**
- Extracted strings from the PDF
- Filtered for HTTP/HTTPS URLs
- Removed known benign metadata references

**Negative space / ruled out:**
- Adobe, W3C, and schema-related URLs
- Formatting and metadata references

**Impact framing:**
- These URLs represent potential download points for additional malware

```bash
strings "RobCo Image.pdf" | grep -Eo 'https?://[^ ]+'
```

### 📸 Evidence  
![Q2]<img width="1899" height="783" alt="q2" src="https://github.com/user-attachments/assets/ebe05a2b-cee7-43c0-a3ad-f1013078d6f9" />
<img width="1899" height="783" alt="q2" src="https://github.com/user-attachments/assets/ebe05a2b-cee7-43c0-a3ad-f1013078d6f9" />


### ✅ Answer
```
hxxp[:]//hosting2022private[.]duckdns[.]org/eubp/example[.]zip,
hxxps[:]//stcdanismalik[.]com/Update/UpdatePDF[.]exe,
hxxps[:]//stcdanismalik[.]com/Update/UpdatePDF[.]zip
```

---

## 3️⃣ Image Download Source Attribution

**Question:**  
Where did Luis download the image from?

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:**  
The source of the image can be identified through outbound web requests from Luis’ workstation.

**Why this hypothesis existed:**
- Download events are logged in web access logs
- Attackers often reuse the same domain for hosting and delivery

**Action taken:**
- Reviewed `access.log` for outbound requests
- Filtered for attacker-related domains

**Negative space / ruled out:**
- Internal services
- CDN and common third-party services

**Impact framing:**
- Identifying the download source helps attribute attacker infrastructure

```bash
grep -i enclave access.log
```

### 📸 Evidence  
![Q3]<img width="1781" height="253" alt="q3" src="https://github.com/user-attachments/assets/699add3a-88de-490e-9dfc-55e8067aa628" />
<img width="1781" height="253" alt="q3" src="https://github.com/user-attachments/assets/699add3a-88de-490e-9dfc-55e8067aa628" />


### ✅ Answer
```
https://www.enclavenet.com/image
```

---

## 4️⃣ Command-and-Control Beacon Detection

**Question:**  
What URL has the highest amount of traffic based on a minimum of 10 beacons at 5-second intervals?

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:**  
If the host is compromised, it may be beaconing regularly to a C2 endpoint.

**Why this hypothesis existed:**
- Regular, short-interval traffic is a common C2 pattern
- Commodity malware frequently uses HTTP-based beacons

**Action taken:**
- Executed the provided beacon detection script
- Targeted Luis’ internal IP address
- Filtered for 5-second intervals with at least 10 occurrences

**Negative space / ruled out:**
- Normal browsing behavior
- CDN polling and update services

**Impact framing:**
- The identified URL represents the primary C2 endpoint

```bash
python3 potatu-bot-beacon.py -i 5 -c 10 172.16.42.107 access.log
```

### 📸 Evidence  
![Q4]<img width="1899" height="735" alt="q4" src="https://github.com/user-attachments/assets/a872a79c-2808-4389-8ccd-c977ca98c6a8" />
<img width="1899" height="735" alt="q4" src="https://github.com/user-attachments/assets/a872a79c-2808-4389-8ccd-c977ca98c6a8" />


### ✅ Answer
```
https://www1-secure-vpn.com/collect
```

---

## 5️⃣ Identification of Additional Compromised Hosts

**Question:**  
Lastly, let’s find additional hosts in the space station network that are compromised and reach out to the domain above. Place the hostnames in their respective order — including Luis’ machine.

### 🔍 Methodology (Hypothesis‑Driven)

**Hypothesis:**  
If one host is beaconing to the C2 domain, other compromised hosts may exhibit the same behavior.

**Why this hypothesis existed:**
- Lateral compromise is common in internal networks
- C2 infrastructure is often reused across hosts

**Action taken:**
- Extracted all internal IPs communicating with the C2 domain
- Mapped IP addresses to hostnames using the Network Topology report

**Negative space / ruled out:**
- Servers and infrastructure devices
- Hosts without outbound communication to the domain

**Impact framing:**
- Identifying all affected hosts is critical for containment

### 📸 Evidence  
![Q5]<img width="660" height="476" alt="q5" src="https://github.com/user-attachments/assets/65cb5baa-fad7-468a-b39d-f660e12110ca" />
<img width="660" height="476" alt="q5" src="https://github.com/user-attachments/assets/65cb5baa-fad7-468a-b39d-f660e12110ca" />



### ✅ Answer
```
HV-KNIGHT, HV-DEVLOP, HV-PALADIN, HV-SCRIBE
```

---

## 🧠 SOC Analyst Notes

- The attacker relied on **web-based C2** to blend in with normal traffic  
- Beacon timing strongly indicates automation  
- Multiple internal workstations were affected, indicating **wider compromise**  

---

## 🎯 MITRE ATT&CK Mapping

| Technique | ID |
|--------|----|
| Web Protocols | T1071.001 |
| Exfiltration Over C2 Channel | T1041 |

---

## ✅ Final Assessment

This investigation demonstrates a **network-centric compromise** leveraging disguised files and periodic HTTP beaconing to maintain command-and-control access. By correlating file artifacts with network telemetry, multiple compromised hosts were identified, enabling effective scoping and remediation.

All findings were derived through structured analysis and aligned with real-world SOC investigative workflows.







