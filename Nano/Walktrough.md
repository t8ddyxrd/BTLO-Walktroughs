# 🛡️ BTLO Investigation Walkthrough – Nano

> **Platform:** Blue Team Labs Online (BTLO)
> **Investigation Dataset:** Log_2V & Log_1D
> **Tools Used:** RITA, Zeek, Linux CLI (zgrep, awk), WHOIS

This document walks through the investigation **in the exact order of the questions**, explaining *what was found, why it matters, and how the conclusion was reached*. Screenshots are referenced where applicable.

---

## 1️⃣ Attacker C2 Server IP & Connection Count

**Question:**
Looking at the RITA HTML Report (**Log_2V**), what is the IP of the attacker’s C2 server? Provide the number of connections as well.

### 🔍 Methodology

* Navigated to **RITA → Beacons (Log_2V)**
* Beaconing traffic indicates **Command & Control (C2)** behavior
* In C2 scenarios, the **infected host initiates outbound connections** to the attacker-controlled server

### 📊 Key Observation

The top beacon entry showed:

* **Source:** `10.234.234.100` (internal / infected host)
* **Destination:** `138.197.117.74` (external server)
* **Connections:** `8440`
* **Beacon Score:** `0.996` (extremely strong beaconing indicator)

📸 *Screenshot:* <img width="1497" height="85" alt="beacon-size" src="https://github.com/user-attachments/assets/9904adf5-081f-47e5-861f-d32f67d4cb73" />


### ✅ Conclusion

The destination IP is the attacker’s C2 server.

**Answer:**

```
138.197.117.74, 8440
```

---

## 2️⃣ Cloud Infrastructure Hosting the C2

**Question:**
What cloud infrastructure is being used for the C2 server?

### 🔍 Methodology

* RITA blacklist tabs (**BL Dest IPs / BL Hostnames**) were empty
* Performed **external WHOIS / ASN lookup** on `138.197.117.74`

### 📊 Key Observation

WHOIS results showed:

* **ASN:** AS14061
* **Organization:** DigitalOcean, LLC
* **NetRange:** 138.197.0.0/16

📸 *Screenshot:* `<img width="832" height="790" alt="digital-ocean-q2" src="https://github.com/user-attachments/assets/2ab3ec57-f7d1-4fbd-a79a-f022d7abc4f4" />


### ✅ Conclusion

The attacker is hosting the C2 on a cloud VPS provider.

**Answer:**

```
DigitalOcean
```

---

## 3️⃣ User Agent Corresponding to the C2 Traffic

**Question:**
Looking at the RITA **User Agents** report, what system corresponds to the connection count in Q1?

### 🔍 Methodology

* Navigated to **RITA → User Agents (Log_2V)**
* Compared connection counts against the **8440 connections** identified in Q1

### 📊 Key Observation

A user agent with a **matching connection count**:

```
Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)
```

📸 *Screenshot:* `<img width="1027" height="603" alt="user-agent-q3" src="https://github.com/user-attachments/assets/d607b42b-c538-4e8a-81ba-ec4d22764bbf" />


### ✅ Conclusion

This user agent corresponds to the system generating the beaconing traffic.

**Answer:**

```
Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)
```

---

## 4️⃣ Low‑Profile Subdomain with Abnormal DNS Volume

**Question:**
In **Log_1D**, what is the low-profile subdomain with an absurd amount of requests?

### 🔍 Methodology

* Switched dataset to **Log_1D**
* Navigated to **RITA → DNS**
* Sorted by **Visited / Request count** (descending)

### 📊 Key Observation

A suspicious domain stood out:

* **Subdomain:** `cat.nanobotninjas.com`
* **Requests:** `82920`
* Extremely high compared to normal CDN / cloud domains

📸 *Screenshot:* `<img width="1524" height="251" alt="dns-q4" src="https://github.com/user-attachments/assets/d906ece9-9e6d-4af0-9361-7c0d2dfe3afb" />


### ✅ Conclusion

Such request volume strongly suggests **automated DNS activity**.

**Answer:**

```
cat.nanobotninjas.com, 82920
```

---

## 5️⃣ Private IP Generating DNS TXT Requests

**Question:**
In the **Zeek logs (Log_1D)**, which private IP is responsible for the DNS TXT requests?

### 🔍 Methodology

* Moved from RITA summaries to **raw Zeek DNS logs**
* Filtered for TXT queries to the subdomain from Q4

```bash
zgrep "cat.nanobotninjas.com" dns_*.log.gz | grep "TXT" | awk '{print $3}' | sort | uniq -c
```

### 📊 Key Observation

Output showed a dominant private IP:

```
82920 10.234.234.105
```

📸 *Screenshots:* `<img width="1919" height="814" alt="cmd-q5" src="https://github.com/user-attachments/assets/d0f04584-82f5-4590-b3f1-d237e63e7b08" />  
                  <img width="1497" height="85" alt="beacon-size" src="https://github.com/user-attachments/assets/9904adf5-081f-47e5-861f-d32f67d4cb73" />



### ✅ Conclusion

This internal host is performing DNS tunneling activity.

**Answer:**

```
10.234.234.105
```

---

## 6️⃣ Numerical System Used in DNS Subdomain Values

**Question:**
What numerical system is being used for the changing value prepended to the subdomain?

### 🔍 Methodology

* Inspected the leftmost label of queried domains
* Example queries:

```
03b00105c0d05fbab.cat.nanobotninjas.com
6e370105c0d05fbab.cat.nanobotninjas.com
```

### 📊 Key Observation

* Characters observed: `0–9` and `a–f`
* No characters beyond `f`

📸 *Screenshot:* `<img width="1916" height="332" alt="cmd-q6" src="https://github.com/user-attachments/assets/3471681b-0693-4aa3-ab22-cc5b20987e8d" />


### ✅ Conclusion

This pattern matches **hexadecimal encoding**.

**Answer:**

```
Base16
```

---

## 7️⃣ Tool Used for C2 over DNS

**Question:**
Judging from the logs, what tool was the attacker using to channel C2 over DNS?

### 🔍 Methodology & Correlation

Evidence collected across questions:

* DNS TXT record abuse
* Hex-encoded payloads
* Chunked data in subdomains
* Domain name containing `cat`

### 🧠 Analyst Insight

These indicators are **textbook fingerprints** of the DNS C2 tool **dnscat2**.

### ✅ Conclusion

The attacker used a well-known DNS tunneling framework.

**Answer:**

```
dnscat
```

---

## 🧩 Final Notes

This investigation demonstrates a **full blue-team workflow**:

* Detection via RITA
* Attribution via Zeek
* Manual log analysis with Linux CLI
* Encoding recognition
* Tool fingerprinting

This mirrors **real SOC investigations**, where analysts pivot between high-level detections and raw telemetry to build confidence in findings.

---

✅ **All questions successfully solved**


