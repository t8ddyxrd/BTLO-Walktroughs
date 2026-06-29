# 🛡️ BTLO Investigation Walkthrough – FunGames

> **Platform:** Blue Team Labs Online (BTLO)  
> **Investigation Dataset:** FunGames  
> **Tools Used:** Wireshark, CyberChef, Linux CLI  
> **Attack Chain Summary:** The attacker exploited a SQL Injection vulnerability in the FunGames web application to extract database credentials. These credentials were reused to gain SSH access to the server. A malicious binary was then transferred to escalate privileges to root, after which sensitive data was exfiltrated covertly via DNS traffic.

This document walks through the investigation **in the exact order of the questions**, explaining *what was found, why it matters, and how the conclusion was reached*. Screenshots are referenced where applicable.

---

## 1️⃣ Attacker IP Address

**Question:**  
What is the IP address of the attacker who is performing the attack?

### 🔍 Methodology

* Opened the PCAP in **Wireshark**
* Filtered for **HTTP traffic** related to the FunGames application
* Identified repeated malicious requests containing SQL injection payloads
* Extracted the **source IP address** from the malicious HTTP requests

📸 *Screenshot:* <img width="1919" height="672" alt="q1 and 2" src="https://github.com/user-attachments/assets/e3adda07-675c-442f-b212-fb396b401544" />



### ✅ Conclusion

The source IP address generating the malicious SQL injection traffic is the attacker.

**Answer:**
192.168.8.130

## 2️⃣ Victim IP Address

**Question:**  
What is the IP address of the victim?

### 🔍 Methodology

* Used the same HTTP packets identified in Question 1
* Extracted the **destination IP address** receiving the malicious requests

📸 *Screenshot:*  <img width="1919" height="672" alt="q1 and 2" src="https://github.com/user-attachments/assets/e3adda07-675c-442f-b212-fb396b401544" />


### ✅ Conclusion

This IP address belongs to the compromised FunGames web server.

**Answer:**
192.168.8.142

## 3️⃣ Attack Type Identified

**Question:**  
Which attack was performed by the attacker?

### 🔍 Methodology

* Inspected HTTP GET parameters sent to `/game-details.php`
* Observed SQL injection indicators such as:
  * `UNION ALL SELECT`
  * `CONCAT` / `CONCAT_WS`
  * `SLEEP(5)` time-based checks
* Confirmed database interaction via server-side error output

📸 *Screenshot:* <img width="1894" height="445" alt="q3" src="https://github.com/user-attachments/assets/8d1cce46-37fa-4657-8733-615e9986529f" />



### ✅ Conclusion

The attacker exploited an input validation flaw to manipulate backend SQL queries.

**Answer:**
SQL Injection

## 4️⃣ Tool Used by the Attacker

**Question:**  
It seems the attacker used a famous tool to perform the attack.

### 🔍 Methodology

* Inspected HTTP headers in the malicious requests
* Identified the automated tooling from the **User-Agent** value

📸 *Screenshot:* <img width="1266" height="775" alt="q4" src="https://github.com/user-attachments/assets/a19059e8-17ba-48a8-9f7d-5830ff232289" />



### ✅ Conclusion

The attacker automated SQL injection exploitation using a well-known tool.

**Answer:**
SQL Map

## 5️⃣ Victim Credentials Exposed

**Question:**  
In one of the packets, it is possible to view the victim's username and password.

### 🔍 Methodology

* Followed the HTTP stream associated with the SQL injection requests targeting the FunGames application

* Identified a server response containing raw database output returned as part of the vulnerable query

* Observed that the response body was not clearly readable within the default Wireshark packet view

* Exported the HTTP response data to a file for further analysis

* Opened the extracted response file in Mozilla Firefox to properly render the content

* Reviewed the rendered page and located the exposed database fields

* Extracted the cleartext username and password values from the displayed output




📸 *Screenshot:* <img width="1920" height="791" alt="q5" src="https://github.com/user-attachments/assets/49796026-7b8b-4bb1-bdbe-7cc2cb4f0a27" />

📸 *Screenshot:* <img width="1920" height="779" alt="q5 part 2" src="https://github.com/user-attachments/assets/494a4845-4507-41c5-ad2b-02f266f729ee" />



### ✅ Conclusion

The attacker successfully extracted valid credentials from the database.

**Answer:**
jarovic, Ma77.J@r0v1c-2024

## 6️⃣ File Transferred for Privilege Escalation

**Question:**  
Once the attacker obtained the victim's credentials he accessed the system via SSH. To gain root privileges, they transferred a file to the victim's machine. What is the name of the file?

### 🔍 Methodology

* After SSH access was established, reviewed traffic for tool transfer activity
* Identified an HTTP request for a binary file download
* Extracted the filename from the HTTP request path

📸 *Screenshot:* `<img width="1920" height="802" alt="q6" src="https://github.com/user-attachments/assets/5261ec3a-5bd4-4b0b-b08e-4daf200de323" />



### ✅ Conclusion

The attacker transferred a file used for privilege escalation.

**Answer:**
exploit

## 7️⃣ SHA256 Hash of the Transferred File

**Question:**  
What is the sha256 hash of the file above?

### 🔍 Methodology

* Exported the transferred file from the PCAP (**Export Objects → HTTP**)
* Calculated the SHA256 hash using Linux command line:
  * `sha256sum exploit`

📸 *Screenshot:* <img width="1918" height="782" alt="q7 " src="https://github.com/user-attachments/assets/51e3dac1-0213-48f7-a967-21a7e68f8837" />

📸 *Screenshot:* `<img width="1158" height="562" alt="q7 part 2" src="https://github.com/user-attachments/assets/d7bd5469-647d-47dc-a29c-9ea3f9e4c018" />



### ✅ Conclusion

The SHA256 value uniquely identifies the transferred binary.

**Answer:**
d8dd09b01eb4e363d88ff53c0aace04c39dbea822b7adba7a883970abbf72a77

## 8️⃣ CVE Associated With the Vulnerability

**Question:**  
With which CVE is this type of vulnerability identified?

### 🔍 Methodology

* Identified that root access was achieved via a known Linux privilege escalation exploit
* Correlated the exploit behavior to the relevant public vulnerability identifier

📸 *Screenshot:* <img width="1474" height="868" alt="q8" src="https://github.com/user-attachments/assets/b9f5a9cf-b440-48c8-9e36-e7f9f5151c6a" />



### ✅ Conclusion

The attacker leveraged a known privilege escalation vulnerability.

**Answer:**
CVE-2024-1086

## 9️⃣ Exfiltrated Data String

**Question:**  
After obtaining root privileges, it seems that the attacker exfiltrated sensitive data without transferring any files. Provide the string related to this data.

### 🔍 Methodology

* Inspected DNS traffic originating from the victim host
* Followed the UDP stream containing the abnormal payload
* Extracted the hex-encoded string embedded in DNS traffic

📸 *Screenshot:* <img width="1289" height="788" alt="q9" src="https://github.com/user-attachments/assets/80c7164d-743f-4e48-9a7a-39deddd06457" />



### ✅ Conclusion

Sensitive data was exfiltrated covertly through DNS using an encoded payload.

**Answer:**
4a676216e6b204d696c6c7320313233343536373839313233343536372065787020646174652030382f32382036373620313233200a

## 🔟 Decoded Exfiltrated Data

**Question:**  
It seems that the string has been encoded. What data did the attacker manage to obtain through exfiltration?

### 🔍 Methodology

* Decoded the hex string using **CyberChef** (From Hex)
* Converted the payload into readable plaintext

📸 *Screenshot:* <img width="958" height="617" alt="q10" src="https://github.com/user-attachments/assets/673aa8d4-dd8d-443b-b58a-2297c20c2d6c" />



### ✅ Conclusion

The decoded payload reveals sensitive financial data.

**Answer:**
Frank Mills 1234567891234567 exp date 08/28 cvv 123

## 1️⃣1️⃣ MITRE Technique Identification

**Question:**  
Provide the Mitre ID of this technique—in regard to the previous question.

### 🔍 Methodology

* Mapped the attacker’s remote access method to the MITRE ATT&CK framework
* Identified the technique ID for SSH-based remote service usage

📸 *Screenshot:* <img width="1573" height="341" alt="q11" src="https://github.com/user-attachments/assets/6b986f0f-2a56-4fe2-8ed5-65214dccd50c" />



### ✅ Conclusion

The attacker accessed the system using SSH, which maps to the following ATT&CK technique.

**Answer:**
T1021.004

## 🧩 Final Notes

This investigation demonstrates a **complete blue-team workflow**:

* SQL injection used for initial access and credential theft
* SSH used for remote access into the victim system
* Privilege escalation performed using a transferred exploit binary
* DNS-based exfiltration used to extract sensitive data covertly

The findings were derived directly from packet evidence using repeatable forensic methods.

---

✅ **All questions successfully solved**



