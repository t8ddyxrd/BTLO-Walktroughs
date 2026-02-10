# 🛡️ BTLO Investigation Walkthrough – Vortex

> **Platform:** Blue Team Labs Online (BTLO)  
> **Investigation Dataset:** Vortex  
> **Tools Used:** Wireshark, Zeek, Linux CLI, CyberChef  

This document walks through the investigation **in the exact order of the questions**, explaining *what was found, why it matters, and how the conclusion was reached*. Screenshots are referenced where applicable.

---

## 1️⃣ Time of Initial Connection to the Malicious Website

**Question:**  
What time did the suspected user system/browser connect to the malicious website?

### 🔍 Methodology

* Opened the PCAP in **Wireshark**
* Filtered for **DNS / HTTP traffic**
* Identified the **first outbound connection** to the malicious domain
* Switched the time format to **Date and Time of Day**
* Extracted the timestamp from the earliest relevant packet

📸 *Screenshot:* `<img width="1417" height="110" alt="q1 and 2" src="https://github.com/user-attachments/assets/d4f3fbd2-73be-4135-9575-4ca5df786ddf" />`



### ✅ Conclusion

This timestamp represents the first interaction between the victim system and attacker-controlled infrastructure.

**Answer:**
22:51:00.220437

## 2️⃣ Briana’s IP Address

**Question:**  
What is Briana’s IP address?

### 🔍 Methodology

* Used the same packet identified in Question 1
* Extracted the **source IP address** from the packet details

📸 *Screenshot:* `<img width="1417" height="110" alt="q1 and 2" src="https://github.com/user-attachments/assets/63368cdb-2d82-45b5-900d-30188f4f41ef" />`


### ✅ Conclusion

This private IP address belongs to Briana’s system.

**Answer:**
192.168.1.27

## 3️⃣ Briana’s MAC Address and Vendor

**Question:**  
What is Briana’s MAC/Ethernet address? What is the vendor name for the MAC address?

### 🔍 Methodology

* Inspected **Ethernet II** headers in Wireshark
* Identified the source MAC address
* Used OUI resolution to determine the hardware vendor
* 


📸 *Screenshot:* `<img width="1235" height="234" alt="q3" src="https://github.com/user-attachments/assets/42d551de-6adb-4a1c-b278-a11d212079ba" />`

### ✅ Conclusion

The MAC address and vendor identify the network interface used by Briana’s machine.

**Answer:**
bc:ea:fa:22:74:fb, Hewlett Packard
## 4️⃣ Briana’s Windows Machine Name

**Question:**  
What is Briana’s Windows machine name?

### 🔍 Methodology

* Filtered for **SMTP traffic**
* Inspected outbound messages and metadata
* Extracted the hostname from **EHLO** and email subject fields

📸 *Screenshot:* `<img width="1529" height="127" alt="q4" src="https://github.com/user-attachments/assets/12ac615b-00b8-4c6d-8961-d904a1bba270" />`


### ✅ Conclusion

The hostname uniquely identifies Briana’s Windows system.

**Answer:**
DESKTOP-WIN11PC
## 5️⃣ Briana’s Windows Username

**Question:**  
What is Briana’s Windows username?

### 🔍 Methodology

* Reviewed **SMTP DATA** sections containing system metadata
* Identified malware-exfiltrated credential information
* Extracted the Windows username value

📸 *Screenshot:* `<img width="842" height="137" alt="q7 5 and 8" src="https://github.com/user-attachments/assets/93d649c6-77b6-48b2-984d-645110c1c095" />`


### ✅ Conclusion

This username corresponds to the logged-in Windows user on the infected host.

**Answer:**
admin@windows11users.com
## 6️⃣ Attacker Email Address Used for Exfiltration

**Question:**  
What email address was the attacker sending data to?

### 🔍 Methodology

* Inspected SMTP **RCPT TO** fields
* Identified the external destination inbox used to receive stolen data

📸 *Screenshot:* `<img width="1307" height="40" alt="q6" src="https://github.com/user-attachments/assets/ed9516a8-aef2-45b8-9dcc-0c0db045c0bf" />`


### ✅ Conclusion

This email address was controlled by the attacker and used for data exfiltration.

**Answer:**
zaritkt@arhitektkondizajn.com
## 7️⃣ CPU Type of Briana’s Computer

**Question:**  
What type of CPU does Briana’s computer use?

### 🔍 Methodology

* Examined system information embedded in SMTP exfiltrated data
* Extracted the CPU field

📸 *Screenshot:* `<img width="842" height="137" alt="q7 5 and 8" src="https://github.com/user-attachments/assets/8d2b9ca7-3236-470c-a0d4-995a91a790dd" />`


### ✅ Conclusion

This identifies the processor used by Briana’s system.

**Answer:**
Intel(R) Core(TM) i5-13600K CPU @ 5.10GHz

## 8️⃣ Amount of RAM Installed

**Question:**  
How much RAM does Briana’s computer have?

### 🔍 Methodology

* Extracted RAM information from system metadata
* Converted the reported value into gigabytes

📸 *Screenshot:* `<img width="842" height="137" alt="q7 5 and 8" src="https://github.com/user-attachments/assets/55a48f6b-f096-4260-8e02-6e9e7223c0cd" />`


### ✅ Conclusion

This reflects the total installed system memory.

**Answer:**
32GB
## 9️⃣ Type of Account Login Data Stolen

**Question:**  
What type of account login data was stolen by the attacker?

### 🔍 Methodology

* Reviewed SMTP exfiltration payloads
* Observed repeated credential fields across multiple services

📸 *Screenshot:* `<img width="806" height="155" alt="q9" src="https://github.com/user-attachments/assets/74988f0b-68a5-464b-be6b-6a82babbfb6c" />`


### ✅ Conclusion

The attacker stole authentication credentials.

**Answer:**
Username,Password
## 🔟 Amazon Account Credentials

**Question:**  
What are the username and password related to the Amazon account?

### 🔍 Methodology

* Located Amazon-specific credential block inside SMTP DATA
* Extracted the explicitly listed username and password


📸 *Screenshot:* `<img width="640" height="461" alt="q10" src="https://github.com/user-attachments/assets/1c9a0c88-4d5f-4879-a734-6e9642f0cb11" />`


### ✅ Conclusion

These credentials belong to the compromised Amazon account.

**Answer:**
admin@windows11users.com ,3F076#TF4P$Im!9mkLs069eTk
## 1️⃣1️⃣ Username Used to Authenticate to webhostbox[.]net

**Question:**  
What username did Briana use to authenticate to webhostbox[.]net?

### 🔍 Methodology

* Followed the **SMTP AUTH LOGIN** TCP stream
* Identified the Base64-encoded username
* Decoded the value using CyberChef

📸 *Screenshot:* `<img width="959" height="897" alt="q11" src="https://github.com/user-attachments/assets/a2831109-76b6-4112-8069-79e978597f20" />`


### ✅ Conclusion

This username was used during SMTP authentication.

**Answer:**
marketing@transgear.in

## 1️⃣2️⃣ Password Used to Authenticate to webhostbox[.]net

**Question:**  
What password did Briana use to authenticate to webhostbox[.]net?

### 🔍 Methodology

* Continued analysis of the same SMTP AUTH LOGIN TCP stream
* Identified the password token used during authentication

📸 *Screenshot:* `<img width="965" height="886" alt="q12" src="https://github.com/user-attachments/assets/9bb3c07c-c0c2-4b65-aa06-f9455e40bd1d" />`


### ✅ Conclusion

This value represents the password used for SMTP authentication.

**Answer:**
M@ssw0rd#621

## 🧩 Final Notes

This investigation demonstrates a **complete blue-team workflow**:

* Initial access identification via network traffic analysis  
* Host attribution and system profiling  
* Credential theft and SMTP exfiltration detection  
* Protocol-level authentication analysis  

The findings were derived directly from packet evidence using repeatable forensic methods.

---

✅ **All questions successfully solved**
