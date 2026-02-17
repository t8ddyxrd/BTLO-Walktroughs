# 🛡️ BTLO Investigation Walkthrough – RobCo / Enclave

> **Platform:** Blue Team Labs Online (BTLO)  
> **Investigation Type:** Malicious File Analysis  
> **Focus:** File masquerading & initial indicator validation  

---

## 📌 Executive Summary

This investigation begins with the analysis of a suspicious image file discovered on **Luis Harrold’s device**. Although the file appeared to be a standard image based on its `.png` extension, further inspection was required to determine whether the file had been **masqueraded to conceal malicious content**.

Identifying the true file type is a critical first step, as it determines the appropriate analysis techniques and helps assess the potential threat posed by the file.

---

## 1️⃣ Identifying the True File Type

### ❓ Question
Looking into it further, what is the true file type of this image?

### 📸 Evidence
The Linux `file` utility was used to inspect the actual file type rather than relying on the file extension.

```bash```
`<img width="763" height="318" alt="q1" src="https://github.com/user-attachments/assets/f14ac980-fb01-4983-b474-8ac75a7375a8" />``



### 🧠 Finding

Despite the .png extension, the file is identified as a PDF document (version 1.4). This confirms that the file is masquerading as an image, a common technique used to bypass user suspicion and basic security controls.

### ✅ Answer
PDF




