# 🛡️ 🛡️ BTLO Investigation Walkthrough-Vault

> **Platform:** Azure / Blue Team Labs Online (BTLO-style)  
> **Investigation Focus:** Azure Sign-In Logs & Key Vault Diagnostic Logs  
> **Primary Tooling:** Timeline Explorer, Azure Sign-In Logs, Azure Key Vault Diagnostics

---

## 📌 Executive Summary

This investigation analyzes **Azure Sign-In Logs** and **Azure Key Vault Diagnostic Logs** to trace suspicious authentication activity originating from an external IP address and to fully attribute subsequent **Key Vault access and enumeration activity**.

The analysis confirms that a legitimate Azure user authenticated successfully, after which **automated Key Vault operations** were performed within the **FINANCE** resource group. Activity was conducted using **Azure CLI, Azure SDK for Python, and Microsoft Azure PowerShell**, resulting in enumeration of **Key Vaults, keys, and secrets**.

---

## 🧬 Investigation Flow

1. Identify suspicious sign-in activity
2. Attribute authentication to user and account type
3. Correlate sign-in with Key Vault diagnostics
4. Identify application, user-agent, and tooling
5. Enumerate affected Key Vaults, keys, and secrets
6. Attribute specific operations via correlation IDs

---

## 🧠 Analyst Mindset & Investigation Framing

This investigation was conducted using a **hypothesis-driven SOC workflow**, mirroring how real-world cloud incidents are handled in enterprise Security Operations Centers.

Rather than treating each alert or log entry in isolation, identity telemetry (Azure Sign-In Logs) was **continuously correlated** with Azure Key Vault Diagnostic Logs using timestamps, subscription IDs, application IDs, and correlation IDs to reconstruct a complete activity chain.

At each stage, the analyst deliberately:
- Formed an initial hypothesis based on observable indicators (external IP address, token type, application usage)
- Tested that hypothesis by pivoting across log sources and narrowing scope using deterministic identifiers
- Explicitly ruled out benign background activity (platform-managed services, routine Azure operations)
- Assessed **impact**, focusing on which cryptographic assets (keys/secrets) were exposed and how

This methodology reflects modern cloud SOC operations, where activity is often **legitimate in isolation** but becomes risky when combined. The investigation demonstrates how administrative tooling (CLI, SDKs, PowerShell) can be differentiated and attributed with high confidence.

---

1. Identify suspicious sign-in activity
2. Attribute authentication to user and account type
3. Correlate sign-in with Key Vault diagnostics
4. Identify application, user-agent, and tooling
5. Enumerate affected Key Vaults, keys, and secrets
6. Attribute specific operations via correlation IDs

---

## Q1) Identify the individual associated with the login from the suspicious IP `201.231.8.199`

**Why this matters:** Identity attribution is the foundation of cloud investigations. Confirming the exact user prevents misattribution to service principals or background Azure activity.



### 📸 Evidence
<img width="115" height="297" alt="q1 part 1" src="https://github.com/user-attachments/assets/7a1ebaeb-1167-41ac-8ef6-4d3d5bf65a99" />
<img width="170" height="296" alt="q1 part 2" src="https://github.com/user-attachments/assets/dae4d7c5-9bc0-4a3c-b000-1fe6b820363d" />


### ✅ Answer
```
Miriam Graham
```

---

## Q2) Determine the User Principal Name (UPN) of the identified user

**Why this matters:** The UPN uniquely identifies the account within Entra ID and enables accurate correlation across identity, resource, and audit logs.



### 📸 Evidence
<img width="221" height="295" alt="q2" src="https://github.com/user-attachments/assets/a2fa4fcd-d53f-46ef-8829-a3452530847d" />


### ✅ Answer
```
MiriamG@bank.onmicrosoft.com
```

---

## Q3) Ascertain whether the user is categorized as a member, guest, or external account

**Why this matters:** Account type determines trust level. Member accounts typically have broader access and represent higher risk when compromised.



### 📸 Evidence
<img width="96" height="306" alt="q3" src="https://github.com/user-attachments/assets/353b1639-ffdc-4641-890a-8a3dbacd3933" />


### ✅ Answer
```
Member
```

---

## Q4) Identify the token type issued to the user

**Why this matters:** Token type reveals session persistence and reuse potential. Refresh tokens significantly increase blast radius if abused.



### 📸 Evidence
<img width="173" height="290" alt="q4" src="https://github.com/user-attachments/assets/61bb53ec-52eb-4cdc-93e9-fd9e28dca101" />


### ✅ Answer
```
PrimaryRefreshToken
```

---

## Q5) Was any Conditional Access policy applied during sign-in?

**Why this matters:** Lack of Conditional Access enforcement exposes cloud resources to unauthorized access from unmanaged locations.



### 📸 Evidence
<img width="168" height="298" alt="q5" src="https://github.com/user-attachments/assets/31903277-bf89-4721-8d86-6dd112494f54" />


### ✅ Answer
```
No
```

---

## Q6) Provide the subscription ID for the user who accessed the Key Vaults

**Why this matters:** Subscription scope defines the boundary of impact and determines which assets must be reviewed for exposure.



### 📸 Evidence
<img width="280" height="710" alt="q6" src="https://github.com/user-attachments/assets/4df27f49-16f9-4140-bd80-45cc052fedca" />


### ✅ Answer
```
12az1234-04by-4e50-1e11-c00ae123d0bd
```

---

## Q7) Identify the resource group where the Key Vaults were accessed

**Why this matters:** Resource groups logically separate business functions. Access to sensitive groups like FINANCE elevates severity.



### 📸 Evidence
<img width="163" height="721" alt="q7" src="https://github.com/user-attachments/assets/1f36c2c4-2d64-4d35-b0f6-fd852f2b42d3" />

### ✅ Answer
```
Finance
```

---

## Q8) Determine the total number of Key Vaults present in the identified resource group

**Why this matters:** Enumerating Key Vault count establishes attack surface size and potential data exposure.



### 📸 Evidence
<img width="888" height="707" alt="q8" src="https://github.com/user-attachments/assets/2ca0fe62-fe37-403f-a2be-bdf27cc3fcc5" />


### ✅ Answer
```
2
```

---

## Q9) How many operations were executed using the application ID

**Why this matters:** Operation volume helps distinguish normal administrative access from scripted or automated enumeration.

 `04b07795-8ddb-461a-bbee-02f9e1bf7b46`

### 📸 Evidence
<img width="1539" height="812" alt="q9" src="https://github.com/user-attachments/assets/f21c0e17-90f5-4b03-9e34-cd1f9c8879d1" />


### ✅ Answer
```
14
```

---

## Q10) Retrieve the application display name associated with the application ID

**Why this matters:** Application attribution identifies the tooling used and enables behavioral baselining.



### 📸 Evidence
<img width="275" height="194" alt="q10" src="https://github.com/user-attachments/assets/7579914c-e743-4286-8fc0-8d85f511cdff" />


### ✅ Answer
```
Microsoft Azure CLI
```

---

## Q11) Identify the User-Agent associated with key-related operations

**Why this matters:** User-Agent strings reveal SDKs, languages, and execution environments used during sensitive operations.



### 📸 Evidence
<img width="801" height="633" alt="q11" src="https://github.com/user-attachments/assets/3beb64f2-f722-4323-9ddc-7df73fd9c814" />


### ✅ Answer
```
azsdk-python-keyvault-keys/4.9.0b3 Python/3.11.5 (Windows-10.0.19044-SP0)
```

---

## Q12) Identify the specific Key Vault where a key was identified

**Why this matters:** Pinpointing the vault allows targeted access review and key rotation decisions.



### 📸 Evidence
<img width="396" height="637" alt="q12" src="https://github.com/user-attachments/assets/60e11b91-4276-41ed-bde5-afc9a92128da" />


### ✅ Answer
```
SALARY
```

---

## Q13) Provide the name of the key present in the identified Key Vault

**Why this matters:** Key names often reflect business function and sensitivity, informing incident severity.



### 📸 Evidence
<img width="1247" height="704" alt="q13" src="https://github.com/user-attachments/assets/23e9a820-da66-46c4-8069-d288fd530396" />


### ✅ Answer
```
Payroll
```

---

## Q14) Identify the secret name found in one of the Key Vaults

**Why this matters:** Secrets typically store credentials or tokens; exposure can lead to downstream compromise.



### 📸 Evidence
<img width="573" height="73" alt="q14" src="https://github.com/user-attachments/assets/481f6bf4-8c19-4885-acdf-323825a3ec88" />


### ✅ Answer
```
Confidential
```

---

## Q15) Determine the operation associated with the correlation ID

**Why this matters:** Correlation IDs allow precise reconstruction of individual actions across distributed logs.

 `9c059db6-eb2f-4085-9979-4c94a5b19b0d`

### 📸 Evidence
<img width="580" height="109" alt="q15" src="https://github.com/user-attachments/assets/23a34c4e-7138-49dc-b7e0-e44aab118395" />


### ✅ Answer
```
KeyList
```

---

## Q16) Identify the application associated with the aforementioned operation

**Why this matters:** Final application attribution completes the kill-chain and enables accurate reporting and remediation.



### 📸 Evidence
<img width="1333" height="342" alt="q16" src="https://github.com/user-attachments/assets/435eaa69-93e9-4817-8f53-45a41799e8b3" />


### ✅ Answer
```
Microsoft Azure PowerShell
```

---

## 🎯 Final Assessment

The activity observed represents **legitimate but high-risk administrative behavior**. Successful authentication from an external IP, combined with the absence of Conditional Access enforcement and extensive Key Vault enumeration, highlights significant exposure risk.

This investigation demonstrates how **correlating identity, application, and Key Vault telemetry** enables precise attribution of cloud activity and supports effective SOC-level cloud investigations.

---

✅ **All questions Q1–Q16 have been fully mapped, evidenced, and documented.**

