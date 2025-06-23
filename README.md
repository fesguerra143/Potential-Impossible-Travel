


# 🛡️ Incident Response: Brute-Force Attempts Detected

# Objective:
Identify and analyze potential brute-force logon attempts across the environment.

---
# Tools & Technology:
- Azure Virtual Machine
- Microsoft Sentinel
- Log Analytics Workspace
- KQL Query

---
# Table of contents

- [1. Summary](#1-summary)
- [2. Initial Detection & Analysis](#2-initial-detection--analysis)
- [3. Investigation](#3-investigation)
- [4. Containment Actions Taken](#4-containment-actions-taken)
---



## 1. Summary
Date of Notes: June 21, 2025 <br />
Incident Type: Brute-Force Logon Attempts <br />
Status: Contained <br />


## 2. Initial Detection & Analysis
### Methodology:
An analytics rule (potentially in Microsoft Sentinel) was configured to detect a high volume of failed logon attempts. The following Kusto Query Language (KQL) query was utilized to identify devices experiencing a significant number of LogonFailed events within a 5-hour window:



### Microsoft Sentinel: Configuration → Analytics Rule Creation
#### General Settings:
![analyticrulecreation1](https://github.com/user-attachments/assets/6c5e6703-b27d-474c-ad29-b778f9670970)

#### Set rule logic Settings:
![analyticrulecreation2](https://github.com/user-attachments/assets/d5f943cc-c7f0-4264-92bb-993c3b4f903d)

##### Rule logic Testing using Log Analytics Workspace

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10

```
![loganalytics1](https://github.com/user-attachments/assets/0bebfefd-9528-4265-adc0-0e091d19dbc6)

#### Incident Settings:

![analyticrulecreation3](https://github.com/user-attachments/assets/01a56ba6-c909-423b-9778-ce9994960127)


#### Review and Create: 
![analyticrulecreation4](https://github.com/user-attachments/assets/282d098e-0d13-44c4-9072-fc3fcbb969ef)


### Microsoft Sentinel: Threat Management → Incidents

![analyticrulecreation5](https://github.com/user-attachments/assets/ebabf39d-2aef-44cb-865f-a4dcaefaab79)

![analyticrulecreation6](https://github.com/user-attachments/assets/ae021b2e-0c12-4117-a39b-960baa895c98)


### 📊 Analysis
A brute force detection rule in Microsoft Sentinel flagged multiple failed login attempts originating from two distinct public IP addresses. These were targeting two separate virtual machines in our environment:

| Remote IP      | Target VM      | Failed Logons |
| -------------- | -------------- | ------------- |
| 27.124.47.210  | panbear-2nd-vm | 26            |
| 103.159.255.76 | hercules-soc   | 40            |


## 3. Investigation
#### ✅ Verification of Access Attempts
A follow-up query was used to verify whether any of the suspicious IP addresses had successful logins:

```kql
DeviceLogonEvents
| where RemoteIP in ("27.124.47.210", "103.159.255.76")
| where ActionType != "LogonFailed"
```
![analyticrulecreation7](https://github.com/user-attachments/assets/4136541e-8f34-4b73-96c5-6739739fbed9)

#### Result:
🔒 No successful logins were observed from the flagged IP addresses.

#### Incident Activity Log:

![analyticrulecreation9](https://github.com/user-attachments/assets/27ec9ba3-4c1b-4f9c-9bee-eb0107635b36)

![analyticrulecreation10](https://github.com/user-attachments/assets/6f0f979b-95a5-4717-80e3-ac65a15a17ae)


## 4. Containment Actions Taken
### Isolated Devices:
Both panbear-2nd-vm and hercules-soc were isolated in Microsoft Defender for Endpoint (MDE) to prevent further compromise.

###  Malware Scan:
A full anti-malware scan was initiated and completed on both VMs using MDE.

###  NSG Lockdown:
Network Security Group (NSG) rules were updated:
RDP access from the public internet was blocked.
Only the investigator’s home IP is currently allowed RDP access.
A Bastion host was proposed as a more secure alternative for future access.

### Policy Recommendation:
A recommendation has been submitted to enforce restricted RDP access for all virtual machines across the environment.
