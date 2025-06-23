# Potential Impossible Travel Project

##  🛡️ Incident Response: Impossible Travel Alert Investigation

# Objective:
Investigate and validate potential "Impossible Travel" alerts triggered by unusual user logon patterns across multiple geographic regions.

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
Incident Type: Potential Impossible Travel (User Logon Anomaly) <br />
Status: Contained <br />


## 2. Initial Detection & Analysis
### Methodology:
An Azure Sentinel Scheduled Query Rule, designed to identify users logging in from more than two different geographic regions within a 7-day period, flagged a total of 38 accounts for potential "Impossible Travel." The initial detection was based on the following KQL query against the SigninLogs table:


### Microsoft Sentinel: Configuration → Analytics Rule Creation
#### General Settings:
![pic3](https://github.com/user-attachments/assets/59e104d7-fc55-46b9-904f-6288eb3e54b2)

#### Set rule logic Settings:

![pic4](https://github.com/user-attachments/assets/660e28e0-45d1-467a-b823-8ee2518aeaee)

##### Rule logic Testing using Log Analytics Workspace

```kql
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed

```
![pic2](https://github.com/user-attachments/assets/481243fa-d7e9-49e2-945f-ab3e5c454718)


#### Incident Settings:


![pic5](https://github.com/user-attachments/assets/adf2d1a5-4c5e-4a03-a047-6817a3821a9c)


#### Review and Create: 


![pic6](https://github.com/user-attachments/assets/1a63b340-3759-4b7c-9929-4e21502e0a88)

### Microsoft Sentinel: Threat Management → Incidents

![pic7](https://github.com/user-attachments/assets/e8744eaa-11e8-43ec-9404-92cfe2878999)



![pic8](https://github.com/user-attachments/assets/d759a91b-179a-4805-b09e-4f5e42ab766f)


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
