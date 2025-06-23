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
A total of 38 user accounts were flagged for potential impossible travel events based on logins from multiple geographic regions within a short time window. Upon investigation, most accounts showed login activity that was reasonable and within expected travel timeframes. However, one user was found to exhibit highly suspicious behavior.

✅ Benign Accounts
The following accounts showed no signs of compromise. All login attempts occurred within the same country and plausible travel timelines:

4e122e9d51e9b00071f10e1ee3037f485ab8889007b1fd516162f9c292cc0be1@lognpacific.com

d20f692f7709ac4d9aab6d97dcf562b2cb8091753d448a02dc4f7971cc4cd759@lognpacific.com

ea0365054ad134cfdaa92b0f9ca82e52dd107233780bbc292e48873a0e7dcdd3@lognpacific.com

9f70b6b2ead907b656636d76ba0e504891f1d33097ba8d30cf1f955ab91f00d3@lognpacific.com

3eb65d404a37eeaf6387796fad6f35913a03b04e963a8dbe274f1507151e3f84@lognpacific.com

5a1a409ddae648ace835da2376f9b16ffc87e31769233f69fcf269fadcad2f64@lognpacific.com

05052212485141aa60d9344755217508aa48c758dff6d0061c43cb6366ac7fb9@lognpacific.com

cdf38e188df8889ea023840f8f26bb0b4fa6c0f87cd9764b56cd80cfa2ed2e78@lognpacific.com

9c9ecf443bab503c2016bba334a806279b07532911585da6a5b76432bb6877df@lognpacific.com

8a8d661894fa5534013237658692a56123b7cad0a2d74f337c758d352da76e73@lognpacific.com

d192a4eb8adec8d1264074bca42d83b8fdffd7e07b82e110358deedb17644d68@lognpacific.com

arisa_admin@lognpacific.com

### Verified each suspicious account using the query below: 

```kql
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == "4e122e9d51e9b00071f10e1ee3037f485ab8889007b1fd516162f9c292cc0be1@lognpacific.com"
| project TimeGenerated, UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc 
```
![pic10](https://github.com/user-attachments/assets/b4ecc452-56a4-4fc5-9fbb-203c7ee027aa)


#### Results: All of these accounts were determined to be Benign Positives.

## 3. Investigation
#### ✅ Identified True Positive:
User:
667e503b5c6895297d79a49dbe21b8b53a147fb504da9e93cb9cd03ff65d7336@lognpacific.com
User ID: 9bff0192-2e00-489e-b7f2-e73e019cc908

```kql
// Investigate Potential Impossible Travel Instances
let TargetUserPrincipalName = "667e503b5c6895297d79a49dbe21b8b53a147fb504da9e93cb9cd03ff65d7336@lognpacific.com";
let TimePeriodThreshold = timespan(7d);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```
#### Result:
This account exhibited impossible travel behavior by logging in from San Jose, California and Shilin, Taipei within short time intervals that do not allow for realistic travel. Below are the observed logins:
| Timestamp (UTC)        | City     | Country |
| ---------------------- | -------- | ------- |
| 6/17/2025, 03:23:58 AM | San Jose | US      |
| 6/17/2025, 06:52:58 AM | Taipei   | TW      |
| 6/17/2025, 06:54:55 AM | Taipei   | TW      |
| 6/18/2025, 10:04:53 AM | San Jose | US      |
| 6/18/2025, 10:06:27 AM | San Jose | US      |
| 6/18/2025, 10:23:33 PM | Taipei   | TW      |

![pic11](https://github.com/user-attachments/assets/d8789a38-5c29-4891-82c7-bd2e1eef145c)

#### Azure Activity Log:

![pic12](https://github.com/user-attachments/assets/00ff250b-87ca-4db9-82e8-5ada036e6eb7)

#### Update Microsoft Sentinel Incidents Activity Log:
![pic13](https://github.com/user-attachments/assets/94f63e6b-06ad-405a-988f-d46b1aa5f03e)


![pic14](https://github.com/user-attachments/assets/6412979b-d0dd-4005-a562-3397cb3f1170)

## 4. Containment, Eradication, and Recovery
✅ Status: Confirmed True Positive

🛑 Action Taken:

The user’s account was immediately disabled in Azure Active Directory.

The incident was escalated to management for further investigation.


