# 🚨 Incident Report: Create Alert Rule (Potential Impossible Travel) 🚨

## 📝 **Explanation**  
Corporations often have strict policies prohibiting:  
- 🌍 Logging in from multiple geographic regions outside designated areas.  
- 🔄 Account sharing (a standard security measure).  
- 🛡️ Using non-corporate VPNs.  

This scenario detects unusual activity, such as logins from **multiple geographic regions** within a short time frame.  

Whenever a user logs into Azure or authenticates with their main Azure account, logs are created in the **"SigninLogs"** table and forwarded to the **Log Analytics workspace** used by Microsoft Sentinel (our SIEM).  

### **Detection Objective:**  
Trigger an alert in Sentinel if a user logs into more than **one location** within a 7-day time period. Not all alerts will indicate malicious activity, as some may be false positives.  

---

## 🚦 **Creating the Alert Rule (Potential Impossible Travel)**  
**Objective:**  
Set up a Sentinel **Scheduled Query Rule** in Log Analytics to detect users logging into multiple geographic regions.  

### **Rule Configuration Details:**  
1. **Trigger Conditions:**  
   - A user logs into two or more distinct locations within 7 days.  

2. **KQL Query:**

```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
``` 
```kql
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationAllowed = 1;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize count() by UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationAllowed
```
 ![image](https://github.com/user-attachments/assets/7b17f159-abfc-45b1-a448-b87f7dd30487)


3. **Analytics Rule Settings:**  
   - **Name:** Potential Impossible Travel Alert  
   - **Description:** Detects logins from multiple geographic regions.  
   - ✅ Enable the Rule.  
   - 🔄 Run Query Every 4 Hours.  
   - 📅 Lookup Data for the Last 24 Hours.  
   - ❌ Stop Running Query After Alert is Generated.  

4. **Entity Mappings:**  
   - **Account ID:** AadUserId → `UserId`  
   - **Display Name:** UserPrincipalName → `Value`  

---

## 🔍 Detection and Analysis

1. # 🧪 Steps to Validate Incident

- ✅ Assign the incident to yourself and set the status to **Active**.
- 🔄 Use **Investigate** to review entities (may take time).
- 📊 Examine output from the analytics rule to identify flagged accounts.


### 🧪 Query Used for Investigation

```kusto
let TimePeriodThreshold = timespan(7d); 
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == "bc8ade461d58a18b6a0b88842a4d36c2a5417b06023345b8333d2b82b07ec965@lognpacific.com"
   or UserPrincipalName == "c6a39b587ff1ebcf3da2040b489b6319269a8fc0911ac0915a1bdd938160244b@lognpacific.com"
| project TimeGenerated, UserPrincipalName,
          City = tostring(parse_json(LocationDetails).city),
          State = tostring(parse_json(LocationDetails).state),
          Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc

```

## 📌 **Flagged Accounts**

- **User 1:** `bc8ade461d58a18b6a0b88842a4d36c2a5417b06023345b8333d2b82b07ec965@lognpacific.com`  
  **Object ID:** `686eb047-f961-4073-b292-b8bb2c8911db`  
  **Detected Instances:** 3

- **User 2:** `c6a39b587ff1ebcf3da2040b489b6319269a8fc0911ac0915a1bdd938160244b@lognpacific.com`  
  **Object ID:** `30688920-e870-49db-82f3-fc9e12135daa`  
  **Detected Instances:** 3

# 🔎 **Observed Findings**

It was determined that the alert was **TRUE BENIGN**.

- User `bc8ade461d58a18b6a0b88842a4d36c2a5417b06023345b8333d2b82b07ec965@lognpacific.com` logged into **Toronto** and **North York, Canada** within a **1-hour** time period, which is not uncommon.

- User `c6a39b587ff1ebcf3da2040b489b6319269a8fc0911ac0915a1bdd938160244b@lognpacific.com` logged into **Santa Ana** and **Pasig City, Philippines** within a **2-hour** time period, which is not uncommon.

`

## 🛠️ **Containment, Eradication, and Recovery**  

- **Outcome:**  
   The alert was determined to be **True Benign**:  
   - Account activity aligned with expected behavior.  
   - Users logged into locations within reasonable proximity and timeframes.  

- **Next Steps:**  
   - 🔍 Pivot to analyze additional activity for these accounts using:  
     ```kql
     AzureActivity
     | where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "AzureADObjectID"
     ```  
   - **If suspicious behavior is detected**, disable the account and escalate.  

---

## 🔄 **Post-Incident Activities**  
1. **Policy Updates:**  
   - Implement a **geo-fencing policy** in Azure to restrict logins outside specific regions.  
2. **Documentation:**  
   - Record all findings and lessons learned in the incident management system.  

---

## ✅ **Closure**  
1. **Review Incident:**  
   - Confirm resolution and update notes.  
   - Mark the incident as a **Benign Positive** or **False Positive** (based on findings).  
2. **Finalize Report:**  
   - Submit the report and close the case in Sentinel.  

📌 **Status:** Closed as **Benign Positive**.  

---

**✨ Lessons Learned:**  
- Better geographic restrictions can enhance security.  
- Not all triggers are threats; careful analysis prevents unnecessary escalations.  

