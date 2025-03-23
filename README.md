



---

# 🚨 Incident Response: Brute Force Attempt Detection

![image](https://github.com/user-attachments/assets/078932c1-3e7e-48cf-a0c1-1cd787336ce6)

---

## Scenario Context
During routine monitoring, I identified a pattern of repeated failed login attempts targeting privileged accounts within our Microsoft Azure environment. These attempts primarily occurred outside of standard business hours and may indicate a brute-force or credential-stuffing attack in progress.

In accordance with **NIST SP 800-61** guidelines, I have initiated an investigation to validate the threat, assess its scope, and implement appropriate containment and mitigation measures.

---

## 🔍 **Objective: Find Brute Force and Create Sentinel Scheduled Query Rule**
Implement a **Sentinel Scheduled Query Rule** using KQL in Log Analytics to detect when the same remote IP address fails to log in to the same Azure VM 50+ times within a 5-hour period.

---

## 🛠️ **Platforms and Tools**
- **Microsoft Sentinel**
- **Microsoft Defender for Endpoint**
- **Kusto Query Language (KQL)**
- **Windows 10 Virtual Machines (Microsoft Azure)**

---

## **Incident Response Phases**
### 1️⃣ Preparation

1. **Policies and Guidelines:**
   - Define standard procedures for responding to brute-force login attempts, account lockouts, and recovery workflows.
   - Include predefined steps for alerting, temporarily disabling accounts, and reporting suspicious login behavior.

2. **Access Monitoring and Logging:**
   - Ensure comprehensive logging of authentication attempts within Azure AD.
   - Leverage **Microsoft Defender for Identity** and **Azure Sentinel** for real-time threat detection and automated alerting.

3. **Security Team Readiness:**
   - Conduct regular training sessions focused on identifying and responding to credential-based attacks such as brute force and credential stuffing.

4. **Incident Communication Strategy:**
   - Develop a clear escalation process involving IT support and owners of privileged accounts in the event of an incident.


---

### 2️⃣ Detection & Analysis
#### Observations:
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
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 50
| order by TimeGenerated desc
```
![image](https://github.com/user-attachments/assets/e865614b-1402-4587-8951-e8a6e52e413c)



- **Three Azure VMs** were targeted by brute force attempts from **three public IPs**:
  
  | **Remote IP**       | **Failed Attempts** | **Target Machine**    |
  |---------------------|---------------------|-----------------------|
  | `122.4.92.3`    | 100                 | `justin-mde-lab-`    |
  | `185.7.214.14`     | 98                 | `kevlarvm`    |
  | `10.0.0.8`    | 98, 69                 | `linux-vm-vm-test-steve, windowsstig`     |

  ![image](https://github.com/user-attachments/assets/67c62c47-69d9-4266-be89-3b0780b2f7cf)


- KQL Query to detect failed logins:  
  ```kql
  DeviceLogonEvents
  | where RemoteIP in ("122.4.92.3", "185.7.214.14", "10.0.0.8" )
  | where ActionType != "LogonFailed"
  ```

  **Result:** No successful logins from these IPs were detected.

#### Analysis Steps:
1. **Review Patterns:**
   - Analyzed Azure AD sign-in logs to assess failed login attempt thresholds.
   - Detected unusual activity occurring outside business hours and originating from suspicious geolocations.

2. **Document Findings:**
   - Collected and archived logs showing attempt frequency, source IPs, and affected user accounts.

3. **Prioritize:**
   - **High Priority:** Privileged accounts targeted during off-hours.
   - **Low Priority:** Isolated, user-specific failed attempts.

---

### 3️⃣ Containment
#### Immediate Actions:
1. **Device Isolation:**
   - Isolated affected devices using **Microsoft Defender for Endpoint**.

2. **Network Security Group (NSG) Update:**
   - Restricted RDP access to authorized IPs only.
   - Blocked all external IPs linked to failed login attempts.

3. **Anti-Malware Scans:**
   - Performed scans on affected devices for potential compromise.

---

### 4️⃣ Eradication & Recovery

1. **Credential Renewal:**
   - Issued password resets for impacted user accounts.
   - Applied stricter password requirements to privileged accounts.

2. **Multi-Factor Authentication (MFA):**
   - Activated MFA for all critical and high-privilege user accounts.

3. **Location-Based Restrictions:**
   - Implemented geo-blocking to prevent access from known high-risk regions.

---

### 5️⃣ Post-Incident Activity

1. **Review and Reflection:**
   - Assessed the speed and effectiveness of detection measures.
   - Evaluated the security posture of privileged accounts during the incident.

2. **Security Enhancements:**
   - Refined login alert thresholds to improve detection accuracy.
   - Increased user awareness through updated training on secure password practices.

3. **Incident Documentation:**
   - Logged detailed findings, response actions, and proposed improvements for future prevention.

---

### **Step 1: Create an Alert Rule**

To create an alert rule in Microsoft Sentinel:

1. Open **Microsoft Sentinel**.
2. Select your workspace.
3. Navigate to **Configuration** > **Analytics**.
4. Click the **➕ Create** button and choose **Scheduled query rule**.

After selecting **"Scheduled query rule"**, you’ll be taken to the **Analytics rule details** page. Complete the following fields:

1. **Name**:  
   - Assign a rule name, such as **"🔥 Brute Force Login Attempt Alert 🔐"**.

2. **Description**:  
   - Briefly explain the rule’s purpose, for example:  
     *"🔍 Identifies potential brute-force attacks by detecting multiple failed login attempts beyond a specific threshold."*

3. **Severity**:  
   - Set the alert’s severity:
     - **Low** 🟢  
     - **Medium** 🟡  
     - **High** 🔴 

4. **Tactics**:  
   - Choose relevant **MITRE ATT&CK tactics** that align with brute-force activity:
     - **🎯 Initial Access**  
     - **🔑 Credential Access**

      
![image](https://github.com/user-attachments/assets/aff8696a-1f58-4506-95b4-96d43bd51e4b)


5. **Rule type**:  
   - Select **Scheduled 🕒**.

6. **Set rule frequency**:  
   - Choose how often the query should run (e.g., **Every 4 hours ⏱️**).

7. **Set query results to look back**:  
   - Define the time window for the query (e.g., **Last 5 hours ⏳**).

---

### **Step 2: Add the KQL Query**  
In the **Set rule query** step, paste your KQL query to detect brute-force attempts:  

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 50
| order by TimeGenerated desc
```
![image](https://github.com/user-attachments/assets/75dedd96-254f-41bc-9b49-5edad6f0ffcf)


- 🛠️ This query scans **sign-in logs** for failed authentication attempts and highlights suspicious activity patterns.  
- 💡 Customize the threshold to fit your environment (e.g., `more than 10 failed attempts`).

---

### **Step 3: Define Incident Settings**  
1. **Create incidents based on alert results**: Ensure this is selected ✅.  
2. **Group alerts into incidents**:  
   - Choose **"🧩 Grouped into a single incident if they share the same entities"** to avoid duplicates.

---

### **Step 4: Add Actions and Automation**  
1. Configure **actions** to trigger when the rule is activated:  
   - Add a **Playbook 🛠️** for automated responses, such as:  
     - Blocking an IP 🚫.  
     - Sending an email to your security team 📧.  
     - Triggering a Teams or Slack notification 💬.  

2. Example Playbook: A Logic App that sends an **email notification 📤** to the SOC.

---

### **Step 5: Review and Enable**  
1. **Review everything** to ensure it’s correct:
   - Name 🔖, description 📝, KQL query 📊, frequency ⏱️, and action settings ⚙️.  

2. Click **"Create"** to enable the rule 🎉.  

---

### **Step 6: Validate Your Rule**  
1. Test the rule by simulating a brute-force attack or using sample logs:
   - Run a script that triggers **failed login attempts** (simulated safely) 🧑‍💻.
   - Replay historical logs using KQL 📜.

2. Verify that alerts are generated 🚨 and incidents are grouped as expected ✅.  
---
## 🚫 **Outcome**
- **Attack Status:** Brute force attempts **unsuccessful**.  
- **Recommendations:** Lockdown NSG rules for all VMs and enforce MFA on privileged accounts.

🎉 **Status:** Incident resolved. No further action required.

---
