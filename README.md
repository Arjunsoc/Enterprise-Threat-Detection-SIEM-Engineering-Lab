# Enterprise-Threat-Detection-SIEM-Engineering-La


## Project Overview
This project documents the development and validation of a centralized security monitoring and detection pipeline using Wazuh SIEM. The lab focuses on configuring endpoint telemetry via Sysmon, engineering custom XML rules, implementing Constant Data Database (CDB) whitelists, and mapping simulated adversary behaviors directly to the MITRE ATT&CK framework.

---

🛑 ##  Phase 1: Brute Force Detection – Network Telemetry Parsing (MITRE ATT&CK T1110)

### Objective
To successfully capture and alert on distributed network brute-force attempts targeting internal file shares (SMB) and remote access points (RDP), ensuring the SIEM correctly records the true remote attacker IP address rather than local system endpoints.

### Detection Engineering Logic
A custom alert rule was created to track high-frequency Windows security authentication failures (Event ID 4625). To filter out standard system noise and focus explicitly on authentication protocol vectors, the rule flags instances utilizing the Negotiate or NTLM authentication packages over network-based logon streams.

* **Custom Alert Rule (`local_rules.xml`):**
```xml
<rule id="100011" level="10">
  <if_group>windows</if_group>
  <if_sid>60122</if_sid>
  <description>Wazuh Custom Rule: Windows Authentication Failed via Network Protocol</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>

###  Attack Simulation & Verification
From a remote attacker instance on the local subnet, an active protocol scan was launched against the target Windows machine share path to trigger real-time failure telemetry:

```bash
smbclient -L //192.168.159.13 -U Administrator%WrongPasswordAttempt

<img width="921" height="400" alt="Screenshot 2026-06-18 151549" src="https://github.com/user-attachments/assets/9b8d717b-e2d3-42f5-bd7d-f4eb404367d6" />
<img width="776" height="527" alt="Screenshot 2026-06-18 152352" src="https://github.com/user-attachments/assets/23be2644-561c-4b9f-a664-52e06d1edab6" />

<!-- End of Phase 1 Image -->
<img width="921" height="400" alt="Screenshot..." src="https://github.com/user-attachments/assets/9b8d717b-e2d3-42f5-bd7d-f4eb404367d6" />


---

## 🛑 Phase 2: Defense Evasion – Detecting Event Log Clearing (MITRE ATT&CK T1562.001)

### 📋 Objective

To detect malicious attempts by an adversary to delete Windows Event logs to hide their operational footprint, while filtering out routine maintenance actions performed by designated system administrators.
 Detection Engineering Logic

The wevtutil.exe utility is tracked via Sysmon process creation logs (Event ID 1). A custom rule maps specific regex arguments matching the log clearing syntax (cl). To avoid alert fatigue, the rule evaluates the executing user identity against a local CDB database file containing authorized administrator accounts.

    The Whitelist Database (authorized_admins):

arjun:
Administrator:
SYSTEM:

**The Custom Alert Rule (local_rules.xml):**

``xml
<rule id="100020" level="12">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)wevtutil\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)cl\s+(Security|System|Application)</field>
  <list field="win.eventdata.user" lookup="not_match_key">etc/lists/authorized_admins</list>
  <description>CRITICAL: Unauthorized Clearing of Windows Event Logs Detected! Potential Defense Evasion.</description>
  <mitre>
    <id>T1562.001</id>
  </mitre>
  <group>defense_evasion,impair_defenses</group>
</rule>

Attack Simulation & Verification

An unauthorized user account on the target system executed the log wiping command via the command prompt:

wevtutil cl Security

<img width="1007" height="637" alt="Screenshot 2026-06-18 142001" src="https://github.com/user-attachments/assets/01961fe3-9409-4629-ba89-cd42dd54f3e5" />
