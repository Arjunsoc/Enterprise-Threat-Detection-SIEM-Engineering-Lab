# Enterprise-Threat-Detection-SIEM-Engineering-La


## Project Overview
This project documents the development and validation of a centralized security monitoring and detection pipeline using Wazuh SIEM. The lab focuses on configuring endpoint telemetry via Sysmon, engineering custom XML rules, implementing Constant Data Database (CDB) whitelists, and mapping simulated adversary behaviors directly to the MITRE ATT&CK framework.

---

🛑 ##  Phase 1: Brute Force Detection – Network Telemetry Parsing (MITRE ATT&CK T1110)

### Objective
To successfully capture and alert on distributed network brute-force attempts targeting internal file shares (SMB) and remote access points (RDP), ensuring the SIEM correctly records the true remote attacker IP address rather than local system endpoints.

### Detection Engineering Logic
A custom alert rule was created to track high-frequency Windows security authentication failures (Event ID 4625). To filter out standard system noise and focus explicitly on authentication protocol vectors, the rule flags instances utilizing the Negotiate or NTLM authentication packages over network-based logon streams.

 **Custom Alert Rule (`local_rules.xml`):**
```xml
<rule id="100011" level="10">
  <if_group>windows</if_group>
  <if_sid>60122</if_sid>
  <description>Wazuh Custom Rule: Windows Authentication Failed via Network Protocol</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
`
###  Attack Simulation & Verification
From a remote attacker instance on the local subnet, an active protocol scan was launched against the target Windows machine share path to trigger real-time failure telemetry:

```bash
smbclient -L //192.168.159.13 -U Administrator%WrongPasswordAttempt
`

Wazuh SIEM Detection Telemetry:


<img width="776" height="527" alt="Screenshot 2026-06-18 152352" src="https://github.com/user-attachments/assets/2ed336b2-bba5-4231-ac52-aa4bb07680bb" />


Kali Linux Simulation:


<img width="921" height="400" alt="Screenshot 2026-06-18 151549" src="https://github.com/user-attachments/assets/c54f97ef-04b8-4527-b007-b572d1aa5719" />

