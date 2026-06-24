# Enterprise-Threat-Detection-SIEM-Engineering-La


## Project Overview
This project documents the development and validation of a centralized security monitoring and detection pipeline using Wazuh SIEM. The lab focuses on configuring endpoint telemetry via Sysmon, engineering custom XML rules, implementing Constant Data Database (CDB) whitelists, and mapping simulated adversary behaviors directly to the MITRE ATT&CK framework.

---

 ##  Phase 1: Brute Force Detection – Network Telemetry Parsing (MITRE ATT&CK T1110)

**Objective**
To successfully capture and alert on distributed network brute-force attempts targeting internal file shares (SMB) and remote access points (RDP), ensuring the SIEM correctly records the true remote attacker IP address rather than local system endpoints.

**Detection Engineering Logic**
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
```
**Attack Simulation & Verification**
From a remote attacker instance on the local subnet, an active protocol scan was launched against the target Windows machine share path to trigger real-time failure telemetry:

```bash
smbclient -L //192.168.159.13 -U Administrator%WrongPasswordAttempt
```

Wazuh SIEM Detection Telemetry:


<img width="776" height="527" alt="Screenshot 2026-06-18 152352" src="https://github.com/user-attachments/assets/2ed336b2-bba5-4231-ac52-aa4bb07680bb" />


Kali Linux Simulation:


<img width="921" height="400" alt="Screenshot 2026-06-18 151549" src="https://github.com/user-attachments/assets/c54f97ef-04b8-4527-b007-b572d1aa5719" />





## Phase 2: Defense Evasion – Detecting Event Log Clearing (MITRE ATT&CK T1562.001)**
 Objective

To detect malicious attempts by an adversary to delete Windows Event logs to hide their operational footprint, while filtering out routine maintenance actions performed by designated system administrators.

**Detection Engineering Logic**

The wevtutil.exe utility is tracked via Sysmon process creation logs (Event ID 1). A custom rule maps specific regex arguments matching the log clearing syntax.

The Whitelist Database (authorized_admins):
arjun:
Administrator:
SYSTEM:

**The Custom Alert Rule**

```xml
<rule id="100020" level="12">
    <if_sid>61603</if_sid> <field name="win.eventdata.image" type="pcre2">(?i)wevtutil\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)cl\s+(Security|System|Application|Setup)</field>
    <list field="win.eventdata.user" lookup="not_match_key">etc/lists/authorized_admins</list>
    <description>CRITICAL: Unauthorized Clearing of Windows Event Logs Detected! [MITRE ATT&amp;CK T1562.001]</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>defense_evasion,log_clearing</group>
  </rule>
```
**Attack Simulation & Verification**
To simulate an adversary attempting to evade detection and clear their tracks, the following log-wiping command was executed from an unauthorized context on the target Windows endpoint:

```powershell
wevtutil cl Security
```
<img width="1057" height="677" alt="Screenshot 2026-06-18 142253" src="https://github.com/user-attachments/assets/174ff369-6373-407a-a683-8ca95199d2d3" />

Wazuh SIEM Detection Telemetry:

<img width="1007" height="637" alt="Screenshot 2026-06-18 142001" src="https://github.com/user-attachments/assets/c9e1a917-8ca9-4de9-a24e-1e640138e501" />


##  Phase 3: Active Response & Automated Incident Containment
### Architectural Overview
To advance the detection platform from a passive monitoring repository into a proactive incident mitigation engine, an **SOAR-style Active Response pipeline** was engineered. The implementation specifically targets threat vectors associated with **MITRE ATT&CK T1562.001 (Impair Defenses: Indicator Blocking)**—specifically, administrative attempts to wipe system logs via the Windows event utility (`wevtutil.exe`).

The end-to-end telemetry loop operates under the following execution path:
1. **Trigger:** An adversary attempts execution of `wevtutil cl Security` on a monitored Windows endpoint.
2. **Ingestion & Correlation:** Sysmon captures the process execution event thread, passing it via the local encrypted socket to the Wazuh Agent. The Wazuh Manager correlates the metadata payload against **Custom Detection Rule ID: 100020**.
3. **Orchestration:** Upon matching rule conditions, the Manager's engine fires an Active Response action packet down the persistent command channel (`TCP 1514`) targeting the specific agent.
4. **Containment:** The local Wazuh Agent passes the structured JSON alert parameters via Standard Input (`STDIN`) to a batch wrapper middleman, which translates the pipe into a custom kernel-level PowerShell termination thread, killing the offending process ID before file-system erasure can finalize.


### Technical Implementation

 1.**Endpoint Automation Script** (`C:\Program Files (x86)\ossec-agent\active-response\bin\kill-malicious-process.ps1`)
This production-grade script handles the raw JSON stream emitted by the `wazuh-execd` daemon, deserializes the multi-nested parameter block, isolates the specific process tree ID (`processId`), forcefully drops the execution context, and appends a cryptographic trace entry to the local log audit pipeline:

```powershell
$DebugPreference = "Continue"
$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

# 1. Read structural JSON telemetry passed via standard STDIN pipe from Wazuh Execd
$inputJson = $input | Out-String

if (-not $inputJson) {
    Add-Content $LogFile "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') [Process Killer] Error: Received empty STDIN data pipe block."
    Exit 0
}

try {
    # 2. Deserialize the raw string into an accessible object model
    $alertObject = ConvertFrom-Json $inputJson

    # 3. Target and isolate the explicit offensive Process ID (PID) from the nested Sysmon event metadata
    $pidToKill = $alertObject.parameters.alert.data.win.eventdata.processId

    if ($pidToKill) {
        # 4. Terminate the thread immediately using the native Windows kernel interaction interface
        Stop-Process -Id $pidToKill -Force
        Add-Content $LogFile "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') [Process Killer] Successfully terminated malicious PID: $pidToKill"
    } else {
        Add-Content $LogFile "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') [Process Killer] Alert received, but target metadata did not contain a valid processId field."
    }
}
catch {
    Add-Content $LogFile "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') [Process Killer] Exception occurred during execution loop: $_"
}
```

2.**Batch Execution Wrapper File** (C:\Program Files (x86)\ossec-agent\active-response\bin\kill-process.bat)

```cmd
   @echo off
   powershell.exe -ExecutionPolicy Bypass -Command "$input | & '%~dp0kill-malicious-process.ps1'"
```
3.**Monitored Agent Local Configuration** (C:\Program Files (x86)\ossec-agent\ossec.conf)

To ensure compliance with local asset hardening constraints, the agent endpoint file was updated to allow execution commands and explicitly register the valid signature path parameters

```xml
<active-response>
    <disabled>no</disabled>
    <ca_store>wpk_root.pem</ca_store>
    <ca_verification>no</ca_verification>
  </active-response>

  <command>
    <name>win-kill-process</name>
    <executable>kill-process.bat</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
```

4. **Centralized Manager Configuration Layout**(/var/ossec/etc/ossec.conf)

The central engine on the Ubuntu Manager links the custom telemetry generation stream directly to the target execution file, establishing the binding loop between Rule 100020 and the endpoint action framework

```xml
<command>
    <name>win-kill-process</name>
    <executable>kill-process.bat</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>win-kill-process</command>
    <location>local</location>
    <rules_id>100020</rules_id>
  </active-response>
```

### Simulation, Verification & Definitive Proof
1.**Attacker Emulation Context**

From an administrative shell context on the Windows endpoint, an automated log erasure routine was initialized to erase security traces

```powershell
wevtutil cl Security
```

2. **Endpoint Containment Validation Log**

Inspection of the endpoint active response log trace confirms that the automated loop successfully intercepted the attack, evaluated the telemetry context, extracted target PID 1172, and safely terminated the threat

2026-06-21 13:17:34 [Process Killer] Successfully terminated malicious PID: 1172

<img width="1336" height="797" alt="Screenshot 2026-06-21 134912" src="https://github.com/user-attachments/assets/25d6f39a-2c0f-4fb5-a6c0-2c3157fdc798" />


3. **SIEM Dashboard Analysis & Metric Tracking**

   <img width="772" height="493" alt="Screenshot 2026-06-21 135027" src="https://github.com/user-attachments/assets/226a9113-3f07-4e28-a4f7-be19aefb6fc6" />


## Phase 4: Cross-Platform Threat Intelligence Enrichment(Virus Total) & Centralized Alerting Pipeline

### Architectural Overview
To supplement endpoint behavioral monitoring with global threat intelligence, an automated **Threat Intelligence Enrichment pipeline** was integrated into the architecture. This phase shifts the system from standalone activity detection to data-enriched validation, specifically cross-referencing file-system modifications against globally crowdsourced threat indicators.

The end-to-end data pipeline operates under the following execution path:

1. **Trigger:** A file creation event occurs within a monitored target directory (such as the standard user `Downloads` folder), which is tracked continuously via custom **Sysmon FileCreate (Event ID 11)** monitoring.
2. **Local Collection & Inspection:** The creation event invokes a background integration loop. A custom PowerShell analysis thread isolates the target object, computes its cryptographic signature (SHA-256 hash), and targets the **VirusTotal API v3 endpoint** for reputation scoring.
3. **Structured Audit Logging:** The result of the API analysis is committed asynchronously to a local flat-text syslog file (`active-responses.log`). The automation string leverages direct .NET file-stream handling (`[System.IO.File]::AppendAllLines`) to maintain non-blocking file access and bypass concurrent read/write OS locks.
4. **SIEM Ingestion & Rule Parsing:** The local Wazuh Agent collects the syslog string via an optimized absolute-path engine block and ships it across the encrypted tunnel (`TCP 1514`) to the **Wazuh Manager**. 
5. **Dashboard Visualization:** The Manager filters the raw incoming text stream through a decoupled detection module (**Custom Rule ID: 100050**), parsing the explicit string pattern and raising a **Level 12 Critical Security Alert** instantly onto the centralized SIEM Dashboard.

---

### Technical Implementation

#### 1. Endpoint Enrichment Script (`C:\Program Files (x86)\ossec-agent\active-response\bin\virustotal.ps1`)
This automated script handles API transactions, captures responses, filters out communication or rate-limit errors, and appends a cleanly parsed audit trail to the log file in standard UTF-8 encoding:

```powershell
# 1. Configuration
$API_KEY = "a0c13d5790fb7289d1dcf71a28b22123b76bcb2699350b65abb84253f0c9b5b4"
$log_path = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

# 2. Read the JSON payload
$input_json = $input | Out-String

try {
    $alert_data = $input_json | ConvertFrom-Json
    $file_path = $alert_data.parameters.alert.data.win.eventdata.targetFilename
    
    if (Test-Path $file_path) {
        $file_hash = (Get-FileHash -Path $file_path -Algorithm SHA256).Hash
        $vt_url = "https://www.virustotal.com/api/v3/files/$file_hash"
        
        # 3. Use standalone curl.exe to bypass ALL Windows SSL/TLS issues
        # -s (silent), -H (header), -k (insecure/ignore cert errors)
        $curl_cmd = "curl.exe -s -k -H `"x-apikey: $API_KEY`" `"$vt_url`""
        $json_response = Invoke-Expression $curl_cmd
        
        $response = $json_response | ConvertFrom-Json
        
        $malicious = $response.data.attributes.last_analysis_stats.malicious
        $total = $malicious + $response.data.attributes.last_analysis_stats.harmless + $response.data.attributes.last_analysis_stats.undetected
        
        $msg = "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') active-response/bin/virustotal.ps1: SUCCESS - Hash: $file_hash | Malicious: $malicious / $total"
        Add-Content -Path $log_path -Value $msg
    }
}
catch {
    Add-Content -Path $log_path -Value "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') active-response/bin/virustotal.ps1: CRITICAL - $($_.Exception.Message)"
}
```
**2. Local File Collector Configuration (ossec.conf - Windows Agent)**
To ensure the agent reads the text stream accurately without path ambiguity, an absolute target path is specified inside the log collection array

```xml
<localfile>
    <location>C:\Program Files (x86)\ossec-agent\active-response\active-responses.log</location>
    <log_format>syslog</log_format>
</localfile>
```

**3. Custom Decoupled Detection Rule (local_rules.xml - Wazuh Manager)**

To reliably catch the text pattern independent of rigid log group constraints or OS classification rules, this matching logic parses the syslog stream directly:

```xml
<group name="windows_sysmon,">
    <!-- Rule 100050: Independent Text-Match Alerting Block -->
    <rule id="100050" level="12">
        <match>active-response/bin/virustotal.ps1: SUCCESS</match>
        <description>VirusTotal Integration: Threat Intelligence confirmed malicious file hash match.</description>
    </rule>
```
