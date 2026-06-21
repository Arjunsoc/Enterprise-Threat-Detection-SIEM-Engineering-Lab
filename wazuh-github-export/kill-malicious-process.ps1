<#
  Wazuh Custom Active Response: Malicious Process Termination
  Parses incoming JSON alert data from the Manager and terminates the offending PID.
#>
$DebugPreference = "Continue"
$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

# 1. Read input from STDIN sent by the Wazuh Manager
$inputJson = $input | Out-String

if (-not $inputJson) {
    Add-Content $LogFile "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') [Process Killer] Error: Received empty STDIN payload."
    Exit 0
}

try {
    # 2. Convert raw JSON input into an accessible object
    $alertObject = ConvertFrom-Json $inputJson
    
    # 3. Target and extract the process ID (PID) from the Sysmon telemetry block
    $pidToKill = $alertObject.parameters.alert.data.win.eventdata.processId

    if ($pidToKill) {
        # 4. Terminate the target process forcefully
        Stop-Process -Id $pidToKill -Force
        Add-Content $LogFile "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') [Process Killer] Successfully terminated malicious PID: $pidToKill"
    } else {
        Add-Content $LogFile "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') [Process Killer] Alert received, but no valid Process ID (PID) found in metadata."
    }
}
catch {
    Add-Content $LogFile "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') [Process Killer] Exception occurred during execution: $_"
}