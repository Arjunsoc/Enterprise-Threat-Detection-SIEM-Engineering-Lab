# 1. Configuration
$API_KEY = "API"
$log_path = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

# 2. Read the JSON payload from Wazuh
$input_json = $input | Out-String

try {
    $alert_data = $input_json | ConvertFrom-Json
    $file_path = $alert_data.parameters.alert.data.win.eventdata.targetFilename
    
    if (Test-Path $file_path) {
        $file_hash = (Get-FileHash -Path $file_path -Algorithm SHA256).Hash
        $vt_url = "https://www.virustotal.com/api/v3/files/$file_hash"
        
        # 3. Query VirusTotal via curl.exe to bypass PowerShell TLS issues
        $curl_cmd = "curl.exe -s -k -H `"x-apikey: $API_KEY`" `"$vt_url`""
        $json_response = Invoke-Expression $curl_cmd
        
        $response = $json_response | ConvertFrom-Json
        
        # 4. Parse results and force integers
        if ($null -ne $response.data.attributes.last_analysis_stats) {
            $malicious = [int]$response.data.attributes.last_analysis_stats.malicious
            $harmless = [int]$response.data.attributes.last_analysis_stats.harmless
            $undetected = [int]$response.data.attributes.last_analysis_stats.undetected
            
            $total = $malicious + $harmless + $undetected
            
            $msg = "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') active-response/bin/virustotal.ps1: SUCCESS - Hash: $file_hash | Malicious: $malicious / $total"
        } else {
            # Fallback for completely unknown files
            $msg = "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') active-response/bin/virustotal.ps1: SUCCESS - Hash: $file_hash | Malicious: 0 / 0"
        }
        
        # 5. WRITE USING ASCII ENCODING (CRITICAL FOR WAZUH TO READ IT)
        Add-Content -Path $log_path -Value $msg -Encoding ASCII
    }
}
catch {
    Add-Content -Path $log_path -Value "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') active-response/bin/virustotal.ps1: CRITICAL - $($_.Exception.Message)" -Encoding ASCII
}
