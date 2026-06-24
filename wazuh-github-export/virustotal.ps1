# 1. Configuration
$API_KEY = "API"
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