#Function Check-VirusTotal {
    #Set API Key
    #$VTapikey = "d6279cc78c23bc5ab8db6d4cec65243b956ffdbab10b4d0e6d05618bbe0bf91f"

    ###API header variable remains constant for all options
    $api_headers = @{
        "accept"="application/json"
        "X-Api-Key"="<enter-api-key-here>"
    }

#$DLLPath = "C:\temp\proc\jahdndivygfbendjcuvgbr.exe"
    $fileHash = Get-FileHash ($DLLPath) | Select-Object -ExpandProperty Hash
    $fileHash = "6d6b50ac34692e324b25147855ff3a075b1d5505f7fd550e405bca20ad94879a"
    $hashUri = "http://www.filescan.io/api/reports/search?sha256=$fileHash&main_task_state=success"
    
    try {
        $hashResults = Invoke-RestMethod -Uri $hashUri -Headers $api_headers -Method Get
        $verdict = $hashResults.items.verdict
        $reportID = $hashResults.items.id[1]
        $reportID
        
        ### Waiting to hear back from support on the report details
        $reportUri = "https://www.filescan.io/api/reports/$reportID/$fileHash"
        $reportResults = Invoke-RestMethod -Uri $reportUri -Headers $api_headers -Method Get
        $reportResults.reports
        ###
        
        #return $results
    } 
    catch {
        if ([string]$Error[0] -like "*401*"){
            Write-Host("Issue with the API key")
        }
        else{
            $Error[0]
        }
    }
#}
