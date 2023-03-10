###############################
#                             #
# ThreatGrid Hash Submission  #
# Script Author: Cyber Panda  #
#                             #
###############################

Function Check-ThreatGridHash{

###ThreatGrid API key
$key = "<enter-api-key-here>"

###API header variable remains constant for all options
$api_headers = @{
"Content-Type"="application/json"
"User-Agent"="ThreatGrid API Script"
"Accept"="*/*"
"Cache-Control"="no-cache"
"Host"="panacea.threatgrid.com"
"Accept-Encoding"="gzip, deflate"
}

###Prompt for submission
$fileHash = Get-FileHash ($DLLPath) | Select-Object -ExpandProperty Hash

###Query
$api_query = "https://panacea.threatgrid.com/api/v2/search/submissions?term=sample&q=$fileHash&api_key=$key"
$response = Invoke-RestMethod -Uri $api_query -Headers $api_headers -Method Get
$response.data
$total = $response.data.total

###Output the Threat Score and SHA256 from your organization
for ($n=0; $n -lt $total;$n++){
    if ($response.data[0].items[$n].item.analysis.threat_score){
        Write-Host $n
        Write-Host $response.data[0].items[$n].item.sha256
        }
}
}
