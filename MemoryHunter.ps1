### Step 1: Pivot from Anomaly Detection to Memory Analysis
### Step 2: Function to check if space available, split out mem dump
### Step 3: dlllist/dlldump +
### Step 4: malfind
### Step 5: VT Query
### Step 6: NVD Query?
### Step 6: ThreatGrid query
### Step 7: Bstrings?
### Step 8: yarascan?
### Step 9: files? 508 b3p83
### Step 10: Shellbags? volatility -f victim.raw --profile=Win7SP1x64 shellbags
### Step 11: Create response for S1 investigation
### Ideally I was trying to use direct memory analysis but VMs have issues 


# WinPmem download: https://github.com/Velocidex/WinPmem/releases
# Volatility download: https://www.volatilityfoundation.org/releases
#Requires -RunAsAdministrator

#VirusTotal
$VTapikey = "d6279cc78c23bc5ab8db6d4cec65243b956ffdbab10b4d0e6d05618bbe0bf91f"
$VTPositives = "unknown"

#Create folders if they don't exist
New-Item -ItemType Directory -Path C:\temp\proc\ -ErrorAction SilentlyContinue

#Imports
$TrustedCerts = Import-Csv -Path ./baselines/TrustedCerts.csv #for bypassing
$AnomolousProcs = Import-Csv -Path ./output/Hunting/anomalousProcs.csv
$AnomolousProcsOptimized = @()
$AnomolousDLLsOptimized = @()

#Check VirusTotal
Function Check-VirusTotal {
    $fileHash = Get-FileHash ($DLLPath) | Select-Object -ExpandProperty Hash
    $uri = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$VTapikey&resource=$fileHash"
    
    try {
        $VTPositives = Invoke-RestMethod -Uri $uri |Select-Object -ExpandProperty positives
        return $VTPositives
    } 
    catch {
        if ([string]$Error[0] -like "*(403) Forbidden.*"){
            Write-Host("Error reaching out to VirusTotal, most likely due to the API key missing.")
        }
        else{
            $reason = "Error reaching VirusTotal."
        }
    }
}

Function Analyze-DLLsFull {
    #dlllist / dlldump #Dumpfiles was missing python package
    $dlllist = .\modules\memory\Volatility\vol3.exe -o "C:\temp\proc" -f "C:\temp\mem.raw" windows.dlllist.DllList --pid 1236 --dump
    foreach($dll in $dlllist){
        $VTPositives = "unknown"
        #Fields: PID  ProcessBase  Size  Name  Path  LoadTime  File output
        $dll = $dll -split("\t")
        $CurrentDllExtraMeta = @()
        $DLLPath = $dll[5]

        #Filter out the header area
        if ($DLLPath -like "*.*"){
            $CurrentDllExtraMeta = $DLLPath | Get-AuthenticodeSignature -ErrorAction SilentlyContinue | ` Select-Object -Property Status,SignerCertificate

            #Filter for valid certs in our baseline
            if (($CurrentDllExtraMeta.Status = "Valid") -and ($CurrentDllExtraMeta.SignerCertificate.Subject -in $TrustedCerts.Subject)){
                #Skip Valid and in Trusted Certs
            }
            else{
                $VTPositives = Check-VirusTotal($dll)
                Write-Host("$($dll[4]) has $($VTPositives) hits on VT.")
                
                #TG
                #bstrings?
                #report?
            }
        }
        else{
            #Skip header area
        }
    }
    
    #Malware
    #Malfind will search for suspicious structures related to malware
    $malfind = .\modules\memory\Volatility\vol3.exe -o "C:\temp\proc" -f "C:\temp\mem.raw" windows.malfind.Malfind --pid 1236 --dump
    if ($malfind.Count -le 4){
        #4 indicates nothing returned on malfind
    }
    else{
Write-Host("malfind results need to be flushed out")
    }
 
    #yarascan
    #./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
    #./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
    #mkdir rules
    #python malware_yara_rules.py
    #Only Windows
    #./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
    #All
    #./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar

    #Netscan seems to hang and doesn't seem to be searchable by pid?
    #$netscan = .\modules\memory\Volatility\vol3.exe -f "C:\temp\mem.raw" windows.netscan.NetScan

    #./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
    #./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
    #./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
    #./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
    #./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
    #./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks

}
Write-Host("Dumping Memory...")
#Dump the memory with WinPmem
#.\memory\WinPmem\winpmem_mini_x64_rc2.exe c:\temp\mem.raw

#Here we build out our anomolous processes / DLLs for analysis
foreach($AnomolousProc in $AnomolousProcs){

    if($AnomolousProc.Reason -match 'is NOT in the DLL baseline list'){
        #This needs to be broken out!
        $AnomolousDLLsOptimized += $AnomolousProc
    }
    else{
        $AnomolousProcsOptimized += $AnomolousProc
    }
}
$AnomolousDLLsOptimized = $AnomolousDLLsOptimized  | Sort-Object -Unique
$AnomolousProcsOptimized = $AnomolousProcsOptimized | Sort-Object -Unique

Write-Host("Processing Memory File...")
Analyze-DLLsFull
