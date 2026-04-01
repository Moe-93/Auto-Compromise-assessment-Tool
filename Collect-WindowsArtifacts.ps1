#requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Forensic Artifact Collection Script for CAT Tool

.DESCRIPTION
    Collects forensic artifacts from Windows systems for analysis with CAT tool.
    Run as Administrator for full access to all artifacts.

.PARAMETER OutputDir
    Directory to store collected artifacts (default: .\collected_artifacts)

.PARAMETER SpecificArtifacts
    Array of specific artifacts to collect (default: all)

.PARAMETER Package
    Package collection into ZIP file

.EXAMPLE
    .\Collect-WindowsArtifacts.ps1

.EXAMPLE
    .\Collect-WindowsArtifacts.ps1 -OutputDir "C:\Forensics\Case001" -Package

.EXAMPLE
    .\Collect-WindowsArtifacts.ps1 -SpecificArtifacts @("SecurityWELS", "Prefetch")
#>

[CmdletBinding()]
param(
    [string]$OutputDir = ".\collected_artifacts",
    [string[]]$SpecificArtifacts = @(),
    [switch]$Package
)

#Requires -Version 5.1

# Initialize
$Hostname = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CollectionDir = Join-Path $OutputDir "$Hostname`_$Timestamp"
$CollectedFiles = @()
$Errors = @()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry

    $LogFile = Join-Path $CollectionDir "collection.log"
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
}

function New-CollectionDirectory {
    if (!(Test-Path $CollectionDir)) {
        New-Item -ItemType Directory -Path $CollectionDir -Force | Out-Null
    }

    # Create Windows subdirectory
    $WindowsDir = Join-Path $CollectionDir "Windows"
    New-Item -ItemType Directory -Path $WindowsDir -Force | Out-Null
}

function Copy-Artifact {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$ArtifactName
    )

    try {
        if (Test-Path $Source) {
            $DestPath = Join-Path $CollectionDir "Windows" $Destination
            $DestDir = Split-Path $DestPath -Parent

            if (!(Test-Path $DestDir)) {
                New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
            }

            if (Test-Path $Source -PathType Container) {
                Copy-Item -Path $Source -Destination $DestPath -Recurse -Force
            } else {
                Copy-Item -Path $Source -Destination $DestPath -Force
            }

            $script:CollectedFiles += $DestPath
            Write-Log "Collected $ArtifactName`: $Source"
            return $true
        } else {
            Write-Log "Source not found for $ArtifactName`: $Source" "WARNING"
            return $false
        }
    } catch {
        $script:Errors += "$ArtifactName`: $_"
        Write-Log "Error collecting $ArtifactName`: $_" "ERROR"
        return $false
    }
}

function Export-CommandOutput {
    param(
        [string]$Command,
        [string]$Destination,
        [string]$ArtifactName
    )

    try {
        $DestPath = Join-Path $CollectionDir "Windows" $Destination
        $DestDir = Split-Path $DestPath -Parent

        if (!(Test-Path $DestDir)) {
            New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
        }

        $Output = Invoke-Expression $Command 2>&1
        $Output | Out-File -FilePath $DestPath -Encoding UTF8

        $script:CollectedFiles += $DestPath
        Write-Log "Executed command for $ArtifactName"
        return $true
    } catch {
        $script:Errors += "$ArtifactName`: $_"
        Write-Log "Command failed for $ArtifactName`: $_" "ERROR"
        return $false
    }
}

function Export-RegistryKey {
    param(
        [string]$RegistryPath,
        [string]$Destination,
        [string]$ArtifactName
    )

    try {
        $DestPath = Join-Path $CollectionDir "Windows" $Destination
        $DestDir = Split-Path $DestPath -Parent

        if (!(Test-Path $DestDir)) {
            New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
        }

        $Output = reg query "$RegistryPath" /s 2>&1
        $Output | Out-File -FilePath $DestPath -Encoding UTF8

        $script:CollectedFiles += $DestPath
        Write-Log "Exported registry for $ArtifactName"
        return $true
    } catch {
        $script:Errors += "$ArtifactName`: $_"
        Write-Log "Registry export failed for $ArtifactName`: $_" "ERROR"
        return $false
    }
}

# Main Collection
Write-Host "`n==============================================" -ForegroundColor Cyan
Write-Host "Windows Forensic Artifact Collection" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

New-CollectionDirectory
Write-Log "Starting Windows artifact collection..."

# Define all artifacts
$Artifacts = @{
    "Prefetch" = @{ 
        Source = "C:\Windows\Prefetch"; 
        Destination = "Prefetch"; 
        Type = "Directory" 
    }
    "ShimCache" = @{ 
        Source = "C:\Windows\AppCompat\Programs\Amcache.hve"; 
        Destination = "ShimCache\Amcache.hve"; 
        Type = "File" 
    }
    "AmCache" = @{ 
        Source = "C:\Windows\AppCompat\Programs\Amcache.hve"; 
        Destination = "AmCache\Amcache.hve"; 
        Type = "File" 
    }
    "StartupItems" = @{
        Sources = @(
            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        Destination = "StartupItems"
        Type = "MultiDirectory"
    }
    "DLLs" = @{
        Command = "Get-ChildItem C:\Windows\System32\*.dll | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize"
        Destination = "DLLs\dll_list.txt"
        Type = "Command"
    }
    "HostedServices" = @{
        Command = "sc query type= service state= all"
        Destination = "HostedServices\services.txt"
        Type = "Command"
    }
    "Executables" = @{
        Command = "Get-ChildItem C:\Windows\System32, C:\Windows\SysWOW64 -Filter *.exe -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize"
        Destination = "Executables\exe_list.txt"
        Type = "Command"
    }
    "SecurityWELS" = @{
        Source = "C:\Windows\System32\winevt\Logs\Security.evtx"
        Destination = "EventLogs\Security.evtx"
        Type = "File"
    }
    "SystemWELS" = @{
        Source = "C:\Windows\System32\winevt\Logs\System.evtx"
        Destination = "EventLogs\System.evtx"
        Type = "File"
    }
    "BITSWELS" = @{
        Source = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-BITS-Client%4Operational.evtx"
        Destination = "EventLogs\BITS_Client.evtx"
        Type = "File"
    }
    "PowerShellOperationalWELS" = @{
        Source = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
        Destination = "EventLogs\PowerShell_Operational.evtx"
        Type = "File"
    }
    "TaskSchedulerWELS" = @{
        Source = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx"
        Destination = "EventLogs\TaskScheduler_Operational.evtx"
        Type = "File"
    }
    "LocalTermServerWELS" = @{
        Source = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"
        Destination = "EventLogs\TerminalServices_Local.evtx"
        Type = "File"
    }
    "RemoteTermServerWELS" = @{
        Source = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"
        Destination = "EventLogs\TerminalServices_Remote.evtx"
        Type = "File"
    }
    "WindowsPowerShellWELS" = @{
        Source = "C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx"
        Destination = "EventLogs\Windows_PowerShell.evtx"
        Type = "File"
    }
    "PrintSvcWELS" = @{
        Source = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PrintService%4Operational.evtx"
        Destination = "EventLogs\PrintService_Operational.evtx"
        Type = "File"
    }
    "WMIWELS" = @{
        Source = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx"
        Destination = "EventLogs\WMI_Activity.evtx"
        Type = "File"
    }
    "Autoruns" = @{
        Command = "wmic startup get Caption,Command,Location,User /format:csv"
        Destination = "Autoruns\startup.csv"
        Type = "Command"
    }
    "WERLogs" = @{
        Source = "C:\ProgramData\Microsoft\Windows\WER"
        Destination = "WERLogs"
        Type = "Directory"
    }
    "NamedPipesAudit" = @{
        Command = "Get-ChildItem \\\.\pipe\ | Select-Object Name"
        Destination = "NamedPipes\pipes.txt"
        Type = "Command"
    }
    "GPOScriptsAudit" = @{
        Sources = @(
            "C:\Windows\System32\GroupPolicy\Machine\Scripts",
            "C:\Windows\System32\GroupPolicy\User\Scripts"
        )
        Destination = "GPOScripts"
        Type = "MultiDirectory"
    }
    "WindowsFirewall" = @{
        Command = "netsh advfirewall show allprofiles"
        Destination = "Firewall\firewall_config.txt"
        Type = "Command"
    }
    "CCMRUA" = @{
        Source = "C:\Windows\CCM\Logs"
        Destination = "CCMRUA"
        Type = "Directory"
    }
    "DefenderWELS" = @{
        Source = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx"
        Destination = "EventLogs\Defender_Operational.evtx"
        Type = "File"
    }
    "CertUtilCache" = @{
        Command = "certutil -urlcache *"
        Destination = "CertUtil\urlcache.txt"
        Type = "Command"
    }
    "OSInfo" = @{
        Command = "systeminfo"
        Destination = "OSInfo\systeminfo.txt"
        Type = "Command"
    }
    "MFT" = @{
        Command = "fsutil fsinfo ntfsinfo C:"
        Destination = "MFT\ntfsinfo.txt"
        Type = "Command"
    }
    "USBSTOR" = @{
        RegistryPath = "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        Destination = "USBSTOR\usb_registry.txt"
        Type = "Registry"
    }
    "BrowsingHistory" = @{
        Sources = @(
            "$env:LOCALAPPDATA\Microsoft\Windows\History",
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
            "$env:APPDATA\Mozilla\Firefox\Profiles"
        )
        Destination = "BrowserHistory"
        Type = "MultiDirectory"
    }
    "RunningProcesses" = @{
        Command = "wmic process get Name,ProcessId,CommandLine,ExecutablePath /format:csv"
        Destination = "Processes\running_processes.csv"
        Type = "Command"
    }
}

# Filter artifacts if specific list provided
if ($SpecificArtifacts.Count -gt 0) {
    $ArtifactsToCollect = $Artifacts.GetEnumerator() | Where-Object { $SpecificArtifacts -contains $_.Key }
} else {
    $ArtifactsToCollect = $Artifacts.GetEnumerator()
}

# Collect each artifact
foreach ($Artifact in $ArtifactsToCollect) {
    $Name = $Artifact.Key
    $Config = $Artifact.Value

    Write-Host "`nProcessing: $Name" -ForegroundColor Yellow

    switch ($Config.Type) {
        "File" {
            Copy-Artifact -Source $Config.Source -Destination $Config.Destination -ArtifactName $Name
        }
        "Directory" {
            Copy-Artifact -Source $Config.Source -Destination $Config.Destination -ArtifactName $Name
        }
        "Command" {
            Export-CommandOutput -Command $Config.Command -Destination $Config.Destination -ArtifactName $Name
        }
        "Registry" {
            Export-RegistryKey -RegistryPath $Config.RegistryPath -Destination $Config.Destination -ArtifactName $Name
        }
        "MultiDirectory" {
            $Index = 0
            foreach ($Source in $Config.Sources) {
                $Dest = Join-Path $Config.Destination "item_$Index`_$((Split-Path $Source -Leaf))"
                Copy-Artifact -Source $Source -Destination $Dest -ArtifactName "$Name`_$Index"
                $Index++
            }
        }
    }
}

# Create summary
$Summary = @{
    collection_timestamp = $Timestamp
    hostname = $Hostname
    os_type = "Windows"
    total_files_collected = $CollectedFiles.Count
    errors = $Errors
    collected_files = $CollectedFiles
    collection_directory = $CollectionDir
}

$SummaryPath = Join-Path $CollectionDir "Windows_collection_summary.json"
$Summary | ConvertTo-Json -Depth 3 | Out-File -FilePath $SummaryPath -Encoding UTF8

Write-Log "Collection complete. Summary saved to $SummaryPath"

# Package if requested
if ($Package) {
    $ZipFile = Join-Path $OutputDir "$Hostname`_$Timestamp`_forensics.zip"
    Write-Host "`nPackaging collection..." -ForegroundColor Cyan

    try {
        Compress-Archive -Path $CollectionDir -DestinationPath $ZipFile -Force
        Write-Log "Collection packaged: $ZipFile"
        Write-Host "Package created: $ZipFile" -ForegroundColor Green
    } catch {
        Write-Log "Failed to create package: $_" "ERROR"
    }
}

# Final summary
Write-Host "`n==============================================" -ForegroundColor Green
Write-Host "COLLECTION COMPLETE" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
Write-Host "Total files collected: $($CollectedFiles.Count)" -ForegroundColor White
Write-Host "Errors: $($Errors.Count)" -ForegroundColor $(if ($Errors.Count -gt 0) { "Red" } else { "Green" })
Write-Host "Collection directory: $CollectionDir" -ForegroundColor White
if ($Package) {
    Write-Host "Package: $ZipFile" -ForegroundColor White
}
Write-Host "==============================================" -ForegroundColor Green

# Return collection directory path
return $CollectionDir
