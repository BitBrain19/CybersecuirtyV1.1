##############################
# deploy_windows.ps1
# Purpose: Deploy remote_log_forwarder.py to Windows devices and create a Scheduled Task
# Usage: .\deploy_windows.ps1 -DeviceName "Device01" -ApiUrl "https://cybergard.example.com/api/v1/logs/ingest" -ApiKey "your_api_key_here"
##############################

param(
    [Parameter(Mandatory=$true)]
    [string]$DeviceName,
    
    [Parameter(Mandatory=$true)]
    [string]$ApiUrl,
    
    [Parameter(Mandatory=$false)]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$false)]
    [string]$CaBundle,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipVerify,
    
    [Parameter(Mandatory=$false)]
    [string]$ForwarderPath = "C:\CyberGard\remote_log_forwarder.py"
)

# Requires admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Ensure Python 3 is installed
$python = (Get-Command python -ErrorAction SilentlyContinue) -or (Get-Command python3 -ErrorAction SilentlyContinue)
if (-not $python) {
    Write-Error "Python 3 is not installed or not in PATH. Please install Python first."
    exit 1
}

Write-Host "Installing CyberGard Log Forwarder for device: $DeviceName" -ForegroundColor Green

# Create directory
$forwarderDir = Split-Path $ForwarderPath
if (-not (Test-Path $forwarderDir)) {
    New-Item -ItemType Directory -Path $forwarderDir -Force | Out-Null
    Write-Host "Created directory: $forwarderDir"
}

# Copy forwarder script (assumes this script is in the same dir as remote_log_forwarder.py)
$sourceScript = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "remote_log_forwarder.py"
if (Test-Path $sourceScript) {
    Copy-Item -Path $sourceScript -Destination $ForwarderPath -Force
    Write-Host "Deployed forwarder script to: $ForwarderPath"
} else {
    Write-Error "Could not find remote_log_forwarder.py at: $sourceScript"
    exit 1
}

# Build command line arguments
$args = @(
    "`"$ForwarderPath`"",
    "--url `"$ApiUrl`"",
    "--device-name `"$DeviceName`""
)

if ($ApiKey) {
    $args += "--api-key `"$ApiKey`""
}

if ($CaBundle) {
    $args += "--ca-bundle `"$CaBundle`""
}

if ($SkipVerify) {
    $args += "--skip-verify"
}

$argumentString = $args -join ' '

# Create Scheduled Task to run at startup
$taskName = "CyberGardLogForwarder-$DeviceName"
$taskDescription = "CyberGard log forwarder for device $DeviceName"

# Remove old task if it exists
try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
catch {}

# Use pythonw to run silently (no console window)
$taskAction = New-ScheduledTaskAction -Execute "pythonw.exe" -Argument $argumentString
$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskSettings = New-ScheduledTaskSettingSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable

Register-ScheduledTask -TaskName $taskName `
    -Action $taskAction `
    -Trigger $taskTrigger `
    -Settings $taskSettings `
    -Description $taskDescription `
    -RunLevel Highest `
    -Force | Out-Null

Write-Host "Scheduled Task created: $taskName" -ForegroundColor Green

# Start the task immediately
Start-ScheduledTask -TaskName $taskName
Write-Host "Started log forwarder immediately" -ForegroundColor Green

Write-Host ""
Write-Host "Deployment complete for $DeviceName" -ForegroundColor Green
Write-Host "Task will run at startup. To check status, view Task Scheduler or run:" -ForegroundColor Cyan
Write-Host "  Get-ScheduledTask -TaskName `"$taskName`" | Select-Object State, LastRunTime"
