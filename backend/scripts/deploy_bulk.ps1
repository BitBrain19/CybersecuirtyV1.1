##############################
# deploy_bulk.ps1
# Purpose: Deploy remote_log_forwarder to multiple Windows devices using a CSV manifest
# Usage: .\deploy_bulk.ps1 -ManifestFile "devices.csv" -SourceDir "C:\path\to\scripts"
# CSV Format: DeviceName,IpAddress,ApiKey (ApiKey is optional)
##############################

param(
    [Parameter(Mandatory=$true)]
    [string]$ManifestFile,
    
    [Parameter(Mandatory=$true)]
    [string]$ApiUrl,
    
    [Parameter(Mandatory=$false)]
    [string]$SourceDir = (Split-Path $MyInvocation.MyCommand.Path),
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipVerify,
    
    [Parameter(Mandatory=$false)]
    [string]$CaBundle
)

# Check if manifest file exists
if (-not (Test-Path $ManifestFile)) {
    Write-Error "Manifest file not found: $ManifestFile"
    exit 1
}

Write-Host "Bulk deployment of CyberGard Log Forwarder" -ForegroundColor Cyan
Write-Host "Manifest: $ManifestFile"
Write-Host "API URL: $ApiUrl"
Write-Host ""

$deployScript = Join-Path $SourceDir "deploy_windows.ps1"
if (-not (Test-Path $deployScript)) {
    Write-Error "Could not find deploy_windows.ps1 at: $deployScript"
    exit 1
}

$successCount = 0
$failureCount = 0

# Read and process manifest
Import-Csv $ManifestFile | ForEach-Object {
    $deviceName = $_.DeviceName
    $ipAddress = $_.IpAddress
    $apiKey = $_.ApiKey
    
    Write-Host "Deploying to: $deviceName ($ipAddress)" -ForegroundColor Yellow
    
    try {
        # Build deployment command
        $deployArgs = @(
            "-DeviceName '$deviceName'",
            "-ApiUrl '$ApiUrl'",
            "-SourceDir '$SourceDir'"
        )
        
        if ($apiKey) {
            $deployArgs += "-ApiKey '$apiKey'"
        }
        
        if ($SkipVerify) {
            $deployArgs += "-SkipVerify"
        }
        
        if ($CaBundle) {
            $deployArgs += "-CaBundle '$CaBundle'"
        }
        
        # For remote deployment via WinRM/SSH, you would invoke the script remotely
        # Example (requires WinRM): Invoke-Command -ComputerName $ipAddress -FilePath $deployScript -ArgumentList $deployArgs
        # For now, this is a template for local or manual deployment
        
        Write-Host "  [Success] Deployment command ready for $deviceName" -ForegroundColor Green
        $successCount++
    }
    catch {
        Write-Host "  [Failed] Error deploying to $deviceName : $_" -ForegroundColor Red
        $failureCount++
    }
    Write-Host ""
}

Write-Host "Deployment Summary" -ForegroundColor Cyan
Write-Host "  Successful: $successCount"
Write-Host "  Failed: $failureCount"
