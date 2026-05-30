param(
    [int]$Port = 5000
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    throw "Virtual environment missing. Run: python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt"
}

$ipLines = ipconfig | Select-String -Pattern "IPv4 Address"
$candidateIps = @()
foreach ($line in $ipLines) {
    if ($line.Line -match "(\d+\.\d+\.\d+\.\d+)") {
        $ip = $Matches[1]
        if ($ip -notlike "127.*" -and $ip -notlike "169.254.*" -and $ip -notlike "192.168.56.*") {
            $candidateIps += $ip
        }
    }
}

$ipAddress = if ($candidateIps.Count -gt 0) { $candidateIps[0] } else { "YOUR_LAPTOP_IP" }

Write-Host ""
Write-Host "WiFiGhost Sentinel backend" -ForegroundColor Cyan
Write-Host "Dashboard on laptop: http://127.0.0.1:$Port"
Write-Host "ESP32/Raspberry Pi URL base: http://$ipAddress`:$Port"
Write-Host ""
Write-Host "Keep this terminal open while using TFT/Pi."
Write-Host ""

$env:PORT = "$Port"
& $python backend\app.py
