param(
    [Parameter(Mandatory = $true)]
    [string]$Ssid,

    [Parameter(Mandatory = $true)]
    [string]$Password,

    [int]$Port = 5000
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$secretsPath = Join-Path $repoRoot "firmware\esp32_touch_controller\secrets.h"

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

if (-not $candidateIps -or $candidateIps.Count -eq 0) {
    throw "Could not find a Wi-Fi/hotspot IPv4 address. Connect laptop to the same hotspot as ESP32, then retry."
}

$ipAddress = $candidateIps[0]
$content = @"
#pragma once

const char* WIFI_SSID = "$Ssid";
const char* WIFI_PASSWORD = "$Password";

const char* API_STATE_URL = "http://$ipAddress`:$Port/api/device/state";
const char* API_CONTROL_URL = "http://$ipAddress`:$Port/api/device/control";
"@

Set-Content -LiteralPath $secretsPath -Value $content -Encoding ASCII

Write-Host ""
Write-Host "ESP32 secrets.h updated:" -ForegroundColor Green
Write-Host "  SSID: $Ssid"
Write-Host "  Laptop API IP: $ipAddress"
Write-Host "  State URL: http://$ipAddress`:$Port/api/device/state"
Write-Host ""
Write-Host "Next: upload firmware/esp32_touch_controller/esp32_touch_controller.ino in Arduino IDE."
