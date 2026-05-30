#pragma once

// Copy this file to secrets.h, or run:
// powershell -ExecutionPolicy Bypass -File scripts\configure_esp32.ps1 -Ssid "your-hotspot-name" -Password "your-hotspot-password"
const char* WIFI_SSID = "your-hotspot-name";
const char* WIFI_PASSWORD = "your-hotspot-password";

// Use laptop/Raspberry Pi Wi-Fi IP address, not 127.0.0.1 and not VirtualBox/Ethernet adapter IP.
const char* API_STATE_URL = "http://192.168.x.x:5000/api/device/state";
const char* API_CONTROL_URL = "http://192.168.x.x:5000/api/device/control";
