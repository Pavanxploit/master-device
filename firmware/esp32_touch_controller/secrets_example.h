#pragma once

// Copy to secrets.h and edit.
const char* WIFI_SSID = "your-hotspot-name";
const char* WIFI_PASSWORD = "your-hotspot-password";

// Use laptop/Raspberry Pi IP address, not 127.0.0.1.
const char* API_STATE_URL = "http://192.168.1.10:5000/api/device/state";
const char* API_CONTROL_URL = "http://192.168.1.10:5000/api/device/control";
