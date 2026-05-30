# Mobile Hotspot / College Network Runbook

Use this whenever you move from home Wi-Fi to mobile hotspot or college network.

## Rule

The port usually stays:

```text
5000
```

The laptop IP changes. ESP32 and Raspberry Pi must call the new laptop IP.

Do not use:

```text
127.0.0.1
192.168.56.1
```

`127.0.0.1` means the ESP32 itself. `192.168.56.1` is usually VirtualBox/host-only adapter, not your hotspot.

## Fast Start

1. Connect laptop and ESP32 to the same hotspot.
2. Run:

```powershell
cd "C:\Users\jeeva\Documents\New project\master-device"
powershell -ExecutionPolicy Bypass -File scripts\configure_esp32.ps1 -Ssid "YOUR_HOTSPOT_NAME" -Password "YOUR_HOTSPOT_PASSWORD"
powershell -ExecutionPolicy Bypass -File scripts\start_backend.ps1
```

3. Upload `firmware/esp32_touch_controller/esp32_touch_controller.ino`.
4. Open dashboard:

```text
http://127.0.0.1:5000
```

## What TFT Should Show

If Wi-Fi is correct:

```text
Wi-Fi connected
ESP32 IP: ...
```

If backend IP is wrong:

```text
OFFLINE
Backend offline
Check laptop IP and port 5000
```

Run `configure_esp32.ps1` again after changing networks.
