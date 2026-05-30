# WiFiGhost Sentinel

AI-assisted wireless intrusion detection using Raspberry Pi monitor mode, ESP32 TFT touch control, and a Flask dashboard.

## What this version adds

This is the upgraded master-device version of WiFiGhost AI. It keeps the ESP32/TFT idea, but adds a Raspberry Pi wireless sensor path for deeper passive Wi-Fi security monitoring.

Current v1 features:

- Explainable risk score with clear reasons and recommendations
- Evil twin / rogue AP fingerprint detection
- Deauthentication burst detection
- Probe request privacy-leak detection
- Open hotspot bait detection
- Environment drift and channel drift detection
- Flask dashboard with controls, evidence, AP table, and event timeline
- SQLite event logging
- Raspberry Pi monitor-mode collector scaffold
- Safe simulation mode for demos without live packet capture
- ESP32 ILI9341 TFT + XPT2046 touch controller firmware

## Architecture

```text
Wi-Fi adapter in monitor mode
          |
          v
Raspberry Pi passive packet collector
          |
          v
Flask API + explainable risk engine + Isolation Forest
          |
          +--> Dashboard controls and evidence view
          |
          +--> ESP32 TFT touch alert/control panel
```

## Quick run on Windows/laptop

```powershell
cd "C:\Users\jeeva\Documents\New project\master-device"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python backend\app.py
```

Open dashboard:
```text
http://127.0.0.1:5000
```

### When You Change Wi-Fi / Mobile Hotspot

The backend port stays `5000`, but the laptop IP changes. Regenerate the ESP32 config before uploading:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\configure_esp32.ps1 -Ssid "YOUR_HOTSPOT_NAME" -Password "YOUR_HOTSPOT_PASSWORD"
powershell -ExecutionPolicy Bypass -File scripts\start_backend.ps1
```

See [docs/mobile_hotspot_runbook.md](docs/mobile_hotspot_runbook.md) for the full college/mobile-hotspot checklist.

### Mode 1: DEMO Mode (Testing)

Use dashboard buttons or send demo attacks:

```bash
python scripts\send_demo.py normal
python scripts\send_demo.py evil_twin
python scripts\send_demo.py deauth
python scripts\send_demo.py privacy
python scripts\send_demo.py mixed
```

### Mode 2: REAL-WORLD WiFi Analysis (Production)

**NEW**: Analyze actual WiFi networks instead of demos!

#### Quick Start (Recommended)
```bash
# Continuous real WiFi scanning
python scripts\real_wifi_sniffer.py --loop --interval 30
```

#### Interactive Menu
```bash
# Choose between real-world and demo modes
python launcher.py
```

#### Learn from Your Environment
```bash
# Learn what's normal in your location
python scripts\real_wifi_sniffer.py --learn --device-id "office-trusted"
```

#### Full Documentation
See [REAL_WORLD_QUICKSTART.md](REAL_WORLD_QUICKSTART.md) for:
- Real WiFi scanning setup
- Raspberry Pi monitor-mode configuration
- Model training on real data
- Production deployment guide

## Raspberry Pi Real-World Collection

### Real WiFi Packet Capture (Advanced)

Set up monitor mode on Raspberry Pi:

```bash
sudo apt-get install airmon-ng scapy
sudo airmon-ng start wlan1

# Real packet sniffing
sudo python3 pi_sensor/real_wifi_collector.py --interface wlan1mon --loop --verbose

# Stop monitor mode
sudo airmon-ng stop wlan1mon
```

### Demo/Simulation Mode (Quick Testing)

```bash
python3 pi_sensor/monitor_collector.py --url http://LAPTOP_IP:5000/api/pi/window --simulate mixed --loop
```

### Real Network Scanning (Windows/Linux Desktop)

```bash
python scripts/real_wifi_sniffer.py --loop --interval 30
```

Both collectors send real data to the backend for actual threat analysis.
See [docs/real_world_deployment.md](docs/real_world_deployment.md) for complete setup guide.

## ESP32 TFT touch firmware

Open:

```text
firmware/esp32_touch_controller/esp32_touch_controller.ino
```

Install Arduino libraries:

- Adafruit GFX Library
- Adafruit ILI9341
- XPT2046_Touchscreen

Copy:

```text
firmware/esp32_touch_controller/secrets_example.h
```

to:

```text
firmware/esp32_touch_controller/secrets.h
```

Or use the helper script:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\configure_esp32.ps1 -Ssid "YOUR_HOTSPOT_NAME" -Password "YOUR_HOTSPOT_PASSWORD"
```

`secrets.h` is local-only and ignored by Git, so your hotspot password is not pushed.

## Main TFT wiring

| TFT pin | ESP32 pin |
| --- | --- |
| VCC | 3V3 |
| GND | GND |
| CS | GPIO17 / TX2 |
| RESET | GPIO22 |
| D/C | GPIO21 |
| SDI / MOSI | GPIO23 |
| SCK | GPIO18 |
| SDO / MISO | GPIO19 |
| LED | 3V3 |

## Touch wiring

| Touch pin | ESP32 pin |
| --- | --- |
| T_CS | GPIO16 |
| T_IRQ | GPIO4 |
| T_DIN | GPIO23 |
| T_DO | GPIO19 |
| T_CLK | GPIO18 |

## Detection logic

The system uses:

- Isolation Forest for anomaly detection
- Rule-based cybersecurity scoring for explainability

The dashboard shows exactly why risk is high, including:

- reason title
- evidence
- risk points
- recommended action

## Current partition

Completed now:

- backend, dashboard, risk engine, event storage
- Pi collector scaffold with simulation and real sniffing
- ESP32 touch control firmware
- docs and setup guide

Next-week tuning:

- calibrate touch coordinates on your exact TFT
- verify Arduino compile/upload on your hardware
- tune Pi monitor-mode capture with your exact Wi-Fi adapter chipset
- add MAC vendor OUI lookup
- add charts and downloadable PDF incident report
- test false positives in your room/college/lab
