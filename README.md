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
python scripts\train_model.py
python backend\app.py
```

Open:

```text
http://127.0.0.1:5000
```

Use dashboard buttons:

1. `Seed baseline`
2. `Normal`
3. `Evil twin`
4. `Deauth burst`
5. `Probe privacy`
6. `Mixed attack`

## Raspberry Pi collector

Safe simulation mode:

```bash
python3 pi_sensor/monitor_collector.py --url http://LAPTOP_IP:5000/api/pi/window --simulate mixed --loop
```

Real monitor-mode mode:

```bash
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
python3 pi_sensor/monitor_collector.py --iface wlan1 --url http://LAPTOP_IP:5000/api/pi/window --loop
```

If your adapter creates `wlan1mon`, use:

```bash
python3 pi_sensor/monitor_collector.py --iface wlan1mon --url http://LAPTOP_IP:5000/api/pi/window --loop
```

This collector is passive. It does not inject packets and does not perform attacks.

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

Edit Wi-Fi and API IP.

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
