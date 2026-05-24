# WiFiGhost Sentinel Implementation Plan

## Completed in v1

1. Explainable risk engine
2. Flask API and dashboard
3. SQLite event logging
4. Demo payloads for normal, evil twin, deauth, privacy, and mixed attacks
5. Raspberry Pi monitor-mode collector scaffold
6. ESP32 TFT/touch controller firmware
7. Setup and wiring documentation

## Why this is more powerful

The original ESP32 scanner can detect access point changes. The Raspberry Pi with a monitor-mode adapter can also observe management-frame behavior such as probe requests and deauthentication frames. This makes the project closer to a real wireless IDS.

## Threat modules

| Module | What it detects | Evidence shown |
| --- | --- | --- |
| Evil twin fingerprinting | Same SSID from unknown BSSID | suspicious SSID list |
| Deauth burst | Abnormal disconnect frames | deauth frame count |
| Probe privacy leak | Clients probing many non-baseline SSIDs | privacy probe count |
| Open hotspot bait | Strong open AP near trusted networks | open AP count and RSSI |
| Environment drift | Many new BSSIDs/SSIDs | unknown BSSID count |
| Channel drift | Known AP/channel behavior changed | channel switch count |

## Touch screen controls

The ESP32 touch display supports these commands:

- Pause / run monitoring
- Learn current baseline
- Cycle TFT page
- Trigger mixed demo

The dashboard has full control and more detailed evidence.

## Safe demo script

1. Start Flask backend.
2. Open dashboard.
3. Click `Seed baseline`.
4. Click `Normal`; show low risk.
5. Click `Mixed attack`; show alert.
6. Explain why risk is high using the reason cards.
7. Show ESP32 TFT displays the same state.
8. Optional: run Pi collector simulation mode and show events arriving as Raspberry Pi source.

## Remaining hardware validation

The code is ready for first hardware testing. The next step is to calibrate the touch coordinates and verify the real monitor-mode adapter output. Different TFT touch panels and Wi-Fi chipsets often require small per-device tuning.
