# Raspberry Pi Monitor Mode Setup

## Goal

Use the Raspberry Pi plus external Wi-Fi adapter as a passive wireless IDS sensor.

## Check adapter

```bash
iw dev
iw list | grep -A 10 "Supported interface modes"
```

Look for:

```text
monitor
```

## Install packages

```bash
sudo apt update
sudo apt install -y python3-pip iw wireless-tools
pip3 install -r requirements.txt
```

## Enable monitor mode

Option 1:

```bash
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
```

Option 2, if using aircrack-ng tools:

```bash
sudo airmon-ng start wlan1
```

Then use the created interface, often `wlan1mon`.

## Run collector

```bash
python3 pi_sensor/monitor_collector.py --iface wlan1mon --url http://LAPTOP_IP:5000/api/pi/window --loop
```

## Demo without hardware capture

```bash
python3 pi_sensor/monitor_collector.py --simulate mixed --url http://LAPTOP_IP:5000/api/pi/window --loop
```

## Safety

This project is passive. Do not run deauthentication, injection, or capture of private payload data. The collector only summarizes management-frame metadata for defensive monitoring.
