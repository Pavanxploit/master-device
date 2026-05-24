# API Reference

## Dashboard

```text
GET /
```

## Status

```text
GET /api/status
```

Returns latest risk state, reasons, features, events, and control state.

## ESP32 scan

```text
POST /api/scan
```

## Raspberry Pi window

```text
POST /api/pi/window
```

Payload:

```json
{
  "device_id": "raspberry-pi-monitor",
  "networks": [
    {
      "ssid": "Campus-Lab",
      "bssid": "A4:2B:B0:11:22:33",
      "rssi": -49,
      "channel": 6,
      "encryption": "WPA2"
    }
  ],
  "frame_stats": {
    "beacon_count": 145,
    "probe_request_count": 12,
    "deauth_count": 0,
    "unique_client_count": 5
  },
  "probes": [
    {
      "client_hash": "anon-001",
      "requested_ssid": "Campus-Lab",
      "rssi": -64
    }
  ]
}
```

## Device state for TFT

```text
GET /api/device/state
```

## Device control from TFT

```text
POST /api/device/control
```

Payload:

```json
{
  "action": "toggle_pause"
}
```

Actions:

- `toggle_pause`
- `learn_current`
- `cycle_page`
- `demo_mixed`

## Dashboard control

```text
POST /api/control
```

Supports mode, sensitivity, and action commands.
