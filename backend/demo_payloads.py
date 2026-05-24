from __future__ import annotations

import time


BASELINE_NETWORKS = [
    {"ssid": "Campus-Lab", "bssid": "A4:2B:B0:11:22:33", "rssi": -49, "channel": 6, "encryption": "WPA2"},
    {"ssid": "Library-WiFi", "bssid": "B8:27:EB:44:55:66", "rssi": -62, "channel": 11, "encryption": "WPA2"},
    {"ssid": "Project-Room", "bssid": "C0:FF:EE:77:88:99", "rssi": -56, "channel": 1, "encryption": "WPA2"},
]


def base_payload(device_id: str = "demo-sensor") -> dict:
    return {
        "device_id": device_id,
        "timestamp_ms": int(time.time() * 1000),
        "networks": [dict(item) for item in BASELINE_NETWORKS],
        "frame_stats": {
            "beacon_count": 145,
            "probe_request_count": 12,
            "probe_response_count": 8,
            "deauth_count": 0,
            "disassoc_count": 0,
            "auth_count": 4,
            "assoc_count": 3,
            "unique_client_count": 5,
            "channel_switch_count": 0,
        },
        "probes": [
            {"client_hash": "known-001", "requested_ssid": "Campus-Lab", "rssi": -64},
            {"client_hash": "known-002", "requested_ssid": "Library-WiFi", "rssi": -70},
        ],
    }


def evil_twin_payload() -> dict:
    payload = base_payload("demo-evil-twin")
    payload["networks"].extend(
        [
            {"ssid": "Campus-Lab", "bssid": "DE:AD:BE:EF:10:01", "rssi": -30, "channel": 11, "encryption": "OPEN"},
            {"ssid": "Free-Campus-WiFi", "bssid": "DE:AD:BE:EF:10:02", "rssi": -35, "channel": 11, "encryption": "OPEN"},
        ]
    )
    payload["frame_stats"]["probe_response_count"] = 35
    return payload


def deauth_payload() -> dict:
    payload = base_payload("demo-deauth")
    payload["frame_stats"]["deauth_count"] = 44
    payload["frame_stats"]["disassoc_count"] = 9
    payload["frame_stats"]["unique_client_count"] = 12
    return payload


def privacy_payload() -> dict:
    payload = base_payload("demo-privacy")
    payload["frame_stats"]["probe_request_count"] = 78
    payload["frame_stats"]["unique_client_count"] = 18
    payload["probes"] = [
        {"client_hash": f"anon-{index:03d}", "requested_ssid": ssid, "rssi": -55 - index}
        for index, ssid in enumerate(
            [
                "Home-OldRouter",
                "Hostel-5G",
                "Cafe-Free",
                "Railway-WiFi",
                "PhoneHotspot",
                "Airport-Free",
                "Campus-Lab",
                "Library-WiFi",
            ],
            start=1,
        )
    ]
    return payload


def mixed_payload() -> dict:
    payload = evil_twin_payload()
    payload["device_id"] = "demo-mixed-attack"
    payload["frame_stats"]["deauth_count"] = 26
    payload["frame_stats"]["probe_request_count"] = 83
    payload["frame_stats"]["unique_client_count"] = 21
    payload["probes"] = privacy_payload()["probes"]
    return payload
