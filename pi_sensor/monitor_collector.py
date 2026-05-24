from __future__ import annotations

import argparse
import json
import random
import time
from collections import Counter, defaultdict
from urllib.request import Request, urlopen


def post_json(url: str, payload: dict) -> dict:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def simulated_window(attack: str = "mixed") -> dict:
    from pathlib import Path
    import sys

    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    from backend.demo_payloads import base_payload, deauth_payload, evil_twin_payload, mixed_payload, privacy_payload

    payloads = {
        "normal": base_payload,
        "evil_twin": evil_twin_payload,
        "deauth": deauth_payload,
        "privacy": privacy_payload,
        "mixed": mixed_payload,
    }
    payload = payloads.get(attack, mixed_payload)()
    payload["device_id"] = "raspberry-pi-sim"
    return payload


def sniff_window(interface: str, seconds: int) -> dict:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sniff

    aps: dict[str, dict] = {}
    probes = []
    clients = set()
    stats = Counter()
    channel_seen: dict[str, set[int]] = defaultdict(set)

    def parse_packet(packet) -> None:
        if not packet.haslayer(Dot11):
            return
        dot11 = packet[Dot11]
        subtype = int(dot11.subtype)
        packet_type = int(dot11.type)
        rssi = int(getattr(packet, "dBm_AntSignal", -100) or -100)

        if packet_type == 0 and subtype == 8 and packet.haslayer(Dot11Beacon):
            bssid = (dot11.addr3 or "").upper()
            ssid = "<hidden>"
            channel = 0
            elt = packet.getlayer(Dot11Elt)
            while elt is not None:
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode(errors="ignore") or "<hidden>"
                    except Exception:
                        ssid = "<hidden>"
                if elt.ID == 3 and elt.info:
                    channel = int(elt.info[0])
                elt = elt.payload.getlayer(Dot11Elt)
            if bssid:
                stats["beacon_count"] += 1
                channel_seen[bssid].add(channel)
                aps[bssid] = {
                    "ssid": ssid,
                    "bssid": bssid,
                    "rssi": rssi,
                    "channel": channel,
                    "encryption": "WPA/WPA2",
                }

        elif packet_type == 0 and subtype == 4:
            stats["probe_request_count"] += 1
            client = (dot11.addr2 or "").upper()
            if client:
                clients.add(client)
            requested = "<broadcast>"
            elt = packet.getlayer(Dot11Elt)
            if elt is not None and elt.ID == 0:
                try:
                    requested = elt.info.decode(errors="ignore") or "<broadcast>"
                except Exception:
                    requested = "<broadcast>"
            probes.append({"client_mac": client, "requested_ssid": requested, "rssi": rssi})

        elif packet_type == 0 and subtype == 5:
            stats["probe_response_count"] += 1
        elif packet_type == 0 and subtype == 10:
            stats["disassoc_count"] += 1
        elif packet_type == 0 and subtype == 11:
            stats["auth_count"] += 1
        elif packet_type == 0 and subtype in {0, 1}:
            stats["assoc_count"] += 1
        elif packet_type == 0 and subtype == 12:
            stats["deauth_count"] += 1

    sniff(iface=interface, timeout=seconds, prn=parse_packet, store=False)

    stats["unique_client_count"] = len(clients)
    stats["channel_switch_count"] = sum(1 for channels in channel_seen.values() if len(channels) > 1)

    return {
        "device_id": "raspberry-pi-monitor",
        "window_seconds": seconds,
        "networks": list(aps.values()),
        "frame_stats": dict(stats),
        "probes": probes[:80],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive WiFiGhost Sentinel Raspberry Pi collector.")
    parser.add_argument("--iface", default="wlan1mon", help="Monitor-mode interface, for example wlan1mon.")
    parser.add_argument("--url", default="http://127.0.0.1:5000/api/pi/window")
    parser.add_argument("--window", type=int, default=20)
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--simulate", choices=["normal", "evil_twin", "deauth", "privacy", "mixed"], help="Send simulated windows instead of sniffing.")
    args = parser.parse_args()

    while True:
        payload = simulated_window(args.simulate) if args.simulate else sniff_window(args.iface, args.window)
        result = post_json(args.url, payload)
        print(json.dumps({"status": result["status"], "risk_score": result["risk_score"], "top_reason": result["top_reason"]}, indent=2))
        if not args.loop:
            break
        time.sleep(2)


if __name__ == "__main__":
    main()
