from __future__ import annotations

import argparse
import json
from urllib.request import Request, urlopen

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.demo_payloads import base_payload, deauth_payload, evil_twin_payload, mixed_payload, privacy_payload


PAYLOADS = {
    "normal": base_payload,
    "evil_twin": evil_twin_payload,
    "deauth": deauth_payload,
    "privacy": privacy_payload,
    "mixed": mixed_payload,
}


def post_json(url: str, payload: dict) -> dict:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a WiFiGhost Sentinel demo window.")
    parser.add_argument("kind", choices=sorted(PAYLOADS), nargs="?", default="mixed")
    parser.add_argument("--url", default="http://127.0.0.1:5000/api/pi/window")
    parser.add_argument("--learn", action="store_true")
    args = parser.parse_args()
    url = args.url + ("?learn=1" if args.learn else "")
    print(json.dumps(post_json(url, PAYLOADS[args.kind]()), indent=2))


if __name__ == "__main__":
    main()
