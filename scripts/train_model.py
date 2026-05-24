from __future__ import annotations

import random
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.risk_engine import FEATURE_NAMES


def normal_row() -> list[float]:
    ap_count = random.randint(3, 9)
    unknown_bssid_count = random.choice([0, 0, 0, 1, 1])
    new_ssid_count = random.choice([0, 0, 1])
    known_ssid_unknown_bssid_count = 0
    duplicate_ssid_count = random.choice([0, 0, 0, 1])
    open_network_count = random.choice([0, 0, 1])
    weak_encryption_count = open_network_count
    strong_unknown_count = 0
    avg_rssi = random.uniform(-73, -48)
    max_rssi = random.uniform(-58, -39)
    channel_spread = random.choice([5, 6, 10, 11])
    deauth_count = random.choice([0, 0, 0, 1, 2])
    disassoc_count = random.choice([0, 0, 1])
    probe_request_count = random.randint(3, 26)
    unique_client_count = random.randint(1, 10)
    privacy_probe_count = random.choice([0, 0, 1, 2])
    channel_switch_count = random.choice([0, 0, 0, 1])
    return [
        ap_count,
        unknown_bssid_count,
        new_ssid_count,
        known_ssid_unknown_bssid_count,
        duplicate_ssid_count,
        open_network_count,
        weak_encryption_count,
        strong_unknown_count,
        avg_rssi,
        max_rssi,
        channel_spread,
        deauth_count,
        disassoc_count,
        probe_request_count,
        unique_client_count,
        privacy_probe_count,
        channel_switch_count,
    ]


def main() -> None:
    random.seed(42)
    rows = [normal_row() for _ in range(650)]
    model = IsolationForest(n_estimators=180, contamination=0.08, random_state=42)
    model.fit(np.array(rows, dtype=float))
    out = ROOT / "models" / "sentinel_iforest.joblib"
    out.parent.mkdir(exist_ok=True)
    joblib.dump(model, out)
    print(f"Saved {out}")
    print("Features:", ", ".join(FEATURE_NAMES))


if __name__ == "__main__":
    main()
