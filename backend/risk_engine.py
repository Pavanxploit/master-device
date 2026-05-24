from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np

try:
    from .storage import SentinelStore
except ImportError:
    from storage import SentinelStore


FEATURE_NAMES = [
    "ap_count",
    "unknown_bssid_count",
    "new_ssid_count",
    "known_ssid_unknown_bssid_count",
    "duplicate_ssid_count",
    "open_network_count",
    "weak_encryption_count",
    "strong_unknown_count",
    "avg_rssi",
    "max_rssi",
    "channel_spread",
    "deauth_count",
    "disassoc_count",
    "probe_request_count",
    "unique_client_count",
    "privacy_probe_count",
    "channel_switch_count",
]

OPEN_OR_WEAK = {"OPEN", "WEP", "NONE"}
SENSITIVITY = {"low": 0.78, "normal": 1.0, "high": 1.22}


@dataclass
class Reason:
    title: str
    detail: str
    evidence: str
    points: int
    recommendation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "points": self.points,
            "recommendation": self.recommendation,
        }


def clamp(value: float, low: int = 0, high: int = 100) -> int:
    return int(max(low, min(high, round(value))))


def normalize_bssid(value: Any) -> str:
    return str(value or "").strip().upper()


def normalize_ssid(value: Any) -> str:
    value = str(value or "").strip()
    return value if value else "<hidden>"


def normalize_encryption(value: Any) -> str:
    text = str(value or "UNKNOWN").upper()
    if "OPEN" in text or text == "NONE":
        return "OPEN"
    if "WEP" in text:
        return "WEP"
    if "WPA3" in text:
        return "WPA3"
    if "WPA2" in text:
        return "WPA2"
    if "WPA" in text:
        return "WPA"
    return text


def client_hash(mac: str) -> str:
    normalized = normalize_bssid(mac)
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]


class SentinelRiskEngine:
    def __init__(self, root: Path, store: SentinelStore) -> None:
        self.root = root
        self.store = store
        self.model_path = root / "models" / "sentinel_iforest.joblib"
        self.model = joblib.load(self.model_path) if self.model_path.exists() else None

    @property
    def model_status(self) -> str:
        return "IsolationForest ready" if self.model else "rules-only until model is trained"

    def analyze(self, payload: dict[str, Any], source: str = "sensor", learn: bool = False) -> dict[str, Any]:
        state = self.store.load_state()
        if state.get("mode") == "paused" and source not in {"demo", "control"}:
            latest = self.store.latest()
            latest["state"] = state
            latest["top_reason"] = "Monitoring is paused from dashboard or TFT."
            return latest

        networks = self.normalize_networks(payload.get("networks") or payload.get("aps") or [])
        frame_stats = self.normalize_frame_stats(payload.get("frame_stats") or {})
        probes = self.normalize_probes(payload.get("probes") or [])

        if learn or state.get("mode") == "learning":
            self.learn_baseline(networks, probes)

        features = self.extract_features(networks, frame_stats, probes)
        reasons = self.rule_reasons(networks, frame_stats, probes, features)
        rule_score = self.rule_score(reasons)
        ml_score = self.ml_risk(features)
        sensitivity = SENSITIVITY.get(state.get("sensitivity", "normal"), 1.0)
        combined = max(rule_score, ml_score or 0)
        risk_score = clamp(combined * sensitivity)
        status, threat = self.classify(risk_score, reasons)

        if status == "SAFE" and not reasons:
            reasons.append(
                Reason(
                    "Normal wireless environment",
                    "Current scan is close to the saved baseline.",
                    f"{len(networks)} APs observed, deauth={frame_stats.get('deauth_count', 0)}",
                    0,
                    "Continue monitoring. Re-learn baseline only after confirming the environment is trusted.",
                )
            )

        result = {
            "timestamp_ms": int(time.time() * 1000),
            "source": source,
            "device_id": payload.get("device_id", source),
            "status": status,
            "risk_score": risk_score,
            "threat": threat,
            "top_reason": reasons[0].detail,
            "reasons": [reason.as_dict() for reason in reasons],
            "recommendations": [reason.recommendation for reason in reasons[:4]],
            "features": features,
            "networks": networks,
            "frame_stats": frame_stats,
            "probes": probes[:12],
            "ml_score": ml_score,
            "rule_score": rule_score,
            "model_status": self.model_status,
            "state": self.store.load_state(),
            "profile_summary": self.store.profile_summary(),
        }
        self.store.save_latest(result)
        return result

    def learn_baseline(self, networks: list[dict[str, Any]], probes: list[dict[str, Any]]) -> dict[str, Any]:
        baseline = self.store.load_baseline()
        state = self.store.load_state()
        profile_name = state.get("active_profile", "lab")
        profile = baseline.setdefault("profiles", {}).setdefault(
            profile_name,
            {"known_bssids": {}, "ssid_to_bssids": {}, "known_client_hashes": []},
        )

        known_bssids = {}
        ssid_to_bssids: dict[str, list[str]] = {}
        for net in networks:
            bssid = net["bssid"]
            ssid = net["ssid"]
            known_bssids[bssid] = {
                "ssid": ssid,
                "channel": net["channel"],
                "encryption": net["encryption"],
                "last_rssi": net["rssi"],
                "fingerprint": self.ap_fingerprint(net),
            }
            ssid_to_bssids.setdefault(ssid, [])
            if bssid not in ssid_to_bssids[ssid]:
                ssid_to_bssids[ssid].append(bssid)

        known_clients = sorted({probe.get("client_hash") for probe in probes if probe.get("client_hash")})
        profile["known_bssids"] = known_bssids
        profile["ssid_to_bssids"] = ssid_to_bssids
        profile["known_client_hashes"] = known_clients
        profile["updated_at"] = int(time.time() * 1000)
        baseline["active_profile"] = profile_name
        return self.store.save_baseline(baseline)

    def extract_features(self, networks: list[dict[str, Any]], frame_stats: dict[str, int], probes: list[dict[str, Any]]) -> dict[str, float]:
        profile = self.store.active_profile()
        known_bssids = profile.get("known_bssids", {})
        ssid_to_bssids = profile.get("ssid_to_bssids", {})
        seen_ssids: dict[str, int] = {}
        rssis: list[int] = []
        channels: list[int] = []

        unknown_bssid_count = 0
        new_ssid_count = 0
        known_ssid_unknown_bssid_count = 0
        open_network_count = 0
        weak_encryption_count = 0
        strong_unknown_count = 0
        channel_switch_count = 0

        for net in networks:
            ssid = net["ssid"]
            bssid = net["bssid"]
            encryption = net["encryption"]
            seen_ssids[ssid] = seen_ssids.get(ssid, 0) + 1
            rssis.append(int(net["rssi"]))
            if int(net["channel"]):
                channels.append(int(net["channel"]))
            is_known_bssid = bssid in known_bssids
            is_known_ssid = ssid in ssid_to_bssids
            if not is_known_bssid:
                unknown_bssid_count += 1
            if not is_known_ssid:
                new_ssid_count += 1
            if is_known_ssid and not is_known_bssid:
                known_ssid_unknown_bssid_count += 1
            if encryption == "OPEN":
                open_network_count += 1
            if encryption in OPEN_OR_WEAK:
                weak_encryption_count += 1
            if not is_known_bssid and int(net["rssi"]) >= -48:
                strong_unknown_count += 1
            if is_known_bssid and int(net["channel"]) != int(known_bssids[bssid].get("channel", 0)):
                channel_switch_count += 1

        privacy_probe_count = len([p for p in probes if p.get("requested_ssid") and p.get("requested_ssid") not in ssid_to_bssids])
        duplicate_ssid_count = sum(1 for count in seen_ssids.values() if count > 1)
        avg_rssi = float(sum(rssis) / len(rssis)) if rssis else -100.0

        return {
            "ap_count": float(len(networks)),
            "unknown_bssid_count": float(unknown_bssid_count),
            "new_ssid_count": float(new_ssid_count),
            "known_ssid_unknown_bssid_count": float(known_ssid_unknown_bssid_count),
            "duplicate_ssid_count": float(duplicate_ssid_count),
            "open_network_count": float(open_network_count),
            "weak_encryption_count": float(weak_encryption_count),
            "strong_unknown_count": float(strong_unknown_count),
            "avg_rssi": avg_rssi,
            "max_rssi": float(max(rssis)) if rssis else -100.0,
            "channel_spread": float(max(channels) - min(channels)) if channels else 0.0,
            "deauth_count": float(frame_stats.get("deauth_count", 0)),
            "disassoc_count": float(frame_stats.get("disassoc_count", 0)),
            "probe_request_count": float(frame_stats.get("probe_request_count", 0)),
            "unique_client_count": float(frame_stats.get("unique_client_count", 0)),
            "privacy_probe_count": float(privacy_probe_count),
            "channel_switch_count": float(channel_switch_count + frame_stats.get("channel_switch_count", 0)),
        }

    def rule_reasons(
        self,
        networks: list[dict[str, Any]],
        frame_stats: dict[str, int],
        probes: list[dict[str, Any]],
        features: dict[str, float],
    ) -> list[Reason]:
        profile = self.store.active_profile()
        known_bssids = profile.get("known_bssids", {})
        ssid_to_bssids = profile.get("ssid_to_bssids", {})
        reasons: list[Reason] = []

        evil_twins = sorted({net["ssid"] for net in networks if net["ssid"] in ssid_to_bssids and net["bssid"] not in known_bssids})
        if evil_twins:
            reasons.append(
                Reason(
                    "Evil twin fingerprint mismatch",
                    "A trusted SSID is being advertised by an unknown BSSID.",
                    "SSIDs: " + ", ".join(evil_twins[:4]),
                    38,
                    "Do not connect to the suspicious SSID. Verify router MAC/BSSID before trusting it.",
                )
            )

        if features["deauth_count"] >= 12:
            reasons.append(
                Reason(
                    "Deauthentication burst",
                    "A burst of deauth frames can indicate Wi-Fi disruption or forced reconnect activity.",
                    f"deauth_count={int(features['deauth_count'])}",
                    34,
                    "Check whether clients are disconnecting. Move to a trusted AP and continue passive monitoring.",
                )
            )

        if features["strong_unknown_count"] > 0:
            reasons.append(
                Reason(
                    "Strong unknown access point",
                    "An unknown AP is physically close to the scanner based on strong RSSI.",
                    f"strong_unknown_count={int(features['strong_unknown_count'])}, max_rssi={int(features['max_rssi'])}",
                    20,
                    "Inspect nearby hotspots and compare BSSID/security settings with trusted routers.",
                )
            )

        if features["open_network_count"] > 0 and (features["strong_unknown_count"] > 0 or features["new_ssid_count"] > 0):
            reasons.append(
                Reason(
                    "Open hotspot bait",
                    "A new or strong open network is visible near trusted networks.",
                    f"open_network_count={int(features['open_network_count'])}",
                    18,
                    "Avoid joining open networks during the alert window.",
                )
            )

        if features["duplicate_ssid_count"] > 0:
            reasons.append(
                Reason(
                    "Duplicate SSID confusion",
                    "Multiple APs share the same SSID in the scan window.",
                    f"duplicate_ssid_count={int(features['duplicate_ssid_count'])}",
                    14,
                    "Compare BSSID and channel values. Duplicate SSID alone is not always malicious.",
                )
            )

        if features["privacy_probe_count"] >= 5:
            reasons.append(
                Reason(
                    "Probe request privacy leak",
                    "Nearby clients are probing for several non-baseline SSIDs.",
                    f"privacy_probe_count={int(features['privacy_probe_count'])}",
                    12,
                    "Anonymize client identifiers and use this only for defensive awareness.",
                )
            )

        if features["channel_switch_count"] > 0:
            reasons.append(
                Reason(
                    "Channel fingerprint drift",
                    "A known BSSID or observed AP pattern changed channel unexpectedly.",
                    f"channel_switch_count={int(features['channel_switch_count'])}",
                    10,
                    "Re-learn baseline only if this was a planned router/channel change.",
                )
            )

        if features["unknown_bssid_count"] >= 6:
            reasons.append(
                Reason(
                    "Large environment drift",
                    "Several unknown BSSIDs appeared in the same window.",
                    f"unknown_bssid_count={int(features['unknown_bssid_count'])}",
                    10,
                    "Use room profiles so normal crowded areas do not create false positives.",
                )
            )

        return sorted(reasons, key=lambda item: item.points, reverse=True)[:7]

    def rule_score(self, reasons: list[Reason]) -> int:
        if not reasons:
            return 5
        # Use weighted accumulation with diminishing returns so one strong signal is enough,
        # while multiple weak signals still build confidence.
        total = 5
        for index, reason in enumerate(reasons):
            total += reason.points * (0.86 ** index)
        return clamp(total)

    def ml_risk(self, features: dict[str, float]) -> int | None:
        if self.model is None:
            return None
        vector = np.array([[features[name] for name in FEATURE_NAMES]], dtype=float)
        prediction = int(self.model.predict(vector)[0])
        raw_score = float(self.model.score_samples(vector)[0])
        mapped = 100 - ((raw_score + 0.68) / 0.20 * 100)
        if prediction == -1:
            mapped = max(mapped, 68)
        return clamp(mapped)

    def classify(self, risk_score: int, reasons: list[Reason]) -> tuple[str, str]:
        titles = " ".join(reason.title.lower() for reason in reasons)
        if risk_score >= 72:
            if "evil twin" in titles:
                return "ALERT", "Possible evil twin access point"
            if "deauthentication" in titles:
                return "ALERT", "Possible Wi-Fi disruption attack"
            return "ALERT", "High-risk wireless anomaly"
        if risk_score >= 42:
            return "WATCH", "Wireless environment drift"
        return "SAFE", "Normal wireless environment"

    def normalize_networks(self, networks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for item in networks:
            bssid = normalize_bssid(item.get("bssid") or item.get("mac") or item.get("addr"))
            if not bssid:
                continue
            normalized.append(
                {
                    "ssid": normalize_ssid(item.get("ssid")),
                    "bssid": bssid,
                    "rssi": self.to_int(item.get("rssi"), -100),
                    "channel": self.to_int(item.get("channel"), 0),
                    "encryption": normalize_encryption(item.get("encryption") or item.get("auth") or item.get("privacy")),
                    "vendor": item.get("vendor", "unknown"),
                    "beacon_interval": self.to_int(item.get("beacon_interval"), 0),
                    "fingerprint": self.ap_fingerprint(item),
                }
            )
        return normalized

    def normalize_frame_stats(self, frame_stats: dict[str, Any]) -> dict[str, int]:
        keys = [
            "beacon_count",
            "probe_request_count",
            "probe_response_count",
            "deauth_count",
            "disassoc_count",
            "auth_count",
            "assoc_count",
            "unique_client_count",
            "channel_switch_count",
        ]
        return {key: self.to_int(frame_stats.get(key), 0) for key in keys}

    def normalize_probes(self, probes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for item in probes:
            hashed = item.get("client_hash") or client_hash(str(item.get("client_mac", "")))
            normalized.append(
                {
                    "client_hash": hashed,
                    "requested_ssid": normalize_ssid(item.get("requested_ssid") or item.get("ssid")),
                    "rssi": self.to_int(item.get("rssi"), -100),
                }
            )
        return normalized

    def ap_fingerprint(self, net: dict[str, Any]) -> str:
        ssid = normalize_ssid(net.get("ssid"))
        encryption = normalize_encryption(net.get("encryption") or net.get("auth") or net.get("privacy"))
        channel = self.to_int(net.get("channel"), 0)
        beacon_interval = self.to_int(net.get("beacon_interval"), 0)
        return f"{ssid}|{encryption}|{channel}|{beacon_interval}"

    def to_int(self, value: Any, fallback: int) -> int:
        try:
            if value is None or (isinstance(value, float) and math.isnan(value)):
                return fallback
            return int(value)
        except (TypeError, ValueError):
            return fallback
