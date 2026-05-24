from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any


DEFAULT_STATE = {
    "mode": "monitor",
    "sensitivity": "normal",
    "active_profile": "lab",
    "device_page": 0,
    "pi_sensor": "standby",
    "last_command": None,
}


class SentinelStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.data_dir = root / "data"
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "sentinel.db"
        self.state_path = self.data_dir / "state.json"
        self.latest_path = self.data_dir / "latest.json"
        self.baseline_path = self.data_dir / "baseline.json"
        self.demo_baseline_path = self.data_dir / "demo_baseline.json"
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    threat TEXT NOT NULL,
                    source TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def now_ms(self) -> int:
        return int(time.time() * 1000)

    def load_state(self) -> dict[str, Any]:
        if self.state_path.exists():
            return DEFAULT_STATE | self._load_json(self.state_path)
        self.save_state(DEFAULT_STATE)
        return dict(DEFAULT_STATE)

    def save_state(self, state: dict[str, Any]) -> dict[str, Any]:
        merged = DEFAULT_STATE | state
        self._save_json(self.state_path, merged)
        return merged

    def update_state(self, updates: dict[str, Any]) -> dict[str, Any]:
        state = self.load_state()
        state.update({k: v for k, v in updates.items() if v is not None})
        return self.save_state(state)

    def load_baseline(self) -> dict[str, Any]:
        if self.baseline_path.exists():
            return self._load_json(self.baseline_path)
        if self.demo_baseline_path.exists():
            baseline = self._load_json(self.demo_baseline_path)
            self.save_baseline(baseline)
            return baseline
        baseline = {"profiles": {"lab": {"known_bssids": {}, "ssid_to_bssids": {}, "known_client_hashes": []}}, "active_profile": "lab"}
        self.save_baseline(baseline)
        return baseline

    def save_baseline(self, baseline: dict[str, Any]) -> dict[str, Any]:
        self._save_json(self.baseline_path, baseline)
        return baseline

    def active_profile(self) -> dict[str, Any]:
        baseline = self.load_baseline()
        state = self.load_state()
        profile_name = state.get("active_profile") or baseline.get("active_profile") or "lab"
        profiles = baseline.setdefault("profiles", {})
        return profiles.setdefault(profile_name, {"known_bssids": {}, "ssid_to_bssids": {}, "known_client_hashes": []})

    def save_latest(self, result: dict[str, Any]) -> None:
        self._save_json(self.latest_path, result)
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                """
                INSERT INTO events (created_at, status, risk_score, threat, source, summary, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(result.get("timestamp_ms", self.now_ms())),
                    result.get("status", "READY"),
                    int(result.get("risk_score", 0)),
                    result.get("threat", "Unknown"),
                    result.get("source", "unknown"),
                    result.get("top_reason", "No reason"),
                    json.dumps(result),
                ),
            )

    def latest(self) -> dict[str, Any]:
        if self.latest_path.exists():
            return self._load_json(self.latest_path)
        return {
            "timestamp_ms": self.now_ms(),
            "source": "system",
            "status": "READY",
            "risk_score": 0,
            "threat": "Waiting for sensor input",
            "top_reason": "Start a demo or connect ESP32/Raspberry Pi sensor.",
            "reasons": [],
            "recommendations": ["Run a normal demo or start the Pi collector in simulation mode."],
            "features": {},
            "networks": [],
            "frame_stats": {},
            "state": self.load_state(),
            "profile_summary": self.profile_summary(),
        }

    def events(self, limit: int = 40) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute(
                """
                SELECT id, created_at, status, risk_score, threat, source, summary
                FROM events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def clear_events(self) -> None:
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM events")
        if self.latest_path.exists():
            self.latest_path.unlink()

    def profile_summary(self) -> dict[str, Any]:
        baseline = self.load_baseline()
        state = self.load_state()
        profile_name = state.get("active_profile", "lab")
        profile = baseline.get("profiles", {}).get(profile_name, {})
        return {
            "active_profile": profile_name,
            "known_bssid_count": len(profile.get("known_bssids", {})),
            "known_ssid_count": len(profile.get("ssid_to_bssids", {})),
            "known_client_count": len(profile.get("known_client_hashes", [])),
        }

    def _load_json(self, path: Path) -> dict[str, Any]:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)

    def _save_json(self, path: Path, payload: dict[str, Any]) -> None:
        with path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2)
