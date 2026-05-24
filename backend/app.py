from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

try:
    from .demo_payloads import base_payload, deauth_payload, evil_twin_payload, mixed_payload, privacy_payload
    from .risk_engine import SentinelRiskEngine
    from .storage import SentinelStore
except ImportError:
    from demo_payloads import base_payload, deauth_payload, evil_twin_payload, mixed_payload, privacy_payload
    from risk_engine import SentinelRiskEngine
    from storage import SentinelStore


ROOT = Path(__file__).resolve().parents[1]
app = Flask(__name__)
store = SentinelStore(ROOT)
engine = SentinelRiskEngine(ROOT, store)


@app.get("/")
def index() -> str:
    return render_template("index.html")


@app.get("/api/status")
def status() -> Any:
    latest = store.latest()
    latest["state"] = store.load_state()
    latest["profile_summary"] = store.profile_summary()
    latest["events"] = store.events(12)
    latest["model_status"] = engine.model_status
    return jsonify(latest)


@app.get("/api/events")
def events() -> Any:
    return jsonify({"events": store.events(int(request.args.get("limit", 40)))})


@app.post("/api/scan")
def scan() -> Any:
    payload = request.get_json(silent=True) or {}
    result = engine.analyze(payload, source="esp32", learn=request.args.get("learn") == "1")
    return jsonify(result)


@app.post("/api/pi/window")
def pi_window() -> Any:
    payload = request.get_json(silent=True) or {}
    store.update_state({"pi_sensor": "online"})
    result = engine.analyze(payload, source="raspberry-pi", learn=request.args.get("learn") == "1")
    return jsonify(result)


@app.post("/api/baseline/learn")
def learn_baseline() -> Any:
    payload = request.get_json(silent=True) or {}
    if not payload:
        latest = store.latest()
        payload = {
            "device_id": latest.get("device_id", "latest"),
            "networks": latest.get("networks", []),
            "frame_stats": latest.get("frame_stats", {}),
            "probes": latest.get("probes", []),
        }
    result = engine.analyze(payload, source="control", learn=True)
    return jsonify({"message": "Baseline learned from current trusted environment", "result": result})


@app.post("/api/control")
def control() -> Any:
    payload = request.get_json(silent=True) or {}
    action = payload.get("action")
    updates: dict[str, Any] = {}

    if payload.get("mode") in {"monitor", "learning", "paused"}:
        updates["mode"] = payload["mode"]
    if payload.get("sensitivity") in {"low", "normal", "high"}:
        updates["sensitivity"] = payload["sensitivity"]
    if payload.get("active_profile"):
        updates["active_profile"] = str(payload["active_profile"])
    if payload.get("device_page") is not None:
        updates["device_page"] = int(payload["device_page"]) % 4

    if action == "toggle_pause":
        state = store.load_state()
        updates["mode"] = "monitor" if state.get("mode") == "paused" else "paused"
    elif action == "cycle_page":
        updates["device_page"] = (int(store.load_state().get("device_page", 0)) + 1) % 4
    elif action == "clear_events":
        store.clear_events()
    elif action == "demo_normal":
        return jsonify(engine.analyze(base_payload(), source="demo"))
    elif action == "demo_evil_twin":
        return jsonify(engine.analyze(evil_twin_payload(), source="demo"))
    elif action == "demo_deauth":
        return jsonify(engine.analyze(deauth_payload(), source="demo"))
    elif action == "demo_privacy":
        return jsonify(engine.analyze(privacy_payload(), source="demo"))
    elif action == "demo_mixed":
        return jsonify(engine.analyze(mixed_payload(), source="demo"))
    elif action == "learn_current":
        latest = store.latest()
        return jsonify(
            {
                "state": store.load_state(),
                "result": engine.analyze(
                    {
                        "device_id": "latest",
                        "networks": latest.get("networks", []),
                        "frame_stats": latest.get("frame_stats", {}),
                        "probes": latest.get("probes", []),
                    },
                    source="control",
                    learn=True,
                ),
            }
        )

    updates["last_command"] = action
    state = store.update_state(updates)
    return jsonify({"state": state, "latest": store.latest()})


@app.get("/api/device/state")
def device_state() -> Any:
    latest = store.latest()
    state = store.load_state()
    compact_reasons = latest.get("reasons", [])[:3]
    return jsonify(
        {
            "status": latest.get("status", "READY"),
            "risk_score": int(latest.get("risk_score", 0)),
            "threat": latest.get("threat", "Waiting for input"),
            "top_reason": latest.get("top_reason", "No sensor input yet"),
            "reasons": compact_reasons,
            "features": latest.get("features", {}),
            "frame_stats": latest.get("frame_stats", {}),
            "mode": state.get("mode"),
            "sensitivity": state.get("sensitivity"),
            "device_page": int(state.get("device_page", 0)),
            "profile": state.get("active_profile", "lab"),
            "updated_ms": latest.get("timestamp_ms"),
        }
    )


@app.post("/api/device/control")
def device_control() -> Any:
    payload = request.get_json(silent=True) or {}
    action = payload.get("action", "cycle_page")
    with app.test_request_context(json={"action": action}):
        return control()


@app.post("/api/demo/<kind>")
def demo(kind: str) -> Any:
    payloads = {
        "normal": base_payload,
        "evil_twin": evil_twin_payload,
        "deauth": deauth_payload,
        "privacy": privacy_payload,
        "mixed": mixed_payload,
    }
    if kind == "seed":
        baseline = store._load_json(store.demo_baseline_path)
        store.save_baseline(baseline)
        return jsonify({"message": "Demo baseline loaded", "profile_summary": store.profile_summary()})
    if kind not in payloads:
        return jsonify({"error": "unknown demo"}), 404
    return jsonify(engine.analyze(payloads[kind](), source="demo"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
