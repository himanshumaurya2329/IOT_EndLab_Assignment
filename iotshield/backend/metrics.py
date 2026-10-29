"""
IoTShield Metrics
=================
Calculates and records experiment metrics:
  - Detection time (attack start → first controller detection)
  - Prevention success rate
  - Added latency (baseline RTT vs protected RTT)

Results are exported to results/ as JSON and CSV.
"""

import csv
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

_HERE = Path(__file__).resolve().parent.parent
_RESULTS_DIR = _HERE / "results"


def _results_dir() -> Path:
    _RESULTS_DIR.mkdir(exist_ok=True)
    return _RESULTS_DIR


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Prevention Success Rate ───────────────────────────────────────────────────

def compute_prevention_rate(
    packets_sent: int,
    packets_detected: int,
    packets_dropped_by_rule: int,
    packets_dropped_current: int,
) -> Dict:
    """
    Compute prevention success rate.

    Prevention success rate = verified_prevented / total_attempted × 100

    Definitions:
      - packets_sent: packets the attack script attempted to send
      - packets_detected: packets the controller saw and classified as spoofed
      - packets_dropped_current: packets dropped immediately (no PacketOut)
      - packets_dropped_by_rule: subsequent packets dropped by installed OVS rule

    Limitation: We cannot independently verify that every rule-match equals
    a prevented packet unless we also check the victim's ARP cache.
    """
    if packets_sent == 0:
        return {
            "packets_sent": 0,
            "packets_detected": 0,
            "packets_dropped_current": 0,
            "packets_dropped_by_rule": packets_dropped_by_rule,
            "prevention_rate_pct": None,
            "note": "No attack packets were sent.",
        }

    total_prevented = packets_dropped_current + packets_dropped_by_rule
    rate = min(100.0, (total_prevented / packets_sent) * 100)

    return {
        "packets_sent": packets_sent,
        "packets_detected": packets_detected,
        "packets_dropped_current": packets_dropped_current,
        "packets_dropped_by_rule": packets_dropped_by_rule,
        "total_prevented": total_prevented,
        "prevention_rate_pct": round(rate, 2),
        "note": (
            "Rate = (dropped_current + dropped_by_rule) / packets_sent × 100. "
            "Packets dropped by installed OVS rule are counted via flow counters "
            "where available; otherwise estimated from attack count − detected."
        ),
    }


# ── Detection Time ────────────────────────────────────────────────────────────

def compute_detection_time(
    attack_start_ts: float,
    first_detection_ts: float,
) -> Dict:
    """
    Compute detection latency.

    attack_start_ts: UNIX timestamp (monotonic) when attack began
    first_detection_ts: UNIX timestamp (monotonic) when controller first detected

    Note: This measures the time from the attack script's first packet send
    to the controller's Packet-In handler processing. It includes:
      - Network propagation delay (within Mininet, negligible)
      - OVS Packet-In overhead
      - Controller processing time
    It does NOT measure external network latency.
    """
    if attack_start_ts is None or first_detection_ts is None:
        return {
            "attack_start_ts": None,
            "first_detection_ts": None,
            "detection_latency_ms": None,
            "note": "Attack start or detection timestamp not recorded.",
        }
    latency_ms = (first_detection_ts - attack_start_ts) * 1000
    return {
        "attack_start_ts": attack_start_ts,
        "first_detection_ts": first_detection_ts,
        "detection_latency_ms": round(latency_ms, 3),
        "note": (
            "Latency = first_detection - attack_start (monotonic clock). "
            "Includes OVS Packet-In processing but NOT external network latency."
        ),
    }


# ── Added Latency ─────────────────────────────────────────────────────────────

def compute_added_latency(
    baseline_rtt_ms: float,
    protected_rtt_ms: float,
) -> Dict:
    """
    Compute added latency due to SDN controller overhead.

    added_latency = protected_RTT - baseline_RTT

    Note: Controller processing time ≠ end-to-end network latency.
    After the first flow rule is installed, subsequent packets follow the
    data plane without controller involvement. The first-packet RTT is
    higher because it goes to the controller; subsequent packets do not.
    """
    added_ms = protected_rtt_ms - baseline_rtt_ms
    return {
        "baseline_rtt_ms": round(baseline_rtt_ms, 3),
        "protected_rtt_ms": round(protected_rtt_ms, 3),
        "added_latency_ms": round(added_ms, 3),
        "note": (
            "Added latency = protected_RTT − baseline_RTT. "
            "The first packet in a new flow incurs controller processing overhead. "
            "After flow-rule installation, subsequent packets bypass the controller."
        ),
    }


# ── Export helpers ────────────────────────────────────────────────────────────

def export_to_json(data: dict, filename: str) -> Path:
    path = _results_dir() / filename
    data["exported_at"] = _now_iso()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path


def export_to_csv(rows: List[Dict], filename: str, fieldnames: List[str]) -> Path:
    path = _results_dir() / filename
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


def save_full_experiment_results(
    prevention: Dict,
    detection: Dict,
    latency: Dict,
    topology: Dict,
    notes: str = "",
) -> Dict[str, Path]:
    """Save all experiment results and return file paths."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    full = {
        "experiment_timestamp": _now_iso(),
        "topology": topology,
        "prevention_metrics": prevention,
        "detection_metrics": detection,
        "latency_metrics": latency,
        "notes": notes,
    }

    json_path = export_to_json(full, f"experiment_{ts}.json")

    # Also write a flat CSV summary row
    flat = {
        "timestamp": _now_iso(),
        "packets_sent": prevention.get("packets_sent"),
        "packets_detected": prevention.get("packets_detected"),
        "total_prevented": prevention.get("total_prevented"),
        "prevention_rate_pct": prevention.get("prevention_rate_pct"),
        "detection_latency_ms": detection.get("detection_latency_ms"),
        "baseline_rtt_ms": latency.get("baseline_rtt_ms"),
        "protected_rtt_ms": latency.get("protected_rtt_ms"),
        "added_latency_ms": latency.get("added_latency_ms"),
    }
    fieldnames = list(flat.keys())
    csv_path = export_to_csv([flat], f"experiment_{ts}.csv", fieldnames)

    return {"json": json_path, "csv": csv_path}

