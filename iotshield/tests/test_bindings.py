"""
IoTShield Unit Tests — Trusted Bindings and Security Logic
===========================================================
Tests the core ARP spoofing detection logic WITHOUT requiring Mininet,
Open vSwitch, or Ryu to be running.

Run: python -m pytest tests/ -q
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Make project root importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Trusted Bindings Data ──────────────────────────────────────────────────────

TRUSTED = {
    "10.0.0.1": {"mac": "00:00:00:00:00:01", "port": 1, "host": "h1", "role": "IoT Sensor"},
    "10.0.0.2": {"mac": "00:00:00:00:00:02", "port": 2, "host": "h2", "role": "Trusted Server"},
    "10.0.0.3": {"mac": "00:00:00:00:00:03", "port": 3, "host": "h3", "role": "Attacker"},
}

POLICY = {
    "unknown_sender": "warn",
    "mismatch_action": "drop_and_block",
    "port_mismatch_action": "warn_and_log",
    "auto_trust_unknown": False,
}


# ── Helper: minimal ARP spoofing detection logic (extracted from sdn_guard) ───

def classify_arp(trusted, sender_ip, sender_mac, in_port):
    """
    Classify an ARP packet claim.
    Returns: ("LEGITIMATE", None) | ("SPOOFING", reason) | ("UNKNOWN", None)
    """
    sender_mac = sender_mac.lower()
    binding = trusted.get(sender_ip)

    if binding is None:
        return "UNKNOWN", None

    expected_mac = binding["mac"].lower()
    expected_port = binding.get("port")

    if sender_mac != expected_mac:
        reason = (
            f"MAC mismatch: IP {sender_ip} claimed by {sender_mac} "
            f"but expected {expected_mac}"
        )
        return "SPOOFING", reason

    if expected_port is not None and in_port != expected_port:
        reason = f"Port mismatch: arrived on {in_port}, expected {expected_port}"
        return "PORT_MISMATCH", reason

    return "LEGITIMATE", None


# ── Tests: IP-MAC matching ────────────────────────────────────────────────────

class TestIPMACBinding:
    def test_legitimate_h1(self):
        result, reason = classify_arp(TRUSTED, "10.0.0.1", "00:00:00:00:00:01", 1)
        assert result == "LEGITIMATE"
        assert reason is None

    def test_legitimate_h2(self):
        result, reason = classify_arp(TRUSTED, "10.0.0.2", "00:00:00:00:00:02", 2)
        assert result == "LEGITIMATE"

    def test_legitimate_h3(self):
        result, reason = classify_arp(TRUSTED, "10.0.0.3", "00:00:00:00:00:03", 3)
        assert result == "LEGITIMATE"

    def test_mac_mismatch_detected(self):
        """h3 claiming h2's IP — the core attack scenario."""
        result, reason = classify_arp(
            TRUSTED,
            sender_ip="10.0.0.2",       # h2's IP
            sender_mac="00:00:00:00:00:03",  # h3's MAC (WRONG)
            in_port=3,
        )
        assert result == "SPOOFING"
        assert reason is not None
        assert "mismatch" in reason.lower()
        assert "10.0.0.2" in reason
        assert "00:00:00:00:00:03" in reason

    def test_mac_mismatch_any_ip(self):
        """Any host with a wrong MAC for a known IP is detected."""
        result, reason = classify_arp(
            TRUSTED,
            sender_ip="10.0.0.1",
            sender_mac="de:ad:be:ef:00:01",  # unknown MAC for h1
            in_port=1,
        )
        assert result == "SPOOFING"

    def test_unknown_sender(self):
        """An IP not in the trusted table is unknown, not automatically malicious."""
        result, reason = classify_arp(
            TRUSTED,
            sender_ip="10.0.0.99",      # not in trusted table
            sender_mac="aa:bb:cc:dd:ee:ff",
            in_port=4,
        )
        assert result == "UNKNOWN"
        assert reason is None  # Unknown, not SPOOFING

    def test_port_mismatch(self):
        """h1's legitimate MAC arriving on wrong port triggers PORT_MISMATCH."""
        result, reason = classify_arp(
            TRUSTED,
            sender_ip="10.0.0.1",
            sender_mac="00:00:00:00:00:01",  # correct MAC
            in_port=2,                          # WRONG port
        )
        assert result == "PORT_MISMATCH"
        assert reason is not None

    def test_mac_case_insensitive(self):
        """MAC comparison is case-insensitive."""
        result, _ = classify_arp(
            TRUSTED,
            sender_ip="10.0.0.1",
            sender_mac="00:00:00:00:00:01".upper(),  # uppercase
            in_port=1,
        )
        assert result == "LEGITIMATE"

    def test_spoofing_takes_priority_over_port(self):
        """MAC mismatch detected even when port also mismatches."""
        result, _ = classify_arp(
            TRUSTED,
            sender_ip="10.0.0.2",
            sender_mac="00:00:00:00:00:03",  # wrong MAC
            in_port=99,                        # also wrong port
        )
        assert result == "SPOOFING"  # MAC mismatch checked first


# ── Tests: Trusted bindings JSON loading ─────────────────────────────────────

class TestBindingsLoader:
    def test_valid_bindings_file(self, tmp_path):
        """Valid bindings JSON is parsed correctly."""
        data = {
            "bindings": [
                {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "port": 1, "host": "h1"},
            ],
            "policy": {"unknown_sender": "warn"},
        }
        f = tmp_path / "bindings.json"
        f.write_text(json.dumps(data))

        with open(f) as fh:
            loaded = json.load(fh)

        assert len(loaded["bindings"]) == 1
        assert loaded["bindings"][0]["ip"] == "10.0.0.1"

    def test_empty_bindings(self, tmp_path):
        data = {"bindings": [], "policy": {}}
        f = tmp_path / "bindings.json"
        f.write_text(json.dumps(data))

        with open(f) as fh:
            loaded = json.load(fh)
        assert loaded["bindings"] == []

    def test_invalid_json_raises(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("NOT VALID JSON {{{")

        with pytest.raises(json.JSONDecodeError):
            with open(f) as fh:
                json.load(fh)


# ── Tests: Metrics ────────────────────────────────────────────────────────────

class TestMetrics:
    def test_prevention_rate_100_percent(self):
        from backend.metrics import compute_prevention_rate
        result = compute_prevention_rate(
            packets_sent=10,
            packets_detected=10,
            packets_dropped_by_rule=0,
            packets_dropped_current=10,
        )
        assert result["prevention_rate_pct"] == 100.0

    def test_prevention_rate_50_percent(self):
        from backend.metrics import compute_prevention_rate
        result = compute_prevention_rate(
            packets_sent=10,
            packets_detected=5,
            packets_dropped_by_rule=0,
            packets_dropped_current=5,
        )
        assert result["prevention_rate_pct"] == 50.0

    def test_prevention_rate_zero_sent(self):
        from backend.metrics import compute_prevention_rate
        result = compute_prevention_rate(
            packets_sent=0,
            packets_detected=0,
            packets_dropped_by_rule=0,
            packets_dropped_current=0,
        )
        assert result["prevention_rate_pct"] is None

    def test_prevention_rate_cap_at_100(self):
        """Rate cannot exceed 100% even if counters are inconsistent."""
        from backend.metrics import compute_prevention_rate
        result = compute_prevention_rate(
            packets_sent=5,
            packets_detected=5,
            packets_dropped_by_rule=5,
            packets_dropped_current=5,  # total=10 > sent=5
        )
        assert result["prevention_rate_pct"] == 100.0

    def test_detection_time(self):
        from backend.metrics import compute_detection_time
        start = 1000.0
        detected = 1000.012  # 12ms later
        result = compute_detection_time(start, detected)
        assert abs(result["detection_latency_ms"] - 12.0) < 0.1

    def test_detection_time_none_inputs(self):
        from backend.metrics import compute_detection_time
        result = compute_detection_time(None, None)
        assert result["detection_latency_ms"] is None

    def test_added_latency(self):
        from backend.metrics import compute_added_latency
        result = compute_added_latency(baseline_rtt_ms=2.5, protected_rtt_ms=5.1)
        assert abs(result["added_latency_ms"] - 2.6) < 0.01

    def test_added_latency_negative(self):
        """Protected RTT can theoretically be less (measurement noise)."""
        from backend.metrics import compute_added_latency
        result = compute_added_latency(baseline_rtt_ms=5.0, protected_rtt_ms=4.9)
        assert result["added_latency_ms"] < 0


# ── Tests: Event Service ───────────────────────────────────────────────────────

class TestEventService:
    def test_event_ingestion(self, tmp_path):
        from backend.event_service import EventService
        svc = EventService(demo_mode=False)

        event = {
            "type": "ARP_SPOOFING_DETECTED",
            "severity": "CRITICAL",
            "src_ip": "10.0.0.2",
            "src_mac": "00:00:00:00:00:03",
        }
        svc._ingest(event)

        events = svc.get_recent_events(limit=10)
        assert len(events) == 1
        assert events[0]["type"] == "ARP_SPOOFING_DETECTED"

    def test_demo_events_labelled(self):
        from backend.event_service import EventService
        svc = EventService(demo_mode=True)
        events = svc.get_recent_events(limit=100)
        assert len(events) > 0
        for ev in events:
            assert ev.get("demo") is True, f"Event not labelled as demo: {ev}"

    def test_stats_aggregation(self):
        from backend.event_service import EventService
        svc = EventService(demo_mode=False)

        svc._ingest({"type": "ARP_LEGITIMATE"})
        svc._ingest({"type": "ARP_LEGITIMATE"})
        svc._ingest({"type": "ARP_SPOOFING_DETECTED"})
        svc._ingest({"type": "ARP_UNKNOWN_SENDER"})

        stats = svc.get_stats()
        assert stats["arp_legitimate"] == 2
        assert stats["arp_suspicious"] == 1
        assert stats["arp_unknown"] == 1
        assert stats["arp_inspected"] == 4

    def test_event_filter_by_type(self):
        from backend.event_service import EventService
        svc = EventService(demo_mode=False)

        svc._ingest({"type": "ARP_LEGITIMATE"})
        svc._ingest({"type": "ARP_SPOOFING_DETECTED"})

        suspicious = svc.get_recent_events(event_type="ARP_SPOOFING_DETECTED")
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "ARP_SPOOFING_DETECTED"

    def test_clear_events(self):
        from backend.event_service import EventService
        svc = EventService(demo_mode=False)
        svc._ingest({"type": "ARP_LEGITIMATE"})
        assert len(svc.get_recent_events()) == 1

        svc.clear_events()
        assert len(svc.get_recent_events()) == 0

    def test_event_timestamp_generated(self):
        from backend.event_service import EventService
        svc = EventService(demo_mode=False)
        svc._ingest({"type": "ARP_LEGITIMATE"})  # no timestamp provided
        events = svc.get_recent_events()
        assert "timestamp" in events[0]

    def test_subscription_queue(self):
        from backend.event_service import EventService
        svc = EventService(demo_mode=False)
        q = svc.subscribe()

        svc._ingest({"type": "ARP_LEGITIMATE", "msg": "test"})

        # Should have the event in the queue
        import queue as q_module
        try:
            event = q.get(timeout=1)
            assert event["type"] == "ARP_LEGITIMATE"
        except q_module.Empty:
            pytest.fail("Subscribed queue did not receive event")

        svc.unsubscribe(q)


# ── Tests: Event Serialization ────────────────────────────────────────────────

class TestEventSerialization:
    def test_event_is_json_serializable(self):
        from controller.event_logger import (
            log_arp_suspicious, LOG_FILE
        )
        import os

        # Use temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as tf:
            temp_log = tf.name

        with patch("controller.event_logger.LOG_FILE", temp_log):
            from controller.event_logger import _write_event
            event = {
                "type": "ARP_SPOOFING_DETECTED",
                "severity": "CRITICAL",
                "src_ip": "10.0.0.2",
                "src_mac": "00:00:00:00:00:03",
                "detection_latency_ms": 12.5,
            }
            _write_event(event)

        with open(temp_log) as fh:
            line = fh.readline()
            parsed = json.loads(line)

        assert parsed["type"] == "ARP_SPOOFING_DETECTED"
        assert parsed["detection_latency_ms"] == 12.5
        assert "timestamp" in parsed

        os.unlink(temp_log)


# ── Tests: Export ─────────────────────────────────────────────────────────────

class TestExport:
    def test_export_to_json(self, tmp_path):
        from backend.metrics import export_to_json
        data = {"prevention_rate_pct": 90.0, "packets_sent": 10}

        with patch("backend.metrics._RESULTS_DIR", tmp_path):
            path = export_to_json(data, "test_export.json")

        assert path.exists()
        with open(path) as fh:
            loaded = json.load(fh)
        assert loaded["prevention_rate_pct"] == 90.0
        assert "exported_at" in loaded

    def test_export_to_csv(self, tmp_path):
        from backend.metrics import export_to_csv
        rows = [{"metric": "latency", "value_ms": 12.5}]
        fieldnames = ["metric", "value_ms"]

        with patch("backend.metrics._RESULTS_DIR", tmp_path):
            path = export_to_csv(rows, "test_export.csv", fieldnames)

        assert path.exists()
        with open(path) as fh:
            content = fh.read()
        assert "latency" in content
        assert "12.5" in content

