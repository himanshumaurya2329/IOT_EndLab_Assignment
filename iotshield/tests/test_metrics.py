"""
IoTShield Unit Tests — Metrics Module
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestPreventionRate:
    def test_full_prevention(self):
        from backend.metrics import compute_prevention_rate
        r = compute_prevention_rate(10, 10, 0, 10)
        assert r["prevention_rate_pct"] == 100.0
        assert r["total_prevented"] == 10

    def test_partial_prevention(self):
        from backend.metrics import compute_prevention_rate
        r = compute_prevention_rate(10, 7, 3, 4)
        # dropped_current(4) + dropped_by_rule(3) = 7 / 10 = 70%
        assert r["prevention_rate_pct"] == 70.0

    def test_zero_sent(self):
        from backend.metrics import compute_prevention_rate
        r = compute_prevention_rate(0, 0, 0, 0)
        assert r["prevention_rate_pct"] is None

    def test_rate_never_exceeds_100(self):
        from backend.metrics import compute_prevention_rate
        r = compute_prevention_rate(5, 5, 10, 10)
        assert r["prevention_rate_pct"] == 100.0

    def test_result_includes_note(self):
        from backend.metrics import compute_prevention_rate
        r = compute_prevention_rate(10, 5, 0, 5)
        assert "note" in r
        assert len(r["note"]) > 10


class TestDetectionTime:
    def test_normal_calculation(self):
        from backend.metrics import compute_detection_time
        r = compute_detection_time(1000.0, 1000.025)
        assert abs(r["detection_latency_ms"] - 25.0) < 0.01

    def test_zero_latency(self):
        from backend.metrics import compute_detection_time
        r = compute_detection_time(100.0, 100.0)
        assert r["detection_latency_ms"] == 0.0

    def test_none_start(self):
        from backend.metrics import compute_detection_time
        r = compute_detection_time(None, 1000.0)
        assert r["detection_latency_ms"] is None

    def test_none_detection(self):
        from backend.metrics import compute_detection_time
        r = compute_detection_time(1000.0, None)
        assert r["detection_latency_ms"] is None


class TestAddedLatency:
    def test_normal_overhead(self):
        from backend.metrics import compute_added_latency
        r = compute_added_latency(2.0, 5.5)
        assert abs(r["added_latency_ms"] - 3.5) < 0.01

    def test_no_overhead(self):
        from backend.metrics import compute_added_latency
        r = compute_added_latency(2.0, 2.0)
        assert r["added_latency_ms"] == 0.0

    def test_negative_overhead(self):
        """Measurement noise can produce negative added latency."""
        from backend.metrics import compute_added_latency
        r = compute_added_latency(5.0, 4.8)
        assert r["added_latency_ms"] < 0

    def test_result_contains_all_keys(self):
        from backend.metrics import compute_added_latency
        r = compute_added_latency(1.0, 3.0)
        assert "baseline_rtt_ms" in r
        assert "protected_rtt_ms" in r
        assert "added_latency_ms" in r
        assert "note" in r

