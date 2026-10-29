"""
IoTShield Unit Tests — Event Service Module
"""

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestEventServiceLive:
    """Tests for EventService in live (non-demo) mode."""

    def _make_svc(self):
        from backend.event_service import EventService
        return EventService(demo_mode=False)

    def test_initial_empty(self):
        svc = self._make_svc()
        events = svc.get_recent_events()
        assert events == []

    def test_ingest_single(self):
        svc = self._make_svc()
        svc._ingest({"type": "ARP_LEGITIMATE", "src_ip": "10.0.0.1"})
        events = svc.get_recent_events()
        assert len(events) == 1

    def test_timestamp_added(self):
        svc = self._make_svc()
        svc._ingest({"type": "TEST"})
        ev = svc.get_recent_events()[0]
        assert "timestamp" in ev

    def test_demo_false_in_live_mode(self):
        svc = self._make_svc()
        svc._ingest({"type": "ARP_LEGITIMATE"})
        ev = svc.get_recent_events()[0]
        assert ev["demo"] is False

    def test_limit_respected(self):
        svc = self._make_svc()
        for i in range(20):
            svc._ingest({"type": "ARP_LEGITIMATE", "seq": i})
        events = svc.get_recent_events(limit=5)
        assert len(events) == 5

    def test_filter_by_type(self):
        svc = self._make_svc()
        svc._ingest({"type": "ARP_LEGITIMATE"})
        svc._ingest({"type": "ARP_SPOOFING_DETECTED"})
        svc._ingest({"type": "ARP_LEGITIMATE"})

        critical = svc.get_recent_events(event_type="ARP_SPOOFING_DETECTED")
        assert len(critical) == 1

    def test_stats_counts(self):
        svc = self._make_svc()
        for _ in range(3):
            svc._ingest({"type": "ARP_LEGITIMATE"})
        svc._ingest({"type": "ARP_SPOOFING_DETECTED"})
        svc._ingest({"type": "ARP_UNKNOWN_SENDER"})
        svc._ingest({"type": "FLOW_RULE_INSTALLED"})

        stats = svc.get_stats()
        assert stats["arp_legitimate"] == 3
        assert stats["arp_suspicious"] == 1
        assert stats["arp_unknown"] == 1
        assert stats["arp_inspected"] == 5
        assert stats["flow_rules_installed"] == 1

    def test_clear_empties_buffer(self):
        svc = self._make_svc()
        for _ in range(5):
            svc._ingest({"type": "ARP_LEGITIMATE"})
        svc.clear_events()
        assert svc.get_recent_events() == []

    def test_subscribe_receives_future_events(self):
        import queue
        svc = self._make_svc()
        q = svc.subscribe()
        svc._ingest({"type": "ARP_SPOOFING_DETECTED", "src_ip": "10.0.0.2"})

        try:
            ev = q.get(timeout=1)
            assert ev["type"] == "ARP_SPOOFING_DETECTED"
        except queue.Empty:
            pytest.fail("Subscriber did not receive event")

    def test_subscribe_receives_recent_events(self):
        svc = self._make_svc()
        # Ingest some events before subscribing
        for i in range(5):
            svc._ingest({"type": "ARP_LEGITIMATE", "seq": i})

        import queue
        q = svc.subscribe()
        # Recent events should be replayed
        received = []
        try:
            while True:
                received.append(q.get_nowait())
        except queue.Empty:
            pass

        assert len(received) >= 5  # At least the 5 recent events

    def test_unsubscribe(self):
        import queue
        svc = self._make_svc()
        q = svc.subscribe()
        svc.unsubscribe(q)
        # After unsubscribing, future events should not go to q
        svc._ingest({"type": "ARP_LEGITIMATE"})
        with pytest.raises(queue.Empty):
            q.get_nowait()

    def test_detection_latency_none_initially(self):
        svc = self._make_svc()
        assert svc.get_detection_latency_ms() is None

    def test_detection_latency_from_event(self):
        svc = self._make_svc()
        svc._ingest({
            "type": "ARP_SPOOFING_DETECTED",
            "detection_latency_ms": 15.5,
        })
        assert svc.get_detection_latency_ms() == 15.5


class TestEventServiceDemoMode:
    def test_demo_events_present(self):
        from backend.event_service import EventService
        svc = EventService(demo_mode=True)
        events = svc.get_recent_events()
        assert len(events) > 0

    def test_all_demo_events_labelled(self):
        from backend.event_service import EventService
        svc = EventService(demo_mode=True)
        events = svc.get_recent_events()
        for ev in events:
            assert ev.get("demo") is True, f"Unlabelled demo event: {ev}"

    def test_demo_stats_not_empty(self):
        from backend.event_service import EventService
        svc = EventService(demo_mode=True)
        stats = svc.get_stats()
        assert stats["demo_mode"] is True
        # Demo mode loads preset events
        assert stats["arp_inspected"] > 0

