"""
IoTShield Event Service
=======================
Reads structured JSONL events from the controller's log file and
provides them to the Flask backend for SSE streaming and API queries.

The event log is written by controller/event_logger.py.
This service tails that file — no database required.
"""

import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional

EVENT_LOG_FILE = os.environ.get("IOTSHIELD_EVENT_LOG", "/tmp/iotshield_events.jsonl")
MAX_EVENTS = 500          # Keep last 500 events in memory
TAIL_INTERVAL = 0.25      # seconds between file tail polls

# Demo-mode events (clearly labelled) for when Mininet is unavailable
DEMO_EVENTS = [
    {
        "type": "CONTROLLER_STARTUP",
        "severity": "INFO",
        "message": "[DEMO] IoTShield controller started",
        "timestamp": "2026-10-29T00:00:00Z",
        "demo": True,
    },
    {
        "type": "SWITCH_CONNECTED",
        "severity": "INFO",
        "datapath_id": "0x0000000000000001",
        "message": "[DEMO] Switch s1 connected",
        "timestamp": "2026-10-29T00:00:01Z",
        "demo": True,
    },
    {
        "type": "ARP_LEGITIMATE",
        "severity": "INFO",
        "src_ip": "10.0.0.1",
        "src_mac": "00:00:00:00:00:01",
        "dst_ip": "10.0.0.2",
        "in_port": 1,
        "operation": "ARP_REQUEST",
        "message": "[DEMO] Legitimate ARP: h1 → h2",
        "timestamp": "2026-10-29T00:00:02Z",
        "demo": True,
    },
    {
        "type": "ARP_SPOOFING_DETECTED",
        "severity": "CRITICAL",
        "src_ip": "10.0.0.2",
        "src_mac": "00:00:00:00:00:03",
        "expected_mac": "00:00:00:00:00:02",
        "in_port": 3,
        "operation": "ARP_REPLY",
        "reason": "MAC mismatch: claimed 10.0.0.2 but MAC 00:00:00:00:00:03 ≠ expected 00:00:00:00:00:02",
        "action": "DROP_AND_INSTALL_RULE",
        "detection_latency_ms": 12.4,
        "message": "[DEMO] ARP SPOOFING DETECTED: h3 impersonating h2",
        "timestamp": "2026-10-29T00:00:03Z",
        "demo": True,
    },
    {
        "type": "FLOW_RULE_INSTALLED",
        "severity": "WARNING",
        "in_port": 3,
        "src_mac": "00:00:00:00:00:03",
        "priority": 200,
        "action": "DROP",
        "message": "[DEMO] Drop rule installed for attacker port 3",
        "timestamp": "2026-10-29T00:00:04Z",
        "demo": True,
    },
]


class EventService:
    """
    Tails the controller's JSONL event log and maintains an in-memory
    buffer of recent events for SSE streaming and REST queries.
    """

    def __init__(self, demo_mode: bool = False):
        self._events: Deque[dict] = deque(maxlen=MAX_EVENTS)
        self._subscribers: List[object] = []  # SSE queues
        self._lock = threading.Lock()
        self._demo_mode = demo_mode
        self._running = False
        self._tail_thread: Optional[threading.Thread] = None
        self._file_pos = 0

        if demo_mode:
            self._load_demo_events()

    def _load_demo_events(self):
        """Pre-load clearly labelled demo events."""
        now_base = time.time()
        for i, ev in enumerate(DEMO_EVENTS):
            ev = dict(ev)  # copy
            ev["timestamp"] = datetime.fromtimestamp(
                now_base - (len(DEMO_EVENTS) - i) * 2, tz=timezone.utc
            ).isoformat()
            ev["demo"] = True
            with self._lock:
                self._events.append(ev)

    def start_tailing(self):
        """Start background thread to tail the event log file.
        
        NOTE: We do NOT pre-load historic events here. The frontend fetches
        the current state via /api/events on page load. This prevents ghost
        events from appearing when the backend restarts mid-session.
        """
        if self._demo_mode:
            return
        self._running = True

        # Set file position to current end-of-file so we only tail NEW events
        # written after this backend process started. This is the correct behaviour:
        # the UI fetches historic events via GET /api/events and the SSE stream
        # delivers only future events.
        if os.path.exists(EVENT_LOG_FILE):
            try:
                self._file_pos = os.path.getsize(EVENT_LOG_FILE)
            except OSError:
                self._file_pos = 0
        else:
            self._file_pos = 0

        self._tail_thread = threading.Thread(
            target=self._tail_loop, daemon=True, name="EventTailer"
        )
        self._tail_thread.start()

    def stop_tailing(self):
        self._running = False

    def _tail_loop(self):
        """Continuously read new lines from the event log file."""
        while self._running:
            try:
                if not os.path.exists(EVENT_LOG_FILE):
                    time.sleep(TAIL_INTERVAL)
                    continue
                size = os.path.getsize(EVENT_LOG_FILE)
                if size < self._file_pos:
                    # File was rotated/truncated
                    self._file_pos = 0
                if size > self._file_pos:
                    with open(EVENT_LOG_FILE, "r", encoding="utf-8") as fh:
                        fh.seek(self._file_pos)
                        new_data = fh.read()
                        self._file_pos = fh.tell()
                    for line in new_data.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                            self._ingest(event)
                        except json.JSONDecodeError:
                            pass
            except OSError:
                pass
            time.sleep(TAIL_INTERVAL)

    def _ingest(self, event: dict):
        """Store event and notify SSE subscribers."""
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        event["demo"] = False
        with self._lock:
            self._events.append(event)
            # Notify all SSE subscriber queues
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except Exception:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)

    def subscribe(self, replay_recent: bool = True) -> "SimpleQueue":
        """Register a new SSE subscriber queue and return it.
        
        Args:
            replay_recent: If True, replay up to 20 recent in-memory events to the queue.
                           Set to False when subscriber (e.g. SSE stream) fetches history
                           separately via /api/events to prevent double-rendering.
        """
        import queue
        q = queue.SimpleQueue()
        with self._lock:
            self._subscribers.append(q)
            if replay_recent:
                recent = list(self._events)[-20:]
                for ev in recent:
                    q.put_nowait(ev)
        return q

    def unsubscribe(self, q):
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def get_recent_events(self, limit: int = 100, event_type: Optional[str] = None) -> List[dict]:
        with self._lock:
            events = list(self._events)
        if event_type:
            events = [e for e in events if e.get("type") == event_type]
        return events[-limit:]

    def get_stats(self) -> Dict:
        with self._lock:
            events = list(self._events)
        stats = {
            "total_events": len(events),
            "arp_inspected": 0,
            "arp_legitimate": 0,
            "arp_suspicious": 0,
            "arp_unknown": 0,
            "flow_rules_installed": 0,
            "packets_blocked": 0,
            "demo_mode": self._demo_mode,
        }
        for ev in events:
            t = ev.get("type", "")
            if t in ("ARP_LEGITIMATE", "PACKET_FORWARDED"):
                stats["arp_legitimate"] += 1
                stats["arp_inspected"] += 1
            elif t == "ARP_SPOOFING_DETECTED":
                stats["arp_suspicious"] += 1
                stats["arp_inspected"] += 1
                stats["packets_blocked"] += 1
            elif t == "ARP_UNKNOWN_SENDER":
                stats["arp_unknown"] += 1
                stats["arp_inspected"] += 1
            elif t == "FLOW_RULE_INSTALLED":
                stats["flow_rules_installed"] += 1
        return stats

    def get_detection_latency_ms(self) -> Optional[float]:
        """Return detection latency from the most recent attack detection."""
        with self._lock:
            events = list(self._events)
        for ev in reversed(events):
            if ev.get("type") == "ARP_SPOOFING_DETECTED":
                return ev.get("detection_latency_ms")
        return None

    def clear_events(self):
        """Clear event buffer (used on lab reset)."""
        with self._lock:
            self._events.clear()
            dead = []
            reset_ev = {
                "type": "RESET",
                "severity": "INFO",
                "message": "Security logs cleared",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            for q in self._subscribers:
                try:
                    q.put_nowait(reset_ev)
                except Exception:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)
        self._file_pos = 0
        if not self._demo_mode and os.path.exists(EVENT_LOG_FILE):
            try:
                with open(EVENT_LOG_FILE, "w") as f:
                    pass  # truncate
            except OSError:
                pass

