"""
IoTShield Event Logger
======================
Structured JSONL event logging for the Ryu ARP-Guard controller.
Events are written to a file consumed by the Flask backend via SSE.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Optional

LOG_FILE = os.environ.get("IOTSHIELD_EVENT_LOG", "/tmp/iotshield_events.jsonl")
CONTROLLER_LOG = os.environ.get("IOTSHIELD_CTRL_LOG", "/tmp/iotshield_controller.log")

# Ensure files exist immediately with 0666 permissions so any user/process can write to them
for _fpath in (LOG_FILE, CONTROLLER_LOG):
    try:
        if not os.path.exists(_fpath):
            with open(_fpath, "w", encoding="utf-8"):
                pass
        os.chmod(_fpath, 0o666)
    except Exception:
        pass

# Thread-safe file write lock
_file_lock = threading.Lock()

# Standard Python logger for the controller process
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(CONTROLLER_LOG, mode="a"),
    ],
)

logger = logging.getLogger("iotshield.controller")


def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _write_event(event: dict) -> None:
    """Append a JSON event to the shared event log file."""
    event.setdefault("timestamp", _now_iso())
    line = json.dumps(event) + "\n"
    with _file_lock:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(line)
        except PermissionError:
            try:
                os.chmod(LOG_FILE, 0o666)
                with open(LOG_FILE, "a", encoding="utf-8") as fh:
                    fh.write(line)
            except Exception as exc:
                logger.error("Failed to write event log: %s", exc)
        except OSError as exc:
            logger.error("Failed to write event log: %s", exc)


# ── Public logging helpers ────────────────────────────────────────────────────

def log_startup(controller_ip: str, port: int) -> None:
    event = {
        "type": "CONTROLLER_STARTUP",
        "severity": "INFO",
        "controller_ip": controller_ip,
        "openflow_port": port,
        "message": f"IoTShield controller listening on {controller_ip}:{port}",
    }
    _write_event(event)
    logger.info(event["message"])


def log_switch_connected(datapath_id: int, n_tables: int) -> None:
    event = {
        "type": "SWITCH_CONNECTED",
        "severity": "INFO",
        "datapath_id": f"{datapath_id:#018x}",
        "n_tables": n_tables,
        "message": f"Switch 0x{datapath_id:016x} connected ({n_tables} tables)",
    }
    _write_event(event)
    logger.info(event["message"])


def log_arp_legitimate(
    src_ip: str,
    src_mac: str,
    dst_ip: str,
    in_port: int,
    operation: str,
) -> None:
    event = {
        "type": "ARP_LEGITIMATE",
        "severity": "INFO",
        "src_ip": src_ip,
        "src_mac": src_mac,
        "dst_ip": dst_ip,
        "in_port": in_port,
        "operation": operation,
        "action": "ALLOW",
        "message": f"Legitimate ARP {operation}: {src_ip} ({src_mac}) port={in_port} → {dst_ip}",
    }
    _write_event(event)
    logger.debug(event["message"])


def log_packet_forwarded(
    src_ip: str,
    src_mac: str,
    dst_ip: str,
    dst_mac: str,
    in_port: int,
    out_port: int,
    protocol: str = "ICMP",
) -> None:
    event = {
        "type": "PACKET_FORWARDED",
        "severity": "INFO",
        "src_ip": src_ip,
        "src_mac": src_mac,
        "dst_ip": dst_ip,
        "dst_mac": dst_mac,
        "in_port": in_port,
        "out_port": out_port,
        "protocol": protocol,
        "action": "ALLOW",
        "message": f"Legitimate {protocol}: {src_ip} ({src_mac}) port={in_port} → {dst_ip} ({dst_mac}) port={out_port}",
    }
    _write_event(event)
    logger.info(event["message"])


def log_arp_unknown(
    src_ip: str,
    src_mac: str,
    in_port: int,
    operation: str,
) -> None:
    event = {
        "type": "ARP_UNKNOWN_SENDER",
        "severity": "WARNING",
        "src_ip": src_ip,
        "src_mac": src_mac,
        "in_port": in_port,
        "operation": operation,
        "message": (
            f"Unknown ARP sender: {src_ip} ({src_mac}) port={in_port}. "
            "Not auto-trusted per policy."
        ),
    }
    _write_event(event)
    logger.warning(event["message"])


def log_arp_suspicious(
    src_ip: str,
    src_mac: str,
    in_port: int,
    operation: str,
    expected_mac: Optional[str],
    expected_port: Optional[int],
    reason: str,
    action: str,
    detection_latency_ms: Optional[float] = None,
) -> None:
    event = {
        "type": "ARP_SPOOFING_DETECTED",
        "severity": "CRITICAL",
        "src_ip": src_ip,
        "src_mac": src_mac,
        "in_port": in_port,
        "operation": operation,
        "expected_mac": expected_mac,
        "expected_port": expected_port,
        "reason": reason,
        "action": action,
        "detection_latency_ms": detection_latency_ms,
        "message": (
            f"ARP SPOOFING DETECTED: {src_ip} claimed by {src_mac} "
            f"(expected {expected_mac}) port={in_port}. "
            f"Reason: {reason}. Action: {action}."
        ),
    }
    _write_event(event)
    logger.critical(event["message"])


def log_flow_rule_installed(
    datapath_id: int,
    in_port: int,
    src_mac: str,
    priority: int,
    action: str,
) -> None:
    event = {
        "type": "FLOW_RULE_INSTALLED",
        "severity": "WARNING",
        "datapath_id": f"{datapath_id:#018x}",
        "in_port": in_port,
        "src_mac": src_mac,
        "priority": priority,
        "action": action,
        "message": (
            f"Drop rule installed: dpid=0x{datapath_id:016x} "
            f"in_port={in_port} src_mac={src_mac} priority={priority}"
        ),
    }
    _write_event(event)
    logger.warning(event["message"])


def log_flow_rule_removed(datapath_id: int, in_port: int, src_mac: str) -> None:
    event = {
        "type": "FLOW_RULE_REMOVED",
        "severity": "INFO",
        "datapath_id": f"{datapath_id:#018x}",
        "in_port": in_port,
        "src_mac": src_mac,
        "message": f"Drop rule removed: port={in_port} mac={src_mac}",
    }
    _write_event(event)
    logger.info(event["message"])


def log_port_mismatch(
    src_ip: str,
    src_mac: str,
    in_port: int,
    expected_port: int,
) -> None:
    event = {
        "type": "PORT_MISMATCH",
        "severity": "WARNING",
        "src_ip": src_ip,
        "src_mac": src_mac,
        "in_port": in_port,
        "expected_port": expected_port,
        "message": (
            f"Port mismatch: {src_ip} ({src_mac}) arrived on port {in_port}, "
            f"expected port {expected_port}"
        ),
    }
    _write_event(event)
    logger.warning(event["message"])


def log_attack_start(attacker_ip: str, attacker_mac: str, target_ip: str) -> None:
    event = {
        "type": "ATTACK_START_MARKER",
        "severity": "INFO",
        "attacker_ip": attacker_ip,
        "attacker_mac": attacker_mac,
        "target_ip": target_ip,
        "message": (
            f"[ATTACK MARKER] Attack script started: "
            f"{attacker_ip} ({attacker_mac}) spoofing {target_ip}"
        ),
    }
    _write_event(event)
    logger.info(event["message"])

