"""
IoTShield Lab Manager
=====================
Manages starting, stopping, and resetting lab processes safely.

Only invoked from local API endpoints; subprocess calls do not use
shell=True or user-supplied strings to prevent injection.
"""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

_HERE = Path(__file__).resolve().parent.parent
_PID_DIR = Path("/tmp")

# PID files for each managed process
_PID_FILES = {
    "ryu": _PID_DIR / "iotshield_ryu.pid",
    "mininet": _PID_DIR / "iotshield_mininet.pid",
    "backend": _PID_DIR / "iotshield_backend.pid",
}

_VENV_PYTHON = _HERE / "venv" / "bin" / "python3"
_SYSTEM_PYTHON = "python3"


def _python() -> str:
    if _VENV_PYTHON.exists():
        return str(_VENV_PYTHON)
    return _SYSTEM_PYTHON


def _read_pid(name: str) -> Optional[int]:
    pf = _PID_FILES.get(name)
    if pf and pf.exists():
        try:
            return int(pf.read_text().strip())
        except (ValueError, OSError):
            pass
    return None


def _write_pid(name: str, pid: int):
    pf = _PID_FILES[name]
    pf.write_text(str(pid))


def _process_alive(pid: Optional[int]) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists and is running, but owned by another user (e.g. root)
        return True
    except OSError:
        return False


def get_lab_status() -> Dict:
    """Return current status of all lab components."""
    ryu_pid = _read_pid("ryu")
    mn_pid = _read_pid("mininet")
    return {
        "ryu_running": _process_alive(ryu_pid),
        "ryu_pid": ryu_pid,
        "mininet_running": _process_alive(mn_pid),
        "mininet_pid": mn_pid,
        "controller_port_open": _check_port(6633),
        "backend_port_open": _check_port(5000),
    }


def _check_port(port: int) -> bool:
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
        s.close()
        return True
    except OSError:
        return False


def start_ryu(log_file: str = "/tmp/iotshield_ryu.log") -> Tuple[bool, str]:
    """Start the Ryu controller as a background process."""
    if _process_alive(_read_pid("ryu")):
        return True, "Ryu already running"

    ryu_manager = _find_ryu_manager()
    if not ryu_manager:
        return False, "ryu-manager not found. Run: pip install ryu"

    controller_app = str(_HERE / "controller" / "sdn_guard.py")
    cmd = [
        ryu_manager,
        controller_app,
        "--ofp-tcp-listen-port", "6633",
        "--observe-links",
    ]

    with open(log_file, "w") as log_fh:
        proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,   # detach from terminal
        )

    _write_pid("ryu", proc.pid)
    time.sleep(2)

    if not _process_alive(proc.pid):
        return False, f"Ryu failed to start. Check log: {log_file}"

    return True, f"Ryu started (pid={proc.pid})"


def _find_ryu_manager() -> Optional[str]:
    """Locate ryu-manager in PATH or venv."""
    venv_ryu = _HERE / "venv" / "bin" / "ryu-manager"
    if venv_ryu.exists():
        return str(venv_ryu)
    result = subprocess.run(
        ["which", "ryu-manager"], capture_output=True, text=True
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def stop_ryu() -> Tuple[bool, str]:
    """Stop the Ryu controller process."""
    pid = _read_pid("ryu")
    if not _process_alive(pid):
        return True, "Ryu not running"
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
        time.sleep(1)
        if _process_alive(pid):
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        _PID_FILES["ryu"].unlink(missing_ok=True)
        return True, f"Ryu stopped (was pid={pid})"
    except (ProcessLookupError, PermissionError) as exc:
        return False, f"Could not stop Ryu: {exc}"


def trigger_attack(
    count: int = 10,
    interval: float = 0.5,
    dry_run: bool = False,
) -> Tuple[bool, str]:
    """
    Trigger the ARP spoofing attack inside Mininet.
    Validates inputs before execution.
    """
    # Validate
    count = max(1, min(count, 100))         # clamp to [1, 100]
    interval = max(0.1, min(interval, 5.0)) # clamp to [0.1, 5.0]

    if not _process_alive(_read_pid("mininet")):
        return False, "Mininet is not running. Start the lab first."

    attack_script = str(_HERE / "attacks" / "arp_spoof.py")
    cmd = [
        "sudo", "ip", "netns", "exec", "h3",
        _python(), attack_script,
        "--iface", "h3-eth0",
        "--count", str(count),
        "--interval", str(interval),
    ]
    if dry_run:
        cmd.append("--dry-run")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return True, f"Attack launched (pid={proc.pid})"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Failed to launch attack: {exc}"


def reset_lab() -> Tuple[bool, str]:
    """
    Reset the lab to a clean state.
    - Clear OVS flow rules
    - Clear event log
    - Remove quarantine/drop rules
    """
    messages = []

    # Remove drop and forwarding flow rules on s1, then reinstate table-miss
    try:
        subprocess.run(
            ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1"],
            capture_output=True, text=True, timeout=5
        )
        # CRITICAL: Always re-install table-miss rule so packets continue reaching Ryu!
        add_res = subprocess.run(
            ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1", "priority=0,actions=controller"],
            capture_output=True, text=True, timeout=5
        )
        if add_res.returncode == 0:
            messages.append("OVS rules reset (table-miss re-installed)")
        else:
            messages.append(f"OVS table-miss re-install WARN: {add_res.stderr.strip()}")
    except (OSError, subprocess.TimeoutExpired) as exc:
        messages.append(f"OVS reset skipped: {exc}")

    # Flush ARP neighbor tables inside Mininet host namespaces so fresh ARP occurs
    try:
        pg_res = subprocess.run(["pgrep", "-f", "mininet:h"], capture_output=True, text=True, timeout=3)
        if pg_res.returncode == 0:
            pids = pg_res.stdout.strip().split()
            for pid in pids:
                if pid.isdigit():
                    subprocess.run(
                        ["sudo", "nsenter", "-t", pid, "-n", "ip", "neigh", "flush", "all"],
                        capture_output=True, text=True, timeout=2
                    )
            messages.append("Host ARP neighbor tables flushed")
    except Exception as exc:
        messages.append(f"Host ARP flush note: {exc}")

    # Signal Ryu controller to reset its internal active_drops and stats
    try:
        Path("/tmp/iotshield_reset.trigger").touch()
        messages.append("Controller reset signaled")
    except Exception:
        pass

    # Clear event log
    event_log = Path("/tmp/iotshield_events.jsonl")
    if event_log.exists():
        event_log.write_text("")
        messages.append("Event log cleared")

    return True, "; ".join(messages)

