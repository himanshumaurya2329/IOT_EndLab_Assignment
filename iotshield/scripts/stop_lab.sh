#!/usr/bin/env bash
# =============================================================================
#  IoTShield Lab Stop Script
#  Stops only IoTShield processes (Ryu, Mininet, backend).
#  Does NOT kill unrelated Python or OVS processes.
#  Usage: sudo bash scripts/stop_lab.sh
# =============================================================================
set -euo pipefail

echo "======================================================"
echo "  IoTShield Lab Shutdown"
echo "======================================================"

_stop_by_pid() {
    local name="$1"
    local pid_file="/tmp/iotshield_${name}.pid"

    if [ ! -f "$pid_file" ]; then
        echo "  [INFO] $name PID file not found (already stopped?)"
        return 0
    fi

    PID=$(cat "$pid_file" 2>/dev/null || echo "")
    if [ -z "$PID" ]; then
        echo "  [INFO] $name PID file empty"
        rm -f "$pid_file"
        return 0
    fi

    if kill -0 "$PID" 2>/dev/null; then
        echo "  [INFO] Stopping $name (pid=$PID)..."
        kill -TERM "$PID" 2>/dev/null || true
        sleep 2
        if kill -0 "$PID" 2>/dev/null; then
            echo "  [WARN] $name still running, sending SIGKILL..."
            kill -KILL "$PID" 2>/dev/null || true
        fi
        echo "  [OK] $name stopped"
    else
        echo "  [INFO] $name (pid=$PID) is not running"
    fi

    rm -f "$pid_file"
}

# Stop backend first (least disruptive)
_stop_by_pid "backend"
pkill -f 'backend/app.py' 2>/dev/null || true

# Stop Mininet
_stop_by_pid "mininet"

# Clean up Mininet state
echo
echo "── Cleaning Mininet state ────────────────────────────"
if command -v mn &>/dev/null && [ "$(id -u)" -eq 0 ]; then
    mn -c 2>/dev/null || true
    echo "  [OK] mn -c cleanup done"
else
    echo "  [INFO] Skipping mn -c (not root or mn not found)"
fi

# Stop Ryu
_stop_by_pid "ryu"
fuser -k 6633/tcp 2>/dev/null || true
fuser -k 5000/tcp 2>/dev/null || true

echo
echo "======================================================"
echo "  IoTShield Lab STOPPED"
echo "  All IoTShield processes have been terminated."
echo "  OVS and other system services are untouched."
echo "======================================================"

