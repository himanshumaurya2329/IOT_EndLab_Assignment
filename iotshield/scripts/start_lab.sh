#!/usr/bin/env bash
# =============================================================================
#  IoTShield Lab Startup Script
#  Starts Ryu controller, Mininet topology, and dashboard backend in order.
#  Usage: sudo bash scripts/start_lab.sh [--demo]
#
#  --demo: Start only the dashboard backend in demo mode (no Mininet needed)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_PYTHON="$PROJECT_ROOT/venv/bin/python3"
VENV_RYU="$PROJECT_ROOT/venv/bin/ryu-manager"
LOG_DIR="/tmp"
DEMO_MODE=false

# ── Parse args ────────────────────────────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --demo) DEMO_MODE=true ;;
    esac
done

# ── Python interpreter ────────────────────────────────────────────────────────
if [ -f "$VENV_PYTHON" ]; then
    PYTHON="$VENV_PYTHON"
else
    PYTHON="python3"
fi

# If running as root via sudo, inherit user site-packages if installed under ~/.local
if [ -n "${SUDO_USER:-}" ] && [ -d "/home/$SUDO_USER/.local/lib" ]; then
    USER_SITE=$(find "/home/$SUDO_USER/.local/lib" -maxdepth 2 -type d -name "site-packages" 2>/dev/null | tr '\n' ':' || true)
    if [ -n "$USER_SITE" ]; then
        export PYTHONPATH="${USER_SITE}${PYTHONPATH:-}"
    fi
fi

# ── Locate Ryu Manager ────────────────────────────────────────────────────────
if [ -f "$VENV_RYU" ]; then
    RYU="$VENV_RYU"
elif command -v ryu-manager &>/dev/null; then
    RYU="$(which ryu-manager)"
elif [ -f "/usr/local/bin/ryu-manager" ]; then
    RYU="/usr/local/bin/ryu-manager"
elif [ -n "${SUDO_USER:-}" ] && [ -f "/home/$SUDO_USER/.local/bin/ryu-manager" ]; then
    RYU="/home/$SUDO_USER/.local/bin/ryu-manager"
elif [ -f "$HOME/.local/bin/ryu-manager" ]; then
    RYU="$HOME/.local/bin/ryu-manager"
else
    RYU=""
fi

echo "======================================================"
echo "  IoTShield Lab Startup"
echo "  Mode: $([ "$DEMO_MODE" = true ] && echo 'DEMO' || echo 'LIVE')"
echo "======================================================"

cd "$PROJECT_ROOT"
export PYTHONPATH="$PROJECT_ROOT:${PYTHONPATH:-}"

# CRITICAL: Wipe all logs to zero BEFORE starting any process.
# This ensures the backend loads exactly 0 historic events on startup.
# We do this early (before Ryu / backend start) so nothing races the truncation.
printf '' > /tmp/iotshield_events.jsonl 2>/dev/null || true
printf '' > /tmp/iotshield_ryu.log    2>/dev/null || true
printf '' > /tmp/iotshield_backend.log 2>/dev/null || true
chmod 666 /tmp/iotshield_events.jsonl /tmp/iotshield_ryu.log /tmp/iotshield_backend.log 2>/dev/null || true

# ── Demo mode: just start the backend ────────────────────────────────────────
if [ "$DEMO_MODE" = true ]; then
    echo "[INFO] Starting dashboard in demo mode..."
    $PYTHON backend/app.py --demo --host 0.0.0.0 --port 5000 &
    echo $! > /tmp/iotshield_backend.pid
    sleep 2
    echo
    echo "======================================================"
    echo "  Dashboard ready (DEMO MODE):"
    echo "  http://localhost:5000"
    echo "  Logs: /tmp/iotshield_backend.log"
    echo "======================================================"
    echo
    echo "  NOTE: Demo mode shows labelled simulated events."
    echo "  For a live lab, run: sudo bash scripts/start_lab.sh"
    exit 0
fi

# ── Live mode: check root ─────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Mininet requires root. Run with sudo:"
    echo "        sudo bash scripts/start_lab.sh"
    exit 1
fi

# ── Step 1: Prerequisites ─────────────────────────────────────────────────────
echo
echo "── Step 1: Checking prerequisites ──────────────────"

if ! command -v mn &>/dev/null; then
    echo "[FAIL] Mininet not found. Run: bash scripts/install.sh"
    exit 1
fi

if ! ovs-vsctl show &>/dev/null 2>&1; then
    echo "[INFO] Starting OVS service..."
    systemctl start openvswitch-switch 2>/dev/null || \
    service openvswitch-switch start 2>/dev/null || \
        /usr/share/openvswitch/scripts/ovs-ctl start 2>/dev/null || \
        ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
            --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
            --pidfile --detach --log-file 2>/dev/null || true
    sleep 2
    ovs-vswitchd --pidfile --detach 2>/dev/null || true
    sleep 1
fi

if ovs-vsctl show &>/dev/null 2>&1; then
    echo "  [OK] OVS is running"
else
    echo "[FAIL] OVS could not be started."
    echo "       WSL2 limitation: the OVS kernel module may not be available."
    echo "       Try: sudo modprobe openvswitch"
    echo "       If that fails, see docs/troubleshooting.md for the Docker fallback."
    exit 1
fi

# ── Step 2: Clean stale state ─────────────────────────────────────────────────
echo
echo "── Step 2: Cleaning stale Mininet/OVS state ─────────"

mn -c 2>/dev/null || true
sleep 1
echo "  [OK] Mininet cleanup done"

# ── Step 3: Start Ryu controller ─────────────────────────────────────────────
echo
echo "── Step 3: Starting Ryu controller ─────────────────"

if [ -z "$RYU" ]; then
    echo "[FAIL] ryu-manager not found. Run: bash scripts/install.sh"
    exit 1
fi

# Kill any existing Ryu or stale process on port 6633
fuser -k 6633/tcp 2>/dev/null || true
if [ -f /tmp/iotshield_ryu.pid ]; then
    OLD_PID=$(cat /tmp/iotshield_ryu.pid 2>/dev/null || echo "")
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
    fi
fi

$RYU controller/sdn_guard.py \
    --ofp-tcp-listen-port 6633 \
    --observe-links \
    > "$LOG_DIR/iotshield_ryu.log" 2>&1 &
RYU_PID=$!
echo $RYU_PID > /tmp/iotshield_ryu.pid
echo "  [INFO] Ryu started (pid=$RYU_PID), log: $LOG_DIR/iotshield_ryu.log"

# Wait for Ryu to be ready
echo "  [INFO] Waiting for Ryu to listen on port 6633..."
for i in $(seq 1 15); do
    if ss -tlnp 2>/dev/null | grep -q ":6633 " || \
       netstat -tlnp 2>/dev/null | grep -q ":6633 "; then
        echo "  [OK] Ryu listening on port 6633"
        break
    fi
    if [ "$i" -eq 15 ]; then
        echo "  [WARN] Ryu not yet listening. Check log: $LOG_DIR/iotshield_ryu.log"
    fi
    sleep 1
done

# ── Step 4: Start dashboard backend ──────────────────────────────────────────
echo
echo "── Step 4: Starting dashboard backend ───────────────"

# Kill any existing backend or stale process on port 5000
fuser -k 5000/tcp 2>/dev/null || true
if [ -f /tmp/iotshield_backend.pid ]; then
    OLD_BACKEND_PID=$(cat /tmp/iotshield_backend.pid 2>/dev/null || echo "")
    if [ -n "$OLD_BACKEND_PID" ] && kill -0 "$OLD_BACKEND_PID" 2>/dev/null; then
        kill "$OLD_BACKEND_PID" 2>/dev/null || true
        sleep 1
    fi
fi
pkill -f 'backend/app.py' 2>/dev/null || true

$PYTHON backend/app.py \
    --host 0.0.0.0 \
    --port 5000 \
    > "$LOG_DIR/iotshield_backend.log" 2>&1 &
BACKEND_PID=$!
echo $BACKEND_PID > /tmp/iotshield_backend.pid
echo "  [INFO] Backend started (pid=$BACKEND_PID), log: $LOG_DIR/iotshield_backend.log"
sleep 2

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "======================================================"
echo "  IoTShield Lab STARTED"
echo
echo "  Dashboard:   http://localhost:5000"
echo
echo "  RECOMMENDED 3-TERMINAL SETUP:"
echo "    Terminal 1 (this window): Mininet CLI"
echo "    Terminal 2: python3 scripts/watch_ryu.py    (Readable Ryu controller log)"
echo "    Terminal 3: python3 scripts/watch_events.py (Security event monitor)"
echo
echo "  DEMO COMMANDS (type in Mininet CLI below):"
echo "    mininet> h1 ping -c 3 h2                             (normal traffic)"
echo "    mininet> h3 python3 attacks/arp_spoof.py --count 10  (launch attack)"
echo "    mininet> h1 ping -c 3 h2                             (verify h1-h2 unaffected)"
echo "======================================================"
echo

# ── Step 5: Start Mininet (Foreground interactive CLI) ───────────────────────
$PYTHON topology/iot_topology.py

