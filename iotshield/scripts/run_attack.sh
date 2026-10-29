#!/usr/bin/env bash
# =============================================================================
#  IoTShield Attack Script
#  Triggers the controlled ARP spoofing demonstration inside Mininet.
#  Usage: sudo bash scripts/run_attack.sh [--count N] [--interval S] [--dry-run]
#
#  This script ONLY targets the isolated Mininet lab network.
#  It NEVER sends traffic to the physical LAN or internet.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

VENV_PYTHON="$PROJECT_ROOT/venv/bin/python3"
if [ -f "$VENV_PYTHON" ]; then
    PYTHON="$VENV_PYTHON"
else
    PYTHON="python3"
fi

COUNT=10
INTERVAL=0.5
DRY_RUN=false

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --count) COUNT="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "======================================================"
echo "  IoTShield ARP Spoofing Attack Demo"
echo "  LAB USE ONLY — Isolated Mininet Network"
echo "======================================================"

# ── Check lab is running ──────────────────────────────────────────────────────
if [ ! -f /tmp/iotshield_mininet.pid ]; then
    echo "[WARN] Mininet PID file not found."
    echo "       Start the lab first: sudo bash scripts/start_lab.sh"
    echo "       Or continue anyway if you know Mininet is running."
    read -rp "       Continue? [y/N] " choice
    [[ "${choice,,}" != "y" ]] && exit 1
fi

if [ -f /tmp/iotshield_mininet.pid ]; then
    MN_PID=$(cat /tmp/iotshield_mininet.pid 2>/dev/null || echo "")
    if [ -n "$MN_PID" ] && ! kill -0 "$MN_PID" 2>/dev/null; then
        echo "[WARN] Mininet process (pid=$MN_PID) is not running."
    fi
fi

echo
echo "── Pre-attack: Testing h1 → h2 connectivity ─────────"
echo "  (Running from h1's network namespace)"

if [ "$(id -u)" -eq 0 ]; then
    H1_RESULT=$(ip netns exec h1 ping -c 3 -W 2 10.0.0.2 2>&1 || true)
    if echo "$H1_RESULT" | grep -q "0% packet loss\|[123] received"; then
        echo "  [PASS] h1 → h2 connectivity: WORKING before attack"
    else
        echo "  [WARN] h1 → h2 connectivity: uncertain before attack"
        echo "  $H1_RESULT"
    fi
else
    echo "  [INFO] Not root; skipping pre-attack ping test."
    echo "         From Mininet CLI, run: h1 ping -c 3 h2"
fi

echo
echo "── Launching attack from h3 ─────────────────────────"
DRY_FLAG=""
[ "$DRY_RUN" = true ] && DRY_FLAG="--dry-run"

cd "$PROJECT_ROOT"

if [ "$(id -u)" -eq 0 ]; then
    # Run the attack script inside h3's network namespace
    ip netns exec h3 $PYTHON attacks/arp_spoof.py \
        --iface h3-eth0 \
        --count "$COUNT" \
        --interval "$INTERVAL" \
        $DRY_FLAG
else
    echo "[WARN] Not running as root. Running attack script without namespace isolation."
    echo "       For a proper demo, use: sudo bash scripts/run_attack.sh"
    $PYTHON attacks/arp_spoof.py \
        --count "$COUNT" \
        --interval "$INTERVAL" \
        $DRY_FLAG
fi

echo
echo "── Post-attack: Checking OVS flow rules ─────────────"
if command -v ovs-ofctl &>/dev/null && [ "$(id -u)" -eq 0 ]; then
    echo "  Flow rules on s1 (including any drop rules):"
    sudo ovs-ofctl -O OpenFlow13 dump-flows s1 2>/dev/null || echo "  (OVS not available)"
else
    echo "  [INFO] Run manually: sudo ovs-ofctl -O OpenFlow13 dump-flows s1"
fi

echo
echo "── Post-attack: Testing h1 → h2 connectivity ────────"
if [ "$(id -u)" -eq 0 ]; then
    H1_POST=$(ip netns exec h1 ping -c 3 -W 2 10.0.0.2 2>&1 || true)
    if echo "$H1_POST" | grep -q "0% packet loss\|[123] received"; then
        echo "  [PASS] h1 → h2 connectivity: PRESERVED after attack mitigation"
    else
        echo "  [INFO] h1 → h2 connectivity after attack:"
        echo "  $H1_POST"
    fi
fi

echo
echo "======================================================"
echo "  Attack demo complete."
echo "  Check the dashboard: http://localhost:5000"
echo "  Ryu log: tail -f /tmp/iotshield_ryu.log"
echo "  Events:  tail -f /tmp/iotshield_events.jsonl"
echo "======================================================"

