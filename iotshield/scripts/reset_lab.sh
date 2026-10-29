#!/usr/bin/env bash
# =============================================================================
#  IoTShield Lab Reset Script
#  Restores the lab to a clean state after an attack demonstration.
#  Clears drop/quarantine rules, clears event log, verifies h1-h2 connectivity.
#  Usage: sudo bash scripts/reset_lab.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "======================================================"
echo "  IoTShield Lab Reset"
echo "======================================================"

# ── Check root ────────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "[WARN] Some operations require root (OVS flow rule removal)."
    echo "       Run with: sudo bash scripts/reset_lab.sh"
fi

# ── Step 1: Remove ALL flow rules from s1 ────────────────────────────────────
echo
echo "── Step 1: Clearing OVS flow rules ─────────────────"
echo "  This removes all flow rules, including drop/quarantine rules."
echo "  The controller will reinstall table-miss rules on the next packet."

if command -v ovs-ofctl &>/dev/null; then
    if sudo ovs-ofctl -O OpenFlow13 del-flows s1 2>/dev/null; then
        # Re-install table-miss rule so OVS continues redirecting traffic to controller
        sudo ovs-ofctl -O OpenFlow13 add-flow s1 priority=0,actions=controller 2>/dev/null || true
        echo "  [OK] Flow rules reset on s1 (table-miss re-installed)"
    else
        echo "  [WARN] Could not clear flow rules (OVS may not be running)"
    fi
    # Show current (should be empty or just table-miss)
    echo "  Current flows after reset:"
    sudo ovs-ofctl -O OpenFlow13 dump-flows s1 2>/dev/null | head -5 || true
else
    echo "  [WARN] ovs-ofctl not found"
fi

# ── Step 1b: Flush host ARP neighbor caches ──────────────────────────────────
for hpid in $(pgrep -f "mininet:h" 2>/dev/null || true); do
    sudo nsenter -t "$hpid" -n ip neigh flush all 2>/dev/null || true
done
touch /tmp/iotshield_reset.trigger 2>/dev/null || true
echo "  [OK] Host ARP caches flushed & Controller reset signaled"

# ── Step 2: Clear event log ───────────────────────────────────────────────────
echo
echo "── Step 2: Clearing event log ───────────────────────"
EVENT_LOG="/tmp/iotshield_events.jsonl"
if [ -f "$EVENT_LOG" ]; then
    # Archive before clearing
    ARCHIVE_DIR="$PROJECT_ROOT/results"
    mkdir -p "$ARCHIVE_DIR"
    TS=$(date +%Y%m%dT%H%M%S)
    cp "$EVENT_LOG" "$ARCHIVE_DIR/events_archive_${TS}.jsonl" 2>/dev/null || true
    echo "  [INFO] Archived events to results/events_archive_${TS}.jsonl"
    > "$EVENT_LOG"
    echo "  [OK] Event log cleared"
else
    echo "  [INFO] Event log not found (already clean)"
fi

# ── Step 3: Clear attack results ──────────────────────────────────────────────
echo
echo "── Step 3: Archiving attack results ─────────────────"
RESULTS_DIR="$PROJECT_ROOT/results"
ATTACK_RUN="$RESULTS_DIR/attack_run.json"
if [ -f "$ATTACK_RUN" ]; then
    mv "$ATTACK_RUN" "$RESULTS_DIR/attack_run_${TS:-$(date +%Y%m%dT%H%M%S)}.json"
    echo "  [OK] Archived previous attack results"
fi

# ── Step 4: Verify h1 → h2 connectivity restored ─────────────────────────────
echo
echo "── Step 4: Verifying h1 → h2 connectivity ───────────"
echo "  (After clearing drop rules, h3's quarantine is lifted)"
echo "  Waiting 3 seconds for the controller to reinstall forwarding rules..."
sleep 3

if [ "$(id -u)" -eq 0 ] && ip netns list 2>/dev/null | grep -q "^h1"; then
    PING_RESULT=$(ip netns exec h1 ping -c 3 -W 2 10.0.0.2 2>&1 || true)
    if echo "$PING_RESULT" | grep -q "0% packet loss\|[123] received"; then
        echo "  [PASS] h1 → h2 connectivity: RESTORED ✓"
    else
        echo "  [INFO] Ping result:"
        echo "  $PING_RESULT"
        echo "  [INFO] The controller will reinstall forwarding rules on the next ARP."
        echo "         From Mininet CLI: h1 ping h2"
    fi
else
    echo "  [INFO] Cannot run connectivity test (not root or netns not available)."
    echo "         From Mininet CLI: h1 ping h2"
fi

echo
echo "  IMPORTANT: h3 (the attacker) is no longer quarantined."
echo "  The drop rule has been removed. This is the expected lab recovery state."

# ── Step 5: Reset backend event counter ───────────────────────────────────────
echo
echo "── Step 5: Resetting dashboard counters ─────────────"
if command -v curl &>/dev/null; then
    if curl -s -X POST http://localhost:5000/api/reset 2>/dev/null | grep -q '"success": true'; then
        echo "  [OK] Dashboard event counters reset via API"
    else
        echo "  [INFO] Could not reach dashboard API (may not be running)"
    fi
else
    echo "  [INFO] curl not found; skipping dashboard reset"
fi

echo
echo "======================================================"
echo "  Lab RESET complete."
echo "  Ready for the next demonstration run."
echo
echo "  To run the attack again: sudo bash scripts/run_attack.sh"
echo "  To stop the lab:         sudo bash scripts/stop_lab.sh"
echo "======================================================"

