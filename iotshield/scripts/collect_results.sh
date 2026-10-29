#!/usr/bin/env bash
# =============================================================================
#  IoTShield Results Collector
#  Collects and exports experiment metrics to results/ directory.
#  Usage: bash scripts/collect_results.sh [--packets-sent N]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_ROOT/results"
VENV_PYTHON="$PROJECT_ROOT/venv/bin/python3"
PYTHON="${VENV_PYTHON:-python3}"
[ -f "$VENV_PYTHON" ] && PYTHON="$VENV_PYTHON"

PACKETS_SENT=10
while [[ $# -gt 0 ]]; do
    case $1 in
        --packets-sent) PACKETS_SENT="$2"; shift 2 ;;
        *) shift ;;
    esac
done

echo "======================================================"
echo "  IoTShield Results Collector"
echo "======================================================"

mkdir -p "$RESULTS_DIR"

# Query the backend API for current metrics
if command -v curl &>/dev/null; then
    echo "[INFO] Fetching metrics from backend API..."
    METRICS=$(curl -s "http://localhost:5000/api/metrics?packets_sent=${PACKETS_SENT}" 2>/dev/null || echo "{}")
    EVENTS=$(curl -s "http://localhost:5000/api/events?limit=100" 2>/dev/null || echo "{}")
    STATUS=$(curl -s "http://localhost:5000/api/status" 2>/dev/null || echo "{}")

    TS=$(date +%Y%m%dT%H%M%S)
    echo "$METRICS" > "$RESULTS_DIR/metrics_${TS}.json"
    echo "$EVENTS" > "$RESULTS_DIR/events_${TS}.json"
    echo "$STATUS" > "$RESULTS_DIR/status_${TS}.json"
    echo "  [OK] Saved to results/ (timestamp: $TS)"
fi

# Collect OVS flow stats
if command -v ovs-ofctl &>/dev/null; then
    echo "[INFO] Collecting OVS flow stats..."
    sudo ovs-ofctl -O OpenFlow13 dump-flows s1 2>/dev/null \
        > "$RESULTS_DIR/ovs_flows_${TS:-$(date +%Y%m%dT%H%M%S)}.txt" || true
fi

# Run the Python metrics module
cd "$PROJECT_ROOT"
$PYTHON -c "
import json, sys
sys.path.insert(0, '.')
from backend.metrics import compute_prevention_rate, compute_added_latency, save_full_experiment_results
from topology.iot_topology import get_topology_info

prevention = compute_prevention_rate(
    packets_sent=${PACKETS_SENT},
    packets_detected=0,
    packets_dropped_by_rule=0,
    packets_dropped_current=0,
)
detection = {'detection_latency_ms': None, 'note': 'Run attack to measure'}
latency = {'baseline_rtt_ms': None, 'protected_rtt_ms': None, 'added_latency_ms': None}
topo = get_topology_info()

paths = save_full_experiment_results(prevention, detection, latency, topo, notes='Collected by collect_results.sh')
print(f'  [OK] JSON: {paths[\"json\"]}')
print(f'  [OK] CSV:  {paths[\"csv\"]}')
" 2>/dev/null || echo "  [WARN] Python metrics collection failed"

echo
echo "======================================================"
echo "  Results saved to: $RESULTS_DIR/"
echo "  Files:"
ls -la "$RESULTS_DIR/" 2>/dev/null | grep -v "^total" | grep -v "^d" || true
echo "======================================================"

