#!/usr/bin/env bash
# =============================================================================
#  IoTShield Live Event Watcher
#  Formats JSONL events into clean, readable terminal logs
#  Usage: bash scripts/watch_events.sh
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

if [ -f "$PROJECT_ROOT/venv/bin/python3" ]; then
    PYTHON="$PROJECT_ROOT/venv/bin/python3"
else
    PYTHON="python3"
fi

exec $PYTHON "$PROJECT_ROOT/scripts/watch_events.py"

