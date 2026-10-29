#!/usr/bin/env bash
# =============================================================================
#  IoTShield Installation Script
#  Installs system packages and Python dependencies.
#  Usage: bash scripts/install.sh
#
#  Safe to run multiple times (idempotent).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_ROOT/venv"

echo "======================================================"
echo "  IoTShield Installation"
echo "  Project root: $PROJECT_ROOT"
echo "======================================================"

# ── Check we're on Linux ──────────────────────────────────────────────────────
if [[ "$OSTYPE" != "linux"* ]]; then
    echo "[ERROR] This script must run on Linux (Ubuntu/WSL2)."
    echo "        On Windows, open Ubuntu (WSL2) and navigate to the project directory."
    exit 1
fi

# ── Check sudo access ─────────────────────────────────────────────────────────
if ! sudo -n true 2>/dev/null && ! sudo true 2>/dev/null; then
    echo "[ERROR] sudo access required for system package installation."
    exit 1
fi

# ── System packages ───────────────────────────────────────────────────────────
echo
echo "── System Packages ──────────────────────────────────"
echo "[INFO] Updating apt package list..."
sudo apt-get update -qq

SYSTEM_PACKAGES=(
    mininet
    openvswitch-switch
    openvswitch-common
    python3
    python3-pip
    python3-venv
    python3-dev
    python3-scapy
    python3-flask
    python3-requests
    python3-pytest
    net-tools
    iproute2
    iputils-ping
    tcpdump
    curl
    git
)

echo "[INFO] Installing system packages..."
for pkg in "${SYSTEM_PACKAGES[@]}"; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        echo "  [OK] $pkg already installed"
    else
        echo "  [INSTALL] $pkg..."
        sudo apt-get install -y -qq "$pkg" || echo "  [WARN] $pkg install failed (may be optional)"
    fi
done

# ── Start OVS service ─────────────────────────────────────────────────────────
echo
echo "── Open vSwitch Service ─────────────────────────────"
if sudo service openvswitch-switch start 2>/dev/null || \
   sudo /usr/share/openvswitch/scripts/ovs-ctl start 2>/dev/null; then
    echo "  [OK] OVS service started"
else
    echo "  [WARN] Could not start OVS service. You may need to start it manually."
    echo "         WSL2 note: OVS service may start automatically when ovs-vsctl is used."
fi

# ── Python Packages Check & Installation ──────────────────────────────
echo
echo "── Python Packages & Virtual Environment ───────────"

# Always create project venv with system site-packages if missing
if [ ! -d "$VENV_DIR" ]; then
    echo "[INFO] Creating project venv with system site-packages..."
    python3 -m venv --system-site-packages "$VENV_DIR" || true
fi

if [ -f "$VENV_DIR/bin/pip" ]; then
    echo "[INFO] Upgrading pip/setuptools/wheel in venv..."
    "$VENV_DIR/bin/pip" install --upgrade --quiet pip setuptools wheel 2>/dev/null || true
    echo "[INFO] Installing required dependencies in venv..."
    "$VENV_DIR/bin/pip" install --quiet "eventlet>=0.35.2" "dnspython>=2.0" "flask-cors>=4.0" "scapy>=2.5" "pytest>=7.0" "requests>=2.28" || true
    if ! "$VENV_DIR/bin/python" -c "import ryu" 2>/dev/null; then
        echo "[INFO] Installing ryu in venv without build isolation..."
        "$VENV_DIR/bin/pip" install --quiet --no-build-isolation ryu || true
    fi
fi

# Also attempt global/system-wide install for fallback
if ! python3 -c "import ryu" 2>/dev/null; then
    echo "[INFO] Installing ryu globally (for sudo/system access)..."
    sudo pip3 install --break-system-packages --quiet --no-build-isolation ryu 2>/dev/null || true
    if ! python3 -c "import ryu" 2>/dev/null; then
        cd /tmp && rm -rf ryu
        git clone --depth 1 https://github.com/faucetsdn/ryu.git && cd ryu
        sed -i 's/ryu\.hooks\.save_orig/#ryu.hooks.save_orig/g' setup.py
        sed -i 's/ryu\.hooks\.restore_orig/#ryu.hooks.restore_orig/g' setup.py
        sudo pip3 install --break-system-packages --ignore-installed . 2>/dev/null || true
        cd "$PROJECT_ROOT"
    fi
fi

# ── Verify critical imports ────────────────────────────────────────────────────
echo
echo "── Verification ─────────────────────────────────────"
CRITICAL_IMPORTS=("flask" "scapy" "eventlet")
ALL_OK=true
for mod in "${CRITICAL_IMPORTS[@]}"; do
    if python3 -c "import $mod" 2>/dev/null; then
        echo "  [OK] import $mod"
    else
        echo "  [FAIL] import $mod — check requirements"
        ALL_OK=false
    fi
done

if python3 -c "import ryu" 2>/dev/null; then
    echo "  [OK] import ryu"
else
    echo "  [WARN] import ryu failed — Ryu must be available to run the controller"
fi

# ── Mininet check ─────────────────────────────────────────────────────────────
echo
echo "── Mininet Kernel Check ─────────────────────────────"
if command -v mn &>/dev/null; then
    echo "  [OK] mn command found"
    echo "  [INFO] Testing OVS availability..."
    if sudo ovs-vsctl show &>/dev/null 2>&1; then
        echo "  [OK] OVS responding to ovs-vsctl"
    else
        echo "  [WARN] OVS not responding. This is common on WSL2."
        echo "         Try: sudo service openvswitch-switch start"
    fi
else
    echo "  [FAIL] mn not found. Install: sudo apt install mininet"
    ALL_OK=false
fi

# ── Create results directory ──────────────────────────────────────────────────
mkdir -p "$PROJECT_ROOT/results"
touch "$PROJECT_ROOT/results/.gitkeep"

# ── Set executable permissions ───────────────────────────────────────────────
chmod +x "$PROJECT_ROOT/scripts"/*.sh 2>/dev/null || true

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "======================================================"
if $ALL_OK; then
    echo "  ✓ Installation complete!"
    echo
    echo "  To start the full lab (requires root):"
    echo "    bash scripts/start_lab.sh"
    echo
    echo "  To run only the dashboard (demo mode, no Mininet needed):"
    echo "    source venv/bin/activate"
    echo "    python3 backend/app.py --demo"
    echo "    Open: http://localhost:5000"
else
    echo "  ⚠ Installation completed with warnings."
    echo "    Check the output above and consult docs/troubleshooting.md"
fi
echo "======================================================"

