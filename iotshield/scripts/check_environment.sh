#!/usr/bin/env bash
# =============================================================================
#  IoTShield Environment Checker
#  Inspects the WSL2/Ubuntu environment for all required components.
#  Usage: bash scripts/check_environment.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

PASS="[PASS]"
WARN="[WARN]"
FAIL="[FAIL]"
INFO="[INFO]"

pass_count=0
warn_count=0
fail_count=0

_pass() { echo -e "\e[32m${PASS}\e[0m $1"; ((pass_count++)) || true; }
_warn() { echo -e "\e[33m${WARN}\e[0m $1"; ((warn_count++)) || true; }
_fail() { echo -e "\e[31m${FAIL}\e[0m $1"; ((fail_count++)) || true; }
_info() { echo -e "\e[36m${INFO}\e[0m $1"; }
_section() { echo; echo "── $1 ──────────────────────────────────────────"; }

echo "======================================================"
echo "  IoTShield Environment Checker"
echo "  $(date)"
echo "======================================================"

# ── OS & Kernel ───────────────────────────────────────────────────────────────
_section "Operating System"

if command -v lsb_release &>/dev/null; then
    OS=$(lsb_release -ds 2>/dev/null)
    _pass "OS: $OS"
else
    _warn "lsb_release not found; cannot identify OS"
fi

KERNEL=$(uname -r)
if echo "$KERNEL" | grep -qi "microsoft"; then
    _pass "Kernel: $KERNEL (WSL2 detected)"
else
    _info "Kernel: $KERNEL (non-WSL environment)"
fi

# ── Python ────────────────────────────────────────────────────────────────────
_section "Python"

if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1)
    PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
    PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 8 ]; then
        _pass "Python: $PY_VER (≥ 3.8 required)"
    else
        _fail "Python $PY_VER is too old. Need ≥ 3.8. Install: sudo apt install python3.10"
    fi
else
    _fail "python3 not found. Install: sudo apt install python3"
fi

if command -v pip3 &>/dev/null; then
    _pass "pip3: $(pip3 --version | head -1)"
else
    _warn "pip3 not found. Install: sudo apt install python3-pip"
fi

# ── Mininet ───────────────────────────────────────────────────────────────────
_section "Mininet"

if command -v mn &>/dev/null; then
    MN_VER=$(mn --version 2>&1 | head -1)
    _pass "Mininet: $MN_VER"
else
    _fail "Mininet not found. Install: sudo apt install mininet"
fi

# ── Open vSwitch ──────────────────────────────────────────────────────────────
_section "Open vSwitch"

if command -v ovs-vsctl &>/dev/null; then
    OVS_VER=$(ovs-vsctl --version | head -1)
    _pass "ovs-vsctl: $OVS_VER"
else
    _fail "ovs-vsctl not found. Install: sudo apt install openvswitch-switch"
fi

if command -v ovs-ofctl &>/dev/null; then
    _pass "ovs-ofctl: available"
else
    _warn "ovs-ofctl not found"
fi

# Check OVS service/daemon
if sudo ovs-vsctl show &>/dev/null 2>&1; then
    _pass "OVS daemon: running (ovs-vsctl show succeeded)"
else
    _warn "OVS daemon may not be running. Try: sudo service openvswitch-switch start"
    _info "  Or: sudo /usr/share/openvswitch/scripts/ovs-ctl start"
fi

# ── Ryu Controller ────────────────────────────────────────────────────────────
_section "Ryu SDN Controller"

if command -v ryu-manager &>/dev/null; then
    _pass "ryu-manager: found at $(which ryu-manager)"
elif [ -f "venv/bin/ryu-manager" ]; then
    _pass "ryu-manager: found in venv (venv/bin/ryu-manager)"
else
    _warn "ryu-manager not found. Install with: bash scripts/install.sh"
    _info "  Or manually: pip3 install ryu"
fi

# Check ryu Python package
if python3 -c "import ryu" 2>/dev/null; then
    _pass "ryu Python package: importable"
elif [ -f "venv/bin/python3" ] && venv/bin/python3 -c "import ryu" 2>/dev/null; then
    _pass "ryu Python package: importable (via venv)"
else
    _warn "ryu not importable. Run: bash scripts/install.sh"
fi

# ── Python Dependencies ───────────────────────────────────────────────────────
_section "Python Dependencies"

DEPS="flask scapy eventlet"
for dep in $DEPS; do
    if python3 -c "import $dep" 2>/dev/null; then
        _pass "$dep: importable"
    elif [ -f "venv/bin/python3" ] && venv/bin/python3 -c "import $dep" 2>/dev/null; then
        _pass "$dep: importable (via venv)"
    else
        _warn "$dep: NOT importable. Run: bash scripts/install.sh"
    fi
done

# ── Docker ────────────────────────────────────────────────────────────────────
_section "Docker (optional)"

if command -v docker &>/dev/null; then
    DOCKER_VER=$(docker --version)
    _pass "Docker: $DOCKER_VER"
    if docker info &>/dev/null 2>&1; then
        _pass "Docker daemon: running"
    else
        _warn "Docker installed but daemon not accessible"
    fi
else
    _info "Docker not found (optional for this project)"
fi

# ── Network capabilities ──────────────────────────────────────────────────────
_section "Network Capabilities"

if ip netns list &>/dev/null 2>&1; then
    _pass "Network namespaces: supported"
else
    _warn "Network namespaces: may not be available (run as root?)"
fi

if [ -e /dev/net/tun ]; then
    _pass "TUN device: /dev/net/tun exists"
else
    _warn "TUN device not found. May affect Mininet. Try: sudo modprobe tun"
fi

# ── Ports ─────────────────────────────────────────────────────────────────────
_section "Port Availability"

for port in 6633 5000; do
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || \
       netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
        _warn "Port $port: IN USE (may conflict with Ryu/Flask)"
    else
        _pass "Port $port: available"
    fi
done

# ── Config Files ──────────────────────────────────────────────────────────────
_section "Configuration Files"

for f in config/trusted_bindings.json config/settings.json; do
    if [ -f "$f" ]; then
        _pass "$f: exists"
    else
        _fail "$f: MISSING. Re-run project setup."
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "======================================================"
echo "  Summary: ${pass_count} PASS | ${warn_count} WARN | ${fail_count} FAIL"
echo "======================================================"

if [ "$fail_count" -gt 0 ]; then
    echo "  ✗ Some required components are missing."
    echo "    Run: bash scripts/install.sh"
    exit 1
elif [ "$warn_count" -gt 0 ]; then
    echo "  ⚠ Environment has warnings but may still work."
    echo "    Run: bash scripts/install.sh to resolve"
    exit 0
else
    echo "  ✓ Environment looks good! Run: bash scripts/start_lab.sh"
    exit 0
fi

