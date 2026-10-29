# IoTShield — Setup From Scratch Guide

This guide provides end-to-end instructions for setting up **IoTShield** on a fresh Linux or Windows WSL 2 system immediately after cloning the repository.

---

## Table of Contents
1. [Prerequisites & System Requirements](#1-prerequisites--system-requirements)
2. [Step 1: Clone the Repository](#step-1-clone-the-repository)
3. [Step 2: Install System Dependencies](#step-2-install-system-dependencies)
4. [Step 3: Start Open vSwitch (OVS) Service](#step-3-start-open-vswitch-ovs-service)
5. [Step 4: Setup Python Environment & Dependencies](#step-4-setup-python-environment--dependencies)
   - [Option A: Automated One-Click Installation (Recommended)](#option-a-automated-one-click-installation-recommended)
   - [Option B: Manual Step-by-Step Installation](#option-b-manual-step-by-step-installation)
6. [Step 5: Verify Environment & Run Test Suite](#step-5-verify-environment--run-test-suite)
7. [Step 6: Launching the Lab (3-Terminal Architecture)](#step-6-launching-the-lab-3-terminal-architecture)
8. [Step 7: Testing Legitimate Traffic & Simulating Attacks](#step-7-testing-legitimate-traffic--simulating-attacks)
9. [Step 8: Resetting and Stopping the Lab](#step-8-resetting-and-stopping-the-lab)
10. [Troubleshooting & Common Issues](#10-troubleshooting--common-issues)

---

## 1. Prerequisites & System Requirements

| Requirement | Specification |
|:---|:---|
| **Operating System** | **Linux**: Ubuntu 22.04 LTS / 24.04 LTS or Debian 12.<br>**Windows**: Windows 10/11 with **WSL 2** (Ubuntu 22.04 / 24.04 LTS installed). |
| **CPU & Memory** | 2+ CPU cores, 4 GB+ RAM (8 GB recommended). |
| **Permissions** | `sudo` root privileges (required for Mininet network namespaces & OVS kernel manipulation). |
| **Docker Requirement** | **None.** Docker is NOT needed and NOT used. |

> [!NOTE]
> **Windows Users:** All commands below must be executed inside your **Ubuntu WSL 2 terminal**, NOT in Windows PowerShell or Command Prompt. The Web Dashboard (`http://localhost:5000`) can be opened directly in your standard Windows browser (Chrome, Edge, Firefox).

---

## Step 1: Clone the Repository

Open your Linux/WSL terminal and clone the repository:

```bash
git clone https://github.com/himanshumaurya2329/IOT_EndLab_Assignment.git
cd IOT_EndLab_Assignment/iotshield
```

Verify you are in the project folder:
```bash
pwd
# Expected output ends with: .../IOT_EndLab_Assignment/iotshield
ls -la
```

---

## Step 2: Install System Dependencies

Update the package lists and install required networking tools, Open vSwitch, Mininet, and Python build utilities:

```bash
sudo apt-get update
sudo apt-get install -y \
    mininet \
    openvswitch-switch \
    openvswitch-common \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    net-tools \
    iproute2 \
    iputils-ping \
    tcpdump \
    curl \
    git
```

---

## Step 3: Start Open vSwitch (OVS) Service

Open vSwitch must be running as a background service before Mininet can create virtual bridges and OpenFlow switches:

```bash
# Start OVS service
sudo service openvswitch-switch start

# Verify OVS is running
sudo ovs-vsctl show
```

If `ovs-vsctl show` outputs an empty switch database with a UUID (and no error), OVS is ready.

---

## Step 4: Setup Python Environment & Dependencies

You can choose either the automated script or manual installation.

### Option A: Automated One-Click Installation (Recommended)

The project includes an automated setup script that installs dependencies, builds Ryu with proper patches, and verifies all imports:

```bash
cd /path/to/IOT_EndLab_Assignment/iotshield
bash scripts/install.sh
```

---

### Option B: Manual Step-by-Step Installation

If you prefer full manual control:

#### 1. (Optional) Create and Activate Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
```

*(Note: On Ubuntu 24.04 without a venv, pass `--break-system-packages` to pip if using system Python).*

#### 2. Install Python Core Dependencies
```bash
pip install "flask>=2.3,<4.0" "flask-cors>=4.0" "scapy>=2.5" "pytest>=7.0" "requests>=2.28" "dnspython>=2.0"
```

#### 3. Install Eventlet (Compatible Version)
```bash
pip install "eventlet>=0.35.2"
```

#### 4. Install Ryu SDN Controller
Ryu requires `--no-build-isolation` on modern Python (3.11/3.12):
```bash
pip install --no-build-isolation ryu
```
*Alternative if pip fails on Python 3.12:*
```bash
cd /tmp && rm -rf ryu
git clone --depth 1 https://github.com/faucetsdn/ryu.git && cd ryu
sed -i 's/ryu\.hooks\.save_orig/#ryu.hooks.save_orig/g' setup.py
sed -i 's/ryu\.hooks\.restore_orig/#ryu.hooks.restore_orig/g' setup.py
pip install --ignore-installed .
cd -
```

#### 5. Verify Python Imports
```bash
python3 -c "import flask, scapy, eventlet, ryu; print('All Python dependencies OK!')"
```

---

## Step 5: Verify Environment & Run Test Suite

### 1. Run Pre-flight Environment Check:
```bash
bash scripts/check_environment.sh
```
All critical checks (Linux kernel, Mininet `mn`, `ovs-vsctl`, Python libraries) should report `[OK]`.

### 2. Run the 59 Automated Unit Tests:
```bash
python3 -m pytest tests/ -v
```
**Expected Result:**
```
============================== 59 passed in ~0.50s ==============================
```
*(The test suite verifies trusted bindings validation, IP-MAC spoofing detection logic, event streaming serialization, and metric calculators without needing Mininet running).*

---

## Step 6: Launching the Lab (3-Terminal Architecture)

For an interactive, real-time SOC (Security Operations Center) monitoring experience:

### Terminal 1: Start Mininet & Full Lab (Controller + Backend + Topology)
```bash
cd /path/to/IOT_EndLab_Assignment/iotshield
sudo bash scripts/start_lab.sh
```
- Starts Open vSwitch.
- Launches Ryu SDN Controller (`controller/sdn_guard.py`) on port 6633/6653.
- Starts Flask Dashboard backend on port 5000.
- Boots Mininet topology (`h1` IoT Sensor, `h2` IoT Server, `h3` Rogue Attacker, `s1` OVS Switch).
- Drops you directly into the interactive `mininet>` prompt.

### Terminal 2 (Optional but Recommended): Clean Ryu Controller Log
```bash
cd /path/to/IOT_EndLab_Assignment/iotshield
python3 scripts/watch_ryu.py
```
- Displays color-coded controller activity without deprecation noise.

### Terminal 3 (Optional but Recommended): Formatted Security Event Stream
```bash
cd /path/to/IOT_EndLab_Assignment/iotshield
python3 scripts/watch_events.py
```
- Real-time formatted event feed showing safe packets in green and blocked attacks in red.

### Web Browser Dashboard:
Open in your browser:
```
http://localhost:5000
```
- Live dark SOC dashboard with real-time statistics, packet animation, rolling traffic chart, and SDN binding table.

---

## Step 7: Testing Legitimate Traffic & Simulating Attacks

All commands are run directly in **Terminal 1 (`mininet>` prompt)**:

### 1. Test Normal Legitimate Traffic (ICMP Ping):
```bash
mininet> h1 ping -c 3 h2
```
- `0% packet loss`.
- Controller verifies `h1` IP/MAC on Port 1, pushes forwarding flow rule (`idle_timeout 5s`).
- Packets Inspected count increments; green animation runs on Web UI.

### 2. Launch ARP Spoofing Attack from Attacker (`h3`):
```bash
mininet> h3 python3 attacks/arp_spoof.py --count 10
```
- `h3` injects 10 rogue ARP replies claiming to own Server IP `10.0.0.2`.
- Ryu inspects incoming ARP packet against `config/trusted_bindings.json`.
- **Mismatch detected!** Ryu immediately drops packet and installs hardware **DROP rule (`priority 200`)** in OVS switch `s1`.
- Web UI shows instant Red toast alert; `h3` marked `QUARANTINED`; Attack Flagged & Packets Blocked counters increment.

### 3. Verify Legitimate Traffic is Still Operational:
```bash
mininet> h1 ping -c 3 h2
```
- `0% packet loss`. IoT sensor-to-server traffic is completely unaffected while the attacker is isolated!

---

## Step 8: Resetting and Stopping the Lab

### To Reset for Another Demo:
- Click the **"Reset / Clear Data"** button on the Web UI, OR
- In a terminal run:
  ```bash
  sudo bash scripts/reset_lab.sh
  ```
- This flushes drop rules, re-instates table-miss rule, flushes host ARP caches, and clears UI metrics.

### To Cleanly Stop the Entire Lab:
1. In Terminal 1 (`mininet>`), type:
   ```bash
   mininet> exit
   ```
2. Stop all background services:
   ```bash
   sudo bash scripts/stop_lab.sh
   sudo mn -c
   ```

---

## 10. Troubleshooting & Common Issues

| Problem | Cause | Solution |
|:---|:---|:---|
| `Cannot connect to OVS` | OVS daemon is stopped | Run `sudo service openvswitch-switch start` |
| `Address already in use: 5000` | Stale Flask instance running | Run `sudo fuser -k 5000/tcp` |
| `Address already in use: 6633` | Stale Ryu instance running | Run `sudo fuser -k 6633/tcp` or `sudo killall ryu-manager` |
| `Permission denied` | Mininet / OVS requires root | Prepend `sudo` to scripts (`sudo bash scripts/start_lab.sh`) |
| `100% packet loss` after reset | Table-miss rule missing | Run `sudo bash scripts/reset_lab.sh` which restores `priority=0,actions=controller` |
| `externally-managed-environment` | Python 3.12 PEP 668 restriction | Use `python3 -m venv venv && source venv/bin/activate` or pass `--break-system-packages` to pip |

