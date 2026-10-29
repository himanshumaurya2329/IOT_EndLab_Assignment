# IoTShield Lab Evaluation — Screenshots and Evidence Guide

This document specifies the exact screenshots required for your end-semester lab submission, report, and viva presentation, along with the commands and stages to capture them.

---

## Required Screenshots Checklist

### 1. Environment Verification
- **Artifact:** Terminal capture of `scripts/check_environment.sh`
- **Command:** `bash scripts/check_environment.sh`
- **Key Evidence to Highlight:**
  - Ubuntu 24.04 LTS / Linux kernel details (WSL2)
  - Python version (>= 3.8)
  - Mininet (`/usr/bin/mn`) detected
  - Open vSwitch (`ovs-vsctl`) active
  - Configuration files verified

---

### 2. Network Topology Startup & Baseline Connectivity
- **Artifact:** Mininet startup and ping connectivity test
- **Command:**
  ```bash
  sudo bash scripts/start_lab.sh
  # In Mininet CLI:
  mininet> pingall
  mininet> h1 ping -c 3 h2
  ```
- **Key Evidence to Highlight:**
  - Nodes `h1`, `h2`, `h3`, and switch `s1` initialized
  - OpenFlow 1.3 protocol set on `s1`
  - Switch connects to Ryu controller on port 6633
  - Baseline ping between `h1` (10.0.0.1) and `h2` (10.0.0.2) shows **0% packet loss**

---

### 3. Ryu Controller Startup and Event Logging
- **Artifact:** Ryu controller console log
- **Command:** `tail -f /tmp/iotshield_ryu.log`
- **Key Evidence to Highlight:**
  - `IoTShield Guard initialised`
  - Loaded trusted bindings for `10.0.0.1`, `10.0.0.2`, `10.0.0.3`
  - Switch features registered and table-miss flow rule installed (priority 0)

---

### 4. Controlled ARP Spoofing Attack Execution
- **Artifact:** Attacker console (`h3`) running Scapy attack generator
- **Command:**
  ```bash
  # Inside Mininet CLI or separate terminal:
  mininet> h3 python3 attacks/arp_spoof.py --count 10 --interval 0.5
  ```
- **Key Evidence to Highlight:**
  - Attacker: `10.0.0.3` (`00:00:00:00:00:03`)
  - Target/Victim: `10.0.0.1`
  - Impersonated IP: `10.0.0.2` (Trusted Server)
  - Sequence of spoofed ARP replies transmitted
  - Clear "LAB USE ONLY" banner

---

### 5. Detection & Immediate Mitigation in Ryu Controller
- **Artifact:** Controller log capturing detection event
- **Key Evidence to Highlight:**
  - `CRITICAL: ARP SPOOFING DETECTED: 10.0.0.2 claimed by 00:00:00:00:00:03 (expected 00:00:00:00:00:02) port=3`
  - Reason: `MAC mismatch`
  - Action: `DROP_AND_INSTALL_RULE`
  - `WARNING: Drop rule installed: dpid=... in_port=3 src_mac=00:00:00:00:00:03 priority=200`
  - Detection latency measured in milliseconds

---

### 6. Open vSwitch (OVS) Flow Table Inspection
- **Artifact:** Flow rule table showing security drop rule
- **Command:** `sudo ovs-ofctl -O OpenFlow13 dump-flows s1`
- **Key Evidence to Highlight:**
  - Priority 200 rule: `priority=200,in_port=3,dl_src=00:00:00:00:00:03 actions=drop`
  - Packet counter (`n_packets`) showing blocked malicious frames
  - Forwarding rules at priority 100
  - Table-miss rule at priority 0

---

### 7. Post-Attack Legitimate Traffic Preservation
- **Artifact:** Successful ping between `h1` and `h2` while attack is active or mitigated
- **Command:** `mininet> h1 ping -c 4 h2`
- **Key Evidence to Highlight:**
  - `0% packet loss` between legitimate sensor and server
  - Confirms zero denial-of-service on legitimate channels

---

### 8. Cybersecurity SOC Dashboard — Overview Tab
- **Artifact:** Browser view of `http://localhost:5000` (Security Dashboard)
- **Visual Elements to Capture:**
  - Dark SOC UI theme
  - Status Cards: Network Status (Healthy / Alert), Controller Status, Total ARP Inspected
  - Suspicious Events counter incremented
  - Blocked Packets counter incremented
  - Active Drop Rules count: 1
  - Live Security Events table listing `ARP_SPOOFING_DETECTED` with timestamp, offending MAC, reason, and action
  - Real-time traffic timeline chart showing the spike in blocked packets

---

### 9. Interactive Network Topology Visualization
- **Artifact:** Browser view of `http://localhost:5000` (Network Topology tab)
- **Visual Elements to Capture:**
  - Node diagram: `h1` (Sensor), `s1` (Switch), `h2` (Server), `h3` (Attacker), and Ryu Controller
  - Animated packet path showing blocked packet at switch / red attack highlight
  - Live topology event log pane synchronized with controller events

---

### 10. Experiment Results and Metrics Export
- **Artifact:** Terminal output and directory listing of exported metrics
- **Command:** `bash scripts/collect_results.sh --packets-sent 10`
- **Key Evidence to Highlight:**
  - Generation of `results/experiment_*.json` and `results/experiment_*.csv`
  - Summary metrics: 100% Prevention Rate, Detection Latency (ms), Added Latency (ms)

---

### 11. Demonstration Reset
- **Artifact:** Reset script execution restoring pristine baseline
- **Command:** `sudo bash scripts/reset_lab.sh`
- **Key Evidence to Highlight:**
  - OVS drop flow rules cleared
  - Quarantine state lifted
  - Event log archived and reset
  - Connectivity between nodes verified

