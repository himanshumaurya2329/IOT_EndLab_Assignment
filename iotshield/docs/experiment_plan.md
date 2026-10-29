# IoTShield Experiment Plan

## Objectives

1. Measure baseline RTT between h1 and h2 (pre-controller and post-controller)
2. Demonstrate ARP spoofing attack detection and prevention
3. Measure detection latency (time from attack start to first controller detection)
4. Measure prevention success rate
5. Verify legitimate traffic is preserved post-mitigation
6. Export all results to JSON and CSV

---

## Pre-Experiment Setup

```bash
# 1. Open Ubuntu WSL2
# 2. Navigate to project
cd /mnt/c/Users/hmury/Desktop/IOT_EndLab_Assignment/iotshield

# 3. Activate venv
source venv/bin/activate

# 4. Check environment
bash scripts/check_environment.sh

# 5. Start the lab (Terminal 1)
sudo bash scripts/start_lab.sh
```

Wait for: "IoTShield Lab STARTED" message and Mininet CLI prompt.

---

## Experiment 1: Baseline Connectivity

**Purpose:** Establish that the network works normally before any attack.

**Steps:**

```
# From Mininet CLI:
mininet> pingall
mininet> h1 ping -c 10 -i 0.2 h2
mininet> h1 ping -c 10 -i 0.2 h3
```

**Expected results:**
- `pingall`: 0% dropped
- h1→h2: 0% packet loss, RTT ~0.1–2ms

**Record:** Average RTT from `ping` output (the `rtt min/avg/max/mdev` line)

---

## Experiment 2: Baseline RTT Without Controller

> *Optional, for added-latency calculation. Skip if time is short.*

```bash
# Stop Ryu (but leave OVS running)
kill $(cat /tmp/iotshield_ryu.pid)

# Set OVS to standalone mode (so traffic still flows)
sudo ovs-vsctl set-fail-mode s1 standalone

# Measure RTT without controller
sudo ip netns exec h1 ping -c 20 -i 0.2 10.0.0.2

# Record: avg RTT
# Restart Ryu
source venv/bin/activate
venv/bin/ryu-manager controller/sdn_guard.py --ofp-tcp-listen-port 6633 &
sudo ovs-vsctl set-fail-mode s1 secure
```

---

## Experiment 3: ARP Spoofing Attack

**Purpose:** Demonstrate the attack, detection, and mitigation.

**Steps (use 3 terminals):**

**Terminal 2 — Watch Ryu log:**
```bash
tail -f /tmp/iotshield_ryu.log | grep -E "SPOOF|DROP|LEGITIMATE|CRITICAL|WARNING"
```

**Terminal 3 — Watch event stream:**
```bash
tail -f /tmp/iotshield_events.jsonl
```

**Terminal 1 (Mininet CLI) — Run attack:**
```
mininet> h3 python3 /mnt/c/.../iotshield/attacks/arp_spoof.py --count 10 --interval 0.5
```

Or from Terminal 2:
```bash
sudo bash scripts/run_attack.sh --count 10 --interval 0.5
```

**Record:**
- Attack start time (printed by script)
- First detection log timestamp (from Ryu log)
- Detection latency (if logged in event JSON: `"detection_latency_ms"`)

---

## Experiment 4: Verify OVS Drop Rule

**After the attack:**

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

**Record:**
- Priority of drop rule (should be 200)
- `n_packets` counter on the drop rule (should be ≥ 9 for 10-packet attack)
- Match fields: `in_port=3, dl_src=00:00:00:00:00:03`

```bash
# Save flows to file
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 > results/flows_post_attack.txt
```

---

## Experiment 5: Post-Mitigation Connectivity

**Verify h1 can still reach h2 after the drop rule is installed:**

```
mininet> h1 ping -c 5 h2
```

**Expected:** 0% packet loss (legitimate traffic is unaffected).

**Also check h3 is blocked:**
```
mininet> h3 ping -c 3 h1
```
(Packets from h3 may or may not reach h1 depending on which port they exit — ARP from h3's real IP is also blocked by the drop rule. This is expected.)

---

## Experiment 6: Metrics Collection

```bash
# Collect all results
bash scripts/collect_results.sh --packets-sent 10

# Check what was saved
ls -la results/
```

**Also fetch from API:**
```bash
curl "http://localhost:5000/api/metrics?packets_sent=10" | python3 -m json.tool
curl "http://localhost:5000/api/events?limit=20" | python3 -m json.tool
```

---

## Experiment 7: Reset and Rerun

```bash
sudo bash scripts/reset_lab.sh
```

Verify:
1. OVS flows cleared (`sudo ovs-ofctl -O OpenFlow13 dump-flows s1` shows only table-miss)
2. Event log cleared
3. h1 can ping h2 again

Rerun the attack for a second trial:
```bash
sudo bash scripts/run_attack.sh --count 10
```

---

## Data Collection Checklist

| Measurement | Tool | Value to Record |
|---|---|---|
| Baseline RTT (avg) | `ping -c 20 h2` | `avg` from rtt line |
| Protected RTT (avg) | `ping -c 20 h2` (with Ryu) | `avg` from rtt line |
| Added latency | Formula | Protected − Baseline |
| Detection latency | Ryu log / event JSON | `detection_latency_ms` |
| Packets sent | Attack script output | Count |
| Packets detected | Event log | Count `ARP_SPOOFING_DETECTED` |
| Packets blocked by rule | `ovs-ofctl dump-flows` | `n_packets` on drop rule |
| Prevention rate | Formula | (detected+blocked)/sent×100 |

---

## Expected Results Summary

| Metric | Expected Value | Notes |
|---|---|---|
| Baseline RTT | 0.1 – 2 ms | Mininet loopback, very low |
| Detection latency | 5 – 50 ms | Python processing + OVS overhead |
| Prevention rate | 100% | All 10 packets prevented |
| Post-attack h1→h2 | 0% packet loss | Legitimate traffic preserved |
| Drop rule priority | 200 | Higher than forwarding (100) |

