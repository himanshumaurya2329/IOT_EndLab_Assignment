# IoTShield Troubleshooting Guide

## Issue 1: OVS Does Not Start in WSL2

**Symptom:**
```
$ sudo ovs-vsctl show
ovs-vsctl: unix:/var/run/openvswitch/db.sock: database connection failed (No such file or directory)
```

**Cause:** The OVS daemons (ovsdb-server, ovs-vswitchd) are not running. WSL2 does not auto-start services.

**Fix:**
```bash
# Option A: Use service command
sudo service openvswitch-switch start

# Option B: Start daemons manually
sudo mkdir -p /var/run/openvswitch
sudo ovsdb-server \
    --remote=punix:/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --pidfile --detach --log-file=/tmp/ovsdb.log
sudo ovs-vswitchd --pidfile --detach --log-file=/tmp/ovs-vswitchd.log
sudo ovs-vsctl --no-wait init

# Verify:
sudo ovs-vsctl show
```

**If `modprobe openvswitch` fails:** The WSL2 kernel may not have the OVS module. Check:
```bash
uname -r          # should show microsoft-standard-WSL2
zcat /proc/config.gz | grep -i openvswitch
```
If `CONFIG_OPENVSWITCH=m` is missing, use the Docker fallback (see docs/README.md).

---

## Issue 2: Ryu Installation Fails on Python 3.12

**Symptom:**
```
error: legacy-install-failure
× Encountered error while trying to install package ryu
```

**Cause:** Ryu uses deprecated `setup.py` patterns not supported by pip's build isolation in Python 3.12+.

**Fix A — Disable build isolation:**
```bash
source venv/bin/activate
pip install setuptools==67.8.0 wheel
pip install --no-build-isolation ryu
```

**Fix B — Use the maintained fork:**
```bash
pip install ryu-agent
# Change start command from 'ryu-manager' to 'ryu-agent' in scripts/start_lab.sh
```

**Fix C — Use Python 3.10:**
```bash
sudo apt install python3.10 python3.10-venv
python3.10 -m venv venv310
source venv310/bin/activate
pip install ryu flask scapy eventlet pytest
```
Update `PYTHON` variable in `scripts/start_lab.sh` to point to `venv310/bin/python3`.

---

## Issue 3: Mininet "RTNETLINK answers: File exists"

**Symptom:**
```
Exception: Error creating interface pair (s1-eth1, h1-eth0): RTNETLINK answers: File exists
```

**Cause:** Stale Mininet state from a previous run that wasn't cleaned up.

**Fix:**
```bash
sudo mn -c
# If mn -c hangs, kill OVS bridges manually:
sudo ovs-vsctl del-br s1 2>/dev/null || true
sudo ip link delete s1-eth1 2>/dev/null || true
sudo ip link delete s1-eth2 2>/dev/null || true
sudo ip link delete s1-eth3 2>/dev/null || true
# Then retry:
sudo python3 topology/iot_topology.py
```

---

## Issue 4: Controller Not Connecting (Switch in "fail standalone" mode)

**Symptom:** Ryu log shows no `Switch connected` message. OVS switch operates without controller.

**Diagnosis:**
```bash
# Check if Ryu is actually listening
ss -tlnp | grep 6633

# Check OVS controller config
sudo ovs-vsctl show | grep -A5 Controller

# Check if controller is reachable from OVS
curl -v telnet://127.0.0.1:6633
```

**Fix:**
```bash
# Manually set the controller on s1
sudo ovs-vsctl set-controller s1 tcp:127.0.0.1:6633

# Set OpenFlow version
sudo ovs-vsctl set bridge s1 protocols=OpenFlow13

# Check connection status
sudo ovs-vsctl find controller is_connected=true
```

If Ryu is not listening, check the Ryu log:
```bash
tail -50 /tmp/iotshield_ryu.log
```

Common Ryu startup errors:
- `ImportError: No module named 'ryu'` → activate venv: `source venv/bin/activate`
- `Address already in use: 6633` → kill old Ryu: `kill $(cat /tmp/iotshield_ryu.pid)`

---

## Issue 5: Dashboard Shows "Disconnected" / No Events

**Symptom:** Browser shows OFFLINE badge. Events table is empty even after running attack.

**Diagnosis:**
```bash
# Test backend health
curl http://localhost:5000/api/health

# Test events endpoint
curl http://localhost:5000/api/events

# Check Flask is running
ss -tlnp | grep 5000
```

**Fix:**
1. **Backend not running:** Start it: `source venv/bin/activate && python3 backend/app.py`
2. **Wrong port:** Make sure you're opening `http://localhost:5000` not `http://127.0.0.1:5000` (both should work in WSL2)
3. **CORS issue:** Backend sets CORS headers — if serving from a different origin, check browser console
4. **Event log not being written:** Check permissions: `ls -la /tmp/iotshield_events.jsonl`

**Demo mode workaround:**
```bash
python3 backend/app.py --demo
```
Opens at `http://localhost:5000` with clearly labelled simulated events.

---

## Issue 6: SSE Stream Not Updating

**Symptom:** Dashboard connects but event counter never increments.

**Diagnosis:**
```bash
# Test SSE stream manually (should keep streaming)
curl -N http://localhost:5000/api/events/stream
```

You should see:
```
: heartbeat

: heartbeat

data: {"type":"ARP_LEGITIMATE",...}
```

**Fix:**
- If no heartbeat after 15 seconds: Flask threading issue. Restart backend.
- If heartbeat works but no data: Check event log file exists and has content:
  ```bash
  ls -la /tmp/iotshield_events.jsonl
  cat /tmp/iotshield_events.jsonl | tail -5
  ```
- If file is empty: Ryu is not running or the controller is not receiving ARP packets. Check Ryu log.

---

## Issue 7: Attack Script "No Such Device" Error

**Symptom:**
```
OSError: [Errno 19] No such device
ERROR: send failed: [Errno 19] No such device
```

**Cause:** The attack script is not running inside h3's network namespace, so interface `h3-eth0` does not exist.

**Fix — Run inside h3's namespace:**
```bash
sudo ip netns exec h3 python3 attacks/arp_spoof.py --iface h3-eth0
```

**List h3's interfaces:**
```bash
sudo ip netns exec h3 ip link show
```

The interface might be named differently. Use the name shown.

**Alternative — Run from Mininet CLI:**
```
mininet> h3 python3 /path/to/iotshield/attacks/arp_spoof.py
```
Mininet automatically runs the command in h3's namespace.

---

## Issue 8: Port Already In Use

**Symptom:**
```
OSError: [Errno 98] Address already in use: ('0.0.0.0', 5000)
# or
Error: Address already in use (port 6633)
```

**Fix:**
```bash
# Find what's using the port
sudo ss -tlnp | grep -E "5000|6633"

# Kill by PID (replace XXXX)
sudo kill XXXX

# Or kill by port
sudo fuser -k 5000/tcp
sudo fuser -k 6633/tcp
```

---

## Issue 9: Permission Denied Errors

**Symptom:**
```
PermissionError: [Errno 1] Operation not permitted
```

**Cause:** Mininet, OVS, and Scapy require root. The topology script and attack script need `sudo`.

**Fix:**
```bash
# Start Mininet topology as root
sudo python3 topology/iot_topology.py

# Run attack as root
sudo bash scripts/run_attack.sh

# If you need to run Scapy inside netns
sudo ip netns exec h3 python3 attacks/arp_spoof.py
```

The Flask backend does NOT need root. Only start it as root if you need to call `ovs-ofctl` from the API (which already uses `sudo` in the subprocess call).

---

## Issue 10: `mn --test pingall` Hangs

**Symptom:** Running `mn --test pingall` never completes.

**Cause:** OVS in "fail standalone" mode without a controller may still try to contact a controller.

**Fix:**
```bash
# Run Mininet without a controller for the standalone test
sudo mn --controller=none --test pingall

# Or set OVS to standalone mode first
sudo ovs-vsctl set-fail-mode s1 standalone
```

For IoTShield, always run Mininet with the Ryu controller running first.

---

## Quick Reference: Log Files

| Component | Log File |
|---|---|
| Ryu controller | `/tmp/iotshield_ryu.log` |
| Flask backend | `/tmp/iotshield_backend.log` |
| OVS daemon | `/tmp/ovs-vswitchd.log` |
| ovsdb-server | `/tmp/ovsdb.log` |
| Event stream | `/tmp/iotshield_events.jsonl` |

```bash
# Watch all logs simultaneously
tail -f /tmp/iotshield_ryu.log /tmp/iotshield_events.jsonl /tmp/iotshield_backend.log
```

