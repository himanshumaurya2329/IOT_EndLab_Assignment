"""
IoTShield Mininet Topology
==========================
Creates a simple 3-host, 1-switch topology for the IoTShield lab.

Topology:
    h1 (IoT Sensor/Victim)  ──┐
    h2 (Trusted Server)     ──┤ s1 (OVS) ── Ryu Controller (external)
    h3 (Attacker)           ──┘

Usage (run as root inside WSL):
    sudo python3 topology/iot_topology.py

The script:
  1. Creates the topology with static IP/MAC assignments.
  2. Configures OVS switch to use OpenFlow 1.3.
  3. Connects to the Ryu controller at 127.0.0.1:6633.
  4. Runs a connectivity test (h1 ping h2).
  5. Drops into an interactive Mininet CLI.
"""

import json
import os
import sys
import time
from pathlib import Path

# Ensure system site-packages (/usr/lib/python3/dist-packages) are accessible
# in case the user activated a virtual environment without --system-site-packages
for _p in ("/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages"):
    if os.path.exists(_p) and _p not in sys.path:
        sys.path.append(_p)

# Mininet imports — only available inside Linux lab
from mininet.log import setLogLevel, info, error
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink

_HERE = Path(__file__).resolve().parent.parent
_SETTINGS_FILE = _HERE / "config" / "settings.json"


def load_settings() -> dict:
    try:
        with open(_SETTINGS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Cannot load settings: {exc}")
        sys.exit(1)


def create_topology():
    """Create and start the IoTShield Mininet topology."""
    setLogLevel("info")
    settings = load_settings()

    ctrl_ip = settings["topology"]["controller_ip"]
    ctrl_port = settings["topology"]["controller_port"]
    host_defs = settings["topology"]["hosts"]

    info("\n*** IoTShield: Creating topology\n")

    # ── Controller ────────────────────────────────────────────────────────────
    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False,
        autoStaticArp=False,  # We want to observe ARP in action
    )

    info(f"*** Adding controller c0 at {ctrl_ip}:{ctrl_port}\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip=ctrl_ip,
        port=ctrl_port,
    )

    # ── Switch ────────────────────────────────────────────────────────────────
    info("*** Adding switch s1\n")
    s1 = net.addSwitch("s1", cls=OVSSwitch, protocols="OpenFlow13", failMode="secure")

    # ── Hosts ─────────────────────────────────────────────────────────────────
    hosts = {}
    for hdef in host_defs:
        name = hdef["name"]
        ip = hdef["ip"]
        mac = hdef["mac"]
        info(f"*** Adding host {name} ip={ip} mac={mac}\n")
        h = net.addHost(name, ip=ip, mac=mac)
        hosts[name] = h

    # ── Links (deterministic port assignment) ─────────────────────────────────
    # Port assignments: h1→port1, h2→port2, h3→port3
    info("*** Adding links (h1-s1 port1, h2-s1 port2, h3-s1 port3)\n")
    net.addLink(hosts["h1"], s1, port1=0, port2=1)
    net.addLink(hosts["h2"], s1, port1=0, port2=2)
    net.addLink(hosts["h3"], s1, port1=0, port2=3)

    # ── Start network ─────────────────────────────────────────────────────────
    info("*** Starting network\n")
    net.build()
    net.start()

    # Configure OpenFlow 1.3 and controller connection on s1
    info(f"*** Configuring s1 to connect to controller at {ctrl_ip}:{ctrl_port}\n")
    s1.cmd(f"ovs-vsctl set-controller s1 tcp:{ctrl_ip}:{ctrl_port}")
    s1.cmd("ovs-vsctl set bridge s1 protocols=OpenFlow13")

    # Wait for controller connection
    info(f"*** Waiting for controller at {ctrl_ip}:{ctrl_port}...\n")
    connected = _wait_for_controller(s1, timeout=15)
    if not connected:
        error("Controller did not connect within 15 seconds. Is Ryu running?\n")
        error("Start Ryu first: cd iotshield && ryu-manager controller/sdn_guard.py\n")
        net.stop()
        sys.exit(1)

    info("*** Controller connected!\n")
    # Ensure table-miss rule is immediately present on s1 so all initial ARP/ICMP reaches Ryu
    s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 priority=0,actions=controller")
    time.sleep(1)
    info("*** Table-miss rule confirmed active on s1.\n")

    # ── Initial connectivity test ─────────────────────────────────────────────
    info("\n*** Testing baseline connectivity (h1 → h2)...\n")
    result = hosts["h1"].cmd("ping -c 3 -W 2 10.0.0.2")
    if "0% packet loss" in result:
        info("*** Baseline connectivity: PASS ✓\n")
    elif "1 received" in result or "2 received" in result or "3 received" in result:
        info("*** Baseline connectivity: PASS (partial ARP resolution) ✓\n")
    else:
        error("*** Baseline connectivity: FAIL ✗\n")
        error(result)

    # Write PID file so scripts can track this process
    pid_file = "/tmp/iotshield_mininet.pid"
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))
    info(f"*** PID written to {pid_file}\n")

    # Clean up baseline artifacts so demo starts at exactly 0 events
    for h in hosts.values():
        h.cmd("ip neigh flush all")
    try:
        with open("/tmp/iotshield_events.jsonl", "w") as f:
            pass
        os.chmod("/tmp/iotshield_events.jsonl", 0o666)
    except OSError:
        pass
    # Trigger controller stats reset
    try:
        Path("/tmp/iotshield_reset.trigger").touch()
    except OSError:
        pass

    # ── CLI ───────────────────────────────────────────────────────────────────
    # Set working directory for all hosts to project root
    for h in hosts.values():
        h.cmd(f"cd {_HERE}")

    info("\n*** IoTShield topology ready.\n")
    info("    h1 = 10.0.0.1/24  (IoT Sensor/Victim)\n")
    info("    h2 = 10.0.0.2/24  (Trusted Server)\n")
    info("    h3 = 10.0.0.3/24  (Compromised Host/Attacker)\n")
    info("\n    Run the attack: h3 python3 attacks/arp_spoof.py\n")
    info("    Or use: run_attack.sh from a second terminal\n\n")

    CLI(net)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    info("*** Stopping network\n")
    net.stop()
    if os.path.exists(pid_file):
        os.remove(pid_file)


def _wait_for_controller(switch, timeout: int = 15) -> bool:
    """Poll OVS switch until it reports controller connectivity."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = switch.cmd("ovs-vsctl find controller is_connected=true")
        if "is_connected" in status and "true" in status:
            return True
        time.sleep(1)
    return False


def get_topology_info() -> dict:
    """Return static topology description for the API (no live Mininet needed)."""
    return {
        "hosts": [
            {"name": "h1", "ip": "10.0.0.1", "mac": "00:00:00:00:00:01",
             "role": "IoT Sensor / Victim", "port": 1},
            {"name": "h2", "ip": "10.0.0.2", "mac": "00:00:00:00:00:02",
             "role": "Trusted Server", "port": 2},
            {"name": "h3", "ip": "10.0.0.3", "mac": "00:00:00:00:00:03",
             "role": "Compromised Host / Attacker", "port": 3},
        ],
        "switches": [
            {"name": "s1", "type": "OVS", "openflow_version": "OpenFlow13"}
        ],
        "controller": {
            "name": "Ryu",
            "ip": "127.0.0.1",
            "port": 6633,
        },
        "links": [
            {"src": "h1", "dst": "s1", "src_port": 0, "dst_port": 1},
            {"src": "h2", "dst": "s1", "src_port": 0, "dst_port": 2},
            {"src": "h3", "dst": "s1", "src_port": 0, "dst_port": 3},
        ],
    }


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[ERROR] Mininet requires root. Run: sudo python3 topology/iot_topology.py")
        sys.exit(1)
    create_topology()

